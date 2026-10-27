import Foundation
import Observation
import ViadereCore
import ViadereKit

/// The clip's tiny state machine: resolve the code, review consent, (create an account), connect, done.
@MainActor @Observable
final class ClipFlowModel {
    enum Step: Equatable { case idle, account, working, done(String) }

    private(set) var step: Step = .idle
    private(set) var accountError: String?
    var displayName = ""
    let connect: ConnectViewModel
    private let services: ViadereServices
    private var invocation: DeepLink?

    init(services: ViadereServices) {
        self.services = services
        connect = ConnectViewModel(services: services)
    }

    /// An invocation URL arrived (QR, NFC, App Clip Code, Messages, Safari banner).
    func handle(url: URL) async {
        guard case .connect(let code, let link)? = DeepLinkRouter.route(url) else {
            return
        }
        invocation = .connect(code: code, link: link)
        step = .idle
        await connect.open(code: code, link: link, source: .appClip)
    }

    /// The person tapped Connect on the review screen.
    func continueTapped() async {
        if await services.sessions.isSignedIn, (try? await services.records.load()) != nil {
            await finish()
        } else {
            accountError = nil
            step = .account
        }
    }

    /// Passkey account + this device's keys, then connect.
    func createAccountAndConnect() async {
        step = .working
        accountError = nil
        do {
            if !(await services.sessions.isSignedIn) { try await services.account.signUp(displayName: displayName) }
            if (try? await services.records.load()) == nil { _ = try await services.account.enrollThisDevice(name: "iPhone") }
            await finish()
        } catch let error as PasskeyError {
            accountError = error == .cancelled ? nil : error.userMessage
            step = .account
        } catch let error as APIError {
            accountError = error.userMessage
            step = .account
        } catch {
            accountError = "We couldn't finish setting up. Get the full Viadere app to continue."
            step = .account
        }
    }

    private func finish() async {
        step = .working
        await connect.connect()
        if case .connected(let relationship) = connect.phase {
            step = .done(relationship.business.safeName)
        } else if case .failed(let message) = connect.phase {
            accountError = message
            step = .account
        }
    }
}
