import Foundation
import Observation
import ViadereCore
import ViadereKit

/// The clip's tiny state machine: resolve the code, review consent, (set up this iPhone), connect, done.
///
/// A new person gets a **device-first, pseudonymous account** (§2.5a): no name, email, phone or passkey. The clip's device holds a request
/// key only, so it is D0, can never approve anything, and stops working after 7 days. Recovery credentials need a user-verified key, which a
/// clip never has, so there is no recovery step here: the full app is where a person sets up approvals and protection.
@MainActor @Observable
final class ClipFlowModel {
    enum Step: Equatable { case idle, account, working, done(String) }

    private(set) var step: Step = .idle
    private(set) var accountError: String?
    let connect: ConnectViewModel
    /// The explanation shown before the passkey sheet when the clip's device enrollment needs an assertion.
    let passkeyGate = PasskeyExplanationGate()
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

    /// This iPhone creates the account (a request-key-only App Clip device), then connects. A session left from an earlier clip launch that
    /// has no device yet enrolls one instead.
    func createAccountAndConnect() async {
        step = .working
        accountError = nil
        do {
            if !(await services.sessions.isSignedIn) {
                _ = try await services.account.createAccount(deviceName: nil)
                await finish()
                return
            }
            await enrollAndConnect()
        } catch {
            report(error)
        }
    }

    private func enrollAndConnect() async {
        do {
            if (try? await services.records.load()) == nil { _ = try await services.account.enrollThisDevice(name: "iPhone", explain: passkeyGate.explainer) }
            await finish()
        } catch {
            report(error)
        }
    }

    private func report(_ error: any Error) {
        switch error {
        case let error as PasskeyError: accountError = error == .cancelled ? nil : error.userMessage
        case let error as APIError: accountError = error.userMessage
        case let error as AppAttestError: accountError = error.userMessage
        default: accountError = "We couldn't finish setting up. Get the full Viadere app to continue."
        }
        step = .account
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
