import Foundation
import Observation
import ViadereCore
import ViadereKit

/// The clip's tiny state machine: resolve the code, review consent, (create an account), connect, done.
@MainActor @Observable
final class ClipFlowModel {
    enum Step: Equatable { case idle, account, recoveryCodes, working, done(String) }

    private(set) var step: Step = .idle
    private(set) var accountError: String?
    var displayName = ""
    /// The new account's recovery codes, on screen once and never stored (the same screen as the app's onboarding).
    private(set) var recoveryCodes: RecoveryCodesViewModel?
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

    /// Passkey account, then the one-time recovery codes, then this device's keys, then connect.
    func createAccountAndConnect() async {
        step = .working
        accountError = nil
        do {
            if !(await services.sessions.isSignedIn) {
                if let codes = try await services.account.signUp(displayName: displayName) {
                    recoveryCodes = RecoveryCodesViewModel(codes: codes)
                    step = .recoveryCodes
                    return
                }
            }
            await enrollAndConnect()
        } catch {
            report(error)
        }
    }

    /// "I saved these": releases the codes and carries on.
    func recoveryCodesSaved() async {
        guard let recoveryCodes, recoveryCodes.finish() else { return }
        self.recoveryCodes = nil
        step = .working
        await enrollAndConnect()
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
