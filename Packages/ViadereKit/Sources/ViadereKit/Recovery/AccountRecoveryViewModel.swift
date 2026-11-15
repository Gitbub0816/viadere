import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

/// What a recovering client keeps while the 72 hour hold runs: enough to poll `recovery/complete`. The **status token** is a secret
/// (it finishes the recovery), so it lives in the Keychain-backed `SecretStore`, not in defaults. Recovery codes are never stored.
public struct RecoveryHold: Codable, Sendable, Equatable {
    public var recoveryId: RecoveryID
    public var statusToken: String
    public var startedAt: Date
    public var activatesAt: Date

    public init(recoveryId: RecoveryID, statusToken: String, startedAt: Date, activatesAt: Date) {
        self.recoveryId = recoveryId
        self.statusToken = statusToken
        self.startedAt = startedAt
        self.activatesAt = activatesAt
    }
}

public struct RecoveryHoldStore: Sendable {
    static let account = "recovery.hold"
    private let slot: JSONSecretSlot<RecoveryHold>

    public init(secrets: any SecretStore) { slot = JSONSecretSlot(secrets: secrets, account: Self.account) }

    public func load() -> RecoveryHold? { try? slot.load() }
    public func save(_ hold: RecoveryHold) throws { try slot.save(hold) }
    public func clear() { try? slot.clear() }
}

/// "Lost your devices?": the account-recovery state machine (§2.26).
///
///     entry ──code accepted──▶ passkeyNeeded ──new passkey registered──▶ holding (72 h, devices can cancel)
///       holding ──poll: activated──▶ codes (shown once) ──"I saved these"──▶ signingIn ──▶ done
///       holding ──poll: cancelled / expired──▶ ended
///
/// Polling happens when the screen opens and when the app returns to the foreground (throttled), never in a tight loop.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class AccountRecoveryViewModel {
    public enum Ending: Equatable, Sendable { case cancelled, expired }

    public enum Phase: Equatable, Sendable {
        /// Enter the recovery ID and one code.
        case entry
        /// A call is in flight.
        case working
        /// The code was accepted (and spent); a new passkey must be registered.
        case passkeyNeeded
        /// The new passkey is registered; the account waits out the hold.
        case holding(RecoveryHold)
        /// The hold passed: the new recovery codes are on screen, once.
        case codes
        /// Signing in with the new passkey.
        case signingIn
        case ended(Ending)
        case done
    }

    public private(set) var phase: Phase = .entry
    public var recoveryIdText = ""
    public var codeText = ""
    public private(set) var errorMessage: String?
    /// A calm line about the last status check ("Still waiting"), never an error.
    public private(set) var statusMessage: String?
    /// The replacement codes, once the hold has passed. Released when saved.
    public private(set) var codes: RecoveryCodesViewModel?
    /// The activation delivered no codes (they were shown before and are gone): the person generates new ones in Settings.
    public private(set) var codesWereNotDelivered = false
    public private(set) var lastCheckedAt: Date?
    /// Called after the new passkey signed in; onboarding continues with this iPhone's setup.
    public var onSignedIn: (@MainActor () -> Void)?

    private let services: ViadereServices
    private let holds: RecoveryHoldStore
    private var options: PasskeyRegistrationOptions?
    private var isChecking = false

    /// The soonest an automatic status check repeats.
    public static let minimumCheckInterval: TimeInterval = 60

    public init(services: ViadereServices) {
        self.services = services
        holds = RecoveryHoldStore(secrets: services.secrets)
    }

    // MARK: Input

    public var normalizedRecoveryID: String? { RecoveryCodeFormat.normalizeRecoveryID(recoveryIdText) }
    public var normalizedCode: String? { RecoveryCodeFormat.normalizeCode(codeText) }
    public var canSubmit: Bool { phase == .entry && normalizedRecoveryID != nil && normalizedCode != nil }

    public static func display(recoveryID raw: String) -> String {
        stride(from: 0, to: raw.count, by: 4).map { String(raw.dropFirst($0).prefix(4)) }.joined(separator: "-")
    }

    public static func display(code raw: String) -> String { String(raw.prefix(5)) + "-" + String(raw.dropFirst(5).prefix(5)) }

    // MARK: Launch

    /// A hold from an earlier launch (the person closed the app during the 72 hours).
    public func resumeIfPending() async {
        guard phase == .entry, let hold = holds.load() else { return }
        phase = .holding(hold)
        await checkStatus(force: true)
    }

    public var hasPendingHold: Bool { holds.load() != nil }

    // MARK: Begin

    /// Spends one code and moves on to the new passkey.
    public func submit() async {
        guard canSubmit, let id = normalizedRecoveryID, let code = normalizedCode else {
            errorMessage = Self.checkInputMessage
            return
        }
        phase = .working
        errorMessage = nil
        do {
            options = try await services.api.beginRecovery(
                RecoveryBeginRequest(recoveryId: Self.display(recoveryID: id), code: Self.display(code: code)))
        } catch let error as APIError {
            phase = .entry
            errorMessage = Self.beginMessage(error)
            return
        } catch {
            phase = .entry
            errorMessage = Self.genericMessage
            return
        }
        codeText = ""
        await registerPasskey()
    }

    /// Registers the new passkey and starts the hold. Can be retried (the code is already spent) until the server's window closes.
    public func registerPasskey() async {
        guard let options else { phase = .entry; return }
        phase = .working
        errorMessage = nil
        do {
            let credential = try await services.passkeys.register(options: options)
            let status = try await services.api.finishRecovery(RecoveryFinishRequest(ceremonyId: options.ceremonyId, credential: credential))
            guard let token = status.statusToken, let activatesAt = status.activatesAt else { throw APIError.decoding("recovery") }
            let hold = RecoveryHold(recoveryId: status.id, statusToken: token, startedAt: status.startedAt, activatesAt: activatesAt)
            try holds.save(hold)
            self.options = nil
            phase = .holding(hold)
        } catch let error as PasskeyError {
            phase = .passkeyNeeded
            if error != .cancelled { errorMessage = error.userMessage }
        } catch let error as APIError {
            phase = .passkeyNeeded
            errorMessage = error == .sessionExpired ? Self.windowClosedMessage : error.userMessage
        } catch {
            phase = .passkeyNeeded
            errorMessage = Self.genericMessage
        }
    }

    /// Back to the start (the passkey window closed, or the person changed their mind).
    public func startOver() {
        options = nil
        errorMessage = nil
        phase = .entry
    }

    // MARK: Hold

    /// Polls `recovery/complete`. Automatic callers (screen open, foreground) are throttled; `force` is the person tapping "Check now".
    public func checkStatus(force: Bool = false) async {
        guard case .holding(let hold) = phase, !isChecking else { return }
        let now = services.clock()
        if !force, let last = lastCheckedAt, now.timeIntervalSince(last) < Self.minimumCheckInterval { return }
        isChecking = true
        defer { isChecking = false }
        lastCheckedAt = now
        let status: RecoveryStatus
        do {
            status = try await services.api.completeRecovery(RecoveryCompleteRequest(recoveryId: hold.recoveryId, statusToken: hold.statusToken))
        } catch {
            // Offline, rate limited or a hiccup: keep waiting. The hold is information, not a task.
            statusMessage = "Couldn't check just now. We'll try again when you open Viadere."
            return
        }
        switch status.state {
        case .holding, .awaitingPasskey:
            statusMessage = "Still waiting. Nothing has changed."
            if let activatesAt = status.activatesAt, activatesAt != hold.activatesAt {
                var updated = hold
                updated.activatesAt = activatesAt
                try? holds.save(updated)
                phase = .holding(updated)
            }
        case .activated:
            statusMessage = nil
            if let set = status.recoveryCodes {
                codes = RecoveryCodesViewModel(codes: set)
                phase = .codes
            } else {
                codesWereNotDelivered = true
                await signIn()
            }
        case .cancelled:
            holds.clear()
            phase = .ended(.cancelled)
        case .expired, .unknown:
            holds.clear()
            phase = .ended(.expired)
        }
    }

    // MARK: Codes and sign-in

    /// "I saved these": releases the codes and signs in with the new passkey.
    public func confirmCodesSaved() async {
        guard phase == .codes, codes?.finish() == true else { return }
        codes = nil
        await signIn()
    }

    /// The codes screen was dismissed without saving (the app locked, the screen disappeared). The codes are gone; the new passkey
    /// already works, so the person signs in and generates new ones from Settings.
    public func codesLost() async {
        guard phase == .codes else { return }
        codes?.release()
        codes = nil
        codesWereNotDelivered = true
        await signIn()
    }

    public func signIn() async {
        phase = .signingIn
        errorMessage = nil
        do {
            try await services.account.signIn()
            holds.clear()
            phase = .done
            onSignedIn?()
        } catch let error as PasskeyError {
            if error != .cancelled { errorMessage = error.userMessage }
        } catch let error as APIError {
            errorMessage = error.userMessage
        } catch {
            errorMessage = Self.genericMessage
        }
        // A failed or cancelled sign-in stays here: "Try again" calls `signIn()`.
    }

    // MARK: Copy

    public static let checkInputMessage = "Check the recovery ID (12 characters) and the code (10 characters), then try again."
    public static let genericMessage = "Something went wrong. Please try again."
    public static let windowClosedMessage = "That took too long, so the recovery window closed. Start again with another code."
    /// One message for every refusal, so it cannot be used to find out which part was wrong.
    public static let notRecognizedMessage = "That recovery ID and code weren't accepted. Check them and try again. Each code works once."

    static func beginMessage(_ error: APIError) -> String {
        switch error {
        case .transport: error.userMessage
        case .server(_, let code, _) where code == .rateLimited: error.userMessage
        default: notRecognizedMessage
        }
    }

    public static let holdExplanation = "To protect your account, recovery takes 72 hours. During that time every device you already have is told, and any of them can cancel it. If nobody cancels, your account moves to this iPhone."
}
