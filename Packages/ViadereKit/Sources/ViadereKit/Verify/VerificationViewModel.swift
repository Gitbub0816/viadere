import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

/// The wording of the verification screens (spec §10.2 marketing integrity, §11.5 disclosure language; counsel review pending).
/// Nothing here claims more than the check does: no universal "verified" badge, no guarantee, no endorsement.
public enum VerificationCopy {
    public static let title = "Verification request"
    public static let consentButton = "Share this and continue"
    public static let declineButton = "Don't share"
    public static let verifiedBusinessNote = "This business has completed Viadere's business-identity checks. Verification does not constitute an endorsement, guarantee of legitimacy, or confirmation of regulatory licensing."
    public static let identityNote = "A verification result describes the attribute and assurance evaluated. It is not a universal guarantee of identity or eligibility."
    public static let ageNote = "Viadere can confirm that you meet an age threshold without sharing your date of birth. Availability and legal sufficiency vary by service and place."
    /// Face ID, Touch ID and your passcode unlock your phone. They do not prove who you are to a business.
    public static let localAuthNote = "Face ID or your passcode confirms it is you using this phone. It does not prove your legal identity."
    public static let walletTitle = "Use your ID in Apple Wallet"
    public static let walletDetail = "Apple Wallet asks you to confirm, then shares only what is listed above. Viadere never sees a photo of your ID."
    public static let documentTitle = "Scan an ID document"
    public static let documentDetail = "Take a photo of your ID and a short selfie. They go straight to our verification provider and are deleted after the check. Viadere does not receive or keep them."
    /// VER-008: there is always another way, and declining is always possible.
    public static let alternativePath = "No ID in Wallet? You can scan an ID document instead. Neither way is required: you can say no, and the business decides how to help you another way."
    public static let walletUnavailableReason = "An ID in Apple Wallet isn't available on this phone for this request."
    public static let documentUnavailableReason = "Scanning an ID document isn't available right now."
    public static let noMethodAvailable = "There's no way to verify here right now. You can decline, and the business will offer another option."
    public static let retry = "That didn't work. You can try again or use another way."
    public static let notVerified = "We couldn't complete this check. Nothing was shared."
    public static let released = "Shared with the business. The result is for this request only."
    public static let declined = "You chose not to share. Nothing was shared."
    public static let expired = "This request has expired."

    /// What the history row says about a status.
    public static func statusText(_ status: ConsumerVerificationStatus) -> String {
        switch status {
        case .pendingConsent: "Waiting for you"
        case .consented: "In progress"
        case .released: "Shared"
        case .notVerified: "Not verified"
        case .declined: "Declined"
        case .expired: "Expired"
        case .cancelled: "Cancelled"
        case .revoked: "Withdrawn"
        }
    }

    public static func labelText(_ label: VerificationLabel) -> String { label.displayName }
}

/// One verification request's journey on the phone: review, consent, method choice, verifying, result.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class VerificationViewModel: Identifiable {
    public enum Phase: Equatable, Sendable {
        case loading
        /// The prompt is shown; the person has not consented.
        case reviewing
        /// Consent is recorded; choose how to verify.
        case choosingMethod
        case verifying(VerificationMethodKind)
        case finished(VerificationAttemptOutcome)
        case failed(String)
    }

    public private(set) var phase: Phase = .loading
    public private(set) var prompt: VerificationPrompt?
    public private(set) var walletAvailability: WalletAvailability = .unavailable
    public private(set) var now: Date
    /// The method to show first (Wallet when it can answer, VER-003), then the alternative (VER-008).
    public private(set) var orderedMethods: [VerificationMethodKind] = []

    public nonisolated let id: VerificationRequestID
    private let api: any VerifyAPI
    private let wallet: any WalletIdentityService
    private let document: any DocumentVerificationService
    private let lock: any AppLockAuthenticator
    private let clock: @Sendable () -> Date
    public var onFinished: (@MainActor (VerificationAttemptOutcome) -> Void)?

    public init(id: VerificationRequestID, api: any VerifyAPI, wallet: any WalletIdentityService = UnavailableWalletIdentity(),
                document: any DocumentVerificationService = UnavailableDocumentVerification(), lock: any AppLockAuthenticator,
                clock: @escaping @Sendable () -> Date = { Date() }) {
        self.id = id
        self.api = api
        self.wallet = wallet
        self.document = document
        self.lock = lock
        self.clock = clock
        now = clock()
    }

    // MARK: Derived

    public var remaining: TimeInterval { max(0, (prompt?.expiresAt ?? now).timeIntervalSince(now)) }
    public var isExpired: Bool { prompt.map { now >= $0.expiresAt } ?? false }

    /// The exact lines shown under "What will be shared".
    public var disclosure: [VerificationDisclosureItem] { prompt?.disclosure ?? [] }

    public var purposeText: String { prompt.map { VerificationPromptContent.purposeText($0.purposeCode) } ?? "" }

    /// The assurance note matching the capability (age threshold or identity), counsel-reviewed wording.
    public var note: String {
        switch prompt?.capability {
        case .ageMinimum?: VerificationCopy.ageNote
        default: VerificationCopy.identityNote
        }
    }

    public func tick() { now = clock() }

    // MARK: Flow

    public func load() async {
        phase = .loading
        do {
            let loaded = try await api.prompt(id)
            apply(loaded)
            await refreshAvailability()
        } catch {
            phase = .failed((error as? APIError)?.userMessage ?? "This request isn't available.")
        }
    }

    private func apply(_ loaded: VerificationPrompt) {
        prompt = loaded
        now = clock()
        switch loaded.status {
        case .pendingConsent: phase = .reviewing
        case .consented: phase = .choosingMethod
        case .expired: phase = .failed(VerificationCopy.expired)
        case .released, .notVerified, .declined, .cancelled, .revoked:
            phase = .finished(VerificationAttemptOutcome(status: loaded.status, label: nil, receiptId: loaded.receiptId, canRetry: false))
        }
    }

    private func refreshAvailability() async {
        guard let prompt, let plan = WalletElementPlan.request(for: prompt.capability, parameters: prompt.parameters) else {
            walletAvailability = .unavailable
            orderedMethods = []
            return
        }
        let serverOffersWallet = prompt.methods.first { $0.kind == .wallet }?.available == true
        walletAvailability = serverOffersWallet ? await wallet.availability(for: plan) : .unavailable
        let serverOffersDocument = prompt.methods.first { $0.kind == .document }?.available == true
        var methods: [VerificationMethodKind] = []
        if walletAvailability == .available { methods.append(.wallet) }
        if serverOffersDocument { methods.append(.document) }
        orderedMethods = methods
    }

    /// Records the consent for exactly what is on screen. Requires the person to unlock the phone first when it can.
    public func consent() async {
        guard let shown = prompt, phase == .reviewing, !isExpired else { return }
        if await lock.isAvailable() {
            guard await lock.authenticate(reason: "Confirm to share this with \(shown.recipientName)") else { return }
        }
        do {
            apply(try await api.consent(id, displayDigest: shown.displayDigest))
            await refreshAvailability()
        } catch let error as APIError {
            phase = .failed(error.code == .conflict ? "This request changed. Open it again to review it." : error.userMessage)
        } catch {
            phase = .failed("Something went wrong.")
        }
    }

    public func decline() async {
        do {
            try await api.decline(id)
            phase = .finished(VerificationAttemptOutcome(status: .declined, label: nil, receiptId: nil, canRetry: false))
            onFinished?(VerificationAttemptOutcome(status: .declined, label: nil, receiptId: nil, canRetry: false))
        } catch {
            phase = .failed((error as? APIError)?.userMessage ?? "Something went wrong.")
        }
    }

    public func verifyWithWallet() async {
        notice = nil
        guard let shown = prompt, phase == .choosingMethod, walletAvailability == .available,
              let plan = WalletElementPlan.request(for: shown.capability, parameters: shown.parameters) else { return }
        phase = .verifying(.wallet)
        do {
            let start = try await api.beginWallet(id)
            guard let nonce = Base64URL.decode(start.nonce) else { throw APIError.decoding("nonce") }
            let envelope = try await wallet.present(plan, nonce: nonce, merchantIdentifier: start.merchantIdentifier)
            finish(try await api.completeWallet(id, attemptId: start.attemptId, envelope: envelope))
        } catch WalletPresentationError.cancelled {
            // The person closed Wallet's sheet: back to the choice, nothing was sent.
            phase = .choosingMethod
        } catch WalletPresentationError.unavailable {
            await refreshAvailability()
            notice = VerificationCopy.walletUnavailableReason
            phase = .choosingMethod
        } catch let error as APIError {
            if error.code == .rateLimited || error.code == .unavailable {
                notice = error.userMessage
                phase = .choosingMethod
            } else {
                phase = .failed(error.userMessage)
            }
        } catch {
            phase = .failed("Something went wrong.")
        }
    }

    public func verifyWithDocument() async {
        notice = nil
        guard phase == .choosingMethod, prompt?.methods.first(where: { $0.kind == .document })?.available == true else { return }
        phase = .verifying(.document)
        do {
            let start = try await api.beginDocument(id)
            let result = await document.verify(sessionToken: start.sessionToken)
            guard result != .cancelled else {
                // Walked away: the server closes the abandoned session itself; ask it where the attempt stands.
                finish(try await api.completeDocument(id, attemptId: start.attemptId))
                return
            }
            finish(try await api.completeDocument(id, attemptId: start.attemptId))
        } catch let error as APIError {
            if error.code == .unavailable || error.code == .rateLimited {
                notice = VerificationCopy.documentUnavailableReason
                phase = .choosingMethod
            } else {
                phase = .failed(error.userMessage)
            }
        } catch {
            phase = .failed("Something went wrong.")
        }
    }

    private func finish(_ outcome: VerificationAttemptOutcome) {
        if outcome.status == .consented {
            // Not concluded (a failed attempt with attempts left): back to the choice.
            phase = .choosingMethod
            notice = VerificationCopy.retry
        } else {
            phase = .finished(outcome)
            onFinished?(outcome)
        }
    }

    /// A message after an attempt that did not conclude the request (the same wording whether the person is under the threshold or the check
    /// failed, AGE-005), or when a way of verifying could not run. The request is still open and the person may try another way.
    public private(set) var notice: String?

    /// The line shown on the result screen.
    public var resultText: String {
        guard case .finished(let outcome) = phase else { return "" }
        switch outcome.status {
        case .released: return VerificationCopy.released
        case .declined, .revoked, .cancelled: return VerificationCopy.declined
        case .expired: return VerificationCopy.expired
        default: return VerificationCopy.notVerified
        }
    }
}

/// Verification history in Settings: receipts, with withdrawal where it still applies.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class VerificationHistoryViewModel {
    public private(set) var items: [VerificationHistoryItem] = []
    public private(set) var pending: [VerificationPrompt] = []
    public private(set) var isLoading = false
    public private(set) var errorMessage: String?
    private let api: any VerifyAPI

    public init(api: any VerifyAPI) { self.api = api }

    public func load() async {
        isLoading = true
        defer { isLoading = false }
        do {
            let list = try await api.list()
            items = list.history
            pending = list.pending
            errorMessage = nil
        } catch {
            errorMessage = (error as? APIError)?.userMessage ?? "Couldn't load your verification history."
        }
    }

    /// Withdraws consent that has not been used yet. A disclosure that was already made cannot be taken back, and the row says so.
    public func withdraw(_ item: VerificationHistoryItem) async {
        guard item.revocable else { return }
        do {
            let updated = try await api.revoke(item.id)
            if let index = items.firstIndex(where: { $0.id == item.id }) { items[index] = updated }
            errorMessage = nil
        } catch let error as APIError {
            let message = error.code == .conflict ? "This was already shared, so it can't be withdrawn." : error.userMessage
            await load()
            errorMessage = message
        } catch {
            errorMessage = "Couldn't withdraw this."
        }
    }

    /// The line under a row.
    public static func summary(_ item: VerificationHistoryItem) -> String {
        var parts = [VerificationCopy.statusText(item.status)]
        if let label = item.label { parts.append(label.displayName) }
        if !item.disclosedFields.isEmpty { parts.append("Shared: " + item.disclosedFields.map { $0.replacingOccurrences(of: "_", with: " ") }.joined(separator: ", ")) }
        return parts.joined(separator: " · ")
    }
}
