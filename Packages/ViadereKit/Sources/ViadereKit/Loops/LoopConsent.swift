import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

/// Whether a Loop of a business may be started, resumed or acted on (WP-3.5, D3 "Consent bypass"). The server is the authority (`403`
/// without both grants); the device applies the same rule first so nothing is even sent without them.
public enum LoopStartDecision: Sendable, Hashable {
    case allowed
    /// The platform `loops` switch is off, or the status is unknown: no entry points.
    case unavailable
    /// No current global enablement (never given, revoked, or below the current text version).
    case needsGlobalConsent
    /// Loops are on, but this business is not authorized at the current text version.
    case needsBusinessAuthorization
}

public enum LoopConsentGate {
    public static func decision(status: LoopConsentStatus?, business: BusinessID) -> LoopStartDecision {
        guard let status, status.available else { return .unavailable }
        guard status.enabled, let global = status.global, isCurrent(global, text: status.text), global.businessId == nil else {
            return .needsGlobalConsent
        }
        guard status.businesses.contains(where: { $0.businessId == business && isCurrent($0, text: status.text) }) else {
            return .needsBusinessAuthorization
        }
        return .allowed
    }

    /// A grant authorizes only at the current text version and digest.
    static func isCurrent(_ grant: LoopConsentGrantView, text: LoopConsentText) -> Bool {
        grant.current && grant.textVersion == text.version && grant.textDigest == text.digest
    }

    /// The per-business authorization sentence with the verified name of the business (`{business}`), or `nil` for a business Viadere has
    /// not verified (it cannot be authorized).
    public static func businessAuthorizationText(_ text: LoopConsentText, business: BusinessSummary) -> String? {
        guard business.isVerified else { return nil }
        let name = business.safeName
        guard !name.isEmpty else { return nil }
        return text.businessAuthorization.replacingOccurrences(of: "{business}", with: name)
    }
}

/// The Loop consent flows (WP-3.5): the global enablement with the non-skippable education and comprehension checks, the per-business
/// authorization, the Settings toggles and revocation.
///
/// * **Non-skippable, no timing pressure.** Every paragraph is shown in order (`advance()` only moves forward one at a time, nothing
///   advances on a timer); the checks appear only after the last paragraph; agreement is a separate explicit act; nothing expires while the
///   customer reads or answers.
/// * **The server checks the answers.** The device never knows the correct options; a `422` clears the answers and agreement and asks the
///   customer to review the text again.
/// * **Exact text.** The request echoes the text version and digest the customer saw; a newer version on the server refuses it.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class LoopConsentViewModel {
    public private(set) var status: LoopConsentStatus?
    public private(set) var isLoading = false
    public private(set) var isSubmitting = false
    public var errorMessage: String?

    // Education state.
    /// The paragraph on screen.
    public private(set) var paragraphIndex = 0
    /// The customer pressed Continue on the last paragraph (every paragraph was shown, in order).
    public private(set) var finishedReading = false
    public private(set) var answers: [String: String] = [:]
    public var agreed = false

    private let api: (any LoopsAPI)?

    public init(api: (any LoopsAPI)?, status: LoopConsentStatus? = nil) {
        self.api = api
        self.status = status
    }

    public var text: LoopConsentText? { status?.text }
    public var isAvailable: Bool { status?.available ?? false }
    /// The global enablement is current (Settings toggle "Loops").
    public var isEnabled: Bool {
        guard let status, status.available, status.enabled, let global = status.global else { return false }
        return LoopConsentGate.isCurrent(global, text: status.text)
    }

    public func decision(for business: BusinessID) -> LoopStartDecision { LoopConsentGate.decision(status: status, business: business) }
    public func isAuthorized(_ business: BusinessID) -> Bool { decision(for: business) == .allowed }

    public func load() async {
        guard let api else { return }
        isLoading = true
        defer { isLoading = false }
        do {
            apply(try await api.consentStatus())
        } catch {
            errorMessage = (error as? APIError)?.userMessage ?? "Couldn't load Loops settings."
        }
    }

    // MARK: Education (global enablement)

    public var paragraphCount: Int { text?.paragraphs.count ?? 0 }
    public var currentParagraph: String? {
        guard let text, text.paragraphs.indices.contains(paragraphIndex) else { return nil }
        return text.paragraphs[paragraphIndex]
    }

    /// "Paragraph 2 of 4" for VoiceOver and the progress label.
    public var progressLabel: String { "Part \(min(paragraphIndex + 1, max(paragraphCount, 1))) of \(max(paragraphCount, 1))" }

    /// True once every paragraph has been shown and the customer continued past the last one: only then are the checks offered.
    public var hasReadAll: Bool { paragraphCount > 0 && finishedReading }

    /// One paragraph forward; on the last paragraph, on to the questions. There is no skip.
    public func advance() {
        guard paragraphCount > 0 else { return }
        if paragraphIndex < paragraphCount - 1 {
            paragraphIndex += 1
        } else {
            finishedReading = true
        }
    }

    /// Back to re-read (from the questions to the last paragraph, then one paragraph at a time).
    public func back() {
        if finishedReading {
            finishedReading = false
            return
        }
        guard paragraphIndex > 0 else { return }
        paragraphIndex -= 1
    }

    public func select(option: String, for check: String) {
        guard let check = text?.checks.first(where: { $0.id == check }), check.options.contains(where: { $0.id == option }) else { return }
        answers[check.id] = option
    }

    public var allChecksAnswered: Bool {
        guard let text else { return false }
        return text.checks.allSatisfy { answers[$0.id] != nil }
    }

    public var canEnable: Bool { hasReadAll && allChecksAnswered && agreed && !isSubmitting && isAvailable }

    /// Sends the global enablement. Refused locally unless everything was read, every check answered and agreement given.
    @discardableResult
    public func enable() async -> Bool {
        guard canEnable, let api, let text else { return false }
        isSubmitting = true
        defer { isSubmitting = false }
        errorMessage = nil
        do {
            apply(try await api.enableLoops(LoopGlobalConsentRequest(textVersion: text.version, textDigest: text.digest, answers: answers, agree: true)))
            resetEducation()
            return true
        } catch let error as APIError {
            if case .server(422, _, _) = error {
                // Wrong answers or a newer text: review again. No lockout, no timer.
                answers = [:]
                agreed = false
                errorMessage = "Some answers don't match the explanation. Take another look and try again."
                await load()
            } else {
                errorMessage = error.userMessage
            }
            return false
        } catch {
            errorMessage = "Couldn't turn on Loops."
            return false
        }
    }

    /// Sign-out: forget everything.
    public func clear() {
        status = nil
        errorMessage = nil
        resetEducation()
    }

    public func resetEducation() {
        paragraphIndex = 0
        finishedReading = false
        answers = [:]
        agreed = false
    }

    // MARK: Per-business authorization

    public func authorizationText(for business: BusinessSummary) -> String? {
        guard let text else { return nil }
        return LoopConsentGate.businessAuthorizationText(text, business: business)
    }

    /// Authorizes one verified, connected business. Requires the current global enablement.
    @discardableResult
    public func authorize(_ business: BusinessSummary) async -> Bool {
        guard let api, let text, authorizationText(for: business) != nil, decision(for: business.id) == .needsBusinessAuthorization else { return false }
        isSubmitting = true
        defer { isSubmitting = false }
        errorMessage = nil
        do {
            apply(try await api.authorizeBusiness(business.id, LoopBusinessConsentRequest(textVersion: text.version, textDigest: text.digest, agree: true)))
            return true
        } catch {
            errorMessage = (error as? APIError)?.userMessage ?? "Couldn't allow Loops from this business."
            await load()
            return false
        }
    }

    /// Revokes one business (its open Loops are cancelled by the server; history is kept).
    public func revoke(_ business: BusinessID) async {
        guard let api else { return }
        do {
            apply(try await api.revokeBusiness(business))
        } catch {
            errorMessage = (error as? APIError)?.userMessage ?? "Couldn't change that."
        }
    }

    /// Turns Loops off: revokes the global grant and every business authorization; open Loops are cancelled; core features are unaffected.
    public func disable() async {
        guard let api else { return }
        do {
            apply(try await api.disableLoops())
            resetEducation()
        } catch {
            errorMessage = (error as? APIError)?.userMessage ?? "Couldn't turn off Loops."
        }
    }

    private func apply(_ new: LoopConsentStatus) {
        // A new text version invalidates an education in progress.
        if let old = status?.text, old.version != new.text.version || old.digest != new.text.digest { resetEducation() }
        status = new
    }
}
