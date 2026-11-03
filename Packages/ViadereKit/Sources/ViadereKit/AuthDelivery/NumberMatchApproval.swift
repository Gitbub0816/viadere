import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

// The push-approval screen (ADR-0022 §2, §5; UX_COPY §3): the person types the number shown on the screen where they are signing in. The phone
// never displays it. Deny and Approve are one component, Deny first; "This wasn't me" is a full-width secondary button in the footer.

/// What the device signs (ADR-0022 §3). `match` is the typed string and is present only on an approve of a number-matched request.
public enum AuthAnswer: Sendable, Equatable {
    case approve(match: String?)
    /// `deny_reason` is `nil` for a plain Deny and `number_mismatch` for the automatic denial after three wrong entries.
    case deny(reason: DenyReason?)
    /// "This wasn't me": `decision: report`, `deny_reason: not_me`.
    case report

    public enum DenyReason: String, Sendable, Equatable { case numberMismatch = "number_mismatch" }
}

/// Signs and sends an answer. The App's implementation signs with the approval key (approve) or the request key (reduce-only) and returns
/// only after the relay accepted the signed result: "Approved" is never shown before that (UX_COPY §0 rule 3).
public protocol ApprovalAnswering: Sendable {
    /// `requestIds` is the one selected request for an approve; for a deny or report it is every open request of the group, which counts as
    /// one denial toward the pause (ADR-0022 §5.2 item 2).
    func answer(_ answer: AuthAnswer, requestIds: [String]) async throws
}

/// Where the wrong-entry count of a request lives (Stage 4 review R4-02): the approval store, per request id, so a dismissal or a relaunch does not
/// give three fresh tries.
public protocol NumberMatchAttemptRecording: Sendable {
    func wrongEntries(requestIds: [String]) async -> Int
    @discardableResult func recordWrongEntry(requestIds: [String]) async -> Int
}

public enum NumberMatchAttemptLimit {
    public static let max = 3
}

/// An in-memory recorder for tests and previews.
public actor InMemoryNumberMatchAttempts: NumberMatchAttemptRecording {
    private var counts: [String: Int] = [:]
    public init() {}
    public func wrongEntries(requestIds: [String]) -> Int { requestIds.map { counts[$0] ?? 0 }.max() ?? 0 }
    public func recordWrongEntry(requestIds: [String]) -> Int {
        let next = min(wrongEntries(requestIds: requestIds) + 1, NumberMatchAttemptLimit.max)
        for id in requestIds { counts[id] = next }
        return next
    }
}

public enum NumberMatchKind: Sendable, Equatable {
    case signIn
    /// Payment step-up: 3 digits, payee shown, and the device must be trusted for payments (D1, ADR-0022 §4).
    case payment(payee: String)
}

/// Everything the screen shows, already verified and sanitized by the request handler.
public struct NumberMatchApprovalContext: Sendable, Equatable {
    public var business: String
    public var kind: NumberMatchKind
    /// `{action}` supplied by the business (≤ 60 characters, sanitized), when there is one.
    public var action: String?
    public var requestedAt: Date?
    public var expiresAt: Date
    /// Nil when the request carries no number (a request created before number matching).
    public var requirement: NumberMatchRequirement?
    /// When true a missing or malformed requirement leaves Approve disabled (fail closed). Deny always works.
    public var requiresNumber: Bool
    public var openRequestCount: Int
    public var requestsInWindow: Int
    public var showFatigueWarning: Bool
    /// Server-visible (relay could read it) rather than business-signed end to end.
    public var relayAsserted: Bool
    /// False when this device cannot approve payments yet (S-PAY-02).
    public var deviceCanApprove: Bool
    public var hasOtherTrustedDevice: Bool
    /// The ids of every open request in the group (deny and report answer all of them).
    public var groupRequestIds: [String]
    /// The one request id when there is no number requirement (single request).
    public var singleRequestId: String?

    public init(business: String, kind: NumberMatchKind = .signIn, action: String? = nil, requestedAt: Date? = nil, expiresAt: Date,
                requirement: NumberMatchRequirement?, requiresNumber: Bool = true, openRequestCount: Int = 1, requestsInWindow: Int = 1,
                showFatigueWarning: Bool = false, relayAsserted: Bool = false, deviceCanApprove: Bool = true, hasOtherTrustedDevice: Bool = true,
                groupRequestIds: [String], singleRequestId: String? = nil) {
        self.business = business
        self.kind = kind
        self.action = action
        self.requestedAt = requestedAt
        self.expiresAt = expiresAt
        self.requirement = requirement
        self.requiresNumber = requiresNumber
        self.openRequestCount = openRequestCount
        self.requestsInWindow = requestsInWindow
        self.showFatigueWarning = showFatigueWarning
        self.relayAsserted = relayAsserted
        self.deviceCanApprove = deviceCanApprove
        self.hasOtherTrustedDevice = hasOtherTrustedDevice
        self.groupRequestIds = groupRequestIds
        self.singleRequestId = singleRequestId
    }
}

@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class NumberMatchApprovalViewModel {
    public enum Phase: Sendable, Equatable {
        case entering
        case submitting
        /// Shown only after the relay accepted the signed answer.
        case approved
        case denied
        case reported
        /// Three wrong entries: the device denied the whole group.
        case autoDenied
        case expired
    }

    public static let maxWrongEntries = 3

    public private(set) var phase: Phase = .entering
    public private(set) var entry = ""
    public private(set) var wrongEntries = 0
    /// A line for the screen (errors and wrong-number feedback). Never colour only.
    public private(set) var notice: String?
    /// Posted as a VoiceOver announcement when it changes (wrong entry).
    public private(set) var announcement: String?
    public private(set) var fatigueAcknowledged = false
    public var isScreenCaptured = false

    public let context: NumberMatchApprovalContext
    private let answering: any ApprovalAnswering
    private let pauser: (@Sendable () async -> Bool)?
    private let clock: @Sendable () -> Date
    private let attempts: (any NumberMatchAttemptRecording)?

    /// - Parameters:
    ///   - initialWrongEntries: the persisted count for this group (R4-02); load it with `NumberMatchAttemptRecording.wrongEntries` before presenting.
    ///   - attempts: where each wrong entry is recorded.
    public init(context: NumberMatchApprovalContext, answering: any ApprovalAnswering, pauser: (@Sendable () async -> Bool)? = nil,
                clock: @escaping @Sendable () -> Date = { Date() }, initialWrongEntries: Int = 0, attempts: (any NumberMatchAttemptRecording)? = nil) {
        self.context = context
        self.answering = answering
        self.pauser = pauser
        self.clock = clock
        self.attempts = attempts
        wrongEntries = min(max(initialWrongEntries, 0), Self.maxWrongEntries)
    }

    /// Seeds the persisted count when the screen opens (R4-02). Only ever raises the count.
    public func restoreWrongEntries(_ stored: Int) {
        wrongEntries = max(wrongEntries, min(max(stored, 0), Self.maxWrongEntries))
        restoringWrongEntries = false
    }

    /// Approve stays off until `restoreWrongEntries` ran (S5-06): the sheet loads the stored count asynchronously after it is on screen, and until then the
    /// screen must not offer a fresh set of tries.
    public func holdApproveUntilRestored() { restoringWrongEntries = true }
    private var restoringWrongEntries = false

    /// True once a wrong number was typed: the App then asks "Leave this request?" before any dismissal, the swipe included (R4-02).
    public var confirmsBeforeLeaving: Bool { wrongEntries > 0 && (phase == .entering || phase == .submitting) }

    // MARK: Copy

    public var isPayment: Bool { if case .payment = context.kind { return true } else { return false } }
    public var digits: Int { context.requirement?.digits ?? (isPayment ? 3 : 2) }
    public var traits: NumberFieldTraits { .required }

    public var title: String {
        switch context.kind {
        case .signIn: return AuthDeliveryCopy.signInTitle(business: context.business)
        case .payment(let payee): return AuthDeliveryCopy.paymentTitle(payee: payee)
        }
    }
    public var subtitle: String { isPayment ? AuthDeliveryCopy.paymentSubtitle : AuthDeliveryCopy.signInSubtitle }
    public var fieldLabel: String { AuthDeliveryCopy.numberFieldLabel(business: context.business) }
    public var helper: String {
        context.requirement?.hasMixedLengths == true
            ? AuthDeliveryCopy.numberHelperAnyLength(business: context.business)
            : AuthDeliveryCopy.numberHelper(business: context.business, digits: digits, payment: isPayment)
    }
    public var groupLine: String? {
        context.openRequestCount > 1 ? AuthDeliveryCopy.openRequests(count: context.openRequestCount, business: context.business) : nil
    }
    public var fatigueLine: String? {
        context.showFatigueWarning ? AuthDeliveryCopy.fatigue(count: context.requestsInWindow, business: context.business) : nil
    }
    public var sameDeviceHint: String { AuthDeliveryCopy.sameDeviceHint(business: context.business) }
    public var relayLine: String? { context.relayAsserted ? AuthDeliveryCopy.unverifiedRelayLine : nil }
    public var denyLine: String { AuthDeliveryCopy.denyLine }
    public var faceIDReason: String { AuthDeliveryCopy.faceIDReason(business: context.business) }
    public var pauseTitle: String { AuthDeliveryCopy.pauseAction(business: context.business) }

    /// The device cannot approve payments yet (S-PAY-02 / S-PAY-02b); it can still deny.
    public var deviceBlockLine: String? {
        guard isPayment, !context.deviceCanApprove else { return nil }
        return context.hasOtherTrustedDevice ? AuthDeliveryCopy.paymentDeviceNotTrusted : AuthDeliveryCopy.paymentNoTrustedDevice(business: context.business)
    }

    /// The screen's result line once finished.
    public var resultLine: String? {
        switch phase {
        case .approved: return isPayment ? AuthDeliveryCopy.approvedPayment(business: context.business) : AuthDeliveryCopy.approved(business: context.business)
        case .denied: return isPayment ? AuthDeliveryCopy.deniedPayment(business: context.business) : AuthDeliveryCopy.denied(business: context.business)
        case .reported: return AuthDeliveryCopy.reported(business: context.business)
        case .autoDenied: return AuthDeliveryCopy.wrongNumberAutoDeny(business: context.business)
        case .expired: return AuthDeliveryCopy.answerExpired
        case .entering, .submitting: return nil
        }
    }

    public var offersPause: Bool { phase == .reported && pauser != nil }

    // MARK: Buttons

    /// True when this request must be answered with a typed number.
    private var numberRequired: Bool { context.requiresNumber || context.requirement != nil }
    private var requirementUsable: Bool { context.requirement?.isWellFormed == true }

    public var isNumberComplete: Bool {
        if let requirement = context.requirement { return NumberMatcher.isComplete(entry, requirement: requirement) }
        return NumberMatcher.isComplete(entry, digits: digits)
    }

    public var needsFatigueAcknowledgement: Bool { context.showFatigueWarning && !fatigueAcknowledged }

    /// Three wrong entries were made. Approve stays off for good on this screen, even when the automatic denial could not be sent (Face ID
    /// cancelled, offline): the only answers left are Deny (sent as `number_mismatch`) and This wasn't me.
    public var wrongEntryLimitReached: Bool { wrongEntries >= Self.maxWrongEntries }

    public var canApprove: Bool {
        guard phase == .entering, !restoringWrongEntries, !wrongEntryLimitReached, !isScreenCaptured, context.deviceCanApprove, !needsFatigueAcknowledgement, context.expiresAt > clock() else { return false }
        if numberRequired { return requirementUsable && isNumberComplete }
        return context.singleRequestId != nil
    }

    /// Deny and Approve: one component, Deny first, identical style; Approve disabled (never hidden) until the number is complete.
    public var buttons: [SafeActionButton] {
        [SafeActionButton(role: .deny, title: AuthDeliveryCopy.deny, isEnabled: canAnswerNo),
         SafeActionButton(role: .approve, title: AuthDeliveryCopy.approve, isEnabled: canApprove)]
    }
    /// The full-width secondary footer button (at least 44 pt in the App).
    public var notMeButton: SafeActionButton { SafeActionButton(role: .notMe, title: AuthDeliveryCopy.notMe, isEnabled: canAnswerNo) }
    private var canAnswerNo: Bool { phase == .entering }

    // MARK: Input

    /// The field's edit hook. Paste, AutoFill and replacements are refused (`NumberMatcher.applyEdit`).
    public func edit(_ proposed: String) {
        guard phase == .entering else { return }
        entry = NumberMatcher.applyEdit(previous: entry, proposed: proposed, digits: digits)
        if notice == AuthDeliveryCopy.numberMatchesSeveral { notice = nil }
    }

    public func acknowledgeFatigue() { fatigueAcknowledged = true }

    // MARK: Answers

    public func deny() async {
        // After three wrong entries a Deny is the retry of the automatic `number_mismatch` denial that could not be sent.
        if wrongEntryLimitReached {
            await submit(.deny(reason: .numberMismatch), requestIds: context.groupRequestIds, success: .autoDenied)
        } else {
            await submit(.deny(reason: nil), requestIds: context.groupRequestIds, success: .denied)
        }
    }

    public func reportNotMe() async { await submit(.report, requestIds: context.groupRequestIds, success: .reported) }

    public func pauseRequests() async -> Bool {
        guard offersPause, let pauser else { return false }
        return await pauser()
    }

    /// Approve: compares the typed number with every open request's code. Exactly one match selects and approves that request.
    public func approve() async {
        guard canApprove else { return }
        guard numberRequired, let requirement = context.requirement else {
            guard let id = context.singleRequestId else { return }
            await submit(.approve(match: nil), requestIds: [id], success: .approved)
            return
        }
        switch NumberMatcher.evaluate(entry: entry, requirement: requirement) {
        case .match(let requestId):
            await submit(.approve(match: entry), requestIds: [requestId], success: .approved)
        case .ambiguous:
            // Nothing is signed. The person starts again on the business's page (S-MFA-15).
            entry = ""
            notice = AuthDeliveryCopy.numberMatchesSeveral
            announcement = AuthDeliveryCopy.numberMatchesSeveral
        case .noMatch:
            wrongEntries += 1
            entry = ""
            if let attempts {
                let stored = await attempts.recordWrongEntry(requestIds: context.groupRequestIds)
                wrongEntries = max(wrongEntries, stored)
            }
            if wrongEntries >= Self.maxWrongEntries {
                await submit(.deny(reason: .numberMismatch), requestIds: context.groupRequestIds, success: .autoDenied)
            } else {
                notice = AuthDeliveryCopy.wrongNumber
                announcement = AuthDeliveryCopy.wrongNumber
            }
        }
    }

    private func submit(_ answer: AuthAnswer, requestIds: [String], success: Phase) async {
        guard phase == .entering, !requestIds.isEmpty else { return }
        if context.expiresAt <= clock() { phase = .expired; notice = AuthDeliveryCopy.answerExpired; return }
        phase = .submitting
        notice = nil
        do {
            try await answering.answer(answer, requestIds: requestIds)
            phase = success
        } catch let error as AuthDeliveryError where error == .expired {
            phase = .expired
        } catch {
            // Nothing is queued: the person can try again while the request is open.
            phase = .entering
            notice = AuthDeliveryCopy.answerNotSent(business: context.business)
            announcement = notice
        }
    }
}

// MARK: Approve v2 adapter

extension NumberMatchApprovalContext {
    /// The screen's context for a verified Approve v2 prompt.
    ///
    /// `numberMatch` is `nil` today: the request wire (`number_match` in the business-signed request, `match` in the `ApprovalResult` v2 JWS,
    /// ADR-0022 §3) lands with the Core and server work. Until then the screen is built the same way but Approve needs no number
    /// (`requiresNumber: false`); the moment a prompt carries a requirement, Approve is disabled until the number is typed and matches.
    public init(prompt: ApprovalPrompt, numberMatch: NumberMatchRequirement? = nil, deviceCanApprove: Bool = true) {
        self.init(group: [prompt], numberMatch: numberMatch, deviceCanApprove: deviceCanApprove)
    }

    /// Whether a verified prompt must be answered with a typed number (R4-04): from **signed or digest-bound policy**, never from whether the relay happened to
    /// send a code: every payment (ADR-0022 §2.1, §4), every request whose business-signed content carries `number_match`, and every authentication whose
    /// details (inside `txn_digest`) name `match_digits`.
    public static func requiresNumber(_ prompt: ApprovalPrompt) -> Bool {
        if prompt.content.numberMatch != nil { return true }
        switch prompt.content.details {
        case .transaction: return true
        case .authentication(let a): return a.matchDigits != nil
        }
    }

    /// The screen for one business's open requests (ADR-0022 §5.2 item 2): the typed number is compared with every request's code.
    public init(group prompts: [ApprovalPrompt], numberMatch: NumberMatchRequirement? = nil, deviceCanApprove: Bool = true) {
        let prompt = prompts[0]
        var requirement = numberMatch
        if requirement == nil {
            let candidates = prompts.compactMap { p in p.content.numberMatch.map { NumberMatchRequirement.Candidate(requestId: p.request.requestId, code: $0.code) } }
            // The field is as long as the longest code; each candidate keeps its own length (S5-01).
            if !candidates.isEmpty { requirement = NumberMatchRequirement(digits: candidates.map { $0.code.utf8.count }.max() ?? 2, candidates: candidates) }
        }
        let required = numberMatch != nil || prompts.contains(where: Self.requiresNumber)
        let business = UntrustedText.name(prompt.business.displayName, max: 40, attribution: nil).text
        let kind: NumberMatchKind
        let action: String?
        switch prompt.content.details {
        case .transaction(let t):
            kind = .payment(payee: UntrustedText.line(t.payeeDisplay, max: 80))
            action = nil
        case .authentication(let a):
            kind = .signIn
            action = UntrustedText.optionalLine(a.actionDisplay, max: 60)
        }
        self.init(business: business, kind: kind, action: action, requestedAt: prompt.request.createdAt, expiresAt: prompt.content.expiresAtDate,
                  requirement: requirement, requiresNumber: required, openRequestCount: max(prompts.count, requirement?.candidates.count ?? 1),
                  requestsInWindow: prompts.map(\.requestsInWindow).max() ?? 1, showFatigueWarning: prompts.contains(where: \.showFatigueWarning),
                  relayAsserted: prompts.contains { $0.assurance == .relayAsserted }, deviceCanApprove: deviceCanApprove,
                  groupRequestIds: prompts.map(\.request.requestId), singleRequestId: prompts.count == 1 ? prompt.request.requestId : nil)
    }
}

/// Answers through `ApproveController` (the existing signed path). For a number-matched request the signed result is `ApprovalResult` v2 (ADR-0022 §3):
/// the typed `match` **inside the signature**, `deny_reason` (`number_mismatch`, `not_me`) and the persisted wrong-entry count. Nothing is queued.
@MainActor
public final class ApproveControllerAnswering: ApprovalAnswering {
    private let controller: ApproveController
    private let prompts: [ApprovalPrompt]
    private let attempts: (any NumberMatchAttemptRecording)?
    private var refusalGroup: String?

    public convenience init(controller: ApproveController, prompt: ApprovalPrompt, attempts: (any NumberMatchAttemptRecording)? = nil) {
        self.init(controller: controller, group: [prompt], attempts: attempts)
    }

    public init(controller: ApproveController, group: [ApprovalPrompt], attempts: (any NumberMatchAttemptRecording)? = nil) {
        self.controller = controller
        prompts = group
        self.attempts = attempts
    }

    /// The v2 members for this answer, or `nil` for a request without number matching (a v1 result, unchanged).
    static func numberMatchAnswer(_ answer: AuthAnswer, prompt: ApprovalPrompt, wrongEntries: Int) -> ApprovalNumberMatchAnswer? {
        guard NumberMatchApprovalContext.requiresNumber(prompt) else { return nil }
        let attempts = min(max(wrongEntries, 0), NumberMatchAttemptLimit.max)
        switch answer {
        case .approve(let match): return ApprovalNumberMatchAnswer(match: match, denyReason: nil, invalidMatchAttempts: attempts)
        case .deny(let reason): return ApprovalNumberMatchAnswer(match: nil, denyReason: reason == .numberMismatch ? .numberMismatch : nil, invalidMatchAttempts: attempts)
        case .report: return ApprovalNumberMatchAnswer(match: nil, denyReason: .notMe, invalidMatchAttempts: attempts)
        }
    }

    public func answer(_ answer: AuthAnswer, requestIds: [String]) async throws {
        let decision: ApprovalDecision
        switch answer {
        case .approve: decision = .approve
        case .deny: decision = .deny
        case .report: decision = .report
        }
        let targets = prompts.filter { requestIds.contains($0.request.requestId) }
        guard !targets.isEmpty else { throw AuthDeliveryError.notActive }
        let wrong = await attempts?.wrongEntries(requestIds: requestIds) ?? 0
        // A Deny, This wasn't me or automatic deny of a group is one refusal, however many requests it closes: every result carries the same group id so the
        // relay counts it once toward the pause (ADR-0022 §5.2 item 2, S5-02). An approve answers one request and needs none.
        // The id is kept for this screen, so a retry after a partly sent group answer still counts once.
        let group: String? = decision == .approve || (targets.count < 2 && refusalGroup == nil) ? nil : (refusalGroup ?? ApprovalAnswerGroup.make())
        if group != nil { refusalGroup = group }
        for prompt in targets {
            // `ApproveController.answer` returns only after the relay accepted the signed result.
            guard await controller.answer(prompt, decision, dismissOnSuccess: false,
                                          numberMatch: Self.numberMatchAnswer(answer, prompt: prompt, wrongEntries: wrong), answerGroup: group) else { throw AuthDeliveryError.failed }
        }
    }
}
