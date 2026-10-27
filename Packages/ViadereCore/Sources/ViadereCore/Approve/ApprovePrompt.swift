import Foundation

/// Protection against notification-prompt fatigue (SEC-DEV-008): a business cannot wear a person down with repeated approval requests.
///
/// Both the relay (authoritative) and the app (warnings) evaluate the same policy over the same history.
public struct ApprovalPromptPolicy: Sendable, Hashable {
    /// The look-back window.
    public var window: TimeInterval
    /// Requests from one business to one customer in the window at which the app shows "You've received several requests".
    public var warnAtRequests: Int
    /// Requests per window per relationship after which further requests are refused (`429`).
    public var maxRequests: Int
    /// Denials or reports in the window after which requests are **auto-denied** (the customer is not prompted).
    public var denialsBeforePause: Int
    /// How long the auto-deny lasts after the last denial.
    public var pauseDuration: TimeInterval
    /// Open (undecided, unexpired) requests per relationship at once.
    public var maxPending: Int

    public init(window: TimeInterval = 3600, warnAtRequests: Int = 3, maxRequests: Int = 6, denialsBeforePause: Int = 3,
                pauseDuration: TimeInterval = 3600, maxPending: Int = 3) {
        self.window = window
        self.warnAtRequests = warnAtRequests
        self.maxRequests = maxRequests
        self.denialsBeforePause = denialsBeforePause
        self.pauseDuration = pauseDuration
        self.maxPending = maxPending
    }

    public static let standard = ApprovalPromptPolicy()

    /// One past request of a relationship.
    public struct Record: Sendable, Hashable {
        public var createdAt: Date
        /// The customer's decision, if one was made.
        public var decision: ApprovalDecision?
        public var isOpen: Bool

        public init(createdAt: Date, decision: ApprovalDecision?, isOpen: Bool = false) {
            self.createdAt = createdAt
            self.decision = decision
            self.isOpen = isOpen
        }
    }

    public enum Verdict: Sendable, Hashable {
        /// Deliver the prompt. `showWarning` is true when the customer has already received several.
        case allow(requestsInWindow: Int, showWarning: Bool)
        /// Too many requests: refuse with `Retry-After`.
        case rateLimited(retryAfter: TimeInterval)
        /// The customer denied or reported repeatedly: auto-deny without prompting until `until`.
        case autoDeny(until: Date)
    }

    /// The verdict for a **new** request given the relationship's history.
    public func evaluate(history: [Record], now: Date) -> Verdict {
        let recent = history.filter { now.timeIntervalSince($0.createdAt) < window && $0.createdAt <= now }
        let refusals = recent.filter { $0.decision == .deny || $0.decision == .report }
        if refusals.count >= denialsBeforePause, let last = refusals.map(\.createdAt).max() {
            let until = last.addingTimeInterval(pauseDuration)
            if until > now { return .autoDeny(until: until) }
        }
        if history.filter(\.isOpen).count >= maxPending { return .rateLimited(retryAfter: 30) }
        if recent.count >= maxRequests, let oldest = recent.map(\.createdAt).min() {
            return .rateLimited(retryAfter: max(1, oldest.addingTimeInterval(window).timeIntervalSince(now)))
        }
        return .allow(requestsInWindow: recent.count + 1, showWarning: recent.count + 1 >= warnAtRequests)
    }
}
