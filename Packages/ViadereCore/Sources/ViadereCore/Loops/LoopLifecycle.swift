import Crypto
import Foundation

/// The state of one Loop revision in the review pipeline (plan section 4.12, FX-3). Every revision of every Loop walks the same path;
/// there is no state that skips human review, and a revision past `draft` is immutable (an edit is a new revision).
public enum LoopRevisionState: String, Sendable, Codable, CaseIterable, Hashable {
    /// Being edited (Studio). The server stores no draft today: a submission creates the revision already past this state.
    case draft
    /// The automated hard gate failed; a human cannot override it (only a rule-set change can).
    case validationFailed = "validation_failed"
    /// Passed the hard gate; waiting for one (or two, for high risk) Viadere reviewers.
    case inReview = "in_review"
    case changesRequested = "changes_requested"
    case rejected
    /// Approved by enough distinct reviewers for exactly its `definition_hash`; signing follows in the same transaction.
    case approved
    /// Signed and served (subject to rollout, switches and the publication's own status).
    case published
    /// A later revision of the same Loop was published; in-flight instances pinned here may finish, no new instance starts.
    case superseded
    /// Withdrawn by the author before a decision.
    case withdrawn

    /// Content can never change in these states (enforced again by a database trigger).
    public var isImmutable: Bool { self != .draft }

    /// Whether the pipeline is over for this revision (no review action applies).
    public var isClosed: Bool { [.validationFailed, .changesRequested, .rejected, .published, .superseded, .withdrawn].contains(self) }

    /// The legal moves. Anything else is refused by the server's compare-and-swap.
    public static func canMove(from: LoopRevisionState, to: LoopRevisionState) -> Bool {
        switch (from, to) {
        case (.draft, .validationFailed), (.draft, .inReview): true
        case (.inReview, .changesRequested), (.inReview, .rejected), (.inReview, .approved), (.inReview, .withdrawn): true
        case (.approved, .published): true
        case (.published, .superseded): true
        default: false
        }
    }
}

/// The state of a customer's Loop instance.
public enum LoopInstanceState: String, Sendable, Codable, CaseIterable, Hashable {
    /// In progress: the customer is on `currentStepId`.
    case active
    /// A delivering action was recorded and the customer reached the result step; waiting for the business's outcome.
    case submitted
    /// Finished: a final outcome arrived, or a terminal step was reached without anything to deliver.
    case completed
    /// Ended by Viadere: consent revoked, publication revoked, business switched off for good.
    case cancelled
    /// Passed its expiry before it was submitted.
    case expired

    public var isOpen: Bool { self == .active || self == .submitted }
}

/// Staged rollout of a publication (plan section 4.12 "allow-list rollout"). A new publication starts with the allow-list only
/// (`percent == 0`): the operator adds the business's test customers, then raises the percentage. The bucket is a deterministic hash of the
/// customer and the publication, so a customer neither flips in and out nor lands in the same bucket for every Loop.
public enum LoopRollout {
    /// `0..<100`.
    public static func bucket(consumerId: UUID, publicationId: UUID) -> Int {
        let input = Data("viadere-loop-rollout-v1|\(publicationId.uuidString.lowercased())|\(consumerId.uuidString.lowercased())".utf8)
        let digest = Array(SHA256.hash(data: input))
        let value = (UInt32(digest[0]) << 24) | (UInt32(digest[1]) << 16) | (UInt32(digest[2]) << 8) | UInt32(digest[3])
        return Int(value % 100)
    }

    public static func isEligible(consumerId: UUID, publicationId: UUID, percent: Int, allowListed: Bool) -> Bool {
        if allowListed { return true }
        guard percent > 0 else { return false }
        return bucket(consumerId: consumerId, publicationId: publicationId) < min(percent, 100)
    }
}

/// Customer reports and the automatic suspension (plan section 4.12 "reports above a threshold auto-suspend the publication pending
/// review"). Counted per **distinct reporter**, so one account cannot keep a Loop up or take it down alone beyond its one vote.
public enum LoopReportPolicy {
    /// Distinct reporters that always suspend, whatever the traffic.
    public static let absoluteThreshold = 5
    /// Or this share of distinct customers who started an instance (with at least `minimumReporters`).
    public static let rateThreshold = 0.05
    public static let minimumReporters = 3

    public static func shouldAutoSuspend(distinctReporters: Int, distinctCustomers: Int) -> Bool {
        if distinctReporters >= absoluteThreshold { return true }
        guard distinctReporters >= minimumReporters, distinctCustomers > 0 else { return false }
        return Double(distinctReporters) / Double(distinctCustomers) >= rateThreshold
    }
}

/// Why a customer reports a Loop.
public enum LoopReportReason: String, Sendable, Codable, CaseIterable, Hashable {
    case misleading
    case unsafe
    case spam
    /// The Loop asked for health information (FX-4).
    case healthDataRequested = "health_data_requested"
    case impersonation
    case other
}

// MARK: - Consent text catalog (WP-3.5)

/// One comprehension question of the Loop education (spec A6.2). The server checks the answers; the device only shows them.
public struct LoopComprehensionCheck: Sendable, Hashable, Codable {
    public struct Option: Sendable, Hashable, Codable {
        public var id: String
        public var label: String
        public init(id: String, label: String) {
            self.id = id
            self.label = label
        }
    }

    public var id: String
    public var question: String
    public var options: [Option]
    /// Not sent to the device in `LoopConsentText` (the server verifies); kept here so the catalog is one value.
    public var correctOptionId: String

    public init(id: String, question: String, options: [Option], correctOptionId: String) {
        self.id = id
        self.question = question
        self.options = options
        self.correctOptionId = correctOptionId
    }
}

/// A version of the counsel-approved Loop consent text (plan WP-3.5, open decision D6.6). The digest covers every word the customer is
/// shown, including the per-business authorization template, so a consent record proves what was agreed to.
public struct LoopConsentTextVersion: Sendable, Hashable {
    public var version: Int
    public var title: String
    public var paragraphs: [String]
    public var checks: [LoopComprehensionCheck]
    /// Per-business authorization text; `{business}` is replaced by the verified display name.
    public var businessAuthorization: String
    public var agreeLabel: String

    public init(version: Int, title: String, paragraphs: [String], checks: [LoopComprehensionCheck], businessAuthorization: String, agreeLabel: String) {
        self.version = version
        self.title = title
        self.paragraphs = paragraphs
        self.checks = checks
        self.businessAuthorization = businessAuthorization
        self.agreeLabel = agreeLabel
    }

    public var jsonValue: JSONValue {
        .object([
            "v": .integer(Int64(version)), "title": .string(title), "paragraphs": .array(paragraphs.map { .string($0) }),
            "checks": .array(checks.map { check in
                .object(["id": .string(check.id), "question": .string(check.question), "correct": .string(check.correctOptionId),
                         "options": .array(check.options.map { .object(["id": .string($0.id), "label": .string($0.label)]) })])
            }),
            "business_authorization": .string(businessAuthorization), "agree_label": .string(agreeLabel),
        ])
    }

    /// `sha256:<hex>` of the canonical JSON of `jsonValue`.
    public var digest: String { (try? ContractHash.sha256(jsonValue)) ?? "" }

    /// Whether `answers` (check id → option id) answer every check correctly, and nothing else.
    public func passes(_ answers: [String: String]) -> Bool {
        Set(answers.keys) == Set(checks.map(\.id)) && checks.allSatisfy { answers[$0.id] == $0.correctOptionId }
    }
}

/// The catalog of Loop consent texts. The current version is the newest; a bump forces every customer to consent again (existing
/// grants at an older version stop authorizing anything, `LoopAccessPolicy` `consent_outdated`).
public enum LoopConsentCatalog {
    /// Draft wording pending counsel review (plan D6.6, K5). Changing any word requires a new version.
    public static let versions: [LoopConsentTextVersion] = [
        LoopConsentTextVersion(
            version: 1,
            title: "Requests built by businesses",
            paragraphs: [
                "Some businesses you use can send you short requests, like choosing a pickup time or checking in. Each one is built by that business, not by Viadere, and always says who built it.",
                "What you enter goes to the business that built the request. Viadere stores it so the business can answer, and checks every request before it reaches you.",
                "Viadere reviewing a request does not mean the business will do what you ask. The request shows whether the business confirmed, declined or hasn't answered.",
                "Don't share health details, passwords or card numbers in these requests. You can report a request, and you can turn this off at any time in Settings.",
            ],
            checks: [
                LoopComprehensionCheck(id: "author", question: "Who builds these requests?",
                                       options: [.init(id: "business", label: "The business named on the request"), .init(id: "viadere", label: "Viadere")],
                                       correctOptionId: "business"),
                LoopComprehensionCheck(id: "recipient", question: "Who receives what you enter?",
                                       options: [.init(id: "business", label: "The business that built the request"), .init(id: "everyone", label: "Every business you use")],
                                       correctOptionId: "business"),
            ],
            businessAuthorization: "Allow {business} to send you requests it built. You can stop this at any time.",
            agreeLabel: "Turn on"),
    ]

    public static var current: LoopConsentTextVersion { versions.max { $0.version < $1.version }! }

    public static func version(_ number: Int) -> LoopConsentTextVersion? { versions.first { $0.version == number } }
}
