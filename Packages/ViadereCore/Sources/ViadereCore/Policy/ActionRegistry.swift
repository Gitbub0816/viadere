import Foundation

/// The id of a registered action (spec v4 A4). Stable strings; an unknown id is never executable.
public struct ActionID: RawRepresentable, Hashable, Sendable, Codable, CustomStringConvertible {
    public let rawValue: String
    public init(rawValue: String) { self.rawValue = rawValue }
    public init(_ rawValue: String) { self.rawValue = rawValue }
    public var description: String { rawValue }

    public init(from decoder: any Decoder) throws { rawValue = try decoder.singleValueContainer().decode(String.self) }
    public func encode(to encoder: any Encoder) throws {
        var c = encoder.singleValueContainer()
        try c.encode(rawValue)
    }
}

public enum ActionRisk: String, Codable, Sendable, Hashable, Comparable {
    case low, medium, high
    case unknown

    public init(from decoder: any Decoder) throws {
        self = ActionRisk(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .unknown
    }

    var rank: Int {
        switch self {
        case .low: 0
        case .medium: 1
        case .high, .unknown: 2
        }
    }

    public static func < (lhs: ActionRisk, rhs: ActionRisk) -> Bool { lhs.rank < rhs.rank }

    /// The risk of a capability's sensitivity.
    public init(sensitivity: Sensitivity) {
        switch sensitivity {
        case .low, .standard: self = .low
        case .high, .critical: self = .high
        }
    }
}

/// Where an action's outcome may be routed (spec v4 A2, A7).
public enum ActionRouting: String, Codable, Sendable, Hashable, CaseIterable {
    /// To the customer's enrolled device (push hint + authenticated fetch).
    case device
    /// To the business's hosted inbox in the console (Loops, hosted mode).
    case hostedInbox = "hosted_inbox"
    /// To an authenticated, configured business endpoint (signed webhook).
    case connectedWebhook = "connected_webhook"
    /// Through a vetted integration connector.
    case integration
}

/// What makes repeating an action safe.
public enum ActionIdempotency: String, Codable, Sendable, Hashable {
    /// The business's own request id (same id + same body replays; a different body is a conflict).
    case businessRequestId = "business_request_id"
    /// A single-use server record consumed by compare-and-swap (a second attempt is a conflict).
    case singleUseRecord = "single_use_record"
}

/// What the audit trail records.
public enum ActionAuditRequirement: String, Codable, Sendable, Hashable {
    /// Every attempt, allowed or refused.
    case everyAttempt = "every_attempt"
    /// Every outcome and every refusal.
    case outcomesAndDenials = "outcomes_and_denials"
}

public enum ActionAvailability: String, Codable, Sendable, Hashable {
    /// Implemented: a business may bind it now.
    case live
    /// Registered for a later phase (Loops): visible in the catalog, never executable.
    case planned
}

/// One registered action (spec v4 A4): a business can bind a button, a link session or a request **only** to an entry of this registry and choose
/// among its allowed labels; it can never name an arbitrary operation with a string.
public struct ActionDefinition: Sendable, Hashable {
    public let id: ActionID
    /// Bumped whenever the action's inputs or meaning change; an instance pins the version it was created with.
    public let schemaVersion: Int
    public let risk: ActionRisk
    /// The key of the Viadere-owned confirmation wording the app shows (the business never supplies security-critical text).
    public let confirmationKey: String
    public let idempotency: ActionIdempotency
    /// Allowed lifetime of one instance, in seconds, and the default.
    public let timeout: ClosedRange<Int>
    public let defaultTimeout: Int
    public let routing: Set<ActionRouting>
    public let audit: ActionAuditRequirement
    /// The capability (entitlement, key scope, policy) the action needs, if any.
    public let capability: Capability?
    /// May be granted to a connection by a link session.
    public let linkable: Bool
    /// May run in a Viadere-hosted Loop without a business backend (spec v4 A4 "Hosted support").
    public let hosted: Bool
    public let availability: ActionAvailability

    public var isLive: Bool { availability == .live }
}

/// The server-side action registry (spec v4 A4), shared by the server and clients. Today it governs link-session capabilities and Approve requests;
/// the Loops runtime binds to the same entries later (the `loop.*` entries are registered as `planned`).
public enum ActionRegistry {
    /// Lifetime of an approval request (`POST /v1/business/approve/requests`, `expires_in_seconds`).
    public static let approveAuthentication = ActionDefinition(
        id: ActionID("approve.authentication"), schemaVersion: 1, risk: .high, confirmationKey: "action.approve.authentication.confirm",
        idempotency: .businessRequestId, timeout: 30...600, defaultTimeout: 120, routing: [.device], audit: .everyAttempt,
        capability: .authChallenge, linkable: false, hosted: false, availability: .live)
    public static let approveTransaction = ActionDefinition(
        id: ActionID("approve.transaction"), schemaVersion: 1, risk: .high, confirmationKey: "action.approve.transaction.confirm",
        idempotency: .businessRequestId, timeout: 30...600, defaultTimeout: 120, routing: [.device], audit: .everyAttempt,
        capability: .transactionApprove, linkable: false, hosted: false, availability: .live)
    /// Linking a customer's app to the business's customer record (WP-C1).
    public static let linkConnect = ActionDefinition(
        id: ActionID("link.connect"), schemaVersion: 1, risk: .medium, confirmationKey: "action.link.connect.confirm",
        idempotency: .singleUseRecord, timeout: LinkSessionLimits.minLifetime...LinkSessionLimits.maxLifetime, defaultTimeout: LinkSessionLimits.maxLifetime,
        routing: [.device, .connectedWebhook], audit: .everyAttempt, capability: nil, linkable: false, hosted: false, availability: .live)

    /// The scope grants a link session may carry: one per linkable capability.
    public static func grant(_ capability: Capability) -> ActionDefinition? { grants.first { $0.capability == capability } }

    static let grants: [ActionDefinition] = [Capability.messageSend, .contactReachable, .consentRequest, .authChallenge, .transactionApprove].map { capability in
        let risk = ActionRisk(sensitivity: capability.definition?.sensitivity ?? .critical)
        return ActionDefinition(id: ActionID("connection.grant." + capability.rawValue), schemaVersion: 1, risk: risk,
                                confirmationKey: "action.connection.grant.\(capability.rawValue).confirm", idempotency: .singleUseRecord,
                                timeout: LinkSessionLimits.minLifetime...LinkSessionLimits.maxLifetime, defaultTimeout: LinkSessionLimits.maxLifetime,
                                routing: [.device], audit: .everyAttempt, capability: capability, linkable: true, hosted: false, availability: .live)
    }

    /// Loop actions of spec v4 A4, registered now so definitions can be validated against them later. **Not executable** (`planned`).
    public static let loops: [ActionDefinition] = [
        planned("loop.acknowledge", risk: .low, hosted: true),
        planned("loop.request_callback", risk: .low, hosted: true),
        planned("loop.check_in", risk: .medium, hosted: true),
        planned("loop.select_option", risk: .medium, hosted: true),
        planned("loop.approve_estimate", risk: .high, hosted: true),
        // First-party verification module only; never business-authored logic.
        planned("loop.identity_attestation", risk: .high, hosted: false),
        // Approved payment provider and separate commerce controls.
        planned("loop.payment", risk: .high, hosted: false),
    ]

    private static func planned(_ id: String, risk: ActionRisk, hosted: Bool) -> ActionDefinition {
        ActionDefinition(id: ActionID(id), schemaVersion: 1, risk: risk, confirmationKey: "action.\(id).confirm", idempotency: .singleUseRecord,
                         timeout: 60...86_400, defaultTimeout: 3600, routing: hosted ? [.hostedInbox, .connectedWebhook] : [.connectedWebhook],
                         audit: .everyAttempt, capability: nil, linkable: false, hosted: hosted, availability: .planned)
    }

    /// Every registered action.
    public static var all: [ActionDefinition] { [approveAuthentication, approveTransaction, linkConnect] + grants + loops }

    public static func definition(_ id: ActionID) -> ActionDefinition? { all.first { $0.id == id } }

    /// The approval action of an Approve request capability.
    public static func approval(for capability: Capability) -> ActionDefinition? {
        switch capability {
        case .authChallenge: approveAuthentication
        case .transactionApprove: approveTransaction
        default: nil
        }
    }

    /// Invariants (asserted in the unit tests): unique ids, a live grant for every linkable capability, high risk never hosted without a first-party
    /// owner, default timeouts inside their range, and nothing `planned` is linkable.
    public static func audit() -> [String] {
        var problems: [String] = []
        let ids = all.map(\.id.rawValue)
        if Set(ids).count != ids.count { problems.append("duplicate ids") }
        for entry in all {
            if !entry.timeout.contains(entry.defaultTimeout) { problems.append("\(entry.id): default timeout outside range") }
            if entry.availability == .planned && entry.linkable { problems.append("\(entry.id): planned but linkable") }
            if entry.linkable && entry.capability == nil { problems.append("\(entry.id): linkable without capability") }
            if entry.routing.isEmpty { problems.append("\(entry.id): no routing") }
        }
        for capability in Capability.known where capability.definition?.sensitivity ?? .critical >= .high && grant(capability)?.risk != nil {
            if grant(capability)?.risk != .high { problems.append("\(capability): high sensitivity must be high risk") }
        }
        return problems
    }
}
