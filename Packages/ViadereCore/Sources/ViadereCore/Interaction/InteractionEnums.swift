import Foundation

/// The structured interaction kinds (spec §5). Extensible: unrecognized kinds decode as
/// `.unknown(rawValue)` so older clients never fail on newer servers. Unknown kinds are
/// treated as maximally sensitive and are never rendered as actionable.
public enum InteractionKind: Hashable, Sendable, Codable, CustomStringConvertible {
    case authenticate, authorize, confirm, choose, acknowledge, reply, status, reward, ticket, message
    case unknown(String)

    /// All known kinds.
    public static let known: [InteractionKind] = [
        .authenticate, .authorize, .confirm, .choose, .acknowledge, .reply, .status, .reward, .ticket, .message,
    ]

    public init(rawValue: String) {
        self = Self.known.first { $0.rawValue == rawValue } ?? .unknown(rawValue)
    }

    public var rawValue: String {
        switch self {
        case .authenticate: "authenticate"
        case .authorize: "authorize"
        case .confirm: "confirm"
        case .choose: "choose"
        case .acknowledge: "acknowledge"
        case .reply: "reply"
        case .status: "status"
        case .reward: "reward"
        case .ticket: "ticket"
        case .message: "message"
        case .unknown(let raw): raw
        }
    }

    public var description: String { rawValue }

    /// Kinds that represent a security or financial decision. These always require a
    /// device-bound signature and are never satisfiable by an SMS/RCS text reply.
    public var isSecuritySensitive: Bool {
        switch self {
        case .authenticate, .authorize, .unknown: true
        default: false
        }
    }

    public init(from decoder: any Decoder) throws {
        self.init(rawValue: try decoder.singleValueContainer().decode(String.self))
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }
}

/// Purpose scopes (spec §4). Consent is granted per purpose.
public enum InteractionPurpose: String, Sendable, Codable, CaseIterable, Hashable {
    case security
    case accountService
    case transactional
    case support
    case marketing
    case rewards

    /// Essential purposes are independent of marketing consent.
    public var isEssential: Bool { self == .security || self == .accountService || self == .transactional }

    /// Whether the consumer can switch this purpose off while staying connected.
    /// Security and account-service notices can only stop by disconnecting.
    public var isRevocable: Bool { self != .security && self != .accountService }

    /// Whether the purpose is on when a relationship is created. Marketing and rewards are opt-in.
    public var isGrantedByDefault: Bool { self != .marketing && self != .rewards }
}

/// Delivery priority requested by the business. Viadere clamps it (`Interaction.effectivePriority`);
/// businesses cannot buy a security-priority override.
public enum InteractionPriority: String, Sendable, Codable, CaseIterable, Comparable {
    case low, normal, high, urgent

    var rank: Int {
        switch self {
        case .low: 0
        case .normal: 1
        case .high: 2
        case .urgent: 3
        }
    }

    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rank < rhs.rank }
}

/// Sensitivity of an interaction; drives `RequiredAssurance` and channel rendering.
public enum Sensitivity: String, Sendable, Codable, CaseIterable, Comparable {
    case low, standard, high, critical

    var rank: Int {
        switch self {
        case .low: 0
        case .standard: 1
        case .high: 2
        case .critical: 3
        }
    }

    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rank < rhs.rank }
}

/// Delivery channels.
public enum Channel: String, Sendable, Codable, CaseIterable, Hashable {
    /// APNs actionable notification (incl. Apple Watch mirroring).
    case nativePush
    /// Inside the Viadere app.
    case inApp
    /// Secure Viadere web flow (passkey sign-in).
    case web
    case sms
    case rcs
    /// Apple Messages for Business (future; policy-gated).
    case appleMessagesForBusiness

    /// Channels whose replies are unauthenticated text (no device-bound signature possible).
    public var isTextMessaging: Bool { self == .sms || self == .rcs || self == .appleMessagesForBusiness }
}

/// The semantic role of a requested action button.
public enum ActionRole: String, Sendable, Codable, CaseIterable {
    case approve, deny, confirm, decline, select, reply, acknowledge, open, report, redeem
}

/// A button/action the business requests the consumer be offered.
public struct RequestedAction: Codable, Sendable, Hashable {
    /// Stable identifier (≤ 64 chars, `[A-Za-z0-9_.-]`).
    public var id: String
    /// Short label (≤ 32 chars).
    public var label: String
    public var role: ActionRole

    public init(id: String, label: String, role: ActionRole) {
        self.id = id
        self.label = label
        self.role = role
    }
}

/// The consumer relationship an interaction is scoped to.
public struct RelationshipScope: Codable, Sendable, Hashable {
    public var consumerId: ConsumerID
    public var relationshipId: RelationshipID
    /// Optional business-side account reference shown to the user, e.g. "Checking ••1234" (≤ 64 chars).
    public var accountReference: String?
    /// The business-facing pairwise reference of the customer (`SubjectRef`). Set only on what a **business** sees; the
    /// consumer's own copy of an interaction never carries it.
    public var subjectRef: SubjectRef?

    public init(consumerId: ConsumerID, relationshipId: RelationshipID, accountReference: String? = nil, subjectRef: SubjectRef? = nil) {
        self.consumerId = consumerId
        self.relationshipId = relationshipId
        self.accountReference = accountReference
        self.subjectRef = subjectRef
    }
}

/// A risk signal shown to the user, e.g. `new_device`, `unusual_location`.
public struct RiskIndicator: Codable, Sendable, Hashable {
    public enum Severity: String, Codable, Sendable { case info, warning, high }
    /// Machine code, `[a-z0-9_]` ≤ 40 chars.
    public var code: String
    /// Human label ≤ 80 chars.
    public var label: String
    public var severity: Severity

    public init(code: String, label: String, severity: Severity) {
        self.code = code
        self.label = label
        self.severity = severity
    }
}
