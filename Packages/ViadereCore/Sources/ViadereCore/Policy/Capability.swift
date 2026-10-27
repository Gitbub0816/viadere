import Foundation

/// A typed capability a business can request through Viadere (spec §6.4). Capabilities are the unit of **entitlement** (what a
/// business may ever do), of **API key scope** (what one credential may do) and of **policy** (what may happen now).
///
/// Wire form: the stable string ID (`message.send`). Unknown IDs decode as `.unknown(raw)` so older clients and servers never fail on
/// a newer catalog; an unknown capability is **never** allowed by the policy engine (fail closed).
public enum Capability: Hashable, Sendable, Codable, CustomStringConvertible {
    case messageSend
    case contactReachable
    case consentRequest
    case authChallenge
    case transactionApprove
    case ageMinimum
    case identityName
    case identityAddress
    case identityVerified
    case unknown(String)

    /// Every known capability, in catalog order.
    public static let known: [Capability] = [
        .messageSend, .contactReachable, .consentRequest, .authChallenge, .transactionApprove,
        .ageMinimum, .identityName, .identityAddress, .identityVerified,
    ]

    /// Tier M (messaging): what every verified business gets by default and nothing more.
    public static let messaging: [Capability] = [.messageSend, .contactReachable, .consentRequest]

    /// Capabilities with an implemented endpoint today (messaging plus the approval-class interaction kinds). `age.minimum` and
    /// `identity.*` exist in the catalog and the policy engine; their endpoints ship with the Verify work package.
    public static let operational: [Capability] = messaging + [.authChallenge, .transactionApprove]

    public init(rawValue: String) {
        self = Self.known.first { $0.rawValue == rawValue } ?? .unknown(rawValue)
    }

    public var rawValue: String {
        switch self {
        case .messageSend: "message.send"
        case .contactReachable: "contact.reachable"
        case .consentRequest: "consent.request"
        case .authChallenge: "auth.challenge"
        case .transactionApprove: "transaction.approve"
        case .ageMinimum: "age.minimum"
        case .identityName: "identity.name"
        case .identityAddress: "identity.address"
        case .identityVerified: "identity.verified"
        case .unknown(let raw): raw
        }
    }

    public var description: String { rawValue }

    /// False for `.unknown`.
    public var isKnown: Bool {
        if case .unknown = self { return false }
        return true
    }

    /// The catalog entry, or `nil` for an unknown capability.
    public var definition: CapabilityDefinition? { CapabilityCatalog.definition(for: self) }

    public init(from decoder: any Decoder) throws {
        self.init(rawValue: try decoder.singleValueContainer().decode(String.self))
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(rawValue)
    }

    /// The capability an interaction of `kind` exercises (SEC-API-003): `authenticate` is `auth.challenge`, `authorize` is
    /// `transaction.approve`, every other known kind is `message.send`. An unknown kind maps to `.unknown`, which is never allowed.
    public static func required(forInteractionKind kind: InteractionKind) -> Capability {
        switch kind {
        case .authenticate: .authChallenge
        case .authorize: .transactionApprove
        case .confirm, .choose, .acknowledge, .reply, .status, .reward, .ticket, .message: .messageSend
        case .unknown(let raw): .unknown("interaction.\(raw)")
        }
    }
}

/// Business risk tiers (spec §8.2). A business holds a **set** of tiers; a tier never implies capabilities by itself, it is only a
/// precondition for being granted the capabilities that name it as their minimum.
public enum BusinessRiskTier: String, Sendable, Codable, CaseIterable, Hashable, Comparable {
    /// Messaging: basic verified business and messaging policies.
    case m = "M"
    /// Approvals: stronger integration security, enrollment controls, approval-specific review.
    case a = "A"
    /// Verified attributes: purpose assessment, data minimization, consent UX, retention rules.
    case v = "V"
    /// Enterprise / regulated: mTLS or private connectivity, audit exports, contractual controls.
    case e = "E"

    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }

    /// What every verified business holds without any grant.
    public static let baseline: Set<BusinessRiskTier> = [.m]
}
