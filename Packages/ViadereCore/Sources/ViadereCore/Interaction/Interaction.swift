import Foundation

/// A server-issued, single-use challenge bound to one interaction. Devices sign it inside
/// `DecisionPayload`; the server rejects any decision whose challenge does not match or was
/// already consumed. Wire: base64url of 32 random bytes (43 chars).
public struct ChallengeNonce: Hashable, Sendable, Codable, CustomStringConvertible {
    public let value: String

    /// Validates a received nonce (base64url, 22–128 chars).
    public init?(_ value: String) {
        guard Base64URL.isValid(value, minLength: 22, maxLength: 128) else { return nil }
        self.value = value
    }

    /// Generates a fresh 256-bit nonce with the system CSPRNG.
    public static func generate() -> ChallengeNonce {
        ChallengeNonce(unchecked: SecureToken.generate(byteCount: 32))
    }

    private init(unchecked: String) { value = unchecked }

    public var description: String { value }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        guard let nonce = ChallengeNonce(try container.decode(String.self)) else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid challenge nonce")
        }
        self = nonce
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(value)
    }
}

/// The versioned interaction envelope (spec §5).
///
/// Wire format: JSON object with `kind` and a `payload` object whose shape depends on `kind`.
/// Unknown kinds decode with `.unknown` payloads and must not be rendered as actionable.
public struct Interaction: Codable, Sendable, Hashable, Identifiable {
    /// Current envelope schema version. Decoders accept versions `1...currentSchemaVersion`.
    public static let currentSchemaVersion = 1

    public var schemaVersion: Int
    public var id: InteractionID
    public var businessId: BusinessID
    public var scope: RelationshipScope
    public var kind: InteractionKind
    public var purpose: InteractionPurpose
    public var payload: InteractionPayload
    public var requestedActions: [RequestedAction]
    public var priority: InteractionPriority
    public var sensitivity: Sensitivity
    public var allowedChannels: [Channel]
    public var createdAt: Date
    public var expiresAt: Date
    /// Business-supplied idempotency key (1–128 chars). Same key + same business ⇒ same interaction.
    public var idempotencyKey: String
    /// Business correlation identifier for audit (≤ 128 chars).
    public var correlationId: String?
    /// Server-issued challenge the device must sign when deciding.
    public var challenge: ChallengeNonce

    public init(schemaVersion: Int = Interaction.currentSchemaVersion, id: InteractionID = InteractionID(),
                businessId: BusinessID, scope: RelationshipScope, purpose: InteractionPurpose,
                payload: InteractionPayload, requestedActions: [RequestedAction] = [],
                priority: InteractionPriority = .normal, sensitivity: Sensitivity = .standard,
                allowedChannels: [Channel] = [.nativePush, .inApp], createdAt: Date, expiresAt: Date,
                idempotencyKey: String, correlationId: String? = nil, challenge: ChallengeNonce = .generate(),
                kind: InteractionKind? = nil) {
        self.schemaVersion = schemaVersion
        self.id = id
        self.businessId = businessId
        self.scope = scope
        self.kind = kind ?? payload.kind ?? .unknown("unknown")
        self.purpose = purpose
        self.payload = payload
        self.requestedActions = requestedActions
        self.priority = priority
        self.sensitivity = sensitivity
        self.allowedChannels = allowedChannels
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.idempotencyKey = idempotencyKey
        self.correlationId = correlationId
        self.challenge = challenge
    }

    enum CodingKeys: String, CodingKey {
        case schemaVersion, id, businessId, scope, kind, purpose, payload, requestedActions, priority
        case sensitivity, allowedChannels, createdAt, expiresAt, idempotencyKey, correlationId, challenge
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        schemaVersion = try c.decode(Int.self, forKey: .schemaVersion)
        guard (1...Self.currentSchemaVersion).contains(schemaVersion) else {
            throw DecodingError.dataCorruptedError(forKey: .schemaVersion, in: c, debugDescription: "Unsupported schema version")
        }
        id = try c.decode(InteractionID.self, forKey: .id)
        businessId = try c.decode(BusinessID.self, forKey: .businessId)
        scope = try c.decode(RelationshipScope.self, forKey: .scope)
        kind = try c.decode(InteractionKind.self, forKey: .kind)
        // Unknown enum values in these fields fall back to the most conservative interpretation.
        purpose = (try? c.decode(InteractionPurpose.self, forKey: .purpose)) ?? .security
        payload = try InteractionPayload.decode(kind: kind, from: c, forKey: .payload)
        requestedActions = (try? c.decodeIfPresent([RequestedAction].self, forKey: .requestedActions)) ?? []
        priority = (try? c.decode(InteractionPriority.self, forKey: .priority)) ?? .normal
        sensitivity = (try? c.decode(Sensitivity.self, forKey: .sensitivity)) ?? .critical
        let rawChannels = try c.decodeIfPresent([String].self, forKey: .allowedChannels) ?? []
        allowedChannels = rawChannels.compactMap(Channel.init(rawValue:))
        createdAt = try c.decode(Date.self, forKey: .createdAt)
        expiresAt = try c.decode(Date.self, forKey: .expiresAt)
        idempotencyKey = try c.decode(String.self, forKey: .idempotencyKey)
        correlationId = try c.decodeIfPresent(String.self, forKey: .correlationId)
        challenge = try c.decode(ChallengeNonce.self, forKey: .challenge)
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(schemaVersion, forKey: .schemaVersion)
        try c.encode(id, forKey: .id)
        try c.encode(businessId, forKey: .businessId)
        try c.encode(scope, forKey: .scope)
        try c.encode(kind, forKey: .kind)
        try c.encode(purpose, forKey: .purpose)
        try payload.encode(to: &c, forKey: .payload)
        try c.encode(requestedActions, forKey: .requestedActions)
        try c.encode(priority, forKey: .priority)
        try c.encode(sensitivity, forKey: .sensitivity)
        try c.encode(allowedChannels, forKey: .allowedChannels)
        try c.encode(createdAt, forKey: .createdAt)
        try c.encode(expiresAt, forKey: .expiresAt)
        try c.encode(idempotencyKey, forKey: .idempotencyKey)
        try c.encodeIfPresent(correlationId, forKey: .correlationId)
        try c.encode(challenge, forKey: .challenge)
    }

    /// True once `now >= expiresAt`.
    public func isExpired(at now: Date) -> Bool { now >= expiresAt }

    /// Priority after Trust-Engine clamping: marketing/rewards never exceed `.normal`;
    /// only `security` may be `.urgent` (others cap at `.high`). Payment cannot change this.
    public var effectivePriority: InteractionPriority {
        switch purpose {
        case .marketing, .rewards: min(priority, .normal)
        case .security: priority
        default: min(priority, .high)
        }
    }

    /// Effective sensitivity: security-sensitive kinds are never below `.standard`, and unknown kinds are `.critical`.
    public var effectiveSensitivity: Sensitivity {
        if case .unknown = kind { return .critical }
        if kind.isSecuritySensitive { return max(sensitivity, .standard) }
        return sensitivity
    }

    /// The assurance a decision on this interaction must carry.
    public var requiredAssurance: RequiredAssurance { AssurancePolicy.requiredAssurance(for: self) }
}
