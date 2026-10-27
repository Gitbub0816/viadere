import Foundation

/// Who performed an audited action.
public struct AuditActor: Codable, Sendable, Hashable {
    public enum Kind: String, Codable, Sendable { case consumer, device, business, businessAPIKey, gateway, system, operator_ = "operator" }
    public var kind: Kind
    /// Opaque identifier of the actor (lowercase UUID or key id); never a phone number or secret.
    public var id: String?

    public init(kind: Kind, id: String? = nil) {
        self.kind = kind
        self.id = id
    }
}

/// An immutable audit record. `metadata` must be redacted: no message bodies, tokens,
/// full phone numbers, or secrets (use `PhoneNumber.masked`).
public struct AuditEvent: Codable, Sendable, Hashable, Identifiable {
    public enum Outcome: String, Codable, Sendable { case success, failure, denied }

    public var id: AuditEventID
    public var occurredAt: Date
    public var actor: AuditActor
    /// Dotted action name, e.g. `interaction.decided`, `gateway.opt_out`, `device.revoked`.
    public var action: String
    public var outcome: Outcome
    public var consumerId: ConsumerID?
    public var businessId: BusinessID?
    public var subjectType: String?
    public var subjectId: String?
    public var correlationId: String?
    public var metadata: [String: String]

    public init(id: AuditEventID = AuditEventID(), occurredAt: Date, actor: AuditActor, action: String, outcome: Outcome,
                consumerId: ConsumerID? = nil, businessId: BusinessID? = nil, subjectType: String? = nil,
                subjectId: String? = nil, correlationId: String? = nil, metadata: [String: String] = [:]) {
        self.id = id
        self.occurredAt = occurredAt
        self.actor = actor
        self.action = action
        self.outcome = outcome
        self.consumerId = consumerId
        self.businessId = businessId
        self.subjectType = subjectType
        self.subjectId = subjectId
        self.correlationId = correlationId
        self.metadata = metadata
    }
}

/// Household / delegated access grant (spec §12). Sensitive purposes are never inherited
/// implicitly: `security` must be listed explicitly and the grant must expire.
public struct DelegationGrant: Codable, Sendable, Hashable, Identifiable {
    public enum Role: String, Codable, Sendable { case viewer, manager }

    public var id: DelegationID
    public var grantorId: ConsumerID
    public var delegateId: ConsumerID
    public var role: Role
    /// Explicit purposes delegated. Empty = nothing.
    public var purposes: [InteractionPurpose]
    /// Explicit businesses in scope. Empty = nothing.
    public var businessIds: [BusinessID]
    public var createdAt: Date
    public var expiresAt: Date
    public var revokedAt: Date?

    public init(id: DelegationID, grantorId: ConsumerID, delegateId: ConsumerID, role: Role, purposes: [InteractionPurpose],
                businessIds: [BusinessID], createdAt: Date, expiresAt: Date, revokedAt: Date? = nil) {
        self.id = id
        self.grantorId = grantorId
        self.delegateId = delegateId
        self.role = role
        self.purposes = purposes
        self.businessIds = businessIds
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.revokedAt = revokedAt
    }

    /// Maximum delegation lifetime.
    public static let maxLifetime: TimeInterval = 365 * 24 * 3600

    /// Whether the delegate may act for `purpose` at `businessId` at time `now`.
    /// Delegates can never approve `authenticate`/`authorize` interactions (checked by the server).
    public func permits(purpose: InteractionPurpose, businessId: BusinessID, now: Date) -> Bool {
        revokedAt == nil && now < expiresAt && purposes.contains(purpose) && businessIds.contains(businessId)
    }

    /// Structural validity: no self-delegation, bounded lifetime, non-empty explicit scopes.
    public var isValid: Bool {
        grantorId != delegateId && !purposes.isEmpty && !businessIds.isEmpty
            && expiresAt > createdAt && expiresAt.timeIntervalSince(createdAt) <= Self.maxLifetime
    }
}
