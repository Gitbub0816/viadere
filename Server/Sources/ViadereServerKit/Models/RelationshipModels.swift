import Fluent
import Foundation
import ViadereCore
import enum ViadereCore.Channel

final class RelationshipRecord: Model, @unchecked Sendable {
    static let schema = "relationships"
    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "business_id") var businessId: UUID
    /// `active` or `disconnected`.
    @Field(key: "status") var status: String
    @Field(key: "source") var source: String
    @Field(key: "connected_at") var connectedAt: Date
    @OptionalField(key: "disconnected_at") var disconnectedAt: Date?
    @Field(key: "last_activity_at") var lastActivityAt: Date
    /// `subject_ref` of this (business, consumer) pair: the only customer identifier a business can address. Set when the row is
    /// created (`SubjectRefMiddleware`) or by the backfill job for older rows; unique per business.
    @OptionalField(key: "subject_ref") var subjectRef: String?
    /// The link session that created or extended this connection, and the digest of the device statement the business confirmed (WP-C1).
    @OptionalField(key: "link_session_id") var linkSessionId: UUID?
    @OptionalField(key: "evidence_digest") var evidenceDigest: String?
    /// Capabilities the customer granted through link sessions, comma-separated (spec v4 D2 `CustomerBusinessConnection.scopes`).
    @OptionalField(key: "scopes") var scopes: String?
    /// `ConnectionMethod` raw value (QR, handle, code, link session).
    @OptionalField(key: "connection_method") var connectionMethod: String?
    @OptionalField(key: "linked_at") var linkedAt: Date?
    /// Per-business preferences (spec v4 C7). Marketing is the consent purpose, not a column.
    @Field(key: "pref_muted") var prefMuted: Bool
    @Field(key: "pref_favorite") var prefFavorite: Bool

    init() {}

    init(consumerId: UUID, businessId: UUID, source: ConnectSource, now: Date) {
        id = UUID()
        self.consumerId = consumerId
        self.businessId = businessId
        status = "active"
        self.source = source.rawValue
        connectedAt = now
        lastActivityAt = now
        connectionMethod = ConnectionMethod(source: source).rawValue
        prefMuted = false
        prefFavorite = false
    }

    /// Status of a connection created by a link session until the business confirms it: never active, listed or addressable.
    static let pendingLink = "pending_link"

    var isActive: Bool { status == "active" }
    var isPendingLink: Bool { status == Self.pendingLink }
    var scopeList: [Capability] { (scopes ?? "").split(separator: ",").map { Capability(rawValue: String($0)) } }
}

/// Append-only consent history: every change is a new row with `version = previous + 1`.
final class ConsentGrantRecord: Model, @unchecked Sendable {
    static let schema = "consent_grants"
    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "relationship_id") var relationshipId: UUID
    @Field(key: "purpose") var purpose: String
    @Field(key: "granted") var granted: Bool
    @Field(key: "version") var version: Int
    @Field(key: "policy_version") var policyVersion: String
    @Field(key: "source") var source: String
    @Field(key: "channels") var channels: String
    @Field(key: "created_at") var createdAt: Date

    init() {}

    init(consumerId: UUID, businessId: UUID, relationshipId: UUID, purpose: InteractionPurpose, granted: Bool, version: Int,
         policyVersion: String, source: ConsentSource, channels: [Channel], now: Date) {
        id = UUID()
        self.consumerId = consumerId
        self.businessId = businessId
        self.relationshipId = relationshipId
        self.purpose = purpose.rawValue
        self.granted = granted
        self.version = version
        self.policyVersion = policyVersion
        self.source = source.rawValue
        self.channels = channels.map(\.rawValue).joined(separator: ",")
        createdAt = now
    }

    var dto: ConsentGrant? {
        guard let purpose = InteractionPurpose(rawValue: purpose), let id else { return nil }
        return ConsentGrant(id: ConsentGrantID(id), consumerId: ConsumerID(consumerId), businessId: BusinessID(businessId),
                            relationshipId: RelationshipID(relationshipId), purpose: purpose, granted: granted, version: version,
                            policyVersion: policyVersion, source: ConsentSource(rawValue: source) ?? .system,
                            channels: channels.split(separator: ",").compactMap { Channel(rawValue: String($0)) },
                            createdAt: createdAt, updatedAt: createdAt)
    }
}

final class DelegationGrantRecord: Model, @unchecked Sendable {
    static let schema = "delegation_grants"
    @ID(key: .id) var id: UUID?
    @Field(key: "grantor_id") var grantorId: UUID
    @Field(key: "delegate_id") var delegateId: UUID
    @Field(key: "role") var role: String
    @Field(key: "purposes") var purposes: String
    @Field(key: "business_ids") var businessIds: String
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "revoked_at") var revokedAt: Date?
    /// The grantor's own label for the delegate (AES-GCM; a name is personal data).
    @OptionalField(key: "label_ciphertext") var labelCiphertext: String?
    /// Set once the `delegation.expired` audit event has been written.
    @Field(key: "expiry_recorded") var expiryRecorded: Bool

    init() {}

    var purposeSet: [InteractionPurpose] { purposes.split(separator: ",").compactMap { InteractionPurpose(rawValue: String($0)) } }
    var businessIdSet: [UUID] { businessIds.split(separator: ",").compactMap { UUID(uuidString: String($0)) } }
    var roleValue: DelegationGrant.Role { DelegationGrant.Role(rawValue: role) ?? .viewer }

    func isActive(at now: Date) -> Bool { revokedAt == nil && now < expiresAt }

    /// Whether the grant covers `purpose` at `businessId` right now.
    func permits(purpose: InteractionPurpose, businessId: UUID, now: Date) -> Bool {
        isActive(at: now) && purposeSet.contains(purpose) && businessIdSet.contains(businessId)
    }

    var dto: DelegationGrant? {
        guard let id else { return nil }
        return DelegationGrant(id: DelegationID(id), grantorId: ConsumerID(grantorId), delegateId: ConsumerID(delegateId),
                               role: roleValue, purposes: purposeSet, businessIds: businessIdSet.map { BusinessID($0) },
                               createdAt: createdAt, expiresAt: expiresAt, revokedAt: revokedAt)
    }
}

final class APNsTokenRecord: Model, @unchecked Sendable {
    static let schema = "apns_tokens"
    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "device_id") var deviceId: UUID
    @Field(key: "token") var token: String
    @Field(key: "environment") var environment: String
    @Field(key: "bundle_id") var bundleId: String
    @Field(key: "updated_at") var updatedAt: Date
    @OptionalField(key: "invalidated_at") var invalidatedAt: Date?

    init() {}

    init(consumerId: UUID, deviceId: UUID, registration: APNsTokenRegistration, now: Date) {
        id = UUID()
        self.consumerId = consumerId
        self.deviceId = deviceId
        token = registration.token
        environment = registration.environment.rawValue
        bundleId = registration.bundleId
        updatedAt = now
    }

    var record: APNsTokenRegistrationRecord {
        APNsTokenRegistrationRecord(token: token, environment: APNsTokenRegistration.Environment(rawValue: environment) ?? .production,
                                    bundleId: bundleId)
    }
}

final class LiveActivityTokenRecord: Model, @unchecked Sendable {
    static let schema = "live_activity_tokens"
    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "device_id") var deviceId: UUID
    @Field(key: "kind") var kind: String
    @OptionalField(key: "activity_id") var activityId: String?
    @OptionalField(key: "business_id") var businessId: UUID?
    @OptionalField(key: "interaction_id") var interactionId: UUID?
    @Field(key: "push_token") var pushToken: String
    @Field(key: "updated_at") var updatedAt: Date

    init() {}
}
