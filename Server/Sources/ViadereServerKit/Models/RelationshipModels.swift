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

    init() {}

    init(consumerId: UUID, businessId: UUID, source: ConnectSource, now: Date) {
        id = UUID()
        self.consumerId = consumerId
        self.businessId = businessId
        status = "active"
        self.source = source.rawValue
        connectedAt = now
        lastActivityAt = now
    }

    var isActive: Bool { status == "active" }
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

    init() {}
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
