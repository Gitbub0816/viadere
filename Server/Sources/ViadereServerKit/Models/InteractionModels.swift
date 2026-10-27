import Fluent
import Foundation
import ViadereCore
import enum ViadereCore.Channel

/// An issued interaction. `interaction_json` is the full `Interaction` (ViadereJSON); the other columns
/// are denormalized for tenant-scoped queries and lifecycle management.
final class InteractionRecord: Model, @unchecked Sendable {
    static let schema = "interactions"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "relationship_id") var relationshipId: UUID
    @Field(key: "kind") var kind: String
    @Field(key: "purpose") var purpose: String
    /// `InteractionStatus.rawValue`.
    @Field(key: "status") var status: String
    @Field(key: "priority") var priority: String
    @Field(key: "sensitivity") var sensitivity: String
    @Field(key: "livemode") var livemode: Bool
    @Field(key: "interaction_json") var interactionJSON: String
    @Field(key: "idempotency_key") var idempotencyKey: String
    /// SHA-256 of the canonical request, to distinguish a true retry from key reuse with a different body.
    @Field(key: "request_hash") var requestHash: String
    @OptionalField(key: "correlation_id") var correlationId: String?
    @OptionalField(key: "activity_key") var activityKey: String?
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "decided_at") var decidedAt: Date?
    @OptionalField(key: "outcome_json") var outcomeJSON: String?
    @Field(key: "expiry_notified") var expiryNotified: Bool
    /// The retention job replaced the payload and outcome with placeholders (WP6).
    @Field(key: "content_erased") var contentErased: Bool

    init() {}

    init(interaction: Interaction, consumerId: UUID, livemode: Bool, requestHash: String, activityKey: String? = nil) throws {
        id = interaction.id.uuid
        businessId = interaction.businessId.uuid
        self.consumerId = consumerId
        relationshipId = interaction.scope.relationshipId.uuid
        kind = interaction.kind.rawValue
        purpose = interaction.purpose.rawValue
        status = InteractionStatus.pending.rawValue
        priority = interaction.priority.rawValue
        sensitivity = interaction.sensitivity.rawValue
        self.livemode = livemode
        interactionJSON = String(decoding: try ViadereJSON.encode(interaction), as: UTF8.self)
        idempotencyKey = interaction.idempotencyKey
        self.requestHash = requestHash
        correlationId = interaction.correlationId
        self.activityKey = activityKey
        createdAt = interaction.createdAt
        expiresAt = interaction.expiresAt
        expiryNotified = false
        contentErased = false
    }

    func interaction() throws -> Interaction {
        try ViadereJSON.decode(Interaction.self, from: Data(interactionJSON.utf8))
    }

    var statusValue: InteractionStatus { InteractionStatus(rawValue: status) ?? .pending }
}

final class InteractionChallengeRecord: Model, @unchecked Sendable {
    static let schema = "interaction_challenges"
    @ID(key: .id) var id: UUID?
    @Field(key: "interaction_id") var interactionId: UUID
    @Field(key: "nonce_hash") var nonceHash: String
    @Field(key: "issued_at") var issuedAt: Date
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "consumed_at") var consumedAt: Date?
    @OptionalField(key: "consumed_by_device") var consumedByDevice: UUID?

    init() {}

    init(interaction: Interaction) {
        id = UUID()
        interactionId = interaction.id.uuid
        nonceHash = SecureToken.hash(interaction.challenge.value)
        issuedAt = interaction.createdAt
        expiresAt = interaction.expiresAt
    }
}

final class DecisionRecord: Model, @unchecked Sendable {
    static let schema = "decisions"
    @ID(key: .id) var id: UUID?
    @Field(key: "interaction_id") var interactionId: UUID
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "device_id") var deviceId: UUID
    @Field(key: "decision") var decision: String
    @Field(key: "assurance") var assurance: String
    @Field(key: "channel") var channel: String
    @Field(key: "signed_payload") var signedPayload: String
    @Field(key: "signature") var signature: String
    @Field(key: "decided_at") var decidedAt: Date

    init() {}
}

final class ConversationSessionRecord: Model, @unchecked Sendable {
    static let schema = "conversation_sessions"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "relationship_id") var relationshipId: UUID
    /// `sms` or `inApp`.
    @Field(key: "channel") var channel: String
    /// `open`, `parked` or `closed`.
    @Field(key: "state") var state: String
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "last_message_at") var lastMessageAt: Date?
    @OptionalField(key: "closed_at") var closedAt: Date?

    init() {}

    init(id: UUID, businessId: UUID, consumerId: UUID, relationshipId: UUID, channel: Channel, now: Date) {
        self.id = id
        self.businessId = businessId
        self.consumerId = consumerId
        self.relationshipId = relationshipId
        self.channel = channel.rawValue
        state = "open"
        createdAt = now
    }
}

/// A message in a business-scoped session. Bodies are encrypted at rest.
final class ConversationMessageRecord: Model, @unchecked Sendable {
    static let schema = "conversation_messages"
    @ID(key: .id) var id: UUID?
    @Field(key: "session_id") var sessionId: UUID
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "direction") var direction: String
    @Field(key: "sender_type") var senderType: String
    @Field(key: "display_name") var displayName: String
    @OptionalField(key: "agent_name") var agentName: String?
    @Field(key: "body_ciphertext") var bodyCiphertext: String
    @Field(key: "channel") var channel: String
    @Field(key: "delivery_status") var deliveryStatus: String
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "delivered_at") var deliveredAt: Date?
    @OptionalField(key: "read_at") var readAt: Date?
    @OptionalField(key: "interaction_id") var interactionId: UUID?
    /// The retention job replaced the body with a placeholder (WP6).
    @Field(key: "content_erased") var contentErased: Bool
    /// Business-supplied idempotency key (business → consumer messages).
    @OptionalField(key: "idempotency_key") var idempotencyKey: String?
    @OptionalField(key: "request_hash") var requestHash: String?
    /// Client-supplied id (consumer → business messages).
    @OptionalField(key: "client_message_id") var clientMessageId: String?
    @OptionalField(key: "provider_message_id") var providerMessageId: String?

    init() {}
}
