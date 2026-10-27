import Fluent
import Foundation
import ViadereCore

/// Database-backed `ReplayGuard` storage; unique on `(scope, nonce)`.
final class ReplayNonceRecord: Model, @unchecked Sendable {
    static let schema = "replay_nonces"
    @ID(key: .id) var id: UUID?
    @Field(key: "scope") var scope: String
    @Field(key: "nonce") var nonce: String
    @Field(key: "expires_at") var expiresAt: Date

    init() {}

    init(scope: String, nonce: String, expiresAt: Date) {
        id = UUID()
        self.scope = scope
        self.nonce = nonce
        self.expiresAt = expiresAt
    }
}

/// Append-only, hash-chained audit log.
final class AuditEventRecord: Model, @unchecked Sendable {
    static let schema = "audit_events"
    @ID(key: .id) var id: UUID?
    @Field(key: "seq") var seq: Int
    @Field(key: "occurred_at") var occurredAt: Date
    @Field(key: "actor_kind") var actorKind: String
    @OptionalField(key: "actor_id") var actorId: String?
    @Field(key: "action") var action: String
    @Field(key: "outcome") var outcome: String
    @OptionalField(key: "consumer_id") var consumerId: UUID?
    @OptionalField(key: "business_id") var businessId: UUID?
    @OptionalField(key: "subject_type") var subjectType: String?
    @OptionalField(key: "subject_id") var subjectId: String?
    @OptionalField(key: "correlation_id") var correlationId: String?
    @Field(key: "metadata_json") var metadataJSON: String
    @Field(key: "prev_hash") var prevHash: String
    @Field(key: "hash") var hash: String
    /// 1 = legacy unkeyed SHA-256; 2 = HMAC-SHA256 under `AUDIT_CHAIN_KEY` with the row id in the hashed content.
    @Field(key: "chain_version") var chainVersion: Int
    /// The `AUDIT_CHAIN_KEY` epoch that authenticates this event (chain version 3 and later; `nil` = epoch 1).
    @OptionalField(key: "key_epoch") var keyEpoch: Int?

    init() {}
}

final class LinkTokenRecord: Model, @unchecked Sendable {
    static let schema = "link_tokens"
    @ID(key: .id) var id: UUID?
    /// `accountLink` or `handoff`.
    @Field(key: "kind") var kind: String
    @Field(key: "token_hash") var tokenHash: String
    @Field(key: "phone_hash") var phoneHash: String
    @Field(key: "phone_ciphertext") var phoneCiphertext: String
    @Field(key: "phone_last4") var phoneLast4: String
    /// SMS conversation revision the token was minted against.
    @Field(key: "context_revision") var contextRevision: Int
    @OptionalField(key: "consumer_id") var consumerId: UUID?
    @OptionalField(key: "purpose") var purpose: String?
    @OptionalField(key: "interaction_id") var interactionId: UUID?
    @Field(key: "attempts") var attempts: Int
    /// `open`, `consumed` or `revoked`.
    @Field(key: "state") var state: String
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "consumed_at") var consumedAt: Date?

    init() {}
}

final class SMSContextRecord: Model, @unchecked Sendable {
    static let schema = "sms_contexts"
    @ID(key: .id) var id: UUID?
    @Field(key: "phone_hash") var phoneHash: String
    /// Encrypted `ConversationContext` JSON.
    @Field(key: "context_ciphertext") var contextCiphertext: String
    /// Optimistic-concurrency counter, mirrors `ConversationContext.revision`.
    @Field(key: "revision") var revision: Int
    @OptionalField(key: "consumer_id") var consumerId: UUID?
    @OptionalField(key: "active_session_id") var activeSessionId: UUID?
    @Field(key: "opted_out") var optedOut: Bool
    @Field(key: "updated_at") var updatedAt: Date

    init() {}
}

final class ProcessedProviderMessageRecord: Model, @unchecked Sendable {
    static let schema = "processed_provider_messages"
    @ID(key: .id) var id: UUID?
    @Field(key: "provider") var provider: String
    @Field(key: "provider_message_id") var providerMessageId: String
    @Field(key: "received_at") var receivedAt: Date

    init() {}

    init(provider: String, providerMessageId: String, receivedAt: Date) {
        id = UUID()
        self.provider = provider
        self.providerMessageId = providerMessageId
        self.receivedAt = receivedAt
    }
}

final class SMSConsentEventRecord: Model, @unchecked Sendable {
    static let schema = "sms_consent_events"
    @ID(key: .id) var id: UUID?
    @Field(key: "phone_hash") var phoneHash: String
    @Field(key: "opted_out") var optedOut: Bool
    @Field(key: "keyword") var keyword: String
    @Field(key: "occurred_at") var occurredAt: Date

    init() {}

    init(phoneHash: String, optedOut: Bool, keyword: String, at: Date) {
        id = UUID()
        self.phoneHash = phoneHash
        self.optedOut = optedOut
        self.keyword = String(keyword.prefix(32))
        occurredAt = at
    }
}

/// Outbound SMS queue. Ordered per phone by `seq`; a later message is never sent while an earlier one is pending.
final class SMSOutboundRecord: Model, @unchecked Sendable {
    static let schema = "sms_outbound"
    @ID(key: .id) var id: UUID?
    @Field(key: "seq") var seq: Int
    @Field(key: "phone_hash") var phoneHash: String
    @Field(key: "phone_ciphertext") var phoneCiphertext: String
    @Field(key: "body_ciphertext") var bodyCiphertext: String
    /// Body contains a secret (OTP, link token) and is wiped after sending.
    @Field(key: "sensitive") var sensitive: Bool
    /// Engine replies to an opted-out sender (STOP confirmation, HELP) may be sent; everything else is dropped.
    @Field(key: "allow_when_opted_out") var allowWhenOptedOut: Bool
    /// `queued`, `sending`, `sent`, `delivered`, `failed`, `cancelled`.
    @Field(key: "status") var status: String
    @Field(key: "attempts") var attempts: Int
    @Field(key: "next_attempt_at") var nextAttemptAt: Date
    @OptionalField(key: "provider_message_id") var providerMessageId: String?
    @OptionalField(key: "error_code") var errorCode: String?
    @OptionalField(key: "message_id") var messageId: UUID?
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "sent_at") var sentAt: Date?

    init() {}
}

final class WebhookSubscriptionRecord: Model, @unchecked Sendable {
    static let schema = "webhook_subscriptions"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "url") var url: String
    @Field(key: "events") var events: String
    /// Encrypted current signing secret.
    @Field(key: "secret_ciphertext") var secretCiphertext: String
    /// Previous secret, also signed with until `previous_secret_expires_at` (rotation overlap).
    @OptionalField(key: "previous_secret_ciphertext") var previousSecretCiphertext: String?
    @OptionalField(key: "previous_secret_expires_at") var previousSecretExpiresAt: Date?
    @Field(key: "active") var active: Bool
    @Field(key: "created_at") var createdAt: Date
    /// `nil` = v1 `WebhookEvent` bodies; `2026-10-27` = the opaque envelope.
    @OptionalField(key: "envelope_version") var envelopeVersion: String?
    /// Version of the current signing secret (1, then +1 at every rotation); part of the `Viadere-Key-Id` header.
    @Field(key: "secret_version") var secretVersion: Int
    /// Ownership of the endpoint was proven by a challenge response (WP6). Until then it receives nothing but the challenge.
    @OptionalField(key: "verified_at") var verifiedAt: Date?
    /// SHA-256 of the outstanding challenge (single use); the challenge itself is only in the request we sent.
    @OptionalField(key: "verification_challenge_hash") var verificationChallengeHash: String?
    @OptionalField(key: "verification_expires_at") var verificationExpiresAt: Date?
    @OptionalField(key: "last_verify_error") var lastVerifyError: String?
    /// Paused endpoints keep their queued deliveries but receive none (ops gap G-5).
    @OptionalField(key: "paused_at") var pausedAt: Date?
    @OptionalField(key: "paused_by") var pausedBy: String?
    @OptionalField(key: "pause_reason") var pauseReason: String?

    init() {}

    var isPaused: Bool { pausedAt != nil }
}

final class WebhookDeliveryRecord: Model, @unchecked Sendable {
    static let schema = "webhook_deliveries"
    @ID(key: .id) var id: UUID?
    @Field(key: "subscription_id") var subscriptionId: UUID
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "event_type") var eventType: String
    /// Exact body bytes (UTF-8 JSON); the same bytes are signed on every attempt.
    @Field(key: "body") var body: String
    /// `pending`, `sending`, `succeeded`, `dead`.
    @Field(key: "status") var status: String
    @Field(key: "attempts") var attempts: Int
    @Field(key: "next_attempt_at") var nextAttemptAt: Date
    @OptionalField(key: "last_status_code") var lastStatusCode: Int?
    @OptionalField(key: "last_error") var lastError: String?
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "delivered_at") var deliveredAt: Date?

    init() {}
}

final class WebhookAttemptRecord: Model, @unchecked Sendable {
    static let schema = "webhook_delivery_attempts"
    @ID(key: .id) var id: UUID?
    @Field(key: "delivery_id") var deliveryId: UUID
    @Field(key: "attempt") var attempt: Int
    @Field(key: "attempted_at") var attemptedAt: Date
    @OptionalField(key: "status_code") var statusCode: Int?
    @Field(key: "duration_ms") var durationMs: Int
    @OptionalField(key: "error") var error: String?

    init() {}
}
