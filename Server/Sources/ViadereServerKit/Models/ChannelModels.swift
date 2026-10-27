import Fluent
import Foundation

/// Per-phone state for a rich channel: cached capability and the *active menu version*. Every rendering that
/// carries tappable suggestions bumps `activeMenuVersion`, so a postback from an older message is stale —
/// the same rule the SMS gateway applies to numbered replies.
final class ChannelEndpointRecord: Model, @unchecked Sendable {
    static let schema = "channel_endpoints"
    @ID(key: .id) var id: UUID?
    @Field(key: "channel") var channel: String
    @Field(key: "phone_hash") var phoneHash: String
    /// `capable`, `incapable` or `unknown`.
    @Field(key: "capability") var capability: String
    @OptionalField(key: "capability_checked_at") var capabilityCheckedAt: Date?
    @Field(key: "active_menu_version") var activeMenuVersion: Int
    @OptionalField(key: "menu_expires_at") var menuExpiresAt: Date?
    @Field(key: "updated_at") var updatedAt: Date

    init() {}

    init(channel: String, phoneHash: String, now: Date) {
        id = UUID()
        self.channel = channel
        self.phoneHash = phoneHash
        capability = "unknown"
        activeMenuVersion = 0
        updatedAt = now
    }
}

/// One tappable RCS suggestion. The wire carries only the opaque token; only its SHA-256 is stored.
final class RCSPostbackRecord: Model, @unchecked Sendable {
    static let schema = "rcs_postbacks"
    @ID(key: .id) var id: UUID?
    @Field(key: "token_hash") var tokenHash: String
    /// The postback is only valid from the phone it was sent to.
    @Field(key: "phone_hash") var phoneHash: String
    @Field(key: "interaction_id") var interactionId: UUID
    @Field(key: "menu_version") var menuVersion: Int
    /// `RCSPostbackTarget.storageValue`.
    @Field(key: "target") var target: String
    /// `open`, `consumed` or `revoked`.
    @Field(key: "state") var state: String
    @Field(key: "expires_at") var expiresAt: Date
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "consumed_at") var consumedAt: Date?

    init() {}
}

/// Durable outbox for rich-channel delivery of an interaction. Rows are created in the same transaction as the
/// interaction; the worker picks the channel, checks capability and falls back to SMS.
final class ChannelOutboundRecord: Model, @unchecked Sendable {
    static let schema = "channel_outbound"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "interaction_id") var interactionId: UUID
    @Field(key: "consumer_id") var consumerId: UUID
    /// `rcs` or `sms` (an `rcs` row is rewritten to `sms` when it falls back).
    @Field(key: "channel") var channel: String
    @Field(key: "preferred_channel") var preferredChannel: String
    @Field(key: "phone_hash") var phoneHash: String
    @Field(key: "phone_ciphertext") var phoneCiphertext: String
    /// `queued`, `sending`, `sent`, `delivered`, `failed`, `cancelled`.
    @Field(key: "status") var status: String
    @Field(key: "attempts") var attempts: Int
    @Field(key: "next_attempt_at") var nextAttemptAt: Date
    @OptionalField(key: "provider_message_id") var providerMessageId: String?
    @OptionalField(key: "error_code") var errorCode: String?
    /// Why the preferred channel was not used (`not_capable`, `provider_error`, `disabled`, …).
    @OptionalField(key: "fallback_reason") var fallbackReason: String?
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "sent_at") var sentAt: Date?

    init() {}
}
