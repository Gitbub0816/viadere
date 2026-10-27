import Fluent
import Foundation
import ViadereCore

// MARK: - Loyalty and rewards

/// One loyalty program per business.
final class LoyaltyProgramRecord: Model, @unchecked Sendable {
    static let schema = "loyalty_programs"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "program_name") var programName: String
    @Field(key: "summary") var summary: String
    @Field(key: "terms_version") var termsVersion: String
    /// IANA time zone of the business: day boundaries for per-day limits and recurrence.
    @Field(key: "time_zone") var timeZone: String
    /// JSON `[LoyaltyTier]`.
    @Field(key: "tiers_json") var tiersJSON: String
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "updated_at") var updatedAt: Date

    init() {}

    var tiers: [LoyaltyTier] {
        (try? ViadereJSON.decode([LoyaltyTier].self, from: Data(tiersJSON.utf8)))?.sorted { $0.minimumPoints < $1.minimumPoints } ?? []
    }
}

/// A consumer's membership. The business-side member reference is PII and is stored AES-GCM encrypted (masked copy for display).
final class LoyaltyAccountRecord: Model, @unchecked Sendable {
    static let schema = "loyalty_accounts"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "program_id") var programId: UUID
    @Field(key: "points_balance") var pointsBalance: Int
    @Field(key: "accepted_terms_version") var acceptedTermsVersion: String
    @OptionalField(key: "member_reference_ciphertext") var memberReferenceCiphertext: String?
    @OptionalField(key: "member_reference_masked") var memberReferenceMasked: String?
    @Field(key: "member_since") var memberSince: Date
    @Field(key: "updated_at") var updatedAt: Date

    init() {}
}

/// Append-only points history. `(business_id, idempotency_key)` is unique, so a retried adjustment applies once.
final class LoyaltyLedgerRecord: Model, @unchecked Sendable {
    static let schema = "loyalty_ledger"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "account_id") var accountId: UUID
    @Field(key: "delta") var delta: Int
    @OptionalField(key: "reason") var reason: String?
    @Field(key: "idempotency_key") var idempotencyKey: String
    @Field(key: "request_hash") var requestHash: String
    @Field(key: "balance_after") var balanceAfter: Int
    @Field(key: "created_at") var createdAt: Date

    init() {}
}

final class RewardRecord: Model, @unchecked Sendable {
    static let schema = "rewards"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    /// Set for a reward issued to one consumer; `NULL` for a reward offered to every connected consumer.
    @OptionalField(key: "consumer_id") var consumerId: UUID?
    @Field(key: "kind") var kind: String
    @Field(key: "title") var title: String
    @OptionalField(key: "details") var details: String?
    /// `active` or `revoked`.
    @Field(key: "status") var status: String
    @OptionalField(key: "valid_from") var validFrom: Date?
    @OptionalField(key: "valid_until") var validUntil: Date?
    /// ISO weekdays, comma separated (`2,3`); empty = every day.
    @Field(key: "recurrence_weekdays") var recurrenceWeekdays: String
    /// Redemptions allowed per local day; `NULL` = no per-day limit.
    @OptionalField(key: "per_day_limit") var perDayLimit: Int?
    @Field(key: "time_zone") var timeZone: String
    @OptionalField(key: "points_cost") var pointsCost: Int?
    @Field(key: "issue_wallet_pass") var issueWalletPass: Bool
    @Field(key: "idempotency_key") var idempotencyKey: String
    @Field(key: "request_hash") var requestHash: String
    @Field(key: "created_at") var createdAt: Date

    init() {}

    var kindValue: RewardKind { RewardKind(rawValue: kind) ?? .perk }
    var isRevoked: Bool { status == "revoked" }
    var weekdays: [Int] { recurrenceWeekdays.split(separator: ",").compactMap { Int($0) } }
    var isRecurring: Bool { !recurrenceWeekdays.isEmpty }
}

/// A consumer saving an offer to their account. Unique per `(reward, consumer)`, so a claim is idempotent and race-safe.
final class RewardClaimRecord: Model, @unchecked Sendable {
    static let schema = "reward_claims"
    @ID(key: .id) var id: UUID?
    @Field(key: "reward_id") var rewardId: UUID
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "claimed_at") var claimedAt: Date

    init() {}
}

/// A single-use redemption code. The code itself is never stored, only its keyed hash.
///
/// `(reward_id, consumer_id, window_key, slot)` is unique, and `slot` is `NULL` once a redemption stops counting (expired or
/// released), so concurrent redemptions cannot exceed a per-day or lifetime limit: the database decides the race.
final class RewardRedemptionRecord: Model, @unchecked Sendable {
    static let schema = "reward_redemptions"
    @ID(key: .id) var id: UUID?
    @Field(key: "reward_id") var rewardId: UUID
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "code_hash") var codeHash: String
    /// `issued`, `consumed` or `expired`.
    @Field(key: "status") var status: String
    /// Local day (`2026-10-27`) for per-day limits, `once` for lifetime limits, `open` when the reward is unlimited.
    @Field(key: "window_key") var windowKey: String
    @OptionalField(key: "slot") var slot: Int?
    @Field(key: "points_held") var pointsHeld: Int
    @OptionalField(key: "location_code") var locationCode: String?
    @Field(key: "issued_at") var issuedAt: Date
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "consumed_at") var consumedAt: Date?
    @OptionalField(key: "released_at") var releasedAt: Date?

    init() {}
}

// MARK: - Wallet

final class WalletPassRecord: Model, @unchecked Sendable {
    static let schema = "wallet_passes"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "kind") var kind: String
    /// `storeCard:{business}`, `coupon:{reward}`, `ticket:{interaction}`: one pass per consumer per subject.
    @Field(key: "subject_key") var subjectKey: String
    @Field(key: "pass_type_identifier") var passTypeIdentifier: String
    @Field(key: "serial_number") var serialNumber: String
    /// Per-pass salt; the authentication token is `HMAC(pepper, id ‖ salt)` and only its keyed hash is stored for comparison.
    @Field(key: "auth_salt") var authSalt: String
    @Field(key: "auth_token_hash") var authTokenHash: String
    @OptionalField(key: "reward_id") var rewardId: UUID?
    @OptionalField(key: "interaction_id") var interactionId: UUID?
    @Field(key: "voided") var voided: Bool
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "updated_at") var updatedAt: Date

    init() {}

    var kindValue: WalletPassKind { WalletPassKind(rawValue: kind) ?? .generic }
}

/// A device that registered for updates to a pass (Apple's PassKit web service).
final class WalletRegistrationRecord: Model, @unchecked Sendable {
    static let schema = "wallet_registrations"
    @ID(key: .id) var id: UUID?
    @Field(key: "pass_id") var passId: UUID
    @Field(key: "device_library_identifier") var deviceLibraryIdentifier: String
    @Field(key: "push_token") var pushToken: String
    @Field(key: "created_at") var createdAt: Date

    init() {}
}

/// Durable queue of pass changes to announce to registered devices.
final class WalletPushOutboxRecord: Model, @unchecked Sendable {
    static let schema = "wallet_push_outbox"
    @ID(key: .id) var id: UUID?
    @Field(key: "pass_id") var passId: UUID
    /// `queued`, `sending`, `sent`.
    @Field(key: "status") var status: String
    @Field(key: "attempts") var attempts: Int
    @Field(key: "next_attempt_at") var nextAttemptAt: Date
    @Field(key: "created_at") var createdAt: Date

    init() {}
}

/// Device-reported problems from the PassKit `log` endpoint. Messages are length-capped and never trusted.
final class WalletLogRecord: Model, @unchecked Sendable {
    static let schema = "wallet_logs"
    @ID(key: .id) var id: UUID?
    @Field(key: "message") var message: String
    @Field(key: "created_at") var createdAt: Date

    init() {}
}

// MARK: - Live Activities

/// One Live Activity start per ongoing event, so two quick status updates cannot start two activities.
final class LiveActivityStartRecord: Model, @unchecked Sendable {
    static let schema = "live_activity_starts"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "activity_key") var activityKey: String
    @Field(key: "created_at") var createdAt: Date

    init() {}
}

// MARK: - Household

/// A pending invitation. The code is stored only as a keyed hash; accepting it creates the `delegation_grants` row with the same id.
final class DelegationInvitationRecord: Model, @unchecked Sendable {
    static let schema = "delegation_invitations"
    @ID(key: .id) var id: UUID?
    @Field(key: "grantor_id") var grantorId: UUID
    @Field(key: "label_ciphertext") var labelCiphertext: String
    @Field(key: "role") var role: String
    @Field(key: "purposes") var purposes: String
    @Field(key: "business_ids") var businessIds: String
    /// When the grant ends once accepted.
    @Field(key: "grant_expires_at") var grantExpiresAt: Date
    @Field(key: "code_hash") var codeHash: String
    @Field(key: "invite_expires_at") var inviteExpiresAt: Date
    @Field(key: "attempts") var attempts: Int
    /// `open`, `accepted`, `revoked` or `locked`.
    @Field(key: "state") var state: String
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "accepted_at") var acceptedAt: Date?

    init() {}
}
