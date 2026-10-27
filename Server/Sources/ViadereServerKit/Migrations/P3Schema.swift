import Fluent
import FluentSQL
import Foundation
import SQLKit

/// P3 (rewards, loyalty, Wallet, Live Activity, household) schema. Security-relevant uniqueness is a database constraint:
/// claims, per-day redemption slots, redemption codes, pass serials, invitation codes and ledger idempotency keys.
struct CreateP3Schema: AsyncMigration {
    var name: String { "CreateP3Schema.v1" }

    func prepare(on db: any Database) async throws {
        // MARK: Loyalty and rewards
        try await db.schema("loyalty_programs")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("program_name", .string, .required)
            .field("summary", .string, .required)
            .field("terms_version", .string, .required)
            .field("time_zone", .string, .required)
            .field("tiers_json", .string, .required)
            .field("created_at", .datetime, .required)
            .field("updated_at", .datetime, .required)
            .unique(on: "business_id")
            .create()

        try await db.schema("loyalty_accounts")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("program_id", .uuid, .required, .references("loyalty_programs", "id"))
            .field("points_balance", .int, .required)
            .field("accepted_terms_version", .string, .required)
            .field("member_reference_ciphertext", .string)
            .field("member_reference_masked", .string)
            .field("member_since", .datetime, .required)
            .field("updated_at", .datetime, .required)
            .unique(on: "business_id", "consumer_id")
            .create()

        try await db.schema("loyalty_ledger")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("consumer_id", .uuid, .required)
            .field("account_id", .uuid, .required, .references("loyalty_accounts", "id"))
            .field("delta", .int, .required)
            .field("reason", .string)
            .field("idempotency_key", .string, .required)
            .field("request_hash", .string, .required)
            .field("balance_after", .int, .required)
            .field("created_at", .datetime, .required)
            .unique(on: "business_id", "idempotency_key")
            .create()

        try await db.schema("rewards")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("consumer_id", .uuid)
            .field("kind", .string, .required)
            .field("title", .string, .required)
            .field("details", .string)
            .field("status", .string, .required)
            .field("valid_from", .datetime)
            .field("valid_until", .datetime)
            .field("recurrence_weekdays", .string, .required)
            .field("per_day_limit", .int)
            .field("time_zone", .string, .required)
            .field("points_cost", .int)
            .field("issue_wallet_pass", .bool, .required)
            .field("idempotency_key", .string, .required)
            .field("request_hash", .string, .required)
            .field("created_at", .datetime, .required)
            .unique(on: "business_id", "idempotency_key")
            .create()

        try await db.schema("reward_claims")
            .id()
            .field("reward_id", .uuid, .required, .references("rewards", "id"))
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("claimed_at", .datetime, .required)
            .unique(on: "reward_id", "consumer_id")
            .create()

        try await db.schema("reward_redemptions")
            .id()
            .field("reward_id", .uuid, .required, .references("rewards", "id"))
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("code_hash", .string, .required)
            .field("status", .string, .required)
            .field("window_key", .string, .required)
            .field("slot", .int)
            .field("points_held", .int, .required)
            .field("location_code", .string)
            .field("issued_at", .datetime, .required)
            .field("expires_at", .datetime, .required)
            .field("consumed_at", .datetime)
            .field("released_at", .datetime)
            .unique(on: "code_hash")
            .unique(on: "reward_id", "consumer_id", "window_key", "slot")
            .create()

        // MARK: Wallet
        try await db.schema("wallet_passes")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("kind", .string, .required)
            .field("subject_key", .string, .required)
            .field("pass_type_identifier", .string, .required)
            .field("serial_number", .string, .required)
            .field("auth_salt", .string, .required)
            .field("auth_token_hash", .string, .required)
            .field("reward_id", .uuid)
            .field("interaction_id", .uuid)
            .field("voided", .bool, .required)
            .field("created_at", .datetime, .required)
            .field("updated_at", .datetime, .required)
            .unique(on: "serial_number")
            .unique(on: "consumer_id", "subject_key")
            .create()

        try await db.schema("wallet_registrations")
            .id()
            .field("pass_id", .uuid, .required, .references("wallet_passes", "id"))
            .field("device_library_identifier", .string, .required)
            .field("push_token", .string, .required)
            .field("created_at", .datetime, .required)
            .unique(on: "pass_id", "device_library_identifier")
            .create()

        try await db.schema("wallet_push_outbox")
            .id()
            .field("pass_id", .uuid, .required, .references("wallet_passes", "id"))
            .field("status", .string, .required)
            .field("attempts", .int, .required)
            .field("next_attempt_at", .datetime, .required)
            .field("created_at", .datetime, .required)
            .create()

        try await db.schema("wallet_logs")
            .id()
            .field("message", .string, .required)
            .field("created_at", .datetime, .required)
            .create()

        // MARK: Live Activities
        try await db.schema("live_activity_starts")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("consumer_id", .uuid, .required)
            .field("activity_key", .string, .required)
            .field("created_at", .datetime, .required)
            .unique(on: "business_id", "consumer_id", "activity_key")
            .create()

        // MARK: Household
        // One column per statement: SQLite cannot add several columns in a single ALTER TABLE.
        try await db.schema("delegation_grants").field("label_ciphertext", .string).update()
        try await db.schema("delegation_grants").field("expiry_recorded", .bool, .required, .sql(.default(false))).update()

        try await db.schema("delegation_invitations")
            .id()
            .field("grantor_id", .uuid, .required, .references("consumers", "id"))
            .field("label_ciphertext", .string, .required)
            .field("role", .string, .required)
            .field("purposes", .string, .required)
            .field("business_ids", .string, .required)
            .field("grant_expires_at", .datetime, .required)
            .field("code_hash", .string, .required)
            .field("invite_expires_at", .datetime, .required)
            .field("attempts", .int, .required)
            .field("state", .string, .required)
            .field("created_at", .datetime, .required)
            .field("accepted_at", .datetime)
            .unique(on: "code_hash")
            .create()

        try await createIndexes(on: db)
    }

    func revert(on db: any Database) async throws {
        for table in ["delegation_invitations", "live_activity_starts", "wallet_logs", "wallet_push_outbox", "wallet_registrations",
                      "wallet_passes", "reward_redemptions", "reward_claims", "rewards", "loyalty_ledger", "loyalty_accounts",
                      "loyalty_programs"] {
            try await db.schema(table).delete()
        }
        try await db.schema("delegation_grants").deleteField("label_ciphertext").update()
        try await db.schema("delegation_grants").deleteField("expiry_recorded").update()
    }

    private func createIndexes(on db: any Database) async throws {
        guard let sql = db as? any SQLDatabase else { return }
        let indexes: [(String, String, String)] = [
            ("idx_rewards_business", "rewards", "business_id, status"),
            ("idx_rewards_consumer", "rewards", "consumer_id"),
            ("idx_loyalty_accounts_consumer", "loyalty_accounts", "consumer_id"),
            ("idx_redemptions_due", "reward_redemptions", "status, expires_at"),
            ("idx_redemptions_consumer", "reward_redemptions", "consumer_id, reward_id"),
            ("idx_wallet_passes_consumer", "wallet_passes", "consumer_id"),
            ("idx_wallet_registrations_device", "wallet_registrations", "device_library_identifier"),
            ("idx_wallet_outbox_due", "wallet_push_outbox", "status, next_attempt_at"),
            ("idx_delegation_grantor", "delegation_grants", "grantor_id"),
            ("idx_delegation_delegate", "delegation_grants", "delegate_id"),
            ("idx_delegation_invites_grantor", "delegation_invitations", "grantor_id"),
            ("idx_live_tokens_consumer", "live_activity_tokens", "consumer_id"),
            ("idx_interactions_activity", "interactions", "business_id, activity_key"),
        ]
        for (name, table, columns) in indexes {
            // Identifiers are compile-time constants above; no user input reaches this statement.
            try await sql.raw(SQLQueryString("CREATE INDEX IF NOT EXISTS \(unsafeRaw: name) ON \(unsafeRaw: table) (\(unsafeRaw: columns))")).run()
        }
    }
}
