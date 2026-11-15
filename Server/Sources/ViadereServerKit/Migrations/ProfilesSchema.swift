import Fluent
import FluentSQL
import Foundation
import SQLKit

/// Customer profiles with selective sharing (docs/PROFILES.md, SECURITY.md §2.97). **Additive and forward-only**: new tables only.
///
/// * `consumer_profiles`: the custom public name (sealed, `consumer_profiles.public_name#{id}`), one row per account that set one.
/// * `profile_values`: one sealed value per (account, field key, entry); `entry_key` is `""` for single-value fields so the unique index holds.
/// * `profile_grants`: per business, per field; `revoked_at` ends a grant (rows are kept as the grant history, without values).
/// * `profile_requests`: a business's request with its stated purpose (business text, not personal data) and the customer's answer.
/// * `profile_receipts`: the customer's disclosure receipts (field keys only).
/// * `profile_verified_facts`: booleans established with an ID, with provenance; never document data.
/// * `profile_verification_attempts`: the Wallet nonce / provider session of a customer-initiated verification (operational ids only).
/// * `profile_category_requests`: what a business asked Viadere to allow it at onboarding, with its justification and the operator decision.
///   The allowed set itself lives in `business_entitlements` (`kind = profile_category`).
struct CreateProfilesSchema: AsyncMigration {
    var name: String { "Profiles.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema("consumer_profiles")
            .id()
            .field("public_name", .string)
            .field("updated_at", .datetime, .required)
            .foreignKey("id", references: "consumers", "id")
            .create()
        try await db.schema("profile_values")
            .id()
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("field_key", .string, .required)
            .field("entry_key", .string, .required)
            .field("value", .string, .required)
            .field("catalog_version", .int, .required)
            .field("created_at", .datetime, .required)
            .field("updated_at", .datetime, .required)
            .unique(on: "consumer_id", "field_key", "entry_key")
            .create()
        try await db.schema("profile_grants")
            .id()
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("relationship_id", .uuid, .required, .references("relationships", "id"))
            .field("field_key", .string, .required)
            .field("request_id", .uuid)
            .field("granted_at", .datetime, .required)
            .field("revoked_at", .datetime)
            .field("revoke_reason", .string)
            .create()
        try await db.schema("profile_requests")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("key_id", .uuid, .required)
            .field("livemode", .bool, .required)
            .field("relationship_id", .uuid, .required, .references("relationships", "id"))
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("subject_ref", .string, .required)
            .field("field_keys", .string, .required)
            .field("purpose", .string, .required)
            .field("status", .string, .required)
            .field("approved_keys", .string)
            .field("idempotency_hash", .string, .required)
            .field("request_hash", .string, .required)
            .field("created_at", .datetime, .required)
            .field("expires_at", .datetime, .required)
            .field("answered_at", .datetime)
            .unique(on: "business_id", "idempotency_hash")
            .create()
        try await db.schema("profile_receipts")
            .id()
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("recipient_name", .string, .required)
            .field("action", .string, .required)
            .field("field_keys", .string, .required)
            .field("purpose", .string)
            .field("request_id", .uuid)
            .field("created_at", .datetime, .required)
            .create()
        try await db.schema("profile_verified_facts")
            .id()
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("fact", .string, .required)
            .field("method", .string, .required)
            .field("assurance", .string, .required)
            .field("policy_version", .string, .required)
            .field("verified_at", .datetime, .required)
            .unique(on: "consumer_id", "fact")
            .create()
        try await db.schema("profile_verification_attempts")
            .id()
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("method", .string, .required)
            .field("keep", .string, .required)
            .field("status", .string, .required)
            .field("nonce", .string)
            .field("provider_session_id", .string)
            .field("failure_reason", .string)
            .field("purge_status", .string)
            .field("purge_attempts", .int, .required, .sql(.default(0)))
            .field("purged_at", .datetime)
            .field("purge_next_at", .datetime)
            .field("created_at", .datetime, .required)
            .field("expires_at", .datetime, .required)
            .field("finished_at", .datetime)
            .create()
        try await db.schema("profile_category_requests")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("category", .string, .required)
            .field("justification", .string)
            .field("status", .string, .required)
            .field("requested_by", .uuid)
            .field("created_at", .datetime, .required)
            .field("decided_at", .datetime)
            .field("decided_by", .string)
            .field("decision_note", .string)
            .create()

        guard let sql = db as? any SQLDatabase else { return }
        for (name, table, columns) in [("idx_profile_grants_relationship", "profile_grants", "relationship_id, revoked_at"),
                                       ("idx_profile_grants_consumer", "profile_grants", "consumer_id, business_id"),
                                       ("idx_profile_requests_consumer_created", "profile_requests", "consumer_id, created_at, id"),
                                       ("idx_profile_requests_open", "profile_requests", "status, expires_at"),
                                       ("idx_profile_receipts_consumer", "profile_receipts", "consumer_id, created_at"),
                                       ("idx_profile_attempts_session", "profile_verification_attempts", "provider_session_id"),
                                       ("idx_profile_category_requests_business", "profile_category_requests", "business_id, status")] {
            // Identifiers are compile-time constants; no user input reaches this statement.
            try await sql.raw(SQLQueryString("CREATE INDEX IF NOT EXISTS \(unsafeRaw: name) ON \(unsafeRaw: table) (\(unsafeRaw: columns))")).run()
        }
    }

    func revert(on db: any Database) async throws {
        guard let sql = db as? any SQLDatabase else { return }
        for table in ["profile_category_requests", "profile_verification_attempts", "profile_verified_facts", "profile_receipts", "profile_requests",
                      "profile_grants", "profile_values", "consumer_profiles"] {
            try await sql.raw(SQLQueryString("DROP TABLE IF EXISTS \(unsafeRaw: table)")).run()
        }
    }
}
