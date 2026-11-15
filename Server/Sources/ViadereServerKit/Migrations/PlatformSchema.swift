import Fluent
import FluentSQL
import Foundation
import SQLKit

/// P4 (rich channels) and P5 (platform) schema. Uniqueness that matters for security is a database constraint.
struct CreatePlatformSchema: AsyncMigration {
    var name: String { "CreatePlatformSchema.v2" }

    func prepare(on db: any Database) async throws {
        // MARK: P4 rich channels
        try await db.schema("channel_endpoints")
            .id()
            .field("channel", .string, .required)
            .field("phone_hash", .string, .required)
            .field("capability", .string, .required)
            .field("capability_checked_at", .datetime)
            .field("active_menu_version", .int, .required)
            .field("menu_expires_at", .datetime)
            .field("updated_at", .datetime, .required)
            .unique(on: "channel", "phone_hash")
            .create()

        try await db.schema("rcs_postbacks")
            .id()
            .field("token_hash", .string, .required)
            .field("phone_hash", .string, .required)
            .field("interaction_id", .uuid, .required, .references("interactions", "id"))
            .field("menu_version", .int, .required)
            .field("target", .string, .required)
            .field("state", .string, .required)
            .field("expires_at", .datetime, .required)
            .field("created_at", .datetime, .required)
            .field("consumed_at", .datetime)
            .unique(on: "token_hash")
            .create()

        try await db.schema("channel_outbound")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("interaction_id", .uuid, .required, .references("interactions", "id"))
            .field("consumer_id", .uuid, .required)
            .field("channel", .string, .required)
            .field("preferred_channel", .string, .required)
            .field("phone_hash", .string, .required)
            .field("phone_ciphertext", .string, .required)
            .field("status", .string, .required)
            .field("attempts", .int, .required)
            .field("next_attempt_at", .datetime, .required)
            .field("provider_message_id", .string)
            .field("error_code", .string)
            .field("fallback_reason", .string)
            .field("created_at", .datetime, .required)
            .field("sent_at", .datetime)
            .unique(on: "interaction_id", "phone_hash")
            .create()

        // MARK: P5 dashboard identity
        try await db.schema("dashboard_users")
            .id()
            .field("kind", .string, .required)
            .field("email_hash", .string, .required)
            .field("email_ciphertext", .string, .required)
            .field("display_name", .string, .required)
            .field("user_handle", .string, .required)
            .field("status", .string, .required)
            .field("created_at", .datetime, .required)
            .field("last_login_at", .datetime)
            .unique(on: "email_hash")
            .unique(on: "user_handle")
            .create()

        try await db.schema("dashboard_passkeys")
            .id()
            .field("user_id", .uuid, .required, .references("dashboard_users", "id"))
            .field("credential_id", .string, .required)
            .field("public_key", .string, .required)
            .field("sign_count", .int, .required)
            .field("backup_eligible", .bool, .required)
            .field("created_at", .datetime, .required)
            .field("last_used_at", .datetime)
            .unique(on: "credential_id")
            .create()

        try await db.schema("dashboard_ceremonies")
            .id()
            .field("kind", .string, .required)
            .field("challenge", .string, .required)
            .field("user_id", .uuid)
            .field("payload_json", .string)
            .field("state", .string, .required)
            .field("expires_at", .datetime, .required)
            .field("created_at", .datetime, .required)
            .create()

        try await db.schema("dashboard_sessions")
            .id()
            .field("user_id", .uuid, .required, .references("dashboard_users", "id"))
            .field("realm", .string, .required)
            .field("token_hash", .string, .required)
            .field("business_id", .uuid)
            .field("created_at", .datetime, .required)
            .field("last_seen_at", .datetime, .required)
            .field("expires_at", .datetime, .required)
            .field("reauth_at", .datetime)
            .field("revoked_at", .datetime)
            .unique(on: "token_hash")
            .create()

        try await db.schema("org_memberships")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("user_id", .uuid, .required, .references("dashboard_users", "id"))
            .field("role", .string, .required)
            .field("created_at", .datetime, .required)
            .field("removed_at", .datetime)
            .unique(on: "business_id", "user_id")
            .create()

        try await db.schema("org_invites")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("email_hash", .string, .required)
            .field("email_ciphertext", .string, .required)
            .field("role", .string, .required)
            .field("token_hash", .string, .required)
            .field("invited_by", .uuid, .required)
            .field("state", .string, .required)
            .field("expires_at", .datetime, .required)
            .field("created_at", .datetime, .required)
            .field("accepted_at", .datetime)
            .unique(on: "token_hash")
            .create()

        try await db.schema("operator_enrollments")
            .id()
            .field("user_id", .uuid, .required, .references("dashboard_users", "id"))
            .field("token_hash", .string, .required)
            .field("state", .string, .required)
            .field("expires_at", .datetime, .required)
            .field("created_at", .datetime, .required)
            .unique(on: "token_hash")
            .create()

        // MARK: P5 onboarding, trust and metering
        try await db.schema("business_applications")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("requested_handle", .string)
            .field("legal_name", .string)
            .field("website", .string)
            .field("description", .string)
            .field("state", .string, .required)
            .field("submitted_at", .datetime, .required)
            .field("reviewed_at", .datetime)
            .field("reviewed_by", .uuid)
            .field("decision_note", .string)
            .unique(on: "business_id")
            .create()

        try await db.schema("business_controls")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("throttled", .bool, .required)
            .field("throttle_source", .string)
            .field("throttle_reason", .string)
            .field("throttled_at", .datetime)
            .field("priority_ceiling", .string)
            .field("suspension_reason", .string)
            .field("updated_at", .datetime, .required)
            .field("updated_by", .uuid)
            .unique(on: "business_id")
            .create()

        try await db.schema("abuse_signals")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("kind", .string, .required)
            .field("bucket", .int, .required)
            .field("count", .int, .required)
            .unique(on: "business_id", "kind", "bucket")
            .create()

        try await db.schema("usage_events")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("meter", .string, .required)
            .field("category", .string, .required)
            .field("quantity", .int, .required)
            .field("livemode", .bool, .required)
            .field("ref", .string, .required)
            .field("occurred_at", .datetime, .required)
            .unique(on: "meter", "ref")
            .create()

        try await createIndexes(on: db)
    }

    func revert(on db: any Database) async throws {
        for table in ["usage_events", "abuse_signals", "business_controls", "business_applications", "operator_enrollments",
                      "org_invites", "org_memberships", "dashboard_sessions", "dashboard_ceremonies", "dashboard_passkeys",
                      "dashboard_users", "channel_outbound", "rcs_postbacks", "channel_endpoints"] {
            try await db.schema(table).delete()
        }
    }

    private func createIndexes(on db: any Database) async throws {
        guard let sql = db as? any SQLDatabase else { return }
        let indexes: [(String, String, String)] = [
            ("idx_channel_outbound_due", "channel_outbound", "status, next_attempt_at"),
            ("idx_channel_outbound_provider", "channel_outbound", "provider_message_id"),
            ("idx_channel_outbound_business", "channel_outbound", "business_id, created_at"),
            ("idx_rcs_postbacks_interaction", "rcs_postbacks", "interaction_id"),
            ("idx_dash_sessions_user", "dashboard_sessions", "user_id"),
            ("idx_memberships_user", "org_memberships", "user_id"),
            ("idx_org_invites_business", "org_invites", "business_id"),
            ("idx_usage_business_time", "usage_events", "business_id, occurred_at"),
            ("idx_abuse_business_time", "abuse_signals", "business_id, bucket"),
            ("idx_decisions_business", "decisions", "business_id, decision"),
            ("idx_consents_business", "consent_grants", "business_id, purpose"),
        ]
        for (name, table, columns) in indexes {
            // Identifiers are compile-time constants above; no user input reaches this statement.
            try await sql.raw(SQLQueryString("CREATE INDEX IF NOT EXISTS \(unsafeRaw: name) ON \(unsafeRaw: table) (\(unsafeRaw: columns))")).run()
        }
    }
}
