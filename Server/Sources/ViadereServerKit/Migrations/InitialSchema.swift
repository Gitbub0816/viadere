import Fluent
import FluentSQL
import SQLKit
import Foundation

/// Creates the complete P0–P2 schema. Rows that must be unique for security reasons are protected by
/// database constraints, not application checks.
struct CreateInitialSchema: AsyncMigration {
    var name: String { "CreateInitialSchema.v1" }

    func prepare(on db: any Database) async throws {
        // MARK: Businesses
        try await db.schema("businesses")
            .id()
            .field("display_name", .string, .required)
            .field("legal_name", .string)
            .field("search_text", .string, .required)
            .field("category", .string, .required)
            .field("verification_status", .string, .required)
            .field("verified_at", .datetime)
            .field("brand_color", .string)
            .field("logo_url", .string)
            .field("website_url", .string)
            .field("tier", .string, .required)
            .field("daily_quota", .int, .required)
            .field("created_at", .datetime, .required)
            .create()

        try await db.schema("business_handles")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("handle", .string, .required)
            .field("skeleton", .string, .required)
            .field("status", .string, .required)
            .field("created_at", .datetime, .required)
            .unique(on: "handle")
            .unique(on: "skeleton")
            .create()

        try await db.schema("business_codes")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("canonical", .string, .required)
            .field("created_at", .datetime, .required)
            .unique(on: "canonical")
            .unique(on: "business_id")
            .create()

        try await db.schema("retired_business_codes")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("canonical", .string, .required)
            .field("retired_at", .datetime, .required)
            .unique(on: "canonical")
            .create()

        try await db.schema("business_api_keys")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("key_hash", .string, .required)
            .field("prefix", .string, .required)
            .field("last4", .string, .required)
            .field("name", .string, .required)
            .field("scopes", .string, .required)
            .field("created_at", .datetime, .required)
            .field("last_used_at", .datetime)
            .field("expires_at", .datetime)
            .field("revoked_at", .datetime)
            .unique(on: "key_hash")
            .create()

        // MARK: Consumers and authentication
        try await db.schema("consumers")
            .id()
            .field("display_name", .string, .required)
            .field("user_handle", .string, .required)
            .field("status", .string, .required)
            .field("created_at", .datetime, .required)
            .unique(on: "user_handle")
            .create()

        try await db.schema("passkey_credentials")
            .id()
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("credential_id", .string, .required)
            .field("public_key", .string, .required)
            .field("sign_count", .int, .required)
            .field("backup_eligible", .bool, .required)
            .field("created_at", .datetime, .required)
            .field("last_used_at", .datetime)
            .unique(on: "credential_id")
            .create()

        try await db.schema("passkey_ceremonies")
            .id()
            .field("kind", .string, .required)
            .field("challenge", .string, .required)
            .field("consumer_id", .uuid)
            .field("display_name", .string)
            .field("user_handle", .string)
            .field("state", .string, .required)
            .field("expires_at", .datetime, .required)
            .field("created_at", .datetime, .required)
            .create()

        try await db.schema("access_tokens")
            .id()
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("token_hash", .string, .required)
            .field("family_id", .uuid, .required)
            .field("expires_at", .datetime, .required)
            .field("created_at", .datetime, .required)
            .field("revoked_at", .datetime)
            .unique(on: "token_hash")
            .create()

        try await db.schema("refresh_tokens")
            .id()
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("token_hash", .string, .required)
            .field("family_id", .uuid, .required)
            .field("state", .string, .required)
            .field("expires_at", .datetime, .required)
            .field("created_at", .datetime, .required)
            .field("used_at", .datetime)
            .unique(on: "token_hash")
            .create()

        try await db.schema("devices")
            .id()
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("name", .string, .required)
            .field("platform", .string, .required)
            .field("created_at", .datetime, .required)
            .field("last_seen_at", .datetime)
            .field("revoked_at", .datetime)
            .create()

        try await db.schema("device_keys")
            .id()
            .field("device_id", .uuid, .required, .references("devices", "id"))
            .field("purpose", .string, .required)
            .field("public_key", .string, .required)
            .field("hardware_backed", .bool, .required)
            .field("created_at", .datetime, .required)
            .unique(on: "device_id", "purpose")
            .create()

        try await db.schema("device_enroll_challenges")
            .id()
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("challenge_hash", .string, .required)
            .field("state", .string, .required)
            .field("expires_at", .datetime, .required)
            .unique(on: "challenge_hash")
            .create()

        try await db.schema("phone_links")
            .id()
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("phone_hash", .string, .required)
            .field("phone_ciphertext", .string, .required)
            .field("phone_masked", .string, .required)
            .field("phone_last4", .string, .required)
            .field("state", .string, .required)
            .field("otp_hash", .string)
            .field("otp_expires_at", .datetime)
            .field("otp_attempts", .int, .required)
            .field("verified_phone_hash", .string)
            .field("created_at", .datetime, .required)
            .field("verified_at", .datetime)
            .unique(on: "verified_phone_hash")
            .create()

        // MARK: Relationships, consent, push, delegation
        try await db.schema("relationships")
            .id()
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("status", .string, .required)
            .field("source", .string, .required)
            .field("connected_at", .datetime, .required)
            .field("disconnected_at", .datetime)
            .field("last_activity_at", .datetime, .required)
            .unique(on: "consumer_id", "business_id")
            .create()

        try await db.schema("consent_grants")
            .id()
            .field("consumer_id", .uuid, .required)
            .field("business_id", .uuid, .required)
            .field("relationship_id", .uuid, .required, .references("relationships", "id"))
            .field("purpose", .string, .required)
            .field("granted", .bool, .required)
            .field("version", .int, .required)
            .field("policy_version", .string, .required)
            .field("source", .string, .required)
            .field("channels", .string, .required)
            .field("created_at", .datetime, .required)
            .unique(on: "relationship_id", "purpose", "version")
            .create()

        try await db.schema("delegation_grants")
            .id()
            .field("grantor_id", .uuid, .required, .references("consumers", "id"))
            .field("delegate_id", .uuid, .required, .references("consumers", "id"))
            .field("role", .string, .required)
            .field("purposes", .string, .required)
            .field("business_ids", .string, .required)
            .field("created_at", .datetime, .required)
            .field("expires_at", .datetime, .required)
            .field("revoked_at", .datetime)
            .create()

        try await db.schema("apns_tokens")
            .id()
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("device_id", .uuid, .required, .references("devices", "id"))
            .field("token", .string, .required)
            .field("environment", .string, .required)
            .field("bundle_id", .string, .required)
            .field("updated_at", .datetime, .required)
            .field("invalidated_at", .datetime)
            .unique(on: "device_id")
            .create()

        try await db.schema("live_activity_tokens")
            .id()
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("device_id", .uuid, .required, .references("devices", "id"))
            .field("kind", .string, .required)
            .field("activity_id", .string)
            .field("business_id", .uuid)
            .field("interaction_id", .uuid)
            .field("push_token", .string, .required)
            .field("updated_at", .datetime, .required)
            .create()

        // MARK: Interactions and conversations
        try await db.schema("interactions")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("relationship_id", .uuid, .required, .references("relationships", "id"))
            .field("kind", .string, .required)
            .field("purpose", .string, .required)
            .field("status", .string, .required)
            .field("priority", .string, .required)
            .field("sensitivity", .string, .required)
            .field("livemode", .bool, .required)
            .field("interaction_json", .string, .required)
            .field("idempotency_key", .string, .required)
            .field("request_hash", .string, .required)
            .field("correlation_id", .string)
            .field("activity_key", .string)
            .field("created_at", .datetime, .required)
            .field("expires_at", .datetime, .required)
            .field("decided_at", .datetime)
            .field("outcome_json", .string)
            .field("expiry_notified", .bool, .required)
            .unique(on: "business_id", "idempotency_key")
            .create()

        try await db.schema("interaction_challenges")
            .id()
            .field("interaction_id", .uuid, .required, .references("interactions", "id"))
            .field("nonce_hash", .string, .required)
            .field("issued_at", .datetime, .required)
            .field("expires_at", .datetime, .required)
            .field("consumed_at", .datetime)
            .field("consumed_by_device", .uuid)
            .unique(on: "interaction_id")
            .create()

        try await db.schema("decisions")
            .id()
            .field("interaction_id", .uuid, .required, .references("interactions", "id"))
            .field("business_id", .uuid, .required)
            .field("consumer_id", .uuid, .required)
            .field("device_id", .uuid, .required)
            .field("decision", .string, .required)
            .field("assurance", .string, .required)
            .field("channel", .string, .required)
            .field("signed_payload", .string, .required)
            .field("signature", .string, .required)
            .field("decided_at", .datetime, .required)
            .unique(on: "interaction_id")
            .create()

        try await db.schema("conversation_sessions")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("relationship_id", .uuid, .required, .references("relationships", "id"))
            .field("channel", .string, .required)
            .field("state", .string, .required)
            .field("created_at", .datetime, .required)
            .field("last_message_at", .datetime)
            .field("closed_at", .datetime)
            .create()

        try await db.schema("conversation_messages")
            .id()
            .field("session_id", .uuid, .required, .references("conversation_sessions", "id"))
            .field("business_id", .uuid, .required)
            .field("consumer_id", .uuid, .required)
            .field("direction", .string, .required)
            .field("sender_type", .string, .required)
            .field("display_name", .string, .required)
            .field("agent_name", .string)
            .field("body_ciphertext", .string, .required)
            .field("channel", .string, .required)
            .field("delivery_status", .string, .required)
            .field("created_at", .datetime, .required)
            .field("delivered_at", .datetime)
            .field("read_at", .datetime)
            .field("interaction_id", .uuid)
            .field("idempotency_key", .string)
            .field("request_hash", .string)
            .field("client_message_id", .string)
            .field("provider_message_id", .string)
            .unique(on: "business_id", "idempotency_key")
            .unique(on: "session_id", "client_message_id")
            .create()

        // MARK: Operational tables
        try await db.schema("replay_nonces")
            .id()
            .field("scope", .string, .required)
            .field("nonce", .string, .required)
            .field("expires_at", .datetime, .required)
            .unique(on: "scope", "nonce")
            .create()

        try await db.schema("audit_events")
            .id()
            .field("seq", .int64, .required)
            .field("occurred_at", .datetime, .required)
            .field("actor_kind", .string, .required)
            .field("actor_id", .string)
            .field("action", .string, .required)
            .field("outcome", .string, .required)
            .field("consumer_id", .uuid)
            .field("business_id", .uuid)
            .field("subject_type", .string)
            .field("subject_id", .string)
            .field("correlation_id", .string)
            .field("metadata_json", .string, .required)
            .field("prev_hash", .string, .required)
            .field("hash", .string, .required)
            .unique(on: "seq")
            .create()

        try await db.schema("link_tokens")
            .id()
            .field("kind", .string, .required)
            .field("token_hash", .string, .required)
            .field("phone_hash", .string, .required)
            .field("phone_ciphertext", .string, .required)
            .field("phone_last4", .string, .required)
            .field("context_revision", .int, .required)
            .field("consumer_id", .uuid)
            .field("purpose", .string)
            .field("interaction_id", .uuid)
            .field("attempts", .int, .required)
            .field("state", .string, .required)
            .field("created_at", .datetime, .required)
            .field("expires_at", .datetime, .required)
            .field("consumed_at", .datetime)
            .unique(on: "token_hash")
            .create()

        try await db.schema("sms_contexts")
            .id()
            .field("phone_hash", .string, .required)
            .field("context_ciphertext", .string, .required)
            .field("revision", .int, .required)
            .field("consumer_id", .uuid)
            .field("active_session_id", .uuid)
            .field("opted_out", .bool, .required)
            .field("updated_at", .datetime, .required)
            .unique(on: "phone_hash")
            .create()

        try await db.schema("processed_provider_messages")
            .id()
            .field("provider", .string, .required)
            .field("provider_message_id", .string, .required)
            .field("received_at", .datetime, .required)
            .unique(on: "provider", "provider_message_id")
            .create()

        try await db.schema("sms_consent_events")
            .id()
            .field("phone_hash", .string, .required)
            .field("opted_out", .bool, .required)
            .field("keyword", .string, .required)
            .field("occurred_at", .datetime, .required)
            .create()

        try await db.schema("sms_outbound")
            .id()
            .field("seq", .int64, .required)
            .field("phone_hash", .string, .required)
            .field("phone_ciphertext", .string, .required)
            .field("body_ciphertext", .string, .required)
            .field("sensitive", .bool, .required)
            .field("allow_when_opted_out", .bool, .required)
            .field("status", .string, .required)
            .field("attempts", .int, .required)
            .field("next_attempt_at", .datetime, .required)
            .field("provider_message_id", .string)
            .field("error_code", .string)
            .field("message_id", .uuid)
            .field("created_at", .datetime, .required)
            .field("sent_at", .datetime)
            .unique(on: "seq")
            .create()

        try await db.schema("webhook_subscriptions")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("url", .string, .required)
            .field("events", .string, .required)
            .field("secret_ciphertext", .string, .required)
            .field("previous_secret_ciphertext", .string)
            .field("previous_secret_expires_at", .datetime)
            .field("active", .bool, .required)
            .field("created_at", .datetime, .required)
            .create()

        try await db.schema("webhook_deliveries")
            .id()
            .field("subscription_id", .uuid, .required, .references("webhook_subscriptions", "id"))
            .field("business_id", .uuid, .required)
            .field("event_type", .string, .required)
            .field("body", .string, .required)
            .field("status", .string, .required)
            .field("attempts", .int, .required)
            .field("next_attempt_at", .datetime, .required)
            .field("last_status_code", .int)
            .field("last_error", .string)
            .field("created_at", .datetime, .required)
            .field("delivered_at", .datetime)
            .create()

        try await db.schema("webhook_delivery_attempts")
            .id()
            .field("delivery_id", .uuid, .required, .references("webhook_deliveries", "id"))
            .field("attempt", .int, .required)
            .field("attempted_at", .datetime, .required)
            .field("status_code", .int)
            .field("duration_ms", .int, .required)
            .field("error", .string)
            .create()

        try await createIndexes(on: db)
        try await createAuditTriggers(on: db)
    }

    func revert(on db: any Database) async throws {
        for table in ["webhook_delivery_attempts", "webhook_deliveries", "webhook_subscriptions", "sms_outbound", "sms_consent_events",
                      "processed_provider_messages", "sms_contexts", "link_tokens", "audit_events", "replay_nonces",
                      "conversation_messages", "conversation_sessions", "decisions", "interaction_challenges", "interactions",
                      "live_activity_tokens", "apns_tokens", "delegation_grants", "consent_grants", "relationships", "phone_links",
                      "device_enroll_challenges", "device_keys", "devices", "refresh_tokens", "access_tokens", "passkey_ceremonies",
                      "passkey_credentials", "consumers", "business_api_keys", "retired_business_codes", "business_codes",
                      "business_handles", "businesses"] {
            try await db.schema(table).delete()
        }
    }

    // MARK: Indexes

    private func createIndexes(on db: any Database) async throws {
        guard let sql = db as? any SQLDatabase else { return }
        let indexes: [(String, String, String)] = [
            ("idx_interactions_consumer_status", "interactions", "consumer_id, status, created_at"),
            ("idx_interactions_business_created", "interactions", "business_id, created_at"),
            ("idx_interactions_pending_expiry", "interactions", "status, expires_at"),
            ("idx_relationships_consumer", "relationships", "consumer_id"),
            ("idx_relationships_business", "relationships", "business_id"),
            ("idx_devices_consumer", "devices", "consumer_id"),
            ("idx_consents_relationship", "consent_grants", "relationship_id, purpose"),
            ("idx_messages_session", "conversation_messages", "session_id, created_at"),
            ("idx_sessions_consumer", "conversation_sessions", "consumer_id"),
            ("idx_sessions_business", "conversation_sessions", "business_id"),
            ("idx_sms_outbound_due", "sms_outbound", "status, next_attempt_at"),
            ("idx_sms_outbound_phone", "sms_outbound", "phone_hash, seq"),
            ("idx_webhook_deliveries_due", "webhook_deliveries", "status, next_attempt_at"),
            ("idx_webhook_subs_business", "webhook_subscriptions", "business_id"),
            ("idx_replay_expiry", "replay_nonces", "expires_at"),
            ("idx_phone_links_consumer", "phone_links", "consumer_id"),
            ("idx_phone_links_phone", "phone_links", "phone_hash"),
            ("idx_audit_business", "audit_events", "business_id, seq"),
            ("idx_link_tokens_phone", "link_tokens", "phone_hash, kind"),
            ("idx_access_tokens_family", "access_tokens", "family_id"),
            ("idx_refresh_tokens_family", "refresh_tokens", "family_id"),
        ]
        for (name, table, columns) in indexes {
            // Identifiers are compile-time constants above; no user input reaches this statement.
            try await sql.raw(SQLQueryString("CREATE INDEX IF NOT EXISTS \(unsafeRaw: name) ON \(unsafeRaw: table) (\(unsafeRaw: columns))")).run()
        }
    }

    // MARK: Append-only tables

    /// Audit events, consent history, decisions and SMS consent events are never edited or deleted.
    /// The database enforces it, so even a bug (or a compromised application role) cannot rewrite history.
    private func createAuditTriggers(on db: any Database) async throws {
        guard let sql = db as? any SQLDatabase else { return }
        let tables: [(table: String, name: String)] = [
            ("audit_events", "audit_events_no_update"),
            ("consent_grants", "consent_grants_no_update"),
            ("decisions", "decisions_no_update"),
            ("sms_consent_events", "sms_consent_events_no_update"),
        ]
        if sql.dialect.name == "postgresql" {
            try await sql.raw("""
                CREATE OR REPLACE FUNCTION viadere_append_only() RETURNS trigger AS $$
                BEGIN
                    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
                END;
                $$ LANGUAGE plpgsql
                """).run()
            for (table, name) in tables {
                // Names are compile-time constants.
                try await sql.raw(SQLQueryString("""
                    CREATE TRIGGER \(unsafeRaw: name) BEFORE UPDATE OR DELETE ON \(unsafeRaw: table)
                    FOR EACH ROW EXECUTE FUNCTION viadere_append_only()
                    """)).run()
            }
        } else {
            for (table, name) in tables {
                try await sql.raw(SQLQueryString("""
                    CREATE TRIGGER \(unsafeRaw: name) BEFORE UPDATE ON \(unsafeRaw: table)
                    BEGIN SELECT RAISE(ABORT, 'append-only table'); END
                    """)).run()
                try await sql.raw(SQLQueryString("""
                    CREATE TRIGGER \(unsafeRaw: table + "_no_delete") BEFORE DELETE ON \(unsafeRaw: table)
                    BEGIN SELECT RAISE(ABORT, 'append-only table'); END
                    """)).run()
            }
        }
    }
}

/// Business-side invariants that SQL cannot express portably.
enum Migrations {
    static let all: [any AsyncMigration] = [CreateInitialSchema(), CreatePlatformSchema(), CreateP3Schema(), CreateSecurityHardeningSchema(), CreateSecurityRound3Schema(), CreatePlatformRound4Schema(), CreateIdentityRound4Schema(), CreateRecoveryRound5Schema(), CreatePolicyWP2Schema(), CreateVaultWP5Schema(), CreateVerifyWP3Schema(), CreateApproveWP1Schema(), CreateApproveGateSchema(), CreatePlatformWP6Schema(), CreateRetentionDeleteGate(), CreateDecisionsRetentionGate(), CreateVerifyGateSchema(), GrantRuntimeRolePrivileges()]
}
