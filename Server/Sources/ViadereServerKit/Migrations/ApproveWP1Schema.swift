import Fluent
import FluentSQL
import Foundation
import SQLKit

/// WP1 (Approve v2, business key directory, transparency log): pairwise approval keys, business-authorized enrollments, signed-result
/// requests, freezes, the append-only Merkle log, and the webhook envelope version.
///
/// Nothing here stores a plaintext transaction for an end-to-end request, a private key, or a Viadere-held business key: the log and the
/// key tables hold public keys and signatures only; `approve_requests.details_sealed` exists only for server-visible requests and is
/// AES-GCM-sealed per row.
struct CreateApproveWP1Schema: AsyncMigration {
    var name: String { "CreateApproveWP1Schema.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema("kd_log_entries")
            .id()
            .field("idx", .int, .required)
            .field("business_id", .uuid, .required)
            .field("entry_type", .string, .required)
            .field("entry", .string, .required)
            .field("leaf_hash", .string, .required)
            .field("created_at", .datetime, .required)
            .unique(on: "idx")
            .create()

        try await db.schema("kd_tree_heads")
            .id()
            .field("tree_size", .int, .required)
            .field("root_hash", .string, .required)
            .field("payload", .string, .required)
            .field("signature", .string, .required)
            .field("created_at", .datetime, .required)
            .create()

        try await db.schema("approve_enrollments")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("relationship_id", .uuid, .required)
            .field("consumer_id", .uuid, .required)
            .field("subject_ref", .string, .required)
            .field("capability", .string, .required)
            .field("required_assurance", .string, .required)
            .field("code_hash", .string, .required)
            .field("status", .string, .required)
            .field("created_at", .datetime, .required)
            .field("expires_at", .datetime, .required)
            .field("claimed_device_id", .uuid)
            .field("statement_payload", .string)
            .field("statement_signature", .string)
            .field("kid", .string)
            .field("device_completed_at", .datetime)
            .field("confirmation", .string)
            .field("confirmed_at", .datetime)
            .field("cancelled_at", .datetime)
            .unique(on: "code_hash")
            .create()

        try await db.schema("approve_keys")
            .id()
            .field("kid", .string, .required)
            .field("enrollment_id", .uuid, .required)
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("relationship_id", .uuid, .required)
            .field("consumer_id", .uuid, .required)
            .field("device_id", .uuid, .required)
            .field("subject_ref", .string, .required)
            .field("public_key", .string, .required)
            .field("hpke_kid", .string, .required)
            .field("hpke_public_key", .string, .required)
            .field("assurance", .string, .required)
            .field("status", .string, .required)
            .field("statement_payload", .string, .required)
            .field("statement_signature", .string, .required)
            .field("confirmation", .string)
            .field("created_at", .datetime, .required)
            .field("activated_at", .datetime)
            .field("revoked_at", .datetime)
            .field("revoked_by", .string)
            .field("revoke_reason", .string)
            .unique(on: "kid")
            .unique(on: "hpke_kid")
            .unique(on: "enrollment_id")
            .create()

        try await db.schema("approve_requests")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("request_id", .string, .required)
            .field("relationship_id", .uuid, .required)
            .field("consumer_id", .uuid, .required)
            .field("subject_ref", .string, .required)
            .field("capability", .string, .required)
            .field("protection", .string, .required)
            .field("request_hash", .string, .required)
            .field("challenge", .string)
            .field("details_sealed", .string)
            .field("status", .string, .required)
            .field("reason", .string)
            .field("created_at", .datetime, .required)
            .field("expires_at", .datetime, .required)
            .field("decided_at", .datetime)
            .field("decided_kid", .string)
            .field("decision", .string)
            .field("amr", .string)
            .field("result_ref", .string)
            .field("result_jws", .string)
            .field("delivered", .int, .required)
            .unique(on: "business_id", "request_id")
            .unique(on: "result_ref")
            .create()

        try await db.schema("approve_deliveries")
            .id()
            .field("request_id", .uuid, .required, .references("approve_requests", "id", onDelete: .cascade))
            .field("kid", .string, .required)
            .field("device_id", .uuid, .required)
            .field("consumer_id", .uuid, .required)
            .field("envelope", .string)
            .field("created_at", .datetime, .required)
            .unique(on: "request_id", "kid")
            .create()

        try await db.schema("approve_freezes")
            .id()
            .field("consumer_id", .uuid, .required)
            .field("scope", .string, .required)
            .field("relationship_id", .uuid)
            .field("business_id", .uuid)
            .field("frozen_by", .string, .required)
            .field("reason", .string)
            .field("created_at", .datetime, .required)
            .field("lifted_at", .datetime)
            .create()

        // Webhook subscriptions: the body format (v1 `WebhookEvent`, or the opaque `2026-10-27` envelope) and the version of the signing secret.
        try await db.schema("webhook_subscriptions").field("envelope_version", .string).update()
        try await db.schema("webhook_subscriptions").field("secret_version", .int, .required, .sql(.default(1))).update()

        guard let sql = db as? any SQLDatabase else { return }
        let indexes: [(String, String, String)] = [
            ("idx_kd_entries_business", "kd_log_entries", "business_id, idx"),
            ("idx_approve_enroll_business", "approve_enrollments", "business_id, status"),
            ("idx_approve_enroll_consumer", "approve_enrollments", "consumer_id, status"),
            ("idx_approve_keys_relationship", "approve_keys", "relationship_id, status"),
            ("idx_approve_keys_consumer", "approve_keys", "consumer_id, status"),
            ("idx_approve_requests_relationship", "approve_requests", "relationship_id, created_at"),
            ("idx_approve_requests_due", "approve_requests", "status, expires_at"),
            ("idx_approve_deliveries_device", "approve_deliveries", "device_id"),
            ("idx_approve_freezes_consumer", "approve_freezes", "consumer_id, lifted_at"),
        ]
        for (name, table, columns) in indexes {
            // Identifiers are compile-time constants above; no user input reaches this statement.
            try await sql.raw(SQLQueryString("CREATE INDEX IF NOT EXISTS \(unsafeRaw: name) ON \(unsafeRaw: table) (\(unsafeRaw: columns))")).run()
        }
        try await createAppendOnlyTriggers(sql)
    }

    /// The log is append-only: the database refuses to change or delete an entry or a signed head, whatever the application does.
    private func createAppendOnlyTriggers(_ sql: any SQLDatabase) async throws {
        let tables = ["kd_log_entries", "kd_tree_heads"]
        if sql.dialect.name == "postgresql" {
            // The function is shared with the audit tables (`viadere_append_only`); it is created there and replaced idempotently here.
            try await sql.raw("""
                CREATE OR REPLACE FUNCTION viadere_append_only() RETURNS trigger AS $$
                BEGIN
                    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
                END;
                $$ LANGUAGE plpgsql
                """).run()
            for table in tables {
                try await sql.raw(SQLQueryString("""
                    CREATE TRIGGER \(unsafeRaw: table)_append_only BEFORE UPDATE OR DELETE ON \(unsafeRaw: table)
                    FOR EACH ROW EXECUTE FUNCTION viadere_append_only()
                    """)).run()
            }
        } else {
            for table in tables {
                try await sql.raw(SQLQueryString("""
                    CREATE TRIGGER \(unsafeRaw: table)_no_update BEFORE UPDATE ON \(unsafeRaw: table)
                    BEGIN SELECT RAISE(ABORT, 'append-only table'); END
                    """)).run()
                try await sql.raw(SQLQueryString("""
                    CREATE TRIGGER \(unsafeRaw: table)_no_delete BEFORE DELETE ON \(unsafeRaw: table)
                    BEGIN SELECT RAISE(ABORT, 'append-only table'); END
                    """)).run()
            }
        }
    }

    func revert(on db: any Database) async throws {
        guard let sql = db as? any SQLDatabase else { return }
        try await db.schema("webhook_subscriptions").deleteField("secret_version").update()
        try await db.schema("webhook_subscriptions").deleteField("envelope_version").update()
        for table in ["approve_freezes", "approve_deliveries", "approve_requests", "approve_keys", "approve_enrollments", "kd_tree_heads", "kd_log_entries"] {
            try await sql.raw(SQLQueryString("DROP TABLE IF EXISTS \(unsafeRaw: table)")).run()
        }
    }
}
