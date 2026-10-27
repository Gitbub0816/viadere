import Fluent
import FluentSQL
import Foundation
import SQLKit

/// Security hardening (review round 2): passkey-bound enrollment and token-family/device binding, new-device cool-down,
/// App Clip devices, linked-phone cool-down, keyed audit chain, and the one permitted edit of an append-only row (the
/// erasure of a deleted account's signed free text).
struct CreateSecurityHardeningSchema: AsyncMigration {
    var name: String { "CreateSecurityHardeningSchema.v3" }

    /// Sentinel written over erased free text.
    static let erased = "[erased]"

    func prepare(on db: any Database) async throws {
        // One column per statement: SQLite cannot add several columns in a single ALTER TABLE.
        // MARK: Token families
        try await db.schema("token_families")
            .id()
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("origin", .string, .required)
            .field("created_at", .datetime, .required)
            .field("enroll_until", .datetime)
            .field("device_id", .uuid)
            .field("expires_at", .datetime)
            .field("revoked_at", .datetime)
            .create()

        // MARK: Devices
        try await db.schema("devices").field("client_kind", .string, .required, .sql(.default("app"))).update()
        try await db.schema("devices").field("approvals_locked_until", .datetime).update()
        try await db.schema("devices").field("expires_at", .datetime).update()
        try await db.schema("devices").field("family_id", .uuid).update()
        try await db.schema("devices").field("confirmed_at", .datetime).update()
        try await db.schema("devices").field("enrollment_method", .string, .required, .sql(.default("legacy"))).update()
        try await db.schema("device_keys").field("attested", .bool, .required, .sql(.default(false))).update()
        try await db.schema("device_enroll_challenges").field("family_id", .uuid).update()

        // MARK: Phone links
        try await db.schema("phone_links").field("usable_from", .datetime).update()
        try await db.schema("phone_links").field("source", .string).update()
        try await db.schema("phone_links").field("confirmed_at", .datetime).update()

        // MARK: Audit chain (1 = legacy unkeyed SHA-256, 2 = HMAC-SHA256 keyed with AUDIT_CHAIN_KEY, row id hashed)
        try await db.schema("audit_events").field("chain_version", .int, .required, .sql(.default(1))).update()

        try await createIndexes(on: db)
        try await replaceDecisionGuard(on: db)
    }

    func revert(on db: any Database) async throws {
        try await db.schema("audit_events").deleteField("chain_version").update()
        for column in ["confirmed_at", "source", "usable_from"] {
            try await db.schema("phone_links").deleteField(.string(column)).update()
        }
        try await db.schema("device_enroll_challenges").deleteField("family_id").update()
        try await db.schema("device_keys").deleteField("attested").update()
        for column in ["enrollment_method", "confirmed_at", "family_id", "expires_at", "approvals_locked_until", "client_kind"] {
            try await db.schema("devices").deleteField(.string(column)).update()
        }
        try await db.schema("token_families").delete()
    }

    private func createIndexes(on db: any Database) async throws {
        guard let sql = db as? any SQLDatabase else { return }
        let indexes: [(String, String, String)] = [
            ("idx_token_families_consumer", "token_families", "consumer_id"),
            ("idx_token_families_device", "token_families", "device_id"),
            ("idx_devices_family", "devices", "family_id"),
            ("idx_webhook_deliveries_created", "webhook_deliveries", "status, created_at"),
        ]
        for (name, table, columns) in indexes {
            // Identifiers are compile-time constants above; no user input reaches this statement.
            try await sql.raw(SQLQueryString("CREATE INDEX IF NOT EXISTS \(unsafeRaw: name) ON \(unsafeRaw: table) (\(unsafeRaw: columns))")).run()
        }
    }

    /// `decisions` stays append-only with exactly one exception: `signed_payload` may be overwritten with `[erased]` (account
    /// deletion removes the free-text `reply` the payload carries). Every other column is immutable and rows are never deleted.
    private func replaceDecisionGuard(on db: any Database) async throws {
        guard let sql = db as? any SQLDatabase else { return }
        let others = ["id", "interaction_id", "business_id", "consumer_id", "device_id", "decision", "assurance", "channel", "signature", "decided_at"]
        if sql.dialect.name == "postgresql" {
            try await sql.raw("DROP TRIGGER IF EXISTS decisions_no_update ON decisions").run()
            try await sql.raw("""
                CREATE OR REPLACE FUNCTION viadere_decisions_guard() RETURNS trigger AS $$
                BEGIN
                    IF TG_OP = 'UPDATE' AND NEW.signed_payload = '[erased]'
                       AND (to_jsonb(NEW) - 'signed_payload') = (to_jsonb(OLD) - 'signed_payload') THEN
                        RETURN NEW;
                    END IF;
                    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
                END;
                $$ LANGUAGE plpgsql
                """).run()
            try await sql.raw("""
                CREATE TRIGGER decisions_guard BEFORE UPDATE OR DELETE ON decisions
                FOR EACH ROW EXECUTE FUNCTION viadere_decisions_guard()
                """).run()
        } else {
            try await sql.raw("DROP TRIGGER IF EXISTS decisions_no_update").run()
            // Column names are compile-time constants.
            let unchanged = others.map { "NEW.\($0) IS OLD.\($0)" }.joined(separator: " AND ")
            try await sql.raw(SQLQueryString("""
                CREATE TRIGGER decisions_guard BEFORE UPDATE ON decisions
                WHEN NOT (NEW.signed_payload = '[erased]' AND \(unsafeRaw: unchanged))
                BEGIN SELECT RAISE(ABORT, 'append-only table'); END
                """)).run()
        }
    }
}
