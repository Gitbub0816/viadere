import Fluent
import FluentSQL
import Foundation
import SQLKit
import ViadereCore

/// WP-B4/B5 (ADR-0013): device-first pseudonymous accounts and stored device trust tiers. **Additive and forward-only**: columns and a table
/// are added, two columns stop being mandatory, nothing is removed or rewritten except the tier backfill below.
///
/// * `consumers.display_name`, `consumers.user_handle`: nullable (a device-first account has neither until it adds a passkey). The existing
///   unique constraint on `user_handle` stays: PostgreSQL and SQLite both treat NULLs as distinct, so it needs no partial index.
/// * `consumers.policy_version` (default 1), `consumers.created_via` (default `passkey`).
/// * `account_enroll_ceremonies`: the single-use account-creation ceremony (reserved account id, challenge hash).
/// * `devices.key_algorithm` (`ES256`), `devices.trust_tier` (`d0`), `devices.integrity_format`, `devices.elevated_at`, `devices.elevated_by`.
/// * `app_attest_keys.format` (`apple-app-attest`), `passkey_credentials.status` (`active`).
/// * `audit_events.actor_ref`, `audit_events.policy_version` (covered by audit chain version 4).
///
/// **Backfill:** a device is `d1` (`elevated_by = migration_backfill`) only if it is an app device, not revoked, outside its window, App Attest
/// verified, and has a user-verified approval key. Everything else is `d0`. (Staging had no accounts when this shipped.)
struct CreateDeviceFirstAccounts: AsyncMigration {
    var name: String { "DeviceFirstAccounts.v1" }

    func prepare(on db: any Database) async throws {
        // One column per statement: SQLite cannot add several columns in a single ALTER TABLE.
        try await db.schema("consumers").field("policy_version", .int, .required, .sql(.default(1))).update()
        try await db.schema("consumers").field("created_via", .string, .required, .sql(.default("passkey"))).update()
        try await makeConsumerFieldsOptional(db)

        try await db.schema("account_enroll_ceremonies")
            .id()
            .field("reserved_account_id", .uuid, .required)
            .field("challenge_hash", .string, .required)
            .field("state", .string, .required)
            .field("expires_at", .datetime, .required)
            .field("created_at", .datetime, .required)
            .unique(on: "reserved_account_id")
            .unique(on: "challenge_hash")
            .create()

        try await db.schema("devices").field("key_algorithm", .string, .required, .sql(.default("ES256"))).update()
        try await db.schema("devices").field("trust_tier", .string, .required, .sql(.default("d0"))).update()
        try await db.schema("devices").field("integrity_format", .string).update()
        try await db.schema("devices").field("elevated_at", .datetime).update()
        try await db.schema("devices").field("elevated_by", .string).update()
        try await db.schema("app_attest_keys").field("format", .string, .required, .sql(.default("apple-app-attest"))).update()
        try await db.schema("passkey_credentials").field("status", .string, .required, .sql(.default("active"))).update()
        try await db.schema("audit_events").field("actor_ref", .string).update()
        try await db.schema("audit_events").field("policy_version", .int).update()

        guard let sql = db as? any SQLDatabase else { return }
        try await sql.raw("UPDATE devices SET integrity_format = 'apple-app-attest' WHERE attestation_status = 'attested'").run()
        let now = Date()
        try await sql.raw("""
            UPDATE devices SET trust_tier = 'd1', elevated_at = \(bind: now), elevated_by = \(bind: TrustElevation.migrationBackfill.rawValue)
            WHERE client_kind = 'app' AND revoked_at IS NULL AND attestation_status = 'attested'
              AND (approvals_locked_until IS NULL OR approvals_locked_until <= \(bind: now))
              AND EXISTS (SELECT 1 FROM device_keys k WHERE k.device_id = devices.id AND k.purpose IN ('approvalBiometric', 'approvalUserPresence'))
            """).run()
    }

    /// PostgreSQL drops the NOT NULL constraints in place. SQLite cannot, so the table is rebuilt from its own DDL with the two constraints
    /// removed, inside one transaction with foreign-key checks deferred to the commit (the rows and the table name are the same afterwards).
    private func makeConsumerFieldsOptional(_ db: any Database) async throws {
        guard let sql = db as? any SQLDatabase else { return }
        if DB.isPostgres(db) {
            try await sql.raw("ALTER TABLE consumers ALTER COLUMN display_name DROP NOT NULL").run()
            try await sql.raw("ALTER TABLE consumers ALTER COLUMN user_handle DROP NOT NULL").run()
            return
        }
        try await db.transaction { tx in
            guard let sql = tx as? any SQLDatabase,
                  let row = try await sql.raw("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'consumers'").first() else { return }
            let original = try row.decode(column: "sql", as: String.self)
            var rebuilt = original
            for column in ["display_name", "user_handle"] {
                let required = "\"\(column)\" TEXT NOT NULL"
                guard rebuilt.contains(required) else { throw DeviceFirstMigrationError.unexpectedSchema(column) }
                rebuilt = rebuilt.replacingOccurrences(of: required, with: "\"\(column)\" TEXT")
            }
            guard let range = rebuilt.range(of: "CREATE TABLE \"consumers\"") else { throw DeviceFirstMigrationError.unexpectedSchema("consumers") }
            rebuilt.replaceSubrange(range, with: "CREATE TABLE \"consumers_device_first\"")
            let indexes = try await sql.raw("SELECT sql FROM sqlite_master WHERE type = 'index' AND tbl_name = 'consumers' AND sql IS NOT NULL").all()
                .map { try $0.decode(column: "sql", as: String.self) }
            try await sql.raw("PRAGMA defer_foreign_keys = ON").run()
            try await sql.raw(SQLQueryString(rebuilt)).run()
            try await sql.raw("INSERT INTO consumers_device_first SELECT * FROM consumers").run()
            try await sql.raw("DROP TABLE consumers").run()
            try await sql.raw("ALTER TABLE consumers_device_first RENAME TO consumers").run()
            for index in indexes { try await sql.raw(SQLQueryString(index)).run() }
        }
    }

    /// Test databases are reverted between runs. The two columns stay nullable (forward-only: putting NOT NULL back could fail on real rows).
    func revert(on db: any Database) async throws {
        try await db.schema("account_enroll_ceremonies").delete()
        for (table, column) in [("consumers", "policy_version"), ("consumers", "created_via"), ("devices", "key_algorithm"), ("devices", "trust_tier"),
                                ("devices", "integrity_format"), ("devices", "elevated_at"), ("devices", "elevated_by"), ("app_attest_keys", "format"),
                                ("passkey_credentials", "status"), ("audit_events", "actor_ref"), ("audit_events", "policy_version")] {
            try await db.schema(table).deleteField(FieldKey(stringLiteral: column)).update()
        }
    }
}

enum DeviceFirstMigrationError: Error, CustomStringConvertible {
    case unexpectedSchema(String)
    var description: String {
        switch self {
        case .unexpectedSchema(let what): "DeviceFirstAccounts.v1: unexpected SQLite schema for \(what); refusing to rebuild the table"
        }
    }
}
