import Fluent
import FluentSQL
import Foundation
import SQLKit

/// Database role split (WP6): the **migrator** role owns the schema and runs `ViadereServer migrate` (`DATABASE_MIGRATION_URL`, the Fly release
/// command); the **runtime** role (`DATABASE_URL`) gets data privileges only. This migration, when `DATABASE_APP_ROLE` names the runtime role,
/// grants it SELECT/INSERT/UPDATE/DELETE on every table and USAGE on every sequence, and sets default privileges so tables created by later
/// migrations are covered too. Without `DATABASE_APP_ROLE` (development, tests, a single-role deployment) it does nothing.
struct GrantRuntimeRolePrivileges: AsyncMigration {
    var name: String { "GrantRuntimeRolePrivileges.v1" }

    /// A PostgreSQL identifier the grants may interpolate: letters, digits and underscores only, never starting with a digit.
    static func isSafeRoleName(_ name: String) -> Bool {
        (1...63).contains(name.count) && name.unicodeScalars.allSatisfy { ($0.isASCII && ($0.properties.isAlphabetic || ("0"..."9").contains($0))) || $0 == "_" }
            && !(name.first?.isNumber ?? true)
    }

    func prepare(on db: any Database) async throws {
        guard DB.isPostgres(db), let sql = db as? any SQLDatabase, let role = ProcessInfo.processInfo.environment["DATABASE_APP_ROLE"], !role.isEmpty else { return }
        guard Self.isSafeRoleName(role) else { throw ServerConfigError.invalid("DATABASE_APP_ROLE") }
        // The role name is validated above (identifier characters only), so interpolating it cannot change the statement.
        for statement in [
            "GRANT USAGE ON SCHEMA public TO \(role)",
            "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO \(role)",
            "GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO \(role)",
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT SELECT, INSERT, UPDATE, DELETE ON TABLES TO \(role)",
            "ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO \(role)",
            "REVOKE CREATE ON SCHEMA public FROM \(role)",
            // The audit log is append-only for the application: rows are never updated (the retention purge is the only delete, after the head export).
            "REVOKE UPDATE ON audit_events FROM \(role)",
        ] {
            try await sql.raw(SQLQueryString(statement)).run()
        }
    }

    func revert(on db: any Database) async throws {}
}

/// Startup check for the runtime role: in staging and production the process that serves requests must not be able to change the schema; it
/// refuses to start if it can (the role split is mandatory there, see `requireMigrationURL`).
enum DatabaseRoles {
    /// Platform gate C1: in staging and production `ViadereServer migrate` connects as the schema owner and only as the schema owner. Without
    /// `DATABASE_MIGRATION_URL` it refuses to run instead of silently migrating (and holding DDL) as the runtime login. Serving processes do not need
    /// the secret, and should not have it (run the release from a separate app or machine: Infra/fly/README.md section 1a).
    static func requireMigrationURL(config: ServerConfig, migrating: Bool) throws {
        guard config.isStrict, migrating, config.operations.migrationDatabaseURL == nil else { return }
        throw ServerConfigError.missing("DATABASE_MIGRATION_URL (required to run migrations in staging and production)")
    }

    /// Whether this process must prove that its login cannot change the schema: every serving process in staging and production that uses
    /// PostgreSQL, whether or not it holds the migration URL (the role split is mandatory, not opt-in).
    static func mustVerifyRuntimeRole(config: ServerConfig, migrating: Bool) -> Bool {
        config.isStrict && !migrating && config.databaseURL != nil
    }

    /// Whether the connected role may create objects in the `public` schema or owns tables there (i.e. has DDL).
    static func runtimeCanChangeSchema(_ db: any Database) async throws -> Bool {
        guard DB.isPostgres(db), let sql = db as? any SQLDatabase else { return false }
        struct Row: Decodable { var create: Bool; var owns: Bool }
        let row = try await sql.raw("""
            SELECT has_schema_privilege(current_user, 'public', 'CREATE') AS "create",
                   EXISTS (SELECT 1 FROM pg_tables WHERE schemaname = 'public' AND tableowner = current_user) AS owns
            """).first(decoding: Row.self)
        return (row?.create ?? false) || (row?.owns ?? false)
    }
}

/// The append-only tables (`audit_events`, `decisions`, `consent_grants`) refuse every UPDATE and DELETE at the database. Retention (LEG-PR-006) has
/// to delete rows past their documented minimum, so the DELETE trigger gets one narrow exception: it passes only inside a transaction that opened the
/// retention gate (`RetentionDeleteGate.perform`). PostgreSQL uses a transaction-local setting that vanishes at commit or rollback; SQLite (tests
/// and development) uses a one-row table that the same transaction closes again, so a failure rolls it back. UPDATE stays refused everywhere, and
/// the other append-only tables (consent SMS events, the key-directory log) get no exception at all.
///
/// Honest limit: a process that can run SQL as the runtime role can open the gate too. What protects the audit log from that is the write-once
/// export of signed heads (`AuditHeadExporter`), not this trigger; the trigger stops accidents and ordinary code paths.
struct CreateRetentionDeleteGate: AsyncMigration {
    var name: String { "CreateRetentionDeleteGate.v1" }

    static let gatedTables = ["audit_events", "decisions", "consent_grants"]

    func prepare(on db: any Database) async throws {
        guard let sql = db as? any SQLDatabase else { return }
        if sql.dialect.name == "postgresql" {
            try await sql.raw("""
                CREATE OR REPLACE FUNCTION viadere_append_only() RETURNS trigger AS $$
                BEGIN
                    IF TG_OP = 'DELETE' AND TG_TABLE_NAME IN ('audit_events', 'decisions', 'consent_grants')
                       AND current_setting('viadere.retention', true) = 'on' THEN
                        RETURN OLD;
                    END IF;
                    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
                END;
                $$ LANGUAGE plpgsql
                """).run()
        } else {
            try await sql.raw("CREATE TABLE IF NOT EXISTS retention_gate (open INTEGER NOT NULL)").run()
            try await sql.raw("INSERT INTO retention_gate (open) SELECT 0 WHERE NOT EXISTS (SELECT 1 FROM retention_gate)").run()
            for table in Self.gatedTables {
                try await sql.raw(SQLQueryString("DROP TRIGGER IF EXISTS \(unsafeRaw: table)_no_delete")).run()
                try await sql.raw(SQLQueryString("""
                    CREATE TRIGGER \(unsafeRaw: table)_no_delete BEFORE DELETE ON \(unsafeRaw: table)
                    WHEN (SELECT open FROM retention_gate LIMIT 1) = 0
                    BEGIN SELECT RAISE(ABORT, 'append-only table'); END
                    """)).run()
            }
        }
    }

    func revert(on db: any Database) async throws {}
}

/// PostgreSQL only: `decisions` has its own guard function (`viadere_decisions_guard`, which also allows the `[erased]` payload scrub), and it did not
/// honor the retention gate, so the purge of signed decisions was refused. This replaces it so that a DELETE passes only inside the gate, exactly as for
/// the other gated tables. UPDATE rules are unchanged. (SQLite keeps a separate `decisions_no_delete` trigger that the gate already opens.)
struct CreateDecisionsRetentionGate: AsyncMigration {
    var name: String { "CreateDecisionsRetentionGate.v1" }

    func prepare(on db: any Database) async throws {
        guard let sql = db as? any SQLDatabase, sql.dialect.name == "postgresql" else { return }
        try await sql.raw("""
            CREATE OR REPLACE FUNCTION viadere_decisions_guard() RETURNS trigger AS $$
            BEGIN
                IF TG_OP = 'DELETE' AND current_setting('viadere.retention', true) = 'on' THEN
                    RETURN OLD;
                END IF;
                IF TG_OP = 'UPDATE' AND NEW.signed_payload = '[erased]'
                   AND (to_jsonb(NEW) - 'signed_payload') = (to_jsonb(OLD) - 'signed_payload') THEN
                    RETURN NEW;
                END IF;
                RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
            END;
            $$ LANGUAGE plpgsql
            """).run()
    }

    func revert(on db: any Database) async throws {}
}

enum RetentionDeleteGate {
    /// Runs `body` in a transaction in which the gated tables accept DELETE. Only the retention job calls this.
    static func perform<T: Sendable>(on db: any Database, _ body: @escaping @Sendable (any Database) async throws -> T) async throws -> T {
        try await db.transaction { tx in
            if let sql = tx as? any SQLDatabase {
                if sql.dialect.name == "postgresql" { try await sql.raw("SET LOCAL viadere.retention = 'on'").run() } else { try await sql.raw("UPDATE retention_gate SET open = 1").run() }
            }
            do {
                let result = try await body(tx)
                if let sql = tx as? any SQLDatabase, sql.dialect.name != "postgresql" { try await sql.raw("UPDATE retention_gate SET open = 0").run() }
                return result
            } catch {
                if let sql = tx as? any SQLDatabase, sql.dialect.name != "postgresql" { _ = try? await sql.raw("UPDATE retention_gate SET open = 0").run() }
                throw error
            }
        }
    }
}
