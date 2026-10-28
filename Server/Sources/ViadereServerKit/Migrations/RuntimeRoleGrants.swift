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

/// Startup check for the runtime role: when `DATABASE_MIGRATION_URL` is configured (the deployment intends to split roles) the process that serves
/// requests must not be able to change the schema. Refuses to start in staging and production if it can.
enum DatabaseRoles {
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
