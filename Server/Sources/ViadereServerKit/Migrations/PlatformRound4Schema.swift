import Fluent
import FluentSQL
import Foundation
import SQLKit

/// Platform round 4: the shared rate-limit store and dashboard email verification.
struct CreatePlatformRound4Schema: AsyncMigration {
    var name: String { "CreatePlatformRound4Schema.v1" }

    func prepare(on db: any Database) async throws {
        // MARK: Shared rate limiter (one row per bucket; timestamps are epoch seconds so the upsert needs no engine-specific date math)
        try await db.schema("rate_limit_buckets")
            .field("key", .string, .identifier(auto: false))
            .field("namespace", .string, .required)
            .field("tokens", .double, .required)
            .field("updated_at", .double, .required)
            .field("expires_at", .double, .required)
            .field("last_allowed", .int, .required)
            .create()

        // MARK: Dashboard email verification (sign-up and invitation codes)
        try await db.schema("dashboard_email_codes")
            .id()
            .field("kind", .string, .required)
            .field("subject_id", .uuid, .required)
            .field("email_hash", .string, .required)
            .field("code_hash", .string, .required)
            .field("attempts", .int, .required)
            .field("expires_at", .datetime, .required)
            .field("created_at", .datetime, .required)
            .field("consumed_at", .datetime)
            .field("payload", .string)
            .create()

        guard let sql = db as? any SQLDatabase else { return }
        let indexes: [(String, String, String)] = [
            ("idx_rate_limit_expires", "rate_limit_buckets", "expires_at"),
            ("idx_email_codes_email", "dashboard_email_codes", "email_hash, kind"),
            ("idx_email_codes_subject", "dashboard_email_codes", "subject_id"),
            ("idx_dash_users_unverified", "dashboard_users", "status, created_at"),
        ]
        for (name, table, columns) in indexes {
            // Identifiers are compile-time constants above; no user input reaches this statement.
            try await sql.raw(SQLQueryString("CREATE INDEX IF NOT EXISTS \(unsafeRaw: name) ON \(unsafeRaw: table) (\(unsafeRaw: columns))")).run()
        }
    }

    func revert(on db: any Database) async throws {
        // IF EXISTS: reverting must succeed even if a table was already removed by hand.
        guard let sql = db as? any SQLDatabase else { return }
        try await sql.raw("DROP TABLE IF EXISTS dashboard_email_codes").run()
        try await sql.raw("DROP TABLE IF EXISTS rate_limit_buckets").run()
    }
}
