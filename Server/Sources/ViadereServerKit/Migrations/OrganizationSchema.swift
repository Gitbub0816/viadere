import Fluent
import FluentSQL
import Foundation
import SQLKit

/// Phase 1 (WP-1.1, WP-1.5). **Additive and forward-only**: three new per-account tables and read-path indexes; no existing row changes meaning.
///
/// * `business_preferences`: the customer's per-business settings (spec v4 C7, D2 `BusinessPreference`): favorite, mute level and end, block.
///   Keyed by (consumer, business) rather than by relationship so a block outlives the connection it ended. `relationships.pref_muted` and
///   `pref_favorite` (WP-C1) are kept in step as a mirror for `CustomerBusinessConnection`.
/// * `conversation_state`: per-account archive and mute of a conversation (spec C4.3). Never shown to the business.
/// * `alert_seen`: per-viewer "seen" marks of alerts (`{source}:{id}`); per viewer because household delegates see the grantor's items.
/// * Indexes for the Alerts read model: every source is read by `(consumer_id, created_at)`.
struct CreateOrganizationSchema: AsyncMigration {
    var name: String { "Organization.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema("business_preferences")
            .id()
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("favorite", .bool, .required, .sql(.default(false)))
            .field("mute_level", .string, .required)
            .field("mute_until", .datetime)
            .field("blocked_at", .datetime)
            .field("updated_at", .datetime, .required)
            .unique(on: "consumer_id", "business_id")
            .create()
        try await db.schema("conversation_state")
            .id()
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("session_id", .uuid, .required, .references("conversation_sessions", "id"))
            .field("archived_at", .datetime)
            .field("muted", .bool, .required, .sql(.default(false)))
            .field("updated_at", .datetime, .required)
            .unique(on: "consumer_id", "session_id")
            .create()
        try await db.schema("alert_seen")
            .id()
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("alert_id", .string, .required)
            .field("seen_at", .datetime, .required)
            .unique(on: "consumer_id", "alert_id")
            .create()

        guard let sql = db as? any SQLDatabase else { return }
        for (name, table, columns) in [("idx_interactions_consumer_created", "interactions", "consumer_id, created_at, id"),
                                       ("idx_approve_requests_consumer_created", "approve_requests", "consumer_id, created_at, id"),
                                       ("idx_verification_requests_consumer_created", "verification_requests", "consumer_id, created_at, id"),
                                       ("idx_security_notices_consumer_created", "security_notices", "consumer_id, created_at, id"),
                                       ("idx_alert_seen_seen_at", "alert_seen", "seen_at")] {
            // Identifiers are compile-time constants; no user input reaches this statement.
            try await sql.raw(SQLQueryString("CREATE INDEX IF NOT EXISTS \(unsafeRaw: name) ON \(unsafeRaw: table) (\(unsafeRaw: columns))")).run()
        }
    }

    func revert(on db: any Database) async throws {
        guard let sql = db as? any SQLDatabase else { return }
        for index in ["idx_interactions_consumer_created", "idx_approve_requests_consumer_created", "idx_verification_requests_consumer_created",
                      "idx_security_notices_consumer_created"] {
            try await sql.raw(SQLQueryString("DROP INDEX IF EXISTS \(unsafeRaw: index)")).run()
        }
        for table in ["alert_seen", "conversation_state", "business_preferences"] { try await sql.raw(SQLQueryString("DROP TABLE IF EXISTS \(unsafeRaw: table)")).run() }
    }
}

/// WP-1.6: a business's module layout for its neutral Viadere home (spec B1, B6, C6.2). Every version is a row; the newest `published` row is
/// served. `layout_json` is validated by `SurfaceLayout.validate` on write and again by every client on read.
struct CreateSurfacesSchema: AsyncMigration {
    var name: String { "Surfaces.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema("business_surfaces")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("version", .int, .required)
            .field("status", .string, .required)
            .field("layout_json", .string, .required)
            .field("published_at", .datetime)
            .field("published_by", .string)
            .field("created_at", .datetime, .required)
            .unique(on: "business_id", "version")
            .create()
    }

    func revert(on db: any Database) async throws {
        try await db.schema("business_surfaces").delete()
    }
}
