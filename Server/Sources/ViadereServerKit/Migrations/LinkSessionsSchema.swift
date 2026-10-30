import Fluent
import FluentSQL
import Foundation
import SQLKit

/// WP-C1 (business link sessions) and WP-C2 (approval hardening). **Additive and forward-only**: one new table per feature, nullable or defaulted
/// columns on existing tables, no row changes meaning.
///
/// * `link_sessions`: one expiring (≤ 5 min), single-use session a business opens for a customer it just authenticated. The code and the
///   business's `customer_ref` are stored only as keyed hashes; the device's statement, binding tag, approval statement, Viadere's signed result
///   and the business's confirmation are kept as evidence.
/// * `relationships.link_session_id`, `relationships.evidence_digest` (the statement digest the business confirmed), and the organization model
///   of spec v4 D2 on the connection: `scopes` (capabilities granted by link sessions), `connection_method`, `linked_at`, `pref_muted`,
///   `pref_favorite` (marketing stays the consent purpose). A relationship created by a link session has status `pending_link` until the business
///   confirms; it is never active, listed or addressable before that.
/// * `approve_requests.attempts` (invalid submissions; the request locks after `maxInvalidSubmissions`), `approve_requests.device_policy`,
///   `approve_keys.device_policy` (the policy in force, recorded per decision and per key), `approve_business_settings`.
struct CreateLinkSessionsSchema: AsyncMigration {
    var name: String { "LinkSessions.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema("link_sessions")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("api_key_id", .uuid, .required)
            .field("livemode", .bool, .required)
            .field("code_hash", .string, .required)
            .field("customer_ref_hash", .string, .required)
            .field("capabilities", .string, .required)
            .field("display_hint", .string)
            .field("root_kid", .string, .required)
            .field("status", .string, .required)
            .field("created_at", .datetime, .required)
            .field("expires_at", .datetime, .required)
            .field("claimed_consumer_id", .uuid)
            .field("claimed_device_id", .uuid)
            .field("relationship_id", .uuid)
            .field("relationship_created", .bool, .required, .sql(.default(false)))
            .field("relationship_prior_status", .string)
            .field("subject_ref", .string)
            .field("statement_payload", .string)
            .field("statement_signature", .string)
            .field("statement_digest", .string)
            .field("connection_kid", .string)
            .field("binding_tag", .string)
            .field("approval_statement_payload", .string)
            .field("approval_statement_signature", .string)
            .field("approval_kid", .string)
            .field("result", .string)
            .field("completed_at", .datetime)
            .field("confirmation", .string)
            .field("verification", .string)
            .field("confirmed_at", .datetime)
            .field("cancelled_at", .datetime)
            .field("ended_reason", .string)
            .unique(on: "code_hash")
            .create()

        // One column per statement: SQLite cannot add several columns in a single ALTER TABLE.
        try await db.schema("relationships").field("link_session_id", .uuid).update()
        try await db.schema("relationships").field("evidence_digest", .string).update()
        try await db.schema("relationships").field("scopes", .string).update()
        try await db.schema("relationships").field("connection_method", .string).update()
        try await db.schema("relationships").field("linked_at", .datetime).update()
        try await db.schema("relationships").field("pref_muted", .bool, .required, .sql(.default(false))).update()
        try await db.schema("relationships").field("pref_favorite", .bool, .required, .sql(.default(false))).update()

        try await db.schema("approve_requests").field("attempts", .int, .required, .sql(.default(0))).update()
        try await db.schema("approve_requests").field("device_policy", .string).update()
        try await db.schema("approve_keys").field("device_policy", .string).update()
        try await db.schema("approve_business_settings")
            .field("business_id", .uuid, .identifier(auto: false), .references("businesses", "id"))
            .field("device_policy", .string, .required)
            .field("updated_at", .datetime, .required)
            .field("updated_by", .string, .required)
            .create()

        guard let sql = db as? any SQLDatabase else { return }
        for (name, table, columns) in [("idx_link_sessions_business", "link_sessions", "business_id, status"),
                                       ("idx_link_sessions_due", "link_sessions", "status, expires_at"),
                                       ("idx_link_sessions_customer", "link_sessions", "business_id, customer_ref_hash, created_at"),
                                       ("idx_link_sessions_consumer", "link_sessions", "claimed_consumer_id")] {
            // Identifiers are compile-time constants; no user input reaches this statement.
            try await sql.raw(SQLQueryString("CREATE INDEX IF NOT EXISTS \(unsafeRaw: name) ON \(unsafeRaw: table) (\(unsafeRaw: columns))")).run()
        }
    }

    func revert(on db: any Database) async throws {
        guard let sql = db as? any SQLDatabase else { return }
        for table in ["approve_business_settings", "link_sessions"] { try await sql.raw(SQLQueryString("DROP TABLE IF EXISTS \(unsafeRaw: table)")).run() }
        for field in ["link_session_id", "evidence_digest", "scopes", "connection_method", "linked_at", "pref_muted", "pref_favorite"] {
            try await db.schema("relationships").deleteField(.string(field)).update()
        }
        for field in ["attempts", "device_policy"] { try await db.schema("approve_requests").deleteField(.string(field)).update() }
        try await db.schema("approve_keys").deleteField("device_policy").update()
    }
}
