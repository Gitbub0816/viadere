import Fluent
import FluentSQL
import Foundation
import SQLKit

/// Phase 2 (Approve) gate fixes:
/// * `approve_enrollments.binding_tag`: the device's HMAC over its statement with the business-held enrollment secret (F1). The relay only
///   stores and forwards it; it cannot verify or forge it.
/// * `approve_freeze_events`: an opaque, per-business reference for each `approve.frozen` webhook, so the event carries no subject (F5).
/// * `kd_root_authorizations`: a dashboard passkey step-up that authorizes one root-key registration or succession for a verified business
///   (condition 4). An API key alone can never register or change a root.
struct CreateApproveGateSchema: AsyncMigration {
    var name: String { "CreateApproveGateSchema.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema("approve_enrollments").field("binding_tag", .string).update()
        try await db.schema("approve_freeze_events")
            .id()
            .field("ref", .string, .required)
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("relationship_id", .uuid, .required)
            .field("created_at", .datetime, .required)
            .unique(on: "ref")
            .create()
        try await db.schema("kd_root_authorizations")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("kind", .string, .required)
            .field("root_kid", .string, .required)
            .field("authorized_by", .string, .required)
            .field("created_at", .datetime, .required)
            .field("expires_at", .datetime, .required)
            .field("consumed_at", .datetime)
            .create()
        guard let sql = db as? any SQLDatabase else { return }
        for (name, table, columns) in [("idx_approve_freeze_events_business", "approve_freeze_events", "business_id, created_at"),
                                       ("idx_kd_root_auth_business", "kd_root_authorizations", "business_id, kind, root_kid")] {
            try await sql.raw(SQLQueryString("CREATE INDEX IF NOT EXISTS \(unsafeRaw: name) ON \(unsafeRaw: table) (\(unsafeRaw: columns))")).run()
        }
    }

    func revert(on db: any Database) async throws {
        guard let sql = db as? any SQLDatabase else { return }
        for table in ["kd_root_authorizations", "approve_freeze_events"] { try await sql.raw(SQLQueryString("DROP TABLE IF EXISTS \(unsafeRaw: table)")).run() }
        try await db.schema("approve_enrollments").deleteField("binding_tag").update()
    }
}
