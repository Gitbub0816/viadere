import Fluent
import FluentSQL
import Foundation
import SQLKit

/// Phase 2 (WP-2.2..2.4, WP-2.8). **Additive and forward-only**: four new per-business tables and one nullable column on `interactions`.
///
/// * `brand_assets`: re-encoded images by SHA-256 and slot, with their review state.
/// * `brand_kits`: named kits with an editable draft and the last approved snapshot (what manifests carry).
/// * `brand_kit_schedules`: one validated schedule per business.
/// * `brand_manifests`: every signed manifest version (or a withdrawal), unique per (business, version).
/// * `interactions.brand_kit_pin`: the kit chosen when the interaction was created (never changes mid-flow).
struct CreateBrandKitsSchema: AsyncMigration {
    var name: String { "BrandKits.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema("brand_assets")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("sha256", .string, .required)
            .field("slot", .string, .required)
            .field("width", .int, .required)
            .field("height", .int, .required)
            .field("bytes", .int, .required)
            .field("state", .string, .required)
            .field("review_note", .string)
            .field("created_by", .string)
            .field("created_at", .datetime, .required)
            .field("reviewed_by", .string)
            .field("reviewed_at", .datetime)
            .unique(on: "business_id", "sha256", "slot")
            .create()
        try await db.schema("brand_kits")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("kit_key", .string, .required)
            .field("name", .string, .required)
            .field("version", .int, .required)
            .field("status", .string, .required)
            .field("tokens_json", .string, .required)
            .field("frame_id", .string)
            .field("assets_json", .string, .required)
            .field("approved_json", .string)
            .field("approved_version", .int)
            .field("review_note", .string)
            .field("created_by", .string)
            .field("created_at", .datetime, .required)
            .field("updated_at", .datetime, .required)
            .field("reviewed_by", .string)
            .field("reviewed_at", .datetime)
            .unique(on: "business_id", "kit_key")
            .create()
        try await db.schema("brand_kit_schedules")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("schedule_json", .string, .required)
            .field("updated_by", .string)
            .field("updated_at", .datetime, .required)
            .unique(on: "business_id")
            .create()
        try await db.schema("brand_manifests")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("version", .int, .required)
            .field("status", .string, .required)
            .field("manifest_json", .string)
            .field("jws", .string)
            .field("manifest_hash", .string)
            .field("kid", .string)
            .field("issued_at", .datetime)
            .field("not_after", .datetime)
            .field("created_at", .datetime, .required)
            .unique(on: "business_id", "version")
            .create()
        try await db.schema("interactions").field("brand_kit_pin", .string).update()

        guard let sql = db as? any SQLDatabase else { return }
        for (name, table, columns) in [("idx_brand_assets_sha256", "brand_assets", "sha256, state"),
                                       ("idx_brand_assets_state", "brand_assets", "state, created_at"),
                                       ("idx_brand_kits_status", "brand_kits", "status, updated_at")] {
            // Identifiers are compile-time constants; no user input reaches this statement.
            try await sql.raw(SQLQueryString("CREATE INDEX IF NOT EXISTS \(unsafeRaw: name) ON \(unsafeRaw: table) (\(unsafeRaw: columns))")).run()
        }
    }

    func revert(on db: any Database) async throws {
        try await db.schema("interactions").deleteField("brand_kit_pin").update()
        for table in ["brand_manifests", "brand_kit_schedules", "brand_kits", "brand_assets"] { try await db.schema(table).delete() }
    }
}
