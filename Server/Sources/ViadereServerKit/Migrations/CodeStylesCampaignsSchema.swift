import Fluent
import FluentSQL
import Foundation
import SQLKit

/// `CodeStylesCampaigns.v1` (**additive and forward-only**; docs/SECURITY.md §2.105, §2.106).
///
/// * `business_code_styles`: at most one row per business, the validated `BusinessCodeStyle` (canonical JSON) for its connect and install
///   codes. No row means the default (the Viadere code).
/// * `campaigns`: campaign links a business created. `public_id` is the identifier inside the signed connect context (`cmp`), unique per
///   business; `archived_at` ends crediting without changing the link.
/// * `relationships.campaign_id`: the campaign credited for the connection, set only from a context the server verified.
struct CreateCodeStylesCampaignsSchema: AsyncMigration {
    var name: String { "CodeStylesCampaigns.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema("business_code_styles")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("style_json", .string, .required)
            .field("updated_by", .string)
            .field("updated_at", .datetime, .required)
            .unique(on: "business_id")
            .create()
        try await db.schema("campaigns")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("public_id", .string, .required)
            .field("name", .string, .required)
            .field("action", .string)
            .field("expires_at", .datetime)
            .field("created_by", .string)
            .field("created_at", .datetime, .required)
            .field("archived_at", .datetime)
            .field("archived_by", .string)
            .unique(on: "business_id", "public_id")
            .create()
        try await db.schema("relationships").field("campaign_id", .uuid).update()

        guard let sql = db as? any SQLDatabase else { return }
        // Identifiers are compile-time constants; no user input reaches this statement.
        try await sql.raw("CREATE INDEX IF NOT EXISTS idx_relationships_campaign ON relationships (business_id, campaign_id)").run()
    }

    func revert(on db: any Database) async throws {
        try await db.schema("relationships").deleteField("campaign_id").update()
        for table in ["campaigns", "business_code_styles"] { try await db.schema(table).delete() }
    }
}
