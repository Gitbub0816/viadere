import Fluent
import Foundation
import SQLKit

/// A customer's installed Loop (SECURITY.md §2.98 "Installed Loops"). One row per (customer, Loop); uninstalling sets `uninstalled_at` and a
/// re-install clears it. `mode` is the customer's choice at the last install (`install_only`, `install_and_connect`); `source` where it
/// started (`directory`, `business_page`, `link`). No customer data beyond the account id: no business-facing surface reads this table.
final class LoopInstallRecord: Model, @unchecked Sendable {
    static let schema = "loop_installs"
    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "definition_id") var definitionId: UUID
    @Field(key: "mode") var mode: String
    @Field(key: "source") var source: String
    @Field(key: "installed_at") var installedAt: Date
    @Field(key: "updated_at") var updatedAt: Date
    @OptionalField(key: "uninstalled_at") var uninstalledAt: Date?
    /// The customer allows this Loop's own alerts in Alerts (`LoopInstallAlerts.v1`, owner decision F-4). Off unless chosen.
    @Field(key: "alerts_enabled") var alertsEnabled: Bool
    init() { alertsEnabled = false }

    var isActive: Bool { uninstalledAt == nil }
}

/// Directory metadata a Viadere operator (`loop_reviewer`) sets for a Loop: whether it is listed in the browsable directory, its category
/// and whether it is featured. Name and description are never stored here: they are read from the reviewed, published definition.
final class LoopDirectoryListingRecord: Model, @unchecked Sendable {
    static let schema = "loop_directory_listings"
    @ID(key: .id) var id: UUID?
    @Field(key: "definition_id") var definitionId: UUID
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "category") var category: String
    @Field(key: "listed") var listed: Bool
    @Field(key: "featured") var featured: Bool
    @Field(key: "set_by") var setBy: UUID
    @Field(key: "set_at") var setAt: Date
    init() {}
}

/// `LoopInstalls.v1` (additive, forward-only): `loop_installs`, `loop_directory_listings` and the nullable `loop_instances.install_id`.
struct CreateLoopInstallsSchema: AsyncMigration {
    var name: String { "LoopInstalls.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema(LoopInstallRecord.schema).id()
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("definition_id", .uuid, .required, .references(LoopDefinitionRecord.schema, "id"))
            .field("mode", .string, .required)
            .field("source", .string, .required)
            .field("installed_at", .datetime, .required)
            .field("updated_at", .datetime, .required)
            .field("uninstalled_at", .datetime)
            .unique(on: "consumer_id", "definition_id").create()
        try await db.schema(LoopDirectoryListingRecord.schema).id()
            .field("definition_id", .uuid, .required, .references(LoopDefinitionRecord.schema, "id"))
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("category", .string, .required)
            .field("listed", .bool, .required)
            .field("featured", .bool, .required)
            .field("set_by", .uuid, .required)
            .field("set_at", .datetime, .required)
            .unique(on: "definition_id").create()
        try await db.schema(LoopInstanceRecord.schema).field("install_id", .uuid).update()
        guard let sql = db as? any SQLDatabase else { return }
        // Compile-time constant statements.
        try await sql.raw("CREATE INDEX IF NOT EXISTS idx_loop_installs_consumer ON loop_installs (consumer_id, uninstalled_at)").run()
        try await sql.raw("CREATE INDEX IF NOT EXISTS idx_loop_installs_business ON loop_installs (business_id, uninstalled_at)").run()
        try await sql.raw("CREATE INDEX IF NOT EXISTS idx_loop_listings_listed ON loop_directory_listings (listed, category)").run()
    }

    func revert(on db: any Database) async throws {
        try await db.schema(LoopInstanceRecord.schema).deleteField("install_id").update()
        try await db.schema(LoopDirectoryListingRecord.schema).delete()
        try await db.schema(LoopInstallRecord.schema).delete()
    }
}
