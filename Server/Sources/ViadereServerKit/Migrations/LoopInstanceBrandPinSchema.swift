import Fluent
import Foundation

/// `LoopInstanceBrandPin.v1` (additive): `loop_instances.brand_kit_pin`, the Brand Kit key pinned when the instance started (the kit the
/// reviewed Loop names, if it was live in the business's signed manifest at that moment), or null for neutral styling. Written once at
/// creation and never updated, like `interactions.brand_kit_pin`: a kit withdrawn, taken down or rescheduled later does not change it.
struct CreateLoopInstanceBrandPin: AsyncMigration {
    var name: String { "LoopInstanceBrandPin.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema("loop_instances").field("brand_kit_pin", .string).update()
    }

    func revert(on db: any Database) async throws {
        try await db.schema("loop_instances").deleteField("brand_kit_pin").update()
    }
}
