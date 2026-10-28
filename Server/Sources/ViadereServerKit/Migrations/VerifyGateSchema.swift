import Fluent
import Foundation

/// Phase 3 (Verify) gate: `verification_attempts.purge_next_at`, the time the next provider-purge try is due (exponential backoff, F3).
struct CreateVerifyGateSchema: AsyncMigration {
    var name: String { "CreateVerifyGateSchema.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema("verification_attempts").field("purge_next_at", .datetime).update()
    }

    func revert(on db: any Database) async throws {
        try await db.schema("verification_attempts").deleteField("purge_next_at").update()
    }
}
