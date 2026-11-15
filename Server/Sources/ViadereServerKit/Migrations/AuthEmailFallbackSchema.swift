import Fluent
import Foundation

/// The tenant policy `allow_email_fallback` (ADR-0020 section 7): a nullable column, so every existing tenant reads as off.
struct CreateAuthEmailFallbackSchema: AsyncMigration {
    var name: String { "AuthEmailFallback.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema(BusinessSecuritySettingsRecord.schema).field("allow_email_fallback", .bool).update()
    }

    func revert(on db: any Database) async throws {
        try await db.schema(BusinessSecuritySettingsRecord.schema).deleteField("allow_email_fallback").update()
    }
}
