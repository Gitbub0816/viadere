import Fluent
import SQLKit

/// `AuthLinkService.v1` (additive, forward-only): the link-service columns of `auth_deliveries` (ADR-0021 §5). Each challenge belongs to one delivery.
struct CreateAuthLinkServiceSchema: AsyncMigration {
    var name: String { "AuthLinkService.v1" }

    func prepare(on db: any Database) async throws {
        // One column per statement: SQLite adds a single column per ALTER TABLE.
        for column in ["link_challenge_id", "link_statement", "link_client_id"] {
            try await db.schema(AuthDeliveryRecord.schema).field(FieldKey(stringLiteral: column), .string).update()
        }
        guard let sql = db as? any SQLDatabase else { return }
        try await sql.raw("CREATE UNIQUE INDEX IF NOT EXISTS idx_auth_deliveries_link_challenge ON auth_deliveries (link_challenge_id)").run()
    }

    func revert(on db: any Database) async throws {
        for column in ["link_challenge_id", "link_statement", "link_client_id"] {
            try await db.schema(AuthDeliveryRecord.schema).deleteField(FieldKey(stringLiteral: column)).update()
        }
    }
}

/// `AuthLinkService.v2` (additive, forward-only): cross-device link-service deliveries (ADR-0021 §6).
struct CreateAuthLinkServiceCrossDevice: AsyncMigration {
    var name: String { "AuthLinkService.v2" }

    func prepare(on db: any Database) async throws {
        try await db.schema(AuthDeliveryRecord.schema).field("link_cross_device", .bool).update()
    }

    func revert(on db: any Database) async throws {
        try await db.schema(AuthDeliveryRecord.schema).deleteField("link_cross_device").update()
    }
}
