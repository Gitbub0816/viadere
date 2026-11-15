import Fluent
import FluentSQL
import Foundation
import SQLKit

/// Wallet completion (docs/WALLET.md):
/// * `scan_generation`: part of the signed presentation code in the pass's QR; bumping it (business "rotate") invalidates every earlier code.
/// * `used_at`: the single check-in of a ticket or reservation pass (set once, by compare-and-swap).
/// * `issued_by`: `business` when the business API issued the pass, NULL when the customer did.
/// * `ticket_venue`, `ticket_seat`, `ticket_starts_at`: a business's schedule/venue change, overriding the ticket interaction's values.
/// * an index for the business-side listing.
struct CreateWalletScanSchema: AsyncMigration {
    var name: String { "CreateWalletScanSchema.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema("wallet_passes").field("scan_generation", .int, .required, .sql(.default(0))).update()
        try await db.schema("wallet_passes").field("used_at", .datetime).update()
        try await db.schema("wallet_passes").field("issued_by", .string).update()
        try await db.schema("wallet_passes").field("ticket_venue", .string).update()
        try await db.schema("wallet_passes").field("ticket_seat", .string).update()
        try await db.schema("wallet_passes").field("ticket_starts_at", .datetime).update()
        guard let sql = db as? any SQLDatabase else { return }
        // Identifiers are compile-time constants; no user input reaches this statement.
        try await sql.raw(SQLQueryString("CREATE INDEX IF NOT EXISTS idx_wallet_passes_business ON wallet_passes (business_id, created_at)")).run()
    }

    func revert(on db: any Database) async throws {
        if let sql = db as? any SQLDatabase { try await sql.raw("DROP INDEX IF EXISTS idx_wallet_passes_business").run() }
        for field in ["ticket_starts_at", "ticket_seat", "ticket_venue", "issued_by", "used_at", "scan_generation"] {
            try await db.schema("wallet_passes").deleteField(.string(field)).update()
        }
    }
}
