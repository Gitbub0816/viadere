import Fluent
import Foundation
import SQLKit

extension Error {
    /// True for unique / foreign-key / not-null violations, in both SQLite and PostgreSQL.
    var isConstraintViolation: Bool {
        if let db = self as? any DatabaseError { return db.isConstraintFailure }
        return false
    }
}

/// Database helpers shared by services.
enum DB {
    /// Whether the connected dialect is PostgreSQL.
    static func isPostgres(_ db: any Database) -> Bool {
        (db as? any SQLDatabase)?.dialect.name == "postgresql"
    }

    /// Compare-and-swap: sets `column = newValue` only on the row whose `column` currently equals
    /// `expected` (all values are bound parameters; identifiers are compile-time constants).
    /// Returns `true` iff exactly one row was updated. Used for single-use tokens, status transitions
    /// and revision-checked contexts, so concurrent requests cannot both win.
    static func swap(_ db: any Database, table: String, id: UUID, column: String, expected: some Encodable & Sendable,
                     newValue: some Encodable & Sendable, extra: [(String, any Encodable & Sendable)] = []) async throws -> Bool {
        guard let sql = db as? any SQLDatabase else { throw APIError.internalError }
        var update = sql.update(table).set(column, to: newValue)
        for (name, value) in extra { update = update.set(name, to: value) }
        let rows = try await update
            .where("id", .equal, id)
            .where(SQLIdentifier(column), .equal, expected)
            .returning("id")
            .all()
        return rows.count == 1
    }

    /// Like `swap` but the expected value is SQL NULL (e.g. `consumed_at IS NULL`).
    static func swapFromNull(_ db: any Database, table: String, id: UUID, column: String, newValue: some Encodable & Sendable,
                             extra: [(String, any Encodable & Sendable)] = []) async throws -> Bool {
        guard let sql = db as? any SQLDatabase else { throw APIError.internalError }
        var update = sql.update(table).set(column, to: newValue)
        for (name, value) in extra { update = update.set(name, to: value) }
        let rows = try await update
            .where("id", .equal, id)
            .where(SQLIdentifier(column), .is, SQLLiteral.null)
            .returning("id")
            .all()
        return rows.count == 1
    }
}

/// Thrown inside a transaction to roll it back when an optimistic-concurrency check loses.
struct ConcurrencyConflict: Error {}
