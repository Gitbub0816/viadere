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

extension Error {
    /// A lock or serialization failure that succeeds when simply tried again: SQLite `busy` (tests) and PostgreSQL deadlocks.
    var isTransientDatabaseFailure: Bool {
        let text = String(describing: self).lowercased()
        return text.contains("database is locked") || text.contains("busy") || text.contains("deadlock") || text.contains("could not serialize")
    }
}

/// Database helpers shared by services.
enum DB {
    /// Runs `body`, retrying with a short jittered pause when the database reports a transient lock or serialization failure.
    /// Business rules still decide the outcome on every attempt (each attempt re-reads state), so a retry can never double-apply.
    static func retryingTransient<T>(attempts: Int = 10, _ body: () async throws -> T) async throws -> T {
        var attempt = 0
        while true {
            do { return try await body() } catch {
                attempt += 1
                guard error.isTransientDatabaseFailure, attempt < attempts else { throw error }
                try await Task.sleep(nanoseconds: UInt64.random(in: 5_000_000...40_000_000) * UInt64(attempt))
            }
        }
    }

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

    /// `SELECT id FROM table WHERE id = ? FOR UPDATE` inside a transaction: serializes concurrent transactions that need a consistent view of
    /// the rows around this one (for example the requests of one relationship). PostgreSQL takes the row lock; SQLite has no row locks and
    /// serializes writers anyway, so the dialect renders no clause.
    static func lockForUpdate(_ db: any Database, table: String, id: UUID) async throws {
        guard let sql = db as? any SQLDatabase else { throw APIError.internalError }
        _ = try await sql.select().column("id").from(table).where("id", .equal, id).for(.update).all()
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
