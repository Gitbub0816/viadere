import Fluent
import Foundation
import ViadereCore

/// `ReplayGuard` backed by the database. Atomicity comes from the unique index on `(scope, nonce)`:
/// of two concurrent registrations of the same nonce, exactly one insert succeeds.
struct DatabaseReplayGuard: ReplayGuard {
    let db: any Database

    func registerIfFresh(nonce: String, scope: String, expiresAt: Date, now: Date) async throws -> Bool {
        // Remove an expired entry for the same key first so a nonce becomes usable again after its window.
        try await ReplayNonceRecord.query(on: db)
            .filter(\.$scope == scope).filter(\.$nonce == nonce).filter(\.$expiresAt <= now).delete()
        do {
            try await ReplayNonceRecord(scope: scope, nonce: nonce, expiresAt: expiresAt).create(on: db)
            return true
        } catch {
            if error.isConstraintViolation { return false }
            throw error
        }
    }

    /// Deletes expired entries (called by the maintenance job).
    static func purge(on db: any Database, now: Date) async throws {
        try await ReplayNonceRecord.query(on: db).filter(\.$expiresAt <= now).delete()
    }
}
