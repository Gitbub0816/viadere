import Foundation

/// Records single-use nonces. The server provides a database-backed implementation
/// (unique index on `(scope, nonce)` plus an expiry sweep).
public protocol ReplayGuard: Sendable {
    /// Atomically records `nonce` in `scope` until `expiresAt`. Returns `true` if it was fresh,
    /// `false` if it was already recorded and not yet expired.
    func registerIfFresh(nonce: String, scope: String, expiresAt: Date, now: Date) async throws -> Bool
}

/// In-memory `ReplayGuard` for tests and single-process tools.
public actor InMemoryReplayGuard: ReplayGuard {
    private struct Key: Hashable {
        let scope: String
        let nonce: String
    }

    private var entries: [Key: Date] = [:]
    private let maxEntries: Int

    /// - Parameter maxEntries: Hard cap; when reached, expired entries are purged first and,
    ///   if still full, registration fails closed (returns `false`).
    public init(maxEntries: Int = 100_000) { self.maxEntries = maxEntries }

    public func registerIfFresh(nonce: String, scope: String, expiresAt: Date, now: Date) async throws -> Bool {
        let key = Key(scope: scope, nonce: nonce)
        if let existing = entries[key], existing > now { return false }
        if entries.count >= maxEntries { purge(now: now) }
        guard entries.count < maxEntries else { return false }
        entries[key] = expiresAt
        return true
    }

    /// Removes expired entries.
    public func purge(now: Date) {
        entries = entries.filter { $0.value > now }
    }

    /// Number of tracked entries (tests).
    public var count: Int { entries.count }
}
