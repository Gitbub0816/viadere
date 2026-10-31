import Fluent
import Foundation
import SQLKit
import Vapor

/// Rate-limit counters in the shared database, so a limit is **global across instances** (the production default,
/// `RATE_LIMIT_STORE=database`).
///
/// One token-bucket check is **one statement**, atomic on both engines (PostgreSQL row lock, SQLite single writer), with no read-modify-write
/// race between instances:
///
///     INSERT INTO rate_limit_buckets (key, namespace, tokens, updated_at, expires_at, last_allowed) VALUES (…)
///     ON CONFLICT (key) DO UPDATE SET tokens = <refill, then take>, last_allowed = <enough tokens?>, updated_at = …, expires_at = …
///     RETURNING tokens, last_allowed
///
/// `last_allowed` is computed from the *old* row inside the same statement, so the caller learns the decision without a second query. Time is
/// the caller's clock in epoch seconds; a skew of a second or two between instances is irrelevant at these rates. The portable `CASE`
/// expressions stand in for `LEAST`/`GREATEST` (PostgreSQL) and `min`/`max` (SQLite). Per-namespace semantics (the key's prefix before `|`),
/// IPv6 /64 keys (`ClientIP.normalize`) and rules are the same as the in-memory store: the rule travels with every call.
///
/// **When the database is unavailable** (error or timeout) the store never throws into a request:
/// * security-critical namespaces (one-time codes, link redemption, phone linking, enrollment, household invitations, dashboard
///   authentication, redemption codes, wallet authentication) **fail closed**: the request is refused (`retryAfter` 30 s);
/// * everything else, including the global per-IP limiter, **degrades to a local in-memory limiter** on this instance, so the platform keeps
///   serving with the per-instance limit instead of failing open.
/// After a failure the database is not tried again for `breakerSeconds`, so an outage does not add its timeout to every request.
public struct DatabaseRateLimitStore: RateLimitStore {
    /// Namespaces (or namespace prefixes) refused while the shared store is down.
    public static let defaultFailClosed: [String] = [
        "phonelink", "link-", "phone-confirm", "household-invite", "enroll", "device-confirm", "dashboard-", "auth-", "otp", "recovery",
        "redemption-consume", "reward-redeem", "wallet-auth-fail", "wallet-scan", "wallet-update",
    ]

    let database: @Sendable () -> (any Database)?
    let fallback: InMemoryRateLimitStore
    let failClosedPrefixes: [String]
    let breaker = Breaker()
    let breakerSeconds: TimeInterval
    private let logger = Logger(label: "viadere.ratelimit")

    /// - Parameter database: resolves the application's database at call time (the store is created before the database is configured).
    public init(database: @escaping @Sendable () -> (any Database)?, failClosedPrefixes: [String] = DatabaseRateLimitStore.defaultFailClosed,
                fallback: InMemoryRateLimitStore = InMemoryRateLimitStore(), breakerSeconds: TimeInterval = 5) {
        self.database = database
        self.failClosedPrefixes = failClosedPrefixes
        self.fallback = fallback
        self.breakerSeconds = breakerSeconds
    }

    /// Remembers (in wall-clock time) when the database last failed.
    final class Breaker: @unchecked Sendable {
        private let lock = NSLock()
        private var openUntil = Date.distantPast
        func isOpen() -> Bool { lock.withLock { Date() < openUntil } }
        func trip(for seconds: TimeInterval) { lock.withLock { openUntil = Date().addingTimeInterval(seconds) } }
        func reset() { lock.withLock { openUntil = .distantPast } }
    }

    func isFailClosed(_ namespace: String) -> Bool { failClosedPrefixes.contains { namespace.hasPrefix($0) } }

    public func take(key: String, rule: RateRule, cost: Double, now: Date) async -> RateDecision {
        let namespace = InMemoryRateLimitStore.namespace(of: key)
        guard !breaker.isOpen(), let sql = database() as? any SQLDatabase else { return await degraded(key: key, namespace: namespace, rule: rule, cost: cost, now: now) }
        do {
            let decision = try await Self.take(on: sql, key: key, namespace: namespace, rule: rule, cost: cost, now: now)
            return decision
        } catch {
            breaker.trip(for: breakerSeconds)
            logger.warning("shared rate-limit store unavailable", metadata: ["namespace": "\(namespace)", "failClosed": "\(isFailClosed(namespace))",
                                                                              "error": "\(type(of: error))"])
            return await degraded(key: key, namespace: namespace, rule: rule, cost: cost, now: now)
        }
    }

    private func degraded(key: String, namespace: String, rule: RateRule, cost: Double, now: Date) async -> RateDecision {
        if isFailClosed(namespace) { return RateDecision(allowed: false, retryAfter: 30) }
        return await fallback.take(key: key, rule: rule, cost: cost, now: now)
    }

    /// The single atomic statement.
    static func take(on sql: any SQLDatabase, key: String, namespace: String, rule: RateRule, cost: Double, now: Date) async throws -> RateDecision {
        let capacity = max(rule.capacity, 0)
        let perSecond = max(rule.perMinute, 0) / 60
        let t = now.timeIntervalSince1970
        // Time until an empty bucket is full again (the row carries no state after that), plus slack.
        let horizon = perSecond > 0 ? min(capacity / perSecond, 7 * 86_400) + 60 : 86_400
        let expires = t + horizon
        // First use of the key: a full bucket minus this request.
        let fresh = capacity >= cost
        let freshTokens = fresh ? min(capacity, capacity - cost) : capacity

        func elapsed() -> SQLQueryString { "(CASE WHEN \(bind: t) > rate_limit_buckets.updated_at THEN \(bind: t) - rate_limit_buckets.updated_at ELSE 0 END)" }
        func refilled() -> SQLQueryString {
            "(CASE WHEN rate_limit_buckets.tokens + \(elapsed()) * \(bind: perSecond) > \(bind: capacity) THEN \(bind: capacity) ELSE rate_limit_buckets.tokens + \(elapsed()) * \(bind: perSecond) END)"
        }
        let newTokens: SQLQueryString = """
            CASE WHEN \(refilled()) >= \(bind: cost) THEN (CASE WHEN \(refilled()) - \(bind: cost) > \(bind: capacity) THEN \(bind: capacity) ELSE \(refilled()) - \(bind: cost) END) ELSE \(refilled()) END
            """
        let allowed: SQLQueryString = "CASE WHEN \(refilled()) >= \(bind: cost) THEN 1 ELSE 0 END"
        let query: SQLQueryString = """
            INSERT INTO rate_limit_buckets (key, namespace, tokens, updated_at, expires_at, last_allowed) \
            VALUES (\(bind: key), \(bind: namespace), \(bind: freshTokens), \(bind: t), \(bind: expires), \(bind: fresh ? 1 : 0)) \
            ON CONFLICT (key) DO UPDATE SET tokens = \(newTokens), last_allowed = \(allowed), updated_at = \(bind: t), expires_at = \(bind: expires) \
            RETURNING tokens, last_allowed
            """
        guard let row = try await sql.raw(query).first() else { throw RateLimitStoreError.noRow }
        let tokens = try row.decode(column: "tokens", as: Double.self)
        let ok = try row.decode(column: "last_allowed", as: Int.self) == 1
        if ok { return RateDecision(allowed: true, retryAfter: 0) }
        return RateDecision(allowed: false, retryAfter: perSecond > 0 ? max(0, cost - tokens) / perSecond : 3600)
    }

    /// Deletes buckets whose state has fully refilled (called by the maintenance job).
    public func purgeExpired(now: Date) async {
        guard !breaker.isOpen(), let sql = database() as? any SQLDatabase else { return }
        do {
            try await sql.raw("DELETE FROM rate_limit_buckets WHERE expires_at < \(bind: now.timeIntervalSince1970)").run()
        } catch {
            logger.warning("rate-limit purge failed", metadata: ["error": "\(type(of: error))"])
        }
    }
}

enum RateLimitStoreError: Error { case noRow }

extension DatabaseRateLimitStore {
    /// The shared-database store for `app` (resolved lazily, so it can be created before the database is configured).
    static func forApplication(_ app: Application) -> DatabaseRateLimitStore {
        DatabaseRateLimitStore(database: { [weak app] in app?.db })
    }
}
