import Foundation
import Vapor

/// Result of consuming a token from a bucket.
public struct RateDecision: Sendable, Equatable {
    public var allowed: Bool
    public var retryAfter: TimeInterval
}

/// Pluggable rate-limit storage. The default is an in-process token bucket; a shared store (Redis,
/// database) can be swapped in for multi-instance deployments without changing callers.
public protocol RateLimitStore: Sendable {
    /// Atomically takes `cost` tokens from the bucket identified by `key`.
    func take(key: String, rule: RateRule, cost: Double, now: Date) async -> RateDecision
}

/// In-process token buckets. **Single instance only**: with several instances each has its own counters, so the effective limit is
/// multiplied by the instance count; a deployment with more than one instance must supply a shared `RateLimitStore` (Redis or
/// the database) through `Overrides.rateLimitStore`.
///
/// Memory is bounded **per namespace** (the part of the key before the first `|`, e.g. `ip`, `sms-phone`): every namespace has its own
/// table, so a flood of fresh keys in one namespace (a signup-email spray, rotating phone numbers) can never exhaust the space of another
/// one — in particular never the global per-IP limiter, which would otherwise turn a cheap flood into a platform-wide outage. When a
/// namespace table is full, buckets that have fully refilled (they carry no state) are swept, at most once per `sweepInterval`, and if it
/// is still full the **least recently used** tenth of that namespace is evicted (amortised: one sort per `cap/10` insertions). A namespace
/// listed in `failClosedNamespaces` refuses new keys instead (`refusedWhileFull`); the default is none, because refusing is exactly the
/// denial of service this design avoids. Evictions and refusals are counted and logged as warnings (at most once a minute per namespace).
public actor InMemoryRateLimitStore: RateLimitStore {
    private struct Bucket {
        var tokens: Double
        var updatedAt: Date
        var capacity: Double
        var refillPerSecond: Double
        var lastUsed: UInt64

        func refilled(at now: Date) -> Double {
            min(capacity, tokens + max(0, now.timeIntervalSince(updatedAt)) * refillPerSecond)
        }
    }

    private var tables: [String: [String: Bucket]] = [:]
    private let maxBucketsPerNamespace: Int
    private let namespaceCaps: [String: Int]
    private let failClosedNamespaces: Set<String>
    private let sweepInterval: TimeInterval
    private var lastSweep: [String: Date] = [:]
    private var lastWarning: [String: Date] = [:]
    private var tick: UInt64 = 0
    private let logger = Logger(label: "viadere.ratelimit")
    /// Requests refused because a fail-closed namespace was full.
    private(set) var refusedWhileFull = 0
    /// Buckets evicted (least recently used) to make room, across all namespaces.
    private(set) var evictions = 0
    private(set) var evictionsByNamespace: [String: Int] = [:]

    /// - Parameters:
    ///   - maxBuckets: the cap of each namespace table (default 50 000); `namespaceCaps` overrides it per namespace.
    public init(maxBuckets: Int = 50_000, namespaceCaps: [String: Int] = ["ip": 200_000, "dashboard-signup-email": 10_000], failClosedNamespaces: Set<String> = [],
                sweepInterval: TimeInterval = 1) {
        self.maxBucketsPerNamespace = max(1, maxBuckets)
        self.namespaceCaps = namespaceCaps
        self.failClosedNamespaces = failClosedNamespaces
        self.sweepInterval = sweepInterval
    }

    static func namespace(of key: String) -> String {
        key.firstIndex(of: "|").map { String(key[..<$0]) } ?? ""
    }

    public func take(key: String, rule: RateRule, cost: Double, now: Date) async -> RateDecision {
        let refillPerSecond = rule.perMinute / 60
        let ns = Self.namespace(of: key)
        var table = tables[ns] ?? [:]
        defer { tables[ns] = table }
        tick &+= 1
        if table[key] == nil {
            let cap = max(1, namespaceCaps[ns] ?? maxBucketsPerNamespace)
            if table.count >= cap {
                sweep(&table, namespace: ns, now: now)
                if table.count >= cap {
                    if failClosedNamespaces.contains(ns) {
                        refusedWhileFull += 1
                        warn(ns, "rate-limit namespace is full; refusing new keys")
                        return RateDecision(allowed: false, retryAfter: 60)
                    }
                    let n = max(1, cap / 10)
                    for victim in table.sorted(by: { $0.value.lastUsed < $1.value.lastUsed }).prefix(n) { table.removeValue(forKey: victim.key) }
                    evictions += n
                    evictionsByNamespace[ns, default: 0] += n
                    warn(ns, "rate-limit namespace is full; evicted \(n) least recently used buckets")
                }
            }
        }
        var bucket = table[key] ?? Bucket(tokens: rule.capacity, updatedAt: now, capacity: rule.capacity, refillPerSecond: refillPerSecond, lastUsed: tick)
        bucket.capacity = rule.capacity
        bucket.refillPerSecond = refillPerSecond
        bucket.tokens = bucket.refilled(at: now)
        bucket.updatedAt = now
        bucket.lastUsed = tick
        let decision: RateDecision
        if bucket.tokens >= cost {
            bucket.tokens -= cost
            decision = RateDecision(allowed: true, retryAfter: 0)
        } else {
            let missing = cost - bucket.tokens
            decision = RateDecision(allowed: false, retryAfter: refillPerSecond > 0 ? missing / refillPerSecond : 3600)
        }
        table[key] = bucket
        return decision
    }

    /// Drops buckets that have fully refilled (they carry no state), at most once per `sweepInterval` per namespace.
    private func sweep(_ table: inout [String: Bucket], namespace: String, now: Date) {
        let last = lastSweep[namespace] ?? .distantPast
        guard now.timeIntervalSince(last) >= sweepInterval || last > now else { return }
        lastSweep[namespace] = now
        table = table.filter { $0.value.refilled(at: now) < $0.value.capacity }
    }

    private func warn(_ namespace: String, _ message: String) {
        let now = Date()
        if let last = lastWarning[namespace], now.timeIntervalSince(last) < 60 { return }
        lastWarning[namespace] = now
        logger.warning("\(message)", metadata: ["namespace": "\(namespace)", "evictions": "\(evictions)", "refusedWhileFull": "\(refusedWhileFull)"])
    }

    /// Number of tracked buckets, all namespaces (tests).
    var count: Int { tables.values.reduce(0) { $0 + $1.count } }
    func count(namespace: String) -> Int { tables[namespace]?.count ?? 0 }
}

/// Convenience facade: named limiters over a store.
public struct RateLimiter: Sendable {
    public let store: any RateLimitStore
    public let clock: any ServerClock

    public init(store: any RateLimitStore, clock: any ServerClock) {
        self.store = store
        self.clock = clock
    }

    /// Consumes one token; throws a 429 `APIError` with `Retry-After` when exhausted.
    public func enforce(_ name: String, key: String, rule: RateRule, cost: Double = 1) async throws {
        let decision = await store.take(key: "\(name)|\(key)", rule: rule, cost: cost, now: clock.now())
        if !decision.allowed { throw APIError.rateLimited(retryAfter: Int(decision.retryAfter.rounded(.up))) }
    }

    /// Non-throwing variant for contexts (SMS) that must drop silently.
    public func allow(_ name: String, key: String, rule: RateRule, cost: Double = 1) async -> Bool {
        await store.take(key: "\(name)|\(key)", rule: rule, cost: cost, now: clock.now()).allowed
    }
}

/// Resolves the client IP. `X-Forwarded-For` is honoured only for the configured number of trusted
/// proxies, so a client cannot spoof its address to evade limits.
public enum ClientIP {
    public static func resolve(_ request: Request, trustedProxies: Int) -> String {
        let peer = request.remoteAddress?.ipAddress ?? "unknown"
        guard trustedProxies > 0, let forwarded = request.headers.first(name: "X-Forwarded-For") else { return normalize(peer) }
        let hops = forwarded.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        guard hops.count >= trustedProxies else { return normalize(peer) }
        // The Nth entry from the right was appended by our outermost trusted proxy.
        return normalize(hops[hops.count - trustedProxies])
    }

    /// The rate-limit identity of an address. An IPv6 customer is routinely handed a whole /64, so keying on the full address lets one
    /// host mint 2^64 "different clients": IPv6 is keyed by its /64 prefix (`2001:db8:1:2::/64`). IPv4-mapped IPv6 addresses are IPv4.
    public static func normalize(_ address: String) -> String {
        let trimmed = address.trimmingCharacters(in: CharacterSet(charactersIn: "[] "))
        guard trimmed.contains(":") else { return trimmed }
        var v6 = in6_addr()
        // Drop a zone id (`fe80::1%en0`).
        guard inet_pton(AF_INET6, String(trimmed.split(separator: "%").first ?? ""), &v6) == 1 else { return trimmed }
        let bytes = withUnsafeBytes(of: &v6) { Array($0) }
        if bytes[0..<10].allSatisfy({ $0 == 0 }), bytes[10] == 0xFF, bytes[11] == 0xFF {
            return "\(bytes[12]).\(bytes[13]).\(bytes[14]).\(bytes[15])"
        }
        let groups = stride(from: 0, to: 8, by: 2).map { String(format: "%x", Int(bytes[$0]) << 8 | Int(bytes[$0 + 1])) }
        return groups.joined(separator: ":") + "::/64"
    }
}

/// Per-IP limiter applied to every request (coarse flood protection). Specific routes add their own limits.
public struct GlobalRateLimitMiddleware: AsyncMiddleware {
    public init() {}

    public func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        let ctx = request.application.ctx
        let ip = ClientIP.resolve(request, trustedProxies: ctx.config.trustedProxyCount)
        let rule = request.url.path.hasPrefix("/v1/providers/") ? ctx.config.rateLimits.providerIP : ctx.config.rateLimits.globalIP
        try await ctx.limiter.enforce("ip", key: ip, rule: rule)
        return try await next.respond(to: request)
    }
}

/// Route-level limiter keyed by client IP (public ceremonies, directory, refresh).
public struct IPRateLimitMiddleware: AsyncMiddleware {
    public let name: String
    public let rule: @Sendable (ServerConfig) -> RateRule

    public init(name: String, rule: @escaping @Sendable (ServerConfig) -> RateRule) {
        self.name = name
        self.rule = rule
    }

    public func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        let ctx = request.application.ctx
        let ip = ClientIP.resolve(request, trustedProxies: ctx.config.trustedProxyCount)
        try await ctx.limiter.enforce(name, key: ip, rule: rule(ctx.config))
        return try await next.respond(to: request)
    }
}
