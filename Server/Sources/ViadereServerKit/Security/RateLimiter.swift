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

public actor InMemoryRateLimitStore: RateLimitStore {
    private struct Bucket {
        var tokens: Double
        var updatedAt: Date
    }

    private var buckets: [String: Bucket] = [:]
    private let maxBuckets: Int

    public init(maxBuckets: Int = 200_000) { self.maxBuckets = maxBuckets }

    public func take(key: String, rule: RateRule, cost: Double, now: Date) async -> RateDecision {
        let refillPerSecond = rule.perMinute / 60
        var bucket = buckets[key] ?? Bucket(tokens: rule.capacity, updatedAt: now)
        let elapsed = max(0, now.timeIntervalSince(bucket.updatedAt))
        bucket.tokens = min(rule.capacity, bucket.tokens + elapsed * refillPerSecond)
        bucket.updatedAt = now
        let decision: RateDecision
        if bucket.tokens >= cost {
            bucket.tokens -= cost
            decision = RateDecision(allowed: true, retryAfter: 0)
        } else {
            let missing = cost - bucket.tokens
            decision = RateDecision(allowed: false, retryAfter: refillPerSecond > 0 ? missing / refillPerSecond : 3600)
        }
        if buckets.count >= maxBuckets, buckets[key] == nil { evict(now: now) }
        if buckets.count < maxBuckets || buckets[key] != nil { buckets[key] = bucket }
        return decision
    }

    private func evict(now: Date) {
        // Drop buckets that have fully refilled (they carry no state).
        buckets = buckets.filter { now.timeIntervalSince($0.value.updatedAt) < 3600 }
    }
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
        guard trustedProxies > 0, let forwarded = request.headers.first(name: "X-Forwarded-For") else { return peer }
        let hops = forwarded.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        guard hops.count >= trustedProxies else { return peer }
        // The Nth entry from the right was appended by our outermost trusted proxy.
        return hops[hops.count - trustedProxies]
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
