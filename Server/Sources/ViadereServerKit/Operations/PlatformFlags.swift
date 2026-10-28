import Fluent
import Foundation
import Vapor
import ViadereCore

/// Operator switches stored in `platform_flags` (ops gaps G-1, G-5, G-6, G-12, G-15). One row per (flag, scope); `scope` is `global` or a
/// business id. Each change needs a reason, is audited with the operator as actor and takes effect on this instance at once and on the others
/// within `PlatformFlags.cacheTTL`.
enum PlatformFlag: String, CaseIterable, Sendable {
    /// G-1: read-only mode. `value` is the static status message shown to clients.
    case maintenance = "maintenance"
    /// G-15: stop new consumer accounts.
    case signupConsumer = "signup.consumer"
    /// G-15: stop new business organizations.
    case signupBusiness = "signup.business"
    /// G-15: stop new dashboard invitations (creating and accepting).
    case inviteDashboard = "invite.dashboard"
    /// G-5: pause webhook delivery. Scope `global` or a business id (per endpoint it is `webhook_subscriptions.paused_at`).
    case webhooksPause = "webhooks.pause"
    /// G-6: emergency messaging restriction (`MessagingRestriction` JSON). Scope `global` or a business id.
    case messagingRestrict = "messaging.restrict"
    /// G-12: abuse thresholds (`AbuseOverride` JSON), global only.
    case abuseThresholds = "abuse.thresholds"
    /// Bookkeeping: the time of the last successful audit-head export (`updated_at`).
    case auditExportMark = "audit.export_mark"

    var globalOnly: Bool { self != .webhooksPause && self != .messagingRestrict }
}

/// What the G-6 switch restricts. Security-purpose traffic (sign-in and payment approvals) is never covered: stop those with a capability
/// switch or by suspending the business.
struct MessagingRestriction: Codable, Sendable, Equatable {
    enum Mode: String, Codable, Sendable { case block, clamp }
    var mode: Mode
    /// `sms`, `rcs`, `push`.
    var channels: [String]
    /// `clamp` only: messages per minute across the scope and channel.
    var perMinute: Int?
    /// Limit to these interaction purposes (`marketing`, `rewards`, ...). `nil` = every purpose except `security`.
    var purposes: [String]?

    static let channelNames: Set<String> = ["sms", "rcs", "push"]
    static let maximumClamp = 600
}

/// G-12: bounded runtime overrides of `AbuseThresholds`. A value outside its bounds is rejected when set, so an operator can tighten or relax
/// within a safe range but never switch the abuse checks off.
struct AbuseOverride: Codable, Sendable, Equatable {
    var complaintRate: Double?
    var optOutRate: Double?
    var minimumSample: Int?
    var windowDays: Double?
    var throttleFactor: Double?

    static let complaintRateBounds = 0.005...0.20
    static let optOutRateBounds = 0.02...0.50
    static let minimumSampleBounds = 5...1000
    static let windowDaysBounds = 1.0...30.0
    static let throttleFactorBounds = 0.05...1.0

    var isWithinBounds: Bool {
        (complaintRate.map(Self.complaintRateBounds.contains) ?? true) && (optOutRate.map(Self.optOutRateBounds.contains) ?? true)
            && (minimumSample.map(Self.minimumSampleBounds.contains) ?? true) && (windowDays.map(Self.windowDaysBounds.contains) ?? true)
            && (throttleFactor.map(Self.throttleFactorBounds.contains) ?? true)
    }

    func applied(to base: AbuseThresholds) -> AbuseThresholds {
        var out = base
        if let complaintRate { out.complaintRate = complaintRate }
        if let optOutRate { out.optOutRate = optOutRate }
        if let minimumSample { out.minimumSample = minimumSample }
        if let windowDays { out.window = windowDays * 86_400 }
        if let throttleFactor { out.throttleFactor = throttleFactor }
        return out
    }
}

/// An in-memory copy of `platform_flags`, valid for a few seconds.
actor PlatformFlagCache {
    struct Snapshot: Sendable {
        var entries: [String: Entry]
        var loadedAt: Date
    }

    struct Entry: Sendable {
        var value: String
        var reason: String
        var updatedAt: Date
    }

    private var cached: Snapshot?

    func snapshot(now: Date, ttl: TimeInterval, load: @Sendable () async throws -> [String: Entry]) async throws -> Snapshot {
        if let cached, now.timeIntervalSince(cached.loadedAt) >= 0, now.timeIntervalSince(cached.loadedAt) < ttl { return cached }
        let fresh = Snapshot(entries: try await load(), loadedAt: now)
        cached = fresh
        return fresh
    }

    func invalidate() { cached = nil }
}

struct PlatformFlags {
    let db: any Database
    let ctx: ServerContext

    static let cacheTTL: TimeInterval = 5
    static let globalScope = "global"

    static func key(_ flag: PlatformFlag, _ scope: String) -> String { "\(flag.rawValue)|\(scope)" }

    // MARK: Read

    /// The cached state. A database failure reads as "no switch is set" (fail open): every switch here restricts something that needs the
    /// database anyway, and a missing table must not turn into an outage on its own.
    func snapshot() async -> [String: PlatformFlagCache.Entry] {
        let db = self.db
        do {
            return try await ctx.platformCache.snapshot(now: ctx.now, ttl: Self.cacheTTL) {
                var entries: [String: PlatformFlagCache.Entry] = [:]
                for row in try await PlatformFlagRecord.query(on: db).all() {
                    entries[Self.key(PlatformFlag(rawValue: row.flag) ?? .auditExportMark, row.scope)] = PlatformFlagCache.Entry(value: row.value, reason: row.reason, updatedAt: row.updatedAt)
                }
                return entries
            }.entries
        } catch {
            ctx.logger.error("platform flags unavailable", metadata: ["type": "\(type(of: error))"])
            return [:]
        }
    }

    func entry(_ flag: PlatformFlag, scope: String = PlatformFlags.globalScope) async -> PlatformFlagCache.Entry? {
        await snapshot()[Self.key(flag, scope)]
    }

    /// The maintenance message, or `nil` when maintenance mode is off.
    func maintenance() async -> String? { await entry(.maintenance)?.value }

    func isStopped(_ flag: PlatformFlag) async -> Bool { await entry(flag) != nil }

    func webhooksPaused(businessId: UUID) async -> Bool {
        let snap = await snapshot()
        return snap[Self.key(.webhooksPause, Self.globalScope)] != nil || snap[Self.key(.webhooksPause, businessId.uuidString.lowercased())] != nil
    }

    /// The abuse thresholds with the operator override applied.
    func abuse(base: AbuseThresholds) async -> AbuseThresholds {
        guard let entry = await entry(.abuseThresholds), let override = try? JSONDecoder().decode(AbuseOverride.self, from: Data(entry.value.utf8)),
              override.isWithinBounds else { return base }
        return override.applied(to: base)
    }

    func restrictions(businessId: UUID) async -> [MessagingRestriction] {
        let snap = await snapshot()
        return [Self.globalScope, businessId.uuidString.lowercased()].compactMap { scope in
            snap[Self.key(.messagingRestrict, scope)].flatMap { try? JSONDecoder().decode(MessagingRestriction.self, from: Data($0.value.utf8)) }
        }
    }

    func all() async throws -> [PlatformFlagRecord] {
        try await PlatformFlagRecord.query(on: db).filter(\.$flag != PlatformFlag.auditExportMark.rawValue).sort(\.$updatedAt, .descending).all()
    }

    // MARK: Write (operator; the caller enforces re-authentication)

    private func reason(_ raw: String) throws -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (8...300).contains(trimmed.count), !trimmed.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw APIError.validation("Record the reason (8 to 300 characters).", details: ["reason": "required"])
        }
        return trimmed
    }

    private func normalizedScope(_ flag: PlatformFlag, businessId: UUID?) async throws -> String {
        if flag.globalOnly {
            guard businessId == nil else { throw APIError.validation("This switch is platform-wide.", details: ["scope": "global_only"]) }
            return Self.globalScope
        }
        guard let businessId else { return Self.globalScope }
        guard try await BusinessRecord.find(businessId, on: db) != nil else { throw APIError.notFound }
        return businessId.uuidString.lowercased()
    }

    /// Turns a switch on (or changes its value). `value` is validated per flag.
    func set(_ flag: PlatformFlag, businessId: UUID? = nil, value rawValue: String, reason rawReason: String, actor: EntitlementActor) async throws {
        let reason = try reason(rawReason)
        let scope = try await normalizedScope(flag, businessId: businessId)
        let value = try validated(flag, rawValue)
        let now = ctx.now
        try await db.transaction { tx in
            if let row = try await PlatformFlagRecord.query(on: tx).filter(\.$flag == flag.rawValue).filter(\.$scope == scope).first() {
                row.value = value
                row.reason = reason
                row.updatedBy = actor.id
                row.updatedAt = now
                try await row.update(on: tx)
            } else {
                let row = PlatformFlagRecord()
                row.id = UUID()
                row.flag = flag.rawValue
                row.scope = scope
                row.value = value
                row.reason = reason
                row.updatedBy = actor.id
                row.updatedAt = now
                try await row.create(on: tx)
            }
            _ = try await AuditService(db: tx, ctx: ctx).record("platform.switch_set", actor: AuditActor(kind: actor.kind, id: actor.id),
                businessId: scope == Self.globalScope ? nil : UUID(uuidString: scope).map(BusinessID.init), subjectType: "platform_switch",
                subjectId: flag.rawValue, metadata: ["scope": scope == Self.globalScope ? "global" : "business", "reason": reason])
        }
        await ctx.platformCache.invalidate()
        if flag == .webhooksPause { ctx.metrics.count(.webhookPaused) }
    }

    func clear(_ flag: PlatformFlag, businessId: UUID? = nil, reason rawReason: String, actor: EntitlementActor) async throws {
        let reason = try reason(rawReason)
        let scope = try await normalizedScope(flag, businessId: businessId)
        try await db.transaction { tx in
            try await PlatformFlagRecord.query(on: tx).filter(\.$flag == flag.rawValue).filter(\.$scope == scope).delete()
            _ = try await AuditService(db: tx, ctx: ctx).record("platform.switch_cleared", actor: AuditActor(kind: actor.kind, id: actor.id),
                businessId: scope == Self.globalScope ? nil : UUID(uuidString: scope).map(BusinessID.init), subjectType: "platform_switch",
                subjectId: flag.rawValue, metadata: ["scope": scope == Self.globalScope ? "global" : "business", "reason": reason])
        }
        await ctx.platformCache.invalidate()
    }

    /// Per-flag validation of the stored value. Anything unparsable is rejected: a switch must never be stored in a form the readers ignore.
    private func validated(_ flag: PlatformFlag, _ raw: String) throws -> String {
        switch flag {
        case .maintenance:
            let message = raw.trimmingCharacters(in: .whitespacesAndNewlines)
            guard (1...200).contains(message.count), !message.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
                throw APIError.validation("Give a short status message (up to 200 characters).", details: ["message": "invalid"])
            }
            return message
        case .signupConsumer, .signupBusiness, .inviteDashboard, .webhooksPause, .auditExportMark:
            return "on"
        case .messagingRestrict:
            guard let restriction = try? JSONDecoder().decode(MessagingRestriction.self, from: Data(raw.utf8)),
                  !restriction.channels.isEmpty, Set(restriction.channels).isSubset(of: MessagingRestriction.channelNames),
                  restriction.mode == .block || (1...MessagingRestriction.maximumClamp).contains(restriction.perMinute ?? 0),
                  (restriction.purposes ?? []).allSatisfy({ InteractionPurpose(rawValue: $0) != nil && $0 != InteractionPurpose.security.rawValue }) else {
                throw APIError.validation("Choose channels (sms, rcs, push) and either block or a per-minute clamp of 1 to \(MessagingRestriction.maximumClamp).",
                                          details: ["restriction": "invalid"])
            }
            return String(decoding: try JSONEncoder().encode(restriction), as: UTF8.self)
        case .abuseThresholds:
            guard let override = try? JSONDecoder().decode(AbuseOverride.self, from: Data(raw.utf8)), override.isWithinBounds,
                  override.complaintRate != nil || override.optOutRate != nil || override.minimumSample != nil || override.windowDays != nil || override.throttleFactor != nil else {
                throw APIError.validation("Thresholds are outside their safe bounds.", details: ["thresholds": "out_of_bounds"])
            }
            return String(decoding: try JSONEncoder().encode(override), as: UTF8.self)
        }
    }
}

// MARK: - Messaging gate (G-6)

struct MessagingGate {
    enum Channel: String, Sendable { case sms, rcs, push }
    enum Decision: Equatable, Sendable {
        case allow
        case block
        /// Over a clamp: try again after this many seconds.
        case delay(TimeInterval)
    }

    let db: any Database
    let ctx: ServerContext

    /// Decides one outbound business message. Sign-in and payment approvals are always allowed here, decided by the **server-known
    /// kind** of the interaction: the purpose a business declares never exempts anything by itself (platform gate M1).
    func decide(businessId: UUID, channel: Channel, purpose: String, kind: InteractionKind? = nil) async -> Decision {
        if purpose == InteractionPurpose.security.rawValue, kind?.isRestrictionExempt == true { return .allow }
        let flags = PlatformFlags(db: db, ctx: ctx)
        var decision = Decision.allow
        for restriction in await flags.restrictions(businessId: businessId) where restriction.channels.contains(channel.rawValue) {
            if let purposes = restriction.purposes, !purposes.contains(purpose) { continue }
            switch restriction.mode {
            case .block:
                ctx.metrics.count(.messagingRestricted)
                return .block
            case .clamp:
                let limit = Double(restriction.perMinute ?? 1)
                // One bucket per (business, channel): the clamp bounds what a single tenant can send.
                let allowed = await ctx.limiter.allow("msg-clamp", key: "\(businessId.uuidString.lowercased())|\(channel.rawValue)", rule: .perMinute(limit, burst: limit))
                if !allowed {
                    ctx.metrics.count(.messagingRestricted)
                    decision = .delay(60)
                }
            }
        }
        return decision
    }
}

// MARK: - Middleware

/// G-1: while maintenance mode is on, every request that is not a read is answered `503` with the operator's static message. Exempt:
/// health checks, the operator console (so the switch can be turned off), `/metrics`, and the SMS/RCS provider callbacks (an opt-out
/// must never be lost to a maintenance window).
struct MaintenanceMiddleware: AsyncMiddleware {
    static let exemptPrefixes = ["/operator", "/v1/providers/", "/metrics"]
    static let exactPaths: Set<String> = ["/healthz", "/readyz"]

    func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        if request.method == .GET || request.method == .HEAD || request.method == .OPTIONS { return try await next.respond(to: request) }
        let path = request.url.path
        if Self.exactPaths.contains(path) || Self.exemptPrefixes.contains(where: { path == $0 || path.hasPrefix($0.hasSuffix("/") ? $0 : $0 + "/") }) {
            return try await next.respond(to: request)
        }
        if let message = await PlatformFlags(db: request.db, ctx: request.ctx).maintenance() {
            request.ctx.metrics.count(.maintenanceRejected)
            throw APIError(.serviceUnavailable, .unavailable, message, headers: ["Retry-After": "60"])
        }
        return try await next.respond(to: request)
    }
}

/// G-15: refuses new sign-ups while the matching switch is on. Sign-in of existing accounts is untouched.
struct SignupGateMiddleware: AsyncMiddleware {
    static let consumerPaths: Set<String> = ["/v1/auth/register/begin", "/v1/auth/register/finish"]
    static let businessPaths: Set<String> = ["/dashboard/auth/signup/begin", "/dashboard/auth/signup/finish"]

    func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        guard request.method == .POST else { return try await next.respond(to: request) }
        let path = request.url.path
        var flag: PlatformFlag?
        if Self.consumerPaths.contains(path) { flag = .signupConsumer }
        else if Self.businessPaths.contains(path) { flag = .signupBusiness }
        else if path == "/dashboard/team/invite" || path.hasPrefix("/dashboard/auth/invite/") || (path.hasPrefix("/dashboard/invite/") && path.hasSuffix("/accept")) { flag = .inviteDashboard }
        if let flag, await PlatformFlags(db: request.db, ctx: request.ctx).isStopped(flag) {
            request.ctx.metrics.count(.signupStopped)
            throw APIError(.serviceUnavailable, .unavailable, "New sign-ups are paused for now. Existing accounts are not affected.", headers: ["Retry-After": "3600"])
        }
        return try await next.respond(to: request)
    }
}
