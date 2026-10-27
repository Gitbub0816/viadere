import Fluent
import Foundation
import Vapor
import ViadereCore

/// What the console knows about the client of a sign-in: a coarse device label, the address with its host part removed, a country if the edge
/// supplied one, and keyed hashes of each. The raw address and agent string are never stored.
struct ClientContext: Sendable {
    var ip: String
    var ipMasked: String
    var userAgent: String
    var uaLabel: String
    var country: String?

    init(_ request: Request) {
        let ctx = request.application.ctx
        ip = ClientIP.rawAddress(request, trustedProxies: ctx.config.trustedProxyCount)
        ipMasked = IPNetwork.masked(ip)
        userAgent = String((request.headers.first(name: .userAgent) ?? "").prefix(300))
        uaLabel = Self.label(for: userAgent)
        // Cloudflare's country header is believed only on a request that passed the origin lock.
        let raw = request.edge.viaEdge ? request.headers.first(name: "CF-IPCountry")?.uppercased() : nil
        country = raw.flatMap { $0.count == 2 && $0.allSatisfy { $0.isASCII && $0.isLetter } && $0 != "XX" && $0 != "T1" ? $0 : nil }
    }

    /// "Safari on macOS": a fixed vocabulary, so the label can be shown and compared without keeping the agent string.
    static func label(for userAgent: String) -> String {
        let ua = userAgent.lowercased()
        let browser: String
        if ua.contains("edg/") || ua.contains("edge/") { browser = "Edge" }
        else if ua.contains("opr/") || ua.contains("opera") { browser = "Opera" }
        else if ua.contains("firefox/") || ua.contains("fxios") { browser = "Firefox" }
        else if ua.contains("chrome/") || ua.contains("crios") { browser = "Chrome" }
        else if ua.contains("safari/") { browser = "Safari" }
        else if ua.isEmpty { browser = "Unknown browser" }
        else { browser = "Other browser" }
        let system: String
        if ua.contains("iphone") || ua.contains("ipad") || ua.contains("ios") { system = "iOS" }
        else if ua.contains("android") { system = "Android" }
        else if ua.contains("cros") { system = "ChromeOS" }
        else if ua.contains("mac os x") || ua.contains("macintosh") { system = "macOS" }
        else if ua.contains("windows") { system = "Windows" }
        else if ua.contains("linux") { system = "Linux" }
        else { system = "an unknown system" }
        return "\(browser) on \(system)"
    }
}

struct SessionSecurity {
    let db: any Database
    let ctx: ServerContext

    /// Records the client on the session and, for a person who has signed in before, raises a suspicious-login alert when the device, country or
    /// network is new. The first sign-in only establishes the baseline. The alert is emailed to the person themselves; a business also gets it on its
    /// security contacts when subscribed. Never blocks the sign-in.
    func recordSignIn(session: DashboardSessionRecord, user: DashboardUserRecord, client: ClientContext, realm: DashboardRealm) async {
        do {
            session.ipHash = ctx.hasher.versionedHex("session-ip", client.ip)
            session.ipMasked = client.ipMasked
            session.uaHash = ctx.hasher.versionedHex("session-ua", client.userAgent)
            session.uaLabel = client.uaLabel
            session.country = client.country
            try await session.update(on: db)
            guard let userId = user.id else { return }
            let known = try await DashboardKnownContextRecord.query(on: db).filter(\.$userId == userId).count()
            var changed: [String] = []
            let now = ctx.now
            var dimensions = [("device", client.uaLabel), ("network", client.ipMasked)]
            if let country = client.country { dimensions.append(("location", country)) }
            for (dimension, value) in dimensions {
                let hash = ctx.hasher.hmacHex("known-context|\(dimension)", value)
                if let existing = try await DashboardKnownContextRecord.query(on: db).filter(\.$userId == userId).filter(\.$dimension == dimension)
                    .filter(\.$valueHash == hash).first() {
                    existing.lastSeenAt = now
                    try await existing.update(on: db)
                } else {
                    let row = DashboardKnownContextRecord()
                    row.id = UUID()
                    row.userId = userId
                    row.dimension = dimension
                    row.valueHash = hash
                    row.firstSeenAt = now
                    row.lastSeenAt = now
                    try await row.create(on: db)
                    if known > 0 { changed.append(dimension) }
                }
            }
            guard !changed.isEmpty else { return }
            ctx.metrics.count(.suspiciousLogin)
            _ = try await AuditService(db: db, ctx: ctx).record("dashboard.suspicious_login", outcome: .success,
                actor: AuditActor(kind: realm == .operator ? .operator_ : .business, id: userId.uuidString.lowercased()), businessId: session.businessId.map(BusinessID.init),
                metadata: ["new": changed.joined(separator: " "), "realm": realm.rawValue])
            let text = """
                We noticed a sign-in to your Viadere \(realm == .operator ? "operator console" : "console") from something new: \(changed.map { "a new \($0)" }.joined(separator: ", ")).

                Device: \(client.uaLabel)
                Network: \(client.ipMasked)\(client.country.map { "\nCountry: \($0)" } ?? "")
                Time: \(DashboardFormat.date(now))

                If this was you, no action is needed. If it was not, sign in, open Security > Sessions, and sign out the session you do not recognize; then rotate any API keys it could have seen.
                """
            if let email = try? ctx.cipher.openString(user.emailCiphertext, context: "dashboard_users.email", rowId: userId) {
                try? await ctx.email.send(EmailMessage(to: email, subject: "New sign-in to your Viadere console", text: text, kind: "suspicious-login"))
            }
            if realm == .business, let businessId = session.businessId {
                await Notifier(db: db, ctx: ctx).notifyBusiness(businessId, roles: [], includeSecurityContacts: true, topic: .suspiciousLogin,
                    subject: "A team member signed in from a new device, location or network", text: text.replacingOccurrences(of: "your Viadere", with: "a team member's Viadere"),
                    kind: "suspicious-login-contact")
            }
        } catch {
            ctx.logger.warning("sign-in context could not be recorded", metadata: ["type": "\(type(of: error))"])
        }
    }

    // MARK: Inventory

    struct Row {
        var session: DashboardSessionRecord
        var userName: String
        var current: Bool
    }

    /// Live sessions of the organization (`all`) or of one user.
    func active(businessId: UUID, userId: UUID?, currentSession: UUID?) async throws -> [Row] {
        let now = ctx.now
        var query = DashboardSessionRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$revokedAt == nil).filter(\.$expiresAt > now)
        if let userId { query = query.filter(\.$userId == userId) }
        let sessions = try await query.sort(\.$lastSeenAt, .descending).limit(200).all()
        let users = try await DashboardUserRecord.query(on: db).filter(\.$id ~~ Set(sessions.map(\.userId)).map { $0 }).all()
        let names = Dictionary(users.compactMap { u in u.id.map { ($0, u.displayName) } }, uniquingKeysWith: { a, _ in a })
        let idle = ctx.config.dashboard.idleTimeout
        return sessions.filter { now.timeIntervalSince($0.lastSeenAt) <= idle }.map { Row(session: $0, userName: names[$0.userId] ?? "—", current: $0.id == currentSession) }
    }

    @discardableResult
    func revoke(sessionId: UUID, businessId: UUID, by actor: AuditActor) async throws -> Bool {
        guard let record = try await DashboardSessionRecord.query(on: db).filter(\.$id == sessionId).filter(\.$businessId == businessId).first() else { throw APIError.notFound }
        guard record.revokedAt == nil else { return false }
        guard try await DB.swapFromNull(db, table: DashboardSessionRecord.schema, id: sessionId, column: "revoked_at", newValue: ctx.now) else { return false }
        ctx.metrics.count(.sessionRevoked)
        _ = try await AuditService(db: db, ctx: ctx).record("dashboard.session_revoked", actor: actor, businessId: BusinessID(businessId), subjectType: "session",
            subjectId: sessionId.uuidString.lowercased(), metadata: ["of_user": record.userId.uuidString.lowercased()])
        return true
    }

    /// Ends every other live session of a user (the "sign out everywhere else" button).
    @discardableResult
    func revokeOthers(userId: UUID, keeping current: UUID, businessId: UUID, by actor: AuditActor) async throws -> Int {
        var count = 0
        for session in try await DashboardSessionRecord.query(on: db).filter(\.$userId == userId).filter(\.$businessId == businessId).filter(\.$revokedAt == nil).all() {
            guard let id = session.id, id != current else { continue }
            if try await revoke(sessionId: id, businessId: businessId, by: actor) { count += 1 }
        }
        return count
    }
}
