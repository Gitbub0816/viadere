@preconcurrency import Crypto
import Fluent
import Foundation
import Vapor
import ViadereCore

/// The two cookie realms. A cookie issued for one realm is useless in the other.
enum DashboardRealm: String {
    case business, `operator`

    /// `__Host-` cookies must be `Secure`, have `Path=/` and no `Domain`: they cannot be set by a sub-domain or over HTTP.
    var cookieName: String { self == .business ? "__Host-vd_session" : "__Host-vd_operator" }
    var loginPath: String { self == .business ? "/dashboard/login" : "/operator/login" }
    var home: String { self == .business ? "/dashboard" : "/operator" }
}

/// Server-side session storage. Only SHA-256 of the cookie value is stored; the cookie itself is a 256-bit random.
///
/// * Rotated on login: every sign-in creates a brand-new session (a presented old cookie is revoked).
/// * Idle timeout (default 30 min) and absolute timeout (default 12 h; operators 15 min / 8 h).
/// * `reauthAt` records the last passkey assertion; sensitive actions need it to be recent.
struct DashboardSessionStore {
    let db: any Database
    let ctx: ServerContext

    static let tokenPrefix = "vds_"

    struct Created {
        let token: String
        let record: DashboardSessionRecord
        let maxAge: Int
    }

    func idleTimeout(_ realm: DashboardRealm) -> TimeInterval {
        realm == .business ? ctx.config.dashboard.idleTimeout : ctx.config.dashboard.operatorIdleTimeout
    }

    func absoluteTimeout(_ realm: DashboardRealm) -> TimeInterval {
        realm == .business ? ctx.config.dashboard.absoluteTimeout : ctx.config.dashboard.operatorAbsoluteTimeout
    }

    /// Starts a new session after a successful passkey assertion/registration.
    func create(userId: UUID, realm: DashboardRealm, businessId: UUID?, replacing previous: String?) async throws -> Created {
        let now = ctx.now
        if let previous, let old = try await lookup(token: previous) {
            old.revokedAt = now
            try await old.update(on: db)
        }
        let token = Self.tokenPrefix + SecureToken.generate()
        let record = DashboardSessionRecord()
        record.id = UUID()
        record.userId = userId
        record.realm = realm.rawValue
        record.tokenHash = SecureToken.hash(token)
        record.businessId = businessId
        record.createdAt = now
        record.lastSeenAt = now
        record.expiresAt = now.addingTimeInterval(absoluteTimeout(realm))
        record.reauthAt = now // the sign-in itself was a fresh user-verifying assertion
        try await record.create(on: db)
        return Created(token: token, record: record, maxAge: Int(absoluteTimeout(realm)))
    }

    private func lookup(token: String) async throws -> DashboardSessionRecord? {
        guard token.hasPrefix(Self.tokenPrefix), token.count <= 80 else { return nil }
        return try await DashboardSessionRecord.query(on: db).filter(\.$tokenHash == SecureToken.hash(token)).first()
    }

    /// The live session for a cookie value, or `nil` (unknown, wrong realm, revoked, idle- or absolute-expired).
    func authenticate(token: String, realm: DashboardRealm) async throws -> DashboardSessionRecord? {
        guard let record = try await lookup(token: token), record.realm == realm.rawValue, record.revokedAt == nil else { return nil }
        let now = ctx.now
        guard now < record.expiresAt, now.timeIntervalSince(record.lastSeenAt) <= idleTimeout(realm) else {
            record.revokedAt = now
            try await record.update(on: db)
            return nil
        }
        if now.timeIntervalSince(record.lastSeenAt) > 10 {
            record.lastSeenAt = now
            try await record.update(on: db)
        }
        return record
    }

    func revoke(token: String) async throws {
        if let record = try await lookup(token: token), record.revokedAt == nil {
            record.revokedAt = ctx.now
            try await record.update(on: db)
        }
    }

    func revokeAll(userId: UUID) async throws {
        try await DashboardSessionRecord.query(on: db).filter(\.$userId == userId).filter(\.$revokedAt == nil)
            .set(\.$revokedAt, to: ctx.now).update()
    }

    static func purge(on db: any Database, now: Date) async throws {
        // Abuse signal buckets older than 90 days carry no value.
        let oldBucket = Int(now.timeIntervalSince1970 / 60) - 90 * 24 * 60
        if try await AbuseSignalRecord.query(on: db).filter(\.$bucket < oldBucket).count() > 0 {
            try await AbuseSignalRecord.query(on: db).filter(\.$bucket < oldBucket).delete()
        }
        let cutoff = now.addingTimeInterval(-24 * 3600)
        if try await DashboardSessionRecord.query(on: db).filter(\.$expiresAt < cutoff).count() > 0 {
            try await DashboardSessionRecord.query(on: db).filter(\.$expiresAt < cutoff).delete()
        }
        if try await DashboardCeremonyRecord.query(on: db).filter(\.$expiresAt < now.addingTimeInterval(-3600)).count() > 0 {
            try await DashboardCeremonyRecord.query(on: db).filter(\.$expiresAt < now.addingTimeInterval(-3600)).delete()
        }
    }

    // MARK: Cookie

    func cookie(for created: Created, realm: DashboardRealm) -> HTTPCookies.Value {
        HTTPCookies.Value(string: created.token, expires: nil, maxAge: created.maxAge, domain: nil, path: "/",
                          isSecure: true, isHTTPOnly: true, sameSite: .strict)
    }

    static func clearingCookie(realm: DashboardRealm) -> HTTPCookies.Value {
        HTTPCookies.Value(string: "", expires: Date(timeIntervalSince1970: 0), maxAge: 0, domain: nil, path: "/",
                          isSecure: true, isHTTPOnly: true, sameSite: .strict)
    }

    // MARK: CSRF

    /// Per-session CSRF token: a keyed MAC of the cookie value. Not stored, cannot be guessed without the
    /// server pepper, and changes whenever the session rotates.
    static func csrfToken(sessionToken: String, hasher: Hasher256) -> String {
        String(hasher.hmacHex("dashboard-csrf", sessionToken).prefix(43))
    }
}

/// An authenticated dashboard request.
struct DashboardPrincipal {
    let user: DashboardUserRecord
    let session: DashboardSessionRecord
    let realm: DashboardRealm
    let sessionToken: String
    let csrf: String
    /// Business realm: the active membership (always freshly loaded) and organization.
    let membership: OrgMembershipRecord?
    let business: BusinessRecord?

    var role: OrgRole? { membership.flatMap { OrgRole(rawValue: $0.role) } }
    var businessUUID: UUID? { business?.id }

    func can(_ permission: DashboardPermission) -> Bool { role?.permits(permission) ?? false }

    func hasFreshReauth(ctx: ServerContext) -> Bool {
        guard let at = session.reauthAt else { return false }
        return ctx.now.timeIntervalSince(at) <= ctx.config.dashboard.reauthWindow
    }
}

struct DashboardPrincipalKey: StorageKey { typealias Value = DashboardPrincipal }

extension Request {
    var dashboard: DashboardPrincipal {
        get throws {
            guard let principal = storage[DashboardPrincipalKey.self] else { throw APIError.unauthorized }
            return principal
        }
    }

    func requireCookie(_ realm: DashboardRealm) -> String? {
        cookies[realm.cookieName]?.string
    }
}

/// Thrown when a sensitive action needs a fresh passkey assertion.
struct ReauthRequired: Error {
    /// Where to send the user after confirming (a fixed dashboard path chosen by the route, never user input).
    let next: String
}

/// Authenticates a dashboard realm from its cookie, loads the *current* membership and role, and enforces CSRF
/// on every state-changing request.
struct DashboardAuthMiddleware: AsyncMiddleware {
    let realm: DashboardRealm
    /// JSON endpoints answer 401 instead of redirecting to the login page.
    var json = false

    func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        let ctx = request.ctx
        let db = request.db
        let store = DashboardSessionStore(db: db, ctx: ctx)
        func unauthenticated() -> Response {
            if json { return DashboardResponses.json(status: .unauthorized, ["error": ["code": "unauthorized", "message": "Authentication required."]]) }
            return DashboardResponses.redirect(realm.loginPath)
        }
        guard let token = request.requireCookie(realm), let session = try await store.authenticate(token: token, realm: realm),
              let user = try await DashboardUserRecord.find(session.userId, on: db), user.status == "active",
              user.isOperator == (realm == .operator) else {
            let response = unauthenticated()
            if request.requireCookie(realm) != nil { response.cookies[realm.cookieName] = DashboardSessionStore.clearingCookie(realm: realm) }
            return response
        }
        var membership: OrgMembershipRecord?
        var business: BusinessRecord?
        if realm == .business {
            // The organization comes from the session but is re-validated against the live membership every time.
            guard let businessId = session.businessId,
                  let found = try await OrgMembershipRecord.query(on: db).filter(\.$userId == session.userId)
                      .filter(\.$businessId == businessId).filter(\.$removedAt == nil).first(),
                  let org = try await BusinessRecord.find(businessId, on: db) else {
                let response = unauthenticated()
                response.cookies[realm.cookieName] = DashboardSessionStore.clearingCookie(realm: realm)
                return response
            }
            membership = found
            business = org
        }
        let csrf = DashboardSessionStore.csrfToken(sessionToken: token, hasher: ctx.hasher)
        let principal = DashboardPrincipal(user: user, session: session, realm: realm, sessionToken: token, csrf: csrf,
                                           membership: membership, business: business)
        request.storage[DashboardPrincipalKey.self] = principal
        if request.method != .GET && request.method != .HEAD {
            try DashboardCSRF.verify(request, expected: csrf, ctx: ctx)
            try await ctx.limiter.enforce("dashboard-action", key: user.id?.uuidString ?? "", rule: ctx.config.rateLimits.dashboardAction)
        }
        return try await next.respond(to: request)
    }
}

enum DashboardCSRF {
    /// State-changing requests must carry the session's CSRF token (form field `_csrf` or `X-CSRF-Token`), and an
    /// `Origin` header, when the browser sends one, must be one of ours. SameSite=Strict cookies are the first
    /// layer; this is the second.
    static func verify(_ request: Request, expected: String, ctx: ServerContext) throws {
        if let origin = request.headers.first(name: .origin), !allowedOrigins(ctx).contains(origin) {
            throw APIError(.forbidden, .forbidden, "Cross-origin request blocked.")
        }
        let supplied = request.headers.first(name: "X-CSRF-Token")
            ?? (try? request.content.get(String.self, at: "_csrf"))
        guard let supplied, ConstantTime.equals(supplied, expected) else {
            throw APIError(.forbidden, .forbidden, "Your session could not be verified. Reload the page and try again.")
        }
    }

    static func allowedOrigins(_ ctx: ServerContext) -> Set<String> {
        var origins: Set<String> = [ctx.config.publicBaseURL.trimmingCharacters(in: CharacterSet(charactersIn: "/")), ctx.config.relyingPartyOrigin]
        if let dashboard = ctx.config.dashboardOrigin { origins.insert(dashboard) }
        return origins
    }
}
