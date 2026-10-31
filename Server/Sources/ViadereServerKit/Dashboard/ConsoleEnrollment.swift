import Fluent
import Foundation
import Vapor
import ViadereCore

/// A one-time, one-hour link that lets an existing business console user register a passkey (the business-realm twin of
/// `operator_enrollments`). Only the token's SHA-256 is stored; the token itself is shown once, on the terminal of whoever ran
/// `ViadereServer staging-demo --console-owner` (staging only). **No HTTP route creates one**: the routes below can only open, begin and
/// finish an existing link.
final class ConsoleEnrollmentRecord: Model, @unchecked Sendable {
    static let schema = "console_enrollments"
    @ID(key: .id) var id: UUID?
    @Field(key: "user_id") var userId: UUID
    /// The organization the enrolled passkey signs in to (the session is bound to it; the membership is re-checked on every request).
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "token_hash") var tokenHash: String
    /// `open`, `used` or `revoked` (a newer link for the same user revokes the older ones).
    @Field(key: "state") var state: String
    @Field(key: "expires_at") var expiresAt: Date
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "used_at") var usedAt: Date?

    init() {}

    /// Fixed lifetime of a link, independent of configuration.
    static let lifetime: TimeInterval = 3600
}

/// `ConsoleEnrollments.v1` (additive): one table.
struct CreateConsoleEnrollmentSchema: AsyncMigration {
    var name: String { "ConsoleEnrollments.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema(ConsoleEnrollmentRecord.schema).id()
            .field("user_id", .uuid, .required, .references("dashboard_users", "id", onDelete: .cascade))
            .field("business_id", .uuid, .required, .references("businesses", "id", onDelete: .cascade))
            .field("token_hash", .string, .required)
            .field("state", .string, .required)
            .field("expires_at", .datetime, .required)
            .field("created_at", .datetime, .required)
            .field("used_at", .datetime)
            .unique(on: "token_hash")
            .create()
    }

    func revert(on db: any Database) async throws {
        try await db.schema(ConsoleEnrollmentRecord.schema).delete()
    }
}

/// `GET /dashboard/enroll/:token` and the two passkey ceremony endpoints. Same properties as the operator enrollment: the token is looked up
/// by hash, spent exactly once when the passkey is stored, valid one hour; IP rate limits on every endpoint; a cross-site `Origin` is refused
/// (there is no session yet, so the token in the body plus the origin check stand in for the session CSRF token); everything is audited.
enum ConsoleEnrollmentRoutes {
    static let pagePrefix = "/dashboard/enroll/"
    static let beginPath = "/dashboard/auth/enroll/begin"
    static let finishPath = "/dashboard/auth/enroll/finish"

    static func register(_ app: Application) {
        let authLimiter = IPRateLimitMiddleware(name: "dashboard-auth") { $0.rateLimits.dashboardAuth }
        let webLimiter = IPRateLimitMiddleware(name: "web") { $0.rateLimits.directory }
        app.routes.grouped(webLimiter).get("dashboard", "enroll", ":token") { req -> Response in
            let token = req.parameters.get("token") ?? ""
            guard try await DashboardAuthService(db: req.db, ctx: req.ctx).openConsoleEnrollment(token: token) != nil else {
                return DashboardUI.authPage(title: "Enrollment", body: "<h1>Link not valid</h1><p>This enrollment link has expired or was already used.</p>",
                                            script: false, status: .gone)
            }
            return DashboardUI.authPage(title: "Console enrollment", body: """
            <h1>Set up your passkey</h1><p class="mu">Register a passkey for your organization's console. You'll use it to sign in at /dashboard/login.</p>\
            <form data-passkey="register" data-begin="\(beginPath)" data-finish="\(finishPath)" data-next="/dashboard">\
            <input type="hidden" name="token" value="\(DashboardUI.esc(token))"><button class="btn" type="submit">Create passkey</button></form>\
            <p id="pk-msg" class="sm err" role="alert"></p>
            """)
        }
        let ceremonies = app.routes.grouped(authLimiter)
        ceremonies.post("dashboard", "auth", "enroll", "begin") { req in
            try verifyOrigin(req)
            let body: EnrollBeginBody = try req.decodeBody()
            return try req.jsonResponse(try await DashboardAuthService(db: req.db, ctx: req.ctx).consoleEnrollBegin(body))
        }
        ceremonies.post("dashboard", "auth", "enroll", "finish") { req -> Response in
            try verifyOrigin(req)
            let body: PasskeyRegistrationFinishRequest = try req.decodeBody()
            let created = try await DashboardAuthService(db: req.db, ctx: req.ctx).consoleEnrollFinish(body, previousCookie: req.requireCookie(.business))
            if let user = try await DashboardUserRecord.find(created.record.userId, on: req.db) {
                await SessionSecurity(db: req.db, ctx: req.ctx).recordSignIn(session: created.record, user: user, client: ClientContext(req), realm: .business)
            }
            let response = DashboardResponses.json(["redirect": DashboardRealm.business.home])
            response.cookies[DashboardRealm.business.cookieName] = DashboardSessionStore(db: req.db, ctx: req.ctx).cookie(for: created, realm: .business)
            return response
        }
    }

    /// A browser always sends `Origin` on these `fetch` POSTs; a foreign one is refused before anything is read.
    static func verifyOrigin(_ req: Request) throws {
        if let origin = req.headers.first(name: .origin), !DashboardCSRF.allowedOrigins(req.ctx).contains(origin) {
            throw APIError(.forbidden, .forbidden, "Cross-origin request blocked.")
        }
    }
}
