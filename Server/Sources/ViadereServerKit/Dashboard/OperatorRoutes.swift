import Fluent
import Foundation
import Vapor
import ViadereCore

private struct DecisionForm: Content {
    var note: String?
    var handle: String?
}

private struct ReasonForm: Content { var reason: String? }
private struct CeilingForm: Content { var ceiling: String }
private struct ThrottleForm: Content {
    var throttled: String
    var reason: String?
}

/// `ViadereServer create-operator --email … --name …` — creates a pending operator and prints a one-time,
/// one-hour enrollment link. The operator then registers a passkey; there are no passwords.
public struct CreateOperatorCommand: AsyncCommand {
    public struct Signature: CommandSignature {
        @Option(name: "email") var email: String?
        @Option(name: "name") var name: String?
        public init() {}
    }

    public let signature = Signature()
    public let help = "Creates a Viadere operator and prints a one-time passkey enrollment link."

    public init() {}

    public func run(using context: CommandContext, signature: Signature) async throws {
        guard let email = signature.email, let name = signature.name else {
            context.console.error("Usage: create-operator --email <address> --name <display name>")
            throw Abort(.badRequest)
        }
        let app = context.application
        let link = try await DashboardAuthService(db: app.db, ctx: app.ctx).createOperator(email: email, displayName: name)
        context.console.print("Operator created. One-time enrollment link (valid 1 hour, shown once):")
        context.console.print("  \(link)")
    }
}

/// Minimal Viadere operator console: review and verify businesses, suspend, abuse signals and downward-only
/// trust overrides. A separate realm (own cookie, own passkeys, shorter timeouts); every mutation needs a fresh
/// passkey assertion and is audited with actor kind `operator`.
enum OperatorRoutes {
    static func register(_ app: Application) {
        let routes = app.routes
        let authLimiter = IPRateLimitMiddleware(name: "dashboard-auth") { $0.rateLimits.dashboardAuth }
        let webLimiter = IPRateLimitMiddleware(name: "web") { $0.rateLimits.directory }

        routes.grouped(webLimiter).get("operator", "login") { req -> Response in
            DashboardUI.authPage(title: "Operator sign in", body: """
            <h1>Operator console</h1><p class="mu">Viadere staff only. Sign in with your passkey.</p>\
            <form data-passkey="login" data-begin="/operator/auth/login/begin" data-finish="/operator/auth/login/finish" data-next="/operator">\
            <button class="btn" type="submit">Sign in with passkey</button></form><p id="pk-msg" class="sm err" role="alert"></p>
            """)
        }
        routes.grouped(webLimiter).get("operator", "enroll", ":token") { req -> Response in
            let token = req.parameters.get("token") ?? ""
            guard try await DashboardAuthService(db: req.db, ctx: req.ctx).openEnrollment(token: token) != nil else {
                return DashboardUI.authPage(title: "Enrollment", body: "<h1>Link not valid</h1><p>This enrollment link has expired or was already used.</p>", script: false, status: .gone)
            }
            return DashboardUI.authPage(title: "Operator enrollment", body: """
            <h1>Set up your passkey</h1><p class="mu">Register a passkey for the operator console.</p>\
            <form data-passkey="register" data-begin="/operator/auth/enroll/begin" data-finish="/operator/auth/enroll/finish" data-next="/operator">\
            <input type="hidden" name="token" value="\(DashboardUI.esc(token))"><button class="btn" type="submit">Create passkey</button></form>\
            <p id="pk-msg" class="sm err" role="alert"></p>
            """)
        }
        let ceremonies = routes.grouped(authLimiter)
        @Sendable func session(_ created: DashboardSessionStore.Created, _ req: Request) async -> Response {
            if let user = try? await DashboardUserRecord.find(created.record.userId, on: req.db) {
                await SessionSecurity(db: req.db, ctx: req.ctx).recordSignIn(session: created.record, user: user, client: ClientContext(req), realm: .operator)
            }
            let response = DashboardResponses.json(["redirect": "/operator"])
            response.cookies[DashboardRealm.operator.cookieName] = DashboardSessionStore(db: req.db, ctx: req.ctx).cookie(for: created, realm: .operator)
            return response
        }
        ceremonies.post("operator", "auth", "login", "begin") { req in
            try req.jsonResponse(try await DashboardAuthService(db: req.db, ctx: req.ctx).loginBegin(realm: .operator))
        }
        ceremonies.post("operator", "auth", "login", "finish") { req in
            let body: PasskeyLoginFinishRequest = try req.decodeBody()
            return await session(try await DashboardAuthService(db: req.db, ctx: req.ctx).loginFinish(realm: .operator, body, previousCookie: req.requireCookie(.operator)), req)
        }
        ceremonies.post("operator", "auth", "enroll", "begin") { req in
            let body: EnrollBeginBody = try req.decodeBody()
            return try req.jsonResponse(try await DashboardAuthService(db: req.db, ctx: req.ctx).enrollBegin(body))
        }
        ceremonies.post("operator", "auth", "enroll", "finish") { req in
            let body: PasskeyRegistrationFinishRequest = try req.decodeBody()
            return await session(try await DashboardAuthService(db: req.db, ctx: req.ctx).enrollFinish(body, previousCookie: req.requireCookie(.operator)), req)
        }
        let json = routes.grouped(DashboardAuthMiddleware(realm: .operator, json: true))
        json.post("operator", "auth", "reauth", "begin") { req in
            try req.jsonResponse(try await DashboardAuthService(db: req.db, ctx: req.ctx).reauthBegin(try req.dashboard))
        }
        json.post("operator", "auth", "reauth", "finish") { req in
            let body: PasskeyLoginFinishRequest = try req.decodeBody()
            try await DashboardAuthService(db: req.db, ctx: req.ctx).reauthFinish(try req.dashboard, body)
            return try req.emptyOK()
        }

        let pages = routes.grouped(DashboardPageErrorMiddleware()).grouped(DashboardAuthMiddleware(realm: .operator))
        pages.post("operator", "logout") { req -> Response in
            let p = try req.dashboard
            try await DashboardSessionStore(db: req.db, ctx: req.ctx).revoke(token: p.sessionToken)
            let response = DashboardResponses.redirect("/operator/login")
            response.cookies[DashboardRealm.operator.cookieName] = DashboardSessionStore.clearingCookie(realm: .operator)
            return response
        }
        pages.get("operator") { req in try await applications(req) }
        pages.get("operator", "applications", ":id") { req in try await application(req) }
        pages.post("operator", "applications", ":id", "approve") { req -> Response in
            let p = try operatorPrincipal(req)
            let id = try req.uuid("id")
            guard p.hasFreshReauth(ctx: req.ctx) else { throw ReauthRequired(next: "/operator/applications/\(id.uuidString.lowercased())") }
            let form = try req.content.decode(DecisionForm.self)
            try await BusinessOnboarding(db: req.db, ctx: req.ctx).approve(businessId: id, operatorId: p.user.id!, handleOverride: form.handle, note: form.note)
            return DashboardResponses.redirect("/operator?m=approved")
        }
        pages.post("operator", "applications", ":id", "reject") { req -> Response in
            let p = try operatorPrincipal(req)
            let id = try req.uuid("id")
            guard p.hasFreshReauth(ctx: req.ctx) else { throw ReauthRequired(next: "/operator/applications/\(id.uuidString.lowercased())") }
            let form = try req.content.decode(DecisionForm.self)
            try await BusinessOnboarding(db: req.db, ctx: req.ctx).reject(businessId: id, operatorId: p.user.id!, note: form.note)
            return DashboardResponses.redirect("/operator?m=rejected")
        }
        pages.get("operator", "businesses") { req in try await businesses(req) }
        pages.get("operator", "businesses", ":id") { req in try await business(req) }
        pages.post("operator", "businesses", ":id", "suspend") { req -> Response in
            let p = try operatorPrincipal(req)
            let id = try req.uuid("id")
            guard p.hasFreshReauth(ctx: req.ctx) else { throw ReauthRequired(next: "/operator/businesses/\(id.uuidString.lowercased())") }
            let form = try req.content.decode(ReasonForm.self)
            try await BusinessOnboarding(db: req.db, ctx: req.ctx).suspend(businessId: id, operatorId: p.user.id!, reason: form.reason ?? "operator action")
            return DashboardResponses.redirect("/operator/businesses/\(id.uuidString.lowercased())?m=suspended")
        }
        pages.post("operator", "businesses", ":id", "unsuspend") { req -> Response in
            let p = try operatorPrincipal(req)
            let id = try req.uuid("id")
            guard p.hasFreshReauth(ctx: req.ctx) else { throw ReauthRequired(next: "/operator/businesses/\(id.uuidString.lowercased())") }
            try await BusinessOnboarding(db: req.db, ctx: req.ctx).unsuspend(businessId: id, operatorId: p.user.id!)
            return DashboardResponses.redirect("/operator/businesses/\(id.uuidString.lowercased())?m=unsuspended")
        }
        pages.post("operator", "businesses", ":id", "ceiling") { req -> Response in
            let p = try operatorPrincipal(req)
            let id = try req.uuid("id")
            guard p.hasFreshReauth(ctx: req.ctx) else { throw ReauthRequired(next: "/operator/businesses/\(id.uuidString.lowercased())") }
            let form = try req.content.decode(CeilingForm.self)
            let ceiling = form.ceiling == "none" ? nil : InteractionPriority(rawValue: form.ceiling)
            if form.ceiling != "none" && ceiling == nil { throw APIError.validation("Choose low, normal, high or none.") }
            try await BusinessOnboarding(db: req.db, ctx: req.ctx).setPriorityCeiling(businessId: id, operatorId: p.user.id!, ceiling: ceiling)
            return DashboardResponses.redirect("/operator/businesses/\(id.uuidString.lowercased())?m=ceiling")
        }
        pages.post("operator", "businesses", ":id", "throttle") { req -> Response in
            let p = try operatorPrincipal(req)
            let id = try req.uuid("id")
            guard p.hasFreshReauth(ctx: req.ctx) else { throw ReauthRequired(next: "/operator/businesses/\(id.uuidString.lowercased())") }
            let form = try req.content.decode(ThrottleForm.self)
            try await BusinessOnboarding(db: req.db, ctx: req.ctx).setThrottle(businessId: id, operatorId: p.user.id!, throttled: form.throttled == "on", reason: form.reason)
            return DashboardResponses.redirect("/operator/businesses/\(id.uuidString.lowercased())?m=throttle")
        }
        pages.get("operator", "abuse") { req in try await abuse(req) }
        OperatorOps.register(pages)
    }

    private static func operatorPrincipal(_ req: Request) throws -> DashboardPrincipal {
        let p = try req.dashboard
        guard p.realm == .operator else { throw APIError.forbidden }
        return p
    }

    // MARK: Pages

    private static func applications(_ req: Request) async throws -> Response {
        let p = try operatorPrincipal(req)
        let pending = try await BusinessApplicationRecord.query(on: req.db).filter(\.$state == "pending").sort(\.$submittedAt, .ascending).all()
        let businesses = try await BusinessRecord.query(on: req.db).filter(\.$id ~~ pending.map(\.businessId)).all()
        let byId = Dictionary(businesses.compactMap { b in b.id.map { ($0, b) } }, uniquingKeysWith: { a, _ in a })
        let rows = pending.map { a -> [String] in
            let b = byId[a.businessId]
            return ["<a href=\"/operator/applications/\(a.businessId.uuidString.lowercased())\">\(DashboardUI.esc(b?.displayName ?? "—"))</a>",
                    DashboardUI.esc(b?.category.replacingOccurrences(of: "_", with: " ") ?? ""), DashboardUI.esc(a.requestedHandle.map { "@" + $0 } ?? "—"),
                    DashboardUI.esc(a.website ?? "—"), DashboardFormat.date(a.submittedAt)]
        }
        let queues = try await OperatorOps.queues(req)
        return DashboardUI.operatorPage(p, title: "Applications", active: "/operator", subtitle: "Pending business verification.", flash: DashboardFormat.flash(req),
                                        body: "<div class=\"card\">\(DashboardFormat.table(["Organization", "Category", "Handle", "Website", "Submitted"], rows, empty: "No pending applications.", caption: "Pending applications"))</div>" + queues)
    }

    private static func application(_ req: Request) async throws -> Response {
        let p = try operatorPrincipal(req)
        let id = try req.uuid("id")
        guard let business = try await BusinessRecord.find(id, on: req.db),
              let app = try await BusinessApplicationRecord.query(on: req.db).filter(\.$businessId == id).first() else { throw APIError.notFound }
        let owners = try await OrgMembershipRecord.query(on: req.db).filter(\.$businessId == id).filter(\.$role == OrgRole.owner.rawValue).all()
        let users = try await DashboardUserRecord.query(on: req.db).filter(\.$id ~~ owners.map(\.userId)).all()
        let ownerLines = users.map { u in
            "\(DashboardUI.esc(u.displayName)) · \(DashboardUI.esc((try? req.ctx.cipher.openString(u.emailCiphertext, context: "dashboard_users.email", rowId: u.id!)) ?? ""))"
        }.joined(separator: "<br>")
        var decide = ""
        if app.state == "pending" {
            decide = """
            <div class="cols"><form method="post" action="/operator/applications/\(id.uuidString.lowercased())/approve">\(DashboardUI.csrf(p))<h3>Approve</h3>\
            <label for="handle">Handle to issue (blank = as requested)</label><input id="handle" name="handle" type="text" maxlength="30" placeholder="\(DashboardUI.esc(app.requestedHandle ?? ""))">\
            <label for="anote">Note</label><textarea id="anote" name="note" maxlength="500"></textarea>\
            <p class="mu sm">Issues the handle and a permanent code and makes the business discoverable. Requires your passkey.</p><button class="btn" type="submit">Verify business</button></form>\
            <form method="post" action="/operator/applications/\(id.uuidString.lowercased())/reject">\(DashboardUI.csrf(p))<h3>Decline</h3>\
            <label for="rnote">Reason (shown to the applicant)</label><textarea id="rnote" name="note" maxlength="500"></textarea><button class="btn d" type="submit">Decline</button></form></div>
            """
        }
        let body = """
        <div class="card"><h2>\(DashboardUI.esc(business.displayName)) \(DashboardFormat.statusBadge(business.status))</h2>\
        <p class="sm">Legal name: \(DashboardUI.esc(app.legalName ?? "—")) · Category: \(DashboardUI.esc(business.category)) · Website: \(DashboardUI.esc(app.website ?? "—"))</p>\
        <p class="sm">Requested handle: \(DashboardUI.esc(app.requestedHandle.map { "@" + $0 } ?? "—"))</p><p class="sm">Owner(s):<br>\(ownerLines)</p>\
        <h3>Description</h3><p>\(DashboardUI.esc(app.detail ?? "—"))</p><p class="mu sm">Submitted \(DashboardFormat.date(app.submittedAt)) · \(DashboardUI.esc(app.state))</p>\(decide)</div>
        """
        return DashboardUI.operatorPage(p, title: "Application", active: "/operator", flash: DashboardFormat.flash(req), body: body)
    }

    private static func businesses(_ req: Request) async throws -> Response {
        let p = try operatorPrincipal(req)
        let all = try await BusinessRecord.query(on: req.db).sort(\.$createdAt, .descending).limit(200).all()
        let controls = try await BusinessControlRecord.query(on: req.db).all()
        let byId = Dictionary(controls.map { ($0.businessId, $0) }, uniquingKeysWith: { a, _ in a })
        let rows = all.map { b -> [String] in
            let c = b.id.flatMap { byId[$0] }
            var flags = ""
            if c?.throttled == true { flags += DashboardFormat.badge("Throttled", "dg") + " " }
            if let ceiling = c?.priorityCeiling { flags += DashboardFormat.badge("Cap: \(ceiling)", "mu") }
            return ["<a href=\"/operator/businesses/\(b.id?.uuidString.lowercased() ?? "")\">\(DashboardUI.esc(b.displayName))</a>", DashboardFormat.statusBadge(b.status),
                    DashboardUI.esc(b.tier), flags, DashboardFormat.date(b.createdAt)]
        }
        return DashboardUI.operatorPage(p, title: "Businesses", active: "/operator/businesses", flash: DashboardFormat.flash(req),
                                        body: "<div class=\"card\">\(DashboardFormat.table(["Business", "Status", "Tier", "Controls", "Created"], rows, caption: "Businesses"))</div>")
    }

    private static func business(_ req: Request) async throws -> Response {
        let p = try operatorPrincipal(req)
        let id = try req.uuid("id")
        guard let business = try await BusinessRecord.find(id, on: req.db) else { throw APIError.notFound }
        let controls = try await BusinessControls.load(id, on: req.db)
        let m = try await AbuseService(db: req.db, ctx: req.ctx).metrics(for: id)
        let settings = await AbuseService(db: req.db, ctx: req.ctx).thresholds()
        let tiles = """
        <div class="grid">\(DashboardFormat.stat(String(m.issued), "Interactions (window)"))\(DashboardFormat.stat(DashboardFormat.percent(m.complaintRate), "Complaint rate (limit \(DashboardFormat.percent(settings.complaintRate)))"))\
        \(DashboardFormat.stat(DashboardFormat.percent(m.optOutRate), "Opt-out rate (limit \(DashboardFormat.percent(settings.optOutRate)))"))\(DashboardFormat.stat(String(m.rateLimitHits), "Rate-limit hits"))</div>
        """
        let csrf = DashboardUI.csrf(p)
        let base = "/operator/businesses/\(id.uuidString.lowercased())"
        let ceilingOptions = ["none": "No extra cap", "high": "High", "normal": "Normal", "low": "Low"].sorted { $0.key > $1.key }.map { key, title in
            "<option value=\"\(key)\"\((controls?.priorityCeiling ?? "none") == key ? " selected" : "")>\(title)</option>"
        }.joined()
        var status = "<div class=\"card\"><h2>Status</h2><p>\(DashboardFormat.statusBadge(business.status)) · plan \(DashboardUI.esc(business.tier))"
        if let reason = controls?.suspensionReason { status += " · reason: \(DashboardUI.esc(reason))" }
        status += "</p>"
        if business.status == .verified {
            status += "<form method=\"post\" action=\"\(base)/suspend\">\(csrf)<label for=\"reason\">Reason</label><input id=\"reason\" name=\"reason\" type=\"text\" maxlength=\"300\" required><p class=\"mu sm\">Blocks the business's API keys and interactions immediately and cancels pending interactions. Requires your passkey.</p><button class=\"btn d\" type=\"submit\">Suspend</button></form>"
        } else if business.status == .suspended {
            status += "<form method=\"post\" action=\"\(base)/unsuspend\">\(csrf)<button class=\"btn\" type=\"submit\">Reinstate</button></form>"
        }
        status += "</div>"
        let controlsCard = """
        <div class="card"><h2>Trust controls</h2><p class="mu sm">Overrides only ever restrict. A ceiling caps the priority the Trust Engine would allow; it can never raise it, and the billing plan is never consulted.</p>\
        <div class="cols"><form method="post" action="\(base)/ceiling">\(csrf)<label for="ceiling">Priority ceiling</label><select id="ceiling" name="ceiling">\(ceilingOptions)</select><p><button class="btn s" type="submit">Apply</button></p></form>\
        <form method="post" action="\(base)/throttle">\(csrf)<label for="reason2">Throttle (quota and API rate × \(settings.throttleFactor))</label>\
        <input id="reason2" name="reason" type="text" maxlength="200" placeholder="Reason"><input type="hidden" name="throttled" value="\(controls?.throttled == true ? "off" : "on")">\
        <p><button class="btn s" type="submit">\(controls?.throttled == true ? "Clear throttle (currently \(DashboardUI.esc(controls?.throttleSource ?? "")))" : "Throttle")</button></p></form></div></div>
        """
        let entitlements = PolicyOperatorRoutes.summaryCard(businessId: id, snapshot: try await EntitlementService(db: req.db, ctx: req.ctx).snapshot(businessId: id))
        let ops = try await OperatorOps.businessPanel(req, p: p, business: business)
        return DashboardUI.operatorPage(p, title: business.displayName, active: "/operator/businesses", flash: DashboardFormat.flash(req), body: tiles + status + ops + entitlements + controlsCard)
    }

    private static func abuse(_ req: Request) async throws -> Response {
        let p = try operatorPrincipal(req)
        let verified = try await BusinessRecord.query(on: req.db).filter(\.$verificationStatus == VerificationStatus.verified.rawValue).limit(200).all()
        let service = AbuseService(db: req.db, ctx: req.ctx)
        var entries: [(BusinessRecord, AbuseService.Metrics, BusinessControlRecord?)] = []
        for business in verified {
            guard let id = business.id else { continue }
            entries.append((business, try await service.metrics(for: id), try await BusinessControls.load(id, on: req.db)))
        }
        entries.sort { max($0.1.complaintRate, $0.1.optOutRate) > max($1.1.complaintRate, $1.1.optOutRate) }
        let rows = entries.map { business, m, c -> [String] in
            ["<a href=\"/operator/businesses/\(business.id?.uuidString.lowercased() ?? "")\">\(DashboardUI.esc(business.displayName))</a>", String(m.issued), String(m.reports),
             DashboardFormat.percent(m.complaintRate), String(m.optOuts), DashboardFormat.percent(m.optOutRate), String(m.rateLimitHits),
             c?.throttled == true ? DashboardFormat.badge("Throttled: \(c?.throttleReason ?? "")", "dg") : DashboardFormat.badge("OK", "ok")]
        }
        let days = Int(await AbuseService(db: req.db, ctx: req.ctx).thresholds().window / 86_400)
        return DashboardUI.operatorPage(p, title: "Abuse signals", active: "/operator/abuse", subtitle: "Last \(days) days. Aggregates only.",
            body: "<div class=\"card\">\(DashboardFormat.table(["Business", "Issued", "Reports", "Complaint rate", "Opt-outs", "Opt-out rate", "Rate-limit hits", "State"], rows, caption: "Abuse signals by business"))</div>")
    }
}
