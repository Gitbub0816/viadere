import Fluent
import Foundation
import Vapor
import ViadereCore

/// Renders thrown errors as HTML inside the dashboard shell (re-authentication prompts, forbidden, validation).
struct DashboardPageErrorMiddleware: AsyncMiddleware {
    func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        let principal = { request.storage[DashboardPrincipalKey.self] }
        do {
            return try await next.respond(to: request)
        } catch let reauth as ReauthRequired {
            guard let p = principal() else { return DashboardResponses.redirect("/dashboard/login") }
            return DashboardUI.reauthPage(p, next: reauth.next, minutes: Int(request.ctx.config.dashboard.reauthWindow / 60))
        } catch let error as APIError {
            return render(error, request: request, principal: principal())
        } catch let error as any AbortError {
            return render(APIErrorMiddleware.map(error), request: request, principal: principal())
        } catch let failure as BusinessOnboarding.Failure {
            let message: String
            switch failure {
            case .handleUnavailable: message = "That handle is not available."
            case .invalidHandle: message = "That value is not valid."
            case .categoryBanned: message = BusinessOnboarding.categoryBannedMessage
            case .invalidCeiling:
                return DashboardUI.errorPage(principal(), status: .unprocessableEntity, title: "Not valid", message: "Choose low, normal, high or none. A ceiling can only lower priority.")
            default: message = "That action is not possible in the current state."
            }
            return DashboardUI.errorPage(principal(), status: .conflict, title: "Not possible", message: message)
        } catch {
            request.logger.error("dashboard error", metadata: ["type": "\(type(of: error))", "requestId": "\(request.requestID)"])
            return DashboardUI.errorPage(principal(), status: .internalServerError, title: "Something went wrong", message: "An internal error occurred. Try again.")
        }
    }

    private func render(_ error: APIError, request: Request, principal: DashboardPrincipal?) -> Response {
        var message = error.message
        if let details = error.details, !details.isEmpty { message += " (" + details.keys.sorted().joined(separator: ", ") + ")" }
        let title: String
        switch error.status {
        case .forbidden: title = "Not allowed"
        case .notFound: title = "Not found"
        case .tooManyRequests: title = "Slow down"
        default: title = "Could not complete that"
        }
        let response = DashboardUI.errorPage(principal, status: error.status, title: title, message: message)
        for (name, value) in error.headers { response.headers.replaceOrAdd(name: name, value: value) }
        return response
    }
}

// MARK: - Forms

private struct CampaignForm: Content {
    var campaign: String
    var action: String?
    var days: Int?
}

private struct InviteForm: Content {
    var email: String
    var role: String
}

private struct RoleForm: Content { var role: String }
private struct VerifyForm: Content {
    var email: String
    var code: String
}
private struct ResendForm: Content { var email: String }
private struct SwitchForm: Content { var businessId: String }
private struct ApplicationForm: Content {
    var legalName: String?
    var website: String?
    var requestedHandle: String?
    var description: String?
}

enum DashboardRoutes {
    static func register(_ app: Application) {
        let routes = app.routes
        let authLimiter = IPRateLimitMiddleware(name: "dashboard-auth") { $0.rateLimits.dashboardAuth }
        let webLimiter = IPRateLimitMiddleware(name: "web") { $0.rateLimits.directory }

        // MARK: Public pages and ceremonies
        let pub = routes.grouped(webLimiter)
        pub.get("dashboard", "login") { req -> Response in
            if let token = req.requireCookie(.business),
               try await DashboardSessionStore(db: req.db, ctx: req.ctx).authenticate(token: token, realm: .business) != nil {
                return DashboardResponses.redirect("/dashboard")
            }
            return DashboardUI.authPage(title: "Sign in", body: """
            <h1>Sign in</h1><p class="mu">Use your passkey to open your organization's dashboard.</p>\
            <form data-passkey="login" data-begin="/dashboard/auth/login/begin" data-finish="/dashboard/auth/login/finish" data-next="/dashboard">\
            <button class="btn" type="submit">Sign in with passkey</button></form><p id="pk-msg" class="sm err" role="alert"></p>\
            <p class="mu sm">New to Viadere? <a href="/dashboard/signup">Create an organization</a>.</p>
            """)
        }
        pub.get("dashboard", "signup") { req -> Response in
            let categories = DashboardAuthService.categories.map { "<option value=\"\($0)\">\(DashboardUI.esc($0.replacingOccurrences(of: "_", with: " ").capitalized))</option>" }.joined()
            return DashboardUI.authPage(title: "Create an organization", body: """
            <h1>Create an organization</h1><p class="mu">Apply to join Viadere as a verified business. A Viadere reviewer checks every application; \
            your handle and code are issued only after approval.</p>\
            <form data-passkey="register" data-begin="/dashboard/auth/signup/begin" data-finish="/dashboard/auth/signup/finish" data-next="/dashboard/verify">\
            <label for="displayName">Your name</label><input id="displayName" name="displayName" type="text" maxlength="64" required autocomplete="name">\
            <label for="email">Work email</label><input id="email" name="email" type="email" maxlength="254" required autocomplete="email">\
            <label for="organizationName">Organization name</label><input id="organizationName" name="organizationName" type="text" minlength="2" maxlength="80" required>\
            <label for="legalName">Legal name (optional)</label><input id="legalName" name="legalName" type="text" maxlength="120">\
            <label for="category">Category</label><select id="category" name="category">\(categories)</select>\
            <label for="website">Website (https)</label><input id="website" name="website" type="url" maxlength="200" placeholder="https://">\
            <label for="requestedHandle">Requested handle (optional)</label><input id="requestedHandle" name="requestedHandle" type="text" maxlength="30" placeholder="yourbrand">\
            <label for="description">What will you use Viadere for?</label><textarea id="description" name="description" maxlength="500"></textarea>\
            <p class="mu sm">You'll create a passkey to sign in. There are no passwords. We'll then email a 6-digit code to confirm your address; your application starts once you enter it.</p>\
            <p><button class="btn" type="submit">Create passkey and apply</button></p></form><p id="pk-msg" class="sm err" role="alert"></p>\
            <p class="mu sm">Already have an account? <a href="/dashboard/login">Sign in</a>.</p>
            """)
        }
        pub.get("dashboard", "invite", ":token") { req in try await invitePage(req, token: req.parameters.get("token") ?? "") }
        pub.get("dashboard", "verify") { _ in verifyPage() }

        let ceremonies = routes.grouped(authLimiter)
        @Sendable func sessionResponse(_ created: DashboardSessionStore.Created, req: Request, realm: DashboardRealm) async throws -> Response {
            // Record where the sign-in came from and warn the person (and the organization's security contacts) if it is new.
            if let user = try await DashboardUserRecord.find(created.record.userId, on: req.db) {
                await SessionSecurity(db: req.db, ctx: req.ctx).recordSignIn(session: created.record, user: user, client: ClientContext(req), realm: realm)
            }
            let response = DashboardResponses.json(["redirect": realm.home])
            response.cookies[realm.cookieName] = DashboardSessionStore(db: req.db, ctx: req.ctx).cookie(for: created, realm: realm)
            return response
        }
        let businessSignup = ceremonies.grouped(SignupGateMiddleware(flag: .signupBusiness))
        let inviteCeremonies = ceremonies.grouped(SignupGateMiddleware(flag: .inviteDashboard))
        businessSignup.post("dashboard", "auth", "signup", "begin") { req in
            let body: SignupBeginBody = try req.decodeBody()
            let ip = ClientIP.resolve(req, trustedProxies: req.ctx.config.trustedProxyCount)
            return try req.jsonResponse(try await DashboardAuthService(db: req.db, ctx: req.ctx).signupBegin(body, ip: ip))
        }
        businessSignup.post("dashboard", "auth", "signup", "finish") { req in
            let body: PasskeyRegistrationFinishRequest = try req.decodeBody()
            // No session yet: the account is unverified until the emailed code is entered.
            try await DashboardAuthService(db: req.db, ctx: req.ctx).signupFinish(body, previousCookie: req.requireCookie(.business))
            return DashboardResponses.json(["redirect": "/dashboard/verify"])
        }
        ceremonies.post("dashboard", "verify") { req -> Response in
            let form = try req.content.decode(VerifyForm.self)
            let ip = ClientIP.resolve(req, trustedProxies: req.ctx.config.trustedProxyCount)
            do {
                try await DashboardAuthService(db: req.db, ctx: req.ctx).verifyEmail(VerifyEmailBody(email: form.email, code: form.code), ip: ip)
            } catch let error as APIError {
                return verifyPage(notice: error.message, status: error.status, error: true, headers: error.headers)
            }
            return DashboardUI.authPage(title: "Email verified", body: """
            <h1>Email verified</h1><p>Your application has been submitted for review. Sign in with the passkey you just created to see its status.</p>\
            <p><a class="btn" href="/dashboard/login">Sign in</a></p>
            """, script: false)
        }
        ceremonies.post("dashboard", "verify", "resend") { req -> Response in
            let form = try req.content.decode(ResendForm.self)
            let ip = ClientIP.resolve(req, trustedProxies: req.ctx.config.trustedProxyCount)
            do {
                try await DashboardAuthService(db: req.db, ctx: req.ctx).resendSignupCode(email: form.email, ip: ip)
            } catch let error as APIError {
                return verifyPage(notice: error.message, status: error.status, error: true, headers: error.headers)
            }
            return verifyPage(notice: "If that address has a sign-up waiting, we've sent a new code. It expires in 15 minutes.")
        }
        ceremonies.post("dashboard", "invite", ":token", "code") { req -> Response in
            let token = req.parameters.get("token") ?? ""
            let ip = ClientIP.resolve(req, trustedProxies: req.ctx.config.trustedProxyCount)
            do {
                try await DashboardAuthService(db: req.db, ctx: req.ctx).sendInviteCode(token: token, ip: ip)
            } catch let error as APIError where error.status == .tooManyRequests {
                return try await invitePage(req, token: token, notice: error.message, error: true, status: error.status, headers: error.headers)
            }
            return try await invitePage(req, token: token, notice: "We've emailed a 6-digit code to the invited address. It expires in 15 minutes.")
        }
        ceremonies.post("dashboard", "auth", "login", "begin") { req in
            try req.jsonResponse(try await DashboardAuthService(db: req.db, ctx: req.ctx).loginBegin(realm: .business))
        }
        ceremonies.post("dashboard", "auth", "login", "finish") { req in
            let body: PasskeyLoginFinishRequest = try req.decodeBody()
            let created = try await DashboardAuthService(db: req.db, ctx: req.ctx).loginFinish(realm: .business, body, previousCookie: req.requireCookie(.business))
            return try await sessionResponse(created, req: req, realm: .business)
        }
        inviteCeremonies.post("dashboard", "auth", "invite", "begin") { req in
            let body: InviteBeginBody = try req.decodeBody()
            return try req.jsonResponse(try await DashboardAuthService(db: req.db, ctx: req.ctx).inviteBegin(body))
        }
        inviteCeremonies.post("dashboard", "auth", "invite", "finish") { req in
            let body: PasskeyRegistrationFinishRequest = try req.decodeBody()
            let created = try await DashboardAuthService(db: req.db, ctx: req.ctx).inviteFinish(body, previousCookie: req.requireCookie(.business))
            return try await sessionResponse(created, req: req, realm: .business)
        }

        // MARK: Authenticated JSON (re-authentication)
        let json = routes.grouped(DashboardAuthMiddleware(realm: .business, json: true))
        json.post("dashboard", "auth", "reauth", "begin") { req in
            try req.jsonResponse(try await DashboardAuthService(db: req.db, ctx: req.ctx).reauthBegin(try req.dashboard))
        }
        json.post("dashboard", "auth", "reauth", "finish") { req in
            let body: PasskeyLoginFinishRequest = try req.decodeBody()
            try await DashboardAuthService(db: req.db, ctx: req.ctx).reauthFinish(try req.dashboard, body)
            return try req.emptyOK()
        }

        // MARK: Authenticated pages
        let pages = routes.grouped(DashboardPageErrorMiddleware()).grouped(DashboardAuthMiddleware(realm: .business))

        pages.post("dashboard", "logout") { req -> Response in
            let p = try req.dashboard
            try await DashboardSessionStore(db: req.db, ctx: req.ctx).revoke(token: p.sessionToken)
            let response = DashboardResponses.redirect("/dashboard/login")
            response.cookies[DashboardRealm.business.cookieName] = DashboardSessionStore.clearingCookie(realm: .business)
            return response
        }

        pages.get("dashboard") { req in try await overview(req) }
        pages.get("dashboard", "templates") { req in try await templatesPage(req) }
        pages.get("dashboard", "campaigns") { req in try await campaignsPage(req) }
        pages.post("dashboard", "campaigns") { req in try await createCampaign(req) }
        pages.post("dashboard", "campaigns", "download") { req in try await downloadCampaign(req) }
        pages.get("dashboard", "consent") { req in try await consentPage(req) }
        pages.get("dashboard", "audit") { req in try await auditPage(req) }
        pages.get("dashboard", "team") { req in try await teamPage(req) }
        let inviteGate = pages.grouped(SignupGateMiddleware(flag: .inviteDashboard))
        inviteGate.post("dashboard", "team", "invite") { req in try await invite(req) }
        pages.post("dashboard", "team", "invites", ":id", "revoke") { req -> Response in
            let (p, _) = try req.businessDashboard
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).revokeInvite(id: try req.uuid("id"))
            return DashboardResponses.redirect("/dashboard/team?m=invite-revoked")
        }
        pages.post("dashboard", "team", "members", ":id", "role") { req -> Response in
            let (p, _) = try req.businessDashboard
            let form = try req.content.decode(RoleForm.self)
            guard let role = OrgRole.parse(form.role) else { throw APIError.validation("Choose a valid role.") }
            let change = try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).changeRole(membershipId: try req.uuid("id"), to: role)
            if case .awaitingApproval = change { return DashboardResponses.redirect("/dashboard/team?m=pending") }
            return DashboardResponses.redirect("/dashboard/team?m=role")
        }
        pages.post("dashboard", "team", "members", ":id", "remove") { req -> Response in
            let (p, _) = try req.businessDashboard
            let change = try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).removeMember(membershipId: try req.uuid("id"))
            if case .awaitingApproval = change { return DashboardResponses.redirect("/dashboard/team?m=pending") }
            return DashboardResponses.redirect("/dashboard/team?m=removed")
        }
        inviteGate.post("dashboard", "invite", ":token", "accept") { req -> Response in
            let p = try req.dashboard
            let token = req.parameters.get("token") ?? ""
            let businessId = try await DashboardActions.acceptInvite(token: token, principal: p, db: req.db, ctx: req.ctx)
            try await DashboardActions.switchOrganization(to: businessId, principal: p, db: req.db)
            return DashboardResponses.redirect("/dashboard?m=joined")
        }
        pages.post("dashboard", "switch") { req -> Response in
            let p = try req.dashboard
            let form = try req.content.decode(SwitchForm.self)
            guard let id = UUID(uuidString: form.businessId) else { throw APIError.forbidden }
            try await DashboardActions.switchOrganization(to: id, principal: p, db: req.db)
            return DashboardResponses.redirect("/dashboard?m=switched")
        }
        pages.get("dashboard", "billing") { req in try await billingPage(req) }
        ConsoleRoutes.register(pages)
        pages.post("dashboard", "organization") { req -> Response in
            let (p, _) = try req.businessDashboard
            let form = try req.content.decode(ApplicationForm.self)
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).resubmit(
                legalName: form.legalName, website: form.website, requestedHandle: form.requestedHandle, description: form.description)
            return DashboardResponses.redirect("/dashboard/organization?m=applied")
        }
    }

    // MARK: Email verification and invitation pages

    /// The sign-up verification page (public). `notice` is a fixed server message, escaped anyway.
    static func verifyPage(notice: String? = nil, status: HTTPStatus = .ok, error: Bool = false, headers: [String: String] = [:]) -> Response {
        let note = notice.map { "<p class=\"sm\(error ? " err" : "")\" role=\"\(error ? "alert" : "status")\">\(DashboardUI.esc($0))</p>" } ?? ""
        let response = DashboardUI.authPage(title: "Verify your email", body: """
        <h1>Check your email</h1><p class="mu">Enter the 6-digit code we sent to the address you signed up with. Until you do, your account is not active.</p>\(note)\
        <form method="post" action="/dashboard/verify"><label for="email">Email</label><input id="email" name="email" type="email" maxlength="254" required autocomplete="email">\
        <label for="code">Code</label><input id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{6,7}" maxlength="7" required>\
        <p><button class="btn" type="submit">Verify</button></p></form>\
        <form method="post" action="/dashboard/verify/resend"><label for="remail">No code? Send a new one to</label><input id="remail" name="email" type="email" maxlength="254" required>\
        <p><button class="btn s" type="submit">Send a new code</button></p></form>
        """, script: false, status: status)
        for (name, value) in headers { response.headers.replaceOrAdd(name: name, value: value) }
        return response
    }

    /// The invitation landing page. A new person is asked for a name and the emailed code; an existing verified account signs in to accept.
    static func invitePage(_ req: Request, token: String, notice: String? = nil, error: Bool = false, status: HTTPStatus = .ok,
                           headers: [String: String] = [:]) async throws -> Response {
        let ctx = req.ctx
        guard let invite = try await DashboardAuthService(db: req.db, ctx: ctx).openInvite(token: token),
              let business = try await BusinessRecord.find(invite.businessId, on: req.db) else {
            return DashboardUI.authPage(title: "Invitation", body: "<h1>Invitation not valid</h1><p>This invitation has expired or was already used. Ask your admin for a new one.</p>", script: false, status: .gone)
        }
        let role = OrgRole(rawValue: invite.role)?.title ?? "Member"
        let note = notice.map { "<p class=\"sm\(error ? " err" : "")\" role=\"\(error ? "alert" : "status")\">\(DashboardUI.esc($0))</p>" } ?? ""
        // An unverified sign-up for the address does not count: it never blocks the invitee.
        let existing = try await DashboardUserRecord.query(on: req.db).filter(\.$emailHash == invite.emailHash).filter(\.$status != "unverified").count() > 0
        let response: Response
        if existing {
            // Existing account: sign in first, then accept with the signed-in session.
            var accept = ""
            if let cookie = req.requireCookie(.business), let session = try await DashboardSessionStore(db: req.db, ctx: ctx).authenticate(token: cookie, realm: .business),
               let user = try await DashboardUserRecord.find(session.userId, on: req.db), ConstantTime.equals(user.emailHash, invite.emailHash) {
                let csrf = DashboardSessionStore.csrfToken(sessionToken: cookie, hasher: ctx.hasher)
                accept = "<form method=\"post\" action=\"/dashboard/invite/\(DashboardUI.esc(token))/accept\"><input type=\"hidden\" name=\"_csrf\" value=\"\(DashboardUI.esc(csrf))\"><button class=\"btn\" type=\"submit\">Accept invitation</button></form>"
            } else {
                accept = "<p><a class=\"btn\" href=\"/dashboard/login\">Sign in to accept</a></p>"
            }
            response = DashboardUI.authPage(title: "Invitation", body: "<h1>Join \(DashboardUI.esc(business.displayName))</h1><p>You've been invited as <strong>\(DashboardUI.esc(role))</strong>. You already have a Viadere account, so sign in to accept.</p>\(accept)", script: false, status: status)
        } else {
            response = DashboardUI.authPage(title: "Invitation", body: """
            <h1>Join \(DashboardUI.esc(business.displayName))</h1><p class="mu">You've been invited as <strong>\(DashboardUI.esc(role))</strong>. Confirm your email with a code, then create a passkey to sign in.</p>\(note)\
            <form method="post" action="/dashboard/invite/\(DashboardUI.esc(token))/code"><p><button class="btn s" type="submit">Email me a code</button></p></form>\
            <form data-passkey="register" data-begin="/dashboard/auth/invite/begin" data-finish="/dashboard/auth/invite/finish" data-next="/dashboard">\
            <input type="hidden" name="token" value="\(DashboardUI.esc(token))">\
            <label for="displayName">Your name</label><input id="displayName" name="displayName" type="text" maxlength="64" required autocomplete="name">\
            <label for="code">Code from the email</label><input id="code" name="code" type="text" inputmode="numeric" autocomplete="one-time-code" maxlength="7" required>\
            <p><button class="btn" type="submit">Create passkey and join</button></p></form><p id="pk-msg" class="sm err" role="alert"></p>
            """, status: status)
        }
        for (name, value) in headers { response.headers.replaceOrAdd(name: name, value: value) }
        return response
    }

    // MARK: Overview

    private static func overview(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewOverview)
        let days = req.query[Int.self, at: "days"] ?? 30
        let o = try await DashboardAnalytics(db: req.db, ctx: req.ctx).overview(businessId: businessId, days: days)
        let periods = [7, 30, 90].map { "<a class=\"btn sm \($0 == o.days ? "" : "s")\" href=\"/dashboard?days=\($0)\">\($0) days</a>" }.joined()
        let tiles = """
        <div class="grid">\(DashboardFormat.stat(String(o.totalIssued), "Interactions issued"))\(DashboardFormat.stat(String(o.totalDecided), "Decided"))\
        \(DashboardFormat.stat(DashboardFormat.duration(o.medianLatency), "Median decision time"))\
        \(DashboardFormat.stat(DashboardFormat.duration(o.p90Latency), "90th percentile"))</div>
        <div class="grid">\(DashboardFormat.stat(DashboardFormat.percent(o.webhookSuccessRate), "Webhook delivery success"))\
        \(DashboardFormat.stat(DashboardFormat.percent(o.channelSuccessRate), "SMS / RCS delivery success"))\
        \(DashboardFormat.stat(String(o.optOuts), "Opt-outs (revocations and disconnects)"))\
        \(DashboardFormat.stat(String(o.reports), "\"Not me\" reports"))</div>
        """
        let chart = "<div class=\"card\"><h2>Interactions per day</h2>\(DashboardFormat.barChart(o.daily, label: "Interactions issued per day"))</div>"
        let rows = zip(o.issuedByKind, o.decidedByKind).map { issued, decided in
            [DashboardUI.esc(issued.kind), String(issued.count), String(decided.count),
             issued.count == 0 ? "—" : DashboardFormat.percent(Double(decided.count) / Double(issued.count))]
        }
        let byKind = "<div class=\"card\"><h2>By kind</h2>\(DashboardFormat.table(["Kind", "Issued", "Decided", "Decision rate"], rows, caption: "Interactions by kind"))</div>"
        let verifyCard = try await VerifyDashboard.card(db: req.db, ctx: req.ctx, businessId: businessId, days: o.days)
        let note = "<p class=\"mu sm\">Live traffic only, aggregated. Viadere never shows individual customers here, and a customer's phone number or messages never appear in analytics.</p>"
        return DashboardUI.businessPage(p, title: "Overview", active: "/dashboard", subtitle: "The last \(o.days) days", actions: periods,
                                        flash: DashboardFormat.flash(req), body: tiles + chart + byKind + verifyCard + note)
    }

    // MARK: Templates

    private static func templatesPage(_ req: Request) async throws -> Response {
        let (p, _) = try req.businessDashboard
        try p.require(.viewTemplates)
        let cards = InteractionTemplates.all(now: req.ctx.now).map { t in
            """
            <div class="card"><h2>\(DashboardUI.esc(t.title))</h2><p class="mu">\(DashboardUI.esc(t.summary))</p>\
            <p class="sm"><span class="badge">\(DashboardUI.esc(t.method))</span> <code>\(DashboardUI.esc(t.path))</code></p><pre>\(DashboardUI.esc(t.json))</pre></div>
            """
        }.joined()
        let intro = "<p class=\"mu\">Replace the placeholder <code>relationshipId</code> with a connected customer's. Every request needs an <code>Idempotency-Key</code> header equal to the body's <code>idempotencyKey</code>. Security kinds are only ever approved on the customer's device — never by text.</p>"
        return DashboardUI.businessPage(p, title: "Templates", active: "/dashboard/templates", subtitle: "Copy a request for the most common interactions.", body: intro + cards)
    }

    // MARK: Campaigns

    private static func campaignForm(_ p: DashboardPrincipal, verified: Bool) -> String {
        guard verified else { return "<div class=\"notice\">Campaign links and QR codes are available after Viadere verifies your organization.</div>" }
        return """
        <div class="card"><h2>Create a link</h2><form method="post" action="/dashboard/campaigns">\(DashboardUI.csrf(p))\
        <div class="cols"><div><label for="campaign">Campaign</label><input id="campaign" name="campaign" type="text" maxlength="64" required placeholder="spring-flyer"></div>\
        <div><label for="action">Action (optional)</label><input id="action" name="action" type="text" maxlength="64" placeholder="enroll_rewards"></div>\
        <div><label for="days">Valid for</label><select id="days" name="days"><option value="90">90 days</option><option value="30">30 days</option><option value="365">1 year</option><option value="0">No expiry</option></select></div></div>\
        <p class="mu sm">The link carries your permanent code plus a signed campaign context. It never contains customer data. The QR code is generated here; nothing is sent to a third party.</p>\
        <button class="btn" type="submit">Generate link and QR</button></form></div>
        """
    }

    private static func campaignsPage(_ req: Request) async throws -> Response {
        let (p, _) = try req.businessDashboard
        try p.require(.manageCampaigns)
        return DashboardUI.businessPage(p, title: "Campaigns", active: "/dashboard/campaigns", subtitle: "Links and QR codes that open Viadere to your business.",
                                        flash: DashboardFormat.flash(req), body: campaignForm(p, verified: p.business?.isVerified == true))
    }

    private static func createCampaign(_ req: Request) async throws -> Response {
        let (p, _) = try req.businessDashboard
        let form = try req.content.decode(CampaignForm.self)
        let result = try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).campaign(name: form.campaign, action: form.action, validDays: form.days ?? 90)
        let svg = result.qr.svg(title: "QR code for your Viadere connect link")
        let expires = result.expiresAt.map { "Expires \(DashboardFormat.date($0))." } ?? "No expiry."
        let body = """
        <div class="card"><h2>Your campaign link</h2><div class="cols"><div><div class="qr">\(svg)</div></div><div>\
        <h3>Link with signed context</h3><pre>\(DashboardUI.esc(result.link.urlString))</pre><p class="mu sm">\(expires) If the context expires or is invalid, the plain code still works.</p>\
        <h3>Plain link</h3><pre>\(DashboardUI.esc(result.plainLink.urlString))</pre>\
        <form method="post" action="/dashboard/campaigns/download">\(DashboardUI.csrf(p))<input type="hidden" name="campaign" value="\(DashboardUI.esc(form.campaign))">\
        <input type="hidden" name="action" value="\(DashboardUI.esc(form.action ?? ""))"><input type="hidden" name="days" value="\(form.days ?? 90)">\
        <button class="btn s" type="submit">Download SVG</button></form></div></div></div>
        """ + campaignForm(p, verified: true)
        return DashboardUI.businessPage(p, title: "Campaigns", active: "/dashboard/campaigns", body: body)
    }

    private static func downloadCampaign(_ req: Request) async throws -> Response {
        let (p, _) = try req.businessDashboard
        let form = try req.content.decode(CampaignForm.self)
        let result = try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).campaign(name: form.campaign, action: form.action, validDays: form.days ?? 90)
        let response = Response(status: .ok, body: .init(string: result.qr.svg(title: "Viadere connect link")))
        response.headers.contentType = HTTPMediaType(type: "image", subType: "svg+xml")
        response.headers.replaceOrAdd(name: .contentDisposition, value: "attachment; filename=\"viadere-connect-\(result.plainLink.code.canonical).svg\"")
        response.headers.replaceOrAdd(name: "Content-Security-Policy", value: "default-src 'none'; style-src 'none'; sandbox")
        return response
    }

    // MARK: Consent

    private static func consentPage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewConsent)
        let status = try await DashboardAnalytics(db: req.db, ctx: req.ctx).consentStatus(businessId: businessId)
        let rows = status.rows.map { [DashboardUI.esc($0.purpose.rawValue), String($0.granted), String($0.notGranted)] }
        let body = """
        <div class="grid">\(DashboardFormat.stat(String(status.active), "Connected customers"))\(DashboardFormat.stat(String(status.disconnected), "Disconnected"))</div>\
        <div class="card"><h2>Consent by purpose</h2>\(DashboardFormat.table(["Purpose", "Granted", "Not granted"], rows, caption: "Consent by purpose"))\
        <p class="mu sm">Counts of current relationships only. Customers control these; marketing and rewards are off until a customer opts in, and security and account-service messages can't be turned off while connected. Individual customers are not shown.</p></div>
        """
        return DashboardUI.businessPage(p, title: "Consent", active: "/dashboard/consent", subtitle: "Where your customers stand, in aggregate.", body: body)
    }

    // MARK: Audit

    private static func auditPage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewAudit)
        let page = max(0, req.query[Int.self, at: "page"] ?? 0)
        let size = 50
        let events = try await AuditEventRecord.query(on: req.db).filter(\.$businessId == businessId).sort(\.$seq, .descending)
            .offset(page * size).limit(size + 1).all()
        let members = try await OrgMembershipRecord.query(on: req.db).filter(\.$businessId == businessId).all()
        let users = try await DashboardUserRecord.query(on: req.db).filter(\.$id ~~ members.map(\.userId)).all()
        let names = Dictionary(users.compactMap { u in u.id.map { ($0.uuidString.lowercased(), u.displayName) } }, uniquingKeysWith: { a, _ in a })
        // The one business-facing projection: consumer actors are this business's subject_ref, Verify events carry no oracle.
        let projection = BusinessAuditProjection(ctx: req.ctx)
        let rows = events.prefix(size).compactMap { projection.project($0) }.map { e -> [String] in
            let actor = e.actorId.flatMap { names[$0] } ?? (e.actorKind == AuditActor.Kind.consumer.rawValue ? (e.actorId ?? "customer") : (e.actorId.map { "…" + $0.suffix(6) } ?? ""))
            let metaText = e.metadata.keys.sorted().map { "\($0)=\(e.metadata[$0] ?? "")" }.joined(separator: " ")
            return [DashboardFormat.date(e.occurredAt), "<code>\(DashboardUI.esc(e.action))</code>",
                    DashboardFormat.badge(e.outcome, e.outcome == "success" ? "ok" : "dg"), "\(DashboardUI.esc(e.actorKind)) \(DashboardUI.esc(actor))",
                    DashboardUI.esc([e.subjectType, e.subjectId.map { "…" + $0.suffix(6) }].compactMap { $0 }.joined(separator: " ")), "<span class=\"mu sm\">\(DashboardUI.esc(metaText))</span>"]
        }
        var pager = "<div class=\"row\">"
        if page > 0 { pager += "<a class=\"btn s sm\" href=\"/dashboard/audit?page=\(page - 1)\">Newer</a>" }
        if events.count > size { pager += "<a class=\"btn s sm\" href=\"/dashboard/audit?page=\(page + 1)\">Older</a>" }
        pager += "</div>"
        let body = "<div class=\"card\">\(DashboardFormat.table(["When", "Action", "Outcome", "Actor", "Subject", "Details"], Array(rows), empty: "No events yet.", caption: "Audit log"))\(pager)</div><p class=\"mu sm\">Append-only and hash-chained. Secrets and message content are never recorded.</p>"
        return DashboardUI.businessPage(p, title: "Audit log", active: "/dashboard/audit", subtitle: "Everything that happened in your organization.", body: body)
    }

    // MARK: Team

    private static func teamPage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewTeam)
        let members = try await OrgMembershipRecord.query(on: req.db).filter(\.$businessId == businessId).filter(\.$removedAt == nil)
            .sort(\.$createdAt, .ascending).all()
        let users = try await DashboardUserRecord.query(on: req.db).filter(\.$id ~~ members.map(\.userId)).all()
        let byId = Dictionary(users.compactMap { u in u.id.map { ($0, u) } }, uniquingKeysWith: { a, _ in a })
        let ctx = req.ctx
        let canManage = p.can(.manageTeam)
        let assignable = OrgRole.allCases.sorted(by: >).filter { p.role?.grantableRoles.contains($0) == true }
        let memberRows = members.map { m -> [String] in
            let user = byId[m.userId]
            let email = user.flatMap { try? ctx.cipher.openString($0.emailCiphertext, context: "dashboard_users.email", rowId: $0.id!) } ?? ""
            let isSelf = m.userId == p.user.id
            var role = DashboardFormat.badge(OrgRole(rawValue: m.role)?.title ?? m.role)
            var actions = ""
            let touchable = canManage && !isSelf && (OrgRole(rawValue: m.role).map { p.role?.grantableRoles.contains($0) == true } ?? false)
            if touchable, let id = m.id?.uuidString.lowercased() {
                let options = assignable.map { "<option value=\"\($0.rawValue)\"\($0.rawValue == m.role ? " selected" : "")>\($0.title)</option>" }.joined()
                role = "<form method=\"post\" action=\"/dashboard/team/members/\(id)/role\" class=\"row\">\(DashboardUI.csrf(p))<select name=\"role\" aria-label=\"Role\">\(options)</select><button class=\"btn s sm\" type=\"submit\">Save</button></form>"
                actions = "<form method=\"post\" action=\"/dashboard/team/members/\(id)/remove\">\(DashboardUI.csrf(p))<button class=\"btn d sm\" type=\"submit\">Remove</button></form>"
            }
            return ["\(DashboardUI.esc(user?.displayName ?? "—"))\(isSelf ? " <span class=\"mu\">(you)</span>" : "")", DashboardUI.esc(email), role, DashboardFormat.date(m.createdAt), actions]
        }
        let invites = try await OrgInviteRecord.query(on: req.db).filter(\.$businessId == businessId).filter(\.$state == "open")
            .filter(\.$expiresAt > ctx.now).sort(\.$createdAt, .descending).all()
        let inviteRows = invites.map { i -> [String] in
            let email = (try? ctx.cipher.openString(i.emailCiphertext, context: "org_invites.email", rowId: i.id!)) ?? ""
            var action = ""
            if canManage, let id = i.id?.uuidString.lowercased() {
                action = "<form method=\"post\" action=\"/dashboard/team/invites/\(id)/revoke\">\(DashboardUI.csrf(p))<button class=\"btn d sm\" type=\"submit\">Revoke</button></form>"
            }
            return [DashboardUI.esc(email), DashboardFormat.badge(OrgRole(rawValue: i.role)?.title ?? i.role), DashboardFormat.date(i.expiresAt), action]
        }
        var form = ""
        if canManage {
            let options = assignable.map { "<option value=\"\($0.rawValue)\"\($0 == .developer ? " selected" : "")>\($0.title) — \(DashboardUI.esc($0.summary))</option>" }.joined()
            form = """
            <div class="card"><h2>Invite a teammate</h2><form method="post" action="/dashboard/team/invite">\(DashboardUI.csrf(p))\
            <div class="cols"><div><label for="email">Email</label><input id="email" name="email" type="email" required maxlength="254"></div>\
            <div><label for="role">Role</label><select id="role" name="role">\(options)</select></div></div>\
            <p class="mu sm">We email a single-use link to this address, and the person confirms a code we email them as well. Adding an owner needs your passkey.</p>\
            <button class="btn" type="submit">Send invitation</button></form></div>
            """
        }
        let roles = OrgRole.allCases.sorted(by: >).map { "<tr><th scope=\"row\">\($0.title)</th><td>\(DashboardUI.esc($0.summary))</td></tr>" }.joined()
        let body = form + "<div class=\"card\"><h2>Members</h2>\(DashboardFormat.table(["Name", "Email", "Role", "Joined", ""], memberRows, caption: "Team members"))</div>"
            + "<div class=\"card\"><h2>Pending invitations</h2>\(DashboardFormat.table(["Email", "Role", "Expires", ""], inviteRows, empty: "None.", caption: "Pending invitations"))</div>"
            + "<div class=\"card\"><h2>Roles</h2><div class=\"tw\"><table><caption class=\"vh\">Roles and what they can do</caption><tbody>\(roles)</tbody></table></div></div>"
        return DashboardUI.businessPage(p, title: "Team", active: "/dashboard/team", subtitle: "Everyone signs in with their own passkey.", flash: DashboardFormat.flash(req), body: body)
    }

    private static func invite(_ req: Request) async throws -> Response {
        let (p, _) = try req.businessDashboard
        let form = try req.content.decode(InviteForm.self)
        guard let role = OrgRole.parse(form.role) else { throw APIError.validation("Choose a valid role.") }
        let change = try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).invite(email: form.email, role: role)
        if case .awaitingApproval = change { return DashboardResponses.redirect("/dashboard/team?m=pending") }
        let body = """
        <div class="card"><h2>Invitation sent</h2><p>We emailed a single-use link to the address you entered. It expires in \(Int(req.ctx.config.dashboard.inviteTTL / 86_400)) days. \
        To join, your teammate opens it and confirms a code that we email to the same address.</p><p><a class="btn s" href="/dashboard/team">Done</a></p></div>
        """
        return DashboardUI.businessPage(p, title: "Invitation", active: "/dashboard/team", body: body)
    }

    // MARK: Billing

    private static func billingPage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewBilling)
        let usage = try await DashboardAnalytics(db: req.db, ctx: req.ctx).usage(businessId: businessId)
        let invoice = usage.invoice
        func lines(_ items: [InvoicePreview.Line]) -> [[String]] {
            items.map { [DashboardUI.esc($0.title) + ($0.note.map { "<br><span class=\"mu sm\">\(DashboardUI.esc($0))</span>" } ?? ""), String($0.quantity),
                         InvoicePreview.format(micros: $0.unitMicros), InvoicePreview.format(micros: $0.totalMicros)] }
        }
        let tier = p.business?.tier ?? "free"
        let tiles = "<div class=\"grid\">\(DashboardFormat.stat(String(usage.totals.interactions), "Interactions this month"))\(DashboardFormat.stat(String(usage.totals.smsSegments), "SMS segments"))\(DashboardFormat.stat(String(usage.totals.rcsMessages), "RCS messages"))\(DashboardFormat.stat(tier.capitalized, "Plan"))</div>"
        let body = tiles + """
        <div class="card"><h2>Platform fees</h2>\(DashboardFormat.table(["Item", "Quantity", "Unit", "Amount"], lines(invoice.platform), caption: "Platform fees"))\
        <p><strong>Platform subtotal: \(InvoicePreview.format(micros: invoice.platformTotalMicros))</strong></p></div>\
        <div class="card"><h2>Transport (carrier and provider pass-through)</h2>\(DashboardFormat.table(["Item", "Quantity", "Unit", "Amount"], lines(invoice.transport), caption: "Transport pass-through"))\
        <p><strong>Transport subtotal: \(InvoicePreview.format(micros: invoice.transportTotalMicros))</strong></p></div>\
        <div class="card"><h2>Preview total</h2><p class="stat"><span class="n">\(InvoicePreview.format(micros: invoice.totalMicros))</span></p>\
        <p class="mu sm">\(DashboardFormat.date(invoice.periodStart)) – \(DashboardFormat.date(invoice.periodEnd)). This is a usage preview, not an invoice: no payment processor is connected, rates are configurable and final pricing is not yet set. Your plan affects quotas only — it never changes the priority of your messages or bypasses a customer's consent.</p></div>
        """
        return DashboardUI.businessPage(p, title: "Billing and usage", active: "/dashboard/billing", subtitle: "Metered usage and an invoice preview for this month.", body: body)
    }
}
