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
        let fields = (error.details ?? [:]).keys.sorted().map(Self.humanize)
        let title: String
        switch error.status {
        case .forbidden: title = "Not allowed"
        case .notFound: title = "Not found"
        case .tooManyRequests: title = "Slow down"
        default: title = "Could not complete that"
        }
        // A failed form submission offers a way back to the form it came from (a same-console path from the Referer, never another site).
        var back: String?
        if let p = principal, request.method == .POST, ![.forbidden, .notFound].contains(error.status) {
            back = ConsoleUI.backPath(referer: request.headers.first(name: .referer), allowedOrigins: DashboardCSRF.allowedOrigins(request.ctx), prefix: p.realm.home)
        }
        let response = DashboardUI.errorPage(principal, status: error.status, title: title, message: error.message, fields: fields, back: back)
        for (name, value) in error.headers { response.headers.replaceOrAdd(name: name, value: value) }
        return response
    }

    /// `registryNumber` → "registry number", `w0_start` → "w0 start" (field keys of validation errors, shown as words).
    static func humanize(_ key: String) -> String {
        var out = ""
        for character in key {
            if character == "_" || character == "-" || character == "." { out += " "; continue }
            if character.isUppercase, !out.isEmpty, out.last != " " { out += " " }
            out += character.lowercased()
        }
        return out
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
            <h1>Sign in</h1><p class="mu">Open your organization's Viadere console with your passkey. There are no passwords.</p>\
            <form data-passkey="login" data-begin="/dashboard/auth/login/begin" data-finish="/dashboard/auth/login/finish" data-next="/dashboard">\
            <div class="form-actions"><button class="btn wide" type="submit">\(ConsoleUI.icon(.key))Sign in with passkey</button></div></form><p id="pk-msg" class="sm err" role="alert"></p>
            """, footer: "New to Viadere? <a href=\"/dashboard/signup\">Create an organization</a>.")
        }
        pub.get("dashboard", "signup") { req -> Response in
            let categories = DashboardAuthService.categories.map { ConsoleUI.Option($0, $0.replacingOccurrences(of: "_", with: " ").capitalized) }
            let about = ConsoleUI.fieldset("About you",
                ConsoleUI.input("displayName", label: "Your name", id: "displayName", required: true, attrs: ["maxlength": "64", "autocomplete": "name"])
                + ConsoleUI.input("email", label: "Work email", id: "email", type: "email", help: "We email a 6-digit code to this address to confirm it.", required: true,
                                  attrs: ["maxlength": "254", "autocomplete": "email"]))
            let organization = ConsoleUI.fieldset("Your organization",
                ConsoleUI.input("organizationName", label: "Organization name", id: "organizationName", help: "The name customers see.", required: true,
                                attrs: ["minlength": "2", "maxlength": "80", "autocomplete": "organization"])
                + ConsoleUI.input("legalName", label: "Legal name", id: "legalName", help: "If it differs from the name above. Not shown to customers.", optional: true, attrs: ["maxlength": "120"])
                + ConsoleUI.select("category", label: "Category", id: "category", options: categories)
                + ConsoleUI.input("website", label: "Website", id: "website", type: "url", placeholder: "https://", help: "An https address you control.", optional: true, attrs: ["maxlength": "200"])
                + ConsoleUI.input("requestedHandle", label: "Requested handle", id: "requestedHandle", placeholder: "yourbrand",
                                  help: "Issued only after approval; Viadere may suggest another.", optional: true, attrs: ["maxlength": "30", "autocapitalize": "none", "spellcheck": "false"])
                + ConsoleUI.textarea("description", label: "What will you use Viadere for?", id: "description", help: "A sentence or two helps the reviewer.", optional: true, attrs: ["maxlength": "500"]))
            return DashboardUI.authPage(title: "Create an organization", body: """
            <h1>Create an organization</h1><p class="mu">Apply to join Viadere as a verified business. A Viadere reviewer checks every application; \
            your handle and code are issued only after approval.</p>\
            <form data-passkey="register" data-begin="/dashboard/auth/signup/begin" data-finish="/dashboard/auth/signup/finish" data-next="/dashboard/verify">\(about)\(organization)\
            \(ConsoleUI.callout(.neutral, title: "What happens next", "<p>You create a passkey to sign in (there are no passwords). We then email a 6-digit code to confirm your address; your application starts once you enter it.</p>"))\
            <div class="form-actions"><button class="btn wide" type="submit">\(ConsoleUI.icon(.key))Create passkey and apply</button></div></form><p id="pk-msg" class="sm err" role="alert"></p>
            """, footer: "Already have an account? <a href=\"/dashboard/login\">Sign in</a>.")
        }
        pub.get("dashboard", "invite", ":token") { req in try await invitePage(req, token: req.parameters.get("token") ?? "") }
        pub.get("dashboard", "verify") { _ in verifyPage() }
        // Business console passkey enrollment: opens and spends links only; links are minted by `staging-demo --console-owner`.
        ConsoleEnrollmentRoutes.register(app)

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
            <h1>Email verified</h1>\(ConsoleUI.callout(.success, "<p>Your application has been submitted for review.</p>"))<p>Sign in with the passkey you just created to follow its status.</p>\
            <div class="form-actions">\(ConsoleUI.linkButton("Sign in", href: "/dashboard/login", .primary))</div>
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
        // Brand image uploads: the body is collected (bounded) before authentication reads its CSRF field (WP-2.2).
        ConsoleBrandStudio.registerUpload(routes.grouped(DashboardPageErrorMiddleware()).grouped(CollectBodyMiddleware(max: ConsoleBrandStudio.uploadBodyLimit))
            .grouped(DashboardAuthMiddleware(realm: .business)))
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
        let note = notice.map { error ? ConsoleUI.callout(.danger, urgent: true, "<p>\(DashboardUI.esc($0))</p>") : ConsoleUI.callout(.success, "<p>\(DashboardUI.esc($0))</p>") } ?? ""
        let response = DashboardUI.authPage(title: "Verify your email", body: """
        <h1>Check your email</h1><p class="mu">Enter the 6-digit code we sent to the address you signed up with. Until you do, your account is not active.</p>\(note)\
        <form method="post" action="/dashboard/verify">\
        \(ConsoleUI.input("email", label: "Email", id: "email", type: "email", required: true, attrs: ["maxlength": "254", "autocomplete": "email"]))\
        \(ConsoleUI.input("code", label: "Code", id: "code", help: "Six digits; spaces are fine.", required: true,
                          attrs: ["inputmode": "numeric", "autocomplete": "one-time-code", "pattern": "[0-9 ]{6,7}", "maxlength": "7"]))\
        <div class="form-actions"><button class="btn wide" type="submit">Verify</button></div></form><hr>\
        <form method="post" action="/dashboard/verify/resend">\
        \(ConsoleUI.input("email", label: "No code? Send a new one to", id: "remail", type: "email", required: true, attrs: ["maxlength": "254", "autocomplete": "email"]))\
        <div class="form-actions"><button class="btn s" type="submit">Send a new code</button></div></form>
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
        let note = notice.map { error ? ConsoleUI.callout(.danger, urgent: true, "<p>\(DashboardUI.esc($0))</p>") : ConsoleUI.callout(.success, "<p>\(DashboardUI.esc($0))</p>") } ?? ""
        // An unverified sign-up for the address does not count: it never blocks the invitee.
        let existing = try await DashboardUserRecord.query(on: req.db).filter(\.$emailHash == invite.emailHash).filter(\.$status != "unverified").count() > 0
        let response: Response
        if existing {
            // Existing account: sign in first, then accept with the signed-in session.
            var accept = ""
            if let cookie = req.requireCookie(.business), let session = try await DashboardSessionStore(db: req.db, ctx: ctx).authenticate(token: cookie, realm: .business),
               let user = try await DashboardUserRecord.find(session.userId, on: req.db), ConstantTime.equals(user.emailHash, invite.emailHash) {
                let csrf = DashboardSessionStore.csrfToken(sessionToken: cookie, hasher: ctx.hasher)
                accept = "<form method=\"post\" action=\"/dashboard/invite/\(DashboardUI.esc(token))/accept\"><input type=\"hidden\" name=\"_csrf\" value=\"\(DashboardUI.esc(csrf))\"><div class=\"form-actions\"><button class=\"btn wide\" type=\"submit\">Accept invitation</button></div></form>"
            } else {
                accept = "<div class=\"form-actions\">\(ConsoleUI.linkButton("Sign in to accept", href: "/dashboard/login", .primary))</div>"
            }
            response = DashboardUI.authPage(title: "Invitation", body: "<h1>Join \(DashboardUI.esc(business.displayName))</h1><p>You've been invited as \(ConsoleUI.pill(role, .accent)). You already have a Viadere account, so sign in to accept.</p>\(accept)", script: false, status: status)
        } else {
            response = DashboardUI.authPage(title: "Invitation", body: """
            <h1>Join \(DashboardUI.esc(business.displayName))</h1><p class="mu">You've been invited as \(ConsoleUI.pill(role, .accent)). Two steps: confirm your email with a code, then create a passkey to sign in.</p>\(note)\
            <h2>1. Get a code</h2><form method="post" action="/dashboard/invite/\(DashboardUI.esc(token))/code"><div class="form-actions"><button class="btn s" type="submit">Email me a code</button></div></form>\
            <h2>2. Create your passkey</h2><form data-passkey="register" data-begin="/dashboard/auth/invite/begin" data-finish="/dashboard/auth/invite/finish" data-next="/dashboard">\
            <input type="hidden" name="token" value="\(DashboardUI.esc(token))">\
            \(ConsoleUI.input("displayName", label: "Your name", id: "displayName", required: true, attrs: ["maxlength": "64", "autocomplete": "name"]))\
            \(ConsoleUI.input("code", label: "Code from the email", id: "code", required: true, attrs: ["inputmode": "numeric", "autocomplete": "one-time-code", "maxlength": "7"]))\
            <div class="form-actions"><button class="btn wide" type="submit">\(ConsoleUI.icon(.key))Create passkey and join</button></div></form><p id="pk-msg" class="sm err" role="alert"></p>
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
        let periods = ConsoleUI.segmented([7, 30, 90].map { ("\($0) days", "/dashboard?days=\($0)", $0 == o.days) }, label: "Period")
        let decisionRate = o.totalIssued == 0 ? nil : DashboardFormat.percent(Double(o.totalDecided) / Double(o.totalIssued))
        let tiles = ConsoleUI.stats([
            ConsoleUI.Stat(String(o.totalIssued), "Interactions issued", hint: "Live traffic, last \(o.days) days"),
            ConsoleUI.Stat(String(o.totalDecided), "Decided", hint: decisionRate.map { "\($0) of issued" }),
            ConsoleUI.Stat(DashboardFormat.duration(o.medianLatency), "Median decision time", hint: "90th percentile \(DashboardFormat.duration(o.p90Latency))"),
            ConsoleUI.Stat(String(o.activeRelationships), "Connected customers"),
        ]) + ConsoleUI.sectionTitle("Delivery and trust", description: "How reliably your messages arrive and how customers respond.") + ConsoleUI.stats([
            ConsoleUI.Stat(DashboardFormat.percent(o.webhookSuccessRate), "Webhook delivery success", href: p.can(.viewWebhooks) ? "/dashboard/webhooks/deliveries" : nil),
            ConsoleUI.Stat(DashboardFormat.percent(o.channelSuccessRate), "SMS / RCS delivery success"),
            ConsoleUI.Stat(String(o.optOuts), "Opt-outs (revocations and disconnects)"),
            ConsoleUI.Stat(String(o.reports), "\"Not me\" reports", hint: o.reports > 0 ? "Customers said a request wasn't theirs" : nil, tone: o.reports > 0 ? .warning : nil),
        ])
        let chart = ConsoleUI.card("Interactions per day", description: "Issued per day, all kinds.", DashboardFormat.barChart(o.daily, label: "Interactions issued per day"))
        let rows = zip(o.issuedByKind, o.decidedByKind).map { issued, decided -> [ConsoleUI.Cell] in
            let rate = issued.count == 0 ? nil : Double(decided.count) / Double(issued.count)
            return [.text(issued.kind), .number(issued.count), .number(decided.count), ConsoleUI.Cell(html: rate.map { DashboardFormat.percent($0) } ?? "—", sort: rate.map { .number($0) })]
        }
        let byKind = ConsoleUI.card("By kind", ConsoleUI.table([ConsoleUI.Column("Kind", key: "kind"), ConsoleUI.Column("Issued", key: "issued", numeric: true),
                                                                 ConsoleUI.Column("Decided", key: "decided", numeric: true), ConsoleUI.Column("Decision rate", key: "rate", numeric: true)],
                                                                rows, caption: "Interactions by kind", state: ConsoleUI.TableState(req, id: "kind"), empty: "No interactions in this period."))
        let verifyCard = try await VerifyDashboard.card(db: req.db, ctx: req.ctx, businessId: businessId, days: o.days)
        let note = ConsoleUI.callout(.neutral, "<p class=\"sm\">Live traffic only, aggregated. Viadere never shows individual customers here, and a customer's phone number or messages never appear in analytics.</p>")
        let attention = await attentionCard(req, p: p, businessId: businessId)
        return DashboardUI.businessPage(p, title: "Overview", active: "/dashboard", subtitle: "How your organization is doing over the last \(o.days) days.", actions: periods,
                                        flash: DashboardFormat.flash(req), body: attention + tiles + "<div class=\"cols\">\(chart)\(byKind)</div>" + verifyCard + note)
    }

    /// "Needs your attention": open work the signed-in person can act on, each item shown only to roles that may open the page it links to.
    private static func attentionCard(_ req: Request, p: DashboardPrincipal, businessId: UUID) async -> String {
        var items: [(ConsoleUI.Tone, ConsoleUI.Icon, String, String, String)] = []
        if p.can(.viewOrganization) || p.can(.manageOrganization), let state = try? await OnboardingService(db: req.db, ctx: req.ctx).state(businessId: businessId) {
            if !state.domainVerified {
                items.append((.accent, .building, "Verify a domain you control", "It unlocks the sandbox and API keys.", "/dashboard/organization/domains"))
            } else if state.goLive == .none || state.goLive == .rejected {
                let blockers = state.requestBlockers
                items.append((.accent, .building, blockers.isEmpty ? "Request production access" : "Finish onboarding",
                              blockers.isEmpty ? "Everything is ready for the go-live review." : "Next: \(blockers.first!.title).", "/dashboard/organization"))
            }
            if !state.contractsCurrent, p.can(.viewCompliance) {
                items.append((.warning, .document, "An agreement needs your acceptance", "Production access and some capabilities wait for it.", "/dashboard/compliance"))
            }
        }
        if p.can(.approveChanges), let open = try? await PendingChanges(db: req.db, ctx: req.ctx).open(businessId: businessId) {
            let waiting = open.filter { $0.status == "pending" && $0.requestedBy != p.user.id }.count
            if waiting > 0 { items.append((.warning, .approve, "\(waiting) request\(waiting == 1 ? "" : "s") wait for a second person", "Keys and roles under two-person approval.", "/dashboard/security/approvals")) }
        }
        if p.can(.viewInbox), let staff = p.user.id, let unread = try? await LoopInbox(db: req.db, ctx: req.ctx).unreadCount(businessId: businessId, staffId: staff), unread > 0 {
            items.append((.accent, .inbox, "\(unread) unread request\(unread == 1 ? "" : "s") in the inbox", "Customers are waiting for your answer.", "/dashboard/inbox"))
        }
        if p.can(.viewWebhooks), let dead = try? await WebhookDeliveryRecord.query(on: req.db).filter(\.$businessId == businessId).filter(\.$status == "dead").count(), dead > 0 {
            items.append((.danger, .alert, "\(dead) webhook deliver\(dead == 1 ? "y" : "ies") failed for good", "Fix the endpoint, then replay them.", "/dashboard/webhooks/deliveries"))
        }
        guard !items.isEmpty else { return "" }
        let list = items.map { tone, icon, title, detail, href in
            "<li class=\"\(tone.cls)\"><div>\(ConsoleUI.icon(icon))<div><strong>\(DashboardUI.esc(title))</strong><br><span class=\"mu sm\">\(DashboardUI.esc(detail))</span></div></div>\(ConsoleUI.linkButton("Open", href: href, .secondary, small: true, ariaLabel: "Open: \(title)"))</li>"
        }.joined()
        return ConsoleUI.card("Needs your attention", "<ul class=\"attn\">\(list)</ul>")
    }

    // MARK: Templates

    private static func templatesPage(_ req: Request) async throws -> Response {
        let (p, _) = try req.businessDashboard
        try p.require(.viewTemplates)
        let cards = InteractionTemplates.all(now: req.ctx.now).map { t in
            ConsoleUI.card(t.title, description: t.summary, actions: ConsoleUI.pill(t.method, .neutral),
                           "<p class=\"sm\"><code>\(DashboardUI.esc(t.method)) \(DashboardUI.esc(t.path))</code></p><pre>\(DashboardUI.esc(t.json))</pre>")
        }.joined()
        let intro = ConsoleUI.callout(.accent, title: "Before you send", """
        <ul><li>Replace the placeholder <code>relationshipId</code> with a connected customer's.</li>\
        <li>Every request needs an <code>Idempotency-Key</code> header equal to the body's <code>idempotencyKey</code>.</li>\
        <li>Security kinds are only ever approved on the customer's device, never by text.</li></ul>
        """)
        return DashboardUI.businessPage(p, title: "Templates", active: "/dashboard/templates", subtitle: "Copy a request for the most common interactions.",
                                        body: intro + "<div class=\"cols\">\(cards)</div>")
    }

    // MARK: Campaigns

    private static func campaignForm(_ p: DashboardPrincipal, verified: Bool) -> String {
        guard verified else {
            return ConsoleUI.callout(.accent, title: "Available after verification", "<p>Campaign links and QR codes are available after Viadere verifies your organization. <a href=\"/dashboard/organization\">See what's left</a></p>")
        }
        let fields = ConsoleUI.input("campaign", label: "Campaign", id: "campaign", placeholder: "spring-flyer", help: "A name you'll recognize in reports.", required: true, attrs: ["maxlength": "64"])
            + ConsoleUI.input("action", label: "Action", id: "action", placeholder: "enroll_rewards", help: "What the app offers when the link opens.", optional: true, attrs: ["maxlength": "64"])
            + ConsoleUI.select("days", label: "Valid for", id: "days", options: [ConsoleUI.Option("90", "90 days"), ConsoleUI.Option("30", "30 days"), ConsoleUI.Option("365", "1 year"), ConsoleUI.Option("0", "No expiry")],
                               help: "After this the plain code still works.")
        return ConsoleUI.card("Create a link", description: "The link carries your permanent code plus a signed campaign context. It never contains customer data, and the QR code is generated here: nothing is sent to a third party.",
                              ConsoleUI.form("/dashboard/campaigns", csrf: DashboardUI.csrf(p), "<div class=\"cols\">\(fields)</div>" + ConsoleUI.formActions(ConsoleUI.button("Generate link and QR"))))
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
        let download = """
        <form method="post" action="/dashboard/campaigns/download">\(DashboardUI.csrf(p))<input type="hidden" name="campaign" value="\(DashboardUI.esc(form.campaign))">\
        <input type="hidden" name="action" value="\(DashboardUI.esc(form.action ?? ""))"><input type="hidden" name="days" value="\(form.days ?? 90)">\
        <button class="btn s" type="submit">Download SVG</button></form>
        """
        let body = ConsoleUI.card("Your campaign link", description: "Print the QR code or share the link. Both open Viadere to your business.", actions: download, """
        <div class="split"><div><h3>Link with signed context</h3><pre>\(DashboardUI.esc(result.link.urlString))</pre><p class="mu sm">\(expires) If the context expires or is invalid, the plain code still works.</p>\
        <h3>Plain link</h3><pre>\(DashboardUI.esc(result.plainLink.urlString))</pre></div><div><div class="qr">\(svg)</div></div></div>
        """) + campaignForm(p, verified: true)
        return DashboardUI.businessPage(p, title: "Campaigns", active: "/dashboard/campaigns", subtitle: "Links and QR codes that open Viadere to your business.",
                                        flash: "Link created.", body: body)
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
        let rows = status.rows.map { row -> [ConsoleUI.Cell] in
            let total = row.granted + row.notGranted
            let share = total == 0 ? nil : Double(row.granted) / Double(total)
            return [.text(row.purpose.rawValue.replacingOccurrences(of: "_", with: " ")), .number(row.granted), .number(row.notGranted),
                    ConsoleUI.Cell(html: share.map { DashboardFormat.percent($0) } ?? "—", sort: share.map { .number($0) })]
        }
        let body = ConsoleUI.stats([ConsoleUI.Stat(String(status.active), "Connected customers"), ConsoleUI.Stat(String(status.disconnected), "Disconnected")])
            + ConsoleUI.card("Consent by purpose", description: "Counts of current relationships only. Individual customers are not shown.",
                             ConsoleUI.table([ConsoleUI.Column("Purpose", key: "purpose"), ConsoleUI.Column("Granted", key: "granted", numeric: true),
                                              ConsoleUI.Column("Not granted", key: "not", numeric: true), ConsoleUI.Column("Opt-in rate", key: "rate", numeric: true)],
                                             rows, caption: "Consent by purpose", state: ConsoleUI.TableState(req, id: "consent"), empty: "No connected customers yet."))
            + ConsoleUI.callout(.neutral, title: "Customers decide", "<p class=\"sm\">Marketing and rewards are off until a customer opts in. Security and account-service messages can't be turned off while a customer is connected.</p>")
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
                    DashboardFormat.badge(e.outcome, e.outcome == "success" ? "ok" : "dg"), "<span class=\"mu sm\">\(DashboardUI.esc(e.actorKind))</span><br>\(DashboardUI.esc(actor))",
                    DashboardUI.esc([e.subjectType, e.subjectId.map { "…" + $0.suffix(6) }].compactMap { $0 }.joined(separator: " ")), metaText.isEmpty ? "<span class=\"mu\">—</span>" : "<code class=\"sm\">\(DashboardUI.esc(metaText))</code>"]
        }
        let newer = page > 0 ? ConsoleUI.linkButton("Newer", href: "/dashboard/audit?page=\(page - 1)", small: true) : "<span></span>"
        let older = events.count > size ? ConsoleUI.linkButton("Older", href: "/dashboard/audit?page=\(page + 1)", small: true) : "<span></span>"
        let pager = page == 0 && events.count <= size ? "" : "<nav class=\"pager\" aria-label=\"Audit log pages\">\(newer)<span>Page \(page + 1), newest first</span>\(older)</nav>"
        let body = ConsoleUI.panel(DashboardFormat.table(["When", "Action", "Outcome", "Actor", "Subject", "Details"], Array(rows), empty: "No events yet.", caption: "Audit log") + pager)
            + ConsoleUI.callout(.neutral, "<p class=\"sm\">Append-only and hash-chained. Secrets and message content are never recorded.</p>")
        return DashboardUI.businessPage(p, title: "Audit log", active: "/dashboard/audit", subtitle: "Everything that happened in your organization, newest first.", body: body)
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
        let memberRows = members.map { m -> [ConsoleUI.Cell] in
            let user = byId[m.userId]
            let email = user.flatMap { try? ctx.cipher.openString($0.emailCiphertext, context: "dashboard_users.email", rowId: $0.id!) } ?? ""
            let isSelf = m.userId == p.user.id
            let roleTitle = OrgRole(rawValue: m.role)?.title ?? m.role
            var role = DashboardFormat.badge(roleTitle)
            var actions = ""
            let touchable = canManage && !isSelf && (OrgRole(rawValue: m.role).map { p.role?.grantableRoles.contains($0) == true } ?? false)
            let name = user?.displayName ?? "—"
            if touchable, let id = m.id?.uuidString.lowercased() {
                let options = assignable.map { ConsoleUI.Option($0.rawValue, $0.title, selected: $0.rawValue == m.role) }
                role = "<form method=\"post\" action=\"/dashboard/team/members/\(id)/role\" class=\"row\">\(DashboardUI.csrf(p))<select name=\"role\" aria-label=\"Role of \(DashboardUI.esc(name))\">\(ConsoleUI.options(options))</select>"
                    + ConsoleUI.button("Save", .secondary, small: true, ariaLabel: "Save the role of \(name)") + "</form>"
                actions = ConsoleUI.confirm("Remove", ariaLabel: "Remove \(name)", ConsoleUI.form("/dashboard/team/members/\(id)/remove", csrf: DashboardUI.csrf(p),
                    "<p>\(DashboardUI.esc(name)) loses access to this organization at once and is signed out here. Removing an admin may need your passkey or a second approver.</p>"
                        + ConsoleUI.button("Remove from the team", .dangerSolid, small: true)))
            }
            return [ConsoleUI.Cell(html: "<strong>\(DashboardUI.esc(name))</strong>\(isSelf ? " " + ConsoleUI.pill("You", .neutral) : "")", sort: .text(name)),
                    .text(email), ConsoleUI.Cell(html: role, sort: .text(roleTitle)), .date(m.createdAt), ConsoleUI.Cell(html: actions)]
        }
        let invites = try await OrgInviteRecord.query(on: req.db).filter(\.$businessId == businessId).filter(\.$state == "open")
            .filter(\.$expiresAt > ctx.now).sort(\.$createdAt, .descending).all()
        let inviteRows = invites.map { i -> [ConsoleUI.Cell] in
            let email = (try? ctx.cipher.openString(i.emailCiphertext, context: "org_invites.email", rowId: i.id!)) ?? ""
            var action = ""
            if canManage, let id = i.id?.uuidString.lowercased() {
                action = ConsoleUI.form("/dashboard/team/invites/\(id)/revoke", csrf: DashboardUI.csrf(p), ConsoleUI.button("Revoke", .danger, small: true, ariaLabel: "Revoke the invitation for \(email)"))
            }
            return [.text(email), ConsoleUI.Cell(html: DashboardFormat.badge(OrgRole(rawValue: i.role)?.title ?? i.role)), .date(i.expiresAt), ConsoleUI.Cell(html: action)]
        }
        var form = ""
        if canManage {
            let options = assignable.map { ConsoleUI.Option($0.rawValue, "\($0.title) — \($0.summary)", selected: $0 == .developer) }
            form = ConsoleUI.card("Invite a teammate", id: "invite", description: "We email a single-use link to this address, and the person confirms a code we email them as well.",
                ConsoleUI.form("/dashboard/team/invite", csrf: DashboardUI.csrf(p),
                    "<div class=\"cols\">" + ConsoleUI.input("email", label: "Email", id: "email", type: "email", required: true, attrs: ["maxlength": "254", "autocomplete": "off"])
                    + ConsoleUI.select("role", label: "Role", id: "role", options: options, help: "Give the least access the job needs. You can change it later.") + "</div>"
                    + ConsoleUI.formActions(ConsoleUI.button("Send invitation") + "<span class=\"mu sm\">Inviting an Owner, Organization Admin or Security Admin asks for your passkey.</span>")))
        }
        let roles = OrgRole.allCases.sorted(by: >).map { "<tr><th scope=\"row\">\($0.title)</th><td>\(DashboardUI.esc($0.summary))</td></tr>" }.joined()
        let rolesTable = "<div class=\"tw\"><table><caption class=\"vh\">Roles and what they can do</caption><tbody>\(roles)</tbody></table></div>"
        let state = ConsoleUI.TableState(req, id: "members")
        let body = ConsoleUI.card("Members", description: "\(members.count) \(members.count == 1 ? "person" : "people") with access.",
                                  ConsoleUI.table([ConsoleUI.Column("Name", key: "name"), ConsoleUI.Column("Email", key: "email"), ConsoleUI.Column("Role", key: "role"),
                                                   ConsoleUI.Column("Joined", key: "joined"), ConsoleUI.Column("", actions: true)], memberRows, caption: "Team members", state: state))
            + ConsoleUI.card("Pending invitations", description: "Invitations expire after \(Int(ctx.config.dashboard.inviteTTL / 86_400)) days.",
                             ConsoleUI.table([ConsoleUI.Column("Email"), ConsoleUI.Column("Role"), ConsoleUI.Column("Expires"), ConsoleUI.Column("", actions: true)], inviteRows,
                                             caption: "Pending invitations", empty: "No open invitations."))
            + form
            + ConsoleUI.card("Roles", description: "Each role gets exactly the permissions its job needs.", ConsoleUI.more("What each role can do", rolesTable))
        let actions = canManage ? ConsoleUI.linkButton("Invite a teammate", href: "#invite", .primary, icon: .plus) : ""
        return DashboardUI.businessPage(p, title: "Team", active: "/dashboard/team", subtitle: "Everyone signs in with their own passkey. Roles decide what each person can see and change.",
                                        actions: actions, flash: DashboardFormat.flash(req), body: body)
    }

    private static func invite(_ req: Request) async throws -> Response {
        let (p, _) = try req.businessDashboard
        let form = try req.content.decode(InviteForm.self)
        guard let role = OrgRole.parse(form.role) else { throw APIError.validation("Choose a valid role.") }
        let change = try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).invite(email: form.email, role: role)
        if case .awaitingApproval = change { return DashboardResponses.redirect("/dashboard/team?m=pending") }
        let body = ConsoleUI.card("Invitation sent", """
        <p>We emailed a single-use link to the address you entered. It expires in \(Int(req.ctx.config.dashboard.inviteTTL / 86_400)) days. \
        To join, your teammate opens it and confirms a code that we email to the same address.</p>\(ConsoleUI.formActions(ConsoleUI.linkButton("Back to the team", href: "/dashboard/team", .primary)))
        """)
        return DashboardUI.businessPage(p, title: "Invitation", active: "/dashboard/team", flash: "Invitation created.", body: body)
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
        let tiles = ConsoleUI.stats([
            ConsoleUI.Stat(InvoicePreview.format(micros: invoice.totalMicros), "Preview total this month", hint: "Platform \(InvoicePreview.format(micros: invoice.platformTotalMicros)) · transport \(InvoicePreview.format(micros: invoice.transportTotalMicros))"),
            ConsoleUI.Stat(String(usage.totals.interactions), "Interactions this month"), ConsoleUI.Stat(String(usage.totals.smsSegments), "SMS segments"),
            ConsoleUI.Stat(String(usage.totals.rcsMessages), "RCS messages"), ConsoleUI.Stat(tier.capitalized, "Plan", hint: "Quotas only; never message priority"),
        ])
        func linesTable(_ items: [InvoicePreview.Line], caption: String, subtotal: Int) -> String {
            let columns = [ConsoleUI.Column("Item"), ConsoleUI.Column("Quantity", numeric: true), ConsoleUI.Column("Unit", numeric: true), ConsoleUI.Column("Amount", numeric: true)]
            return ConsoleUI.table(columns, lines(items).map { $0.map { ConsoleUI.Cell(html: $0) } }, caption: caption, empty: "Nothing billed yet this month.")
                + "<p class=\"row end\"><span class=\"mu\">Subtotal</span> <strong>\(InvoicePreview.format(micros: subtotal))</strong></p>"
        }
        let body = ConsoleUI.callout(.neutral, title: "A usage preview, not an invoice", """
        <p class="sm">\(DashboardFormat.date(invoice.periodStart)) – \(DashboardFormat.date(invoice.periodEnd)). No payment processor is connected, rates are configurable and final pricing is not yet set. \
        Your plan affects quotas only: it never changes the priority of your messages or bypasses a customer's consent.</p>
        """) + tiles
            + "<div class=\"cols\">" + ConsoleUI.card("Platform fees", linesTable(invoice.platform, caption: "Platform fees", subtotal: invoice.platformTotalMicros))
            + ConsoleUI.card("Transport (carrier and provider pass-through)", linesTable(invoice.transport, caption: "Transport pass-through", subtotal: invoice.transportTotalMicros)) + "</div>"
        return DashboardUI.businessPage(p, title: "Billing and usage", active: "/dashboard/billing", subtitle: "Metered usage and an invoice preview for this month.", body: body)
    }
}
