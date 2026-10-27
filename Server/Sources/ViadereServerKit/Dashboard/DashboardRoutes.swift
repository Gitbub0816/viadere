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

private struct CreateKeyForm: Content {
    var name: String
    var mode: String?
    var scopes: [String]?
    var expires: Int?
}

private struct CreateWebhookForm: Content {
    var url: String
    var events: [String]?
}

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
            <form data-passkey="register" data-begin="/dashboard/auth/signup/begin" data-finish="/dashboard/auth/signup/finish" data-next="/dashboard">\
            <label for="displayName">Your name</label><input id="displayName" name="displayName" type="text" maxlength="64" required autocomplete="name">\
            <label for="email">Work email</label><input id="email" name="email" type="email" maxlength="254" required autocomplete="email">\
            <label for="organizationName">Organization name</label><input id="organizationName" name="organizationName" type="text" minlength="2" maxlength="80" required>\
            <label for="legalName">Legal name (optional)</label><input id="legalName" name="legalName" type="text" maxlength="120">\
            <label for="category">Category</label><select id="category" name="category">\(categories)</select>\
            <label for="website">Website (https)</label><input id="website" name="website" type="url" maxlength="200" placeholder="https://">\
            <label for="requestedHandle">Requested handle (optional)</label><input id="requestedHandle" name="requestedHandle" type="text" maxlength="30" placeholder="yourbrand">\
            <label for="description">What will you use Viadere for?</label><textarea id="description" name="description" maxlength="500"></textarea>\
            <p class="mu sm">You'll create a passkey to sign in. There are no passwords.</p>\
            <p><button class="btn" type="submit">Create passkey and apply</button></p></form><p id="pk-msg" class="sm err" role="alert"></p>\
            <p class="mu sm">Already have an account? <a href="/dashboard/login">Sign in</a>.</p>
            """)
        }
        pub.get("dashboard", "invite", ":token") { req -> Response in
            let ctx = req.ctx
            let token = req.parameters.get("token") ?? ""
            guard let invite = try await DashboardAuthService(db: req.db, ctx: ctx).openInvite(token: token),
                  let business = try await BusinessRecord.find(invite.businessId, on: req.db) else {
                return DashboardUI.authPage(title: "Invitation", body: "<h1>Invitation not valid</h1><p>This invitation has expired or was already used. Ask your admin for a new one.</p>", script: false, status: .gone)
            }
            let role = OrgRole(rawValue: invite.role)?.title ?? "Member"
            let existing = try await DashboardUserRecord.query(on: req.db).filter(\.$emailHash == invite.emailHash).count() > 0
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
                return DashboardUI.authPage(title: "Invitation", body: "<h1>Join \(DashboardUI.esc(business.displayName))</h1><p>You've been invited as <strong>\(DashboardUI.esc(role))</strong>. You already have a Viadere account, so sign in to accept.</p>\(accept)", script: false)
            }
            return DashboardUI.authPage(title: "Invitation", body: """
            <h1>Join \(DashboardUI.esc(business.displayName))</h1><p class="mu">You've been invited as <strong>\(DashboardUI.esc(role))</strong>. Create a passkey to sign in.</p>\
            <form data-passkey="register" data-begin="/dashboard/auth/invite/begin" data-finish="/dashboard/auth/invite/finish" data-next="/dashboard">\
            <input type="hidden" name="token" value="\(DashboardUI.esc(token))">\
            <label for="displayName">Your name</label><input id="displayName" name="displayName" type="text" maxlength="64" required autocomplete="name">\
            <p><button class="btn" type="submit">Create passkey and join</button></p></form><p id="pk-msg" class="sm err" role="alert"></p>
            """)
        }

        let ceremonies = routes.grouped(authLimiter)
        @Sendable func sessionResponse(_ created: DashboardSessionStore.Created, req: Request, realm: DashboardRealm) throws -> Response {
            let response = DashboardResponses.json(["redirect": realm.home])
            response.cookies[realm.cookieName] = DashboardSessionStore(db: req.db, ctx: req.ctx).cookie(for: created, realm: realm)
            return response
        }
        ceremonies.post("dashboard", "auth", "signup", "begin") { req in
            let body: SignupBeginBody = try req.decodeBody()
            let ip = ClientIP.resolve(req, trustedProxies: req.ctx.config.trustedProxyCount)
            return try req.jsonResponse(try await DashboardAuthService(db: req.db, ctx: req.ctx).signupBegin(body, ip: ip))
        }
        ceremonies.post("dashboard", "auth", "signup", "finish") { req in
            let body: PasskeyRegistrationFinishRequest = try req.decodeBody()
            let created = try await DashboardAuthService(db: req.db, ctx: req.ctx).signupFinish(body, previousCookie: req.requireCookie(.business))
            return try sessionResponse(created, req: req, realm: .business)
        }
        ceremonies.post("dashboard", "auth", "login", "begin") { req in
            try req.jsonResponse(try await DashboardAuthService(db: req.db, ctx: req.ctx).loginBegin(realm: .business))
        }
        ceremonies.post("dashboard", "auth", "login", "finish") { req in
            let body: PasskeyLoginFinishRequest = try req.decodeBody()
            let created = try await DashboardAuthService(db: req.db, ctx: req.ctx).loginFinish(realm: .business, body, previousCookie: req.requireCookie(.business))
            return try sessionResponse(created, req: req, realm: .business)
        }
        ceremonies.post("dashboard", "auth", "invite", "begin") { req in
            let body: InviteBeginBody = try req.decodeBody()
            return try req.jsonResponse(try await DashboardAuthService(db: req.db, ctx: req.ctx).inviteBegin(body))
        }
        ceremonies.post("dashboard", "auth", "invite", "finish") { req in
            let body: PasskeyRegistrationFinishRequest = try req.decodeBody()
            let created = try await DashboardAuthService(db: req.db, ctx: req.ctx).inviteFinish(body, previousCookie: req.requireCookie(.business))
            return try sessionResponse(created, req: req, realm: .business)
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
        pages.get("dashboard", "api-keys") { req in try await apiKeysPage(req) }
        pages.post("dashboard", "api-keys") { req in try await createKey(req) }
        pages.post("dashboard", "api-keys", ":id", "revoke") { req -> Response in
            let (p, _) = try req.businessDashboard
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).revokeAPIKey(id: try req.uuid("id"))
            return DashboardResponses.redirect("/dashboard/api-keys?m=revoked")
        }
        pages.get("dashboard", "webhooks") { req in try await webhooksPage(req) }
        pages.post("dashboard", "webhooks") { req in try await createWebhook(req) }
        pages.post("dashboard", "webhooks", ":id", "rotate") { req in try await rotateWebhook(req) }
        pages.post("dashboard", "webhooks", ":id", "delete") { req -> Response in
            let (p, _) = try req.businessDashboard
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).deleteWebhook(id: try req.uuid("id"))
            return DashboardResponses.redirect("/dashboard/webhooks?m=deleted")
        }
        pages.get("dashboard", "webhooks", "deliveries") { req in try await deliveriesPage(req) }
        pages.get("dashboard", "webhooks", "deliveries", ":id") { req in try await deliveryPage(req) }
        pages.post("dashboard", "webhooks", "deliveries", ":id", "replay") { req -> Response in
            let (p, _) = try req.businessDashboard
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).replayDelivery(id: try req.uuid("id"))
            return DashboardResponses.redirect("/dashboard/webhooks/deliveries?m=replayed")
        }
        pages.get("dashboard", "templates") { req in try await templatesPage(req) }
        pages.get("dashboard", "campaigns") { req in try await campaignsPage(req) }
        pages.post("dashboard", "campaigns") { req in try await createCampaign(req) }
        pages.post("dashboard", "campaigns", "download") { req in try await downloadCampaign(req) }
        pages.get("dashboard", "consent") { req in try await consentPage(req) }
        pages.get("dashboard", "audit") { req in try await auditPage(req) }
        pages.get("dashboard", "team") { req in try await teamPage(req) }
        pages.post("dashboard", "team", "invite") { req in try await invite(req) }
        pages.post("dashboard", "team", "invites", ":id", "revoke") { req -> Response in
            let (p, _) = try req.businessDashboard
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).revokeInvite(id: try req.uuid("id"))
            return DashboardResponses.redirect("/dashboard/team?m=invite-revoked")
        }
        pages.post("dashboard", "team", "members", ":id", "role") { req -> Response in
            let (p, _) = try req.businessDashboard
            let form = try req.content.decode(RoleForm.self)
            guard let role = OrgRole(rawValue: form.role) else { throw APIError.validation("Choose a valid role.") }
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).changeRole(membershipId: try req.uuid("id"), to: role)
            return DashboardResponses.redirect("/dashboard/team?m=role")
        }
        pages.post("dashboard", "team", "members", ":id", "remove") { req -> Response in
            let (p, _) = try req.businessDashboard
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).removeMember(membershipId: try req.uuid("id"))
            return DashboardResponses.redirect("/dashboard/team?m=removed")
        }
        pages.post("dashboard", "invite", ":token", "accept") { req -> Response in
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
        pages.get("dashboard", "organization") { req in try await organizationPage(req) }
        pages.post("dashboard", "organization") { req -> Response in
            let (p, _) = try req.businessDashboard
            let form = try req.content.decode(ApplicationForm.self)
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).resubmit(
                legalName: form.legalName, website: form.website, requestedHandle: form.requestedHandle, description: form.description)
            return DashboardResponses.redirect("/dashboard/organization?m=applied")
        }
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
        let byKind = "<div class=\"card\"><h2>By kind</h2>\(DashboardFormat.table(["Kind", "Issued", "Decided", "Decision rate"], rows))</div>"
        let note = "<p class=\"mu sm\">Live traffic only, aggregated. Viadere never shows individual customers here, and a customer's phone number or messages never appear in analytics.</p>"
        return DashboardUI.businessPage(p, title: "Overview", active: "/dashboard", subtitle: "The last \(o.days) days", actions: periods,
                                        flash: DashboardFormat.flash(req), body: tiles + chart + byKind + note)
    }

    // MARK: API keys

    private static func apiKeysPage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewAPIKeys)
        let keys = try await BusinessAPIKeyRecord.query(on: req.db).filter(\.$businessId == businessId).sort(\.$createdAt, .descending).all()
        let now = req.ctx.now
        let rows = keys.map { key -> [String] in
            let status: String
            if key.revokedAt != nil { status = DashboardFormat.badge("Revoked", "dg") }
            else if let exp = key.expiresAt, exp <= now { status = DashboardFormat.badge("Expired", "mu") }
            else { status = DashboardFormat.badge(key.livemode ? "Live" : "Test", key.livemode ? "ok" : "mu") }
            var action = ""
            if key.revokedAt == nil, p.can(.manageAPIKeys), let id = key.id {
                action = "<form method=\"post\" action=\"/dashboard/api-keys/\(id.uuidString.lowercased())/revoke\">\(DashboardUI.csrf(p))<button class=\"btn d sm\" type=\"submit\">Revoke</button></form>"
            }
            return [DashboardUI.esc(key.name), "<code>\(DashboardUI.esc(key.prefix))…\(DashboardUI.esc(key.last4))</code>",
                    DashboardUI.esc(key.scopes.replacingOccurrences(of: ",", with: " ")), DashboardFormat.optional(key.lastUsedAt),
                    DashboardFormat.date(key.createdAt), status, action]
        }
        var form = ""
        if p.can(.manageAPIKeys) {
            if p.business?.isVerified == true {
                let scopes = BusinessAPIKeys.Scope.all.map { scope in
                    "<label class=\"ck\"><input type=\"checkbox\" name=\"scopes[]\" value=\"\(scope)\"\(scope == "interactions:write" || scope == "interactions:read" ? " checked" : "")> <code>\(scope)</code></label>"
                }.joined()
                form = """
                <div class="card"><h2>Create a key</h2><form method="post" action="/dashboard/api-keys">\(DashboardUI.csrf(p))\
                <div class="cols"><div><label for="name">Name</label><input id="name" name="name" type="text" maxlength="64" required placeholder="Production server"></div>\
                <div><label for="mode">Mode</label><select id="mode" name="mode"><option value="test">Test (no real delivery)</option><option value="live">Live</option></select></div>\
                <div><label for="expires">Expires</label><select id="expires" name="expires"><option value="0">Never</option><option value="30">In 30 days</option><option value="90">In 90 days</option><option value="365">In a year</option></select></div></div>\
                <label>Scopes</label>\(scopes)<p class="mu sm">Give a key only the scopes it needs. Creating a key asks you to confirm with your passkey. The secret is shown once.</p>\
                <button class="btn" type="submit">Create key</button></form></div>
                """
            } else {
                form = "<div class=\"notice\">Keys can be created after Viadere verifies your organization.</div>"
            }
        }
        let table = "<div class=\"card\"><h2>Keys</h2>\(DashboardFormat.table(["Name", "Key", "Scopes", "Last used", "Created", "Status", ""], rows, empty: "No keys yet."))</div>"
        return DashboardUI.businessPage(p, title: "API keys", active: "/dashboard/api-keys", subtitle: "Credentials for your server integration.",
                                        flash: DashboardFormat.flash(req), body: form + table)
    }

    private static func createKey(_ req: Request) async throws -> Response {
        let (p, _) = try req.businessDashboard
        let form = try req.content.decode(CreateKeyForm.self)
        let issued = try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).createAPIKey(
            name: form.name, live: form.mode == "live", scopes: form.scopes ?? [], expiresInDays: form.expires)
        let body = """
        <div class="card"><h2>Copy your key now</h2><p>This is the only time the full key is shown. Store it in your secrets manager.</p>\
        <div class="secret mono">\(DashboardUI.esc(issued.key))</div>\
        <p class="mu sm">Name: \(DashboardUI.esc(issued.record.name)) · Scopes: \(DashboardUI.esc(issued.record.scopes.replacingOccurrences(of: ",", with: " "))) · \(issued.record.livemode ? "Live" : "Test")</p>\
        <p><a class="btn s" href="/dashboard/api-keys">Done</a></p></div>
        """
        return DashboardUI.businessPage(p, title: "New API key", active: "/dashboard/api-keys", body: body)
    }

    // MARK: Webhooks

    private static func webhooksPage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewWebhooks)
        let subs = try await WebhookSubscriptionRecord.query(on: req.db).filter(\.$businessId == businessId).filter(\.$active == true)
            .sort(\.$createdAt, .descending).all()
        let rows = subs.map { sub -> [String] in
            var actions = ""
            if p.can(.manageWebhooks), let id = sub.id?.uuidString.lowercased() {
                actions = "<div class=\"row\"><form method=\"post\" action=\"/dashboard/webhooks/\(id)/rotate\">\(DashboardUI.csrf(p))<button class=\"btn s sm\" type=\"submit\">Rotate secret</button></form>"
                    + "<form method=\"post\" action=\"/dashboard/webhooks/\(id)/delete\">\(DashboardUI.csrf(p))<button class=\"btn d sm\" type=\"submit\">Delete</button></form></div>"
            }
            return ["<code>\(DashboardUI.esc(sub.url))</code>", DashboardUI.esc(sub.events.replacingOccurrences(of: ",", with: ", ")),
                    DashboardFormat.date(sub.createdAt), actions]
        }
        var form = ""
        if p.can(.manageWebhooks) {
            if p.business?.isVerified == true {
                let events = WebhookService.knownEvents.map { "<label class=\"ck\"><input type=\"checkbox\" name=\"events[]\" value=\"\($0.rawValue)\" checked> <code>\($0.rawValue)</code></label>" }.joined()
                form = """
                <div class="card"><h2>Add an endpoint</h2><form method="post" action="/dashboard/webhooks">\(DashboardUI.csrf(p))\
                <label for="url">HTTPS URL</label><input id="url" name="url" type="url" required placeholder="https://example.com/viadere/webhooks" maxlength="500">\
                <label>Events</label>\(events)<p class="mu sm">Each delivery is signed with <code>Viadere-Signature</code>. The signing secret is shown once, after you confirm with your passkey.</p>\
                <button class="btn" type="submit">Add endpoint</button></form></div>
                """
            } else {
                form = "<div class=\"notice\">Webhooks can be added after Viadere verifies your organization.</div>"
            }
        }
        let list = "<div class=\"card\"><h2>Endpoints</h2>\(DashboardFormat.table(["URL", "Events", "Created", ""], rows, empty: "No endpoints yet."))</div>"
        return DashboardUI.businessPage(p, title: "Webhooks", active: "/dashboard/webhooks", subtitle: "Signed event delivery with retries and a dead-letter queue.",
                                        actions: "<a class=\"btn s sm\" href=\"/dashboard/webhooks/deliveries\">Delivery log</a>",
                                        flash: DashboardFormat.flash(req), body: form + list)
    }

    private static func secretPage(_ p: DashboardPrincipal, response: WebhookSecretResponse, heading: String) -> Response {
        let body = """
        <div class="card"><h2>\(DashboardUI.esc(heading))</h2><p>This signing secret is shown once. Verify the <code>Viadere-Signature</code> header with it.</p>\
        <div class="secret mono">\(DashboardUI.esc(response.secret))</div><p class="mu sm">Endpoint: <code>\(DashboardUI.esc(response.subscription.url.absoluteString))</code></p>\
        <p><a class="btn s" href="/dashboard/webhooks">Done</a></p></div>
        """
        return DashboardUI.businessPage(p, title: "Webhook secret", active: "/dashboard/webhooks", body: body)
    }

    private static func createWebhook(_ req: Request) async throws -> Response {
        let (p, _) = try req.businessDashboard
        let form = try req.content.decode(CreateWebhookForm.self)
        let created = try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).createWebhook(url: form.url, events: form.events ?? [])
        return secretPage(p, response: created, heading: "Endpoint added")
    }

    private static func rotateWebhook(_ req: Request) async throws -> Response {
        let (p, _) = try req.businessDashboard
        let rotated = try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).rotateWebhook(id: try req.uuid("id"))
        return secretPage(p, response: rotated, heading: "Secret rotated")
    }

    private static func deliveriesPage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewWebhooks)
        let deliveries = try await WebhookDeliveryRecord.query(on: req.db).filter(\.$businessId == businessId).sort(\.$createdAt, .descending).limit(50).all()
        let rows = deliveries.map { d -> [String] in
            let id = d.id?.uuidString.lowercased() ?? ""
            let kind = d.status == "succeeded" ? "ok" : (d.status == "dead" ? "dg" : "mu")
            var action = "<a href=\"/dashboard/webhooks/deliveries/\(id)\">View</a>"
            if d.status == "dead", p.can(.manageWebhooks) {
                action += " <form method=\"post\" action=\"/dashboard/webhooks/deliveries/\(id)/replay\" class=\"row\">\(DashboardUI.csrf(p))<button class=\"btn s sm\" type=\"submit\">Replay</button></form>"
            }
            return [DashboardUI.esc(d.eventType), DashboardFormat.badge(d.status, kind), String(d.attempts), d.lastStatusCode.map(String.init) ?? "—",
                    DashboardUI.esc(d.lastError ?? "—"), DashboardFormat.date(d.createdAt), action]
        }
        let body = "<div class=\"card\">\(DashboardFormat.table(["Event", "Status", "Attempts", "Last HTTP", "Last error", "Created", ""], rows, empty: "No deliveries yet."))</div>"
        return DashboardUI.businessPage(p, title: "Delivery log", active: "/dashboard/webhooks", subtitle: "The 50 most recent deliveries. Payloads are redacted.",
                                        actions: "<a class=\"btn s sm\" href=\"/dashboard/webhooks\">Endpoints</a>", flash: DashboardFormat.flash(req), body: body)
    }

    private static func deliveryPage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewWebhooks)
        let id = try req.uuid("id")
        guard let d = try await WebhookDeliveryRecord.query(on: req.db).filter(\.$id == id).filter(\.$businessId == businessId).first() else { throw APIError.notFound }
        let attempts = try await WebhookAttemptRecord.query(on: req.db).filter(\.$deliveryId == id).sort(\.$attempt, .ascending).all()
        let attemptRows = attempts.map { [String($0.attempt), DashboardFormat.date($0.attemptedAt), $0.statusCode.map(String.init) ?? "—", "\($0.durationMs) ms", DashboardUI.esc($0.error ?? "—")] }
        var replay = ""
        if d.status == "dead", p.can(.manageWebhooks) {
            replay = "<form method=\"post\" action=\"/dashboard/webhooks/deliveries/\(id.uuidString.lowercased())/replay\">\(DashboardUI.csrf(p))<button class=\"btn\" type=\"submit\">Replay this delivery</button></form>"
        }
        let body = """
        <div class="card"><h2>\(DashboardUI.esc(d.eventType)) \(DashboardFormat.badge(d.status, d.status == "succeeded" ? "ok" : (d.status == "dead" ? "dg" : "mu")))</h2>\
        <p class="mu sm">Created \(DashboardFormat.date(d.createdAt)) · \(d.attempts) attempt(s)</p>\
        <h3>Payload (redacted)</h3><pre>\(DashboardUI.esc(PayloadRedactor.display(body: d.body)))</pre>\(replay)</div>\
        <div class="card"><h2>Attempts</h2>\(DashboardFormat.table(["#", "When", "HTTP", "Duration", "Error"], attemptRows, empty: "No attempts yet."))</div>
        """
        return DashboardUI.businessPage(p, title: "Delivery", active: "/dashboard/webhooks", actions: "<a class=\"btn s sm\" href=\"/dashboard/webhooks/deliveries\">Back</a>", body: body)
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
        <div class="card"><h2>Consent by purpose</h2>\(DashboardFormat.table(["Purpose", "Granted", "Not granted"], rows))\
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
        let rows = events.prefix(size).map { e -> [String] in
            let actor = e.actorId.flatMap { names[$0] } ?? (e.actorId.map { "…" + $0.suffix(6) } ?? "")
            let meta = (try? JSONDecoder().decode([String: String].self, from: Data(e.metadataJSON.utf8))) ?? [:]
            let metaText = meta.keys.sorted().map { "\($0)=\(meta[$0] ?? "")" }.joined(separator: " ")
            return [DashboardFormat.date(e.occurredAt), "<code>\(DashboardUI.esc(e.action))</code>",
                    DashboardFormat.badge(e.outcome, e.outcome == "success" ? "ok" : "dg"), "\(DashboardUI.esc(e.actorKind)) \(DashboardUI.esc(actor))",
                    DashboardUI.esc([e.subjectType, e.subjectId.map { "…" + $0.suffix(6) }].compactMap { $0 }.joined(separator: " ")), "<span class=\"mu sm\">\(DashboardUI.esc(metaText))</span>"]
        }
        var pager = "<div class=\"row\">"
        if page > 0 { pager += "<a class=\"btn s sm\" href=\"/dashboard/audit?page=\(page - 1)\">Newer</a>" }
        if events.count > size { pager += "<a class=\"btn s sm\" href=\"/dashboard/audit?page=\(page + 1)\">Older</a>" }
        pager += "</div>"
        let body = "<div class=\"card\">\(DashboardFormat.table(["When", "Action", "Outcome", "Actor", "Subject", "Details"], Array(rows), empty: "No events yet."))\(pager)</div><p class=\"mu sm\">Append-only and hash-chained. Secrets and message content are never recorded.</p>"
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
        let assignable = OrgRole.allCases.sorted(by: >).filter { p.role == .owner || $0 != .owner }
        let memberRows = members.map { m -> [String] in
            let user = byId[m.userId]
            let email = user.flatMap { try? ctx.cipher.openString($0.emailCiphertext, context: "dashboard_users.email", rowId: $0.id!) } ?? ""
            let isSelf = m.userId == p.user.id
            var role = DashboardFormat.badge(OrgRole(rawValue: m.role)?.title ?? m.role)
            var actions = ""
            let touchable = canManage && !isSelf && (p.role == .owner || m.role != OrgRole.owner.rawValue)
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
            <p class="mu sm">Viadere doesn't send the email: you'll get a single-use link to share. Adding an owner needs your passkey.</p>\
            <button class="btn" type="submit">Create invitation</button></form></div>
            """
        }
        let roles = OrgRole.allCases.sorted(by: >).map { "<tr><td><strong>\($0.title)</strong></td><td>\(DashboardUI.esc($0.summary))</td></tr>" }.joined()
        let body = form + "<div class=\"card\"><h2>Members</h2>\(DashboardFormat.table(["Name", "Email", "Role", "Joined", ""], memberRows))</div>"
            + "<div class=\"card\"><h2>Pending invitations</h2>\(DashboardFormat.table(["Email", "Role", "Expires", ""], inviteRows, empty: "None."))</div>"
            + "<div class=\"card\"><h2>Roles</h2><div class=\"tw\"><table><tbody>\(roles)</tbody></table></div></div>"
        return DashboardUI.businessPage(p, title: "Team", active: "/dashboard/team", subtitle: "Everyone signs in with their own passkey.", flash: DashboardFormat.flash(req), body: body)
    }

    private static func invite(_ req: Request) async throws -> Response {
        let (p, _) = try req.businessDashboard
        let form = try req.content.decode(InviteForm.self)
        guard let role = OrgRole(rawValue: form.role) else { throw APIError.validation("Choose a valid role.") }
        let link = try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).invite(email: form.email, role: role)
        let body = """
        <div class="card"><h2>Invitation created</h2><p>Share this single-use link with your teammate. It expires in \(Int(req.ctx.config.dashboard.inviteTTL / 86_400)) days and is shown only now.</p>\
        <div class="secret mono">\(DashboardUI.esc(link))</div><p><a class="btn s" href="/dashboard/team">Done</a></p></div>
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
        <div class="card"><h2>Platform fees</h2>\(DashboardFormat.table(["Item", "Quantity", "Unit", "Amount"], lines(invoice.platform)))\
        <p><strong>Platform subtotal: \(InvoicePreview.format(micros: invoice.platformTotalMicros))</strong></p></div>\
        <div class="card"><h2>Transport (carrier and provider pass-through)</h2>\(DashboardFormat.table(["Item", "Quantity", "Unit", "Amount"], lines(invoice.transport)))\
        <p><strong>Transport subtotal: \(InvoicePreview.format(micros: invoice.transportTotalMicros))</strong></p></div>\
        <div class="card"><h2>Preview total</h2><p class="stat"><span class="n">\(InvoicePreview.format(micros: invoice.totalMicros))</span></p>\
        <p class="mu sm">\(DashboardFormat.date(invoice.periodStart)) – \(DashboardFormat.date(invoice.periodEnd)). This is a usage preview, not an invoice: no payment processor is connected, rates are configurable and final pricing is not yet set. Your plan affects quotas only — it never changes the priority of your messages or bypasses a customer's consent.</p></div>
        """
        return DashboardUI.businessPage(p, title: "Billing and usage", active: "/dashboard/billing", subtitle: "Metered usage and an invoice preview for this month.", body: body)
    }

    // MARK: Organization

    private static func organizationPage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.manageOrganization)
        guard let business = p.business else { throw APIError.notFound }
        let application = try await BusinessApplicationRecord.query(on: req.db).filter(\.$businessId == businessId).first()
        var body = "<div class=\"card\"><h2>\(DashboardUI.esc(business.displayName)) \(DashboardFormat.statusBadge(business.status))</h2>"
        if business.isVerified {
            let summary = try await DirectoryService(db: req.db).summary(for: business)
            body += "<p>Handle: <strong>\(DashboardUI.esc(summary?.handle?.display ?? "none"))</strong> · Code: <strong>\(DashboardUI.esc(summary?.code.display ?? ""))</strong></p>"
            body += "<p class=\"mu sm\">Verified \(DashboardFormat.optional(business.verifiedAt)). Your permanent code is never reassigned.</p>"
        } else if let application {
            switch application.state {
            case "pending": body += "<p>Your application was submitted \(DashboardFormat.date(application.submittedAt)) and is awaiting review. Handles and codes are issued only after verification.</p>"
            case "rejected":
                body += "<div class=\"notice dg\">Your application was declined\(application.decisionNote.map { ": " + DashboardUI.esc($0) } ?? ".")</div>"
                body += """
                <form method="post" action="/dashboard/organization">\(DashboardUI.csrf(p))\
                <label for="legalName">Legal name</label><input id="legalName" name="legalName" type="text" maxlength="120" value="\(DashboardUI.esc(application.legalName ?? ""))">\
                <label for="website">Website (https)</label><input id="website" name="website" type="url" maxlength="200" value="\(DashboardUI.esc(application.website ?? ""))">\
                <label for="requestedHandle">Requested handle</label><input id="requestedHandle" name="requestedHandle" type="text" maxlength="30" value="\(DashboardUI.esc(application.requestedHandle ?? ""))">\
                <label for="description">What will you use Viadere for?</label><textarea id="description" name="description" maxlength="500">\(DashboardUI.esc(application.detail ?? ""))</textarea>\
                <p><button class="btn" type="submit">Apply again</button></p></form>
                """
            default: body += "<p>Status: \(DashboardUI.esc(application.state)).</p>"
            }
        } else {
            body += "<p>This organization is \(DashboardUI.esc(business.verificationStatus)).</p>"
        }
        body += "</div>"
        return DashboardUI.businessPage(p, title: "Organization", active: "/dashboard/organization", flash: DashboardFormat.flash(req), body: body)
    }
}
