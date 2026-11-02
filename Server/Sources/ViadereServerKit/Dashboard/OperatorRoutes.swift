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
            <h1>Operator console</h1><p class="mu">Viadere staff only. Sign in with your passkey; every action you take here is audited with your name.</p>\
            <form data-passkey="login" data-begin="/operator/auth/login/begin" data-finish="/operator/auth/login/finish" data-next="/operator">\
            <div class="form-actions"><button class="btn wide" type="submit">\(ConsoleUI.icon(.key))Sign in with passkey</button></div></form><p id="pk-msg" class="sm err" role="alert"></p>
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
            <input type="hidden" name="token" value="\(DashboardUI.esc(token))"><div class="form-actions"><button class="btn wide" type="submit">\(ConsoleUI.icon(.key))Create passkey</button></div></form>\
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
        OperatorLoops.register(pages)
        OperatorBrand.register(pages)
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
        let rows = pending.map { a -> [ConsoleUI.Cell] in
            let b = byId[a.businessId]
            let name = b?.displayName ?? "—"
            return [ConsoleUI.Cell(html: "<a href=\"/operator/applications/\(a.businessId.uuidString.lowercased())\">\(DashboardUI.esc(name))</a>", sort: .text(name)),
                    .text(b?.category.replacingOccurrences(of: "_", with: " ") ?? ""), .text(a.requestedHandle.map { "@" + $0 } ?? "—"),
                    .text(a.website ?? "—"), .date(a.submittedAt),
                    ConsoleUI.Cell(html: ConsoleUI.linkButton("Review", href: "/operator/applications/\(a.businessId.uuidString.lowercased())", small: true, ariaLabel: "Review \(name)"))]
        }
        let counts = try await OperatorOps.queueCounts(req)
        let tiles = ConsoleUI.stats([
            ConsoleUI.Stat(String(pending.count), "Applications waiting", hint: pending.first.map { "Oldest: \(DashboardFormat.day($0.submittedAt))" }, tone: pending.isEmpty ? nil : .accent),
            ConsoleUI.Stat(String(counts.goLive), "Go-live requests", tone: counts.goLive > 0 ? .accent : nil, href: "#go-live"),
            ConsoleUI.Stat(String(counts.legal), "Legal entity reviews", tone: counts.legal > 0 ? .accent : nil, href: "#legal"),
            ConsoleUI.Stat(String(counts.brand), "Brand items waiting", tone: counts.brand > 0 ? .accent : nil, href: "/operator/brand"),
            ConsoleUI.Stat(String(counts.loops), "Loop revisions waiting", tone: counts.loops > 0 ? .accent : nil, href: "/operator/loops"),
            ConsoleUI.Stat(String(counts.support), "Open tickets and appeals", tone: counts.support > 0 ? .warning : nil, href: "/operator/support"),
        ])
        let table = ConsoleUI.card("Pending applications", description: "Oldest first. Verify the organization exists, the website is theirs and the use fits Viadere's policy.",
            ConsoleUI.table([ConsoleUI.Column("Organization", key: "org"), ConsoleUI.Column("Category", key: "category"), ConsoleUI.Column("Handle"), ConsoleUI.Column("Website"),
                             ConsoleUI.Column("Submitted", key: "submitted"), ConsoleUI.Column("", actions: true)], rows, caption: "Pending applications",
                            state: ConsoleUI.TableState(req, id: "a", defaultSort: "submitted"), empty: "No pending applications", emptyMessage: "New business applications appear here."))
        let queues = try await OperatorOps.queues(req)
        return DashboardUI.operatorPage(p, title: "Applications", active: "/operator", subtitle: "What waits for a decision, oldest first.", flash: DashboardFormat.flash(req),
                                        body: tiles + table + queues)
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
        let facts = ConsoleUI.card("Application", actions: DashboardFormat.statusBadge(business.status), ConsoleUI.keyValues([
            ("Display name", DashboardUI.esc(business.displayName)), ("Legal name", DashboardUI.esc(app.legalName ?? "—")), ("Category", DashboardUI.esc(business.category.replacingOccurrences(of: "_", with: " "))),
            ("Website", DashboardUI.esc(app.website ?? "—")), ("Requested handle", DashboardUI.esc(app.requestedHandle.map { "@" + $0 } ?? "—")), ("Owners", ownerLines.isEmpty ? "—" : ownerLines),
            ("Submitted", DashboardFormat.date(app.submittedAt)), ("State", DashboardUI.esc(app.state)),
        ]) + "<h3>What they will use Viadere for</h3><p>\(DashboardUI.esc(app.detail ?? "—"))</p>")
        var decide = ""
        if app.state == "pending" {
            let base = "/operator/applications/\(id.uuidString.lowercased())"
            let approve = ConsoleUI.card("Approve", description: "Issues the handle and a permanent code and makes the business discoverable.",
                ConsoleUI.form("\(base)/approve", csrf: DashboardUI.csrf(p),
                    ConsoleUI.input("handle", label: "Handle to issue", id: "handle", placeholder: app.requestedHandle ?? "", help: "Leave blank to issue the requested handle.", optional: true, attrs: ["maxlength": "30"])
                    + ConsoleUI.textarea("note", label: "Note", id: "anote", help: "Recorded with the decision.", optional: true, attrs: ["maxlength": "500"])
                    + ConsoleUI.formActions(ConsoleUI.button("Verify business", passkey: true) + ConsoleUI.passkeyNote())))
            let decline = ConsoleUI.card("Decline", description: "The applicant sees your reason and can apply again or appeal.", tone: .danger,
                ConsoleUI.form("\(base)/reject", csrf: DashboardUI.csrf(p),
                    ConsoleUI.textarea("note", label: "Reason", id: "rnote", help: "Shown to the applicant. Say what to fix.", attrs: ["maxlength": "500"])
                    + ConsoleUI.formActions(ConsoleUI.button("Decline", .danger, passkey: true))))
            decide = ConsoleUI.sectionTitle("Decision", description: "Both actions ask for your passkey and are audited with your name.") + "<div class=\"cols\">\(approve)\(decline)</div>"
        }
        return DashboardUI.operatorPage(p, title: business.displayName, active: "/operator", subtitle: "Business application", flash: DashboardFormat.flash(req),
                                        breadcrumbs: [ConsoleUI.Crumb("Operator", "/operator"), ConsoleUI.Crumb("Applications", "/operator"), ConsoleUI.Crumb(business.displayName, nil)],
                                        body: facts + decide)
    }

    private static func businesses(_ req: Request) async throws -> Response {
        let p = try operatorPrincipal(req)
        let all = try await BusinessRecord.query(on: req.db).sort(\.$createdAt, .descending).limit(200).all()
        let controls = try await BusinessControlRecord.query(on: req.db).all()
        let byId = Dictionary(controls.map { ($0.businessId, $0) }, uniquingKeysWith: { a, _ in a })
        let rows = all.map { b -> [ConsoleUI.Cell] in
            let c = b.id.flatMap { byId[$0] }
            var flags = ""
            if c?.throttled == true { flags += DashboardFormat.badge("Throttled", "dg") + " " }
            if let ceiling = c?.priorityCeiling { flags += DashboardFormat.badge("Cap: \(ceiling)", "mu") }
            return [ConsoleUI.Cell(html: "<a href=\"/operator/businesses/\(b.id?.uuidString.lowercased() ?? "")\">\(DashboardUI.esc(b.displayName))</a>", sort: .text(b.displayName)),
                    ConsoleUI.Cell(html: DashboardFormat.statusBadge(b.status), sort: .text(b.verificationStatus)), .text(b.tier), ConsoleUI.Cell(html: flags.isEmpty ? "<span class=\"mu\">—</span>" : flags), .date(b.createdAt)]
        }
        let verified = all.filter { $0.status == .verified }.count
        let suspended = all.filter { $0.status == .suspended }.count
        let tiles = ConsoleUI.stats([ConsoleUI.Stat(String(all.count), "Businesses", hint: all.count >= 200 ? "Newest 200 shown" : nil), ConsoleUI.Stat(String(verified), "Verified", tone: .success),
                                     ConsoleUI.Stat(String(suspended), "Suspended", tone: suspended > 0 ? .danger : nil), ConsoleUI.Stat(String(controls.filter(\.throttled).count), "Throttled")])
        return DashboardUI.operatorPage(p, title: "Businesses", active: "/operator/businesses", subtitle: "Every organization, its status and the controls Viadere applied.", flash: DashboardFormat.flash(req),
                                        body: tiles + ConsoleUI.panel(ConsoleUI.table([ConsoleUI.Column("Business", key: "name"), ConsoleUI.Column("Status", key: "status"), ConsoleUI.Column("Tier", key: "tier"),
                                                                                          ConsoleUI.Column("Controls"), ConsoleUI.Column("Created", key: "created")], rows, caption: "Businesses",
                                                                                         state: ConsoleUI.TableState(req, id: "b", defaultSort: "created", defaultAscending: false), pageSize: 50)))
    }

    private static func business(_ req: Request) async throws -> Response {
        let p = try operatorPrincipal(req)
        let id = try req.uuid("id")
        guard let business = try await BusinessRecord.find(id, on: req.db) else { throw APIError.notFound }
        let controls = try await BusinessControls.load(id, on: req.db)
        let m = try await AbuseService(db: req.db, ctx: req.ctx).metrics(for: id)
        let settings = await AbuseService(db: req.db, ctx: req.ctx).thresholds()
        let tiles = ConsoleUI.stats([
            ConsoleUI.Stat(String(m.issued), "Interactions (window)"),
            ConsoleUI.Stat(DashboardFormat.percent(m.complaintRate), "Complaint rate (limit \(DashboardFormat.percent(settings.complaintRate)))", tone: m.complaintRate >= settings.complaintRate ? .danger : nil),
            ConsoleUI.Stat(DashboardFormat.percent(m.optOutRate), "Opt-out rate (limit \(DashboardFormat.percent(settings.optOutRate)))", tone: m.optOutRate >= settings.optOutRate ? .danger : nil),
            ConsoleUI.Stat(String(m.rateLimitHits), "Rate-limit hits"),
        ])
        let csrf = DashboardUI.csrf(p)
        let base = "/operator/businesses/\(id.uuidString.lowercased())"
        let ceilingOptions = [("none", "No extra cap"), ("high", "High"), ("normal", "Normal"), ("low", "Low")].map { key, title in
            ConsoleUI.Option(key, title, selected: (controls?.priorityCeiling ?? "none") == key)
        }
        var statusBody = ConsoleUI.keyValues([("Status", DashboardFormat.statusBadge(business.status)), ("Plan", DashboardUI.esc(business.tier))]
                                             + (controls?.suspensionReason.map { [("Suspension reason", DashboardUI.esc($0))] } ?? []))
        if business.status == .verified {
            statusBody += "<h3>Suspend</h3>" + ConsoleUI.form("\(base)/suspend", csrf: csrf,
                ConsoleUI.reason(id: "reason", help: "Blocks the business's API keys and interactions immediately and cancels pending interactions. Recorded in the audit log.", minLength: 0)
                + ConsoleUI.formActions(ConsoleUI.button("Suspend", .danger, passkey: true) + ConsoleUI.passkeyNote()))
        } else if business.status == .suspended {
            statusBody += ConsoleUI.form("\(base)/unsuspend", csrf: csrf, ConsoleUI.formActions(ConsoleUI.button("Reinstate", passkey: true) + ConsoleUI.passkeyNote()))
        }
        let status = ConsoleUI.card("Status", tone: business.status == .suspended ? .danger : nil, statusBody)
        let throttleOn = controls?.throttled == true
        let controlsCard = ConsoleUI.card("Trust controls", description: "Overrides only ever restrict. A ceiling caps the priority the Trust Engine would allow; it can never raise it, and the billing plan is never consulted.", """
        <div class="cols">\(ConsoleUI.form("\(base)/ceiling", csrf: csrf, ConsoleUI.select("ceiling", label: "Priority ceiling", id: "ceiling", options: ceilingOptions) + ConsoleUI.formActions(ConsoleUI.button("Apply", .secondary, passkey: true))))\
        \(ConsoleUI.form("\(base)/throttle", csrf: csrf, ConsoleUI.input("reason", label: "Throttle (quota and API rate × \(settings.throttleFactor))", id: "reason2", placeholder: "Reason",
                                                                       help: throttleOn ? "Currently throttled (\(controls?.throttleSource ?? ""))." : "Recorded with the change.", attrs: ["maxlength": "200"])
            + ConsoleUI.hidden("throttled", throttleOn ? "off" : "on")
            + ConsoleUI.formActions(ConsoleUI.button(throttleOn ? "Clear throttle (currently \(controls?.throttleSource ?? ""))" : "Throttle", throttleOn ? .secondary : .danger, passkey: true))))</div>
        """)
        let entitlements = PolicyOperatorRoutes.summaryCard(businessId: id, snapshot: try await EntitlementService(db: req.db, ctx: req.ctx).snapshot(businessId: id))
        let ops = try await OperatorOps.businessPanel(req, p: p, business: business)
        return DashboardUI.operatorPage(p, title: business.displayName, active: "/operator/businesses", subtitle: "Status, onboarding, entitlements and controls. Every change needs your passkey.",
                                        flash: DashboardFormat.flash(req), body: tiles + "<div class=\"split\"><div>\(ops)</div><div>\(status)\(entitlements)\(controlsCard)</div></div>")
    }

    private static func abuse(_ req: Request) async throws -> Response {
        let p = try operatorPrincipal(req)
        let verified = try await BusinessRecord.query(on: req.db).filter(\.$verificationStatus == VerificationStatus.verified.rawValue).limit(200).all()
        let service = AbuseService(db: req.db, ctx: req.ctx)
        let settings = await service.thresholds()
        var entries: [(BusinessRecord, AbuseService.Metrics, BusinessControlRecord?)] = []
        for business in verified {
            guard let id = business.id else { continue }
            entries.append((business, try await service.metrics(for: id), try await BusinessControls.load(id, on: req.db)))
        }
        entries.sort { max($0.1.complaintRate, $0.1.optOutRate) > max($1.1.complaintRate, $1.1.optOutRate) }
        func rate(_ value: Double, limit: Double) -> ConsoleUI.Cell {
            ConsoleUI.Cell(html: value >= limit ? "<strong class=\"err\">\(DashboardFormat.percent(value))</strong>" : DashboardFormat.percent(value), sort: .number(value))
        }
        let rows = entries.map { business, m, c -> [ConsoleUI.Cell] in
            [ConsoleUI.Cell(html: "<a href=\"/operator/businesses/\(business.id?.uuidString.lowercased() ?? "")\">\(DashboardUI.esc(business.displayName))</a>", sort: .text(business.displayName)), .number(m.issued), .number(m.reports),
             rate(m.complaintRate, limit: settings.complaintRate), .number(m.optOuts), rate(m.optOutRate, limit: settings.optOutRate), .number(m.rateLimitHits),
             ConsoleUI.Cell(html: c?.throttled == true ? DashboardFormat.badge("Throttled: \(c?.throttleReason ?? "")", "dg") : DashboardFormat.badge("OK", "ok"), sort: .text(c?.throttled == true ? "a" : "b"))]
        }
        let over = entries.filter { $0.1.complaintRate >= settings.complaintRate || $0.1.optOutRate >= settings.optOutRate }.count
        let days = Int(settings.window / 86_400)
        let tiles = ConsoleUI.stats([ConsoleUI.Stat(String(entries.count), "Verified businesses"), ConsoleUI.Stat(String(over), "Over a limit", tone: over > 0 ? .danger : nil),
                                     ConsoleUI.Stat(DashboardFormat.percent(settings.complaintRate), "Complaint-rate limit"), ConsoleUI.Stat(DashboardFormat.percent(settings.optOutRate), "Opt-out-rate limit")])
        return DashboardUI.operatorPage(p, title: "Abuse signals", active: "/operator/abuse", subtitle: "Last \(days) days. Aggregates only; worst first.",
            actions: ConsoleUI.linkButton("Adjust thresholds", href: "/operator/switches#abuse", small: true),
            body: tiles + ConsoleUI.panel(ConsoleUI.table([ConsoleUI.Column("Business", key: "name"), ConsoleUI.Column("Issued", key: "issued", numeric: true), ConsoleUI.Column("Reports", key: "reports", numeric: true),
                                                           ConsoleUI.Column("Complaint rate", key: "complaints", numeric: true), ConsoleUI.Column("Opt-outs", key: "optouts", numeric: true),
                                                           ConsoleUI.Column("Opt-out rate", key: "optoutrate", numeric: true), ConsoleUI.Column("Rate-limit hits", key: "rl", numeric: true), ConsoleUI.Column("State", key: "state")],
                                                          rows, caption: "Abuse signals by business", state: ConsoleUI.TableState(req, id: "x"), pageSize: 50, empty: "No verified businesses yet.")))
    }
}
