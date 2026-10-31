import Fluent
import Foundation
import Vapor
import ViadereCore

private struct RootAuthorizationForm: Content {
    var rootKid: String
}

private struct TicketForm: Content {
    var subject: String
    var body: String
    var topic: String?
}

/// Extension points for the Verify and Approve sections (and any other): another module registers a card, the section page renders it. A card
/// returns HTML for **settings and aggregate metrics only** (counts, rates, states); raw identity data, signed payloads and customer references
/// must never be rendered in the console. The section pages show an empty-state note when no card is registered.
final class ConsoleCards: @unchecked Sendable {
    enum Section: String, Sendable { case verify, approve, messaging }

    struct Provider: Sendable {
        var section: Section
        var order: Int
        var render: @Sendable (_ req: Request, _ principal: DashboardPrincipal, _ businessId: UUID) async throws -> String
    }

    static let shared = ConsoleCards()
    private let lock = NSLock()
    private var providers: [Provider] = []

    func register(section: Section, order: Int = 100, render: @escaping @Sendable (Request, DashboardPrincipal, UUID) async throws -> String) {
        lock.withLock { providers.append(Provider(section: section, order: order, render: render)) }
    }

    func html(for section: Section, req: Request, principal: DashboardPrincipal, businessId: UUID) async -> String {
        let selected = lock.withLock { providers.filter { $0.section == section }.sorted { $0.order < $1.order } }
        var out = ""
        for provider in selected {
            do { out += try await provider.render(req, principal, businessId) } catch {
                req.logger.warning("console card failed", metadata: ["section": "\(section.rawValue)", "type": "\(type(of: error))"])
            }
        }
        return out
    }
}

/// Messaging, Verify, Approve (settings and metrics only) and Support sections.
enum ConsoleSections {
    static func register(_ pages: any RoutesBuilder) {
        pages.get("dashboard", "messaging") { req in try await messaging(req) }
        pages.get("dashboard", "verification") { req in try await verify(req) }
        pages.get("dashboard", "approve") { req in try await approve(req) }
        pages.post("dashboard", "approve", "root-authorizations") { req -> Response in
            let (p, _) = try req.businessDashboard
            let form = try req.content.decode(RootAuthorizationForm.self)
            let actions = DashboardActions(db: req.db, ctx: req.ctx, principal: p)
            try actions.require(.manageSecurity)
            try await actions.requireReauth(next: "/dashboard/approve")
            try await actions.authorizeRootKey(kid: form.rootKid.trimmingCharacters(in: .whitespacesAndNewlines))
            return DashboardResponses.redirect("/dashboard/approve?m=root-authorized")
        }
        pages.get("dashboard", "support") { req in try await support(req) }
        pages.post("dashboard", "support", "tickets") { req -> Response in
            let (p, _) = try req.businessDashboard
            let form = try req.content.decode(TicketForm.self)
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).openTicket(kind: "ticket", subject: form.subject, body: form.body)
            return DashboardResponses.redirect("/dashboard/support?m=ticket")
        }
        pages.get("dashboard", "support", "health") { req in try await health(req) }
        pages.get("dashboard", "support", "notices") { req in try await notices(req) }
        pages.get("dashboard", "support", "appeals") { req in try await appeals(req) }
        pages.post("dashboard", "support", "appeals") { req -> Response in
            let (p, _) = try req.businessDashboard
            let form = try req.content.decode(TicketForm.self)
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).openTicket(kind: "appeal", subject: form.subject, body: form.body)
            return DashboardResponses.redirect("/dashboard/support/appeals?m=ticket")
        }
    }

    // MARK: Messaging

    private static func messaging(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        guard p.can(.viewMessaging) || p.can(.viewConsent) || p.can(.manageCampaigns) else { throw APIError.forbidden }
        let o = try await DashboardAnalytics(db: req.db, ctx: req.ctx).overview(businessId: businessId, days: 30)
        let tiles = "<div class=\"grid\">\(DashboardFormat.stat(String(o.totalIssued), "Messages and interactions (30 days)"))\(DashboardFormat.stat(DashboardFormat.percent(o.channelSuccessRate), "SMS / RCS delivery success"))"
            + "\(DashboardFormat.stat(String(o.optOuts), "Opt-outs"))\(DashboardFormat.stat(String(o.activeRelationships), "Connected customers"))</div>"
        let config = req.ctx.config
        let channels = """
        <div class="card"><h2>Channels</h2><ul>\
        <li>In-app and push: always on. Customers choose their channels per purpose.</li>\
        <li>SMS fallback: \(config.twilio != nil || config.mailerSendSMS != nil ? "available" : "not configured on this deployment"); it is used only where the customer's consent allows it and never for approvals.</li>\
        <li>RCS: \(config.rcs != nil ? "available" : "not configured on this deployment").</li>\
        <li>Opt-outs (STOP) are honored for every channel and shown in Consent.</li></ul>\
        <p class="mu sm">Templates for common interactions are under <a href="/dashboard/templates">Developers &gt; Templates</a>. Inbox and agent assignment are not offered yet.</p></div>
        """
        let mine = await ConsoleCards.shared.html(for: .messaging, req: req, principal: p, businessId: businessId)
        return DashboardUI.businessPage(p, title: "Messaging", active: "/dashboard/messaging", subtitle: "Delivery, consent and campaigns.", body: tiles + channels + mine)
    }

    // MARK: Verify and Approve (settings and metrics only)

    private static func capabilityRows(_ req: Request, businessId: UUID, include: (CapabilityDefinition) -> Bool) async throws -> [[String]] {
        let entitled = try await EntitlementService(db: req.db, ctx: req.ctx).snapshot(businessId: businessId)
        let switches = try await CapabilitySwitchRecord.query(on: req.db).filter(\.$disabled == true).all()
        return CapabilityCatalog.definitions.filter(include).map { definition in
            let capability = definition.capability
            let has = entitled.capabilities.contains(capability) && entitled.tiers.contains(definition.minimumTier)
            let off = switches.contains { $0.capability == capability.rawValue && ($0.scope == CapabilitySwitchRecord.globalScope || $0.scope == businessId.uuidString.lowercased()) }
            let state = off ? DashboardFormat.badge("Switched off by Viadere", "dg") : (has ? DashboardFormat.badge("Enabled", "ok") : DashboardFormat.badge("Not enabled", "mu"))
            return ["<code>\(DashboardUI.esc(capability.rawValue))</code>", "Tier \(definition.minimumTier.rawValue)", state]
        }
    }

    private static func verify(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewVerify)
        let rows = try await capabilityRows(req, businessId: businessId) { $0.minimumTier == .v }
        let enabled = "<div class=\"card\"><h2>Capabilities</h2>\(DashboardFormat.table(["Capability", "Tier", "State"], rows, empty: "No verification capabilities.", caption: "Verification capabilities"))"
            + "<p class=\"mu sm\">Verification capabilities are granted by Viadere after a purpose review (Tier V). A result contains only what the capability defines, for example a yes or no for an age threshold; this page never shows names, birthdates, documents or other raw identity data.</p></div>"
        let metrics = try await VerifyDashboard.card(db: req.db, ctx: req.ctx, businessId: businessId, days: 30)
        let extra = await ConsoleCards.shared.html(for: .verify, req: req, principal: p, businessId: businessId)
        return DashboardUI.businessPage(p, title: "Verify", active: "/dashboard/verification", subtitle: "Settings and aggregate results. No raw identity data.", body: enabled + metrics + extra)
    }

    private static func approve(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewApprove)
        let rows = try await capabilityRows(req, businessId: businessId) { $0.minimumTier == .a }
        let keys = try await BusinessAPIKeyRecord.query(on: req.db).filter(\.$businessId == businessId).filter(\.$revokedAt == nil).all().filter { $0.isUsable(at: req.ctx.now) }
        let approvalKeys = keys.filter { $0.scopeSet.contains(BusinessAPIKeys.Scope.approvalsManage) }.count
        let directoryKeys = keys.filter { $0.scopeSet.contains(BusinessAPIKeys.Scope.keyDirectoryManage) }.count
        let hooks = try await WebhookSubscriptionRecord.query(on: req.db).filter(\.$businessId == businessId).filter(\.$active == true).all()
        let approveHooks = hooks.filter { $0.events.contains("approve.") }.count
        let enabled = "<div class=\"card\"><h2>Capabilities</h2>\(DashboardFormat.table(["Capability", "Tier", "State"], rows, empty: "No approval capabilities.", caption: "Approval capabilities"))</div>"
        let settings = """
        <div class="card"><h2>Integration settings</h2><div class="grid">\(DashboardFormat.stat(String(approvalKeys), "Keys with approval scope"))\(DashboardFormat.stat(String(directoryKeys), "Keys that can publish to the key directory"))\
        \(DashboardFormat.stat(String(approveHooks), "Endpoints subscribed to approval events"))</div>\
        <p class="mu sm">Approvals are signed on the customer's device and verified by you with the enrolled public key; the relay's status alone is never proof. Transaction templates, challenge histories and suspicious-request reports appear here as aggregate counts only. \
        Create approval keys under <a href="/dashboard/api-keys">API keys</a> (a Security Admin or Owner issues them).</p></div>
        """
        let extra = await ConsoleCards.shared.html(for: .approve, req: req, principal: p, businessId: businessId)
        let root = try await rootKeyCard(req, principal: p, businessId: businessId)
        return DashboardUI.businessPage(p, title: "Approve", active: "/dashboard/approve", subtitle: "Settings and aggregate metrics. No payloads.", flash: DashboardFormat.flash(req),
                                        body: enabled + settings + root + extra)
    }

    /// The root key card (condition 4): who may register or change it, and the passkey-gated authorization.
    private static func rootKeyCard(_ req: Request, principal p: DashboardPrincipal, businessId: UUID) async throws -> String {
        let service = RootAuthorization(db: req.db, ctx: req.ctx)
        let state = try await KeyLogService(db: req.db, ctx: req.ctx).state(for: businessId)
        let verified = try await service.hasVerifiedDomain(businessId: businessId)
        let current = state.currentRoot.map { "<code>\(DashboardUI.esc($0.kid))</code>" } ?? "none registered"
        var body = "<div class=\"card\"><h2>Root key</h2><p>Current root key: \(current)</p>"
            + "<p class=\"mu sm\">Your root key signs every key your customers' phones trust you with. Registering or replacing it is never possible with an API key alone: a person with the Security Admin or Owner role authorizes the exact key id here with a passkey, then publishes the signed entry from your tooling within 15 minutes. Every customer's phone alerts its owner when the root changes.</p>"
        if !verified {
            body += "<p>\(DashboardFormat.badge("Domain not verified", "dg")) Verify a domain you control under Organization before registering a root key.</p>"
        } else if p.can(.manageSecurity) {
            body += "<form method=\"post\" action=\"/dashboard/approve/root-authorizations\">\(DashboardUI.csrf(p))"
                + "<label for=\"rk\">Key id of the \(state.currentRoot == nil ? "root key to register" : "new root key")</label><input id=\"rk\" name=\"rootKid\" type=\"text\" maxlength=\"64\" required spellcheck=\"false\" autocomplete=\"off\">"
                + "<button class=\"btn\" type=\"submit\">Authorize with passkey</button></form>"
        } else {
            body += "<p class=\"mu sm\">Ask a Security Admin or Owner to authorize a root key change.</p>"
        }
        return body + "</div>"
    }

    // MARK: Support

    private static func support(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewSupport)
        let origin = req.ctx.config.relyingPartyOrigin
        let docs = """
        <div class="card"><h2>Documentation</h2><ul>\
        <li><a href="\(origin)/developers/quickstart/" rel="noopener">Quickstart</a> · <a href="\(origin)/developers/authentication/" rel="noopener">Authentication and keys</a> · <a href="\(origin)/developers/webhooks/" rel="noopener">Webhooks</a></li>\
        <li><a href="\(origin)/developers/errors/" rel="noopener">Errors</a> · <a href="\(origin)/developers/rate-limits/" rel="noopener">Rate limits</a> · <a href="\(origin)/developers/idempotency/" rel="noopener">Idempotency</a></li>\
        <li><a href="\(origin)/status/" rel="noopener">Platform status</a> · <a href="\(origin)/security/" rel="noopener">Security</a> · <a href="\(origin)/legal/vulnerability-disclosure-policy/" rel="noopener">Report a vulnerability</a></li></ul></div>
        """
        var form = ""
        if p.can(.manageSupport) {
            form = """
            <div class="card"><h2>Contact support</h2><form method="post" action="/dashboard/support/tickets">\(DashboardUI.csrf(p))\
            <label for="subject">Subject</label><input id="subject" name="subject" type="text" maxlength="120" required>\
            <label for="body">What happened?</label><textarea id="body" name="body" maxlength="4000" required></textarea>\
            <p class="mu sm">Do not paste API keys, secrets or customers' personal data. We reply by email to the address on your account.</p><button class="btn" type="submit">Send</button></form></div>
            """
        }
        let tickets = try await SupportDesk(db: req.db, ctx: req.ctx).list(businessId: businessId).filter { $0.kind == "ticket" }
        let rows = tickets.map { [String($0.id?.uuidString.lowercased().prefix(8) ?? ""), DashboardUI.esc($0.subject), DashboardFormat.badge($0.status, $0.status == "open" ? "" : "ok"), DashboardFormat.date($0.createdAt), DashboardUI.esc($0.operatorNote ?? "—")] }
        let list = "<div class=\"card\"><h2>Your tickets</h2>\(DashboardFormat.table(["Reference", "Subject", "Status", "Opened", "Reply"], rows, empty: "No tickets.", caption: "Support tickets"))</div>"
        return DashboardUI.businessPage(p, title: "Support", active: "/dashboard/support", subtitle: "Help, status and appeals.", flash: DashboardFormat.flash(req), body: docs + form + list)
    }

    private static func health(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewSupport)
        let now = req.ctx.now
        let day = now.addingTimeInterval(-86_400)
        let week = now.addingTimeInterval(-7 * 86_400)
        let delivered = try await WebhookDeliveryRecord.query(on: req.db).filter(\.$businessId == businessId).filter(\.$createdAt >= day).filter(\.$status == "succeeded").count()
        let dead = try await WebhookDeliveryRecord.query(on: req.db).filter(\.$businessId == businessId).filter(\.$status == "dead").count()
        let pending = try await WebhookDeliveryRecord.query(on: req.db).filter(\.$businessId == businessId).filter(\.$status == "pending").count()
        let hooks = try await WebhookSubscriptionRecord.query(on: req.db).filter(\.$businessId == businessId).filter(\.$active == true).all()
        let rateLimited = try await AbuseSignalRecord.query(on: req.db).filter(\.$businessId == businessId).filter(\.$kind == "rate_limited").filter(\.$bucket >= Int(week.timeIntervalSince1970 / 60)).all().reduce(0) { $0 + $1.count }
        let keys = try await BusinessAPIKeyRecord.query(on: req.db).filter(\.$businessId == businessId).filter(\.$revokedAt == nil).all().filter { $0.isUsable(at: now) }
        let expiring = keys.filter { ($0.expiresAt ?? .distantFuture) < now.addingTimeInterval(14 * 86_400) }.count
        let flags = PlatformFlags(db: req.db, ctx: req.ctx)
        let maintenance = await flags.maintenance()
        let paused = await flags.webhooksPaused(businessId: businessId)
        let restricted = !(await flags.restrictions(businessId: businessId)).isEmpty
        let state = try await OnboardingService(db: req.db, ctx: req.ctx).state(businessId: businessId)
        let tiles = "<div class=\"grid\">\(DashboardFormat.stat(String(delivered), "Webhook deliveries succeeded (24 h)"))\(DashboardFormat.stat(String(dead), "Dead-lettered deliveries"))\(DashboardFormat.stat(String(pending), "Deliveries waiting"))\(DashboardFormat.stat(String(rateLimited), "Rate-limit hits (7 days)"))</div>"
        var findings: [String] = []
        if hooks.contains(where: { $0.verifiedAt == nil }) && req.ctx.config.operations.webhookOwnershipVerification { findings.append("An endpoint is not verified, so it receives no events.") }
        if hooks.contains(where: { $0.pausedAt != nil }) { findings.append("An endpoint is paused.") }
        if dead > 0 { findings.append("\(dead) deliveries were dead-lettered. Replay them from the delivery log once the endpoint recovers.") }
        if expiring > 0 { findings.append("\(expiring) API key(s) expire within 14 days. Rotate them with an overlap.") }
        if !state.contractsCurrent { findings.append("An agreement needs your acceptance.") }
        if let message = maintenance { findings.append("Viadere is in read-only maintenance: \(message)") }
        if paused { findings.append("Webhook delivery is paused by Viadere for your organization.") }
        if restricted { findings.append("Viadere restricted some outbound messaging for your organization.") }
        let list = findings.isEmpty ? "<p>Everything looks healthy.</p>" : "<ul>\(findings.map { "<li>\(DashboardUI.esc($0))</li>" }.joined())</ul>"
        return DashboardUI.businessPage(p, title: "Integration health", active: "/dashboard/support/health", subtitle: "What needs attention.", body: tiles + "<div class=\"card\"><h2>Findings</h2>\(list)</div>")
    }

    private static func notices(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewSupport)
        let list = try await OperatorNotices(db: req.db, ctx: req.ctx).visibleToBusiness(businessId)
        let cards = list.map { "<div class=\"card\"><h2>\(DashboardUI.esc($0.title)) \(DashboardFormat.badge($0.severity, $0.severity == "info" ? "mu" : "dg"))</h2><p class=\"mu sm\">\(DashboardFormat.date($0.createdAt))</p><p>\(DashboardUI.esc($0.body))</p></div>" }.joined()
        let maintenance = await PlatformFlags(db: req.db, ctx: req.ctx).maintenance().map { "<div class=\"notice dg\" role=\"status\">Read-only maintenance: \(DashboardUI.esc($0))</div>" } ?? ""
        return DashboardUI.businessPage(p, title: "Incident notices", active: "/dashboard/support/notices", subtitle: "Announcements from Viadere.", body: maintenance + (cards.isEmpty ? "<p class=\"mu\">No notices.</p>" : cards))
    }

    private static func appeals(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewSupport)
        let list = try await SupportDesk(db: req.db, ctx: req.ctx).list(businessId: businessId).filter { $0.kind == "appeal" }
        let rows = list.map { [String($0.id?.uuidString.lowercased().prefix(8) ?? ""), DashboardUI.esc($0.subject), DashboardFormat.badge($0.status, $0.status == "open" ? "" : "ok"), DashboardFormat.date($0.createdAt), DashboardUI.esc($0.operatorNote ?? "—")] }
        var form = ""
        if p.can(.manageSupport) {
            form = """
            <div class="card"><h2>Appeal a decision</h2><form method="post" action="/dashboard/support/appeals">\(DashboardUI.csrf(p))\
            <label for="subject">Which decision? (for example: suspension, declined application, throttle, declined production access)</label><input id="subject" name="subject" type="text" maxlength="120" required>\
            <label for="body">Why should it be reviewed?</label><textarea id="body" name="body" maxlength="4000" required></textarea>\
            <p class="mu sm">A person at Viadere who was not involved reviews every appeal.</p><button class="btn" type="submit">Submit appeal</button></form></div>
            """
        }
        return DashboardUI.businessPage(p, title: "Appeals", active: "/dashboard/support/appeals", subtitle: "Ask for a decision to be reviewed.", flash: DashboardFormat.flash(req),
                                        body: form + "<div class=\"card\"><h2>Your appeals</h2>\(DashboardFormat.table(["Reference", "Decision", "Status", "Submitted", "Reply"], rows, empty: "No appeals.", caption: "Appeals"))</div>")
    }
}

enum ConsoleRoutes {
    /// Registers every WP6 console page on the authenticated business group.
    static func register(_ pages: any RoutesBuilder) {
        ConsoleOrganization.register(pages)
        ProfileConsole.register(pages)
        ConsoleSurface.register(pages)
        ConsoleInbox.register(pages)
        ConsoleBrandStudio.register(pages)
        ConsoleDevelopers.register(pages)
        ConsoleSecurity.register(pages)
        ConsoleCompliance.register(pages)
        ConsoleSections.register(pages)
    }
}
