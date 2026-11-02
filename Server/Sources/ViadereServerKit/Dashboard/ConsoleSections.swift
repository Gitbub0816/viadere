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
        let tiles = ConsoleUI.stats([
            ConsoleUI.Stat(String(o.totalIssued), "Messages and interactions (30 days)"),
            ConsoleUI.Stat(DashboardFormat.percent(o.channelSuccessRate), "SMS / RCS delivery success"),
            ConsoleUI.Stat(String(o.optOuts), "Opt-outs", href: p.can(.viewConsent) ? "/dashboard/consent" : nil),
            ConsoleUI.Stat(String(o.activeRelationships), "Connected customers", href: p.can(.viewConsent) ? "/dashboard/consent" : nil),
        ])
        let config = req.ctx.config
        let sms = config.twilio != nil || config.mailerSendSMS != nil
        func channel(_ name: String, _ on: Bool, _ state: String, _ detail: String) -> String {
            "<li class=\"\(on ? "t-success" : "t-neutral")\"><div>\(ConsoleUI.icon(.chat))<div><strong>\(DashboardUI.esc(name))</strong> \(ConsoleUI.pill(state, on ? .success : .neutral))<br><span class=\"mu sm\">\(DashboardUI.esc(detail))</span></div></div></li>"
        }
        let channels = ConsoleUI.card("Channels", description: "Customers choose their channels per purpose. Opt-outs (STOP) are honored for every channel and shown in Consent.", "<ul class=\"attn\">"
            + channel("In-app and push", true, "Always on", "The default for every message and the only channel for approvals.")
            + channel("SMS fallback", sms, sms ? "Available" : "Not configured", "Used only where the customer's consent allows it, and never for approvals.")
            + channel("RCS", config.rcs != nil, config.rcs != nil ? "Available" : "Not configured", "Rich messages where the carrier supports them.")
            + "</ul>")
        var shortcuts = ""
        if p.can(.manageCampaigns) { shortcuts += ConsoleUI.linkButton("Create a campaign link", href: "/dashboard/campaigns", .primary, small: true) }
        if p.can(.viewTemplates) { shortcuts += ConsoleUI.linkButton("Request templates", href: "/dashboard/templates", small: true) }
        if p.can(.viewInbox) { shortcuts += ConsoleUI.linkButton("Open the inbox", href: "/dashboard/inbox", small: true) }
        let mine = await ConsoleCards.shared.html(for: .messaging, req: req, principal: p, businessId: businessId)
        return DashboardUI.businessPage(p, title: "Messaging", active: "/dashboard/messaging", subtitle: "Delivery, consent and campaigns.", actions: shortcuts, body: tiles + channels + mine)
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
        let enabled = ConsoleUI.card("Capabilities", description: "Granted by Viadere after a purpose review (Tier V).",
                                     DashboardFormat.table(["Capability", "Tier", "State"], rows, empty: "No verification capabilities.", caption: "Verification capabilities"))
        let privacy = ConsoleUI.callout(.neutral, title: "Results, never identity data", "<p class=\"sm\">A result contains only what the capability defines, for example a yes or no for an age threshold. This page never shows names, birthdates, documents or other raw identity data.</p>")
        let metrics = try await VerifyDashboard.card(db: req.db, ctx: req.ctx, businessId: businessId, days: 30)
        let extra = await ConsoleCards.shared.html(for: .verify, req: req, principal: p, businessId: businessId)
        return DashboardUI.businessPage(p, title: "Verify", active: "/dashboard/verification", subtitle: "Settings and aggregate results. No raw identity data.", body: privacy + enabled + metrics + extra)
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
        let enabled = ConsoleUI.card("Capabilities", DashboardFormat.table(["Capability", "Tier", "State"], rows, empty: "No approval capabilities.", caption: "Approval capabilities"))
        let settings = ConsoleUI.card("Integration settings", description: "Approvals are signed on the customer's device and verified by you with the enrolled public key; the relay's status alone is never proof.", """
        \(ConsoleUI.stats([ConsoleUI.Stat(String(approvalKeys), "Keys with approval scope"), ConsoleUI.Stat(String(directoryKeys), "Keys that can publish to the key directory"),
                           ConsoleUI.Stat(String(approveHooks), "Endpoints subscribed to approval events")]))\
        <p class="mu sm">Transaction templates, challenge histories and suspicious-request reports appear here as aggregate counts only. \
        Create approval keys under <a href="/dashboard/api-keys">API keys</a> (a Security Admin or Owner issues them).</p>
        """)
        let extra = await ConsoleCards.shared.html(for: .approve, req: req, principal: p, businessId: businessId)
        let root = try await rootKeyCard(req, principal: p, businessId: businessId)
        return DashboardUI.businessPage(p, title: "Approve", active: "/dashboard/approve", subtitle: "Settings and aggregate metrics. No payloads.", flash: DashboardFormat.flash(req),
                                        body: "<div class=\"split\"><div>\(enabled)\(settings)</div><div>\(root)</div></div>" + extra)
    }

    /// The root key card (condition 4): who may register or change it, and the passkey-gated authorization.
    private static func rootKeyCard(_ req: Request, principal p: DashboardPrincipal, businessId: UUID) async throws -> String {
        let service = RootAuthorization(db: req.db, ctx: req.ctx)
        let state = try await KeyLogService(db: req.db, ctx: req.ctx).state(for: businessId)
        let verified = try await service.hasVerifiedDomain(businessId: businessId)
        let current = state.currentRoot.map { "<code>\(DashboardUI.esc($0.kid))</code>" } ?? "<span class=\"mu\">None registered</span>"
        var body = ConsoleUI.keyValues([("Current root key", current)])
            + "<p class=\"mu sm\">Your root key signs every key your customers' phones trust you with. Registering or replacing it is never possible with an API key alone: a person with the Security Admin or Owner role authorizes the exact key id here with a passkey, then publishes the signed entry from your tooling within 15 minutes. Every customer's phone alerts its owner when the root changes.</p>"
        if !verified {
            body += ConsoleUI.callout(.warning, title: "Domain not verified", "<p>Verify a domain you control under <a href=\"/dashboard/organization/domains\">Organization</a> before registering a root key.</p>")
        } else if p.can(.manageSecurity) {
            body += ConsoleUI.form("/dashboard/approve/root-authorizations", csrf: DashboardUI.csrf(p),
                ConsoleUI.input("rootKid", label: "Key id of the \(state.currentRoot == nil ? "root key to register" : "new root key")", id: "rk", help: "Exactly as your tooling prints it.", required: true,
                                attrs: ["maxlength": "64", "spellcheck": "false", "autocomplete": "off"])
                + ConsoleUI.formActions(ConsoleUI.button("Authorize with passkey", passkey: true) + ConsoleUI.passkeyNote("Valid for 15 minutes after you confirm.")))
        } else {
            body += ConsoleUI.callout(.neutral, "<p class=\"sm\">Ask a Security Admin or Owner to authorize a root key change.</p>")
        }
        return ConsoleUI.card("Root key", tone: state.currentRoot == nil ? .warning : nil, body)
    }

    // MARK: Support

    private static func ticketRows(_ tickets: [SupportTicketRecord]) -> [[ConsoleUI.Cell]] {
        tickets.map { [ConsoleUI.Cell(html: "<code>\(String($0.id?.uuidString.lowercased().prefix(8) ?? ""))</code>"), .text($0.subject),
                       ConsoleUI.Cell(html: DashboardFormat.badge($0.status, $0.status == "open" ? "wa" : "ok")), .date($0.createdAt), .text($0.operatorNote ?? "—")] }
    }

    private static func support(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewSupport)
        let origin = req.ctx.config.relyingPartyOrigin
        let docs = ConsoleUI.card("Documentation", """
        <h3>Build</h3><ul class="plain"><li><a href="\(origin)/developers/quickstart/" rel="noopener">Quickstart</a></li><li><a href="\(origin)/developers/authentication/" rel="noopener">Authentication and keys</a></li>\
        <li><a href="\(origin)/developers/webhooks/" rel="noopener">Webhooks</a></li></ul>\
        <h3>Troubleshoot</h3><ul class="plain"><li><a href="\(origin)/developers/errors/" rel="noopener">Errors</a></li><li><a href="\(origin)/developers/rate-limits/" rel="noopener">Rate limits</a></li>\
        <li><a href="\(origin)/developers/idempotency/" rel="noopener">Idempotency</a></li></ul>\
        <h3>Trust</h3><ul class="plain"><li><a href="\(origin)/status/" rel="noopener">Platform status</a></li><li><a href="\(origin)/security/" rel="noopener">Security</a></li>\
        <li><a href="\(origin)/legal/vulnerability-disclosure-policy/" rel="noopener">Report a vulnerability</a></li></ul>
        """)
        var form = ""
        if p.can(.manageSupport) {
            form = ConsoleUI.card("Contact support", description: "We reply by email to the address on your account.",
                ConsoleUI.form("/dashboard/support/tickets", csrf: DashboardUI.csrf(p),
                    ConsoleUI.input("subject", label: "Subject", id: "subject", required: true, attrs: ["maxlength": "120"])
                    + ConsoleUI.textarea("body", label: "What happened?", id: "body", help: "Include what you expected, what happened and when. Do not paste API keys, secrets or customers' personal data.", required: true, attrs: ["maxlength": "4000"])
                    + ConsoleUI.formActions(ConsoleUI.button("Send"))))
        }
        let tickets = try await SupportDesk(db: req.db, ctx: req.ctx).list(businessId: businessId).filter { $0.kind == "ticket" }
        let list = ConsoleUI.card("Your tickets", ConsoleUI.table([ConsoleUI.Column("Reference"), ConsoleUI.Column("Subject"), ConsoleUI.Column("Status"), ConsoleUI.Column("Opened"), ConsoleUI.Column("Reply")],
                                                                ticketRows(tickets), caption: "Support tickets", empty: "No tickets."))
        return DashboardUI.businessPage(p, title: "Support", active: "/dashboard/support", subtitle: "Help, status and appeals.", flash: DashboardFormat.flash(req),
                                        body: "<div class=\"split\"><div>\(form)\(list)</div><div>\(docs)</div></div>")
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
        let tiles = ConsoleUI.stats([
            ConsoleUI.Stat(String(delivered), "Webhook deliveries succeeded (24 h)", tone: .success),
            ConsoleUI.Stat(String(dead), "Dead-lettered deliveries", tone: dead > 0 ? .danger : nil, href: p.can(.viewWebhooks) ? "/dashboard/webhooks/deliveries" : nil),
            ConsoleUI.Stat(String(pending), "Deliveries waiting"),
            ConsoleUI.Stat(String(rateLimited), "Rate-limit hits (7 days)", tone: rateLimited > 0 ? .warning : nil),
        ])
        var findings: [(ConsoleUI.Tone, String, String?)] = []
        if hooks.contains(where: { $0.verifiedAt == nil }) && req.ctx.config.operations.webhookOwnershipVerification { findings.append((.danger, "An endpoint is not verified, so it receives no events.", "/dashboard/webhooks")) }
        if hooks.contains(where: { $0.pausedAt != nil }) { findings.append((.warning, "An endpoint is paused.", "/dashboard/webhooks")) }
        if dead > 0 { findings.append((.danger, "\(dead) deliveries were dead-lettered. Replay them from the delivery log once the endpoint recovers.", "/dashboard/webhooks/deliveries")) }
        if expiring > 0 { findings.append((.warning, "\(expiring) API key(s) expire within 14 days. Rotate them with an overlap.", "/dashboard/api-keys")) }
        if !state.contractsCurrent { findings.append((.warning, "An agreement needs your acceptance.", "/dashboard/compliance")) }
        if let message = maintenance { findings.append((.warning, "Viadere is in read-only maintenance: \(message)", nil)) }
        if paused { findings.append((.warning, "Webhook delivery is paused by Viadere for your organization.", nil)) }
        if restricted { findings.append((.warning, "Viadere restricted some outbound messaging for your organization.", nil)) }
        let list = findings.isEmpty
            ? ConsoleUI.empty("Everything looks healthy", "No open findings for your integration.", icon: .check)
            : "<ul class=\"attn\">" + findings.map { tone, text, href in
                "<li class=\"\(tone.cls)\"><div>\(ConsoleUI.icon(tone == .danger ? .error : .alert))<span>\(DashboardUI.esc(text))</span></div>\(href.map { ConsoleUI.linkButton("Fix", href: $0, small: true, ariaLabel: "Fix: \(text)") } ?? "")</li>"
            }.joined() + "</ul>"
        return DashboardUI.businessPage(p, title: "Integration health", active: "/dashboard/support/health", subtitle: "What needs attention, and where to fix it.",
                                        body: tiles + ConsoleUI.card("Findings", description: findings.isEmpty ? nil : "\(findings.count) open.", list))
    }

    private static func notices(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewSupport)
        let list = try await OperatorNotices(db: req.db, ctx: req.ctx).visibleToBusiness(businessId)
        let cards = list.map {
            ConsoleUI.card($0.title, description: DashboardFormat.date($0.createdAt), actions: DashboardFormat.badge($0.severity, $0.severity == "info" ? "mu" : ($0.severity == "critical" ? "dg" : "wa")),
                           tone: $0.severity == "critical" ? .danger : nil, "<p>\(DashboardUI.esc($0.body))</p>")
        }.joined()
        let maintenance = await PlatformFlags(db: req.db, ctx: req.ctx).maintenance().map { ConsoleUI.callout(.warning, title: "Read-only maintenance", "<p>\(DashboardUI.esc($0))</p>") } ?? ""
        return DashboardUI.businessPage(p, title: "Incident notices", active: "/dashboard/support/notices", subtitle: "Announcements from Viadere.",
                                        body: maintenance + (cards.isEmpty ? ConsoleUI.empty("No notices", "Incident and maintenance announcements from Viadere appear here and are emailed to your admins.", icon: .megaphone) : cards))
    }

    private static func appeals(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewSupport)
        let list = try await SupportDesk(db: req.db, ctx: req.ctx).list(businessId: businessId).filter { $0.kind == "appeal" }
        var form = ""
        if p.can(.manageSupport) {
            form = ConsoleUI.card("Appeal a decision", description: "A person at Viadere who was not involved reviews every appeal.",
                ConsoleUI.form("/dashboard/support/appeals", csrf: DashboardUI.csrf(p),
                    ConsoleUI.input("subject", label: "Which decision?", id: "subject", help: "For example: suspension, declined application, throttle, declined production access.", required: true, attrs: ["maxlength": "120"])
                    + ConsoleUI.textarea("body", label: "Why should it be reviewed?", id: "body", required: true, attrs: ["maxlength": "4000"])
                    + ConsoleUI.formActions(ConsoleUI.button("Submit appeal"))))
        }
        return DashboardUI.businessPage(p, title: "Appeals", active: "/dashboard/support/appeals", subtitle: "Ask for a decision to be reviewed.", flash: DashboardFormat.flash(req),
                                        body: form + ConsoleUI.card("Your appeals", ConsoleUI.table([ConsoleUI.Column("Reference"), ConsoleUI.Column("Decision"), ConsoleUI.Column("Status"), ConsoleUI.Column("Submitted"), ConsoleUI.Column("Reply")],
                                                                                                     ticketRows(list), caption: "Appeals", empty: "No appeals.")))
    }
}

enum ConsoleRoutes {
    /// Registers every WP6 console page on the authenticated business group.
    static func register(_ pages: any RoutesBuilder) {
        ConsoleOrganization.register(pages)
        ProfileConsole.register(pages)
        ConsoleSurface.register(pages)
        ConsoleInbox.register(pages)
        ConsoleLoopStudio.register(pages)
        ConsoleBrandStudio.register(pages)
        ConsoleDevelopers.register(pages)
        ConsoleSecurity.register(pages)
        ConsoleCompliance.register(pages)
        ConsoleSections.register(pages)
    }
}
