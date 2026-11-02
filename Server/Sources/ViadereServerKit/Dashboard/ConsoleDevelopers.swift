import Fluent
import Foundation
import Vapor
import ViadereCore

private struct KeyForm: Content {
    var name: String
    var mode: String?
    var scopes: [String]?
    var capabilities: [String]?
    /// `1` when the form showed the capability boxes: an empty selection then means "none" rather than "default".
    var capabilitiesChosen: String?
    var expires: Int?
    var ipAllowlist: String?
    var requireMtls: String?
}

private struct RotateForm: Content { var overlap: Int? }
private struct WebhookForm: Content {
    var url: String
    var events: [String]?
    var opaque: String?
}
private struct ReasonField: Content { var reason: String? }
private struct ReplyForm: Content {
    var relationshipId: String
    var text: String
}

/// Developers section (spec §9.1): credentials with the full lifecycle, signed webhooks with ownership verification and tooling, the sandbox.
enum ConsoleDevelopers {
    static func register(_ pages: any RoutesBuilder) {
        pages.get("dashboard", "developers") { req in try await overview(req) }
        pages.get("dashboard", "api-keys") { req in try await apiKeysPage(req) }
        pages.post("dashboard", "api-keys") { req in try await createKey(req) }
        pages.post("dashboard", "api-keys", ":id", "revoke") { req -> Response in
            let (p, _) = try req.businessDashboard
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).revokeAPIKey(id: try req.uuid("id"))
            return DashboardResponses.redirect("/dashboard/api-keys?m=revoked")
        }
        pages.post("dashboard", "api-keys", ":id", "rotate") { req in try await rotateKey(req) }
        pages.post("dashboard", "api-keys", "approved", ":id") { req in try await completeApproved(req) }
        pages.get("dashboard", "webhooks") { req in try await webhooksPage(req) }
        pages.post("dashboard", "webhooks") { req in try await createWebhook(req) }
        pages.post("dashboard", "webhooks", ":id", "rotate") { req in
            let (p, _) = try req.businessDashboard
            return secretPage(p, response: try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).rotateWebhook(id: try req.uuid("id")), heading: "Secret rotated")
        }
        pages.post("dashboard", "webhooks", ":id", "delete") { req -> Response in
            let (p, _) = try req.businessDashboard
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).deleteWebhook(id: try req.uuid("id"))
            return DashboardResponses.redirect("/dashboard/webhooks?m=deleted")
        }
        pages.post("dashboard", "webhooks", ":id", "verify") { req in try await verifyEndpoint(req) }
        pages.post("dashboard", "webhooks", ":id", "test") { req -> Response in
            let (p, _) = try req.businessDashboard
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).sendTestEvent(id: try req.uuid("id"))
            return DashboardResponses.redirect("/dashboard/webhooks?m=test")
        }
        pages.post("dashboard", "webhooks", ":id", "pause") { req -> Response in
            let (p, _) = try req.businessDashboard
            let form = try? req.content.decode(ReasonField.self)
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).setWebhookPaused(id: try req.uuid("id"), paused: true, reason: form?.reason ?? "")
            return DashboardResponses.redirect("/dashboard/webhooks?m=paused")
        }
        pages.post("dashboard", "webhooks", ":id", "resume") { req -> Response in
            let (p, _) = try req.businessDashboard
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).setWebhookPaused(id: try req.uuid("id"), paused: false, reason: "")
            return DashboardResponses.redirect("/dashboard/webhooks?m=resumed")
        }
        pages.get("dashboard", "webhooks", "schemas") { req in try await schemasPage(req) }
        pages.get("dashboard", "webhooks", "simulate") { req in try await simulatePage(req) }
        pages.get("dashboard", "webhooks", "deliveries") { req in try await deliveriesPage(req) }
        pages.get("dashboard", "webhooks", "deliveries", ":id") { req in try await deliveryPage(req) }
        pages.post("dashboard", "webhooks", "deliveries", ":id", "replay") { req -> Response in
            let (p, _) = try req.businessDashboard
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).replayDelivery(id: try req.uuid("id"))
            return DashboardResponses.redirect("/dashboard/webhooks/deliveries?m=replayed")
        }
        pages.get("dashboard", "developers", "sandbox") { req in try await sandboxPage(req) }
        pages.post("dashboard", "developers", "sandbox", "customer") { req -> Response in
            let (p, _) = try req.businessDashboard
            _ = try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).createSandboxCustomer()
            return DashboardResponses.redirect("/dashboard/developers/sandbox?m=sandbox")
        }
        pages.post("dashboard", "developers", "sandbox", "reply") { req -> Response in
            let (p, _) = try req.businessDashboard
            let form = try req.content.decode(ReplyForm.self)
            guard let id = UUID(uuidString: form.relationshipId) else { throw APIError.notFound }
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).simulateSandboxReply(relationshipId: id, text: form.text)
            return DashboardResponses.redirect("/dashboard/developers/sandbox?m=reply")
        }
    }

    // MARK: Overview

    private static func overview(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        guard p.can(.viewAPIKeys) || p.can(.viewWebhooks) || p.can(.viewTemplates) else { throw APIError.forbidden }
        let keys = try await BusinessAPIKeyRecord.query(on: req.db).filter(\.$businessId == businessId).filter(\.$revokedAt == nil).all().filter { $0.isUsable(at: req.ctx.now) }
        let hooks = try await WebhookSubscriptionRecord.query(on: req.db).filter(\.$businessId == businessId).filter(\.$active == true).all()
        let state = try await OnboardingService(db: req.db, ctx: req.ctx).state(businessId: businessId)
        let verifiedHooks = hooks.filter { $0.verifiedAt != nil }.count
        let tiles = ConsoleUI.stats([
            ConsoleUI.Stat(String(keys.filter { !$0.livemode }.count), "Sandbox keys", href: p.can(.viewAPIKeys) ? "/dashboard/api-keys" : nil),
            ConsoleUI.Stat(String(keys.filter(\.livemode).count), "Live keys", hint: state.goLive == .approved ? nil : "Unlock after the go-live review", href: p.can(.viewAPIKeys) ? "/dashboard/api-keys" : nil),
            ConsoleUI.Stat("\(verifiedHooks) / \(hooks.count)", "Verified endpoints", tone: hooks.count > verifiedHooks ? .warning : nil, href: p.can(.viewWebhooks) ? "/dashboard/webhooks" : nil),
            ConsoleUI.Stat(state.stage.rawValue.capitalized, "Onboarding stage"),
        ])
        let ownership = req.ctx.config.operations.webhookOwnershipVerification
        let steps = ConsoleUI.checklist([
            ConsoleUI.Step(state.domainVerified, "Verify a domain you control", "<a href=\"/dashboard/organization/domains\">Organization &gt; Domains</a>"),
            ConsoleUI.Step(state.sandboxKey, "Create a sandbox key", "In <a href=\"/dashboard/api-keys\">API keys</a>. The secret is shown once."),
            ConsoleUI.Step(state.testCustomer, "Create a test customer", "In the <a href=\"/dashboard/developers/sandbox\">sandbox</a>; nothing reaches a real person."),
            ConsoleUI.Step(hooks.contains { $0.verifiedAt != nil || !ownership }, "Add and verify a webhook endpoint", "In <a href=\"/dashboard/webhooks\">Webhooks</a>; then receive a signed test reply."),
            ConsoleUI.Step(state.goLive == .approved, "Request production access", "From <a href=\"/dashboard/organization\">Organization</a>. No VPN or private network is needed."),
        ], label: "Quickstart")
        let sample = """
        <pre><code>curl -X POST \(DashboardUI.esc(req.ctx.config.publicBaseURL))/v1/business/messages \\
          -H "Authorization: Bearer vdk_test_&lt;key id&gt;.&lt;secret&gt;" \\
          -H "Idempotency-Key: msg-0001" -H "Content-Type: application/json" \\
          -d '{"relationshipId":"&lt;sandbox relationship&gt;","body":"Hello","idempotencyKey":"msg-0001"}'</code></pre>\
        <p class="mu sm">The OpenAPI description is in the developer documentation. Webhooks are signed with <code>Viadere-Signature</code>; each delivery names its <code>Viadere-Delivery-Id</code> and the <code>Viadere-Key-Id</code> of the signing secret.</p>
        """
        let body = tiles + "<div class=\"split\"><div>" + ConsoleUI.card("Quickstart", description: "From zero to a signed test event, in order.", steps) + "</div><div>"
            + ConsoleUI.card("Send your first message", sample) + "</div></div>"
        return DashboardUI.businessPage(p, title: "Developers", active: "/dashboard/developers", subtitle: "Credentials, webhooks and the sandbox.", flash: DashboardFormat.flash(req), body: body)
    }

    // MARK: API keys

    private static func overlapLabel(_ seconds: Int) -> String {
        switch seconds {
        case 0: "No overlap"
        case 3600: "1 hour overlap"
        case 86_400: "1 day overlap"
        case 7 * 86_400: "7 days overlap"
        default: "30 days overlap"
        }
    }

    private static func apiKeysPage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewAPIKeys)
        let keys = try await BusinessAPIKeyRecord.query(on: req.db).filter(\.$businessId == businessId).sort(\.$createdAt, .descending).all()
        let now = req.ctx.now
        let canManage = p.can(.manageAPIKeys)
        let canRevoke = p.can(.revokeAPIKeys)
        let rows = keys.map { key -> [ConsoleUI.Cell] in
            let status: String
            if key.revokedAt != nil { status = DashboardFormat.badge("Revoked", "dg") }
            else if let exp = key.expiresAt, exp <= now { status = DashboardFormat.badge("Expired", "mu") }
            else if let end = key.autoRevokeAt { status = end <= now ? DashboardFormat.badge("Revoked", "dg") : DashboardFormat.badge("Rotating until \(DashboardFormat.date(end))", "wa") }
            else { status = DashboardFormat.badge(key.livemode ? "Live" : "Test", key.livemode ? "ok" : "mu") }
            var restrictions: [String] = []
            if let ips = key.ipAllowlist, !ips.isEmpty { restrictions.append("IPs: \(ips.split(separator: ",").count)") }
            if key.requiresMTLS { restrictions.append("mTLS") }
            if let exp = key.expiresAt { restrictions.append("expires \(DashboardFormat.day(exp))") }
            var action = ""
            if key.isUsable(at: now), let id = key.id?.uuidString.lowercased() {
                if canManage, key.autoRevokeAt == nil {
                    let options = APIKeyLifecycle.overlapChoices.filter { $0 <= req.ctx.config.operations.apiKeyMaxOverlap }.map {
                        ConsoleUI.Option(String(Int($0)), overlapLabel(Int($0)), selected: Int($0) == 86_400)
                    }
                    action += "<form method=\"post\" action=\"/dashboard/api-keys/\(id)/rotate\" class=\"row\">\(DashboardUI.csrf(p))<label class=\"vh\" for=\"ov-\(id)\">Overlap for \(DashboardUI.esc(key.name))</label><select id=\"ov-\(id)\" name=\"overlap\">\(ConsoleUI.options(options))</select>"
                        + ConsoleUI.button("Rotate", .secondary, small: true, ariaLabel: "Rotate \(key.name)", passkey: true) + "</form>"
                }
                if canRevoke {
                    action += ConsoleUI.confirm("Revoke", ariaLabel: "Revoke \(key.name)", ConsoleUI.form("/dashboard/api-keys/\(id)/revoke", csrf: DashboardUI.csrf(p),
                        "<p>Requests with \(DashboardUI.esc(key.name)) fail at once. This cannot be undone; rotate instead if you need an overlap.</p>"
                        + "<button class=\"btn dd sm\" type=\"submit\" aria-label=\"Revoke \(DashboardUI.esc(key.name))\">Revoke</button>"))
                }
            }
            let ident = key.kid.map { "<code>\(DashboardUI.esc(key.prefix))\(DashboardUI.esc($0))</code>" } ?? "<code>\(DashboardUI.esc(key.prefix))…\(DashboardUI.esc(key.last4))</code>"
            let lastUsed = key.lastUsedAt.map { DashboardFormat.date($0) + (key.lastUsedIPHash.map { "<br><span class=\"mu sm\">from \(DashboardUI.esc(String($0.split(separator: ":").last?.prefix(8) ?? "")))</span>" } ?? "") } ?? "<span class=\"mu\">Never</span>"
            let access = "<span class=\"sm\">\(DashboardUI.esc(key.scopes.replacingOccurrences(of: ",", with: " ")))</span><br>"
                + (key.capabilities.isEmpty ? "<span class=\"mu sm\">no capabilities</span>" : "<code>\(DashboardUI.esc(key.capabilities.replacingOccurrences(of: ",", with: " ")))</code>")
            return [ConsoleUI.Cell(html: "<strong>\(DashboardUI.esc(key.name))</strong><br>\(ident)", sort: .text(key.name)), ConsoleUI.Cell(html: access),
                    .text(restrictions.isEmpty ? "—" : restrictions.joined(separator: ", ")), ConsoleUI.Cell(html: lastUsed, sort: key.lastUsedAt.map { .date($0) }),
                    .date(key.createdAt), ConsoleUI.Cell(html: status), ConsoleUI.Cell(html: action.isEmpty ? "" : "<div class=\"row\">\(action)</div>")]
        }
        var form = ""
        var approvals = ""
        var createAction = ""
        if canManage {
            let sandboxOK = try await OnboardingGate.allows(business: p.business!, livemode: false, on: req.db)
            let liveOK = try await OnboardingGate.allows(business: p.business!, livemode: true, on: req.db)
            if sandboxOK {
                createAction = ConsoleUI.linkButton("Create a key", href: "#create", .primary, icon: .plus)
                let scopes = BusinessAPIKeys.Scope.all.map { scope -> String in
                    let elevated = !KeyScopePolicy.baselineScopes.contains(scope)
                    let allowed = !elevated || p.can(.elevateKeyScope)
                    return "<label class=\"ck\"><input type=\"checkbox\" name=\"scopes[]\" value=\"\(scope)\"\(scope == "interactions:write" || scope == "interactions:read" ? " checked" : "")\(allowed ? "" : " disabled")> <span><code>\(scope)</code>"
                        + (allowed ? "" : " <span class=\"mu sm\">needs a Security Admin or Owner</span>") + "</span></label>"
                }.joined()
                let entitled = try await EntitlementService(db: req.db, ctx: req.ctx).snapshot(businessId: businessId)
                let capabilityBoxes = CapabilityCatalog.definitions.map { definition -> String in
                    let capability = definition.capability
                    let isEntitled = entitled.capabilities.contains(capability) && entitled.tiers.contains(definition.minimumTier)
                    let elevated = !Capability.messaging.contains(capability)
                    let allowed = isEntitled && (!elevated || p.can(.elevateKeyScope))
                    let checked = Capability.messaging.contains(capability) ? " checked" : ""
                    return "<label class=\"ck\"><input type=\"checkbox\" name=\"capabilities[]\" value=\"\(capability.rawValue)\"\(allowed ? checked : " disabled")> <span><code>\(capability.rawValue)</code>"
                        + (!isEntitled ? " <span class=\"mu sm\">not enabled for your organization</span>" : (allowed ? "" : " <span class=\"mu sm\">needs a Security Admin or Owner</span>")) + "</span></label>"
                }.joined()
                let mtls = entitled.tiers.contains(.e) ? ConsoleUI.checkbox("requireMtls", label: "Require a bound client certificate (mutual TLS)") : ""
                var modes = [ConsoleUI.Option("test", "Test (sandbox, no real delivery)")]
                if liveOK { modes.append(ConsoleUI.Option("live", "Live")) }
                let basics = "<div class=\"cols\">"
                    + ConsoleUI.input("name", label: "Name", id: "name", placeholder: "Production server", help: "Where the key is used, so you know what breaks if you revoke it.", required: true, attrs: ["maxlength": "64"])
                    + ConsoleUI.select("mode", label: "Mode", id: "mode", options: modes, help: liveOK ? nil : "Live keys unlock after your go-live review.")
                    + ConsoleUI.select("expires", label: "Expires", id: "expires", options: [ConsoleUI.Option("0", "Never"), ConsoleUI.Option("30", "In 30 days"), ConsoleUI.Option("90", "In 90 days"), ConsoleUI.Option("365", "In a year")])
                    + "</div>"
                form = ConsoleUI.card("Create a key", id: "create", description: "Give a key only the scopes and capabilities it needs. A key can never do more than your organization is entitled to, and it loses a capability the moment Viadere withdraws the entitlement.",
                    ConsoleUI.form("/dashboard/api-keys", csrf: DashboardUI.csrf(p),
                        basics
                        + "<fieldset><legend>Scopes</legend><p class=\"help\">What the key may call.</p><div class=\"cols\">\(scopes)</div></fieldset>"
                        + "<fieldset><legend>Capabilities</legend><p class=\"help\">Which products the key may use.</p><input type=\"hidden\" name=\"capabilitiesChosen\" value=\"1\"><div class=\"cols\">\(capabilityBoxes)</div></fieldset>"
                        + ConsoleUI.fieldset("Network restrictions",
                            ConsoleUI.input("ipAllowlist", label: "Allowed IP addresses", id: "ipAllowlist", placeholder: "203.0.113.0/24, 2001:db8::/48",
                                            help: "When set, the key works only from these networks. Leave empty to allow any address.", optional: true, attrs: ["maxlength": "400", "spellcheck": "false"]) + mtls)
                        + ConsoleUI.formActions(ConsoleUI.button("Create key", passkey: true) + ConsoleUI.passkeyNote("You'll confirm with your passkey. The secret is shown once."), sep: true)))
            } else {
                form = ConsoleUI.callout(.accent, title: "Keys unlock after domain verification", "<p>Verify a domain you control first. <a href=\"/dashboard/organization/domains\">Open Organization &gt; Domains</a></p>")
            }
            // Requests of mine that a second person approved are completed here (I alone see the new secret).
            let mine = try await PendingChanges(db: req.db, ctx: req.ctx).open(businessId: businessId).filter { $0.requestedBy == p.user.id && $0.status == "approved" && $0.kind != PendingChanges.Kind.roleGrant.rawValue && $0.kind != PendingChanges.Kind.securitySetting.rawValue }
            if !mine.isEmpty {
                let items = mine.map { change in
                    "<form method=\"post\" action=\"/dashboard/api-keys/approved/\(change.id?.uuidString.lowercased() ?? "")\" class=\"row\">\(DashboardUI.csrf(p))<span>Approved: \(DashboardUI.esc(change.kind == PendingChanges.Kind.apiKey.rawValue ? "create a key" : "rotate a key"))</span> <button class=\"btn sm\" type=\"submit\">Complete</button></form>"
                }.joined()
                approvals = ConsoleUI.callout(.success, title: "Approved by a second person", "<p class=\"sm\">Complete it to see the new secret. Only you can.</p>\(items)")
            }
        }
        let table = ConsoleUI.card("Keys", description: "A key is shown by its non-secret id. Rotation issues a replacement and keeps the old key working for the overlap you choose, then revokes it automatically.",
            ConsoleUI.table([ConsoleUI.Column("Name", key: "name"), ConsoleUI.Column("Access"), ConsoleUI.Column("Restrictions"), ConsoleUI.Column("Last used", key: "used"),
                             ConsoleUI.Column("Created", key: "created"), ConsoleUI.Column("Status"), ConsoleUI.Column("", actions: true)],
                            rows, caption: "API keys", state: ConsoleUI.TableState(req, id: "keys"), empty: "No keys yet",
                            emptyMessage: "Create a sandbox key to send your first test message."))
        return DashboardUI.businessPage(p, title: "API keys", active: "/dashboard/api-keys", subtitle: "Credentials for your server integration.", actions: createAction,
                                        flash: DashboardFormat.flash(req), body: approvals + table + form)
    }

    private static func secretKeyPage(_ p: DashboardPrincipal, issued: BusinessAPIKeys.Issued, rotated: Bool) -> Response {
        let capabilities = issued.record.capabilities.replacingOccurrences(of: ",", with: " ")
        let body = ConsoleUI.callout(.warning, title: "This is the only time the full key is shown", "<p>Copy it into your secrets manager now. Viadere stores only a hash and cannot show it again.</p>")
            + ConsoleUI.card("Copy your key now", """
            <div class="secret mono" tabindex="0">\(DashboardUI.esc(issued.key))</div>\
            \(ConsoleUI.keyValues([("Name", DashboardUI.esc(issued.record.name)), ("Scopes", DashboardUI.esc(issued.record.scopes.replacingOccurrences(of: ",", with: " "))),
                                   ("Capabilities", DashboardUI.esc(capabilities.isEmpty ? "none" : capabilities)), ("Mode", issued.record.livemode ? "Live" : "Test")]))\
            \(rotated ? "<p class=\"mu sm\">The previous key stays valid for the overlap you chose, then is revoked automatically.</p>" : "")\
            \(ConsoleUI.formActions(ConsoleUI.linkButton("Done, I stored it", href: "/dashboard/api-keys", .primary)))
            """)
        return DashboardUI.businessPage(p, title: "New API key", active: "/dashboard/api-keys", body: body)
    }

    private static func createKey(_ req: Request) async throws -> Response {
        let (p, _) = try req.businessDashboard
        let form = try req.content.decode(KeyForm.self)
        let request = DashboardActions.KeyRequest(
            name: form.name, live: form.mode == "live", scopes: form.scopes ?? [],
            capabilities: form.capabilitiesChosen == "1" ? (form.capabilities ?? []) : form.capabilities, expiresInDays: form.expires,
            ipAllowlist: form.ipAllowlist ?? "", requiresMTLS: form.requireMtls == "1")
        switch try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).createAPIKey(request) {
        case .issued(let issued): return secretKeyPage(p, issued: issued, rotated: false)
        case .awaitingApproval: return DashboardResponses.redirect("/dashboard/api-keys?m=pending")
        }
    }

    private static func rotateKey(_ req: Request) async throws -> Response {
        let (p, _) = try req.businessDashboard
        let form = try req.content.decode(RotateForm.self)
        switch try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).rotateAPIKey(id: try req.uuid("id"), overlap: TimeInterval(form.overlap ?? 86_400)) {
        case .issued(let issued): return secretKeyPage(p, issued: issued, rotated: true)
        case .awaitingApproval: return DashboardResponses.redirect("/dashboard/api-keys?m=pending")
        }
    }

    private static func completeApproved(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        let id = try req.uuid("id")
        guard let change = try await PendingChangeRecord.query(on: req.db).filter(\.$id == id).filter(\.$businessId == businessId).first() else { throw APIError.notFound }
        let actions = DashboardActions(db: req.db, ctx: req.ctx, principal: p)
        let result: DashboardActions.KeyCreation
        if change.kind == PendingChanges.Kind.apiKeyRotation.rawValue {
            result = try await actions.rotateAPIKey(id: UUID(), overlap: 0, approvedChange: id)
        } else {
            result = try await actions.createAPIKey(DashboardActions.KeyRequest(name: "", live: false, scopes: [], capabilities: nil, expiresInDays: nil, ipAllowlist: "",
                                                                                 requiresMTLS: false, approvedChange: id))
        }
        switch result {
        case .issued(let issued): return secretKeyPage(p, issued: issued, rotated: change.kind == PendingChanges.Kind.apiKeyRotation.rawValue)
        case .awaitingApproval: return DashboardResponses.redirect("/dashboard/api-keys?m=pending")
        }
    }

    // MARK: Webhooks

    private static let webhookCrumbs = [ConsoleUI.Crumb("Dashboard", "/dashboard"), ConsoleUI.Crumb("Developers", "/dashboard/developers"), ConsoleUI.Crumb("Webhooks", "/dashboard/webhooks")]

    private static var webhookTools: String {
        ConsoleUI.linkButton("Delivery log", href: "/dashboard/webhooks/deliveries", small: true) + ConsoleUI.linkButton("Event schemas", href: "/dashboard/webhooks/schemas", small: true)
            + ConsoleUI.linkButton("Retry simulator", href: "/dashboard/webhooks/simulate", small: true)
    }

    private static func webhooksPage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewWebhooks)
        let subs = try await WebhookSubscriptionRecord.query(on: req.db).filter(\.$businessId == businessId).filter(\.$active == true).sort(\.$createdAt, .descending).all()
        let verification = req.ctx.config.operations.webhookOwnershipVerification
        let paused = await PlatformFlags(db: req.db, ctx: req.ctx).webhooksPaused(businessId: businessId)
        let rows = subs.map { sub -> [ConsoleUI.Cell] in
            var status = ""
            if verification { status += sub.verifiedAt != nil ? DashboardFormat.badge("Verified", "ok") : DashboardFormat.badge("Not verified", "dg") }
            if sub.pausedAt != nil { status += " " + DashboardFormat.badge("Paused", "wa") }
            if sub.envelopeVersion != nil { status += " " + DashboardFormat.badge("Opaque v2", "mu") }
            if let error = sub.lastVerifyError, sub.verifiedAt == nil { status += "<br><span class=\"mu sm\">Last check: \(DashboardUI.esc(error))</span>" }
            var actions = ""
            if p.can(.manageWebhooks), let id = sub.id?.uuidString.lowercased() {
                func button(_ path: String, _ label: String, _ cls: String = "s", passkey: Bool = false) -> String {
                    "<form method=\"post\" action=\"/dashboard/webhooks/\(id)/\(path)\">\(DashboardUI.csrf(p))<button class=\"btn \(cls) sm\" type=\"submit\" aria-label=\"\(label) \(DashboardUI.esc(sub.url))\">\(passkey ? ConsoleUI.icon(.key) : "")\(label)</button></form>"
                }
                actions = "<div class=\"row\">"
                if sub.verifiedAt == nil && verification { actions += button("verify", "Verify", "") }
                if sub.verifiedAt != nil || !verification { actions += button("test", "Send test event") }
                actions += sub.pausedAt == nil ? button("pause", "Pause") : button("resume", "Resume")
                actions += button("rotate", "Rotate secret", passkey: true)
                actions += ConsoleUI.confirm("Delete", ariaLabel: "Delete \(sub.url)", "<form method=\"post\" action=\"/dashboard/webhooks/\(id)/delete\">\(DashboardUI.csrf(p))"
                    + "<p>The endpoint stops receiving events at once. Queued deliveries to it are dropped.</p><button class=\"btn dd sm\" type=\"submit\" aria-label=\"Delete \(DashboardUI.esc(sub.url))\">Delete</button></form>")
                actions += "</div>"
            }
            return [ConsoleUI.Cell(html: "<code>\(DashboardUI.esc(sub.url))</code>", sort: .text(sub.url)), .text(sub.events.replacingOccurrences(of: ",", with: ", ")), ConsoleUI.Cell(html: status),
                    .date(sub.createdAt), ConsoleUI.Cell(html: actions)]
        }
        var form = ""
        var banner = ""
        var add = ""
        if paused { banner = ConsoleUI.callout(.warning, title: "Delivery paused by Viadere", "<p>Webhook delivery for your organization is paused. Events stay queued and are delivered after the pause is lifted.</p>") }
        if p.can(.manageWebhooks) {
            if try await OnboardingGate.allows(business: p.business!, livemode: false, on: req.db) {
                add = ConsoleUI.linkButton("Add an endpoint", href: "#add", .primary, icon: .plus)
                let events = WebhookService.knownEvents.map { "<label class=\"ck\"><input type=\"checkbox\" name=\"events[]\" value=\"\($0.rawValue)\" checked> <code>\($0.rawValue)</code></label>" }.joined()
                form = ConsoleUI.card("Add an endpoint", id: "add", description: "Each delivery is signed with Viadere-Signature and carries Viadere-Delivery-Id and Viadere-Key-Id." + (verification ? " Before it receives events, the endpoint must prove it is yours: we POST a one-time challenge it has to answer." : ""),
                    ConsoleUI.form("/dashboard/webhooks", csrf: DashboardUI.csrf(p),
                        ConsoleUI.input("url", label: "HTTPS URL", id: "url", type: "url", placeholder: "https://example.com/viadere/webhooks", help: "Public, https, and answering within ten seconds.", required: true, attrs: ["maxlength": "500"])
                        + "<fieldset><legend>Events</legend><div class=\"cols\">\(events)</div></fieldset>"
                        + ConsoleUI.checkbox("opaque", label: "Opaque v2 envelope (ids and a result reference only; for approval and interaction events)")
                        + ConsoleUI.formActions(ConsoleUI.button("Add endpoint", passkey: true) + ConsoleUI.passkeyNote("You'll confirm with your passkey. The signing secret is shown once."), sep: true)))
            } else {
                form = ConsoleUI.callout(.accent, title: "Webhooks unlock after domain verification", "<p>Add endpoints once you have verified a domain you control. <a href=\"/dashboard/organization/domains\">Open Organization &gt; Domains</a></p>")
            }
        }
        let list = ConsoleUI.card("Endpoints", actions: webhookTools,
            ConsoleUI.table([ConsoleUI.Column("URL", key: "url"), ConsoleUI.Column("Events"), ConsoleUI.Column("Status"), ConsoleUI.Column("Created", key: "created"), ConsoleUI.Column("", actions: true)],
                            rows, caption: "Webhook endpoints", state: ConsoleUI.TableState(req, id: "hooks"), empty: "No endpoints yet", emptyMessage: "Add an endpoint to receive signed events and customer replies."))
        return DashboardUI.businessPage(p, title: "Webhooks", active: "/dashboard/webhooks", subtitle: "Signed event delivery with ownership verification, retries and a dead-letter queue.",
                                        actions: add, flash: DashboardFormat.flash(req), body: banner + list + form)
    }

    private static func secretPage(_ p: DashboardPrincipal, response: WebhookSecretResponse, heading: String) -> Response {
        let id = response.subscription.id.description
        let next = p.can(.manageWebhooks) ? "<form method=\"post\" action=\"/dashboard/webhooks/\(id)/verify\">\(DashboardUI.csrf(p))<button class=\"btn\" type=\"submit\">Verify this endpoint now</button></form>" : ""
        let body = ConsoleUI.callout(.warning, title: "This signing secret is shown once", "<p>Store it on your server now; Viadere cannot show it again.</p>")
            + ConsoleUI.card(heading, """
            <p>Verify the <code>Viadere-Signature</code> header with this secret.</p><div class="secret mono" tabindex="0">\(DashboardUI.esc(response.secret))</div>\
            \(ConsoleUI.keyValues([("Endpoint", "<code>\(DashboardUI.esc(response.subscription.url.absoluteString))</code>"), ("Key id", "<code>whk_…_v\(response.subscription.secretVersion ?? 1)</code>")]))\
            <h3>Next: verify the endpoint</h3><p class="mu sm">Configure the secret on your server first, then verify: the check posts a challenge your endpoint must answer with an HMAC proof made from the signing secret (<code>{"challenge_response": "…"}</code>; the SDK's <code>verificationResponse</code> does it). Echoing the challenge is refused.</p>\
            <div class="form-actions">\(next)\(ConsoleUI.linkButton("Done", href: "/dashboard/webhooks"))</div>
            """)
        return DashboardUI.businessPage(p, title: "Webhook secret", active: "/dashboard/webhooks", body: body)
    }

    private static func createWebhook(_ req: Request) async throws -> Response {
        let (p, _) = try req.businessDashboard
        let form = try req.content.decode(WebhookForm.self)
        let created = try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).createWebhook(url: form.url, events: form.events ?? [], opaque: form.opaque == "1")
        return secretPage(p, response: created, heading: "Endpoint added")
    }

    private static func verifyEndpoint(_ req: Request) async throws -> Response {
        let (p, _) = try req.businessDashboard
        let result = try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).verifyWebhook(id: try req.uuid("id"))
        if result.verified { return DashboardResponses.redirect("/dashboard/webhooks?m=verified") }
        let reason: String
        switch result.failure ?? "" {
        case "no_echo": reason = "The endpoint answered, but without a valid proof. Return {\"challenge_response\": HMAC-SHA256(signing secret, challenge)}; echoing the challenge is not accepted."
        case "unreachable": reason = "We could not reach the endpoint. Check that it is public, uses https and answers within ten seconds."
        default: reason = "The endpoint answered with an error status (\(DashboardUI.esc(result.failure ?? ""))). It must answer 2xx."
        }
        let body = ConsoleUI.callout(.danger, title: "Verification failed", urgent: true, "<p>\(reason)</p>") + "<div class=\"row\">\(ConsoleUI.linkButton("Back to endpoints", href: "/dashboard/webhooks", .primary))</div>"
        return DashboardUI.businessPage(p, title: "Endpoint not verified", active: "/dashboard/webhooks", body: body, status: .unprocessableEntity)
    }

    private static func deliveryTone(_ status: String) -> String { status == "succeeded" ? "ok" : (status == "dead" ? "dg" : "mu") }

    private static func deliveriesPage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewWebhooks)
        let deliveries = try await WebhookDeliveryRecord.query(on: req.db).filter(\.$businessId == businessId).sort(\.$createdAt, .descending).limit(50).all()
        let rows = deliveries.map { d -> [ConsoleUI.Cell] in
            let id = d.id?.uuidString.lowercased() ?? ""
            var action = "<a class=\"btn s sm\" href=\"/dashboard/webhooks/deliveries/\(id)\" aria-label=\"View delivery of \(DashboardUI.esc(d.eventType))\">View</a>"
            if d.status == "dead", p.can(.manageWebhooks) {
                action += "<form method=\"post\" action=\"/dashboard/webhooks/deliveries/\(id)/replay\">\(DashboardUI.csrf(p))<button class=\"btn s sm\" type=\"submit\">Replay</button></form>"
            }
            return [.text(d.eventType), ConsoleUI.Cell(html: DashboardFormat.badge(d.status, deliveryTone(d.status)), sort: .text(d.status)), .number(d.attempts),
                    ConsoleUI.Cell(html: d.lastStatusCode.map(String.init) ?? "—", sort: d.lastStatusCode.map { .number(Double($0)) }), .text(d.lastError ?? "—"), .date(d.createdAt),
                    ConsoleUI.Cell(html: "<div class=\"row\">\(action)</div>")]
        }
        let dead = deliveries.filter { $0.status == "dead" }.count
        let tiles = ConsoleUI.stats([
            ConsoleUI.Stat(String(deliveries.filter { $0.status == "succeeded" }.count), "Succeeded", tone: .success),
            ConsoleUI.Stat(String(deliveries.filter { $0.status != "succeeded" && $0.status != "dead" }.count), "Waiting or retrying"),
            ConsoleUI.Stat(String(dead), "Dead-lettered", hint: dead > 0 ? "Replay them once the endpoint recovers" : nil, tone: dead > 0 ? .danger : nil),
        ])
        let body = tiles + ConsoleUI.panel(ConsoleUI.table([ConsoleUI.Column("Event", key: "event"), ConsoleUI.Column("Status", key: "status"), ConsoleUI.Column("Attempts", key: "attempts", numeric: true),
                                                             ConsoleUI.Column("Last HTTP", key: "http", numeric: true), ConsoleUI.Column("Last error"), ConsoleUI.Column("Created", key: "created"), ConsoleUI.Column("", actions: true)],
                                                            rows, caption: "Recent webhook deliveries", state: ConsoleUI.TableState(req, id: "d"), empty: "No deliveries yet",
                                                            emptyMessage: "Deliveries appear here as events are sent to your endpoints."))
        return DashboardUI.businessPage(p, title: "Delivery log", active: "/dashboard/webhooks", subtitle: "The 50 most recent deliveries. Payloads are redacted.",
                                        actions: ConsoleUI.linkButton("Endpoints", href: "/dashboard/webhooks", small: true), flash: DashboardFormat.flash(req),
                                        breadcrumbs: webhookCrumbs + [ConsoleUI.Crumb("Delivery log", nil)], body: body)
    }

    private static func deliveryPage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewWebhooks)
        let id = try req.uuid("id")
        guard let d = try await WebhookDeliveryRecord.query(on: req.db).filter(\.$id == id).filter(\.$businessId == businessId).first() else { throw APIError.notFound }
        let attempts = try await WebhookAttemptRecord.query(on: req.db).filter(\.$deliveryId == id).sort(\.$attempt, .ascending).all()
        let attemptRows = attempts.map { [ConsoleUI.Cell.number($0.attempt), .date($0.attemptedAt), ConsoleUI.Cell(html: $0.statusCode.map(String.init) ?? "—"), ConsoleUI.Cell(html: "\($0.durationMs) ms"), .text($0.error ?? "—")] }
        var replay = ""
        if d.status == "dead", p.can(.manageWebhooks) {
            replay = "<form method=\"post\" action=\"/dashboard/webhooks/deliveries/\(id.uuidString.lowercased())/replay\">\(DashboardUI.csrf(p))<button class=\"btn\" type=\"submit\">Replay this delivery</button></form>"
        }
        let summary = ConsoleUI.card(d.eventType, actions: DashboardFormat.badge(d.status, deliveryTone(d.status)) + replay, ConsoleUI.keyValues([
            ("Created", DashboardFormat.date(d.createdAt)), ("Attempts", String(d.attempts)), ("Delivery id", "<code>\(id.uuidString.lowercased())</code>"),
        ]) + "<h3>Payload (redacted)</h3><pre>\(DashboardUI.esc(PayloadRedactor.display(body: WebhookService(db: req.db, ctx: req.ctx).deliveryBody(d).map { String(decoding: $0, as: UTF8.self) } ?? "")))</pre>")
        let body = summary + ConsoleUI.card("Attempts", ConsoleUI.table([ConsoleUI.Column("#", numeric: true), ConsoleUI.Column("When"), ConsoleUI.Column("HTTP", numeric: true), ConsoleUI.Column("Duration", numeric: true), ConsoleUI.Column("Error")],
                                                                          attemptRows, caption: "Delivery attempts", empty: "No attempts yet."))
        return DashboardUI.businessPage(p, title: "Delivery", active: "/dashboard/webhooks", actions: ConsoleUI.linkButton("Back to the log", href: "/dashboard/webhooks/deliveries", small: true),
                                        breadcrumbs: webhookCrumbs + [ConsoleUI.Crumb("Delivery log", "/dashboard/webhooks/deliveries"), ConsoleUI.Crumb("Delivery", nil)], body: body)
    }

    private static func schemasPage(_ req: Request) async throws -> Response {
        let (p, _) = try req.businessDashboard
        try p.require(.viewWebhooks)
        let cards = WebhookSchemaPreview.samples(now: req.ctx.now).map { sample in
            ConsoleUI.card(titleHTML: "<code>\(DashboardUI.esc(sample.type))</code>", "<pre>\(DashboardUI.esc(sample.json))</pre>")
        }.joined()
        let intro = ConsoleUI.callout(.accent, title: "Every delivery", """
        <p class="sm">A JSON body signed with <code>Viadere-Signature</code> (timestamp and HMAC-SHA256 over the exact bytes). Headers: <code>Viadere-Event-Type</code>, <code>Viadere-Event-Id</code>, \
        <code>Viadere-Delivery-Id</code>, <code>Viadere-Key-Id</code>. Reject timestamps older than five minutes and de-duplicate by delivery id.</p>
        """)
        return DashboardUI.businessPage(p, title: "Event schemas", active: "/dashboard/webhooks", subtitle: "What your endpoint will receive.", actions: ConsoleUI.linkButton("Endpoints", href: "/dashboard/webhooks", small: true),
                                        breadcrumbs: webhookCrumbs + [ConsoleUI.Crumb("Event schemas", nil)], body: intro + "<div class=\"cols\">\(cards)</div>")
    }

    private static func simulatePage(_ req: Request) async throws -> Response {
        let (p, _) = try req.businessDashboard
        try p.require(.viewWebhooks)
        let failures = req.queryInt("failures", default: 3, range: 0...WebhookService.maxAttempts)
        let steps = WebhookRetrySimulation.plan(failures: failures, from: req.ctx.now)
        let rows = steps.map { [ConsoleUI.Cell.number($0.attempt), .date($0.at), .text($0.outcome)] }
        let options = (0...WebhookService.maxAttempts).map { ConsoleUI.Option(String($0), String($0), selected: $0 == failures) }
        let body = ConsoleUI.card("Simulate failures", description: "Nothing is sent. Retries back off 30 s, 2 min, 10 min, 1 h, 6 h, 12 h and 24 h; after \(WebhookService.maxAttempts) failed attempts the delivery is dead-lettered and can be replayed.", """
        <form method="get" action="/dashboard/webhooks/simulate" class="inline">\(ConsoleUI.select("failures", label: "Consecutive failures before your endpoint recovers", id: "failures", options: options))\
        <div class="form-actions"><button class="btn s" type="submit">Show schedule</button></div></form>\
        \(ConsoleUI.table([ConsoleUI.Column("Attempt", numeric: true), ConsoleUI.Column("When"), ConsoleUI.Column("Outcome")], rows, caption: "Simulated retry schedule"))
        """)
        return DashboardUI.businessPage(p, title: "Retry simulator", active: "/dashboard/webhooks", subtitle: "See how a failing endpoint is retried.", actions: ConsoleUI.linkButton("Endpoints", href: "/dashboard/webhooks", small: true),
                                        breadcrumbs: webhookCrumbs + [ConsoleUI.Crumb("Retry simulator", nil)], body: body)
    }

    // MARK: Sandbox

    private static func sandboxPage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        guard p.can(.viewWebhooks) || p.can(.manageWebhooks) else { throw APIError.forbidden }
        let state = try await OnboardingService(db: req.db, ctx: req.ctx).state(businessId: businessId)
        let relationships = try await RelationshipRecord.query(on: req.db).filter(\.$businessId == businessId).all()
        let sandboxIds = Set(try await ConsumerRecord.query(on: req.db).filter(\.$id ~~ relationships.map(\.consumerId)).filter(\.$status == ConsumerRecord.sandboxStatus).all().compactMap(\.id))
        let customers = relationships.filter { sandboxIds.contains($0.consumerId) }
        let hooks = try await WebhookSubscriptionRecord.query(on: req.db).filter(\.$businessId == businessId).filter(\.$active == true).all()
        let steps = ConsoleUI.checklist([
            ConsoleUI.Step(state.domainVerified, "Verify your domain", "<a href=\"/dashboard/organization/domains\">Organization &gt; Domains</a>"),
            ConsoleUI.Step(state.sandboxKey, "Create a sandbox key", "<a href=\"/dashboard/api-keys\">Developers &gt; API keys</a>"),
            ConsoleUI.Step(state.testCustomer, "Create a test customer", "With the button under Test customers."),
            ConsoleUI.Step(hooks.contains { $0.verifiedAt != nil || !req.ctx.config.operations.webhookOwnershipVerification }, "Add and verify a webhook endpoint", "<a href=\"/dashboard/webhooks\">Developers &gt; Webhooks</a>"),
            ConsoleUI.Step(state.testEvent, "Send a test message or event", "Use your key with the API, send a test event from Webhooks, or simulate a reply below."),
        ], label: "Sandbox checklist")
        var create = ""
        if p.can(.manageWebhooks), state.domainVerified {
            create = "<form method=\"post\" action=\"/dashboard/developers/sandbox/customer\">\(DashboardUI.csrf(p))<button class=\"btn sm\" type=\"submit\">\(ConsoleUI.icon(.plus))Create a test customer</button></form>"
        }
        let rows = customers.map { [ConsoleUI.Cell(html: "<code>\($0.id?.uuidString.lowercased() ?? "")</code>"), ConsoleUI.Cell.date($0.connectedAt)] }
        var reply = ""
        if p.can(.manageWebhooks), !customers.isEmpty {
            let options = customers.compactMap { $0.id?.uuidString.lowercased() }.map { ConsoleUI.Option($0, $0) }
            reply = ConsoleUI.card("Simulate a customer reply", description: "Sends a signed message.received event to your verified endpoints, exactly as a real reply would arrive. Nothing reaches a real person.",
                ConsoleUI.form("/dashboard/developers/sandbox/reply", csrf: DashboardUI.csrf(p),
                    ConsoleUI.select("relationshipId", label: "Test customer", id: "relationshipId", options: options)
                    + ConsoleUI.input("text", label: "Reply", id: "text", value: "Thanks, that works for me.", required: true, attrs: ["maxlength": "280"])
                    + ConsoleUI.formActions(ConsoleUI.button("Send simulated reply", .secondary))))
        }
        let body = "<div class=\"split\"><div>" + ConsoleUI.card("Test customers", description: "Sandbox customers behave like connected customers but never reach a real person.", actions: create,
                                   ConsoleUI.table([ConsoleUI.Column("Relationship id"), ConsoleUI.Column("Created")], rows, caption: "Sandbox customers", empty: "No test customers yet",
                                                   emptyMessage: state.domainVerified ? "Create one to try messages and replies end to end." : "Verify a domain first."))
            + reply + "</div><div>" + ConsoleUI.card("Checklist", steps) + "</div></div>"
        return DashboardUI.businessPage(p, title: "Sandbox", active: "/dashboard/developers/sandbox", subtitle: "Try the whole flow with no real customers.", flash: DashboardFormat.flash(req), body: body)
    }
}
