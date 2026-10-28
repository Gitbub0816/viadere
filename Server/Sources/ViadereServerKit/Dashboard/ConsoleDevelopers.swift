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
        let tiles = "<div class=\"grid\">\(DashboardFormat.stat(String(keys.filter { !$0.livemode }.count), "Sandbox keys"))\(DashboardFormat.stat(String(keys.filter(\.livemode).count), "Live keys"))"
            + "\(DashboardFormat.stat(String(hooks.filter { $0.verifiedAt != nil }.count) + " / " + String(hooks.count), "Verified endpoints"))\(DashboardFormat.stat(state.stage.rawValue.capitalized, "Onboarding stage"))</div>"
        let quick = """
        <div class="card"><h2>Quickstart</h2><ol>\
        <li>Verify a domain you control (<a href="/dashboard/organization/domains">Organization &gt; Domains</a>).</li>\
        <li>Create a sandbox key in <a href="/dashboard/api-keys">API keys</a> and a test customer in <a href="/dashboard/developers/sandbox">Sandbox</a>.</li>\
        <li>Send a message with the key; add and verify a <a href="/dashboard/webhooks">webhook endpoint</a> and receive a signed test reply.</li>\
        <li>Request production access from <a href="/dashboard/organization">Organization</a>. No VPN or private network is needed.</li></ol>\
        <pre>curl -X POST \(DashboardUI.esc(req.ctx.config.publicBaseURL))/v1/business/messages \\
          -H "Authorization: Bearer vdk_test_&lt;key id&gt;.&lt;secret&gt;" \\
          -H "Idempotency-Key: msg-0001" -H "Content-Type: application/json" \\
          -d '{"relationshipId":"&lt;sandbox relationship&gt;","body":"Hello","idempotencyKey":"msg-0001"}'</pre>\
        <p class="mu sm">The OpenAPI description is in the developer documentation. Webhooks are signed with <code>Viadere-Signature</code>; each delivery names its <code>Viadere-Delivery-Id</code> and the <code>Viadere-Key-Id</code> of the signing secret.</p></div>
        """
        return DashboardUI.businessPage(p, title: "Developers", active: "/dashboard/developers", subtitle: "Credentials, webhooks and the sandbox.", flash: DashboardFormat.flash(req), body: tiles + quick)
    }

    // MARK: API keys

    private static func apiKeysPage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewAPIKeys)
        let keys = try await BusinessAPIKeyRecord.query(on: req.db).filter(\.$businessId == businessId).sort(\.$createdAt, .descending).all()
        let now = req.ctx.now
        let canManage = p.can(.manageAPIKeys)
        let canRevoke = p.can(.revokeAPIKeys)
        let rows = keys.map { key -> [String] in
            let status: String
            if key.revokedAt != nil { status = DashboardFormat.badge("Revoked", "dg") }
            else if let exp = key.expiresAt, exp <= now { status = DashboardFormat.badge("Expired", "mu") }
            else if let end = key.autoRevokeAt { status = end <= now ? DashboardFormat.badge("Revoked", "dg") : DashboardFormat.badge("Rotating until \(DashboardFormat.date(end))", "mu") }
            else { status = DashboardFormat.badge(key.livemode ? "Live" : "Test", key.livemode ? "ok" : "mu") }
            var restrictions: [String] = []
            if let ips = key.ipAllowlist, !ips.isEmpty { restrictions.append("IPs: \(ips.split(separator: ",").count)") }
            if key.requiresMTLS { restrictions.append("mTLS") }
            if let exp = key.expiresAt { restrictions.append("expires \(DashboardFormat.day(exp))") }
            var action = ""
            if key.isUsable(at: now), let id = key.id?.uuidString.lowercased() {
                if canManage, key.autoRevokeAt == nil {
                    let options = APIKeyLifecycle.overlapChoices.filter { $0 <= req.ctx.config.operations.apiKeyMaxOverlap }.map { value -> String in
                        let label: String
                        switch Int(value) {
                        case 0: label = "No overlap"
                        case 3600: label = "1 hour overlap"
                        case 86_400: label = "1 day overlap"
                        case 7 * 86_400: label = "7 days overlap"
                        default: label = "30 days overlap"
                        }
                        return "<option value=\"\(Int(value))\"\(Int(value) == 86_400 ? " selected" : "")>\(label)</option>"
                    }.joined()
                    action += "<form method=\"post\" action=\"/dashboard/api-keys/\(id)/rotate\" class=\"row\">\(DashboardUI.csrf(p))<label class=\"vh\" for=\"ov-\(id)\">Overlap for \(DashboardUI.esc(key.name))</label><select id=\"ov-\(id)\" name=\"overlap\">\(options)</select><button class=\"btn s sm\" type=\"submit\">Rotate</button></form>"
                }
                if canRevoke {
                    action += "<form method=\"post\" action=\"/dashboard/api-keys/\(id)/revoke\">\(DashboardUI.csrf(p))<button class=\"btn d sm\" type=\"submit\" aria-label=\"Revoke \(DashboardUI.esc(key.name))\">Revoke</button></form>"
                }
            }
            let ident = key.kid.map { "<code>\(DashboardUI.esc(key.prefix))\(DashboardUI.esc($0))</code>" } ?? "<code>\(DashboardUI.esc(key.prefix))…\(DashboardUI.esc(key.last4))</code>"
            let lastUsed = key.lastUsedAt.map { DashboardFormat.date($0) + (key.lastUsedIPHash.map { " · <span class=\"mu sm\">from \(DashboardUI.esc(String($0.split(separator: ":").last?.prefix(8) ?? "")))</span>" } ?? "") } ?? "—"
            return [DashboardUI.esc(key.name), ident, DashboardUI.esc(key.scopes.replacingOccurrences(of: ",", with: " ")),
                    key.capabilities.isEmpty ? "<span class=\"mu\">none</span>" : "<code>\(DashboardUI.esc(key.capabilities.replacingOccurrences(of: ",", with: " ")))</code>",
                    restrictions.isEmpty ? "—" : DashboardUI.esc(restrictions.joined(separator: ", ")), lastUsed, DashboardFormat.date(key.createdAt), status, action]
        }
        var form = ""
        var approvals = ""
        if canManage {
            let sandboxOK = try await OnboardingGate.allows(business: p.business!, livemode: false, on: req.db)
            let liveOK = try await OnboardingGate.allows(business: p.business!, livemode: true, on: req.db)
            if sandboxOK {
                let scopes = BusinessAPIKeys.Scope.all.map { scope -> String in
                    let elevated = !KeyScopePolicy.baselineScopes.contains(scope)
                    let allowed = !elevated || p.can(.elevateKeyScope)
                    return "<label class=\"ck\"><input type=\"checkbox\" name=\"scopes[]\" value=\"\(scope)\"\(scope == "interactions:write" || scope == "interactions:read" ? " checked" : "")\(allowed ? "" : " disabled")> <code>\(scope)</code>"
                        + (allowed ? "" : " <span class=\"mu sm\">needs a Security Admin or Owner</span>") + "</label>"
                }.joined()
                let entitled = try await EntitlementService(db: req.db, ctx: req.ctx).snapshot(businessId: businessId)
                let capabilityBoxes = CapabilityCatalog.definitions.map { definition -> String in
                    let capability = definition.capability
                    let isEntitled = entitled.capabilities.contains(capability) && entitled.tiers.contains(definition.minimumTier)
                    let elevated = !Capability.messaging.contains(capability)
                    let allowed = isEntitled && (!elevated || p.can(.elevateKeyScope))
                    let checked = Capability.messaging.contains(capability) ? " checked" : ""
                    return "<label class=\"ck\"><input type=\"checkbox\" name=\"capabilities[]\" value=\"\(capability.rawValue)\"\(allowed ? checked : " disabled")> <code>\(capability.rawValue)</code>"
                        + (!isEntitled ? " <span class=\"mu sm\">not enabled for your organization</span>" : (allowed ? "" : " <span class=\"mu sm\">needs a Security Admin or Owner</span>")) + "</label>"
                }.joined()
                let mtls = entitled.tiers.contains(.e) ? "<label class=\"ck\"><input type=\"checkbox\" name=\"requireMtls\" value=\"1\"> Require a bound client certificate (mutual TLS)</label>" : ""
                let modes = "<option value=\"test\">Test (sandbox, no real delivery)</option>" + (liveOK ? "<option value=\"live\">Live</option>" : "")
                form = """
                <div class="card"><h2>Create a key</h2><form method="post" action="/dashboard/api-keys">\(DashboardUI.csrf(p))\
                <div class="cols"><div><label for="name">Name</label><input id="name" name="name" type="text" maxlength="64" required placeholder="Production server"></div>\
                <div><label for="mode">Mode</label><select id="mode" name="mode">\(modes)</select></div>\
                <div><label for="expires">Expires</label><select id="expires" name="expires"><option value="0">Never</option><option value="30">In 30 days</option><option value="90">In 90 days</option><option value="365">In a year</option></select></div></div>\
                <fieldset><legend>Scopes</legend>\(scopes)</fieldset><fieldset><legend>Capabilities</legend><input type="hidden" name="capabilitiesChosen" value="1">\(capabilityBoxes)</fieldset>\
                <label for="ipAllowlist">Allowed IP addresses (optional)</label><input id="ipAllowlist" name="ipAllowlist" type="text" maxlength="400" placeholder="203.0.113.0/24, 2001:db8::/48"\
                aria-describedby="ip-help"><p id="ip-help" class="mu sm">When set, the key works only from these networks. Leave empty to allow any address.</p>\(mtls)\
                <p class="mu sm">Give a key only the scopes and capabilities it needs. A key can never do more than your organization is entitled to, and it loses a capability the moment Viadere withdraws the entitlement. Creating a key asks you to confirm with your passkey. The secret is shown once.\(liveOK ? "" : " Live keys unlock after your go-live review.")</p>\
                <button class="btn" type="submit">Create key</button></form></div>
                """
            } else {
                form = "<div class=\"notice\">Keys unlock when you have verified a domain you control. Open <a href=\"/dashboard/organization/domains\">Organization &gt; Domains</a>.</div>"
            }
            // Requests of mine that a second person approved are completed here (I alone see the new secret).
            let mine = try await PendingChanges(db: req.db, ctx: req.ctx).open(businessId: businessId).filter { $0.requestedBy == p.user.id && $0.status == "approved" && $0.kind != PendingChanges.Kind.roleGrant.rawValue && $0.kind != PendingChanges.Kind.securitySetting.rawValue }
            if !mine.isEmpty {
                let items = mine.map { change in
                    "<form method=\"post\" action=\"/dashboard/api-keys/approved/\(change.id?.uuidString.lowercased() ?? "")\">\(DashboardUI.csrf(p))<p>Approved: \(DashboardUI.esc(change.kind == PendingChanges.Kind.apiKey.rawValue ? "create a key" : "rotate a key")) <button class=\"btn sm\" type=\"submit\">Complete</button></p></form>"
                }.joined()
                approvals = "<div class=\"card\"><h2>Approved by a second person</h2>\(items)</div>"
            }
        }
        let table = "<div class=\"card\"><h2>Keys</h2>\(DashboardFormat.table(["Name", "Key", "Scopes", "Capabilities", "Restrictions", "Last used", "Created", "Status", ""], rows, empty: "No keys yet.", caption: "API keys"))"
            + "<p class=\"mu sm\">A key is shown by its non-secret id. Rotation issues a replacement and keeps the old key working for the overlap you choose, then revokes it automatically.</p></div>"
        return DashboardUI.businessPage(p, title: "API keys", active: "/dashboard/api-keys", subtitle: "Credentials for your server integration.", flash: DashboardFormat.flash(req), body: approvals + form + table)
    }

    private static func secretKeyPage(_ p: DashboardPrincipal, issued: BusinessAPIKeys.Issued, rotated: Bool) -> Response {
        let body = """
        <div class="card"><h2>Copy your key now</h2><p>This is the only time the full key is shown. Store it in your secrets manager.</p>\
        <div class="secret mono" tabindex="0">\(DashboardUI.esc(issued.key))</div>\
        <p class="mu sm">Name: \(DashboardUI.esc(issued.record.name)) · Scopes: \(DashboardUI.esc(issued.record.scopes.replacingOccurrences(of: ",", with: " "))) · Capabilities: \(DashboardUI.esc(issued.record.capabilities.replacingOccurrences(of: ",", with: " ").isEmpty ? "none" : issued.record.capabilities.replacingOccurrences(of: ",", with: " "))) · \(issued.record.livemode ? "Live" : "Test")</p>\
        \(rotated ? "<p class=\"mu sm\">The previous key stays valid for the overlap you chose, then is revoked automatically.</p>" : "")\
        <p><a class="btn s" href="/dashboard/api-keys">Done</a></p></div>
        """
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

    private static func webhooksPage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewWebhooks)
        let subs = try await WebhookSubscriptionRecord.query(on: req.db).filter(\.$businessId == businessId).filter(\.$active == true).sort(\.$createdAt, .descending).all()
        let verification = req.ctx.config.operations.webhookOwnershipVerification
        let paused = await PlatformFlags(db: req.db, ctx: req.ctx).webhooksPaused(businessId: businessId)
        let rows = subs.map { sub -> [String] in
            var status = ""
            if verification { status += sub.verifiedAt != nil ? DashboardFormat.badge("Verified", "ok") : DashboardFormat.badge("Not verified", "dg") }
            if sub.pausedAt != nil { status += " " + DashboardFormat.badge("Paused", "mu") }
            if sub.envelopeVersion != nil { status += " " + DashboardFormat.badge("Opaque v2", "mu") }
            if let error = sub.lastVerifyError, sub.verifiedAt == nil { status += "<br><span class=\"mu sm\">Last check: \(DashboardUI.esc(error))</span>" }
            var actions = ""
            if p.can(.manageWebhooks), let id = sub.id?.uuidString.lowercased() {
                func button(_ path: String, _ label: String, _ cls: String = "s") -> String {
                    "<form method=\"post\" action=\"/dashboard/webhooks/\(id)/\(path)\">\(DashboardUI.csrf(p))<button class=\"btn \(cls) sm\" type=\"submit\" aria-label=\"\(label) \(DashboardUI.esc(sub.url))\">\(label)</button></form>"
                }
                actions = "<div class=\"row\">"
                if sub.verifiedAt == nil && verification { actions += button("verify", "Verify", "") }
                if sub.verifiedAt != nil || !verification { actions += button("test", "Send test event") }
                actions += sub.pausedAt == nil ? button("pause", "Pause") : button("resume", "Resume")
                actions += button("rotate", "Rotate secret") + button("delete", "Delete", "d") + "</div>"
            }
            return ["<code>\(DashboardUI.esc(sub.url))</code>", DashboardUI.esc(sub.events.replacingOccurrences(of: ",", with: ", ")), status, DashboardFormat.date(sub.createdAt), actions]
        }
        var form = ""
        var banner = ""
        if paused { banner = "<div class=\"notice dg\" role=\"status\">Webhook delivery for your organization is paused by Viadere. Events stay queued and are delivered after the pause is lifted.</div>" }
        if p.can(.manageWebhooks) {
            if try await OnboardingGate.allows(business: p.business!, livemode: false, on: req.db) {
                let events = WebhookService.knownEvents.map { "<label class=\"ck\"><input type=\"checkbox\" name=\"events[]\" value=\"\($0.rawValue)\" checked> <code>\($0.rawValue)</code></label>" }.joined()
                form = """
                <div class="card"><h2>Add an endpoint</h2><form method="post" action="/dashboard/webhooks">\(DashboardUI.csrf(p))\
                <label for="url">HTTPS URL</label><input id="url" name="url" type="url" required placeholder="https://example.com/viadere/webhooks" maxlength="500">\
                <fieldset><legend>Events</legend>\(events)</fieldset>\
                <label class="ck"><input type="checkbox" name="opaque" value="1"> Opaque v2 envelope (ids and a result reference only; for approval and interaction events)</label>\
                <p class="mu sm">Each delivery is signed with <code>Viadere-Signature</code> and carries <code>Viadere-Delivery-Id</code> and <code>Viadere-Key-Id</code>. The signing secret is shown once, after you confirm with your passkey. \
                \(verification ? "Before it receives events, the endpoint must prove it is yours: we POST a one-time challenge that it has to echo." : "")</p>\
                <button class="btn" type="submit">Add endpoint</button></form></div>
                """
            } else {
                form = "<div class=\"notice\">Webhooks can be added once you have verified a domain you control.</div>"
            }
        }
        let list = "<div class=\"card\"><h2>Endpoints</h2>\(DashboardFormat.table(["URL", "Events", "Status", "Created", ""], rows, empty: "No endpoints yet.", caption: "Webhook endpoints"))</div>"
        let tools = "<div class=\"row\"><a class=\"btn s sm\" href=\"/dashboard/webhooks/deliveries\">Delivery log</a><a class=\"btn s sm\" href=\"/dashboard/webhooks/schemas\">Event schemas</a><a class=\"btn s sm\" href=\"/dashboard/webhooks/simulate\">Retry simulator</a></div>"
        return DashboardUI.businessPage(p, title: "Webhooks", active: "/dashboard/webhooks", subtitle: "Signed event delivery with ownership verification, retries and a dead-letter queue.",
                                        actions: tools, flash: DashboardFormat.flash(req), body: banner + form + list)
    }

    private static func secretPage(_ p: DashboardPrincipal, response: WebhookSecretResponse, heading: String) -> Response {
        let id = response.subscription.id.description
        let next = p.can(.manageWebhooks) ? "<form method=\"post\" action=\"/dashboard/webhooks/\(id)/verify\">\(DashboardUI.csrf(p))<button class=\"btn\" type=\"submit\">Verify this endpoint now</button></form>" : ""
        let body = """
        <div class="card"><h2>\(DashboardUI.esc(heading))</h2><p>This signing secret is shown once. Verify the <code>Viadere-Signature</code> header with it.</p>\
        <div class="secret mono" tabindex="0">\(DashboardUI.esc(response.secret))</div><p class="mu sm">Endpoint: <code>\(DashboardUI.esc(response.subscription.url.absoluteString))</code> · Key id: <code>whk_…_v\(response.subscription.secretVersion ?? 1)</code></p>\
        <p class="mu sm">Configure the secret on your server first, then verify: the check posts a challenge your endpoint must answer with an HMAC proof made from the signing secret (<code>{"challenge_response": "…"}</code>; the SDK's <code>verificationResponse</code> does it). Echoing the challenge is refused.</p>\(next)\
        <p><a class="btn s" href="/dashboard/webhooks">Done</a></p></div>
        """
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
        let body = "<div class=\"notice dg\" role=\"alert\">\(reason)</div><p><a class=\"btn s\" href=\"/dashboard/webhooks\">Back to endpoints</a></p>"
        return DashboardUI.businessPage(p, title: "Endpoint not verified", active: "/dashboard/webhooks", body: body, status: .unprocessableEntity)
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
        let body = "<div class=\"card\">\(DashboardFormat.table(["Event", "Status", "Attempts", "Last HTTP", "Last error", "Created", ""], rows, empty: "No deliveries yet.", caption: "Recent webhook deliveries"))</div>"
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
        <p class="mu sm">Created \(DashboardFormat.date(d.createdAt)) · \(d.attempts) attempt(s) · delivery id <code>\(id.uuidString.lowercased())</code></p>\
        <h3>Payload (redacted)</h3><pre>\(DashboardUI.esc(PayloadRedactor.display(body: WebhookService(db: req.db, ctx: req.ctx).deliveryBody(d).map { String(decoding: $0, as: UTF8.self) } ?? "")))</pre>\(replay)</div>\
        <div class="card"><h2>Attempts</h2>\(DashboardFormat.table(["#", "When", "HTTP", "Duration", "Error"], attemptRows, empty: "No attempts yet.", caption: "Delivery attempts"))</div>
        """
        return DashboardUI.businessPage(p, title: "Delivery", active: "/dashboard/webhooks", actions: "<a class=\"btn s sm\" href=\"/dashboard/webhooks/deliveries\">Back</a>", body: body)
    }

    private static func schemasPage(_ req: Request) async throws -> Response {
        let (p, _) = try req.businessDashboard
        try p.require(.viewWebhooks)
        let cards = WebhookSchemaPreview.samples(now: req.ctx.now).map { sample in
            "<div class=\"card\"><h2><code>\(DashboardUI.esc(sample.type))</code></h2><pre>\(DashboardUI.esc(sample.json))</pre></div>"
        }.joined()
        let intro = "<p class=\"mu\">Every delivery is a JSON body signed with <code>Viadere-Signature</code> (timestamp and HMAC-SHA256 over the exact bytes). Headers: <code>Viadere-Event-Type</code>, <code>Viadere-Event-Id</code>, <code>Viadere-Delivery-Id</code>, <code>Viadere-Key-Id</code>. Reject timestamps older than five minutes and de-duplicate by delivery id.</p>"
        return DashboardUI.businessPage(p, title: "Event schemas", active: "/dashboard/webhooks", subtitle: "What your endpoint will receive.", actions: "<a class=\"btn s sm\" href=\"/dashboard/webhooks\">Endpoints</a>", body: intro + cards)
    }

    private static func simulatePage(_ req: Request) async throws -> Response {
        let (p, _) = try req.businessDashboard
        try p.require(.viewWebhooks)
        let failures = req.queryInt("failures", default: 3, range: 0...WebhookService.maxAttempts)
        let steps = WebhookRetrySimulation.plan(failures: failures, from: req.ctx.now)
        let rows = steps.map { [String($0.attempt), DashboardFormat.date($0.at), DashboardUI.esc($0.outcome)] }
        let options = (0...WebhookService.maxAttempts).map { "<option value=\"\($0)\"\($0 == failures ? " selected" : "")>\($0)</option>" }.joined()
        let body = """
        <div class="card"><h2>Simulate failures</h2><form method="get" action="/dashboard/webhooks/simulate"><label for="failures">Consecutive failures before your endpoint recovers</label>\
        <select id="failures" name="failures">\(options)</select><p><button class="btn s" type="submit">Show schedule</button></p></form>\
        \(DashboardFormat.table(["Attempt", "When", "Outcome"], rows, caption: "Simulated retry schedule"))\
        <p class="mu sm">Nothing is sent. Retries back off 30 s, 2 min, 10 min, 1 h, 6 h, 12 h and 24 h; after \(WebhookService.maxAttempts) failed attempts the delivery is dead-lettered and can be replayed.</p></div>
        """
        return DashboardUI.businessPage(p, title: "Retry simulator", active: "/dashboard/webhooks", subtitle: "See how a failing endpoint is retried.", actions: "<a class=\"btn s sm\" href=\"/dashboard/webhooks\">Endpoints</a>", body: body)
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
        func step(_ done: Bool, _ title: String, _ detail: String) -> String {
            "<li class=\"\(done ? "done" : "")\"><span aria-hidden=\"true\">\(done ? "✓" : "○")</span><div><strong>\(DashboardUI.esc(title))</strong> \(done ? "<span class=\"vh\">done</span>" : "<span class=\"vh\">to do</span>")<br><span class=\"mu sm\">\(detail)</span></div></li>"
        }
        let steps = "<ol class=\"steps\">"
            + step(state.domainVerified, "Verify your domain", "<a href=\"/dashboard/organization/domains\">Organization &gt; Domains</a>")
            + step(state.sandboxKey, "Create a sandbox key", "<a href=\"/dashboard/api-keys\">Developers &gt; API keys</a>")
            + step(state.testCustomer, "Create a test customer", "Below.")
            + step(hooks.contains { $0.verifiedAt != nil || !req.ctx.config.operations.webhookOwnershipVerification }, "Add and verify a webhook endpoint", "<a href=\"/dashboard/webhooks\">Developers &gt; Webhooks</a>")
            + step(state.testEvent, "Send a test message or event", "Use your key with the API, send a test event from Webhooks, or simulate a reply below.")
            + "</ol>"
        var create = ""
        if p.can(.manageWebhooks), state.domainVerified {
            create = "<form method=\"post\" action=\"/dashboard/developers/sandbox/customer\">\(DashboardUI.csrf(p))<p><button class=\"btn\" type=\"submit\">Create a test customer</button></p></form>"
        }
        let rows = customers.map { [ "<code>\($0.id?.uuidString.lowercased() ?? "")</code>", DashboardFormat.date($0.connectedAt) ] }
        var reply = ""
        if p.can(.manageWebhooks), !customers.isEmpty {
            let options = customers.compactMap { $0.id?.uuidString.lowercased() }.map { "<option value=\"\($0)\">\($0)</option>" }.joined()
            reply = """
            <div class="card"><h2>Simulate a customer reply</h2><form method="post" action="/dashboard/developers/sandbox/reply">\(DashboardUI.csrf(p))\
            <label for="relationshipId">Test customer</label><select id="relationshipId" name="relationshipId">\(options)</select>\
            <label for="text">Reply</label><input id="text" name="text" type="text" maxlength="280" required value="Thanks, that works for me.">\
            <p class="mu sm">Sends a signed <code>message.received</code> event to your verified endpoints, exactly as a real reply would arrive. Nothing reaches a real person.</p>\
            <button class="btn s" type="submit">Send simulated reply</button></form></div>
            """
        }
        let body = "<div class=\"card\"><h2>Checklist</h2>\(steps)</div><div class=\"card\"><h2>Test customers</h2>\(create)\(DashboardFormat.table(["Relationship id", "Created"], rows, empty: "No test customers yet.", caption: "Sandbox customers"))</div>\(reply)"
        return DashboardUI.businessPage(p, title: "Sandbox", active: "/dashboard/developers/sandbox", subtitle: "Try the whole flow with no real customers.", flash: DashboardFormat.flash(req), body: body)
    }
}
