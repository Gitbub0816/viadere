import Fluent
import Foundation
import Vapor
import ViadereCore

private struct SwitchForm: Content {
    var action: String?
    var scope: String?
    var businessId: String?
    var message: String?
    var mode: String?
    var channels: [String]?
    var perMinute: Int?
    var reason: String
    var complaintRate: Double?
    var optOutRate: Double?
    var minimumSample: Int?
    var windowDays: Double?
    var throttleFactor: Double?
}
private struct FreezeForm: Content {
    var consumerId: String
    var reason: String
}
private struct NoticeForm: Content {
    var scope: String
    var businessId: String?
    var severity: String
    var title: String
    var body: String
}
private struct RetentionSetForm: Content {
    var days: Int
    var reason: String
}
private struct HoldForm: Content {
    var scopeKind: String
    var scopeId: String?
    var reason: String
}
private struct NoteForm: Content {
    var note: String?
    var reference: String?
    var decision: String?
    var close: String?
    var scope: String?
    var category: String?
}

/// Operator controls for the gaps in docs/ops/KILL-SWITCHES.md: maintenance mode, sign-up stops, webhook pause, messaging restriction, abuse
/// thresholds, consumer freeze, notices, retention and holds, data requests, support, and the onboarding reviews. Every mutation needs a fresh
/// passkey assertion and a recorded reason, is audited with the operator as actor, and is bounded where it can be.
enum OperatorOps {
    private static func principal(_ req: Request) throws -> DashboardPrincipal {
        let p = try req.dashboard
        guard p.realm == .operator else { throw APIError.forbidden }
        return p
    }

    /// The operator principal after the fresh-passkey check every mutation needs.
    private static func mutating(_ req: Request, next: String) throws -> DashboardPrincipal {
        let p = try principal(req)
        guard p.hasFreshReauth(ctx: req.ctx) else { throw ReauthRequired(next: next) }
        return p
    }

    private static func actor(_ p: DashboardPrincipal) -> EntitlementActor { .operatorUser(p.user.id!) }

    static func register(_ pages: any RoutesBuilder) {
        pages.get("operator", "switches") { req in try await switchesPage(req) }
        pages.post("operator", "switches", "maintenance") { req -> Response in
            let p = try mutating(req, next: "/operator/switches")
            let form = try req.content.decode(SwitchForm.self)
            let flags = PlatformFlags(db: req.db, ctx: req.ctx)
            if form.action == "off" { try await flags.clear(.maintenance, reason: form.reason, actor: actor(p)) } else {
                try await flags.set(.maintenance, value: form.message ?? "", reason: form.reason, actor: actor(p))
            }
            return DashboardResponses.redirect("/operator/switches?m=switch")
        }
        pages.post("operator", "switches", "signup") { req -> Response in
            let p = try mutating(req, next: "/operator/switches")
            let form = try req.content.decode(SwitchForm.self)
            guard let flag = PlatformFlag(rawValue: form.scope ?? ""), [.signupConsumer, .signupBusiness, .inviteDashboard, .loops].contains(flag) else { throw APIError.validation("Choose a sign-up switch.") }
            let flags = PlatformFlags(db: req.db, ctx: req.ctx)
            if form.action == "off" { try await flags.clear(flag, reason: form.reason, actor: actor(p)) } else { try await flags.set(flag, value: "on", reason: form.reason, actor: actor(p)) }
            return DashboardResponses.redirect("/operator/switches?m=switch")
        }
        pages.post("operator", "switches", "webhooks") { req -> Response in
            let p = try mutating(req, next: "/operator/switches")
            let form = try req.content.decode(SwitchForm.self)
            let business = try businessScope(form.businessId)
            let flags = PlatformFlags(db: req.db, ctx: req.ctx)
            if form.action == "off" { try await flags.clear(.webhooksPause, businessId: business, reason: form.reason, actor: actor(p)) } else {
                try await flags.set(.webhooksPause, businessId: business, value: "on", reason: form.reason, actor: actor(p))
            }
            return DashboardResponses.redirect("/operator/switches?m=switch")
        }
        pages.post("operator", "switches", "messaging") { req -> Response in
            let p = try mutating(req, next: "/operator/switches")
            let form = try req.content.decode(SwitchForm.self)
            let business = try businessScope(form.businessId)
            let flags = PlatformFlags(db: req.db, ctx: req.ctx)
            if form.action == "off" { try await flags.clear(.messagingRestrict, businessId: business, reason: form.reason, actor: actor(p)) } else {
                let restriction = MessagingRestriction(mode: form.mode == "clamp" ? .clamp : .block, channels: form.channels ?? [], perMinute: form.mode == "clamp" ? form.perMinute : nil, purposes: nil)
                try await flags.set(.messagingRestrict, businessId: business, value: String(decoding: try JSONEncoder().encode(restriction), as: UTF8.self), reason: form.reason, actor: actor(p))
            }
            return DashboardResponses.redirect("/operator/switches?m=switch")
        }
        pages.post("operator", "switches", "abuse") { req -> Response in
            let p = try mutating(req, next: "/operator/switches")
            let form = try req.content.decode(SwitchForm.self)
            let flags = PlatformFlags(db: req.db, ctx: req.ctx)
            if form.action == "off" { try await flags.clear(.abuseThresholds, reason: form.reason, actor: actor(p)) } else {
                let override = AbuseOverride(complaintRate: form.complaintRate, optOutRate: form.optOutRate, minimumSample: form.minimumSample, windowDays: form.windowDays, throttleFactor: form.throttleFactor)
                try await flags.set(.abuseThresholds, value: String(decoding: try JSONEncoder().encode(override), as: UTF8.self), reason: form.reason, actor: actor(p))
            }
            return DashboardResponses.redirect("/operator/switches?m=switch")
        }

        pages.get("operator", "consumers") { req in try await consumersPage(req) }
        pages.post("operator", "consumers", "freeze") { req -> Response in
            let p = try mutating(req, next: "/operator/consumers")
            let form = try req.content.decode(FreezeForm.self)
            guard let id = UUID(uuidString: form.consumerId.trimmingCharacters(in: .whitespaces)) else { throw APIError.validation("Enter the account id.", details: ["consumerId": "invalid"]) }
            try await ConsumerFreeze(db: req.db, ctx: req.ctx).freeze(consumerId: id, reason: form.reason, operatorId: p.user.id!)
            return DashboardResponses.redirect("/operator/consumers?m=frozen")
        }
        pages.post("operator", "consumers", "unfreeze") { req -> Response in
            let p = try mutating(req, next: "/operator/consumers")
            let form = try req.content.decode(FreezeForm.self)
            guard let id = UUID(uuidString: form.consumerId.trimmingCharacters(in: .whitespaces)) else { throw APIError.validation("Enter the account id.", details: ["consumerId": "invalid"]) }
            try await ConsumerFreeze(db: req.db, ctx: req.ctx).unfreeze(consumerId: id, reason: form.reason, operatorId: p.user.id!)
            return DashboardResponses.redirect("/operator/consumers?m=unfrozen")
        }

        pages.get("operator", "notices") { req in try await noticesPage(req) }
        pages.post("operator", "notices") { req -> Response in
            let p = try mutating(req, next: "/operator/notices")
            let form = try req.content.decode(NoticeForm.self)
            guard let scope = OperatorNotices.Scope(rawValue: form.scope) else { throw APIError.validation("Choose an audience.") }
            try await OperatorNotices(db: req.db, ctx: req.ctx).create(scope: scope, businessId: form.businessId.flatMap { UUID(uuidString: $0.trimmingCharacters(in: .whitespaces)) },
                                                                      severity: form.severity, title: form.title, body: form.body, operatorId: p.user.id!)
            return DashboardResponses.redirect("/operator/notices?m=notice")
        }

        pages.get("operator", "retention") { req in try await retentionPage(req) }
        pages.post("operator", "retention", ":cls") { req -> Response in
            let p = try mutating(req, next: "/operator/retention")
            guard let cls = RetentionClass(rawValue: req.parameters.get("cls") ?? "") else { throw APIError.notFound }
            let form = try req.content.decode(RetentionSetForm.self)
            try await RetentionPolicy(db: req.db, ctx: req.ctx).setPlatform(cls, days: form.days, operatorId: p.user.id!, reason: form.reason)
            return DashboardResponses.redirect("/operator/retention?m=saved")
        }
        pages.post("operator", "holds") { req -> Response in
            let p = try mutating(req, next: "/operator/retention")
            let form = try req.content.decode(HoldForm.self)
            _ = try await RetentionPolicy(db: req.db, ctx: req.ctx).placeHold(scopeKind: form.scopeKind, scopeId: form.scopeKind == "global" ? nil : form.scopeId?.trimmingCharacters(in: .whitespaces),
                                                                              reason: form.reason, operatorId: p.user.id!)
            return DashboardResponses.redirect("/operator/retention?m=hold")
        }
        pages.post("operator", "holds", ":id", "release") { req -> Response in
            let p = try mutating(req, next: "/operator/retention")
            try await RetentionPolicy(db: req.db, ctx: req.ctx).releaseHold(id: try req.uuid("id"), operatorId: p.user.id!)
            return DashboardResponses.redirect("/operator/retention?m=saved")
        }
        pages.post("operator", "data-requests", ":id", "complete") { req -> Response in
            let p = try mutating(req, next: "/operator/retention")
            try await TenantDataRequests(db: req.db, ctx: req.ctx).complete(id: try req.uuid("id"), operatorId: p.user.id!)
            return DashboardResponses.redirect("/operator/retention?m=reviewed")
        }
        pages.post("operator", "data-requests", ":id", "reject") { req -> Response in
            let p = try mutating(req, next: "/operator/retention")
            let form = try req.content.decode(NoteForm.self)
            try await TenantDataRequests(db: req.db, ctx: req.ctx).reject(id: try req.uuid("id"), note: form.note ?? "", operatorId: p.user.id!)
            return DashboardResponses.redirect("/operator/retention?m=reviewed")
        }

        pages.get("operator", "support") { req in try await supportPage(req) }
        pages.post("operator", "support", ":id") { req -> Response in
            let p = try mutating(req, next: "/operator/support")
            let form = try req.content.decode(NoteForm.self)
            try await SupportDesk(db: req.db, ctx: req.ctx).respond(id: try req.uuid("id"), note: form.note ?? "", close: form.close == "1", operatorId: p.user.id!)
            return DashboardResponses.redirect("/operator/support?m=reviewed")
        }

        // Per-business operator actions (the panel is part of /operator/businesses/:id).
        let base = pages.grouped("operator", "businesses", ":id")
        base.post("revoke-keys") { req -> Response in
            let id = try req.uuid("id")
            let p = try mutating(req, next: "/operator/businesses/\(id.uuidString.lowercased())")
            let form = try req.content.decode(NoteForm.self)
            let live: Bool? = form.scope == "live" ? true : (form.scope == "test" ? false : nil)
            let count = try await APIKeyLifecycle(db: req.db, ctx: req.ctx).revokeAll(businessId: id, live: live, reason: form.note ?? "revoked by an operator", actor: .operatorUser(p.user.id!))
            if count > 0 {
                await Notifier(db: req.db, ctx: req.ctx).notifyBusiness(id, roles: [.owner, .orgAdmin, .securityAdmin, .developer], subject: "Viadere revoked API keys of your organization",
                    text: "Viadere revoked \(count) API key(s) of your organization (\(form.note ?? "security precaution")). Your organization stays active; create new keys in the console under Developers.", kind: "keys-revoked")
            }
            return DashboardResponses.redirect("/operator/businesses/\(id.uuidString.lowercased())?m=revoked-all")
        }
        base.post("revoke-key", ":keyId") { req -> Response in
            let id = try req.uuid("id")
            let p = try mutating(req, next: "/operator/businesses/\(id.uuidString.lowercased())")
            guard let keyId = req.parameters.get("keyId").flatMap(UUID.init(uuidString:)) else { throw APIError.notFound }
            let form = try req.content.decode(NoteForm.self)
            if try await APIKeyLifecycle(db: req.db, ctx: req.ctx).revoke(id: keyId, businessId: id, reason: form.note ?? "revoked by an operator", actor: .operatorUser(p.user.id!)) {
                await Notifier(db: req.db, ctx: req.ctx).notifyBusiness(id, roles: [.owner, .orgAdmin, .securityAdmin, .developer], subject: "Viadere revoked an API key of your organization",
                    text: "Viadere revoked an API key of your organization (\(form.note ?? "security precaution")). Your organization stays active.", kind: "key-revoked")
            }
            return DashboardResponses.redirect("/operator/businesses/\(id.uuidString.lowercased())?m=revoked-all")
        }
        // WP-1.9: correct a business's category. Into a category banned platform-wide (healthcare) this revokes every entitlement and
        // suspends the business (or declines its application); the offboarding runbook covers the rest.
        base.post("category") { req -> Response in
            let id = try req.uuid("id")
            let p = try mutating(req, next: "/operator/businesses/\(id.uuidString.lowercased())")
            let form = try req.content.decode(NoteForm.self)
            try await BusinessOnboarding(db: req.db, ctx: req.ctx).reclassify(businessId: id, category: form.category ?? "", operatorId: p.user.id!, note: form.note ?? "")
            return DashboardResponses.redirect("/operator/businesses/\(id.uuidString.lowercased())?m=reclassified")
        }
        base.post("legal-entity") { req -> Response in
            let id = try req.uuid("id")
            let p = try mutating(req, next: "/operator/businesses/\(id.uuidString.lowercased())")
            let form = try req.content.decode(NoteForm.self)
            try await OnboardingService(db: req.db, ctx: req.ctx).reviewLegalEntity(businessId: id, approve: form.decision == "approve", note: form.note, operatorId: p.user.id!)
            return DashboardResponses.redirect("/operator/businesses/\(id.uuidString.lowercased())?m=reviewed")
        }
        base.post("enhanced-review") { req -> Response in
            let id = try req.uuid("id")
            let p = try mutating(req, next: "/operator/businesses/\(id.uuidString.lowercased())")
            let form = try req.content.decode(NoteForm.self)
            try await OnboardingService(db: req.db, ctx: req.ctx).reviewEnhanced(businessId: id, approve: form.decision == "approve", reference: form.reference ?? "", operatorId: p.user.id!)
            return DashboardResponses.redirect("/operator/businesses/\(id.uuidString.lowercased())?m=reviewed")
        }
        base.post("go-live") { req -> Response in
            let id = try req.uuid("id")
            let p = try mutating(req, next: "/operator/businesses/\(id.uuidString.lowercased())")
            let form = try req.content.decode(NoteForm.self)
            let service = OnboardingService(db: req.db, ctx: req.ctx)
            switch form.decision {
            case "approve": try await service.decideGoLive(businessId: id, approve: true, note: form.note, operatorId: p.user.id!)
            case "reject": try await service.decideGoLive(businessId: id, approve: false, note: form.note, operatorId: p.user.id!)
            case "revoke": try await service.revokeGoLive(businessId: id, reason: form.note ?? "revoked by an operator", operatorId: p.user.id!)
            default: throw APIError.validation("Choose a decision.")
            }
            return DashboardResponses.redirect("/operator/businesses/\(id.uuidString.lowercased())?m=\(form.decision == "approve" ? "golive-approved" : "golive-rejected")")
        }
        base.post("notify") { req -> Response in
            let id = try req.uuid("id")
            let p = try mutating(req, next: "/operator/businesses/\(id.uuidString.lowercased())")
            let form = try req.content.decode(NoticeForm.self)
            try await OperatorNotices(db: req.db, ctx: req.ctx).create(scope: .business, businessId: id, severity: form.severity, title: form.title, body: form.body, operatorId: p.user.id!)
            return DashboardResponses.redirect("/operator/businesses/\(id.uuidString.lowercased())?m=notice")
        }
    }

    private static func businessScope(_ raw: String?) throws -> UUID? {
        guard let raw = raw?.trimmingCharacters(in: .whitespaces), !raw.isEmpty else { return nil }
        guard let id = UUID(uuidString: raw) else { throw APIError.validation("Enter a business id or leave it empty for the whole platform.", details: ["businessId": "invalid"]) }
        return id
    }

    // MARK: Pages

    private static func reasonField(_ id: String) -> String {
        "<label for=\"\(id)\">Reason (recorded)</label><input id=\"\(id)\" name=\"reason\" type=\"text\" minlength=\"8\" maxlength=\"300\" required>"
    }

    private static func switchesPage(_ req: Request) async throws -> Response {
        let p = try principal(req)
        let csrf = DashboardUI.csrf(p)
        let flags = PlatformFlags(db: req.db, ctx: req.ctx)
        let snapshot = await flags.snapshot()
        func state(_ flag: PlatformFlag, scope: String = "global") -> PlatformFlagCache.Entry? { snapshot[PlatformFlags.key(flag, scope)] }
        var body = ""
        let maintenance = state(.maintenance)
        body += """
        <div class="card"><h2>Maintenance (read-only) mode \(maintenance == nil ? DashboardFormat.badge("Off", "ok") : DashboardFormat.badge("On", "dg"))</h2>\
        <p class="mu sm">While on, every write returns 503 with the message below. Reads, health checks, this console and the SMS/RCS provider callbacks (opt-outs are never lost) keep working.</p>\
        <form method="post" action="/operator/switches/maintenance">\(csrf)<label for="message">Status message shown to clients (plain text, up to 200 characters)</label><input id="message" name="message" type="text" maxlength="200" value="\(DashboardUI.esc(maintenance?.value ?? ""))">\
        \(reasonField("r-m"))<div class="row"><button class="btn d" type="submit" name="action" value="on">Turn on</button><button class="btn s" type="submit" name="action" value="off">Turn off</button></div></form></div>
        """
        func toggle(_ flag: PlatformFlag, _ title: String) -> String {
            let on = state(flag) != nil
            return "<form method=\"post\" action=\"/operator/switches/signup\">\(csrf)<input type=\"hidden\" name=\"scope\" value=\"\(flag.rawValue)\"><h3>\(DashboardUI.esc(title)) \(on ? DashboardFormat.badge("Stopped", "dg") : DashboardFormat.badge("Open", "ok"))</h3>\(reasonField("r-" + flag.rawValue.replacingOccurrences(of: ".", with: "-")))<div class=\"row\"><button class=\"btn d sm\" type=\"submit\" name=\"action\" value=\"on\">Stop</button><button class=\"btn s sm\" type=\"submit\" name=\"action\" value=\"off\">Reopen</button></div></form>"
        }
        body += "<div class=\"card\"><h2>Sign-ups</h2><p class=\"mu sm\">Existing accounts keep working.</p><div class=\"cols\">\(toggle(.signupConsumer, "New consumer accounts"))\(toggle(.signupBusiness, "New business organizations"))\(toggle(.inviteDashboard, "New dashboard invitations"))</div></div>"
        body += "<div class=\"card\"><h2>Loops</h2><p class=\"mu sm\">Stops every hosted Loop: no new instances, existing ones show a neutral paused state and nothing is actionable. Messaging, approvals and every core feature keep working. Per-Loop and per-business switches are under Loops.</p>\(toggle(.loops, "Hosted Loops"))</div>"
        let webhookRows = snapshot.filter { $0.key.hasPrefix(PlatformFlag.webhooksPause.rawValue + "|") }.map { [DashboardUI.esc(String($0.key.split(separator: "|").last ?? "")), DashboardUI.esc($0.value.reason), DashboardFormat.date($0.value.updatedAt)] }
        body += """
        <div class="card"><h2>Webhook delivery pause</h2><p class="mu sm">Queued deliveries stay queued. Leave the business id empty to pause the whole platform.</p>\(DashboardFormat.table(["Scope", "Reason", "Since"], webhookRows, empty: "Not paused.", caption: "Webhook pauses"))\
        <form method="post" action="/operator/switches/webhooks">\(csrf)<label for="wb">Business id (optional)</label><input id="wb" name="businessId" type="text" maxlength="40">\(reasonField("r-w"))\
        <div class="row"><button class="btn d" type="submit" name="action" value="on">Pause</button><button class="btn s" type="submit" name="action" value="off">Resume</button></div></form></div>
        """
        let messagingRows = snapshot.filter { $0.key.hasPrefix(PlatformFlag.messagingRestrict.rawValue + "|") }.map { [DashboardUI.esc(String($0.key.split(separator: "|").last ?? "")), "<code>\(DashboardUI.esc($0.value.value))</code>", DashboardUI.esc($0.value.reason)] }
        body += """
        <div class="card"><h2>Emergency messaging restriction</h2><p class="mu sm">Blocks or rate-clamps outbound SMS, RCS or push for one business or the platform. Sign-in and payment approvals (security purpose) are never covered.</p>\(DashboardFormat.table(["Scope", "Restriction", "Reason"], messagingRows, empty: "No restriction.", caption: "Messaging restrictions"))\
        <form method="post" action="/operator/switches/messaging">\(csrf)<label for="mb">Business id (optional)</label><input id="mb" name="businessId" type="text" maxlength="40">\
        <label for="mode">Mode</label><select id="mode" name="mode"><option value="block">Block</option><option value="clamp">Clamp</option></select>\
        <fieldset><legend>Channels</legend><label class="ck"><input type="checkbox" name="channels[]" value="sms"> SMS</label><label class="ck"><input type="checkbox" name="channels[]" value="rcs"> RCS</label><label class="ck"><input type="checkbox" name="channels[]" value="push"> Push</label></fieldset>\
        <label for="pm">Clamp: messages per minute (1 to \(MessagingRestriction.maximumClamp))</label><input id="pm" name="perMinute" type="number" min="1" max="\(MessagingRestriction.maximumClamp)">\(reasonField("r-ms"))\
        <div class="row"><button class="btn d" type="submit" name="action" value="on">Apply</button><button class="btn s" type="submit" name="action" value="off">Remove</button></div></form></div>
        """
        let override = state(.abuseThresholds)
        body += """
        <div class="card"><h2>Abuse thresholds \(override == nil ? DashboardFormat.badge("Deployment values", "mu") : DashboardFormat.badge("Overridden", "dg"))</h2>\
        <p class="mu sm">Bounded: complaint rate \(AbuseOverride.complaintRateBounds.lowerBound) to \(AbuseOverride.complaintRateBounds.upperBound), opt-out rate \(AbuseOverride.optOutRateBounds.lowerBound) to \(AbuseOverride.optOutRateBounds.upperBound), sample \(AbuseOverride.minimumSampleBounds.lowerBound) to \(AbuseOverride.minimumSampleBounds.upperBound), window \(Int(AbuseOverride.windowDaysBounds.lowerBound)) to \(Int(AbuseOverride.windowDaysBounds.upperBound)) days, throttle factor \(AbuseOverride.throttleFactorBounds.lowerBound) to \(AbuseOverride.throttleFactorBounds.upperBound). Leave a field empty to keep the deployment value.</p>\
        \(override.map { "<p class=\"sm\">Current override: <code>\(DashboardUI.esc($0.value))</code></p>" } ?? "")\
        <form method="post" action="/operator/switches/abuse">\(csrf)<div class="cols">\
        <div><label for="ac">Complaint rate</label><input id="ac" name="complaintRate" type="number" step="0.001"></div><div><label for="ao">Opt-out rate</label><input id="ao" name="optOutRate" type="number" step="0.001"></div>\
        <div><label for="as">Minimum sample</label><input id="as" name="minimumSample" type="number"></div><div><label for="aw">Window (days)</label><input id="aw" name="windowDays" type="number" step="1"></div>\
        <div><label for="at">Throttle factor</label><input id="at" name="throttleFactor" type="number" step="0.05"></div></div>\(reasonField("r-a"))\
        <div class="row"><button class="btn" type="submit" name="action" value="on">Apply</button><button class="btn s" type="submit" name="action" value="off">Reset to deployment values</button></div></form></div>
        """
        body += "<p class=\"mu sm\">Capability switches (messaging, approvals, verification and so on) are under <a href=\"/operator/policy\">Capability policy</a>.</p>"
        return DashboardUI.operatorPage(p, title: "Platform switches", active: "/operator/switches", subtitle: "Emergency controls. Every change is audited with your name and a reason.", flash: DashboardFormat.flash(req), body: body)
    }

    private static func consumersPage(_ req: Request) async throws -> Response {
        let p = try principal(req)
        let csrf = DashboardUI.csrf(p)
        let freezes = try await ConsumerFreeze(db: req.db, ctx: req.ctx).freezes()
        let rows = freezes.map { [ "<code>\($0.consumerId.uuidString.lowercased())</code>", DashboardUI.esc($0.reason), DashboardFormat.date($0.frozenAt), $0.releasedAt.map(DashboardFormat.date) ?? DashboardFormat.badge("Frozen", "dg") ] }
        let body = """
        <div class="card"><h2>Freeze an account</h2><p class="mu sm">Ends every session and device of the account at once and blocks approvals and sign-in. The person is told (in the app and by a generic push). Lifting the freeze restores sign-in only; devices stay revoked and the person recovers through the normal flows.</p>\
        <form method="post" action="/operator/consumers/freeze">\(csrf)<label for="cid">Account id</label><input id="cid" name="consumerId" type="text" maxlength="40" required>\(reasonField("r-f"))<button class="btn d" type="submit">Freeze and sign out</button></form></div>\
        <div class="card"><h2>Lift a freeze</h2><form method="post" action="/operator/consumers/unfreeze">\(csrf)<label for="uid">Account id</label><input id="uid" name="consumerId" type="text" maxlength="40" required>\(reasonField("r-u"))<button class="btn s" type="submit">Unfreeze</button></form></div>\
        <div class="card"><h2>Recent freezes</h2>\(DashboardFormat.table(["Account", "Reason", "Frozen", "Lifted"], rows, empty: "No freezes.", caption: "Account freezes"))</div>
        """
        return DashboardUI.operatorPage(p, title: "Consumer accounts", active: "/operator/consumers", subtitle: "Freeze an account for fraud, coercion or a reported compromise.", flash: DashboardFormat.flash(req), body: body)
    }

    private static func noticesPage(_ req: Request) async throws -> Response {
        let p = try principal(req)
        let csrf = DashboardUI.csrf(p)
        let recent = try await OperatorNoticeRecord.query(on: req.db).sort(\.$createdAt, .descending).limit(30).all()
        let rows = recent.map { [DashboardUI.esc($0.title), DashboardUI.esc($0.scope.replacingOccurrences(of: "_", with: " ")), DashboardFormat.badge($0.severity, $0.severity == "info" ? "mu" : "dg"), DashboardFormat.badge($0.status, $0.status == "done" ? "ok" : ""), String($0.delivered), DashboardFormat.date($0.createdAt)] }
        let scopes = OperatorNotices.Scope.allCases.map { "<option value=\"\($0.rawValue)\">\($0.rawValue.replacingOccurrences(of: "_", with: " "))</option>" }.joined()
        let body = """
        <div class="card"><h2>Notify affected parties</h2><p class="mu sm">Business notices are emailed to Owners, Organization Admins, Security Admins and the security contacts, and listed under Support &gt; Notices. Consumer notices appear in the app's security notices with a generic push. Large audiences are delivered in batches.</p>\
        <form method="post" action="/operator/notices">\(csrf)<label for="scope">Audience</label><select id="scope" name="scope">\(scopes)</select>\
        <label for="nb">Business id (for “business” and “consumers of business”)</label><input id="nb" name="businessId" type="text" maxlength="40">\
        <label for="sev">Severity</label><select id="sev" name="severity"><option value="info">Information</option><option value="important">Important</option><option value="critical">Critical</option></select>\
        <label for="title">Title</label><input id="title" name="title" type="text" maxlength="100" required><label for="body">Message (plain text; up to 300 characters for consumers)</label><textarea id="body" name="body" maxlength="2000" required></textarea>\
        <p><button class="btn" type="submit">Queue notice</button></p></form></div>\
        <div class="card"><h2>Recent notices</h2>\(DashboardFormat.table(["Title", "Audience", "Severity", "State", "Delivered", "Created"], rows, empty: "None.", caption: "Recent notices"))</div>
        """
        return DashboardUI.operatorPage(p, title: "Notices", active: "/operator/notices", flash: DashboardFormat.flash(req), body: body)
    }

    private static func retentionPage(_ req: Request) async throws -> Response {
        let p = try principal(req)
        let csrf = DashboardUI.csrf(p)
        let policy = RetentionPolicy(db: req.db, ctx: req.ctx)
        var rows: [[String]] = []
        for cls in RetentionClass.allCases {
            let def = cls.definition
            let days = try await policy.platformDays(cls)
            rows.append(["<code>\(cls.rawValue)</code><br><span class=\"mu sm\">\(DashboardUI.esc(def.summary))</span>", "\(def.defaultDays)", "\(def.minDays) to \(def.maxDays)", def.tenantAdjustable ? "Shorten only" : "No",
                         "<form method=\"post\" action=\"/operator/retention/\(cls.rawValue)\" class=\"row\">\(csrf)<label class=\"vh\" for=\"p-\(cls.rawValue)\">Days for \(cls.rawValue)</label><input id=\"p-\(cls.rawValue)\" name=\"days\" type=\"number\" min=\"\(def.minDays)\" max=\"\(def.maxDays)\" value=\"\(days)\"><label class=\"vh\" for=\"pr-\(cls.rawValue)\">Reason</label><input id=\"pr-\(cls.rawValue)\" name=\"reason\" type=\"text\" minlength=\"8\" maxlength=\"300\" placeholder=\"Reason\" required><button class=\"btn s sm\" type=\"submit\">Set</button></form>"])
        }
        let holds = try await LegalHoldRecord.query(on: req.db).sort(\.$createdAt, .descending).limit(50).all()
        let holdRows = holds.map { h -> [String] in
            let release = h.releasedAt == nil ? "<form method=\"post\" action=\"/operator/holds/\(h.id?.uuidString.lowercased() ?? "")/release\">\(csrf)<button class=\"btn s sm\" type=\"submit\">Release</button></form>" : DashboardFormat.date(h.releasedAt!)
            return [DashboardUI.esc(h.scopeKind), DashboardUI.esc(h.scopeId ?? "—"), DashboardUI.esc(h.reason), DashboardFormat.date(h.createdAt), release]
        }
        let deletions = try await TenantDataRequests(db: req.db, ctx: req.ctx).openDeletions()
        let deletionRows = deletions.map { r -> [String] in
            let id = r.id?.uuidString.lowercased() ?? ""
            return ["<a href=\"/operator/businesses/\(r.businessId.uuidString.lowercased())\">\(r.businessId.uuidString.lowercased().prefix(8))…</a>", DashboardFormat.date(r.createdAt),
                    "<div class=\"row\"><form method=\"post\" action=\"/operator/data-requests/\(id)/complete\">\(csrf)<button class=\"btn d sm\" type=\"submit\">Carry out deletion</button></form><form method=\"post\" action=\"/operator/data-requests/\(id)/reject\">\(csrf)<label class=\"vh\" for=\"n-\(id)\">Reason</label><input id=\"n-\(id)\" name=\"note\" type=\"text\" maxlength=\"300\" placeholder=\"Reason\" required><button class=\"btn s sm\" type=\"submit\">Reject</button></form></div>"]
        }
        let body = """
        <div class="card"><h2>Retention by data class</h2>\(DashboardFormat.table(["Class", "Default", "Bounds", "Business may change", ""], rows, caption: "Retention by data class"))\
        <p class="mu sm">Values are bounded; the purge jobs run every minute. Backups keep erased data until they age out.</p></div>\
        <div class="card"><h2>Legal holds</h2><p class="mu sm">A hold stops the purge of the matching records until it is released. Scope: the whole platform, one business id, or one consumer id.</p>\(DashboardFormat.table(["Scope", "Id", "Reason", "Placed", ""], holdRows, empty: "No holds.", caption: "Legal holds"))\
        <form method="post" action="/operator/holds">\(csrf)<label for="sk">Scope</label><select id="sk" name="scopeKind"><option value="business">Business</option><option value="consumer">Consumer</option><option value="global">Whole platform</option></select>\
        <label for="si">Id</label><input id="si" name="scopeId" type="text" maxlength="40">\(reasonField("r-h"))<button class="btn" type="submit">Place hold</button></form></div>\
        <div class="card"><h2>Organization deletion requests</h2>\(DashboardFormat.table(["Business", "Requested", ""], deletionRows, empty: "None waiting.", caption: "Deletion requests"))</div>
        """
        return DashboardUI.operatorPage(p, title: "Data and retention", active: "/operator/retention", subtitle: "Retention, legal holds and tenant data requests.", flash: DashboardFormat.flash(req), body: body)
    }

    private static func supportPage(_ req: Request) async throws -> Response {
        let p = try principal(req)
        let csrf = DashboardUI.csrf(p)
        let tickets = try await SupportTicketRecord.query(on: req.db).filter(\.$status != "closed").sort(\.$createdAt, .ascending).limit(100).all()
        let desk = SupportDesk(db: req.db, ctx: req.ctx)
        let cards = tickets.map { t -> String in
            let id = t.id?.uuidString.lowercased() ?? ""
            return """
            <div class="card"><h2>\(DashboardUI.esc(t.subject)) \(DashboardFormat.badge(t.kind, t.kind == "appeal" ? "dg" : "mu"))</h2><p class="mu sm">\(DashboardFormat.date(t.createdAt)) · <a href="/operator/businesses/\(t.businessId.uuidString.lowercased())">business</a> · reference \(id.prefix(8))</p>\
            <p>\(DashboardUI.esc(desk.body(of: t)))</p>\
            <form method="post" action="/operator/support/\(id)">\(csrf)<label for="n-\(id)">Reply</label><textarea id="n-\(id)" name="note" maxlength="1000" required></textarea><label class="ck"><input type="checkbox" name="close" value="1"> Close</label><button class="btn s" type="submit">Send reply</button></form></div>
            """
        }.joined()
        return DashboardUI.operatorPage(p, title: "Support", active: "/operator/support", subtitle: "Tickets and appeals that are open.", flash: DashboardFormat.flash(req),
                                        body: cards.isEmpty ? "<p class=\"mu\">Nothing is open.</p>" : cards)
    }

    // MARK: Panels used by the business page and the queue

    /// Onboarding facts, the reviews that are open and the actions an operator has on keys and the business.
    static func businessPanel(_ req: Request, p: DashboardPrincipal, business: BusinessRecord) async throws -> String {
        guard let id = business.id else { return "" }
        let csrf = DashboardUI.csrf(p)
        let base = "/operator/businesses/\(id.uuidString.lowercased())"
        let service = OnboardingService(db: req.db, ctx: req.ctx)
        let row = try await service.row(id)
        let state = try await service.state(businessId: id)
        var out = ""
        let facts: [[String]] = [
            ["Domain control", state.domainVerified ? "Verified \(DashboardUI.esc(row.controlDomain ?? "")) (\(DashboardUI.esc(row.controlMethod ?? "")))" : "Not verified"],
            ["Legal entity", "\(state.legalEntity.rawValue)" + (row.legalRegistryNumber.map { " · \(DashboardUI.esc($0)) · \(DashboardUI.esc(row.legalJurisdiction ?? "")) · \(DashboardUI.esc(row.legalRegistryName ?? ""))" } ?? "")
                + (row.evidenceReferences.isEmpty ? "" : "<br>Evidence: \(row.evidenceReferences.map { DashboardUI.esc($0) }.joined(separator: "; "))")],
            ["Additional review", state.enhanced.rawValue],
            ["Agreements", state.contractsCurrent ? "Current" : "Outstanding"],
            ["Integration", "Sandbox key \(state.sandboxKey), test customer \(state.testCustomer), test event \(state.testEvent)"],
            ["Go-live", "\(state.goLive.rawValue)" + (row.goLiveUseCase.map { "<br>Use case: \(DashboardUI.esc($0))<br>Volume: \(DashboardUI.esc(row.goLiveVolume ?? ""))" } ?? "")],
            ["Assurance", row.assuranceFailure.map { "Failing: \(DashboardUI.esc($0))" } ?? "In good standing"],
        ]
        out += "<div class=\"card\"><h2>Onboarding (stage: \(state.stage.rawValue))</h2>\(DashboardFormat.table(["Item", "State"], facts, caption: "Onboarding facts"))</div>"
        // WP-1.9: the category, with the reclassify action (healthcare is refused platform-wide).
        let banned = OnboardingService.isBanned(business.category)
        let options = (DashboardAuthService.categories + ["healthcare"]).map { c in
            "<option value=\"\(c)\"\(c == business.category ? " selected" : "")>\(DashboardUI.esc(c.replacingOccurrences(of: "_", with: " ")))</option>"
        }.joined()
        let bannedNotice = banned ? "<div class=\"notice dg\" role=\"alert\">This business is in a category Viadere does not serve (healthcare). Follow the offboarding runbook.</div>" : ""
        out += """
        <div class="card"><h2>Category</h2>\(bannedNotice)<p class="mu sm">Current: \(DashboardUI.esc(business.category)). Reclassifying into healthcare revokes every entitlement and suspends the business.</p>\
        <form method="post" action="\(base)/category">\(csrf)<label for="cat">Category</label><select id="cat" name="category">\(options)</select>\
        <label for="catn">Reason (recorded in the audit log)</label><input id="catn" name="note" type="text" minlength="8" maxlength="300" required>\
        <button class="btn" type="submit">Change category</button></form></div>
        """
        if state.legalEntity == .submitted {
            out += """
            <div class="card"><h2>Legal entity review</h2><form method="post" action="\(base)/legal-entity">\(csrf)<label for="ln">Note (shown to the business if declined)</label><textarea id="ln" name="note" maxlength="500"></textarea>\
            <div class="row"><button class="btn" type="submit" name="decision" value="approve">Approve</button><button class="btn d" type="submit" name="decision" value="reject">Decline</button></div></form></div>
            """
        }
        if state.enhanced == .pending {
            out += """
            <div class="card"><h2>Additional review (sensitive category)</h2><form method="post" action="\(base)/enhanced-review">\(csrf)<label for="er">Reference of the review that was done</label><input id="er" name="reference" type="text" minlength="4" maxlength="120" required>\
            <div class="row"><button class="btn" type="submit" name="decision" value="approve">Approve</button><button class="btn d" type="submit" name="decision" value="reject">Decline</button></div></form></div>
            """
        }
        if state.goLive == .requested || state.goLive == .approved {
            let blockers = state.approvalBlockers
            out += """
            <div class="card"><h2>Production access</h2>\(blockers.isEmpty ? "" : "<p class=\"mu sm\">Open before approval: \(blockers.map { DashboardUI.esc($0.title) }.joined(separator: "; ")).</p>")\
            <form method="post" action="\(base)/go-live">\(csrf)<label for="gn">Note (shown to the business)</label><textarea id="gn" name="note" maxlength="500"></textarea><div class="row">\
            \(state.goLive == .requested ? "<button class=\"btn\" type=\"submit\" name=\"decision\" value=\"approve\">Approve</button><button class=\"btn d\" type=\"submit\" name=\"decision\" value=\"reject\">Decline</button>" : "<button class=\"btn d\" type=\"submit\" name=\"decision\" value=\"revoke\">Revoke production access</button>")\
            </div></form></div>
            """
        }
        let keys = try await BusinessAPIKeyRecord.query(on: req.db).filter(\.$businessId == id).sort(\.$createdAt, .descending).all()
        let keyRows = keys.map { k -> [String] in
            let active = k.isUsable(at: req.ctx.now)
            let revoke = active ? "<form method=\"post\" action=\"\(base)/revoke-key/\(k.id?.uuidString.lowercased() ?? "")\">\(csrf)<label class=\"vh\" for=\"kn-\(k.id?.uuidString.lowercased() ?? "")\">Reason</label><input id=\"kn-\(k.id?.uuidString.lowercased() ?? "")\" name=\"note\" type=\"text\" maxlength=\"200\" placeholder=\"Reason\" required><button class=\"btn d sm\" type=\"submit\">Revoke</button></form>" : DashboardFormat.badge("Not active", "mu")
            return [DashboardUI.esc(k.name), "<code>\(DashboardUI.esc(k.prefix))\(DashboardUI.esc(k.kid ?? "…" + k.last4))</code>", k.livemode ? "Live" : "Test", DashboardFormat.optional(k.lastUsedAt), revoke]
        }
        out += """
        <div class="card"><h2>API keys</h2>\(DashboardFormat.table(["Name", "Key", "Mode", "Last used", ""], keyRows, empty: "No keys.", caption: "API keys of the business"))\
        <p class="mu sm">Revoking keys does not suspend the business.</p>\
        <form method="post" action="\(base)/revoke-keys">\(csrf)<label for="rs">Which keys</label><select id="rs" name="scope"><option value="all">All active keys</option><option value="live">Live keys</option><option value="test">Test keys</option></select>\
        <label for="rn">Reason (shown to the business)</label><input id="rn" name="note" type="text" maxlength="200" required><button class="btn d" type="submit">Revoke keys without suspending</button></form></div>
        <div class="card"><h2>Notify the business</h2><form method="post" action="\(base)/notify">\(csrf)<input type="hidden" name="scope" value="business">\
        <label for="nt">Title</label><input id="nt" name="title" type="text" maxlength="100" required><label for="nb2">Message</label><textarea id="nb2" name="body" maxlength="2000" required></textarea>\
        <label for="ns">Severity</label><select id="ns" name="severity"><option value="info">Information</option><option value="important">Important</option><option value="critical">Critical</option></select><button class="btn s" type="submit">Send</button></form></div>
        """
        return out
    }

    /// Open onboarding reviews, for the operator's landing page.
    static func queues(_ req: Request) async throws -> String {
        let goLive = try await BusinessOnboardingRecord.query(on: req.db).filter(\.$goLiveStatus == OnboardingGoLive.requested.rawValue).sort(\.$goLiveRequestedAt, .ascending).all()
        let legal = try await BusinessOnboardingRecord.query(on: req.db).filter(\.$legalStatus == OnboardingReview.submitted.rawValue).sort(\.$legalSubmittedAt, .ascending).all()
        let ids = Set(goLive.map(\.businessId) + legal.map(\.businessId))
        let names = Dictionary(try await BusinessRecord.query(on: req.db).filter(\.$id ~~ Array(ids)).all().compactMap { b in b.id.map { ($0, b.displayName) } }, uniquingKeysWith: { a, _ in a })
        func link(_ id: UUID) -> String { "<a href=\"/operator/businesses/\(id.uuidString.lowercased())\">\(DashboardUI.esc(names[id] ?? "—"))</a>" }
        let g = goLive.map { [link($0.businessId), DashboardFormat.optional($0.goLiveRequestedAt)] }
        let l = legal.map { [link($0.businessId), DashboardFormat.optional($0.legalSubmittedAt)] }
        return "<div class=\"card\"><h2>Go-live requests</h2>\(DashboardFormat.table(["Organization", "Requested"], g, empty: "None waiting.", caption: "Go-live requests"))</div>"
            + "<div class=\"card\"><h2>Legal entity reviews</h2>\(DashboardFormat.table(["Organization", "Submitted"], l, empty: "None waiting.", caption: "Legal entity reviews"))</div>"
    }
}
