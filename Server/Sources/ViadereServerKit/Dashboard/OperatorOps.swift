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
        ConsoleUI.reason(id: id, label: "Reason (recorded)", help: "8 to 300 characters, recorded in the audit log with your name.")
    }

    private static func switchState(_ on: Bool, onText: String, offText: String) -> String {
        on ? DashboardFormat.badge(onText, "dg") : DashboardFormat.badge(offText, "ok")
    }

    private static func switchesPage(_ req: Request) async throws -> Response {
        let p = try principal(req)
        let csrf = DashboardUI.csrf(p)
        let flags = PlatformFlags(db: req.db, ctx: req.ctx)
        let snapshot = await flags.snapshot()
        func state(_ flag: PlatformFlag, scope: String = "global") -> PlatformFlagCache.Entry? { snapshot[PlatformFlags.key(flag, scope)] }
        var body = ConsoleUI.callout(.warning, title: "Emergency controls", "<p class=\"sm\">Each switch takes effect on the next request. Every change needs your passkey and a recorded reason, and is audited with your name. Capability switches (messaging, approvals, verification and so on) are under <a href=\"/operator/policy\">Capability policy</a>.</p>")
        let maintenance = state(.maintenance)
        body += ConsoleUI.card("Maintenance (read-only) mode", id: "maintenance", description: "While on, every write returns 503 with the message below. Reads, health checks, this console and the SMS/RCS provider callbacks (opt-outs are never lost) keep working.",
                               actions: switchState(maintenance != nil, onText: "On", offText: "Off"), tone: maintenance == nil ? nil : .danger,
            ConsoleUI.form("/operator/switches/maintenance", csrf: csrf,
                ConsoleUI.input("message", label: "Status message shown to clients", id: "message", value: maintenance?.value ?? "", help: "Plain text, up to 200 characters.", attrs: ["maxlength": "200"])
                + reasonField("r-m")
                + ConsoleUI.formActions(ConsoleUI.button("Turn on", .danger, name: "action", value: "on", passkey: true) + ConsoleUI.button("Turn off", .secondary, name: "action", value: "off", passkey: true))))
        func toggle(_ flag: PlatformFlag, _ title: String) -> String {
            let on = state(flag) != nil
            return ConsoleUI.card(title, actions: on ? DashboardFormat.badge("Stopped", "dg") : DashboardFormat.badge("Open", "ok"), tone: on ? .danger : nil,
                "<form method=\"post\" action=\"/operator/switches/signup\">\(csrf)<input type=\"hidden\" name=\"scope\" value=\"\(flag.rawValue)\">\(reasonField("r-" + flag.rawValue.replacingOccurrences(of: ".", with: "-")))"
                + ConsoleUI.formActions(ConsoleUI.button("Stop", .danger, small: true, name: "action", value: "on", ariaLabel: "Stop: \(title)", passkey: true)
                                        + ConsoleUI.button("Reopen", .secondary, small: true, name: "action", value: "off", ariaLabel: "Reopen: \(title)", passkey: true)) + "</form>")
        }
        body += ConsoleUI.sectionTitle("Sign-ups", description: "Existing accounts keep working.")
            + "<div class=\"cols\">\(toggle(.signupConsumer, "New consumer accounts"))\(toggle(.signupBusiness, "New business organizations"))\(toggle(.inviteDashboard, "New dashboard invitations"))</div>"
        body += ConsoleUI.sectionTitle("Loops", description: "Stops every hosted Loop: no new instances, existing ones show a neutral paused state and nothing is actionable. Messaging, approvals and every core feature keep working. Per-Loop and per-business switches are under Loops.")
            + "<div class=\"cols\">\(toggle(.loops, "Hosted Loops"))</div>"
        let webhookRows = snapshot.filter { $0.key.hasPrefix(PlatformFlag.webhooksPause.rawValue + "|") }.map { [DashboardUI.esc(String($0.key.split(separator: "|").last ?? "")), DashboardUI.esc($0.value.reason), DashboardFormat.date($0.value.updatedAt)] }
        body += ConsoleUI.sectionTitle("Delivery")
        body += "<div class=\"cols\">" + ConsoleUI.card("Webhook delivery pause", description: "Queued deliveries stay queued. Leave the business id empty to pause the whole platform.",
                                                        actions: switchState(!webhookRows.isEmpty, onText: "\(webhookRows.count) paused", offText: "Not paused"),
            DashboardFormat.table(["Scope", "Reason", "Since"], webhookRows, empty: "Not paused.", caption: "Webhook pauses")
            + ConsoleUI.form("/operator/switches/webhooks", csrf: csrf,
                ConsoleUI.input("businessId", label: "Business id", id: "wb", placeholder: "Whole platform", optional: true, attrs: ["maxlength": "40", "spellcheck": "false"]) + reasonField("r-w")
                + ConsoleUI.formActions(ConsoleUI.button("Pause", .danger, name: "action", value: "on", passkey: true) + ConsoleUI.button("Resume", .secondary, name: "action", value: "off", passkey: true))))
        let messagingRows = snapshot.filter { $0.key.hasPrefix(PlatformFlag.messagingRestrict.rawValue + "|") }.map { [DashboardUI.esc(String($0.key.split(separator: "|").last ?? "")), "<code>\(DashboardUI.esc($0.value.value))</code>", DashboardUI.esc($0.value.reason)] }
        body += ConsoleUI.card("Emergency messaging restriction", description: "Blocks or rate-clamps outbound SMS, RCS or push for one business or the platform. Sign-in and payment approvals (security purpose) are never covered.",
                               actions: switchState(!messagingRows.isEmpty, onText: "\(messagingRows.count) active", offText: "None"),
            DashboardFormat.table(["Scope", "Restriction", "Reason"], messagingRows, empty: "No restriction.", caption: "Messaging restrictions")
            + ConsoleUI.form("/operator/switches/messaging", csrf: csrf,
                ConsoleUI.input("businessId", label: "Business id", id: "mb", placeholder: "Whole platform", optional: true, attrs: ["maxlength": "40", "spellcheck": "false"])
                + ConsoleUI.select("mode", label: "Mode", id: "mode", options: [ConsoleUI.Option("block", "Block"), ConsoleUI.Option("clamp", "Clamp")])
                + "<fieldset><legend>Channels</legend><div class=\"row\"><label class=\"ck\"><input type=\"checkbox\" name=\"channels[]\" value=\"sms\"> SMS</label><label class=\"ck\"><input type=\"checkbox\" name=\"channels[]\" value=\"rcs\"> RCS</label><label class=\"ck\"><input type=\"checkbox\" name=\"channels[]\" value=\"push\"> Push</label></div></fieldset>"
                + ConsoleUI.input("perMinute", label: "Clamp: messages per minute", id: "pm", type: "number", help: "1 to \(MessagingRestriction.maximumClamp); only for Clamp.", optional: true, attrs: ["min": "1", "max": String(MessagingRestriction.maximumClamp)])
                + reasonField("r-ms")
                + ConsoleUI.formActions(ConsoleUI.button("Apply", .danger, name: "action", value: "on", passkey: true) + ConsoleUI.button("Remove", .secondary, name: "action", value: "off", passkey: true)))) + "</div>"
        let override = state(.abuseThresholds)
        body += ConsoleUI.card("Abuse thresholds", id: "abuse", description: "Bounded: complaint rate \(AbuseOverride.complaintRateBounds.lowerBound) to \(AbuseOverride.complaintRateBounds.upperBound), opt-out rate \(AbuseOverride.optOutRateBounds.lowerBound) to \(AbuseOverride.optOutRateBounds.upperBound), sample \(AbuseOverride.minimumSampleBounds.lowerBound) to \(AbuseOverride.minimumSampleBounds.upperBound), window \(Int(AbuseOverride.windowDaysBounds.lowerBound)) to \(Int(AbuseOverride.windowDaysBounds.upperBound)) days, throttle factor \(AbuseOverride.throttleFactorBounds.lowerBound) to \(AbuseOverride.throttleFactorBounds.upperBound). Leave a field empty to keep the deployment value.",
                               actions: override == nil ? DashboardFormat.badge("Deployment values", "mu") : DashboardFormat.badge("Overridden", "wa"),
            (override.map { "<p class=\"sm\">Current override: <code>\(DashboardUI.esc($0.value))</code></p>" } ?? "")
            + ConsoleUI.form("/operator/switches/abuse", csrf: csrf, "<div class=\"cols\">"
                + ConsoleUI.input("complaintRate", label: "Complaint rate", id: "ac", type: "number", optional: true, attrs: ["step": "0.001"])
                + ConsoleUI.input("optOutRate", label: "Opt-out rate", id: "ao", type: "number", optional: true, attrs: ["step": "0.001"])
                + ConsoleUI.input("minimumSample", label: "Minimum sample", id: "as", type: "number", optional: true)
                + ConsoleUI.input("windowDays", label: "Window (days)", id: "aw", type: "number", optional: true, attrs: ["step": "1"])
                + ConsoleUI.input("throttleFactor", label: "Throttle factor", id: "at", type: "number", optional: true, attrs: ["step": "0.05"]) + "</div>" + reasonField("r-a")
                + ConsoleUI.formActions(ConsoleUI.button("Apply", name: "action", value: "on", passkey: true) + ConsoleUI.button("Reset to deployment values", .secondary, name: "action", value: "off", passkey: true))))
        return DashboardUI.operatorPage(p, title: "Platform switches", active: "/operator/switches", subtitle: "Emergency controls. Every change is audited with your name and a reason.", flash: DashboardFormat.flash(req), body: body)
    }

    private static func consumersPage(_ req: Request) async throws -> Response {
        let p = try principal(req)
        let csrf = DashboardUI.csrf(p)
        let freezes = try await ConsumerFreeze(db: req.db, ctx: req.ctx).freezes()
        let rows = freezes.map { [ConsoleUI.Cell(html: "<code>\($0.consumerId.uuidString.lowercased())</code>"), .text($0.reason), .date($0.frozenAt),
                                  ConsoleUI.Cell(html: $0.releasedAt.map(DashboardFormat.date) ?? DashboardFormat.badge("Frozen", "dg"))] }
        let freeze = ConsoleUI.dangerZone("Freeze an account", description: "Ends every session and device of the account at once and blocks approvals and sign-in. The person is told (in the app and by a generic push).",
            ConsoleUI.form("/operator/consumers/freeze", csrf: csrf,
                ConsoleUI.input("consumerId", label: "Account id", id: "cid", help: "The account's UUID.", required: true, attrs: ["maxlength": "40", "spellcheck": "false", "autocomplete": "off"]) + reasonField("r-f")
                + ConsoleUI.formActions(ConsoleUI.button("Freeze and sign out", .dangerSolid, passkey: true) + ConsoleUI.passkeyNote())))
        let lift = ConsoleUI.card("Lift a freeze", description: "Restores sign-in only; devices stay revoked and the person recovers through the normal flows.",
            ConsoleUI.form("/operator/consumers/unfreeze", csrf: csrf,
                ConsoleUI.input("consumerId", label: "Account id", id: "uid", required: true, attrs: ["maxlength": "40", "spellcheck": "false", "autocomplete": "off"]) + reasonField("r-u")
                + ConsoleUI.formActions(ConsoleUI.button("Unfreeze", .secondary, passkey: true))))
        let body = "<div class=\"cols\">\(freeze)\(lift)</div>" + ConsoleUI.card("Recent freezes", ConsoleUI.table([ConsoleUI.Column("Account"), ConsoleUI.Column("Reason"), ConsoleUI.Column("Frozen"), ConsoleUI.Column("Lifted")],
                                                                                                               rows, caption: "Account freezes", empty: "No freezes."))
        return DashboardUI.operatorPage(p, title: "Consumer accounts", active: "/operator/consumers", subtitle: "Freeze an account for fraud, coercion or a reported compromise.", flash: DashboardFormat.flash(req), body: body)
    }

    private static let severities = [ConsoleUI.Option("info", "Information"), ConsoleUI.Option("important", "Important"), ConsoleUI.Option("critical", "Critical")]

    private static func noticesPage(_ req: Request) async throws -> Response {
        let p = try principal(req)
        let csrf = DashboardUI.csrf(p)
        let recent = try await OperatorNoticeRecord.query(on: req.db).sort(\.$createdAt, .descending).limit(30).all()
        let rows = recent.map { [ConsoleUI.Cell.text($0.title), .text($0.scope.replacingOccurrences(of: "_", with: " ")), ConsoleUI.Cell(html: DashboardFormat.badge($0.severity, $0.severity == "info" ? "mu" : ($0.severity == "critical" ? "dg" : "wa"))),
                                 ConsoleUI.Cell(html: DashboardFormat.badge($0.status, $0.status == "done" ? "ok" : "wa")), .number($0.delivered), .date($0.createdAt)] }
        let scopes = OperatorNotices.Scope.allCases.map { ConsoleUI.Option($0.rawValue, $0.rawValue.replacingOccurrences(of: "_", with: " ").capitalized) }
        let form = ConsoleUI.card("Notify affected parties", description: "Business notices are emailed to Owners, Organization Admins, Security Admins and the security contacts, and listed under Support > Notices. Consumer notices appear in the app's security notices with a generic push. Large audiences are delivered in batches.",
            ConsoleUI.form("/operator/notices", csrf: csrf, "<div class=\"cols\">"
                + ConsoleUI.select("scope", label: "Audience", id: "scope", options: scopes)
                + ConsoleUI.input("businessId", label: "Business id", id: "nb", help: "For the “business” and “consumers of business” audiences.", optional: true, attrs: ["maxlength": "40", "spellcheck": "false"])
                + ConsoleUI.select("severity", label: "Severity", id: "sev", options: severities) + "</div>"
                + ConsoleUI.input("title", label: "Title", id: "title", required: true, attrs: ["maxlength": "100"])
                + ConsoleUI.textarea("body", label: "Message", id: "body", help: "Plain text; up to 300 characters for consumers.", required: true, attrs: ["maxlength": "2000"])
                + ConsoleUI.formActions(ConsoleUI.button("Queue notice", passkey: true) + ConsoleUI.passkeyNote())))
        let body = form + ConsoleUI.card("Recent notices", ConsoleUI.table([ConsoleUI.Column("Title"), ConsoleUI.Column("Audience"), ConsoleUI.Column("Severity"), ConsoleUI.Column("State"),
                                                                             ConsoleUI.Column("Delivered", numeric: true), ConsoleUI.Column("Created")], rows, caption: "Recent notices", empty: "None."))
        return DashboardUI.operatorPage(p, title: "Notices", active: "/operator/notices", subtitle: "Tell businesses and customers about incidents and maintenance.", flash: DashboardFormat.flash(req), body: body)
    }

    private static func retentionPage(_ req: Request) async throws -> Response {
        let p = try principal(req)
        let csrf = DashboardUI.csrf(p)
        let policy = RetentionPolicy(db: req.db, ctx: req.ctx)
        var rows: [[ConsoleUI.Cell]] = []
        for cls in RetentionClass.allCases {
            let def = cls.definition
            let days = try await policy.platformDays(cls)
            rows.append([ConsoleUI.Cell(html: "<code>\(cls.rawValue)</code><br><span class=\"mu sm\">\(DashboardUI.esc(def.summary))</span>", sort: .text(cls.rawValue)),
                         ConsoleUI.Cell(html: "\(def.defaultDays)", sort: .number(Double(def.defaultDays))), .text("\(def.minDays) to \(def.maxDays)"), .text(def.tenantAdjustable ? "Shorten only" : "No"),
                         ConsoleUI.Cell(html: "<form method=\"post\" action=\"/operator/retention/\(cls.rawValue)\" class=\"row\">\(csrf)<label class=\"vh\" for=\"p-\(cls.rawValue)\">Days for \(cls.rawValue)</label><input id=\"p-\(cls.rawValue)\" name=\"days\" type=\"number\" min=\"\(def.minDays)\" max=\"\(def.maxDays)\" value=\"\(days)\"><label class=\"vh\" for=\"pr-\(cls.rawValue)\">Reason</label><input id=\"pr-\(cls.rawValue)\" name=\"reason\" type=\"text\" minlength=\"8\" maxlength=\"300\" placeholder=\"Reason\" required><button class=\"btn s sm\" type=\"submit\">\(ConsoleUI.icon(.key))Set</button></form>")])
        }
        let holds = try await LegalHoldRecord.query(on: req.db).sort(\.$createdAt, .descending).limit(50).all()
        let holdRows = holds.map { h -> [ConsoleUI.Cell] in
            let release = h.releasedAt == nil
                ? ConsoleUI.confirm("Release", ariaLabel: "Release the hold on \(h.scopeKind) \(h.scopeId ?? "")", "<form method=\"post\" action=\"/operator/holds/\(h.id?.uuidString.lowercased() ?? "")/release\">\(csrf)<p>Purging of the matching records resumes.</p><button class=\"btn dd sm\" type=\"submit\">\(ConsoleUI.icon(.key))Release</button></form>")
                : DashboardFormat.date(h.releasedAt!)
            return [.text(h.scopeKind), .text(h.scopeId ?? "—"), .text(h.reason), .date(h.createdAt), ConsoleUI.Cell(html: release)]
        }
        let deletions = try await TenantDataRequests(db: req.db, ctx: req.ctx).openDeletions()
        let deletionRows = deletions.map { r -> [ConsoleUI.Cell] in
            let id = r.id?.uuidString.lowercased() ?? ""
            let carry = ConsoleUI.confirm("Carry out deletion", "<form method=\"post\" action=\"/operator/data-requests/\(id)/complete\">\(csrf)<p>Keys and webhooks are removed, the team is signed out and contact data is deleted. This cannot be undone.</p><button class=\"btn dd sm\" type=\"submit\">\(ConsoleUI.icon(.key))Carry out deletion</button></form>")
            let reject = "<form method=\"post\" action=\"/operator/data-requests/\(id)/reject\" class=\"row\">\(csrf)<label class=\"vh\" for=\"n-\(id)\">Reason</label><input id=\"n-\(id)\" name=\"note\" type=\"text\" maxlength=\"300\" placeholder=\"Reason\" required><button class=\"btn s sm\" type=\"submit\">Reject</button></form>"
            return [ConsoleUI.Cell(html: "<a href=\"/operator/businesses/\(r.businessId.uuidString.lowercased())\">\(r.businessId.uuidString.lowercased().prefix(8))…</a>"), .date(r.createdAt), ConsoleUI.Cell(html: "<div class=\"row\">\(carry)\(reject)</div>")]
        }
        let body = ConsoleUI.card("Organization deletion requests", description: "Requested by an Owner; review before carrying them out.",
                                  ConsoleUI.table([ConsoleUI.Column("Business"), ConsoleUI.Column("Requested"), ConsoleUI.Column("", actions: true)], deletionRows, caption: "Deletion requests", empty: "None waiting."))
            + ConsoleUI.card("Retention by data class", description: "Values are bounded; the purge jobs run every minute. Backups keep erased data until they age out. Setting a value asks for your passkey and a reason.",
                             ConsoleUI.table([ConsoleUI.Column("Class", key: "class"), ConsoleUI.Column("Default", key: "default", numeric: true), ConsoleUI.Column("Bounds"), ConsoleUI.Column("Business may change"), ConsoleUI.Column("", actions: true)],
                                             rows, caption: "Retention by data class", state: ConsoleUI.TableState(req, id: "r")))
            + ConsoleUI.card("Legal holds", description: "A hold stops the purge of the matching records until it is released. Scope: the whole platform, one business id, or one consumer id.",
                DashboardFormat.table(["Scope", "Id", "Reason", "Placed", ""], holdRows.map { $0.map(\.html) }, empty: "No holds.", caption: "Legal holds")
                + "<h3>Place a hold</h3>" + ConsoleUI.form("/operator/holds", csrf: csrf, "<div class=\"cols\">"
                    + ConsoleUI.select("scopeKind", label: "Scope", id: "sk", options: [ConsoleUI.Option("business", "Business"), ConsoleUI.Option("consumer", "Consumer"), ConsoleUI.Option("global", "Whole platform")])
                    + ConsoleUI.input("scopeId", label: "Id", id: "si", help: "Empty for the whole platform.", optional: true, attrs: ["maxlength": "40", "spellcheck": "false"]) + "</div>"
                    + reasonField("r-h") + ConsoleUI.formActions(ConsoleUI.button("Place hold", passkey: true) + ConsoleUI.passkeyNote())))
        return DashboardUI.operatorPage(p, title: "Data and retention", active: "/operator/retention", subtitle: "Retention, legal holds and tenant data requests.", flash: DashboardFormat.flash(req), body: body)
    }

    private static func supportPage(_ req: Request) async throws -> Response {
        let p = try principal(req)
        let csrf = DashboardUI.csrf(p)
        let tickets = try await SupportTicketRecord.query(on: req.db).filter(\.$status != "closed").sort(\.$createdAt, .ascending).limit(100).all()
        let desk = SupportDesk(db: req.db, ctx: req.ctx)
        let names = Dictionary(try await BusinessRecord.query(on: req.db).filter(\.$id ~~ Array(Set(tickets.map(\.businessId)))).all().compactMap { b in b.id.map { ($0, b.displayName) } }, uniquingKeysWith: { a, _ in a })
        let cards = tickets.map { t -> String in
            let id = t.id?.uuidString.lowercased() ?? ""
            let business = "<a href=\"/operator/businesses/\(t.businessId.uuidString.lowercased())\">\(DashboardUI.esc(names[t.businessId] ?? "business"))</a>"
            return ConsoleUI.card(t.subject, descriptionHTML: "\(DashboardFormat.date(t.createdAt)) · \(business) · reference <code>\(id.prefix(8))</code>",
                                  actions: DashboardFormat.badge(t.kind == "appeal" ? "Appeal" : "Ticket", t.kind == "appeal" ? "wa" : "mu"), tone: t.kind == "appeal" ? .warning : nil, """
            <p>\(DashboardUI.esc(desk.body(of: t)))</p>\(t.kind == "appeal" ? ConsoleUI.callout(.neutral, "<p class=\"sm\">Appeals are reviewed by someone who was not involved in the decision.</p>") : "")\
            \(ConsoleUI.form("/operator/support/\(id)", csrf: csrf, ConsoleUI.textarea("note", label: "Reply", id: "n-\(id)", help: "Emailed to the business and shown in its console.", required: true, attrs: ["maxlength": "1000"])
                + ConsoleUI.checkbox("close", label: "Close after replying") + ConsoleUI.formActions(ConsoleUI.button("Send reply", .secondary, passkey: true))))
            """)
        }.joined()
        let appeals = tickets.filter { $0.kind == "appeal" }.count
        let tiles = ConsoleUI.stats([ConsoleUI.Stat(String(tickets.count), "Open"), ConsoleUI.Stat(String(appeals), "Appeals", tone: appeals > 0 ? .warning : nil),
                                     ConsoleUI.Stat(tickets.first.map { DashboardFormat.day($0.createdAt) } ?? "—", "Oldest open since")])
        return DashboardUI.operatorPage(p, title: "Support", active: "/operator/support", subtitle: "Tickets and appeals that are open, oldest first.", flash: DashboardFormat.flash(req),
                                        body: tiles + (cards.isEmpty ? ConsoleUI.empty("Nothing is open", "New tickets and appeals from businesses appear here.", icon: .check) : cards))
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
        // Open reviews first: they are what an operator came here to decide.
        if state.legalEntity == .submitted {
            out += ConsoleUI.card("Legal entity review", description: "Check the registry details below against the public registry.", tone: .warning, ConsoleUI.keyValues([
                ("Registered name", DashboardUI.esc(row.legalRegistryName ?? "—")), ("Registry number", DashboardUI.esc(row.legalRegistryNumber ?? "—")),
                ("Jurisdiction", DashboardUI.esc(row.legalJurisdiction ?? "—")), ("Evidence", row.evidenceReferences.isEmpty ? "—" : row.evidenceReferences.map { DashboardUI.esc($0) }.joined(separator: "<br>")),
            ]) + ConsoleUI.form("\(base)/legal-entity", csrf: csrf,
                ConsoleUI.textarea("note", label: "Note", id: "ln", help: "Shown to the business if declined.", optional: true, attrs: ["maxlength": "500"])
                + ConsoleUI.formActions(ConsoleUI.button("Approve", name: "decision", value: "approve", passkey: true) + ConsoleUI.button("Decline", .danger, name: "decision", value: "reject", passkey: true))))
        }
        if state.enhanced == .pending {
            out += ConsoleUI.card("Additional review (sensitive category)", tone: .warning,
                ConsoleUI.form("\(base)/enhanced-review", csrf: csrf,
                    ConsoleUI.input("reference", label: "Reference of the review that was done", id: "er", required: true, attrs: ["minlength": "4", "maxlength": "120"])
                    + ConsoleUI.formActions(ConsoleUI.button("Approve", name: "decision", value: "approve", passkey: true) + ConsoleUI.button("Decline", .danger, name: "decision", value: "reject", passkey: true))))
        }
        if state.goLive == .requested || state.goLive == .approved {
            let blockers = state.approvalBlockers
            let request = row.goLiveUseCase.map { ConsoleUI.keyValues([("Use case", DashboardUI.esc($0)), ("Volume", DashboardUI.esc(row.goLiveVolume ?? ""))]) } ?? ""
            out += ConsoleUI.card("Production access", actions: DashboardFormat.badge(state.goLive.rawValue, state.goLive == .approved ? "ok" : "wa"), tone: state.goLive == .requested ? .warning : nil,
                request + (blockers.isEmpty ? "" : ConsoleUI.callout(.warning, title: "Open before approval", "<p class=\"sm\">\(blockers.map { DashboardUI.esc($0.title) }.joined(separator: "; ")).</p>"))
                + ConsoleUI.form("\(base)/go-live", csrf: csrf,
                    ConsoleUI.textarea("note", label: "Note", id: "gn", help: "Shown to the business.", optional: true, attrs: ["maxlength": "500"])
                    + ConsoleUI.formActions(state.goLive == .requested
                        ? ConsoleUI.button("Approve", name: "decision", value: "approve", passkey: true) + ConsoleUI.button("Decline", .danger, name: "decision", value: "reject", passkey: true)
                        : ConsoleUI.button("Revoke production access", .danger, name: "decision", value: "revoke", passkey: true))))
        }
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
        out += ConsoleUI.card("Onboarding", actions: ConsoleUI.pill("Stage: \(state.stage.rawValue)", .accent), ConsoleUI.keyValues(facts.map { ($0[0], $0[1]) }))
        // WP-1.9: the category, with the reclassify action (healthcare is refused platform-wide).
        let banned = OnboardingService.isBanned(business.category)
        let options = (DashboardAuthService.categories + ["healthcare"]).map { c in ConsoleUI.Option(c, c.replacingOccurrences(of: "_", with: " "), selected: c == business.category) }
        let bannedNotice = banned ? ConsoleUI.callout(.danger, urgent: true, "<p>This business is in a category Viadere does not serve (healthcare). Follow the offboarding runbook.</p>") : ""
        out += ConsoleUI.card("Category", description: "Current: \(business.category). Reclassifying into healthcare revokes every entitlement and suspends the business.",
            bannedNotice + ConsoleUI.form("\(base)/category", csrf: csrf, "<div class=\"cols\">" + ConsoleUI.select("category", label: "Category", id: "cat", options: options)
                + ConsoleUI.input("note", label: "Reason", id: "catn", help: "Recorded in the audit log.", required: true, attrs: ["minlength": "8", "maxlength": "300"]) + "</div>"
                + ConsoleUI.formActions(ConsoleUI.button("Change category", .secondary, passkey: true))))
        let keys = try await BusinessAPIKeyRecord.query(on: req.db).filter(\.$businessId == id).sort(\.$createdAt, .descending).all()
        let keyRows = keys.map { k -> [String] in
            let active = k.isUsable(at: req.ctx.now)
            let kid = k.id?.uuidString.lowercased() ?? ""
            let revoke = active ? ConsoleUI.confirm("Revoke", ariaLabel: "Revoke \(k.name)", "<form method=\"post\" action=\"\(base)/revoke-key/\(kid)\">\(csrf)<label class=\"vh\" for=\"kn-\(kid)\">Reason</label><input id=\"kn-\(kid)\" name=\"note\" type=\"text\" maxlength=\"200\" placeholder=\"Reason (shown to the business)\" required><p class=\"help\">The business is notified; it is not suspended.</p><button class=\"btn dd sm\" type=\"submit\">\(ConsoleUI.icon(.key))Revoke</button></form>") : DashboardFormat.badge("Not active", "mu")
            return [DashboardUI.esc(k.name), "<code>\(DashboardUI.esc(k.prefix))\(DashboardUI.esc(k.kid ?? "…" + k.last4))</code>", k.livemode ? "Live" : "Test", DashboardFormat.optional(k.lastUsedAt), revoke]
        }
        out += ConsoleUI.card("API keys", description: "Revoking keys does not suspend the business.",
            DashboardFormat.table(["Name", "Key", "Mode", "Last used", ""], keyRows, empty: "No keys.", caption: "API keys of the business")
            + "<h3>Revoke several</h3>" + ConsoleUI.form("\(base)/revoke-keys", csrf: csrf, "<div class=\"cols\">"
                + ConsoleUI.select("scope", label: "Which keys", id: "rs", options: [ConsoleUI.Option("all", "All active keys"), ConsoleUI.Option("live", "Live keys"), ConsoleUI.Option("test", "Test keys")])
                + ConsoleUI.input("note", label: "Reason", id: "rn", help: "Shown to the business.", required: true, attrs: ["maxlength": "200"]) + "</div>"
                + ConsoleUI.formActions(ConsoleUI.button("Revoke keys without suspending", .danger, passkey: true))))
        out += ConsoleUI.card("Notify the business",
            ConsoleUI.form("\(base)/notify", csrf: csrf, ConsoleUI.hidden("scope", "business")
                + ConsoleUI.input("title", label: "Title", id: "nt", required: true, attrs: ["maxlength": "100"])
                + ConsoleUI.textarea("body", label: "Message", id: "nb2", required: true, attrs: ["maxlength": "2000"])
                + ConsoleUI.select("severity", label: "Severity", id: "ns", options: severities)
                + ConsoleUI.formActions(ConsoleUI.button("Send", .secondary, passkey: true))))
        return out
    }

    /// Counts for the operator's landing page.
    static func queueCounts(_ req: Request) async throws -> (goLive: Int, legal: Int, brand: Int, loops: Int, support: Int) {
        let goLive = try await BusinessOnboardingRecord.query(on: req.db).filter(\.$goLiveStatus == OnboardingGoLive.requested.rawValue).count()
        let legal = try await BusinessOnboardingRecord.query(on: req.db).filter(\.$legalStatus == OnboardingReview.submitted.rawValue).count()
        let kits = try await BrandKitRecord.query(on: req.db).filter(\.$status == BrandKitService.KitStatus.pendingReview.rawValue).count()
        let assets = try await BrandAssetRecord.query(on: req.db).filter(\.$state == BrandKitService.AssetState.pendingReview.rawValue).count()
        let loops = try await LoopRevisionRecord.query(on: req.db).filter(\.$state == LoopRevisionState.inReview.rawValue).count()
        let support = try await SupportTicketRecord.query(on: req.db).filter(\.$status != "closed").count()
        return (goLive, legal, kits + assets, loops, support)
    }

    /// Open onboarding reviews, for the operator's landing page.
    static func queues(_ req: Request) async throws -> String {
        let goLive = try await BusinessOnboardingRecord.query(on: req.db).filter(\.$goLiveStatus == OnboardingGoLive.requested.rawValue).sort(\.$goLiveRequestedAt, .ascending).all()
        let legal = try await BusinessOnboardingRecord.query(on: req.db).filter(\.$legalStatus == OnboardingReview.submitted.rawValue).sort(\.$legalSubmittedAt, .ascending).all()
        let ids = Set(goLive.map(\.businessId) + legal.map(\.businessId))
        let names = Dictionary(try await BusinessRecord.query(on: req.db).filter(\.$id ~~ Array(ids)).all().compactMap { b in b.id.map { ($0, b.displayName) } }, uniquingKeysWith: { a, _ in a })
        func link(_ id: UUID) -> String { "<a href=\"/operator/businesses/\(id.uuidString.lowercased())\">\(DashboardUI.esc(names[id] ?? "—"))</a>" }
        func open(_ id: UUID) -> String { ConsoleUI.linkButton("Review", href: "/operator/businesses/\(id.uuidString.lowercased())", small: true, ariaLabel: "Review \(names[id] ?? "business")") }
        let g = goLive.map { [link($0.businessId), DashboardFormat.optional($0.goLiveRequestedAt), open($0.businessId)] }
        let l = legal.map { [link($0.businessId), DashboardFormat.optional($0.legalSubmittedAt), open($0.businessId)] }
        return "<div class=\"cols\">"
            + ConsoleUI.card("Go-live requests", id: "go-live", description: "Production access, oldest first.", DashboardFormat.table(["Organization", "Requested", ""], g, empty: "None waiting.", caption: "Go-live requests"))
            + ConsoleUI.card("Legal entity reviews", id: "legal", description: "Registry checks, oldest first.", DashboardFormat.table(["Organization", "Submitted", ""], l, empty: "None waiting.", caption: "Legal entity reviews"))
            + "</div>"
    }
}
