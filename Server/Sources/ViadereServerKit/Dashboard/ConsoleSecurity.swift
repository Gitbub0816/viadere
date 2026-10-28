import Fluent
import Foundation
import Vapor
import ViadereCore

private struct AllowlistForm: Content { var allowlist: String? }
private struct InactivityForm: Content { var seconds: Int }
private struct ToggleForm: Content { var enabled: String? }
private struct CertificateForm: Content {
    var label: String
    var certificate: String?
    var fingerprint: String?
    var kind: String?
}
private struct AlertsForm: Content {
    var topics: [String]?
    var contacts: String?
}
private struct DecisionNoteForm: Content { var note: String? }

/// Security section (spec §9.1): sessions with revoke, network restrictions, client certificates, alerts and contacts, and second-person approvals.
enum ConsoleSecurity {
    static func register(_ pages: any RoutesBuilder) {
        pages.get("dashboard", "security") { req in try await overview(req) }
        pages.get("dashboard", "security", "sessions") { req in try await sessionsPage(req) }
        pages.post("dashboard", "security", "sessions", ":id", "revoke") { req -> Response in
            let (p, _) = try req.businessDashboard
            let id = try req.uuid("id")
            let own = id == p.session.id
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).revokeSession(id: id)
            let response = DashboardResponses.redirect(own ? "/dashboard/login" : "/dashboard/security/sessions?m=session")
            if own { response.cookies[DashboardRealm.business.cookieName] = DashboardSessionStore.clearingCookie(realm: .business) }
            return response
        }
        pages.post("dashboard", "security", "sessions", "revoke-others") { req -> Response in
            let (p, _) = try req.businessDashboard
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).revokeOtherSessions()
            return DashboardResponses.redirect("/dashboard/security/sessions?m=session")
        }
        pages.get("dashboard", "security", "network") { req in try await networkPage(req) }
        pages.post("dashboard", "security", "network", "allowlist") { req -> Response in
            let (p, _) = try req.businessDashboard
            let form = try req.content.decode(AllowlistForm.self)
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).setConsoleAllowlist(form.allowlist ?? "", callerIP: ClientIP.rawAddress(req, trustedProxies: req.ctx.config.trustedProxyCount))
            return DashboardResponses.redirect("/dashboard/security/network?m=saved")
        }
        pages.post("dashboard", "security", "network", "inactivity") { req -> Response in
            let (p, _) = try req.businessDashboard
            let form = try req.content.decode(InactivityForm.self)
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).setPrivilegedInactivity(seconds: form.seconds)
            return DashboardResponses.redirect("/dashboard/security/network?m=saved")
        }
        pages.get("dashboard", "security", "certificates") { req in try await certificatesPage(req) }
        pages.post("dashboard", "security", "certificates") { req -> Response in
            let (p, _) = try req.businessDashboard
            let form = try req.content.decode(CertificateForm.self)
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).addCertificate(label: form.label, pem: form.certificate, fingerprint: form.fingerprint, asCA: form.kind == "ca")
            return DashboardResponses.redirect("/dashboard/security/certificates?m=cert")
        }
        pages.post("dashboard", "security", "certificates", ":id", "remove") { req -> Response in
            let (p, _) = try req.businessDashboard
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).removeCertificate(id: try req.uuid("id"))
            return DashboardResponses.redirect("/dashboard/security/certificates?m=cert-removed")
        }
        pages.post("dashboard", "security", "certificates", "require") { req -> Response in
            let (p, _) = try req.businessDashboard
            let form = try req.content.decode(ToggleForm.self)
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).setMTLSRequired(form.enabled == "1")
            return DashboardResponses.redirect("/dashboard/security/certificates?m=saved")
        }
        pages.get("dashboard", "security", "alerts") { req in try await alertsPage(req) }
        pages.post("dashboard", "security", "alerts") { req -> Response in
            let (p, _) = try req.businessDashboard
            let form = try req.content.decode(AlertsForm.self)
            let topics = Set((form.topics ?? []).compactMap { SecurityAlertTopic(rawValue: $0) })
            let contacts = (form.contacts ?? "").split(whereSeparator: { $0 == "\n" || $0 == "," || $0 == ";" }).map(String.init)
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).setAlerts(topics: topics, contacts: contacts)
            return DashboardResponses.redirect("/dashboard/security/alerts?m=saved")
        }
        pages.get("dashboard", "security", "approvals") { req in try await approvalsPage(req) }
        pages.post("dashboard", "security", "approvals", "two-person") { req -> Response in
            let (p, _) = try req.businessDashboard
            let form = try req.content.decode(ToggleForm.self)
            let change = try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).setTwoPerson(form.enabled == "1")
            if case .awaitingApproval = change { return DashboardResponses.redirect("/dashboard/security/approvals?m=pending") }
            return DashboardResponses.redirect("/dashboard/security/approvals?m=saved")
        }
        for (verb, approve) in [("approve", true), ("reject", false)] {
            pages.post("dashboard", "security", "approvals", ":id", .constant(verb)) { req -> Response in
                let (p, _) = try req.businessDashboard
                let form = try? req.content.decode(DecisionNoteForm.self)
                try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).decideChange(id: try req.uuid("id"), approve: approve, note: form?.note)
                return DashboardResponses.redirect("/dashboard/security/approvals?m=\(approve ? "approved-change" : "rejected-change")")
            }
        }
        pages.post("dashboard", "security", "approvals", ":id", "cancel") { req -> Response in
            let (p, _) = try req.businessDashboard
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).cancelChange(id: try req.uuid("id"))
            return DashboardResponses.redirect("/dashboard/security/approvals?m=cancelled")
        }
    }

    // MARK: Overview

    private static func overview(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewSecurity)
        let settings = try await SecuritySettings(db: req.db, ctx: req.ctx).settings(businessId: businessId)
        let keys = try await BusinessAPIKeyRecord.query(on: req.db).filter(\.$businessId == businessId).filter(\.$revokedAt == nil).all().filter { $0.isUsable(at: req.ctx.now) }
        let unrestricted = keys.filter { ($0.ipAllowlist ?? "").isEmpty && !$0.requiresMTLS }.count
        let sessions = try await SessionSecurity(db: req.db, ctx: req.ctx).active(businessId: businessId, userId: nil, currentSession: p.session.id)
        let certs = try await MTLSCertificates(db: req.db, ctx: req.ctx).list(businessId: businessId).filter { $0.isActive(at: req.ctx.now) }
        let tiles = "<div class=\"grid\">\(DashboardFormat.stat(String(sessions.count), "Active console sessions"))\(DashboardFormat.stat(String(unrestricted) + " / " + String(keys.count), "Keys without IP or certificate limits"))"
            + "\(DashboardFormat.stat(settings.consoleIPAllowlist.isEmpty ? "Off" : "On", "Console IP allow-list"))\(DashboardFormat.stat(settings.twoPersonRequired ? "On" : "Off", "Two-person approval"))</div>"
        let posture = """
        <div class="card"><h2>Posture</h2><ul>\
        <li>Sign-in: passkeys only, no passwords. Sensitive actions ask for your passkey again and stop working after \(settings.privilegedInactivitySeconds) s of inactivity. <a href="/dashboard/security/network">Change</a></li>\
        <li>Client certificates (Enterprise tier): \(certs.count) active; \(settings.mtlsRequired ? "required for every key" : "optional per key"). <a href="/dashboard/security/certificates">Manage</a></li>\
        <li>Alerts: <a href="/dashboard/security/alerts">sign-ins from new devices, key and role changes, webhook and assurance notices</a> are emailed to the people you choose.</li>\
        <li>Single sign-on for the console is not offered yet; every administrator uses their own passkey.</li></ul></div>
        """
        return DashboardUI.businessPage(p, title: "Security", active: "/dashboard/security", subtitle: "Who can get in, from where, and what happens when something looks wrong.", flash: DashboardFormat.flash(req), body: tiles + posture)
    }

    // MARK: Sessions

    private static func sessionsPage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        let all = req.query[String.self, at: "scope"] == "all" && p.can(.manageSecurity)
        let rows = try await SessionSecurity(db: req.db, ctx: req.ctx).active(businessId: businessId, userId: all ? nil : p.user.id, currentSession: p.session.id)
        let table = rows.map { row -> [String] in
            let s = row.session
            let id = s.id?.uuidString.lowercased() ?? ""
            let label = "\(DashboardUI.esc(s.uaLabel ?? "Unknown device"))\(row.current ? " " + DashboardFormat.badge("This session", "ok") : "")"
            let button = "<form method=\"post\" action=\"/dashboard/security/sessions/\(id)/revoke\">\(DashboardUI.csrf(p))<button class=\"btn d sm\" type=\"submit\" aria-label=\"Sign out \(DashboardUI.esc(s.uaLabel ?? "session"))\">Sign out</button></form>"
            return [DashboardUI.esc(row.userName), label, DashboardUI.esc(s.ipMasked ?? "—"), DashboardUI.esc(s.country ?? "—"), DashboardFormat.date(s.createdAt), DashboardFormat.date(s.lastSeenAt), button]
        }
        var actions = ""
        if p.can(.manageSecurity) {
            actions += all ? "<a class=\"btn s sm\" href=\"/dashboard/security/sessions\">Only mine</a>" : "<a class=\"btn s sm\" href=\"/dashboard/security/sessions?scope=all\">Everyone's sessions</a>"
        }
        let others = "<form method=\"post\" action=\"/dashboard/security/sessions/revoke-others\">\(DashboardUI.csrf(p))<button class=\"btn s\" type=\"submit\">Sign out all my other sessions</button></form>"
        let body = "<div class=\"card\"><h2>\(all ? "All sessions of this organization" : "Your sessions")</h2>\(DashboardFormat.table(["Person", "Device", "Network", "Country", "Signed in", "Last active", ""], table, empty: "No active sessions.", caption: "Active console sessions"))"
            + "<p class=\"mu sm\">Networks are shown without their last part. Sign out any session you do not recognize, then rotate credentials it could have seen. \(all ? "Ending someone else's session asks for your passkey." : "")</p>\(others)</div>"
        return DashboardUI.businessPage(p, title: "Sessions", active: "/dashboard/security/sessions", subtitle: "Where the console is signed in.", actions: actions, flash: DashboardFormat.flash(req), body: body)
    }

    // MARK: Network

    private static func networkPage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewSecurity)
        let settings = try await SecuritySettings(db: req.db, ctx: req.ctx).settings(businessId: businessId)
        let manage = p.can(.manageSecurity)
        let you = ClientIP.rawAddress(req, trustedProxies: req.ctx.config.trustedProxyCount)
        var body = ""
        body += """
        <div class="card"><h2>Console IP allow-list</h2><p class="mu sm">When set, the console works only from these networks. Your current address (\(DashboardUI.esc(IPNetwork.masked(you))).x) must be included, so you cannot lock yourself out. Per-key allow-lists are set when a key is created.</p>\
        <form method="post" action="/dashboard/security/network/allowlist">\(DashboardUI.csrf(p))<label for="allowlist">Allowed networks (comma separated; empty = anywhere)</label>\
        <input id="allowlist" name="allowlist" type="text" maxlength="800" value="\(DashboardUI.esc(settings.consoleIPAllowlist))" \(manage ? "" : "disabled")>\
        \(manage ? "<p><button class=\"btn\" type=\"submit\">Save</button></p>" : "")</form></div>
        """
        body += """
        <div class="card"><h2>Inactivity limit for sensitive actions</h2><p class="mu sm">Creating keys, changing roles and similar actions need your passkey and a session that was active within this many seconds (60 to 900).</p>\
        <form method="post" action="/dashboard/security/network/inactivity">\(DashboardUI.csrf(p))<label for="seconds">Seconds</label>\
        <input id="seconds" name="seconds" type="number" min="60" max="900" value="\(settings.privilegedInactivitySeconds)" \(manage ? "" : "disabled")>\
        \(manage ? "<p><button class=\"btn\" type=\"submit\">Save</button></p>" : "")</form></div>
        """
        return DashboardUI.businessPage(p, title: "Network and timeouts", active: "/dashboard/security/network", flash: DashboardFormat.flash(req), body: body)
    }

    // MARK: Certificates

    private static func certificatesPage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewSecurity)
        let service = MTLSCertificates(db: req.db, ctx: req.ctx)
        let entitled = try await EntitlementService(db: req.db, ctx: req.ctx).snapshot(businessId: businessId).tiers.contains(.e)
        let settings = try await SecuritySettings(db: req.db, ctx: req.ctx).settings(businessId: businessId)
        let certs = try await service.list(businessId: businessId)
        let manage = p.can(.manageSecurity)
        let rows = certs.map { c -> [String] in
            let status = c.revokedAt != nil ? DashboardFormat.badge("Removed", "mu") : (c.isActive(at: req.ctx.now) ? DashboardFormat.badge("Active", "ok") : DashboardFormat.badge("Expired", "dg"))
            let remove = manage && c.revokedAt == nil ? "<form method=\"post\" action=\"/dashboard/security/certificates/\(c.id?.uuidString.lowercased() ?? "")/remove\">\(DashboardUI.csrf(p))<button class=\"btn d sm\" type=\"submit\" aria-label=\"Remove \(DashboardUI.esc(c.label))\">Remove</button></form>" : ""
            return [DashboardUI.esc(c.label), c.kind == "leaf" ? "Certificate" : "Certificate authority", "<code>\(DashboardUI.esc(String(c.fingerprint.prefix(16))))…</code>", DashboardUI.esc(c.subject ?? "—"),
                    c.notAfter.map(DashboardFormat.day) ?? "—", status, remove]
        }
        var body = ""
        if !entitled {
            body += "<div class=\"notice\">Mutual TLS is part of the Enterprise tier. Ask Viadere to enable it for your organization, then add your certificates here.</div>"
        }
        body += "<div class=\"card\"><h2>Certificates</h2>\(DashboardFormat.table(["Label", "Type", "Fingerprint", "Subject", "Expires", "Status", ""], rows, empty: "No certificates yet.", caption: "Client certificates"))"
            + "<p class=\"mu sm\">Viadere terminates mutual TLS at its edge (Cloudflare API Shield) and passes the verified certificate's fingerprint to the API. A key bound to certificates is refused without a matching one. Mutual TLS adds a factor; the API key and every authorization check still apply. Private networking never bypasses them.</p></div>"
        if entitled && manage {
            body += """
            <div class="card"><h2>Add a certificate</h2><form method="post" action="/dashboard/security/certificates">\(DashboardUI.csrf(p))\
            <label for="label">Label</label><input id="label" name="label" type="text" maxlength="64" required>\
            <fieldset><legend>What you are adding</legend><label class="ck"><input type="radio" name="kind" value="leaf" checked> A client certificate (bound by its fingerprint)</label>\
            <label class="ck"><input type="radio" name="kind" value="ca"> A certificate authority (every certificate it issues to you)</label></fieldset>\
            <label for="certificate">PEM certificate (public part only)</label><textarea id="certificate" name="certificate" maxlength="16000" placeholder="-----BEGIN CERTIFICATE-----"></textarea>\
            <label for="fingerprint">Or the SHA-256 fingerprint of a client certificate</label><input id="fingerprint" name="fingerprint" type="text" maxlength="100" placeholder="AB:CD:…">\
            <p class="mu sm">Never paste a private key. The certificate also has to be accepted at the edge: upload the same CA or certificate to the API Shield configuration your Viadere contact gives you.</p>\
            <button class="btn" type="submit">Add certificate</button></form></div>\
            <div class="card"><h2>Require a certificate for every key</h2><form method="post" action="/dashboard/security/certificates/require">\(DashboardUI.csrf(p))\
            <label class="ck"><input type="checkbox" name="enabled" value="1"\(settings.mtlsRequired ? " checked" : "")> Refuse every API key of this organization unless the request carries a bound, verified client certificate</label>\
            <p><button class="btn s" type="submit">Save</button></p></form></div>
            """
        }
        return DashboardUI.businessPage(p, title: "Client certificates", active: "/dashboard/security/certificates", subtitle: "Mutual TLS for enterprise API clients.", flash: DashboardFormat.flash(req), body: body)
    }

    // MARK: Alerts and contacts

    private static func alertsPage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewSecurity)
        let service = SecuritySettings(db: req.db, ctx: req.ctx)
        let subscribed = try await service.subscriptions(businessId: businessId)
        let contacts = try await service.contacts(businessId: businessId)
        let manage = p.can(.manageSecurity)
        let boxes = SecurityAlertTopic.allCases.map { topic in
            "<label class=\"ck\"><input type=\"checkbox\" name=\"topics[]\" value=\"\(topic.rawValue)\"\(subscribed.contains(topic) ? " checked" : "")\(manage ? "" : " disabled")> \(DashboardUI.esc(topic.title))</label>"
        }.joined()
        let body = """
        <div class="card"><h2>Email alerts and security contacts</h2><form method="post" action="/dashboard/security/alerts">\(DashboardUI.csrf(p))\
        <fieldset><legend>Send an email about</legend>\(boxes)</fieldset>\
        <label for="contacts">Security contacts (one address per line, up to five)</label><textarea id="contacts" name="contacts" maxlength="1000" \(manage ? "" : "disabled")>\(DashboardUI.esc(contacts.joined(separator: "\n")))</textarea>\
        <p class="mu sm">Owners, Security Admins and Organization Admins receive these alerts as well. A security contact is the person Viadere writes to in an incident, and is needed before production access. Alerts never contain a secret.</p>\
        \(manage ? "<button class=\"btn\" type=\"submit\">Save</button>" : "")</form></div>
        """
        return DashboardUI.businessPage(p, title: "Alerts and contacts", active: "/dashboard/security/alerts", flash: DashboardFormat.flash(req), body: body)
    }

    // MARK: Approvals

    private static func approvalsPage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewSecurity)
        let settings = try await SecuritySettings(db: req.db, ctx: req.ctx).settings(businessId: businessId)
        let pending = try await PendingChanges(db: req.db, ctx: req.ctx).open(businessId: businessId)
        let users = try await DashboardUserRecord.query(on: req.db).filter(\.$id ~~ pending.map(\.requestedBy)).all()
        let names = Dictionary(users.compactMap { u in u.id.map { ($0, u.displayName) } }, uniquingKeysWith: { a, _ in a })
        let rows = try pending.map { change -> [String] in
            let payload = try PendingChanges(db: req.db, ctx: req.ctx).payload(of: change)
            let what: String
            switch PendingChanges.Kind(rawValue: change.kind) {
            case .apiKey: what = "Create a \(payload.live == true ? "live" : "test") key “\(DashboardUI.esc(payload.name ?? ""))” (\(DashboardUI.esc((payload.scopes ?? []).joined(separator: " "))))\(payload.elevates == true ? " " + DashboardFormat.badge("widens scope", "dg") : "")"
            case .apiKeyRotation: what = "Rotate a key (overlap \(payload.overlapSeconds ?? 0) s)"
            case .roleGrant:
                let title = DashboardUI.esc(OrgRole(rawValue: payload.role ?? "")?.title ?? "")
                switch payload.operation {
                case "invite": what = "Invite with role \(title)"
                case "remove": what = "Remove a \(DashboardUI.esc(OrgRole(rawValue: payload.currentRole ?? "")?.title ?? "")) from the team"
                default: what = "Change a member from \(DashboardUI.esc(OrgRole(rawValue: payload.currentRole ?? "")?.title ?? "")) to \(title)"
                }
            case .securitySetting: what = "Turn off two-person approval"
            case nil: what = DashboardUI.esc(change.kind)
            }
            var action = ""
            let mine = change.requestedBy == p.user.id
            if change.status == "pending" {
                if mine {
                    action = "<form method=\"post\" action=\"/dashboard/security/approvals/\(change.id?.uuidString.lowercased() ?? "")/cancel\">\(DashboardUI.csrf(p))<button class=\"btn s sm\" type=\"submit\">Cancel</button></form>"
                } else if p.can(.approveChanges) {
                    let id = change.id?.uuidString.lowercased() ?? ""
                    action = "<div class=\"row\"><form method=\"post\" action=\"/dashboard/security/approvals/\(id)/approve\">\(DashboardUI.csrf(p))<button class=\"btn sm\" type=\"submit\">Approve</button></form>"
                        + "<form method=\"post\" action=\"/dashboard/security/approvals/\(id)/reject\">\(DashboardUI.csrf(p))<button class=\"btn d sm\" type=\"submit\">Reject</button></form></div>"
                }
            }
            return [what, DashboardUI.esc(names[change.requestedBy] ?? "—"), DashboardFormat.date(change.requestedAt), DashboardFormat.badge(change.status, change.status == "pending" ? "" : "ok"), action]
        }
        var toggle = ""
        if p.can(.manageSecurity) {
            toggle = """
            <div class="card"><h2>Two-person approval</h2><form method="post" action="/dashboard/security/approvals/two-person">\(DashboardUI.csrf(p))\
            <label class="ck"><input type="checkbox" name="enabled" value="1"\(settings.twoPersonRequired ? " checked" : "")> Creating or rotating an API key and granting a role need a second person's approval</label>\
            <p class="mu sm">The approver is always someone other than the requester. For a key, the requester completes it after approval, so only they ever see the secret. Requests expire after 24 hours. Needs at least two people who can approve.</p>\
            <button class="btn" type="submit">Save</button></form></div>
            """
        }
        let list = "<div class=\"card\"><h2>Requests</h2>\(DashboardFormat.table(["Request", "By", "When", "Status", ""], rows, empty: "Nothing is waiting.", caption: "Requests waiting for a second person"))</div>"
        return DashboardUI.businessPage(p, title: "Approvals", active: "/dashboard/security/approvals", subtitle: "Separation of duties for credentials and roles.", flash: DashboardFormat.flash(req), body: toggle + list)
    }
}
