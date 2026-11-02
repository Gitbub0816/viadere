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
        let contacts = try await SecuritySettings(db: req.db, ctx: req.ctx).contacts(businessId: businessId)
        let tiles = ConsoleUI.stats([
            ConsoleUI.Stat(String(sessions.count), "Active console sessions", href: "/dashboard/security/sessions"),
            ConsoleUI.Stat("\(unrestricted) / \(keys.count)", "Keys without IP or certificate limits", tone: unrestricted > 0 && keys.contains(where: \.livemode) ? .warning : nil),
            ConsoleUI.Stat(settings.consoleIPAllowlist.isEmpty ? "Off" : "On", "Console IP allow-list", href: "/dashboard/security/network"),
            ConsoleUI.Stat(settings.twoPersonRequired ? "On" : "Off", "Two-person approval", href: "/dashboard/security/approvals"),
        ])
        func item(_ tone: ConsoleUI.Tone, _ icon: ConsoleUI.Icon, _ title: String, _ state: String, _ detail: String, _ href: String?, _ action: String) -> String {
            "<li class=\"\(tone.cls)\"><div>\(ConsoleUI.icon(icon))<div><strong>\(DashboardUI.esc(title))</strong> \(ConsoleUI.pill(state, tone))<br><span class=\"mu sm\">\(DashboardUI.esc(detail))</span></div></div>"
                + (href.map { ConsoleUI.linkButton(action, href: $0, small: true, ariaLabel: "\(action): \(title)") } ?? "") + "</li>"
        }
        let posture = "<ul class=\"attn\">"
            + item(.success, .key, "Sign-in", "Passkeys only", "No passwords. Every administrator uses their own passkey; single sign-on is not offered yet.", nil, "")
            + item(.success, .clock, "Sensitive actions", "\(settings.privilegedInactivitySeconds) s", "They ask for your passkey again and stop working after this much inactivity.", "/dashboard/security/network", "Change")
            + item(settings.consoleIPAllowlist.isEmpty ? .neutral : .success, .lock, "Console network", settings.consoleIPAllowlist.isEmpty ? "Anywhere" : "Allow-list", "Restrict the console to your networks.", "/dashboard/security/network", "Manage")
            + item(certs.isEmpty ? .neutral : .success, .document, "Client certificates", settings.mtlsRequired ? "Required" : "\(certs.count) active", "Mutual TLS for enterprise API clients.", "/dashboard/security/certificates", "Manage")
            + item(settings.twoPersonRequired ? .success : .neutral, .users, "Two-person approval", settings.twoPersonRequired ? "On" : "Off", "Keys and roles need a second person.", "/dashboard/security/approvals", "Manage")
            + item(contacts.isEmpty ? .warning : .success, .megaphone, "Alerts and contacts", contacts.isEmpty ? "No contact" : "\(contacts.count) contact\(contacts.count == 1 ? "" : "s")",
                   "New-device sign-ins, key and role changes, webhook and assurance notices by email.", "/dashboard/security/alerts", "Manage")
            + "</ul>"
        return DashboardUI.businessPage(p, title: "Security", active: "/dashboard/security", subtitle: "Who can get in, from where, and what happens when something looks wrong.", flash: DashboardFormat.flash(req),
                                        body: tiles + ConsoleUI.card("Posture", description: "Each control and where to change it.", posture))
    }

    // MARK: Sessions

    private static func sessionsPage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        let all = req.query[String.self, at: "scope"] == "all" && p.can(.manageSecurity)
        let rows = try await SessionSecurity(db: req.db, ctx: req.ctx).active(businessId: businessId, userId: all ? nil : p.user.id, currentSession: p.session.id)
        let table = rows.map { row -> [ConsoleUI.Cell] in
            let s = row.session
            let id = s.id?.uuidString.lowercased() ?? ""
            let label = "\(DashboardUI.esc(s.uaLabel ?? "Unknown device"))\(row.current ? " " + DashboardFormat.badge("This session", "ok") : "")"
            let button = "<form method=\"post\" action=\"/dashboard/security/sessions/\(id)/revoke\">\(DashboardUI.csrf(p))<button class=\"btn d sm\" type=\"submit\" aria-label=\"Sign out \(DashboardUI.esc(s.uaLabel ?? "session"))\">Sign out</button></form>"
            return [.text(row.userName), ConsoleUI.Cell(html: label, sort: .text(s.uaLabel ?? "")), .text(s.ipMasked ?? "—"), .text(s.country ?? "—"), .date(s.createdAt), .date(s.lastSeenAt), ConsoleUI.Cell(html: button)]
        }
        var scope = ""
        if p.can(.manageSecurity) {
            scope = ConsoleUI.segmented([("Only mine", "/dashboard/security/sessions", !all), ("Everyone's", "/dashboard/security/sessions?scope=all", all)], label: "Whose sessions")
        }
        let others = "<form method=\"post\" action=\"/dashboard/security/sessions/revoke-others\">\(DashboardUI.csrf(p))<button class=\"btn s\" type=\"submit\">Sign out all my other sessions</button></form>"
        let body = ConsoleUI.card(all ? "All sessions of this organization" : "Your sessions", description: "Networks are shown without their last part.", actions: scope,
                                  ConsoleUI.table([ConsoleUI.Column("Person", key: "person"), ConsoleUI.Column("Device"), ConsoleUI.Column("Network"), ConsoleUI.Column("Country"),
                                                   ConsoleUI.Column("Signed in", key: "in"), ConsoleUI.Column("Last active", key: "seen"), ConsoleUI.Column("", actions: true)],
                                                  table, caption: "Active console sessions", state: ConsoleUI.TableState(req, id: "s", defaultSort: "seen", defaultAscending: false), empty: "No active sessions."))
            + ConsoleUI.callout(.neutral, title: "Something you don't recognize?", "<p class=\"sm\">Sign out the session, then rotate the credentials it could have seen. \(all ? "Ending someone else's session asks for your passkey." : "")</p>")
        return DashboardUI.businessPage(p, title: "Sessions", active: "/dashboard/security/sessions", subtitle: "Where the console is signed in.", actions: others, flash: DashboardFormat.flash(req), body: body)
    }

    // MARK: Network

    private static func networkPage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewSecurity)
        let settings = try await SecuritySettings(db: req.db, ctx: req.ctx).settings(businessId: businessId)
        let manage = p.can(.manageSecurity)
        let you = ClientIP.rawAddress(req, trustedProxies: req.ctx.config.trustedProxyCount)
        let readOnly = manage ? "" : ConsoleUI.callout(.neutral, "<p class=\"sm\">Only a Security Admin or Owner can change these settings.</p>")
        let allowlist = ConsoleUI.card("Console IP allow-list", description: "When set, the console works only from these networks. Per-key allow-lists are set when a key is created.",
            ConsoleUI.form("/dashboard/security/network/allowlist", csrf: DashboardUI.csrf(p),
                ConsoleUI.input("allowlist", label: "Allowed networks", id: "allowlist", value: settings.consoleIPAllowlist, placeholder: "198.51.100.0/24, 2001:db8::/48",
                                help: "Comma separated; empty means anywhere. Your current address (\(IPNetwork.masked(you)).x) must be included, so you cannot lock yourself out.",
                                disabled: !manage, attrs: ["maxlength": "800", "spellcheck": "false"])
                + (manage ? ConsoleUI.formActions(ConsoleUI.button("Save", passkey: true) + ConsoleUI.passkeyNote()) : "")))
        let inactivity = ConsoleUI.card("Inactivity limit for sensitive actions", description: "Creating keys, changing roles and similar actions need your passkey and a session that was active within this many seconds.",
            ConsoleUI.form("/dashboard/security/network/inactivity", csrf: DashboardUI.csrf(p),
                ConsoleUI.input("seconds", label: "Seconds", id: "seconds", type: "number", value: String(settings.privilegedInactivitySeconds), help: "From 60 to 900.",
                                disabled: !manage, attrs: ["min": "60", "max": "900", "step": "1"])
                + (manage ? ConsoleUI.formActions(ConsoleUI.button("Save", passkey: true) + ConsoleUI.passkeyNote()) : "")))
        return DashboardUI.businessPage(p, title: "Network and timeouts", active: "/dashboard/security/network", subtitle: "Where the console works from, and how long a confirmation lasts.",
                                        flash: DashboardFormat.flash(req), body: readOnly + "<div class=\"cols\">\(allowlist)\(inactivity)</div>")
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
        let rows = certs.map { c -> [ConsoleUI.Cell] in
            let status = c.revokedAt != nil ? DashboardFormat.badge("Removed", "mu") : (c.isActive(at: req.ctx.now) ? DashboardFormat.badge("Active", "ok") : DashboardFormat.badge("Expired", "dg"))
            let remove = manage && c.revokedAt == nil
                ? ConsoleUI.confirm("Remove", ariaLabel: "Remove \(c.label)", "<form method=\"post\" action=\"/dashboard/security/certificates/\(c.id?.uuidString.lowercased() ?? "")/remove\">\(DashboardUI.csrf(p))"
                    + "<p>Keys bound to this certificate are refused once it is removed.</p><button class=\"btn dd sm\" type=\"submit\" aria-label=\"Remove \(DashboardUI.esc(c.label))\">\(ConsoleUI.icon(.key))Remove</button></form>") : ""
            return [.text(c.label), .text(c.kind == "leaf" ? "Certificate" : "Certificate authority"), ConsoleUI.Cell(html: "<code>\(DashboardUI.esc(String(c.fingerprint.prefix(16))))…</code>"), .text(c.subject ?? "—"),
                    ConsoleUI.Cell(html: c.notAfter.map(DashboardFormat.day) ?? "—", sort: c.notAfter.map { .date($0) }), ConsoleUI.Cell(html: status), ConsoleUI.Cell(html: remove)]
        }
        var body = ""
        if !entitled {
            body += ConsoleUI.callout(.accent, title: "Part of the Enterprise tier", "<p>Ask Viadere to enable mutual TLS for your organization, then add your certificates here.</p>")
        }
        body += ConsoleUI.card("Certificates", description: "Viadere terminates mutual TLS at its edge (Cloudflare API Shield) and passes the verified certificate's fingerprint to the API. A key bound to certificates is refused without a matching one; the API key and every authorization check still apply.",
                               ConsoleUI.table([ConsoleUI.Column("Label", key: "label"), ConsoleUI.Column("Type"), ConsoleUI.Column("Fingerprint"), ConsoleUI.Column("Subject"),
                                                ConsoleUI.Column("Expires", key: "expires"), ConsoleUI.Column("Status"), ConsoleUI.Column("", actions: true)],
                                               rows, caption: "Client certificates", state: ConsoleUI.TableState(req, id: "c"), empty: "No certificates yet."))
        if entitled && manage {
            body += "<div class=\"cols\">" + ConsoleUI.card("Add a certificate", description: "Never paste a private key. Also upload the same CA or certificate to the API Shield configuration your Viadere contact gives you.",
                ConsoleUI.form("/dashboard/security/certificates", csrf: DashboardUI.csrf(p),
                    ConsoleUI.input("label", label: "Label", id: "label", required: true, attrs: ["maxlength": "64"])
                    + ConsoleUI.choices("kind", legend: "What you are adding", [ConsoleUI.Choice("leaf", "A client certificate", help: "Bound by its fingerprint."),
                                                                                 ConsoleUI.Choice("ca", "A certificate authority", help: "Every certificate it issues to you.")], selected: "leaf")
                    + ConsoleUI.textarea("certificate", label: "PEM certificate (public part only)", id: "certificate", placeholder: "-----BEGIN CERTIFICATE-----", optional: true, attrs: ["maxlength": "16000", "spellcheck": "false"])
                    + ConsoleUI.input("fingerprint", label: "Or the SHA-256 fingerprint of a client certificate", id: "fingerprint", placeholder: "AB:CD:…", optional: true, attrs: ["maxlength": "100", "spellcheck": "false"])
                    + ConsoleUI.formActions(ConsoleUI.button("Add certificate", passkey: true) + ConsoleUI.passkeyNote())))
                + ConsoleUI.card("Require a certificate for every key", description: "Refuse every API key of this organization unless the request carries a bound, verified client certificate.",
                    ConsoleUI.form("/dashboard/security/certificates/require", csrf: DashboardUI.csrf(p),
                        ConsoleUI.checkbox("enabled", label: "Require a bound, verified client certificate for every API key", checked: settings.mtlsRequired)
                        + ConsoleUI.formActions(ConsoleUI.button("Save", .secondary, passkey: true) + ConsoleUI.passkeyNote()))) + "</div>"
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
        let body = (contacts.isEmpty ? ConsoleUI.callout(.warning, title: "No security contact yet", "<p>Viadere writes to this person in an incident. One is needed before production access.</p>") : "")
            + ConsoleUI.card("Email alerts and security contacts", description: "Owners, Security Admins and Organization Admins receive these alerts as well. Alerts never contain a secret.",
                ConsoleUI.form("/dashboard/security/alerts", csrf: DashboardUI.csrf(p),
                    "<fieldset><legend>Send an email about</legend><div class=\"cols\">\(boxes)</div></fieldset>"
                    + ConsoleUI.textarea("contacts", label: "Security contacts", id: "contacts", value: contacts.joined(separator: "\n"), help: "One address per line, up to five.", disabled: !manage, attrs: ["maxlength": "1000"])
                    + (manage ? ConsoleUI.formActions(ConsoleUI.button("Save", passkey: true) + ConsoleUI.passkeyNote()) : ConsoleUI.callout(.neutral, "<p class=\"sm\">Only a Security Admin or Owner can change these settings.</p>"))))
        return DashboardUI.businessPage(p, title: "Alerts and contacts", active: "/dashboard/security/alerts", subtitle: "Who hears about security events, and who Viadere contacts in an incident.",
                                        flash: DashboardFormat.flash(req), body: body)
    }

    // MARK: Approvals

    private static func approvalsPage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewSecurity)
        let settings = try await SecuritySettings(db: req.db, ctx: req.ctx).settings(businessId: businessId)
        let pending = try await PendingChanges(db: req.db, ctx: req.ctx).open(businessId: businessId)
        let users = try await DashboardUserRecord.query(on: req.db).filter(\.$id ~~ pending.map(\.requestedBy)).all()
        let names = Dictionary(users.compactMap { u in u.id.map { ($0, u.displayName) } }, uniquingKeysWith: { a, _ in a })
        let rows = try pending.map { change -> [ConsoleUI.Cell] in
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
                    action = "<div class=\"row\"><form method=\"post\" action=\"/dashboard/security/approvals/\(id)/approve\">\(DashboardUI.csrf(p))<button class=\"btn sm\" type=\"submit\">\(ConsoleUI.icon(.key))Approve</button></form>"
                        + ConsoleUI.confirm("Reject", "<form method=\"post\" action=\"/dashboard/security/approvals/\(id)/reject\">\(DashboardUI.csrf(p))"
                            + ConsoleUI.input("note", label: "Note to the requester", id: "rn-\(id)", optional: true, attrs: ["maxlength": "300"])
                            + "<button class=\"btn dd sm\" type=\"submit\">\(ConsoleUI.icon(.key))Reject</button></form>") + "</div>"
                }
            }
            let tone = change.status == "pending" ? "wa" : (change.status == "approved" ? "ok" : "mu")
            return [ConsoleUI.Cell(html: what), .text(names[change.requestedBy] ?? "—"), .date(change.requestedAt), ConsoleUI.Cell(html: DashboardFormat.badge(change.status, tone)), ConsoleUI.Cell(html: action)]
        }
        var toggle = ""
        if p.can(.manageSecurity) {
            toggle = ConsoleUI.card("Two-person approval", description: "The approver is always someone other than the requester. For a key, the requester completes it after approval, so only they ever see the secret. Requests expire after 24 hours. Needs at least two people who can approve.",
                ConsoleUI.form("/dashboard/security/approvals/two-person", csrf: DashboardUI.csrf(p),
                    ConsoleUI.checkbox("enabled", label: "Creating or rotating an API key and granting a role need a second person's approval", checked: settings.twoPersonRequired)
                    + ConsoleUI.formActions(ConsoleUI.button("Save", passkey: true) + ConsoleUI.passkeyNote(settings.twoPersonRequired ? "Turning it off needs your passkey and a second person." : "You'll confirm with your passkey."))))
        }
        let waiting = pending.filter { $0.status == "pending" && $0.requestedBy != p.user.id }.count
        let list = ConsoleUI.card("Requests", description: waiting > 0 && p.can(.approveChanges) ? "\(waiting) waiting for you. Approving or rejecting asks for your passkey." : nil,
                                  ConsoleUI.table([ConsoleUI.Column("Request"), ConsoleUI.Column("By"), ConsoleUI.Column("When"), ConsoleUI.Column("Status"), ConsoleUI.Column("", actions: true)], rows,
                                                  caption: "Requests waiting for a second person", empty: "Nothing is waiting", emptyMessage: "Requests that need a second person appear here."))
        return DashboardUI.businessPage(p, title: "Approvals", active: "/dashboard/security/approvals", subtitle: "Separation of duties for credentials and roles.", flash: DashboardFormat.flash(req), body: list + toggle)
    }
}
