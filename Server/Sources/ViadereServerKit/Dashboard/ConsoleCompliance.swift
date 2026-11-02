import Fluent
import Foundation
import Vapor
import ViadereCore

private struct AcceptForm: Content {
    var slug: String
    var version: String
    var confirm: String?
}
private struct RetentionForm: Content {
    var days: Int?
    var clear: String?
}
private struct DeletionForm: Content { var confirmation: String }

/// Compliance section (spec §9.1): agreements and versions, retention within the allowed bounds, DPA and sub-processors, export and delete
/// requests, and the attestations each capability requires.
enum ConsoleCompliance {
    static func register(_ pages: any RoutesBuilder) {
        pages.get("dashboard", "compliance") { req in try await agreementsPage(req) }
        pages.post("dashboard", "compliance", "accept") { req -> Response in
            let (p, _) = try req.businessDashboard
            let form = try req.content.decode(AcceptForm.self)
            guard form.confirm == "1" else { throw APIError.validation("Confirm that you have read the document.", details: ["confirm": "required"]) }
            let ip = ClientIP.rawAddress(req, trustedProxies: req.ctx.config.trustedProxyCount)
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).acceptContract(slug: form.slug, version: form.version, ip: ip, userAgent: req.headers.first(name: .userAgent) ?? "")
            return DashboardResponses.redirect("/dashboard/compliance?m=accepted")
        }
        pages.get("dashboard", "compliance", "retention") { req in try await retentionPage(req) }
        pages.post("dashboard", "compliance", "retention", ":cls") { req -> Response in
            let (p, _) = try req.businessDashboard
            guard let cls = RetentionClass(rawValue: req.parameters.get("cls") ?? "") else { throw APIError.notFound }
            let form = try req.content.decode(RetentionForm.self)
            let actions = DashboardActions(db: req.db, ctx: req.ctx, principal: p)
            if form.clear == "1" { try await actions.clearRetention(cls) } else {
                guard let days = form.days else { throw APIError.validation("Enter a number of days.", details: ["days": "required"]) }
                try await actions.setRetention(cls, days: days)
            }
            return DashboardResponses.redirect("/dashboard/compliance/retention?m=saved")
        }
        pages.get("dashboard", "compliance", "requests") { req in try await requestsPage(req) }
        pages.post("dashboard", "compliance", "requests", "export") { req -> Response in
            let (p, _) = try req.businessDashboard
            _ = try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).requestExport()
            return DashboardResponses.redirect("/dashboard/compliance/requests?m=requested")
        }
        pages.post("dashboard", "compliance", "requests", "delete") { req -> Response in
            let (p, _) = try req.businessDashboard
            let form = try req.content.decode(DeletionForm.self)
            try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).requestDeletion(confirmation: form.confirmation)
            return DashboardResponses.redirect("/dashboard/compliance/requests?m=requested")
        }
        pages.post("dashboard", "compliance", "requests", ":id", "download") { req -> Response in
            let (p, _) = try req.businessDashboard
            let data = try await DashboardActions(db: req.db, ctx: req.ctx, principal: p).downloadExport(id: try req.uuid("id"))
            let response = Response(status: .ok, body: .init(data: data))
            response.headers.contentType = .json
            response.headers.replaceOrAdd(name: .contentDisposition, value: "attachment; filename=\"viadere-organization-export.json\"")
            response.headers.replaceOrAdd(name: "Content-Security-Policy", value: "default-src 'none'; sandbox")
            return response
        }
    }

    private static func siteOrigin(_ ctx: ServerContext) -> String { ctx.config.relyingPartyOrigin }

    // MARK: Agreements

    private static func agreementsPage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewCompliance)
        let service = ContractService(db: req.db, ctx: req.ctx)
        let statuses = try await service.statuses(businessId: businessId)
        let origin = siteOrigin(req.ctx)
        let canAccept = p.can(.acceptContracts)
        let open = statuses.filter { !$0.current }.count
        let rows = statuses.map { status -> [ConsoleUI.Cell] in
            let doc = status.document
            let link = "<a href=\"\(DashboardUI.esc(doc.url(siteOrigin: origin)))\" rel=\"noopener\">\(DashboardUI.esc(doc.title))</a><br><span class=\"mu sm\">Version \(DashboardUI.esc(doc.version))</span>"
            let state = status.current ? DashboardFormat.badge("Accepted \(status.acceptedVersion ?? "")", "ok") : DashboardFormat.badge("Needs your acceptance", "dg")
            var action = ""
            if canAccept, !(status.acceptedVersion == doc.version) {
                action = """
                <form method="post" action="/dashboard/compliance/accept">\(DashboardUI.csrf(p))<input type="hidden" name="slug" value="\(DashboardUI.esc(doc.slug))"><input type="hidden" name="version" value="\(DashboardUI.esc(doc.version))">\
                <label class="ck"><input type="checkbox" name="confirm" value="1" required> I have read version \(DashboardUI.esc(doc.version)) and accept it for my organization</label>\
                <button class="btn sm" type="submit">\(ConsoleUI.icon(.key))Accept</button></form>
                """
            }
            return [ConsoleUI.Cell(html: link, sort: .text(doc.title)), ConsoleUI.Cell(html: state), .date(status.acceptedAt), ConsoleUI.Cell(html: action)]
        }
        let history = try await service.history(businessId: businessId)
        let names = Dictionary(uniqueKeysWithValues: LegalCatalog.documents.map { ($0.slug, $0.title) })
        let users = try await DashboardUserRecord.query(on: req.db).filter(\.$id ~~ history.map(\.acceptedBy)).all()
        let who = Dictionary(users.compactMap { u in u.id.map { ($0, u.displayName) } }, uniquingKeysWith: { a, _ in a })
        let historyRows = history.map { [ConsoleUI.Cell.text(names[$0.slug] ?? $0.slug), .text($0.version), .text(who[$0.acceptedBy] ?? "—"), .date($0.acceptedAt)] }
        let links = ConsoleUI.card("Data processing and sub-processors", description: "Data region: all data is held in the United States today; a regional choice is not offered yet.", """
        <ul><li><a href="\(origin)/legal/data-processing-addendum/" rel="noopener">Data Processing Addendum</a></li>\
        <li><a href="\(origin)/legal/subprocessors/" rel="noopener">Sub-processors</a></li>\
        <li><a href="\(origin)/legal/incident-notification-policy/" rel="noopener">Incident notification policy</a></li>\
        <li><a href="\(origin)/legal/vulnerability-disclosure-policy/" rel="noopener">Vulnerability disclosure policy</a></li></ul>
        """)
        let attest = try await attestations(req, businessId: businessId, statuses: statuses)
        let banner = open > 0 ? ConsoleUI.callout(.warning, title: "\(open) agreement\(open == 1 ? " needs" : "s need") acceptance",
                                                  "<p>\(canAccept ? "Read each document, tick the box and accept. Accepting asks for your passkey." : "Ask an Owner or Organization Admin to accept them.")</p>") : ""
        let body = banner + ConsoleUI.card("Agreements", description: "When an agreement changes in substance you are asked to accept the new version; editorial changes do not need a new acceptance. Each acceptance records who, when, which version and a hash of the network and browser.",
                                           ConsoleUI.table([ConsoleUI.Column("Document"), ConsoleUI.Column("Status"), ConsoleUI.Column("Accepted"), ConsoleUI.Column("", actions: true)], rows, caption: "Agreements and their versions"))
            + "<div class=\"cols\">" + attest + links + "</div>"
            + ConsoleUI.card("Acceptance history", ConsoleUI.table([ConsoleUI.Column("Document"), ConsoleUI.Column("Version"), ConsoleUI.Column("Accepted by"), ConsoleUI.Column("When")], historyRows,
                                                                    caption: "Acceptance history", empty: "Nothing accepted yet."))
        return DashboardUI.businessPage(p, title: "Compliance", active: "/dashboard/compliance", subtitle: "Agreements, retention and your data.", flash: DashboardFormat.flash(req), body: body)
    }

    /// The attestations each capability needs, derived from what the organization holds (nothing here is a separate checkbox).
    private static func attestations(_ req: Request, businessId: UUID, statuses: [ContractService.Status]) async throws -> String {
        let state = try await OnboardingService(db: req.db, ctx: req.ctx).state(businessId: businessId)
        func status(_ slug: String) -> String {
            guard let s = statuses.first(where: { $0.document.slug == slug }) else { return DashboardFormat.badge("Not required", "mu") }
            return s.current ? DashboardFormat.badge("Attested", "ok") : DashboardFormat.badge("Open", "dg")
        }
        let rows = [
            ["Consent, opt-out and content rules for messaging", status("messaging-consent-content-policy-addendum")],
            ["Approvals: incident readiness and enrollment controls (Tier A)", status("mfa-approval-services-addendum")],
            ["Verified attributes: purpose, minimization and retention (Tier V)", status("verification-services-addendum")],
            ["Legal entity reviewed", state.legalEntity == .approved ? DashboardFormat.badge("Reviewed", "ok") : DashboardFormat.badge("Open", "dg")],
            ["Additional review for sensitive categories", state.enhanced == .notRequired ? DashboardFormat.badge("Not required", "mu") : (state.enhanced == .approved ? DashboardFormat.badge("Reviewed", "ok") : DashboardFormat.badge("Open", "dg"))],
        ]
        return ConsoleUI.card("Required attestations", description: "Derived from the agreements you accepted and the reviews Viadere completed.",
                              DashboardFormat.table(["Attestation", "Status"], rows, caption: "Required attestations"))
    }

    // MARK: Retention

    private static func retentionPage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewCompliance)
        let policy = RetentionPolicy(db: req.db, ctx: req.ctx)
        let manage = p.can(.manageCompliance)
        var rows: [[ConsoleUI.Cell]] = []
        for cls in RetentionClass.allCases {
            let def = cls.definition
            let platform = try await policy.platformDays(cls)
            let effective = try await policy.effectiveDays(cls, businessId: businessId)
            var control = def.tenantAdjustable ? "" : "<span class=\"mu sm\">Set by Viadere</span>"
            if def.tenantAdjustable, manage {
                control = """
                <form method="post" action="/dashboard/compliance/retention/\(cls.rawValue)" class="row">\(DashboardUI.csrf(p))<label class="vh" for="d-\(cls.rawValue)">Days for \(cls.rawValue)</label>\
                <input id="d-\(cls.rawValue)" name="days" type="number" min="\(def.minDays)" max="\(platform)" value="\(effective)"><button class="btn s sm" type="submit">\(ConsoleUI.icon(.key))Save</button></form>
                """
                if effective < platform {
                    control += "<form method=\"post\" action=\"/dashboard/compliance/retention/\(cls.rawValue)\">\(DashboardUI.csrf(p))<input type=\"hidden\" name=\"clear\" value=\"1\"><button class=\"btn g sm\" type=\"submit\">Use the platform value</button></form>"
                }
            }
            let applies = effective < platform ? "<strong>\(effective)</strong> " + DashboardFormat.badge("Shortened", "ok") : "\(effective)"
            rows.append([ConsoleUI.Cell(html: DashboardUI.esc(def.summary) + "<br><span class=\"mu sm\">\(DashboardUI.esc(def.tables))</span>", sort: .text(def.summary)),
                         ConsoleUI.Cell(html: "\(platform)", sort: .number(Double(platform))), .text("\(def.minDays) to \(def.maxDays)"), ConsoleUI.Cell(html: applies, sort: .number(Double(effective))), ConsoleUI.Cell(html: control)])
        }
        let body = ConsoleUI.callout(.accent, title: "Shorten, never lengthen", """
        <p class="sm">You can shorten the classes marked adjustable for your own data, never lengthen them. A legal hold placed by Viadere on your organization suspends purging until it is released. \
        Backups keep erased data until they age out (point-in-time recovery window: 7 days in staging, 35 days in production).\(manage ? " Saving asks for your passkey." : "")</p>
        """) + ConsoleUI.panel(ConsoleUI.table([ConsoleUI.Column("Data", key: "data"), ConsoleUI.Column("Platform days", key: "platform", numeric: true), ConsoleUI.Column("Allowed range"),
                                                 ConsoleUI.Column("Applies to you", key: "applies", numeric: true), ConsoleUI.Column("", actions: true)],
                                                rows, caption: "Retention by data class", state: ConsoleUI.TableState(req, id: "r")))
        return DashboardUI.businessPage(p, title: "Retention", active: "/dashboard/compliance/retention", subtitle: "How long data is kept, in days.", flash: DashboardFormat.flash(req), body: body)
    }

    // MARK: Requests

    private static func requestsPage(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        try p.require(.viewCompliance)
        let requests = try await TenantDataRequests(db: req.db, ctx: req.ctx).list(businessId: businessId)
        let manage = p.can(.manageDataRequests)
        let rows = requests.map { r -> [ConsoleUI.Cell] in
            var action = ""
            if manage, r.kind == "export", r.status == "ready", let expires = r.artifactExpiresAt, expires > req.ctx.now, let id = r.id?.uuidString.lowercased() {
                action = "<form method=\"post\" action=\"/dashboard/compliance/requests/\(id)/download\">\(DashboardUI.csrf(p))<button class=\"btn sm\" type=\"submit\">\(ConsoleUI.icon(.key))Download</button></form>"
            }
            return [.text(r.kind == "export" ? "Export" : "Deletion"), ConsoleUI.Cell(html: DashboardFormat.badge(r.status, r.status == "ready" || r.status == "completed" ? "ok" : "wa")),
                    .date(r.createdAt), .text(r.note ?? "—"), ConsoleUI.Cell(html: action)]
        }
        var forms = ""
        if manage {
            forms += ConsoleUI.card("Export your organization's data", description: "Profile, team, credential metadata (never secrets), webhooks, domains, agreements, settings, audit events and totals. Customer-level data is not included. Ready at once and available for 24 hours.",
                                    ConsoleUI.form("/dashboard/compliance/requests/export", csrf: DashboardUI.csrf(p), ConsoleUI.formActions(ConsoleUI.button("Prepare export", passkey: true) + ConsoleUI.passkeyNote())))
        }
        let list = ConsoleUI.card("Requests", ConsoleUI.table([ConsoleUI.Column("Type"), ConsoleUI.Column("Status"), ConsoleUI.Column("Requested"), ConsoleUI.Column("Note"), ConsoleUI.Column("", actions: true)], rows,
                                                         caption: "Data requests", empty: "No requests yet."))
        var danger = ""
        if p.role == .owner {
            danger = ConsoleUI.dangerZone("Delete your organization's data", description: "An Owner can ask Viadere to end this organization: API keys and webhooks are removed, the team is signed out, and your contact data is deleted. Your handle and code stay reserved and are never reused. A Viadere operator reviews every request; audit records follow their retention period.",
                ConsoleUI.form("/dashboard/compliance/requests/delete", csrf: DashboardUI.csrf(p),
                    ConsoleUI.input("confirmation", label: "Type DELETE to confirm", id: "confirmation", help: "In capital letters.", required: true, attrs: ["autocomplete": "off", "spellcheck": "false"])
                    + ConsoleUI.formActions(ConsoleUI.button("Request deletion", .dangerSolid, passkey: true) + ConsoleUI.passkeyNote())))
        }
        return DashboardUI.businessPage(p, title: "Data requests", active: "/dashboard/compliance/requests", subtitle: "Export or delete your organization's data.", flash: DashboardFormat.flash(req),
                                        body: forms + list + danger)
    }
}
