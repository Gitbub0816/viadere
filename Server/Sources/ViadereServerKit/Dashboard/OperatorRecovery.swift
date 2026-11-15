import Fluent
import Foundation
import Vapor
import ViadereCore

/// Operator pages for the operator path of console passkey recovery (G25, docs/SECURITY.md §2.111): look up an organization, see whether it
/// still has an administrator who can do it from the console (then the operator path is closed), request with the identity-proof checklist,
/// approve as a second operator, release after the waiting period, cancel. Every mutation needs a fresh passkey.
enum OperatorRecovery {
    static let path = "/operator/recoveries"

    private static func principal(_ req: Request) throws -> DashboardPrincipal {
        let p = try req.dashboard
        guard p.realm == .operator else { throw APIError.forbidden }
        return p
    }

    private static func mutating(_ req: Request, next: String) throws -> DashboardPrincipal {
        let p = try principal(req)
        guard p.hasFreshReauth(ctx: req.ctx) else { throw ReauthRequired(next: next) }
        return p
    }

    /// The checklist boxes that were ticked (`check_<key>=1`).
    static func submittedChecks(_ req: Request) -> [String] {
        ConsoleRecovery.checklist.compactMap { item in (try? req.content.get(String.self, at: "check_\(item.key)")) == "1" ? item.key : nil }
    }

    static func register(_ pages: any RoutesBuilder) {
        pages.get("operator", "recoveries") { req in try await listPage(req) }
        pages.get("operator", "recoveries", ":id") { req in try await detailPage(req) }
        pages.post("operator", "recoveries") { req -> Response in
            let p = try mutating(req, next: path)
            guard let business = (try? req.content.get(String.self, at: "businessId")).flatMap(UUID.init(uuidString:)),
                  let member = (try? req.content.get(String.self, at: "membershipId")).flatMap(UUID.init(uuidString:)) else {
                throw APIError.validation("Choose the organization and the member.")
            }
            let record = try await ConsoleRecovery(db: req.db, ctx: req.ctx).operatorRequest(operatorId: p.user.id!, businessId: business, membershipId: member,
                reason: (try? req.content.get(String.self, at: "reason")) ?? "", checks: submittedChecks(req))
            return DashboardResponses.redirect("\(path)/\(record.id!.uuidString.lowercased())?m=recovery-requested")
        }
        pages.post("operator", "recoveries", ":id", "approve") { req -> Response in
            let id = try req.uuid("id")
            let p = try mutating(req, next: "\(path)/\(id.uuidString.lowercased())")
            try await ConsoleRecovery(db: req.db, ctx: req.ctx).operatorApprove(id: id, operatorId: p.user.id!, checks: submittedChecks(req))
            return DashboardResponses.redirect("\(path)/\(id.uuidString.lowercased())?m=recovery-approved")
        }
        pages.post("operator", "recoveries", ":id", "release") { req -> Response in
            let id = try req.uuid("id")
            let p = try mutating(req, next: "\(path)/\(id.uuidString.lowercased())")
            try await ConsoleRecovery(db: req.db, ctx: req.ctx).operatorRelease(id: id, operatorId: p.user.id!)
            return DashboardResponses.redirect("\(path)/\(id.uuidString.lowercased())?m=recovery-released")
        }
        pages.post("operator", "recoveries", ":id", "cancel") { req -> Response in
            let id = try req.uuid("id")
            let p = try mutating(req, next: "\(path)/\(id.uuidString.lowercased())")
            let reason = ((try? req.content.get(String.self, at: "reason")) ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            guard ConsoleRecovery.reasonLength.contains(reason.count) else { throw APIError.validation("Record why (8 to 300 characters).", details: ["reason": "required"]) }
            try await ConsoleRecovery(db: req.db, ctx: req.ctx).cancel(id: id, actor: ConsoleRecovery.operatorActor(p.user.id!), by: "operator:" + p.user.id!.uuidString.lowercased())
            return DashboardResponses.redirect("\(path)/\(id.uuidString.lowercased())?m=recovery-cancelled")
        }
    }

    private static func stateLabel(_ r: ConsoleRecoveryRecord) -> String {
        switch r.state {
        case "requested": ConsoleUI.pill("Needs a second operator", .warning)
        case "waiting": ConsoleUI.pill("Waiting period", .accent)
        case "released": ConsoleUI.pill("Link sent", .accent)
        case "completed": ConsoleUI.pill("Completed", .success)
        default: ConsoleUI.pill(r.state.capitalized, .neutral)
        }
    }

    static func checklistFields(prefix: String) -> String {
        ConsoleUI.fieldset("Identity-proof checklist", help: "Confirm every item yourself. What each check requires is set by Viadere's owner and counsel (docs/SECURITY.md §2.111); record references in the reason, never documents.",
            ConsoleRecovery.checklist.map { ConsoleUI.checkbox("check_\($0.key)", label: $0.text, required: true) }.joined())
    }

    private static func listPage(_ req: Request) async throws -> Response {
        let p = try principal(req)
        let open = try await ConsoleRecoveryRecord.query(on: req.db).sort(\.$requestedAt, .descending).limit(100).all()
        let businesses = Dictionary(try await BusinessRecord.query(on: req.db).filter(\.$id ~~ open.map(\.businessId)).all().compactMap { b in b.id.map { ($0, b.displayName) } },
                                    uniquingKeysWith: { a, _ in a })
        let rows = open.map { r -> [ConsoleUI.Cell] in
            let id = r.id!.uuidString.lowercased()
            let name = businesses[r.businessId] ?? "—"
            return [ConsoleUI.Cell(html: "<a href=\"\(path)/\(id)\">\(DashboardUI.esc(name))</a>", sort: .text(name)), .text(r.path == "admin" ? "Organization admin" : "Operator"),
                    ConsoleUI.Cell(html: stateLabel(r), sort: .text(r.state)), .date(r.requestedAt),
                    ConsoleUI.Cell(html: ConsoleUI.linkButton("Open", href: "\(path)/\(id)", small: true, ariaLabel: "Open the recovery for \(name)"))]
        }
        var body = ConsoleUI.callout(.accent, title: "Last resort", "<p class=\"sm\">Use this only when an organization has no other Owner or Organization Admin with a working passkey: otherwise they recover the member from the console (Team). Two different operators, the checklist, a 72-hour waiting period with notice to the organization, then a one-hour link to the member's own address.</p>")
        body += ConsoleUI.card("Recoveries", description: "Newest first, including those started by an organization's own administrators.",
            ConsoleUI.table([ConsoleUI.Column("Organization", key: "org"), ConsoleUI.Column("Path"), ConsoleUI.Column("State", key: "state"),
                             ConsoleUI.Column("Started", key: "started"), ConsoleUI.Column("", actions: true)], rows, caption: "Console recoveries",
                            state: ConsoleUI.TableState(req, id: "rc", defaultSort: "started"), empty: "No recoveries", emptyMessage: "Passkey recoveries of business console users appear here."))
        // Start: look an organization up, then pick the member.
        let lookup = req.query[String.self, at: "business"].flatMap { UUID(uuidString: $0.trimmingCharacters(in: .whitespaces)) }
        var start = "<form method=\"get\" action=\"\(path)\" class=\"row\">" + ConsoleUI.input("business", label: "Organization id", id: "rc-b", value: lookup?.uuidString.lowercased(),
            required: true, attrs: ["maxlength": "36", "size": "40", "spellcheck": "false"])
            + ConsoleUI.button("Look up", .secondary) + "</form><p class=\"help\">The organization id is on its page under Businesses.</p>"
        if let lookup, let business = try await BusinessRecord.find(lookup, on: req.db) {
            let members = try await OrgMembershipRecord.query(on: req.db).filter(\.$businessId == lookup).filter(\.$removedAt == nil).sort(\.$createdAt, .ascending).all()
            let users = Dictionary(try await DashboardUserRecord.query(on: req.db).filter(\.$id ~~ members.map(\.userId)).all().compactMap { u in u.id.map { ($0, u) } },
                                   uniquingKeysWith: { a, _ in a })
            var memberRows: [[String]] = []
            var options: [ConsoleUI.Option] = []
            for m in members {
                let passkeys = try await DashboardPasskeyRecord.query(on: req.db).filter(\.$userId == m.userId).count()
                let user = users[m.userId]
                memberRows.append([DashboardUI.esc(user?.displayName ?? "—"), DashboardUI.esc(OrgRole(rawValue: m.role)?.title ?? m.role), String(passkeys),
                                   DashboardUI.esc(user?.status ?? ""), DashboardFormat.optional(user?.lastLoginAt)])
                options.append(ConsoleUI.Option(m.id!.uuidString.lowercased(), "\(user?.displayName ?? "—") (\(OrgRole(rawValue: m.role)?.title ?? m.role))"))
            }
            start += "<h3>\(DashboardUI.esc(business.displayName))</h3>" + DashboardFormat.table(["Member", "Role", "Passkeys", "Status", "Last sign-in"], memberRows, caption: "Members")
            start += ConsoleUI.form(path, csrf: DashboardUI.csrf(p), ConsoleUI.hidden("businessId", lookup.uuidString.lowercased())
                + ConsoleUI.select("membershipId", label: "Member who lost every passkey", id: "rc-m", options: options)
                + ConsoleUI.reason(id: "rc-r", help: "Why, and the references of the checks you did (ticket, call log). Recorded in the audit log.", multiline: true)
                + checklistFields(prefix: "rq")
                + ConsoleUI.formActions(ConsoleUI.button("Request recovery", passkey: true) + ConsoleUI.passkeyNote()))
        }
        body += ConsoleUI.card("Start a recovery", description: "Refused while the organization has another Owner or Organization Admin with a passkey.", start)
        return DashboardUI.operatorPage(p, title: "Console recovery", active: path, subtitle: "Business console users who lost every passkey.", flash: DashboardFormat.flash(req), body: body)
    }

    private static func detailPage(_ req: Request) async throws -> Response {
        let p = try principal(req)
        let id = try req.uuid("id")
        guard let r = try await ConsoleRecoveryRecord.find(id, on: req.db), let business = try await BusinessRecord.find(r.businessId, on: req.db) else { throw APIError.notFound }
        let user = try await DashboardUserRecord.find(r.userId, on: req.db)
        let role = try await OrgMembershipRecord.find(r.membershipId, on: req.db).flatMap { OrgRole(rawValue: $0.role)?.title }
        let me = p.user.id
        func who(_ id: UUID?) -> String { id.map { $0 == me ? "you" : String($0.uuidString.lowercased().prefix(8)) } ?? "—" }
        let facts = ConsoleUI.card("Recovery", actions: stateLabel(r), ConsoleUI.keyValues([
            ("Organization", "<a href=\"/operator/businesses/\(business.id!.uuidString.lowercased())\">\(DashboardUI.esc(business.displayName))</a>"),
            ("Member", "\(DashboardUI.esc(user?.displayName ?? "—")) · \(DashboardUI.esc(role ?? ""))"),
            ("Path", r.path == "admin" ? "Started by an administrator of the organization" : "Operator-assisted"),
            ("Reason", DashboardUI.esc(r.reason)),
            ("Requested", "\(DashboardFormat.date(r.requestedAt)) by \(who(r.requestedBy))"),
            ("Approved", r.approvedAt.map { "\(DashboardFormat.date($0)) by \(who(r.approvedBy))" } ?? "—"),
            ("Link released no earlier than", DashboardFormat.optional(r.releaseAt)),
            ("Released", r.releasedAt.map { "\(DashboardFormat.date($0)) by \(who(r.releasedBy))" } ?? "—"),
            ("Completed", DashboardFormat.optional(r.completedAt)),
        ]))
        var actions = ""
        let base = "\(path)/\(id.uuidString.lowercased())"
        if r.path == "operator", r.state == "requested" {
            actions += r.requestedBy == me
                ? ConsoleUI.callout(.warning, "<p class=\"sm\">You requested this recovery. A different operator has to confirm the checklist and approve it.</p>")
                : ConsoleUI.card("Approve as the second operator", description: "Starts the 72-hour waiting period and tells every member and security contact of the organization.",
                    ConsoleUI.form("\(base)/approve", csrf: DashboardUI.csrf(p), checklistFields(prefix: "ap")
                        + ConsoleUI.formActions(ConsoleUI.button("Approve recovery", passkey: true) + ConsoleUI.passkeyNote())))
        }
        if r.path == "operator", r.state == "waiting" || r.state == "released" {
            let ready = r.state == "released" || (r.releaseAt.map { req.ctx.now >= $0 } ?? false)
            actions += ConsoleUI.card(r.state == "released" ? "Send a new link" : "Release the enrollment link",
                description: r.state == "released" ? "Only when the last link expired unused." : "Possible once the waiting period has ended. The link goes to the member's own address; you never see it.",
                ConsoleUI.form("\(base)/release", csrf: DashboardUI.csrf(p), ConsoleUI.formActions(ConsoleUI.button(r.state == "released" ? "Send a new link" : "Release link", passkey: true, disabled: !ready)
                    + ConsoleUI.passkeyNote())))
        }
        if r.isOpen {
            actions += ConsoleUI.card("Cancel", tone: .danger, ConsoleUI.form("\(base)/cancel", csrf: DashboardUI.csrf(p),
                ConsoleUI.reason(id: "rc-c") + ConsoleUI.formActions(ConsoleUI.button("Cancel recovery", .danger, passkey: true))))
        }
        return DashboardUI.operatorPage(p, title: business.displayName, active: path, subtitle: "Console passkey recovery", flash: DashboardFormat.flash(req),
                                        breadcrumbs: [ConsoleUI.Crumb("Operator", "/operator"), ConsoleUI.Crumb("Console recovery", path), ConsoleUI.Crumb(business.displayName, nil)],
                                        body: facts + (actions.isEmpty ? "" : "<div class=\"cols\">\(actions)</div>"))
    }
}
