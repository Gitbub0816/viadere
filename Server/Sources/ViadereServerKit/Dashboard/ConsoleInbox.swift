import Fluent
import Foundation
import Vapor
import ViadereCore

private struct InboxDecisionForm: Content {
    var decision: String
    var note: String?
}

private struct InboxNoteForm: Content { var note: String }
private struct InboxAssignForm: Content { var assignee: String? }
private struct InboxHoursForm: Content {
    var queue: String
    var hours: String?
    var timezone: String
}

/// The hosted business inbox (WP-3.4) and Loop submission (WP-3.2 business side). Server-rendered like the rest of the console: every page
/// re-reads the current membership (a role change takes effect on the next request), every POST carries the CSRF token, and the tenant is
/// always the session's organization. Fully keyboard operable (plain links, forms and buttons); new items appear on reload (no script).
enum ConsoleInbox {
    static let inboxPath = "/dashboard/inbox"
    static let loopsPath = "/dashboard/loops"

    static let messages: [String: String] = [
        "accepted": "Marked as confirmed. The customer sees that you confirmed.",
        "rejected": "Marked as declined. The customer sees that you couldn't do this.",
        "asked": "Your question was recorded and the customer was notified.",
        "note": "Note added.", "assigned": "Assignment updated.", "hours": "Operating hours saved.",
        "submitted": "Submitted for Viadere review. Every Loop and every revision is reviewed before customers can see it.",
        "failed": "The automated checks found problems. Fix them and submit a new revision.",
        "withdrawn": "Revision withdrawn.",
    ]

    static func register(_ pages: any RoutesBuilder) {
        pages.get("dashboard", "inbox") { req in try await list(req) }
        pages.get("dashboard", "inbox", ":id") { req in try await item(req) }
        pages.post("dashboard", "inbox", ":id", "decide") { req -> Response in
            let (p, businessId, staff) = try manage(req)
            let id = try req.uuid("id")
            let form = try req.content.decode(InboxDecisionForm.self)
            try await LoopInbox(db: req.db, ctx: req.ctx).decide(itemId: id, businessId: businessId, staffId: staff, decision: form.decision, note: form.note)
            _ = p
            let flag = form.decision == "accept" ? "accepted" : form.decision == "reject" ? "rejected" : "asked"
            return DashboardResponses.redirect("\(inboxPath)/\(id.uuidString.lowercased())?im=\(flag)")
        }
        pages.post("dashboard", "inbox", ":id", "note") { req -> Response in
            let (_, businessId, staff) = try manage(req)
            let id = try req.uuid("id")
            let form = try req.content.decode(InboxNoteForm.self)
            try await LoopInbox(db: req.db, ctx: req.ctx).addNote(itemId: id, businessId: businessId, staffId: staff, kind: "note", text: form.note)
            return DashboardResponses.redirect("\(inboxPath)/\(id.uuidString.lowercased())?im=note")
        }
        pages.post("dashboard", "inbox", ":id", "assign") { req -> Response in
            let (_, businessId, staff) = try manage(req)
            let id = try req.uuid("id")
            let form = try req.content.decode(InboxAssignForm.self)
            let assignee = try form.assignee.flatMap { raw -> UUID? in
                if raw.isEmpty || raw == "none" { return nil }
                guard let id = UUID(uuidString: raw) else { throw APIError.validation("Choose a team member.") }
                return id
            }
            try await LoopInbox(db: req.db, ctx: req.ctx).assign(itemId: id, businessId: businessId, staffId: staff, to: assignee)
            return DashboardResponses.redirect("\(inboxPath)/\(id.uuidString.lowercased())?im=assigned")
        }
        pages.post("dashboard", "inbox", "hours") { req -> Response in
            let (_, businessId, staff) = try manage(req)
            let form = try req.content.decode(InboxHoursForm.self)
            try await LoopInbox(db: req.db, ctx: req.ctx).setHours(businessId: businessId, staffId: staff, queue: form.queue, hours: form.hours ?? "", timezone: form.timezone)
            return DashboardResponses.redirect("\(inboxPath)?im=hours")
        }
        pages.get("dashboard", "loops") { req in try await loops(req) }
        pages.post("dashboard", "loops", "revisions", ":id", "withdraw") { req -> Response in
            let (p, businessId) = try req.businessDashboard
            guard p.can(.submitLoops), let userId = p.user.id else { throw APIError.forbidden }
            try await LoopPublicationService(db: req.db, ctx: req.ctx).withdraw(revisionId: try req.uuid("id"), businessId: businessId, by: userId)
            return DashboardResponses.redirect("\(loopsPath)?im=withdrawn")
        }
    }

    private static func manage(_ req: Request) throws -> (DashboardPrincipal, UUID, UUID) {
        let (p, businessId) = try req.businessDashboard
        guard p.can(.manageInbox), let staff = p.user.id else { throw APIError.forbidden }
        return (p, businessId, staff)
    }

    static func flash(_ req: Request) -> String? { req.query[String.self, at: "im"].flatMap { messages[$0] } }

    // MARK: Pages

    private static func list(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        guard p.can(.viewInbox), let staff = p.user.id else { throw APIError.forbidden }
        let inbox = LoopInbox(db: req.db, ctx: req.ctx)
        let state = req.query[String.self, at: "state"]
        let items = try await inbox.items(businessId: businessId, state: state, queue: nil)
        let read = try await inbox.readIds(staffId: staff, items: items.compactMap(\.id))
        let unread = try await inbox.unreadCount(businessId: businessId, staffId: staff)
        let titles = try await loopTitles(items.map(\.instanceId), on: req.db)
        let rows = items.map { item -> [ConsoleUI.Cell] in
            let isRead = read.contains(item.id!)
            let label = titles[item.instanceId] ?? "Request"
            let link = "<a href=\"\(inboxPath)/\(item.id!.uuidString.lowercased())\">\(isRead ? "" : "<strong>")\(DashboardUI.esc(label))\(isRead ? "" : "</strong> <span class=\"vh\">(unread)</span>")</a>"
            return [ConsoleUI.Cell(html: (isRead ? "" : ConsoleUI.pill("New", .accent) + " ") + link, sort: .text(label)), .text(item.queueKey), ConsoleUI.Cell(html: stateBadge(item.state), sort: .text(item.state)),
                    .text(item.assigneeId == staff ? "You" : (item.assigneeId == nil ? "—" : "Assigned")), .date(item.createdAt)]
        }
        let filters = ConsoleUI.segmented([("", "All"), ("new", "New"), ("open", "Open"), ("waiting", "Waiting for customer"), ("closed", "Closed")].map { key, title in
            (title, "\(inboxPath)\(key.isEmpty ? "" : "?state=\(key)")", (state ?? "") == key)
        }, label: "Filter requests")
        let queues = try await InboxQueueRecord.query(on: req.db).filter(\.$businessId == businessId).sort(\.$key).all()
        let queueRows = queues.map { q -> [ConsoleUI.Cell] in
            let hours = q.hoursJSON.flatMap { try? JSONDecoder().decode(OperatingHours.self, from: Data($0.utf8)) }
            let zone = TimeZone(identifier: q.timezone) ?? .gmt
            let open = hours.map { $0.isOpen(at: req.ctx.now, timezone: zone) } ?? true
            return [.text(q.key), .text(hours?.text ?? "Always open"), .text(q.timezone), ConsoleUI.Cell(html: open ? DashboardFormat.badge("Open now", "ok") : DashboardFormat.badge("Closed now", "mu"))]
        }
        let hoursForm = p.can(.manageInbox) ? ConsoleUI.form("\(inboxPath)/hours", csrf: DashboardUI.csrf(p),
            "<div class=\"cols\">"
            + ConsoleUI.input("queue", label: "Queue", id: "q", value: LoopPublicationService.defaultQueue, required: true, attrs: ["maxlength": "40"])
            + ConsoleUI.input("hours", label: "Hours", id: "h", placeholder: "1-5 09:00-17:00; 6 10:00-14:00", help: "For example 1-5 09:00-17:00 for Monday to Friday. Blank means always open.", optional: true, attrs: ["maxlength": "200"])
            + ConsoleUI.input("timezone", label: "Time zone", id: "tz", value: "UTC", help: "An IANA name, for example America/New_York.", required: true, attrs: ["maxlength": "64"])
            + "</div>" + ConsoleUI.formActions(ConsoleUI.button("Save hours", .secondary))) : ""
        let body = ConsoleUI.card("Requests", actions: filters, """
        <p role="status" aria-live="polite" class="mu sm">\(unread) unread request\(unread == 1 ? "" : "s"). Reload the page to see new requests.</p>\
        \(ConsoleUI.table([ConsoleUI.Column("Request", key: "request"), ConsoleUI.Column("Queue", key: "queue"), ConsoleUI.Column("State", key: "state"), ConsoleUI.Column("Assignee"),
                           ConsoleUI.Column("Received", key: "received")], rows, caption: "Inbox requests", state: ConsoleUI.TableState(req, id: "i", defaultSort: "received", defaultAscending: false),
                          empty: "No requests yet", emptyMessage: "Requests customers send through your Loops arrive here."))
        """) + ConsoleUI.card("Queues and operating hours", description: "Hours are shown to your team. Requests still arrive, and customers keep seeing \"waiting for them to confirm\", outside hours.",
                               ConsoleUI.table([ConsoleUI.Column("Queue"), ConsoleUI.Column("Hours"), ConsoleUI.Column("Time zone"), ConsoleUI.Column("Now")], queueRows, caption: "Queues",
                                               empty: "Requests go to the default queue.") + hoursForm)
        return DashboardUI.businessPage(p, title: "Inbox", active: inboxPath, subtitle: "Requests customers sent through your Loops.", actions: ConsoleUI.pill("\(unread) unread", unread > 0 ? .accent : .neutral),
                                        flash: flash(req), body: body)
    }

    private static func item(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        guard p.can(.viewInbox), let staff = p.user.id else { throw APIError.forbidden }
        let detail = try await LoopInbox(db: req.db, ctx: req.ctx).open(itemId: try req.uuid("id"), businessId: businessId, staffId: staff)
        let id = detail.item.id!.uuidString.lowercased()
        let answers = detail.answers.map { [ConsoleUI.Cell.text($0.step), .text($0.label), .text($0.value)] }
        let notes = detail.notes.map { note in
            (titleHTML: "\(DashboardFormat.badge(note.kind == "info_request" ? "Asked customer" : "Note", note.kind == "info_request" ? "" : "mu")) \(DashboardUI.esc(note.author))",
             meta: DashboardFormat.date(note.at), bodyHTML: DashboardUI.esc(note.text))
        }
        let outcome = detail.outcome.map { LoopStringCatalog.outcomeText($0, business: "your organization") } ?? "—"
        var actions = ""
        if p.can(.manageInbox) {
            let csrf = DashboardUI.csrf(p)
            let members = try await OrgMembershipRecord.query(on: req.db).filter(\.$businessId == businessId).filter(\.$removedAt == nil).all()
                .filter { OrgRole(rawValue: $0.role)?.permits(.viewInbox) == true }
            let users = try await DashboardUserRecord.query(on: req.db).filter(\.$id ~~ members.map(\.userId)).all()
            let options = [ConsoleUI.Option("none", "Nobody")] + users.map { ConsoleUI.Option($0.id!.uuidString.lowercased(), $0.displayName, selected: detail.item.assigneeId == $0.id) }
            let final = detail.outcome?.isFinal == true
            let answer = final ? ConsoleUI.callout(.success, "<p>This request has a final answer.</p>") : ConsoleUI.form("\(inboxPath)/\(id)/decide", csrf: csrf,
                ConsoleUI.choices("decision", legend: "Decision", [ConsoleUI.Choice("accept", "Confirm", help: "The customer sees that you confirmed."),
                                                                   ConsoleUI.Choice("reject", "Decline", help: "The customer sees that you couldn't do this.", tone: .danger),
                                                                   ConsoleUI.Choice("ask_info", "Ask for more information", help: "The customer is notified.")], required: true)
                + ConsoleUI.textarea("note", label: "Note", id: "dn", help: "Internal. Required when asking for information.", optional: true, attrs: ["maxlength": "1000"])
                + ConsoleUI.formActions(ConsoleUI.button("Send answer")))
            actions = ConsoleUI.card("Answer", answer)
                + ConsoleUI.card("Assignment",
                    ConsoleUI.form("\(inboxPath)/\(id)/assign", csrf: csrf, ConsoleUI.select("assignee", label: "Assign to", id: "as", options: options) + ConsoleUI.formActions(ConsoleUI.button("Assign", .secondary))))
                + ConsoleUI.card("Internal note",
                    ConsoleUI.form("\(inboxPath)/\(id)/note", csrf: csrf, ConsoleUI.textarea("note", label: "Note", id: "nt", help: "Only your team sees notes.", required: true, attrs: ["maxlength": "1000"])
                                   + ConsoleUI.formActions(ConsoleUI.button("Add note", .secondary))))
        }
        let summary = ConsoleUI.card(detail.definition?.title ?? "Request", actions: stateBadge(detail.item.state), ConsoleUI.keyValues([
            ("Customer sees", DashboardUI.esc(outcome)), ("Received", DashboardFormat.date(detail.item.createdAt)), ("Read by", String(detail.readers)),
        ]) + ConsoleUI.callout(.neutral, "<p class=\"sm\">The customer is identified only by this request. Don't ask for health details, passwords or card numbers.</p>")
            + "<h3>What the customer entered</h3>" + ConsoleUI.table([ConsoleUI.Column("Step"), ConsoleUI.Column("Field"), ConsoleUI.Column("Answer")], answers, caption: "What the customer entered", empty: "No answers.")
            + "<h3>History</h3>" + (notes.isEmpty ? "<p class=\"mu\">No notes yet.</p>" : ConsoleUI.timeline(notes, label: "Request history")))
        let body = actions.isEmpty ? summary : "<div class=\"split\"><div>\(summary)</div><div>\(actions)</div></div>"
        return DashboardUI.businessPage(p, title: "Request", active: inboxPath, actions: ConsoleUI.linkButton("Back to the inbox", href: inboxPath, small: true), flash: flash(req), body: body)
    }

    private static func loops(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        guard ConsoleLoopStudio.canView(p) else { throw APIError.forbidden }
        let revisions = try await LoopRevisionRecord.query(on: req.db).filter(\.$businessId == businessId).sort(\.$createdAt, .descending).limit(50).all()
        let definitions = Dictionary(try await LoopDefinitionRecord.query(on: req.db).filter(\.$businessId == businessId).all().map { ($0.id!, $0.key) }, uniquingKeysWith: { a, _ in a })
        var rows: [[ConsoleUI.Cell]] = []
        for revision in revisions {
            let reviews = try await LoopReviewRecord.query(on: req.db).filter(\.$revisionId == revision.id!).sort(\.$at, .ascending).all()
            var messages = LoopPublicationService.hits(revision.ruleHitsJSON).filter { !$0.rule.isReviewFlag }.map { "\($0.rule.rawValue) at \($0.path.isEmpty ? "definition" : $0.path)" }
            for review in reviews where review.decision == "reject" || review.decision == "request_changes" {
                if let sealed = review.notesSealed, let text = try? req.ctx.cipher.openString(sealed, context: "loop_reviews.notes", rowId: review.id!) {
                    messages.append("Reviewer: \(text)")
                }
            }
            let checks = reviews.contains { $0.stage == "automated" && $0.decision == "pass" }
            let approvals = reviews.filter { $0.stage != "automated" && $0.decision == "approve" }.count
            let needed = revision.requiredReview == LoopReviewLevel.twoPerson.rawValue ? 2 : 1
            let pipeline = "\(DashboardFormat.badge(checks ? "Checks passed" : "Checks failed", checks ? "ok" : "dg")) \(DashboardFormat.badge("Reviews \(approvals)/\(needed)", approvals >= needed ? "ok" : "mu"))"
            var withdraw = ""
            if revision.stateValue == .inReview && p.can(.submitLoops) {
                withdraw = "<form method=\"post\" action=\"\(loopsPath)/revisions/\(revision.id!.uuidString.lowercased())/withdraw\">\(DashboardUI.csrf(p))<button class=\"btn s sm\" type=\"submit\">Withdraw</button></form>"
            }
            let state = revision.stateValue
            let tone = state == .published ? "ok" : ([.rejected, .validationFailed].contains(state) ? "dg" : (state == .changesRequested ? "wa" : "mu"))
            rows.append([.text(definitions[revision.definitionId] ?? "—"), .number(revision.revision), ConsoleUI.Cell(html: DashboardFormat.badge(ConsoleLoopStudio.stateLabel(state), tone), sort: .text(revision.state)),
                         ConsoleUI.Cell(html: pipeline), ConsoleUI.Cell(html: messages.isEmpty ? "<span class=\"mu\">—</span>" : "<span class=\"sm\">\(DashboardUI.esc(messages.prefix(6).joined(separator: "; ")))</span>"),
                         ConsoleUI.Cell(html: withdraw)])
        }
        let body = ConsoleUI.callout(.accent, title: "How review works", """
        <p class="sm">Viadere reviews every Loop and every revision before customers can see it: automated checks, then a Viadere reviewer (two for high-risk actions), then a signed publication. \
        You can submit; only Viadere publishes. A published revision keeps serving until a new one passes review. Loops can't collect health information, passwords, card or bank details, or government ids, and can't link anywhere.</p>
        """) + ConsoleUI.card("Your Loops", ConsoleUI.table([ConsoleUI.Column("Loop", key: "loop"), ConsoleUI.Column("Revision", key: "rev", numeric: true), ConsoleUI.Column("State", key: "state"),
                                                          ConsoleUI.Column("Pipeline"), ConsoleUI.Column("Messages"), ConsoleUI.Column("", actions: true)],
                                                         rows, caption: "Loop revisions", state: ConsoleUI.TableState(req, id: "l"), empty: "No Loops submitted yet",
                                                         emptyMessage: "Start from a template in Loop Studio, check the preview, and submit it for Viadere review.",
                                                         emptyAction: ConsoleUI.linkButton("Open Loop Studio", href: ConsoleLoopStudio.path, .primary, small: true)))
        return DashboardUI.businessPage(p, title: "Loops", active: loopsPath, subtitle: "Requests customers can send you from the Viadere app.",
                                        actions: ConsoleUI.linkButton("Open Loop Studio", href: ConsoleLoopStudio.path, .primary), flash: flash(req), body: body)
    }

    static func stateBadge(_ state: String) -> String {
        switch state {
        case "new": DashboardFormat.badge("New", "ok")
        case "open": DashboardFormat.badge("Open")
        case "waiting": DashboardFormat.badge("Waiting for customer", "wa")
        default: DashboardFormat.badge("Closed", "mu")
        }
    }

    static func loopTitles(_ instanceIds: [UUID], on db: any Database) async throws -> [UUID: String] {
        guard !instanceIds.isEmpty else { return [:] }
        let instances = try await LoopInstanceRecord.query(on: db).filter(\.$id ~~ instanceIds).all()
        let revisions = Dictionary(try await LoopRevisionRecord.query(on: db).filter(\.$id ~~ instances.map(\.revisionId)).all().map { ($0.id!, $0) }, uniquingKeysWith: { a, _ in a })
        var out: [UUID: String] = [:]
        for instance in instances {
            if let revision = revisions[instance.revisionId], let definition = LoopDefinition.parse(Data(revision.definitionJSON.utf8)).definition {
                out[instance.id!] = definition.title
            }
        }
        return out
    }
}
