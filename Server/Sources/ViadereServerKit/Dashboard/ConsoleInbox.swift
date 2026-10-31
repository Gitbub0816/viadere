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
private struct LoopSubmitForm: Content {
    var definition: String
    var template: String?
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
        pages.post("dashboard", "loops") { req -> Response in
            let (p, businessId) = try req.businessDashboard
            guard p.can(.submitLoops), let userId = p.user.id else { throw APIError.forbidden }
            let form = try req.content.decode(LoopSubmitForm.self)
            let revision = try await LoopPublicationService(db: req.db, ctx: req.ctx).submit(businessId: businessId, authorId: userId, definition: Data(form.definition.utf8),
                                                                                            templateKey: form.template.flatMap { $0.isEmpty ? nil : $0 })
            return DashboardResponses.redirect("\(loopsPath)?im=\(revision.stateValue == .inReview ? "submitted" : "failed")")
        }
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
        let rows = items.map { item -> [String] in
            let isRead = read.contains(item.id!)
            let label = titles[item.instanceId] ?? "Request"
            return ["<a href=\"\(inboxPath)/\(item.id!.uuidString.lowercased())\">\(isRead ? "" : "<strong>")\(DashboardUI.esc(label))\(isRead ? "" : "</strong> <span class=\"vh\">(unread)</span>")</a>",
                    DashboardUI.esc(item.queueKey), stateBadge(item.state), item.assigneeId == staff ? "You" : (item.assigneeId == nil ? "—" : "Assigned"),
                    DashboardFormat.date(item.createdAt)]
        }
        let filters = ["": "All", "new": "New", "open": "Open", "waiting": "Waiting for customer", "closed": "Closed"].sorted { $0.key < $1.key }.map { key, title in
            "<a href=\"\(inboxPath)\(key.isEmpty ? "" : "?state=\(key)")\"\((state ?? "") == key ? " aria-current=\"page\"" : "")>\(title)</a>"
        }.joined(separator: " · ")
        let queues = try await InboxQueueRecord.query(on: req.db).filter(\.$businessId == businessId).sort(\.$key).all()
        let queueRows = queues.map { q -> [String] in
            let hours = q.hoursJSON.flatMap { try? JSONDecoder().decode(OperatingHours.self, from: Data($0.utf8)) }
            let zone = TimeZone(identifier: q.timezone) ?? .gmt
            let open = hours.map { $0.isOpen(at: req.ctx.now, timezone: zone) } ?? true
            return [DashboardUI.esc(q.key), DashboardUI.esc(hours?.text ?? "Always open"), DashboardUI.esc(q.timezone), open ? DashboardFormat.badge("Open now", "ok") : DashboardFormat.badge("Closed now", "mu")]
        }
        let hoursForm = p.can(.manageInbox) ? """
        <form method="post" action="\(inboxPath)/hours">\(DashboardUI.csrf(p))<div class="cols">\
        <div><label for="q">Queue</label><input id="q" name="queue" type="text" maxlength="40" value="\(LoopPublicationService.defaultQueue)" required></div>\
        <div><label for="h">Hours (blank = always open)</label><input id="h" name="hours" type="text" maxlength="200" placeholder="1-5 09:00-17:00; 6 10:00-14:00"></div>\
        <div><label for="tz">Time zone</label><input id="tz" name="timezone" type="text" maxlength="64" value="UTC" required></div></div>\
        <p class="mu sm">Hours are shown to your team. Requests still arrive, and customers keep seeing "waiting for them to confirm", outside hours.</p>\
        <button class="btn s" type="submit">Save hours</button></form>
        """ : ""
        let body = """
        <div class="card"><h2>Requests <span class="badge">\(unread) unread</span></h2>\
        <p role="status" aria-live="polite" class="mu sm">\(unread) unread request\(unread == 1 ? "" : "s"). Reload the page to see new requests.</p>\
        <nav aria-label="Filter requests" class="sm">\(filters)</nav>\
        \(DashboardFormat.table(["Request", "Queue", "State", "Assignee", "Received"], rows, empty: "No requests yet.", caption: "Inbox requests"))</div>\
        <div class="card"><h2>Queues and operating hours</h2>\(DashboardFormat.table(["Queue", "Hours", "Time zone", "Now"], queueRows, empty: "Requests go to the default queue.", caption: "Queues"))\(hoursForm)</div>
        """
        return DashboardUI.businessPage(p, title: "Inbox", active: inboxPath, subtitle: "Requests customers sent through your Loops.", flash: flash(req), body: body)
    }

    private static func item(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        guard p.can(.viewInbox), let staff = p.user.id else { throw APIError.forbidden }
        let detail = try await LoopInbox(db: req.db, ctx: req.ctx).open(itemId: try req.uuid("id"), businessId: businessId, staffId: staff)
        let id = detail.item.id!.uuidString.lowercased()
        let answers = detail.answers.map { [DashboardUI.esc($0.step), DashboardUI.esc($0.label), DashboardUI.esc($0.value)] }
        let notes = detail.notes.map { note in
            "<li><span class=\"badge\">\(note.kind == "info_request" ? "Asked customer" : "Note")</span> \(DashboardUI.esc(note.author)), \(DashboardFormat.date(note.at)): \(DashboardUI.esc(note.text))</li>"
        }.joined()
        let outcome = detail.outcome.map { LoopStringCatalog.outcomeText($0, business: "your organization") } ?? "—"
        var actions = ""
        if p.can(.manageInbox) {
            let csrf = DashboardUI.csrf(p)
            let members = try await OrgMembershipRecord.query(on: req.db).filter(\.$businessId == businessId).filter(\.$removedAt == nil).all()
                .filter { OrgRole(rawValue: $0.role)?.permits(.viewInbox) == true }
            let users = try await DashboardUserRecord.query(on: req.db).filter(\.$id ~~ members.map(\.userId)).all()
            let options = "<option value=\"none\">Nobody</option>" + users.map { u in
                "<option value=\"\(u.id!.uuidString.lowercased())\"\(detail.item.assigneeId == u.id ? " selected" : "")>\(DashboardUI.esc(u.displayName))</option>"
            }.joined()
            let final = detail.outcome?.isFinal == true
            actions = """
            <div class="card"><h2>Answer</h2>\(final ? "<p class=\"mu\">This request has a final answer.</p>" : """
            <form method="post" action="\(inboxPath)/\(id)/decide">\(csrf)<fieldset><legend>Decision</legend>\
            <label class="ck"><input type="radio" name="decision" value="accept" required> Confirm</label>\
            <label class="ck"><input type="radio" name="decision" value="reject"> Decline</label>\
            <label class="ck"><input type="radio" name="decision" value="ask_info"> Ask for more information</label></fieldset>\
            <label for="dn">Note (internal; required when asking for information)</label><textarea id="dn" name="note" maxlength="1000"></textarea>\
            <button class="btn" type="submit">Send answer</button></form>
            """)</div>\
            <div class="card"><h2>Assignment and notes</h2><div class="cols">\
            <form method="post" action="\(inboxPath)/\(id)/assign">\(csrf)<label for="as">Assign to</label><select id="as" name="assignee">\(options)</select><p><button class="btn s" type="submit">Assign</button></p></form>\
            <form method="post" action="\(inboxPath)/\(id)/note">\(csrf)<label for="nt">Internal note</label><textarea id="nt" name="note" maxlength="1000" required></textarea><p><button class="btn s" type="submit">Add note</button></p></form>\
            </div></div>
            """
        }
        let body = """
        <div class="card"><h2>\(DashboardUI.esc(detail.definition?.title ?? "Request"))</h2>\
        <p class="sm">State: \(stateBadge(detail.item.state)) · Customer sees: \(DashboardUI.esc(outcome)) · Received \(DashboardFormat.date(detail.item.createdAt)) · Read by \(detail.readers)</p>\
        <p class="mu sm">The customer is identified only by this request. Don't ask for health details, passwords or card numbers.</p>\
        \(DashboardFormat.table(["Step", "Field", "Answer"], answers, empty: "No answers.", caption: "What the customer entered"))\
        <h3>History</h3><ul class="plain">\(notes.isEmpty ? "<li class=\"mu\">No notes yet.</li>" : notes)</ul></div>\(actions)
        """
        return DashboardUI.businessPage(p, title: "Request", active: inboxPath, flash: flash(req), body: body)
    }

    private static func loops(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        guard p.can(.submitLoops) else { throw APIError.forbidden }
        let revisions = try await LoopRevisionRecord.query(on: req.db).filter(\.$businessId == businessId).sort(\.$createdAt, .descending).limit(50).all()
        let definitions = Dictionary(try await LoopDefinitionRecord.query(on: req.db).filter(\.$businessId == businessId).all().map { ($0.id!, $0.key) }, uniquingKeysWith: { a, _ in a })
        var rows: [[String]] = []
        for revision in revisions {
            let reviews = try await LoopReviewRecord.query(on: req.db).filter(\.$revisionId == revision.id!).sort(\.$at, .ascending).all()
            var messages = LoopPublicationService.hits(revision.ruleHitsJSON).filter { !$0.rule.isReviewFlag }.map { "\($0.rule.rawValue) at \($0.path.isEmpty ? "definition" : $0.path)" }
            for review in reviews where review.decision == "reject" || review.decision == "request_changes" {
                if let sealed = review.notesSealed, let text = try? req.ctx.cipher.openString(sealed, context: "loop_reviews.notes", rowId: review.id!) {
                    messages.append("Reviewer: \(text)")
                }
            }
            let stages = "Checks \(reviews.contains { $0.stage == "automated" && $0.decision == "pass" } ? "passed" : "failed") · " +
                "Reviews \(reviews.filter { $0.stage != "automated" && $0.decision == "approve" }.count)/\(revision.requiredReview == LoopReviewLevel.twoPerson.rawValue ? 2 : 1)"
            var withdraw = ""
            if revision.stateValue == .inReview {
                withdraw = "<form method=\"post\" action=\"\(loopsPath)/revisions/\(revision.id!.uuidString.lowercased())/withdraw\">\(DashboardUI.csrf(p))<button class=\"btn s sm\" type=\"submit\">Withdraw</button></form>"
            }
            rows.append([DashboardUI.esc(definitions[revision.definitionId] ?? "—"), String(revision.revision), DashboardUI.esc(revision.state.replacingOccurrences(of: "_", with: " ")),
                         DashboardUI.esc(stages), DashboardUI.esc(messages.prefix(6).joined(separator: "; ")), withdraw])
        }
        let body = """
        <div class="card"><h2>Your Loops</h2><p class="mu sm">Viadere reviews every Loop and every revision before customers can see it: automated checks, then a Viadere reviewer \
        (two for high-risk actions), then a signed publication. You can submit; only Viadere publishes. A published revision keeps serving until a new one passes review.</p>\
        \(DashboardFormat.table(["Loop", "Revision", "State", "Pipeline", "Messages", ""], rows, empty: "No Loops submitted yet.", caption: "Loop revisions"))</div>\
        <div class="card"><h2>Submit a revision</h2><form method="post" action="\(loopsPath)">\(DashboardUI.csrf(p))\
        <label for="def">Loop definition (JSON, schema version 1)</label><textarea id="def" name="definition" rows="14" maxlength="65536" required></textarea>\
        <label for="tpl">Template (optional)</label><input id="tpl" name="template" type="text" maxlength="40">\
        <p class="mu sm">Loops can't collect health information, passwords, card or bank details, or government ids, and can't link anywhere.</p>\
        <button class="btn" type="submit">Submit for review</button></form></div>
        """
        return DashboardUI.businessPage(p, title: "Loops", active: loopsPath, subtitle: "Requests customers can send you from the Viadere app.", flash: flash(req), body: body)
    }

    static func stateBadge(_ state: String) -> String {
        switch state {
        case "new": DashboardFormat.badge("New", "ok")
        case "open": DashboardFormat.badge("Open")
        case "waiting": DashboardFormat.badge("Waiting for customer", "mu")
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
