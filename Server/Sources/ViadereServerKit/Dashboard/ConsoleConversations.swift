import Fluent
import Foundation
import Vapor
import ViadereCore
import typealias ViadereCore.SessionID
import enum ViadereCore.Channel

private struct ConversationReplyForm: Content {
    var body: String
    var agent_name: String?
    var idempotency_key: String
}

private struct ConversationAssignForm: Content { var assignee: String? }

private struct ConversationImageForm: Content { var file: File }

/// The console conversation inbox (G5, docs/SECURITY.md §2.108): a business without its own integration reads and answers customer messages.
///
/// * Tenant: every query filters on the session's organization; another tenant's thread id is the same plain `404` as an unknown one, for
///   reading and for every action.
/// * Permissions are re-read on every request (`viewConversations` to read, `replyConversations` to act), so a role change applies on the
///   next request.
/// * Customers appear only as this business's pairwise `subject_ref` (§2.30), never as a Viadere account id, phone number or name.
/// * Message bodies are decrypted only after the tenant check; every thread opened writes `conversation.console_read` (actor, thread id,
///   never a body); output is escaped.
/// * A reply goes through `ConversationService.businessSend`, the business API's `sendMessage` path: the same validation, idempotency,
///   policy and consent check, test/live separation, channel routing (SMS thread or push) and attribution (the verified business name).
/// * Images (SECURITY.md §2.113): an upload goes through `MessageAttachmentService.businessUpload` with the same console principal; a
///   thumbnail is the console download route (same origin, `viewConversations`, tenant-checked), never a storage URL. Nothing about an image
///   is rendered but its dimensions and the escaped, fixed alt text.
enum ConsoleConversations {
    static let path = "/dashboard/conversations"
    /// The image plus multipart framing.
    static let uploadBodyLimit = MessageAttachmentPolicy.maxUploadBytes + 64 * 1024

    static let messages: [String: String] = [
        "sent": "Reply sent.", "duplicate": "That reply was already sent.", "assigned": "Assignment updated.",
        "closed": "Conversation closed. The customer can start a new one.", "reopened": "Conversation reopened.",
        "image": "Image added. It is sent with your next reply.",
    ]

    /// `POST /dashboard/conversations/{uuid}/attachments`: the console's only multipart path besides the Brand Studio upload.
    static func isUploadPath(_ path: String) -> Bool {
        let parts = path.split(separator: "/", omittingEmptySubsequences: false)
        return parts.count == 5 && parts[0].isEmpty && parts[1] == "dashboard" && parts[2] == "conversations"
            && UUID(uuidString: String(parts[3])) != nil && parts[4] == "attachments"
    }

    static func attachmentPath(session: UUID, attachment: AttachmentID) -> String {
        "\(path)/\(session.uuidString.lowercased())/attachments/\(attachment)"
    }

    /// `POST /dashboard/conversations/:id/attachments` (multipart), on a route group that collects the bounded body before authentication.
    static func registerUpload(_ group: any RoutesBuilder) {
        group.on(.POST, "dashboard", "conversations", ":id", "attachments", body: .collect(maxSize: ByteCount(value: uploadBodyLimit))) { req -> Response in
            let (_, business, staff) = try act(req)
            let id = try req.uuid("id")
            let form: ConversationImageForm
            do { form = try req.content.decode(ConversationImageForm.self) } catch { throw APIError.validation("Choose an image file.", details: ["file": "missing"]) }
            let declared = form.file.contentType.map { "\($0.type)/\($0.subType)" } ?? ""
            _ = try await ConsoleConversationService(db: req.db, ctx: req.ctx)
                .upload(business: business, staffId: staff, sessionId: id, data: Data(buffer: form.file.data), contentType: declared, runtime: req.attachments)
            return DashboardResponses.redirect("\(path)/\(id.uuidString.lowercased())?cm=image")
        }
    }

    static func register(_ pages: any RoutesBuilder) {
        pages.get("dashboard", "conversations") { req in try await list(req) }
        pages.get("dashboard", "conversations", ":id") { req in try await thread(req) }
        pages.get("dashboard", "conversations", ":id", "attachments", ":attachmentId") { req -> Response in
            let (p, businessId) = try req.businessDashboard
            guard p.can(.viewConversations) else { throw APIError.forbidden }
            let session = try await ConsoleConversationService(db: req.db, ctx: req.ctx).owned(businessId: businessId, sessionId: try req.uuid("id"))
            guard let attachmentId = req.parameters.get("attachmentId").flatMap(AttachmentID.init) else { throw APIError.notFound }
            let (row, data) = try await MessageAttachmentService(db: req.db, ctx: req.ctx, runtime: req.attachments)
                .businessDownload(businessId: businessId, session: session, attachmentId: attachmentId)
            return MessageAttachmentService.imageResponse(data, row: row, disposition: .inline)
        }
        pages.post("dashboard", "conversations", ":id", "reply") { req -> Response in
            let (p, business, staff) = try act(req)
            let id = try req.uuid("id")
            let form = try req.content.decode(ConversationReplyForm.self)
            // Ticked images are `image_<id>` checkboxes (only ids are read; the service re-checks every one).
            let fields = (try? req.content.decode([String: String].self)) ?? [:]
            let images = fields.keys.filter { $0.hasPrefix("image_") }.sorted().compactMap { AttachmentID(String($0.dropFirst(6))) }
            let created = try await ConsoleConversationService(db: req.db, ctx: req.ctx)
                .reply(business: business, staffId: staff, sessionId: id, body: form.body, agentName: form.agent_name, formKey: form.idempotency_key,
                       attachmentIds: images)
            _ = p
            return DashboardResponses.redirect("\(path)/\(id.uuidString.lowercased())?cm=\(created ? "sent" : "duplicate")")
        }
        pages.post("dashboard", "conversations", ":id", "assign") { req -> Response in
            let (_, business, staff) = try act(req)
            let id = try req.uuid("id")
            let form = try req.content.decode(ConversationAssignForm.self)
            let assignee = try form.assignee.flatMap { raw -> UUID? in
                if raw.isEmpty || raw == "none" { return nil }
                guard let id = UUID(uuidString: raw) else { throw APIError.validation("Choose a team member.") }
                return id
            }
            try await ConsoleConversationService(db: req.db, ctx: req.ctx).assign(businessId: business.id!, staffId: staff, sessionId: id, to: assignee)
            return DashboardResponses.redirect("\(path)/\(id.uuidString.lowercased())?cm=assigned")
        }
        for (action, open) in [("close", false), ("reopen", true)] {
            pages.post("dashboard", "conversations", ":id", .constant(action)) { req -> Response in
                let (_, business, staff) = try act(req)
                let id = try req.uuid("id")
                try await ConsoleConversationService(db: req.db, ctx: req.ctx).setOpen(open, businessId: business.id!, staffId: staff, sessionId: id)
                return DashboardResponses.redirect("\(path)/\(id.uuidString.lowercased())?cm=\(open ? "reopened" : "closed")")
            }
        }
    }

    private static func act(_ req: Request) throws -> (DashboardPrincipal, BusinessRecord, UUID) {
        let (p, _) = try req.businessDashboard
        guard p.can(.replyConversations), let staff = p.user.id, let business = p.business else { throw APIError.forbidden }
        return (p, business, staff)
    }

    static func flash(_ req: Request) -> String? { req.query[String.self, at: "cm"].flatMap { messages[$0] } }

    /// The short form of a `subject_ref` shown in lists ("sub_" and eight characters); the full value is on the thread page.
    static func shortRef(_ ref: String) -> String { String(ref.prefix(12)) + (ref.count > 12 ? "…" : "") }

    static func channelLabel(_ raw: String) -> String {
        switch Channel(rawValue: raw) {
        case .sms?: "SMS"
        case .inApp?: "Viadere app"
        default: "Viadere app"
        }
    }

    // MARK: Pages

    private static func list(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        guard p.can(.viewConversations), let staff = p.user.id else { throw APIError.forbidden }
        let state = req.query[String.self, at: "state"].flatMap { ["open", "closed"].contains($0) ? $0 : nil }
        let view = req.query[String.self, at: "view"].flatMap { ["mine", "unassigned", "unread"].contains($0) ? $0 : nil }
        let service = ConsoleConversationService(db: req.db, ctx: req.ctx)
        let all = try await service.threads(businessId: businessId, staffId: staff, state: state)
        let threads = all.filter { t in
            switch view {
            case "mine": t.assigneeId == staff
            case "unassigned": t.assigneeId == nil
            case "unread": t.unread
            default: true
            }
        }
        let unread = all.filter { $0.unread && $0.session.state != "closed" }.count
        let names = try await service.staffNames(businessId: businessId, ids: Set(threads.compactMap(\.assigneeId)))
        let rows = threads.map { t -> [ConsoleUI.Cell] in
            let id = t.session.id!.uuidString.lowercased()
            let label = "Customer \(shortRef(t.subjectRef))"
            let link = "<a href=\"\(path)/\(id)\">\(t.unread ? "<strong>" : "")\(DashboardUI.esc(label))\(t.unread ? "</strong> <span class=\"vh\">(unread)</span>" : "")</a>"
            let assignee = t.assigneeId == nil ? "—" : (t.assigneeId == staff ? "You" : names[t.assigneeId!] ?? "Team member")
            return [ConsoleUI.Cell(html: (t.unread ? ConsoleUI.pill("New", .accent) + " " : "") + link + (t.sandbox ? " " + ConsoleUI.pill("Test", .neutral) : ""), sort: .text(label)),
                    .text(channelLabel(t.session.channel)),
                    ConsoleUI.Cell(html: stateBadge(t.session.state), sort: .text(t.session.state)),
                    .text(assignee), .number(t.messageCount), .date(t.session.lastMessageAt ?? t.session.createdAt)]
        }
        func link(state s: String?, view v: String?) -> String {
            var items: [String] = []
            if let s { items.append("state=\(s)") }
            if let v { items.append("view=\(v)") }
            return path + (items.isEmpty ? "" : "?" + items.joined(separator: "&"))
        }
        let stateFilter = ConsoleUI.segmented([(nil, "All"), ("open", "Open"), ("closed", "Closed")].map { key, title in
            (title, link(state: key, view: view), state == key)
        }, label: "Filter by status")
        let viewFilter = ConsoleUI.segmented([(nil, "Everyone's"), ("mine", "Assigned to me"), ("unassigned", "Unassigned"), ("unread", "Unread")].map { key, title in
            (title, link(state: state, view: key), view == key)
        }, label: "Filter by assignment")
        let body = ConsoleUI.card("Conversations", actions: stateFilter, """
        <div class="row">\(viewFilter)</div>\
        <p role="status" aria-live="polite" class="mu sm">\(unread) open conversation\(unread == 1 ? "" : "s") with unread messages. Reload the page to see new messages.</p>\
        \(ConsoleUI.table([ConsoleUI.Column("Customer", key: "customer"), ConsoleUI.Column("Channel"), ConsoleUI.Column("Status", key: "status"), ConsoleUI.Column("Assigned"),
                           ConsoleUI.Column("Messages", key: "count", numeric: true), ConsoleUI.Column("Last activity", key: "activity")],
                          rows, caption: "Customer conversations", state: ConsoleUI.TableState(req, id: "c", defaultSort: "activity", defaultAscending: false),
                          empty: "No conversations yet", emptyMessage: "When a connected customer writes to you in the Viadere app or over SMS, the conversation appears here."))
        """) + ConsoleUI.callout(.neutral, "<p class=\"sm\">Customers are shown by the reference Viadere gives your organization. It is the same reference your API and webhooks use, and it means nothing to any other business.</p>")
        return DashboardUI.businessPage(p, title: "Conversations", active: path, subtitle: "Messages from connected customers. Reply here or through the API.",
                                        actions: ConsoleUI.pill("\(unread) unread", unread > 0 ? .accent : .neutral), flash: flash(req), body: body)
    }

    private static func thread(_ req: Request) async throws -> Response {
        let (p, businessId) = try req.businessDashboard
        guard p.can(.viewConversations), let staff = p.user.id else { throw APIError.forbidden }
        let service = ConsoleConversationService(db: req.db, ctx: req.ctx)
        let detail = try await service.open(businessId: businessId, staffId: staff, sessionId: try req.uuid("id"))
        let id = detail.session.id!.uuidString.lowercased()
        let open = detail.session.state != "closed"
        let entries = detail.messages.map { m -> String in
            let who: String
            switch m.message.direction {
            case .consumerToBusiness: who = "Customer"
            case .businessToConsumer:
                who = m.message.attribution.displayName + (m.message.attribution.agentName.map { " · " + $0 } ?? "")
                    + (m.sentBy.map { " (sent by \($0))" } ?? "")
            case .system: who = "Viadere"
            }
            let text = m.erased ? "<em class=\"mu\">This message was removed.</em>" : DashboardUI.esc(m.message.body)
            let cls = m.message.direction == .businessToConsumer ? "out" : (m.message.direction == .system ? "sys" : "in")
            let images = imagesHTML(m.message.attachments ?? [], session: detail.session.id!, from: m.message.direction == .consumerToBusiness ? "customer" : "you")
            let bodyHTML = m.message.body.isEmpty && !images.isEmpty ? "" : "<p class=\"b\">\(text)</p>"
            return "<li class=\"\(cls)\"><p class=\"m\">\(DashboardUI.esc(who)) · <time>\(DashboardFormat.date(m.message.createdAt))</time></p>\(bodyHTML)\(images)</li>"
        }
        let thread = entries.isEmpty ? ConsoleUI.empty("No messages yet") : "<ol class=\"thread\" aria-label=\"Messages, oldest first\">\(entries.joined())</ol>"
        var assigneeName: String?
        if let assignee = detail.assigneeId { assigneeName = try await service.staffNames(businessId: businessId, ids: [assignee])[assignee] ?? "Team member" }
        let summary = ConsoleUI.card("Customer \(shortRef(detail.subjectRef))", actions: stateBadge(detail.session.state), ConsoleUI.keyValues([
            ("Channel", DashboardUI.esc(channelLabel(detail.session.channel)) + (detail.sandbox ? " " + ConsoleUI.pill("Test customer", .neutral) : "")),
            ("Assigned", DashboardUI.esc(detail.assigneeId == staff ? "You" : assigneeName ?? "Nobody")),
            ("Started", DashboardFormat.date(detail.session.createdAt)),
        ]) + "<p class=\"sm mu\">Customer reference <code class=\"mono\">\(DashboardUI.esc(detail.subjectRef))</code></p>"
            + ConsoleUI.callout(.neutral, "<p class=\"sm\">Viadere never shows you the customer's phone number or account. Don't ask for passwords, card numbers or health details in a reply.</p>")
            + "<h3>Messages</h3>" + thread)
        var actions = ""
        if p.can(.replyConversations) {
            let csrf = DashboardUI.csrf(p)
            if open && detail.canReply {
                let pending = try await service.pendingUploads(businessId: businessId, sessionId: detail.session.id!)
                let pendingHTML = pending.isEmpty ? "" : "<fieldset class=\"attq\"><legend>Images to send</legend>" + pending.enumerated().map { index, a in
                    ConsoleUI.checkbox("image_\(a.id)", label: "Image \(index + 1)", checked: true,
                                       labelHTML: thumbnail(a, session: detail.session.id!, alt: "Image \(index + 1) to send", size: 72) + " Image \(index + 1) · \(a.width) × \(a.height)")
                }.joined() + "<p class=\"help\">Untick an image to leave it out. Images not sent within an hour are removed.</p></fieldset>"
                actions += ConsoleUI.card("Reply", description: "Sent as \(detail.businessName). The customer sees your verified name.", ConsoleUI.form("\(path)/\(id)/reply", csrf: csrf,
                    ConsoleUI.hidden("idempotency_key", SecureToken.generate(byteCount: 18))
                    + pendingHTML
                    + ConsoleUI.textarea("body", label: "Message", id: "rb", help: pending.isEmpty ? "Up to \(ConversationService.maxBody) characters." : "Up to \(ConversationService.maxBody) characters. You can send images without a message.",
                                         required: pending.isEmpty, attrs: ["maxlength": String(ConversationService.maxBody), "rows": "4"])
                    + ConsoleUI.input("agent_name", label: "Your name", id: "an", help: "Shown to the customer next to your organization's name.", optional: true, attrs: ["maxlength": "40"])
                    + ConsoleUI.formActions(ConsoleUI.button("Send reply"))))
                if pending.count < MessageAttachmentPolicy.maxPerMessage {
                    actions += ConsoleUI.card("Add an image", description: "Viadere removes location, camera and other hidden data from the image and sends it only to this customer in the Viadere app. Customers who reach you by text are told an image is waiting in the app.",
                        ConsoleUI.form("\(path)/\(id)/attachments", csrf: csrf, multipart: true,
                            ConsoleUI.input("file", label: "Image file", id: "img", type: "file", help: "PNG or JPEG, up to 2 MB.", required: true, attrs: ["accept": "image/png,image/jpeg"])
                            + ConsoleUI.formActions(ConsoleUI.button("Add image", .secondary))))
                }
            } else if open {
                actions += ConsoleUI.callout(.warning, "<p>This customer is no longer connected to you, so you can't reply.</p>")
            }
            let members = try await service.assignableMembers(businessId: businessId)
            let options = [ConsoleUI.Option("none", "Nobody")] + members.map { ConsoleUI.Option($0.id.uuidString.lowercased(), $0.name, selected: detail.assigneeId == $0.id) }
            actions += ConsoleUI.card("Assignment", ConsoleUI.form("\(path)/\(id)/assign", csrf: csrf,
                ConsoleUI.select("assignee", label: "Assign to", id: "as", options: options) + ConsoleUI.formActions(ConsoleUI.button("Assign", .secondary))))
            actions += ConsoleUI.card(open ? "Close the conversation" : "Reopen the conversation",
                description: open ? "The customer can still write; a new message starts a new conversation." : "Reopen to reply in this thread again.",
                ConsoleUI.form("\(path)/\(id)/\(open ? "close" : "reopen")", csrf: csrf, ConsoleUI.formActions(ConsoleUI.button(open ? "Close" : "Reopen", .secondary))))
        }
        let body = actions.isEmpty ? summary : "<div class=\"split\"><div>\(summary)</div><div>\(actions)</div></div>"
        return DashboardUI.businessPage(p, title: "Conversation", active: path, actions: ConsoleUI.linkButton("Back to conversations", href: path, small: true),
                                        flash: flash(req), body: body)
    }

    /// A thumbnail through the console download route. The alt text is fixed copy (customers' images have no business-visible name).
    static func thumbnail(_ a: MessageAttachment, session: UUID, alt: String, size: Int) -> String {
        let scale = Double(size) / Double(max(a.width, a.height, 1))
        let w = max(1, Int((Double(a.width) * min(1, scale)).rounded())), h = max(1, Int((Double(a.height) * min(1, scale)).rounded()))
        return "<img src=\"\(DashboardUI.esc(attachmentPath(session: session, attachment: a.id)))\" alt=\"\(DashboardUI.esc(alt))\" width=\"\(w)\" height=\"\(h)\" loading=\"lazy\" decoding=\"async\">"
    }

    static func imagesHTML(_ attachments: [MessageAttachment], session: UUID, from: String) -> String {
        guard !attachments.isEmpty else { return "" }
        let label = from == "customer" ? "Image from the customer" : "Image you sent"
        return "<ul class=\"att\" aria-label=\"Images\">" + attachments.enumerated().map { index, a in
            let alt = attachments.count == 1 ? label : "\(label), \(index + 1) of \(attachments.count)"
            return "<li><a href=\"\(DashboardUI.esc(attachmentPath(session: session, attachment: a.id)))\" target=\"_blank\" rel=\"noopener noreferrer\">\(thumbnail(a, session: session, alt: alt, size: 240))<span class=\"vh\"> (opens the full image)</span></a></li>"
        }.joined() + "</ul>"
    }

    static func stateBadge(_ state: String) -> String {
        state == "closed" ? DashboardFormat.badge("Closed", "mu") : DashboardFormat.badge("Open", "ok")
    }
}

/// Tenant-scoped reads and actions behind the console conversation pages.
struct ConsoleConversationService {
    let db: any Database
    let ctx: ServerContext

    struct Thread {
        var session: ConversationSessionRecord
        var subjectRef: String
        var assigneeId: UUID?
        var unread: Bool
        var messageCount: Int
        var sandbox: Bool
    }

    struct ThreadMessage {
        var message: ConversationMessage
        var erased: Bool
        /// The console user who sent it (from the audit chain), when it was sent from the console.
        var sentBy: String?
    }

    struct Detail {
        var session: ConversationSessionRecord
        var subjectRef: String
        var assigneeId: UUID?
        var messages: [ThreadMessage]
        var sandbox: Bool
        var canReply: Bool
        var businessName: String
    }

    func threads(businessId: UUID, staffId: UUID, state: String?) async throws -> [Thread] {
        var query = ConversationSessionRecord.query(on: db).filter(\.$businessId == businessId)
        if let state { query = state == "closed" ? query.filter(\.$state == "closed") : query.filter(\.$state != "closed") }
        let sessions = try await query.sort(\.$lastMessageAt, .descending).sort(\.$createdAt, .descending).limit(200).all()
        let ids = sessions.compactMap(\.id)
        guard !ids.isEmpty else { return [] }
        let states = Dictionary(try await ConversationConsoleStateRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$sessionId ~~ ids).all()
            .map { ($0.sessionId, $0.assigneeId) }, uniquingKeysWith: { a, _ in a })
        let reads = Dictionary(try await ConversationConsoleReadRecord.query(on: db).filter(\.$staffId == staffId).filter(\.$businessId == businessId)
            .filter(\.$sessionId ~~ ids).all().map { ($0.sessionId, $0.readAt) }, uniquingKeysWith: { a, _ in a })
        let consumers = Dictionary(try await ConsumerRecord.query(on: db).filter(\.$id ~~ Array(Set(sessions.map(\.consumerId)))).all().map { ($0.id!, $0.isSandbox) },
                                   uniquingKeysWith: { a, _ in a })
        var out: [Thread] = []
        for session in sessions {
            let id = session.id!
            let lastInbound = try await ConversationMessageRecord.query(on: db).filter(\.$sessionId == id).filter(\.$businessId == businessId)
                .filter(\.$direction == MessageDirection.consumerToBusiness.rawValue).sort(\.$createdAt, .descending).first()?.createdAt
            let count = try await ConversationMessageRecord.query(on: db).filter(\.$sessionId == id).filter(\.$businessId == businessId).count()
            let unread = lastInbound.map { at in reads[id].map { at > $0 } ?? true } ?? false
            out.append(Thread(session: session, subjectRef: ctx.subjects.subjectRef(businessId: BusinessID(businessId), consumerId: ConsumerID(session.consumerId)).rawValue,
                              assigneeId: states[id] ?? nil, unread: unread, messageCount: count, sandbox: consumers[session.consumerId] ?? false))
        }
        return out
    }

    /// One thread of **this** business (another tenant's id is not found). Records the staff member's read mark and audits the read.
    func open(businessId: UUID, staffId: UUID, sessionId: UUID) async throws -> Detail {
        let session = try await owned(businessId: businessId, sessionId: sessionId)
        let rows = try await ConversationMessageRecord.query(on: db).filter(\.$sessionId == sessionId).filter(\.$businessId == businessId)
            .sort(\.$createdAt, .descending).sort(\.$id, .ascending).limit(200).all().reversed()
        let conversations = ConversationService(db: db, ctx: ctx)
        let outbound = rows.filter { $0.direction == MessageDirection.businessToConsumer.rawValue }.compactMap { $0.id?.uuidString.lowercased() }
        var senders: [String: String] = [:]
        if !outbound.isEmpty {
            let events = try await AuditEventRecord.query(on: db).filter(\.$action == "message.business_sent").filter(\.$businessId == businessId)
                .filter(\.$subjectId ~~ outbound).filter(\.$actorKind == AuditActor.Kind.business.rawValue).all()
            let userIds = Set(events.compactMap { $0.actorId.flatMap(UUID.init(uuidString:)) })
            let names = try await staffNames(businessId: businessId, ids: userIds)
            for event in events {
                if let subject = event.subjectId, let user = event.actorId.flatMap(UUID.init(uuidString:)) { senders[subject] = names[user] ?? "a former team member" }
            }
        }
        let refs = try await MessageAttachmentService.references(messageIds: rows.compactMap(\.id), on: db)
        let messages = try rows.map { row in
            ThreadMessage(message: try conversations.dto(row, attachments: refs[row.id!]), erased: row.contentErased, sentBy: senders[row.id!.uuidString.lowercased()])
        }
        let now = ctx.now
        if let read = try await ConversationConsoleReadRecord.query(on: db).filter(\.$sessionId == sessionId).filter(\.$staffId == staffId).first() {
            read.readAt = now
            try await read.update(on: db)
        } else {
            let read = ConversationConsoleReadRecord()
            read.id = UUID()
            read.sessionId = sessionId
            read.businessId = businessId
            read.staffId = staffId
            read.readAt = now
            do { try await read.create(on: db) } catch let error where error.isConstraintViolation {}
        }
        // The read is audited: who opened which thread. Never the body, never the customer's account.
        _ = try await AuditService(db: db, ctx: ctx).record("conversation.console_read", actor: LoopPublicationService.businessActor(staffId), businessId: BusinessID(businessId),
                                                            subjectType: "conversation_session", subjectId: sessionId.uuidString.lowercased(),
                                                            metadata: ["messages": String(messages.count)])
        let relationship = try await RelationshipRecord.query(on: db).filter(\.$id == session.relationshipId).filter(\.$businessId == businessId).first()
        let sandbox = try await ConsumerRecord.find(session.consumerId, on: db)?.isSandbox ?? false
        let assignee = try await ConversationConsoleStateRecord.query(on: db).filter(\.$sessionId == sessionId).filter(\.$businessId == businessId).first()?.assigneeId
        let name = try await BusinessRecord.find(businessId, on: db)?.displayName ?? ""
        return Detail(session: session, subjectRef: ctx.subjects.subjectRef(businessId: BusinessID(businessId), consumerId: ConsumerID(session.consumerId)).rawValue,
                      assigneeId: assignee, messages: messages, sandbox: sandbox, canReply: relationship?.isActive == true, businessName: name)
    }

    func owned(businessId: UUID, sessionId: UUID) async throws -> ConversationSessionRecord {
        guard let session = try await ConversationSessionRecord.query(on: db).filter(\.$id == sessionId).filter(\.$businessId == businessId).first() else {
            throw APIError.notFound
        }
        return session
    }

    /// A console form's idempotency key: what the page generated, nothing else.
    static func validFormKey(_ raw: String) -> Bool {
        (16...64).contains(raw.count) && raw.unicodeScalars.allSatisfy { $0.isASCII && (CharacterSet.alphanumerics.contains($0) || $0 == "-" || $0 == "_") }
    }

    /// Replies through the business API's `sendMessage` path. Returns false when the same form was submitted again (idempotent replay).
    func reply(business: BusinessRecord, staffId: UUID, sessionId: UUID, body: String, agentName: String?, formKey: String,
               attachmentIds: [AttachmentID] = []) async throws -> Bool {
        guard let businessId = business.id else { throw APIError.forbidden }
        let session = try await owned(businessId: businessId, sessionId: sessionId)
        guard Self.validFormKey(formKey) else { throw APIError.validation("Reload the page and try again.", details: ["idempotency_key": "invalid"]) }
        guard session.state != "closed" else { throw APIError.conflict("This conversation is closed. Reopen it to reply.") }
        let (principal, relationship) = try await consolePrincipal(business: business, staffId: staffId, session: session)
        let agent = agentName?.trimmingCharacters(in: .whitespacesAndNewlines)
        let request = BusinessSendMessageRequest(relationshipId: RelationshipID(relationship.id!), sessionId: SessionID(sessionId), body: body,
                                                 agentName: (agent?.isEmpty ?? true) ? nil : agent, idempotencyKey: "console:" + formKey,
                                                 attachmentIds: attachmentIds.isEmpty ? nil : attachmentIds)
        return try await ConversationService(db: db, ctx: ctx).businessSend(principal: principal, request: request, headerKey: nil).created
    }

    /// The principal a console action uses on the business-API path. Test and live stay apart exactly as for API keys: a sandbox customer is
    /// answered in test mode, a real customer only once the organization's production access is approved.
    func consolePrincipal(business: BusinessRecord, staffId: UUID, session: ConversationSessionRecord) async throws -> (BusinessPrincipal, RelationshipRecord) {
        guard let businessId = business.id else { throw APIError.forbidden }
        guard let relationship = try await RelationshipRecord.query(on: db).filter(\.$id == session.relationshipId).filter(\.$businessId == businessId).first(),
              let consumer = try await ConsumerRecord.find(relationship.consumerId, on: db) else { throw APIError.notFound }
        let livemode = !consumer.isSandbox
        guard try await OnboardingGate.allows(business: business, livemode: livemode, on: db) else {
            throw APIError(.forbidden, .forbidden, livemode ? "Replying to customers is available after your go-live review." : "Verify a domain you control to use the sandbox.")
        }
        let principal = BusinessPrincipal(businessId: BusinessID(businessId), keyId: Self.consoleKeyId, livemode: livemode, scopes: [BusinessAPIKeys.Scope.messagesWrite],
                                          businessName: business.displayName, capabilities: [.messageSend], consoleUserId: staffId)
        return (principal, relationship)
    }

    /// An image for the next reply (the console's `businessUpload`).
    func upload(business: BusinessRecord, staffId: UUID, sessionId: UUID, data: Data, contentType: String, runtime: AttachmentRuntime) async throws -> MessageAttachment {
        guard let businessId = business.id else { throw APIError.forbidden }
        let session = try await owned(businessId: businessId, sessionId: sessionId)
        guard session.state != "closed" else { throw APIError.conflict("This conversation is closed. Reopen it to reply.") }
        let (principal, _) = try await consolePrincipal(business: business, staffId: staffId, session: session)
        return try await MessageAttachmentService(db: db, ctx: ctx, runtime: runtime).businessUpload(principal: principal, sessionId: SessionID(sessionId), data: data, contentType: contentType)
    }

    /// Images added in the console to this thread and not sent yet (any team member's: the thread is the team's).
    func pendingUploads(businessId: UUID, sessionId: UUID) async throws -> [MessageAttachment] {
        try await MessageAttachmentRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$sessionId == sessionId).filter(\.$side == "business")
            .filter(\.$state == "pending").filter(\.$expiresAt > ctx.now).sort(\.$createdAt, .ascending).all()
            .filter { $0.uploaderRef.hasPrefix("console:") }.map(MessageAttachmentService.dto)
    }

    /// The key id a console principal carries. Not a key: no key row has it, and audit events name the console user instead.
    static let consoleKeyId = UUID(uuidString: "00000000-0000-0000-0000-000000000000")!

    func assign(businessId: UUID, staffId: UUID, sessionId: UUID, to assignee: UUID?) async throws {
        _ = try await owned(businessId: businessId, sessionId: sessionId)
        if let assignee {
            guard try await assignableMembers(businessId: businessId).contains(where: { $0.id == assignee }) else {
                throw APIError.validation("Choose a team member who can see conversations.")
            }
        }
        let now = ctx.now
        if let existing = try await ConversationConsoleStateRecord.query(on: db).filter(\.$sessionId == sessionId).filter(\.$businessId == businessId).first() {
            existing.assigneeId = assignee
            existing.updatedAt = now
            try await existing.update(on: db)
        } else {
            let row = ConversationConsoleStateRecord()
            row.id = UUID()
            row.sessionId = sessionId
            row.businessId = businessId
            row.assigneeId = assignee
            row.updatedAt = now
            do { try await row.create(on: db) } catch let error where error.isConstraintViolation {
                try await ConversationConsoleStateRecord.query(on: db).filter(\.$sessionId == sessionId).set(\.$assigneeId, to: assignee).set(\.$updatedAt, to: now).update()
            }
        }
        _ = try await AuditService(db: db, ctx: ctx).record("conversation.assigned", actor: LoopPublicationService.businessActor(staffId), businessId: BusinessID(businessId),
                                                            subjectType: "conversation_session", subjectId: sessionId.uuidString.lowercased(),
                                                            metadata: ["assignee": assignee?.uuidString.lowercased() ?? "none"])
    }

    func setOpen(_ open: Bool, businessId: UUID, staffId: UUID, sessionId: UUID) async throws {
        let session = try await owned(businessId: businessId, sessionId: sessionId)
        if open {
            guard session.state == "closed" else { return }
            guard let relationship = try await RelationshipRecord.query(on: db).filter(\.$id == session.relationshipId).filter(\.$businessId == businessId).first(),
                  relationship.isActive else { throw APIError.conflict("This customer is no longer connected to you.") }
            // One open thread per relationship and channel: a newer open one wins.
            if try await ConversationSessionRecord.query(on: db).filter(\.$relationshipId == session.relationshipId).filter(\.$channel == session.channel)
                .filter(\.$state == "open").filter(\.$id != sessionId).first() != nil {
                throw APIError.conflict("The customer already has a newer open conversation with you. Reply there.")
            }
            guard try await DB.swap(db, table: ConversationSessionRecord.schema, id: sessionId, column: "state", expected: "closed", newValue: "open") else { return }
            try await ConversationSessionRecord.query(on: db).filter(\.$id == sessionId).set(\.$closedAt, to: nil).update()
        } else {
            guard session.state != "closed" else { return }
            guard try await DB.swap(db, table: ConversationSessionRecord.schema, id: sessionId, column: "state", expected: session.state, newValue: "closed",
                                    extra: [("closed_at", ctx.now)]) else { return }
        }
        _ = try await AuditService(db: db, ctx: ctx).record(open ? "conversation.reopened" : "conversation.closed", actor: LoopPublicationService.businessActor(staffId),
                                                            businessId: BusinessID(businessId), subjectType: "conversation_session", subjectId: sessionId.uuidString.lowercased())
    }

    struct Member { var id: UUID; var name: String }

    /// Current members of this organization whose role can read conversations.
    func assignableMembers(businessId: UUID) async throws -> [Member] {
        let members = try await OrgMembershipRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$removedAt == nil).all()
            .filter { OrgRole(rawValue: $0.role)?.permits(.viewConversations) == true }
        guard !members.isEmpty else { return [] }
        return try await DashboardUserRecord.query(on: db).filter(\.$id ~~ members.map(\.userId)).all().map { Member(id: $0.id!, name: $0.displayName) }
            .sorted { $0.name < $1.name }
    }

    /// Display names of this organization's current or former members (never another organization's people).
    func staffNames(businessId: UUID, ids: Set<UUID>) async throws -> [UUID: String] {
        guard !ids.isEmpty else { return [:] }
        let members = Set(try await OrgMembershipRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$userId ~~ Array(ids)).all().map(\.userId))
        guard !members.isEmpty else { return [:] }
        return Dictionary(try await DashboardUserRecord.query(on: db).filter(\.$id ~~ Array(members)).all().map { ($0.id!, $0.displayName) }, uniquingKeysWith: { a, _ in a })
    }
}
