import Fluent
import Foundation
import ViadereCore

// MARK: - Queue message types (plan 4.5 step 4, SECURITY.md §2.91, §2.94)

/// Loop messages ride the shared outbox and consumer (ids-only envelope with the tenant from the row; processed_messages idempotency;
/// unknown types dead-lettered).
enum LoopQueue {
    static let all: [QueueMessageType] = [deliver, timeout, notify]

    /// Delivers an action event to the hosted inbox: one inbox item per event however often the message arrives, then a content-free email
    /// alert to the business's inbox staff. A dead-lettered delivery marks the event `unknown` (never shown as delivered).
    static let deliver = QueueMessageType(name: "loop.action.deliver", version: 1, queue: .loopDelivery, timeToLive: 3 * 86_400, requiresTenant: true, claim: { envelope, tx, ctx in
        guard let event = try await LoopActionEventRecord.find(envelope.ref, on: tx) else { return .done }
        guard event.businessId == envelope.tenant else { return .deadLetter(reason: "tenant_mismatch") }
        guard event.delivers else { return .done }
        if try await InboxItemRecord.query(on: tx).filter(\.$eventId == event.id!).first() != nil { return .done }
        guard let instance = try await LoopInstanceRecord.find(event.instanceId, on: tx), let revision = try await LoopRevisionRecord.find(instance.revisionId, on: tx) else { return .done }
        let queue = LoopDefinition.parse(Data(revision.definitionJSON.utf8)).definition?.step(event.stepId)?.actions
            .first { $0.id == event.actionId }?.routing?.queue ?? LoopPublicationService.defaultQueue
        let item = InboxItemRecord()
        item.id = UUID()
        item.businessId = event.businessId
        item.instanceId = event.instanceId
        item.eventId = event.id!
        item.queueKey = queue
        item.state = "new"
        item.createdAt = ctx.now
        item.updatedAt = ctx.now
        try await item.create(on: tx)
        let businessId = event.businessId
        return .afterCommit { db, ctx in
            await Notifier(db: db, ctx: ctx).notifyBusiness(businessId, roles: Set(OrgRole.allCases.filter { $0.permits(.manageInbox) }), includeSecurityContacts: false,
                subject: "New request in your Viadere inbox", text: "A customer sent a request through one of your Loops. Open the Inbox in the Viadere console to see it.",
                kind: "loop-inbox")
            return nil
        }
    }, onDeadLetter: { envelope, db, ctx in
        guard let event = try await LoopActionEventRecord.find(envelope.ref, on: db), event.businessId == envelope.tenant else { return }
        try await LoopRuntimeService(db: db, ctx: ctx).recordOutcome(eventId: event.id!, businessId: event.businessId, outcome: .unknown, source: .system,
                                                                     actor: nil, reason: "delivery_dead_lettered")
    })

    /// Response deadlines (ref = event) and instance expiries (ref = instance). Early or repeated messages change nothing.
    static let timeout = QueueMessageType(name: "loop.instance.timeout", version: 1, queue: .loopTimeout, timeToLive: 31 * 86_400, requiresTenant: true, claim: { envelope, tx, ctx in
        if let event = try await LoopActionEventRecord.find(envelope.ref, on: tx) {
            guard event.businessId == envelope.tenant else { return .deadLetter(reason: "tenant_mismatch") }
            guard event.delivers, let due = event.responseDueAt else { return .done }
            if due > ctx.now { return .retry(at: due) }
            let id = event.id!
            let business = event.businessId
            return .afterCommit { db, ctx in
                try await LoopRuntimeService(db: db, ctx: ctx).recordOutcome(eventId: id, businessId: business, outcome: .timedOut, source: .system, actor: nil, reason: "deadline")
                return nil
            }
        }
        guard let instance = try await LoopInstanceRecord.find(envelope.ref, on: tx) else { return .done }
        guard instance.businessId == envelope.tenant else { return .deadLetter(reason: "tenant_mismatch") }
        guard instance.stateValue == .active else { return .done }
        if instance.expiresAt > ctx.now { return .retry(at: instance.expiresAt) }
        try await LoopRuntimeService(db: tx, ctx: ctx).expireIfDue(instance)
        return .done
    })

    /// The opaque customer push after an outcome change (queue `push`, like other interaction wake-ups).
    static let notify = QueueMessageType(name: "loop.outcome.notify", version: 1, queue: .push, timeToLive: 3600, requiresTenant: true, claim: { envelope, tx, _ in
        guard let event = try await LoopActionEventRecord.find(envelope.ref, on: tx) else { return .done }
        guard event.businessId == envelope.tenant else { return .deadLetter(reason: "tenant_mismatch") }
        let consumer = event.consumerId
        let instance = event.instanceId
        return .afterCommit { db, ctx in
            await LoopRuntimeService(db: db, ctx: ctx).pushOutcome(consumer: consumer, instanceId: instance)
            return nil
        }
    })
}

// MARK: - Hosted business inbox (WP-3.4)

/// Operating hours of an inbox queue (plan D6.2: shown to staff as open/closed; email alerts and outcomes are not delayed by them).
struct OperatingHours: Codable, Sendable, Equatable {
    /// ISO weekday 1 (Monday) to 7 → minutes from midnight `[open, close)`.
    var days: [String: [Int]]

    static func parse(_ text: String) -> OperatingHours? {
        // "1-5 09:00-17:00; 6 10:00-14:00"
        var days: [String: [Int]] = [:]
        for part in text.split(separator: ";").map({ $0.trimmingCharacters(in: .whitespaces) }) where !part.isEmpty {
            let pieces = part.split(separator: " ")
            guard pieces.count == 2 else { return nil }
            let range = pieces[0].split(separator: "-").compactMap { Int($0) }
            let times = pieces[1].split(separator: "-").map(String.init)
            guard (1...2).contains(range.count), range.allSatisfy({ (1...7).contains($0) }), times.count == 2,
                  let open = minutes(times[0]), let close = minutes(times[1]), open < close else { return nil }
            for day in range[0]...(range.last ?? range[0]) { days[String(day)] = [open, close] }
        }
        return days.isEmpty ? nil : OperatingHours(days: days)
    }

    static func minutes(_ text: String) -> Int? {
        let parts = text.split(separator: ":").compactMap { Int($0) }
        guard parts.count == 2, (0...24).contains(parts[0]), (0...59).contains(parts[1]), parts[0] * 60 + parts[1] <= 1440 else { return nil }
        return parts[0] * 60 + parts[1]
    }

    func isOpen(at date: Date, timezone: TimeZone) -> Bool {
        var calendar = Calendar(identifier: .iso8601)
        calendar.timeZone = timezone
        let weekday = (calendar.component(.weekday, from: date) + 5) % 7 + 1
        guard let window = days[String(weekday)], window.count == 2 else { return false }
        let minute = calendar.component(.hour, from: date) * 60 + calendar.component(.minute, from: date)
        return minute >= window[0] && minute < window[1]
    }

    var text: String {
        days.keys.sorted().map { day in
            let w = days[day]!
            return "\(day) \(String(format: "%02d:%02d", w[0] / 60, w[0] % 60))-\(String(format: "%02d:%02d", w[1] / 60, w[1] % 60))"
        }.joined(separator: "; ")
    }
}

/// Staff operations on the hosted inbox. Every call takes the business from the authenticated console membership (never from the form) and
/// re-checks the permission against the **current** role, so a downgrade takes effect on the next request.
struct LoopInbox {
    let db: any Database
    let ctx: ServerContext

    struct ItemDetail {
        var item: InboxItemRecord
        var instance: LoopInstanceRecord
        var event: LoopActionEventRecord
        var definition: LoopDefinition?
        /// Inputs of every event of the instance, in order (step id, field label, value text).
        var answers: [(step: String, label: String, value: String)]
        var outcome: LoopActionOutcome?
        var notes: [(kind: String, author: String, at: Date, text: String)]
        var readers: Int
    }

    func items(businessId: UUID, state: String?, queue: String?, limit: Int = 100) async throws -> [InboxItemRecord] {
        var query = InboxItemRecord.query(on: db).filter(\.$businessId == businessId)
        if let state, ["new", "open", "waiting", "closed"].contains(state) { query = query.filter(\.$state == state) }
        if let queue { query = query.filter(\.$queueKey == queue) }
        return try await query.sort(\.$createdAt, .descending).limit(limit).all()
    }

    func unreadCount(businessId: UUID, staffId: UUID) async throws -> Int {
        let open = try await InboxItemRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$state != "closed").all()
        guard !open.isEmpty else { return 0 }
        let read = Set(try await InboxReadRecord.query(on: db).filter(\.$staffId == staffId).filter(\.$itemId ~~ open.compactMap(\.id)).all().map(\.itemId))
        return open.filter { !read.contains($0.id!) }.count
    }

    func readIds(staffId: UUID, items: [UUID]) async throws -> Set<UUID> {
        guard !items.isEmpty else { return [] }
        return Set(try await InboxReadRecord.query(on: db).filter(\.$staffId == staffId).filter(\.$itemId ~~ items).all().map(\.itemId))
    }

    /// Loads one item of **this** business (another tenant's id is not found) and records the read receipt.
    func open(itemId: UUID, businessId: UUID, staffId: UUID) async throws -> ItemDetail {
        guard let item = try await InboxItemRecord.query(on: db).filter(\.$id == itemId).filter(\.$businessId == businessId).first(),
              let instance = try await LoopInstanceRecord.query(on: db).filter(\.$id == item.instanceId).filter(\.$businessId == businessId).first(),
              let event = try await LoopActionEventRecord.query(on: db).filter(\.$id == item.eventId).filter(\.$businessId == businessId).first() else {
            throw APIError.notFound
        }
        if try await InboxReadRecord.query(on: db).filter(\.$itemId == itemId).filter(\.$staffId == staffId).first() == nil {
            let read = InboxReadRecord()
            read.itemId = itemId
            read.staffId = staffId
            read.readAt = ctx.now
            do { try await read.create(on: db) } catch let error where error.isConstraintViolation {}
        }
        if item.state == "new" { _ = try await DB.swap(db, table: InboxItemRecord.schema, id: itemId, column: "state", expected: "new", newValue: "open", extra: [("updated_at", ctx.now)]) }
        let runtime = LoopRuntimeService(db: db, ctx: ctx)
        let revision = try await LoopRevisionRecord.find(instance.revisionId, on: db)
        let definition = revision.flatMap { LoopDefinition.parse(Data($0.definitionJSON.utf8)).definition }
        var answers: [(String, String, String)] = []
        for e in try await LoopActionEventRecord.query(on: db).filter(\.$instanceId == instance.id!).sort(\.$createdAt, .ascending).all() {
            let step = definition?.step(e.stepId)
            for (key, value) in runtime.inputs(of: e).sorted(by: { $0.key < $1.key }) {
                let field = step?.fields.first { $0.id == key }
                answers.append((step?.title ?? e.stepId, field?.label ?? key, Self.describe(value, field: field)))
            }
        }
        var notes: [(String, String, Date, String)] = []
        let rows = try await InboxNoteRecord.query(on: db).filter(\.$itemId == itemId).filter(\.$businessId == businessId).sort(\.$createdAt, .ascending).all()
        let authors = Dictionary(try await DashboardUserRecord.query(on: db).filter(\.$id ~~ rows.map(\.authorId)).all().map { ($0.id!, $0.displayName) }, uniquingKeysWith: { a, _ in a })
        for note in rows {
            let text = (try? ctx.cipher.openString(note.bodySealed, context: "inbox_notes.body", rowId: note.id!)) ?? ""
            notes.append((note.kind, authors[note.authorId] ?? "Team member", note.createdAt, text))
        }
        let readers = try await InboxReadRecord.query(on: db).filter(\.$itemId == itemId).count()
        _ = try await AuditService(db: db, ctx: ctx).record("inbox.item_viewed", actor: LoopPublicationService.businessActor(staffId), businessId: BusinessID(businessId),
                                                            subjectType: "inbox_item", subjectId: itemId.uuidString.lowercased())
        return ItemDetail(item: try await InboxItemRecord.find(itemId, on: db) ?? item, instance: instance, event: event, definition: definition, answers: answers,
                          outcome: try await runtime.currentOutcome(eventId: event.id!)?.outcomeValue, notes: notes, readers: readers)
    }

    static func describe(_ value: JSONValue, field: LoopField?) -> String {
        func label(_ id: String) -> String { field?.options?.first { $0.id == id }?.label ?? id }
        switch value {
        case .string(let s): return field?.options != nil ? label(s) : s
        case .bool(let b): return b ? "Yes" : "No"
        case .array(let items): return items.compactMap(\.stringValue).map(label).joined(separator: ", ")
        default: return ""
        }
    }

    /// Accept, reject or ask for more information. Outcomes go through `LoopOutcomeMachine` (a final outcome cannot be changed).
    func decide(itemId: UUID, businessId: UUID, staffId: UUID, decision: String, note: String?) async throws {
        guard let item = try await InboxItemRecord.query(on: db).filter(\.$id == itemId).filter(\.$businessId == businessId).first() else { throw APIError.notFound }
        let runtime = LoopRuntimeService(db: db, ctx: ctx)
        switch decision {
        case "accept", "reject":
            guard try await runtime.recordOutcome(eventId: item.eventId, businessId: businessId, outcome: decision == "accept" ? .accepted : .rejected,
                                                  source: .staff, actor: staffId, reason: nil) else {
                throw APIError.conflict("This request already has a final answer.")
            }
            try await InboxItemRecord.query(on: db).filter(\.$id == itemId).set(\.$state, to: "closed").set(\.$closedAt, to: ctx.now).set(\.$updatedAt, to: ctx.now).update()
            if let note, !note.trimmingCharacters(in: .whitespaces).isEmpty { try await addNote(itemId: itemId, businessId: businessId, staffId: staffId, kind: "note", text: note) }
        case "ask_info":
            let text = (note ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            guard !text.isEmpty else { throw APIError.validation("Say what information you need.") }
            try await addNote(itemId: itemId, businessId: businessId, staffId: staffId, kind: "info_request", text: text)
            try await InboxItemRecord.query(on: db).filter(\.$id == itemId).set(\.$state, to: "waiting").set(\.$updatedAt, to: ctx.now).update()
            // The customer gets the opaque push; the request itself stays pending (nothing promissory is shown).
            let event = try await LoopActionEventRecord.find(item.eventId, on: db)
            if let event { await runtime.pushOutcome(consumer: event.consumerId, instanceId: event.instanceId) }
        default:
            throw APIError.validation("Choose accept, reject or ask for information.")
        }
        _ = try await AuditService(db: db, ctx: ctx).record("inbox.decision", actor: LoopPublicationService.businessActor(staffId), businessId: BusinessID(businessId),
                                                            subjectType: "inbox_item", subjectId: itemId.uuidString.lowercased(), metadata: ["decision": decision])
    }

    func addNote(itemId: UUID, businessId: UUID, staffId: UUID, kind: String, text raw: String) async throws {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, text.count <= 1000 else { throw APIError.validation("Notes are 1 to 1000 characters.") }
        guard try await InboxItemRecord.query(on: db).filter(\.$id == itemId).filter(\.$businessId == businessId).first() != nil else { throw APIError.notFound }
        let note = InboxNoteRecord()
        note.id = UUID()
        note.itemId = itemId
        note.businessId = businessId
        note.authorId = staffId
        note.kind = kind
        note.bodySealed = try ctx.cipher.seal(text, context: "inbox_notes.body", rowId: note.id!)
        note.createdAt = ctx.now
        try await note.create(on: db)
        _ = try await AuditService(db: db, ctx: ctx).record("inbox.note_added", actor: LoopPublicationService.businessActor(staffId), businessId: BusinessID(businessId),
                                                            subjectType: "inbox_item", subjectId: itemId.uuidString.lowercased(), metadata: ["kind": kind])
    }

    /// Assigns to a current member of the same business who may view the inbox (or unassigns with `nil`).
    func assign(itemId: UUID, businessId: UUID, staffId: UUID, to assignee: UUID?) async throws {
        guard try await InboxItemRecord.query(on: db).filter(\.$id == itemId).filter(\.$businessId == businessId).first() != nil else { throw APIError.notFound }
        if let assignee {
            guard let member = try await OrgMembershipRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$userId == assignee).filter(\.$removedAt == nil).first(),
                  OrgRole(rawValue: member.role)?.permits(.viewInbox) == true else { throw APIError.validation("Choose a team member who can see the inbox.") }
        }
        try await InboxItemRecord.query(on: db).filter(\.$id == itemId).set(\.$assigneeId, to: assignee).set(\.$updatedAt, to: ctx.now).update()
        _ = try await AuditService(db: db, ctx: ctx).record("inbox.assigned", actor: LoopPublicationService.businessActor(staffId), businessId: BusinessID(businessId),
                                                            subjectType: "inbox_item", subjectId: itemId.uuidString.lowercased(),
                                                            metadata: ["assignee": assignee?.uuidString.lowercased() ?? "none"])
    }

    func setHours(businessId: UUID, staffId: UUID, queue key: String, hours: String, timezone: String) async throws {
        guard LoopIDs.isValid(key) else { throw APIError.validation("Check the queue name.") }
        guard let zone = TimeZone(identifier: timezone) else { throw APIError.validation("Choose a valid time zone (for example America/Phoenix).") }
        let trimmed = hours.trimmingCharacters(in: .whitespaces)
        var json: String?
        if !trimmed.isEmpty {
            guard let parsed = OperatingHours.parse(trimmed) else { throw APIError.validation("Write hours like 1-5 09:00-17:00; 6 10:00-14:00.") }
            json = String(decoding: try JSONEncoder().encode(parsed), as: UTF8.self)
        }
        if let existing = try await InboxQueueRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$key == key).first() {
            try await InboxQueueRecord.query(on: db).filter(\.$id == existing.id!).set(\.$hoursJSON, to: json).set(\.$timezone, to: zone.identifier).update()
        } else {
            let row = InboxQueueRecord()
            row.businessId = businessId
            row.key = key
            row.name = key
            row.hoursJSON = json
            row.timezone = zone.identifier
            row.createdAt = ctx.now
            try await row.create(on: db)
        }
        _ = try await AuditService(db: db, ctx: ctx).record("inbox.hours_changed", actor: LoopPublicationService.businessActor(staffId), businessId: BusinessID(businessId),
                                                            subjectType: "inbox_queue", subjectId: key)
    }

    /// Retention: closed items older than the window are deleted with their notes and read receipts.
    func purgeClosed(before cutoff: Date) async throws -> Int {
        let old = try await InboxItemRecord.query(on: db).filter(\.$state == "closed").filter(\.$closedAt < cutoff).limit(500).all()
        let ids = old.compactMap(\.id)
        guard !ids.isEmpty else { return 0 }
        try await InboxNoteRecord.query(on: db).filter(\.$itemId ~~ ids).delete()
        try await InboxReadRecord.query(on: db).filter(\.$itemId ~~ ids).delete()
        try await InboxItemRecord.query(on: db).filter(\.$id ~~ ids).delete()
        return ids.count
    }
}

/// The periodic safety net behind the `loop-timeout` queue: expires instances and times out pending deliveries whose messages were lost or
/// dead-lettered (the same CAS-guarded code as the handlers, so a message and the sweep never double-apply).
struct LoopMaintenance {
    let db: any Database
    let ctx: ServerContext

    func sweep(limit: Int = 200) async throws {
        let now = ctx.now
        let runtime = LoopRuntimeService(db: db, ctx: ctx)
        for instance in try await LoopInstanceRecord.query(on: db).filter(\.$state == LoopInstanceState.active.rawValue).filter(\.$expiresAt <= now).limit(limit).all() {
            try await runtime.expireIfDue(instance)
        }
        for event in try await LoopActionEventRecord.query(on: db).filter(\.$delivers == true).filter(\.$responseDueAt <= now).sort(\.$createdAt, .descending).limit(limit).all() {
            guard try await runtime.currentOutcome(eventId: event.id!)?.outcomeValue == .pending else { continue }
            try await runtime.recordOutcome(eventId: event.id!, businessId: event.businessId, outcome: .timedOut, source: .system, actor: nil, reason: "deadline")
        }
    }
}

/// Tenant deletion (`TenantDataRequests.complete`): every Loop and inbox row of the business, children first. Events are append-only
/// (no UPDATE) but may be deleted with their tenant.
enum LoopTenantData {
    static func delete(businessId: UUID, on db: any Database) async throws {
        let items = try await InboxItemRecord.query(on: db).filter(\.$businessId == businessId).all().compactMap(\.id)
        if !items.isEmpty {
            try await InboxNoteRecord.query(on: db).filter(\.$itemId ~~ items).delete()
            try await InboxReadRecord.query(on: db).filter(\.$itemId ~~ items).delete()
        }
        try await InboxItemRecord.query(on: db).filter(\.$businessId == businessId).delete()
        try await InboxQueueRecord.query(on: db).filter(\.$businessId == businessId).delete()
        try await LoopActionOutcomeRecord.query(on: db).filter(\.$businessId == businessId).delete()
        try await LoopActionEventRecord.query(on: db).filter(\.$businessId == businessId).delete()
        try await LoopReportRecord.query(on: db).filter(\.$businessId == businessId).delete()
        try await LoopInstanceRecord.query(on: db).filter(\.$businessId == businessId).delete()
        let publications = try await LoopPublicationRecord.query(on: db).filter(\.$businessId == businessId).all().compactMap(\.id)
        if !publications.isEmpty { try await LoopRolloutAllowRecord.query(on: db).filter(\.$publicationId ~~ publications).delete() }
        try await LoopPublicationRecord.query(on: db).filter(\.$businessId == businessId).delete()
        try await LoopReviewRecord.query(on: db).filter(\.$businessId == businessId).delete()
        try await LoopRevisionRecord.query(on: db).filter(\.$businessId == businessId).delete()
        try await LoopDefinitionRecord.query(on: db).filter(\.$businessId == businessId).delete()
        try await LoopSwitchRecord.query(on: db).filter(\.$businessId == businessId).delete()
        try await LoopStudioDraftRecord.query(on: db).filter(\.$businessId == businessId).delete()
    }
}
