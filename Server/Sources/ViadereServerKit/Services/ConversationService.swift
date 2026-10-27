import Fluent
import Foundation
import ViadereCore
import struct ViadereCore.Page
import typealias ViadereCore.SessionID
import enum ViadereCore.Channel

/// Tenant-scoped conversation sessions and messages. Every query filters on the owning consumer (app side)
/// or the authenticated business (API side); a session id alone never grants access.
struct ConversationService {
    let db: any Database
    let ctx: ServerContext

    static let maxBody = 1600

    // MARK: Mapping

    func dto(_ record: ConversationMessageRecord) throws -> ConversationMessage {
        let body = (try? ctx.cipher.openString(record.bodyCiphertext, context: "conversation_messages.body", rowId: record.id!)) ?? ""
        return ConversationMessage(
            id: MessageID(record.id!), sessionId: SessionID(record.sessionId), businessId: BusinessID(record.businessId),
            direction: MessageDirection(rawValue: record.direction) ?? .system,
            attribution: MessageAttribution(senderType: MessageAttribution.SenderType(rawValue: record.senderType) ?? .viadere,
                                            displayName: record.displayName, agentName: record.agentName),
            body: body, channel: Channel(rawValue: record.channel) ?? .inApp, createdAt: record.createdAt,
            deliveredAt: record.deliveredAt, readAt: record.readAt, deliveryStatus: DeliveryStatus(rawValue: record.deliveryStatus) ?? .queued,
            interactionId: record.interactionId.map { InteractionID($0) })
    }

    static func cleanBody(_ raw: String) throws -> String {
        let scalars = raw.unicodeScalars.filter { $0 == "\n" || $0 == "\t" || ($0.value >= 0x20 && $0.value != 0x7F) }
        let text = String(String.UnicodeScalarView(scalars)).trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty, text.count <= maxBody else {
            throw APIError.validation("A message must be 1 to \(maxBody) characters.", details: ["body": "invalid"])
        }
        return text
    }

    // MARK: Consumer API

    func summaries(consumer: ConsumerID) async throws -> [ConversationSummary] {
        let sessions = try await ConversationSessionRecord.query(on: db).filter(\.$consumerId == consumer.uuid)
            .sort(\.$lastMessageAt, .descending).sort(\.$createdAt, .descending).limit(100).all()
        let businesses = try await BusinessRecord.query(on: db).filter(\.$id ~~ Array(Set(sessions.map(\.businessId)))).all()
        let summaries = try await DirectoryService(db: db).summaries(for: businesses)
        let byId = Dictionary(summaries.map { ($0.id.uuid, $0) }, uniquingKeysWith: { first, _ in first })
        var out: [ConversationSummary] = []
        for session in sessions {
            guard let business = byId[session.businessId], let id = session.id else { continue }
            let last = try await ConversationMessageRecord.query(on: db).filter(\.$sessionId == id).sort(\.$createdAt, .descending).first()
            let unread = try await ConversationMessageRecord.query(on: db).filter(\.$sessionId == id)
                .filter(\.$direction == MessageDirection.businessToConsumer.rawValue).filter(\.$readAt == nil).count()
            let preview = last.flatMap { try? ctx.cipher.openString($0.bodyCiphertext, context: "conversation_messages.body", rowId: $0.id!) }
                .map { SMSEncoding.field($0, maxLength: 80) }
            out.append(ConversationSummary(id: SessionID(id), business: business, state: ConversationSummary.State(rawValue: session.state) ?? .closed,
                                           lastMessagePreview: preview, lastMessageAt: session.lastMessageAt, unreadCount: unread))
        }
        return out
    }

    func start(consumer: ConsumerID, businessId: BusinessID) async throws -> ConversationSummary {
        guard let relationship = try await RelationshipRecord.query(on: db).filter(\.$consumerId == consumer.uuid)
            .filter(\.$businessId == businessId.uuid).filter(\.$status == "active").first(),
              try await DirectoryService(db: db).verified(id: businessId.uuid) != nil else { throw APIError.notFound }
        let existing = try await ConversationSessionRecord.query(on: db).filter(\.$relationshipId == relationship.id!)
            .filter(\.$channel == Channel.inApp.rawValue).filter(\.$state == "open").first()
        let session: ConversationSessionRecord
        if let existing { session = existing } else {
            session = ConversationSessionRecord(id: UUID(), businessId: businessId.uuid, consumerId: consumer.uuid,
                                                relationshipId: relationship.id!, channel: .inApp, now: ctx.now)
            try await session.create(on: db)
        }
        guard let summary = try await summaries(consumer: consumer).first(where: { $0.id.uuid == session.id }) else { throw APIError.internalError }
        return summary
    }

    func ownedSession(consumer: ConsumerID, id: SessionID) async throws -> ConversationSessionRecord {
        guard let session = try await ConversationSessionRecord.query(on: db).filter(\.$id == id.uuid)
            .filter(\.$consumerId == consumer.uuid).first() else { throw APIError.notFound }
        return session
    }

    func messages(consumer: ConsumerID, sessionId: SessionID, cursor: String?, limit: Int) async throws -> Page<ConversationMessage> {
        let session = try await ownedSession(consumer: consumer, id: sessionId)
        let limit = min(max(limit, 1), 100)
        let offset = cursor.flatMap { Int($0) }.map { max(0, $0) } ?? 0
        let rows = try await ConversationMessageRecord.query(on: db).filter(\.$sessionId == session.id!)
            .sort(\.$createdAt, .descending).sort(\.$id, .ascending).offset(offset).limit(limit + 1).all()
        let page = Array(rows.prefix(limit))
        let now = ctx.now
        for row in page where row.direction == MessageDirection.businessToConsumer.rawValue && row.readAt == nil {
            row.readAt = now
            row.deliveryStatus = DeliveryStatus.read.rawValue
            try await row.update(on: db)
        }
        return Page(items: try page.map(dto), nextCursor: rows.count > limit ? String(offset + limit) : nil)
    }

    func send(consumer: ConsumerID, sessionId: SessionID, request: SendMessageRequest) async throws -> ConversationMessage {
        let body = try Self.cleanBody(request.body)
        guard !request.clientMessageId.isEmpty, request.clientMessageId.count <= 64,
              request.clientMessageId.unicodeScalars.allSatisfy({ $0.isASCII && (CharacterSet.alphanumerics.contains($0) || "-_.:".unicodeScalars.contains($0)) })
        else { throw APIError.validation("clientMessageId is invalid.", details: ["clientMessageId": "invalid"]) }
        let session = try await ownedSession(consumer: consumer, id: sessionId)
        guard session.state != "closed" else { throw APIError.conflict("This conversation is closed.") }
        guard let relationship = try await RelationshipRecord.query(on: db).filter(\.$id == session.relationshipId)
            .filter(\.$consumerId == consumer.uuid).first(), relationship.isActive,
              try await DirectoryService(db: db).verified(id: session.businessId) != nil else { throw APIError.conflict("You are not connected to this business.") }
        if let existing = try await ConversationMessageRecord.query(on: db).filter(\.$sessionId == session.id!)
            .filter(\.$clientMessageId == request.clientMessageId).first() { return try dto(existing) }
        let now = ctx.now
        let record = ConversationMessageRecord()
        record.id = UUID()
        record.sessionId = session.id!
        record.businessId = session.businessId
        record.consumerId = consumer.uuid
        record.direction = MessageDirection.consumerToBusiness.rawValue
        record.senderType = MessageAttribution.SenderType.consumer.rawValue
        record.displayName = "You"
        record.bodyCiphertext = try ctx.cipher.seal(body, context: "conversation_messages.body", rowId: record.id!)
        record.channel = Channel.inApp.rawValue
        record.deliveryStatus = DeliveryStatus.delivered.rawValue
        record.createdAt = now
        record.clientMessageId = request.clientMessageId
        do {
            try await db.transaction { tx in
                try await record.create(on: tx)
                session.lastMessageAt = now
                try await session.update(on: tx)
                relationship.lastActivityAt = now
                try await relationship.update(on: tx)
                try await WebhookService(db: tx, ctx: ctx).enqueue(.messageReceived, businessId: BusinessID(session.businessId),
                    payload: MessageReceivedPayload(sessionId: sessionId, relationshipId: RelationshipID(relationship.id!),
                                                    subjectRef: ctx.subjects.subjectRef(businessId: BusinessID(relationship.businessId), consumerId: ConsumerID(relationship.consumerId)),
                                                    messageId: MessageID(record.id!), text: body, channel: .inApp, receivedAt: now))
            }
        } catch {
            if error.isConstraintViolation, let existing = try await ConversationMessageRecord.query(on: db)
                .filter(\.$sessionId == session.id!).filter(\.$clientMessageId == request.clientMessageId).first() { return try dto(existing) }
            throw error
        }
        return try dto(record)
    }

    // MARK: Business API

    func businessSend(principal: BusinessPrincipal, request: BusinessSendMessageRequest, headerKey: String?) async throws -> (message: ConversationMessage, created: Bool) {
        if let headerKey, headerKey != request.idempotencyKey { throw APIError.badRequest("Idempotency-Key header does not match the request body.") }
        // SEC-API-003: the key must carry `message.send` and the business must be entitled to it *now*, before a replay can answer.
        try await PolicyService(db: db, ctx: ctx).enforce(PolicyInput(.messageSend), principal: principal, auditAllowed: false)
        guard !request.idempotencyKey.isEmpty, request.idempotencyKey.count <= 128 else {
            throw APIError.validation("idempotencyKey is required.", details: ["idempotencyKey": "invalid"])
        }
        let body = try Self.cleanBody(request.body)
        let hash = SecureToken.sha256Hex(try ViadereJSON.encode(request))
        if let existing = try await ConversationMessageRecord.query(on: db).filter(\.$businessId == principal.businessId.uuid)
            .filter(\.$idempotencyKey == request.idempotencyKey).first() {
            guard let stored = existing.requestHash, ConstantTime.equals(stored, hash) else {
                throw APIError(.conflict, .idempotencyConflict, "This Idempotency-Key was already used with a different request.")
            }
            return (try dto(existing), false)
        }
        guard let relationship = try await RelationshipRecord.query(on: db).filter(\.$id == request.relationshipId.uuid)
            .filter(\.$businessId == principal.businessId.uuid).first() else { throw APIError.notFound }
        guard relationship.isActive else { throw APIError.conflict("The consumer is not connected to your business.") }
        try await Sandbox(db: db).requireMatching(relationship: relationship, livemode: principal.livemode)
        let policy = PolicyService(db: db, ctx: ctx)
        let subject = try await policy.subjectFacts(relationship: relationship, capability: .messageSend, interactionPurpose: .support)
        let decision = try await policy.decide(PolicyInput(.messageSend, subjectRef: SubjectResolver(db: db, ctx: ctx).ref(for: relationship), purpose: "support"),
                                               principal: principal, stage: .full, subject: subject)
        if decision.primaryReason == .consentRequired { throw APIError(.forbidden, .consentRequired, "The consumer has not consented to support messages.") }
        if let error = decision.apiError { throw error }
        let session: ConversationSessionRecord
        if let sessionId = request.sessionId {
            // The session must belong to this business *and* this relationship.
            guard let found = try await ConversationSessionRecord.query(on: db).filter(\.$id == sessionId.uuid)
                .filter(\.$businessId == principal.businessId.uuid).filter(\.$relationshipId == relationship.id!).first() else { throw APIError.notFound }
            // A closed session still accepts history-only messages (they are never rendered in another thread).
            session = found
        } else if let open = try await ConversationSessionRecord.query(on: db).filter(\.$relationshipId == relationship.id!)
            .filter(\.$businessId == principal.businessId.uuid).filter(\.$state == "open").sort(\.$createdAt, .descending).first() {
            session = open
        } else {
            session = ConversationSessionRecord(id: UUID(), businessId: principal.businessId.uuid, consumerId: relationship.consumerId,
                                                relationshipId: relationship.id!, channel: .inApp, now: ctx.now)
            try await session.create(on: db)
        }
        let now = ctx.now
        let agent = request.agentName.map { SMSEncoding.field($0, maxLength: 40) }.flatMap { $0.isEmpty ? nil : $0 }
        let record = ConversationMessageRecord()
        record.id = UUID()
        record.sessionId = session.id!
        record.businessId = principal.businessId.uuid
        record.consumerId = relationship.consumerId
        record.direction = MessageDirection.businessToConsumer.rawValue
        record.senderType = (agent == nil ? MessageAttribution.SenderType.business : .agent).rawValue
        // Attribution always uses the verified business name, never business-supplied text.
        record.displayName = principal.businessName
        record.agentName = agent
        record.bodyCiphertext = try ctx.cipher.seal(body, context: "conversation_messages.body", rowId: record.id!)
        record.channel = session.channel
        record.deliveryStatus = DeliveryStatus.queued.rawValue
        record.createdAt = now
        record.idempotencyKey = request.idempotencyKey
        record.requestHash = hash
        do {
            try await db.transaction { tx in
                try await record.create(on: tx)
                session.lastMessageAt = now
                try await session.update(on: tx)
                relationship.lastActivityAt = now
                try await relationship.update(on: tx)
                _ = try await AuditService(db: tx, ctx: ctx).record("message.business_sent", actor: AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased()),
                    consumerId: ConsumerID(relationship.consumerId), businessId: principal.businessId, subjectType: "message",
                    subjectId: record.id?.uuidString.lowercased())
            }
        } catch {
            if error.isConstraintViolation, let existing = try await ConversationMessageRecord.query(on: db)
                .filter(\.$businessId == principal.businessId.uuid).filter(\.$idempotencyKey == request.idempotencyKey).first() {
                guard existing.requestHash == hash else {
                    throw APIError(.conflict, .idempotencyConflict, "This Idempotency-Key was already used with a different request.")
                }
                return (try dto(existing), false)
            }
            throw error
        }
        // Delivery: SMS thread if this session is the active SMS session, otherwise a generic push.
        // Test-mode messages never reach a real SMS thread (and sandbox consumers have none).
        let viaSMS = principal.livemode ? try await GatewayService(db: db, ctx: ctx).deliverBusinessMessage(
            businessId: principal.businessId, sessionId: SessionID(session.id!), text: body, messageId: record.id) : false
        if !viaSMS {
            // In-app / history-only messages are "delivered" once stored; SMS ones follow provider receipts.
            record.deliveryStatus = DeliveryStatus.delivered.rawValue
            record.deliveredAt = ctx.now
            try await record.update(on: db)
            if principal.livemode, session.state != "closed" {
                await pushMessageNotice(consumerId: relationship.consumerId, businessId: principal.businessId)
            }
        }
        return (try dto(record), true)
    }

    private func pushMessageNotice(consumerId: UUID, businessId: BusinessID) async {
        do {
            guard let business = try await BusinessRecord.find(businessId.uuid, on: db),
                  let summary = try await DirectoryService(db: db).summary(for: business) else { return }
            let devices = try await DeviceRecord.query(on: db).filter(\.$consumerId == consumerId).filter(\.$revokedAt == nil).all()
            let tokens = try await APNsTokenRecord.query(on: db).filter(\.$deviceId ~~ devices.compactMap(\.id)).filter(\.$invalidatedAt == nil).all()
            for token in tokens {
                let message = PushPayloadBuilder.messageNotice(business: summary, token: token.record, topic: ctx.config.appBundleID)
                if await ctx.apns.send(message) == .tokenInvalid {
                    try await APNsTokenRecord.query(on: db).filter(\.$id == token.id!).set(\.$invalidatedAt, to: ctx.now).update()
                }
            }
        } catch {}
    }
}
