import Crypto
import Fluent
import Foundation
import Vapor
import ViadereCore
import typealias ViadereCore.SessionID

/// Message attachments (docs/SECURITY.md §2.113): upload, binding to one conversation of one tenant, download by a participant, and deletion.
///
/// * **Ingestion** is the Brand Kit decoder front end and pure-Swift codecs (`BrandImagePipeline.reencode`, ADR-0017) with the attachment
///   limits of `MessageAttachmentPolicy`; nothing of the upload but its pixels is stored.
/// * **At rest** the re-encoded image is sealed with the field cipher (AES-256-GCM) under the additional data
///   `message_attachments.object:{business}#{attachment id}` and written create-only to the private attachment store; the row holds the
///   plaintext SHA-256, checked on every read. A stored object moved to another name, another tenant or another row does not open.
/// * **Binding**: the tenant, the customer and the conversation are fixed at upload from the authenticated caller and the conversation it
///   owns. Sending names pending ids; each must be a pending upload of the same side to the same conversation of the same tenant, unexpired,
///   and is claimed by compare-and-swap inside the message's transaction. Anything else is the same `404` as an unknown id.
/// * **Lifetime**: an unsent upload expires after `MessageAttachmentPolicy.pendingLifetime`; an attached image follows its message's
///   conversation retention; account and tenant deletion mark the rows, and `sweep` removes the objects, then the rows.
struct MessageAttachmentService {
    let db: any Database
    let ctx: ServerContext
    let runtime: AttachmentRuntime

    enum Side: String { case consumer, business }

    enum State: String {
        case pending, attached, deleting
    }

    static func objectContext(business: UUID) -> String { "message_attachments.object:\(business.uuidString.lowercased())" }

    /// `attachments/{business}/{session}/{attachment}.bin`: the only object name an attachment has (no type, no hash, no customer id).
    static func objectName(business: UUID, session: UUID, id: UUID) -> String {
        "attachments/\(business.uuidString.lowercased())/\(session.uuidString.lowercased())/\(id.uuidString.lowercased()).bin"
    }

    // MARK: Mapping

    static func dto(_ row: MessageAttachmentRecord) -> MessageAttachment {
        MessageAttachment(id: AttachmentID(row.id!), sessionId: SessionID(row.sessionId), mediaType: row.mediaType, byteSize: row.byteSize,
                          width: row.width, height: row.height, sha256: row.sha256,
                          state: row.state == State.attached.rawValue ? .attached : .pending,
                          expiresAt: row.state == State.pending.rawValue ? row.expiresAt : nil)
    }

    /// The attached images of each message, in order. Rows being deleted are left out.
    static func references(messageIds: [UUID], on db: any Database) async throws -> [UUID: [MessageAttachment]] {
        guard !messageIds.isEmpty else { return [:] }
        var out: [UUID: [MessageAttachment]] = [:]
        for chunk in stride(from: 0, to: messageIds.count, by: 200).map({ Array(messageIds[$0..<min($0 + 200, messageIds.count)]) }) {
            let rows = try await MessageAttachmentRecord.query(on: db).filter(\.$messageId ~~ chunk).filter(\.$state == State.attached.rawValue).all()
            for row in rows.sorted(by: { ($0.position ?? 0) < ($1.position ?? 0) }) {
                guard let message = row.messageId else { continue }
                out[message, default: []].append(dto(row))
            }
        }
        return out
    }

    // MARK: Upload

    /// The customer's upload to a conversation they own and may write in.
    func consumerUpload(consumer: ConsumerID, deviceId: DeviceID?, sessionId: SessionID, data: Data, contentType: String) async throws -> MessageAttachment {
        let session = try await ConversationService(db: db, ctx: ctx).ownedSession(consumer: consumer, id: sessionId)
        guard session.state != "closed" else { throw APIError.conflict("This conversation is closed.") }
        guard let relationship = try await RelationshipRecord.query(on: db).filter(\.$id == session.relationshipId)
            .filter(\.$consumerId == consumer.uuid).first(), relationship.isActive else { throw APIError.conflict("You are not connected to this business.") }
        try await ctx.limiter.enforce("attachment-upload-consumer", key: consumer.description, rule: ctx.config.attachments.uploadRatePerConsumer)
        return try await ingest(session: session, side: .consumer, uploaderRef: deviceId.map { "device:\($0)" } ?? "consumer",
                                actor: AuditActor(kind: .consumer, id: consumer.description), data: data, contentType: contentType)
    }

    /// The business's upload (API key or console) to one of its conversations. A test key reaches sandbox conversations only.
    func businessUpload(principal: BusinessPrincipal, sessionId: SessionID, data: Data, contentType: String) async throws -> MessageAttachment {
        try await PolicyService(db: db, ctx: ctx).enforce(PolicyInput(.messageSend), principal: principal, auditAllowed: false)
        let session = try await businessSession(principal: principal, sessionId: sessionId)
        guard let relationship = try await RelationshipRecord.query(on: db).filter(\.$id == session.relationshipId)
            .filter(\.$businessId == principal.businessId.uuid).first() else { throw APIError.notFound }
        guard relationship.isActive else { throw APIError.conflict("The consumer is not connected to your business.") }
        try await ctx.limiter.enforce("attachment-upload-business", key: principal.businessId.description, rule: ctx.config.attachments.uploadRatePerBusiness)
        let ref = principal.consoleUserId.map { "console:\($0.uuidString.lowercased())" } ?? "key:\(principal.keyId.uuidString.lowercased())"
        return try await ingest(session: session, side: .business, uploaderRef: ref, actor: principal.auditActor, data: data, contentType: contentType)
    }

    /// A conversation of this business, on the same side of the test/live line as the key (another tenant's id is the same `404`).
    func businessSession(principal: BusinessPrincipal, sessionId: SessionID) async throws -> ConversationSessionRecord {
        guard let session = try await ConversationSessionRecord.query(on: db).filter(\.$id == sessionId.uuid)
            .filter(\.$businessId == principal.businessId.uuid).first() else { throw APIError.notFound }
        guard try await Sandbox(db: db).matches(consumerId: session.consumerId, livemode: principal.livemode) else { throw APIError.notFound }
        return session
    }

    private func ingest(session: ConversationSessionRecord, side: Side, uploaderRef: String, actor: AuditActor, data: Data, contentType: String) async throws -> MessageAttachment {
        guard let store = runtime.store else { throw APIError(.serviceUnavailable, .unavailable, "Image uploads are not available right now.") }
        let sessionId = session.id!
        let now = ctx.now
        let pending = try await MessageAttachmentRecord.query(on: db).filter(\.$sessionId == sessionId).filter(\.$side == side.rawValue)
            .filter(\.$state == State.pending.rawValue).filter(\.$expiresAt > now).count()
        guard pending < MessageAttachmentPolicy.maxPendingPerSession else {
            throw APIError.conflict("Send or wait for the images you already added before adding more.")
        }
        guard await runtime.gate.acquire() else { throw APIError(.serviceUnavailable, .unavailable, "Uploads are busy. Try again in a moment.") }
        let result = BrandImagePipeline.reencode(data, declaredContentType: contentType, maxDimension: MessageAttachmentPolicy.maxStoredDimension,
                                                 maxStoredBytes: MessageAttachmentPolicy.maxStoredBytes, encoding: .jpegWhenOpaque)
        await runtime.gate.release()
        let image: BrandImagePipeline.Encoded
        switch result {
        case .failure(let rejection):
            _ = try await AuditService(db: db, ctx: ctx).record("message.attachment_rejected", outcome: .denied, actor: actor, businessId: BusinessID(session.businessId),
                                                                subjectType: "conversation_session", subjectId: sessionId.uuidString.lowercased(),
                                                                metadata: ["side": side.rawValue, "reason": rejection.rawValue])
            throw APIError.validation(MessageAttachmentPolicy.message(rejection), details: ["file": rejection.rawValue])
        case .success(let value): image = value
        }
        guard MessageAttachmentPolicy.storedMediaTypes.contains(image.mediaType) else { throw APIError.internalError }
        let row = MessageAttachmentRecord()
        let id = UUID()
        row.id = id
        row.businessId = session.businessId
        row.consumerId = session.consumerId
        row.sessionId = sessionId
        row.side = side.rawValue
        row.uploaderRef = uploaderRef
        row.mediaType = image.mediaType
        row.byteSize = image.data.count
        row.width = image.width
        row.height = image.height
        row.sha256 = image.sha256
        row.objectName = Self.objectName(business: session.businessId, session: sessionId, id: id)
        row.state = State.pending.rawValue
        row.createdAt = now
        row.expiresAt = now.addingTimeInterval(MessageAttachmentPolicy.pendingLifetime)
        // The row first: an object can then never exist without a row that names it (and that the sweep deletes).
        try await row.create(on: db)
        do {
            let sealed = try ctx.cipher.seal(image.data, context: Self.objectContext(business: session.businessId), rowId: id)
            try await store.create(name: row.objectName, data: Data(sealed.utf8), contentType: "application/octet-stream")
        } catch {
            try? await MessageAttachmentRecord.query(on: db).filter(\.$id == id).delete()
            ctx.logger.error("attachment store write failed", metadata: ["type": "\(type(of: error))"])
            throw APIError(.serviceUnavailable, .unavailable, "Image uploads are not available right now.")
        }
        _ = try await AuditService(db: db, ctx: ctx).record("message.attachment_uploaded", actor: actor, businessId: BusinessID(session.businessId),
                                                            subjectType: "message_attachment", subjectId: id.uuidString.lowercased(),
                                                            metadata: ["side": side.rawValue, "session": sessionId.uuidString.lowercased(), "type": image.mediaType,
                                                                       "bytes": String(image.data.count), "width": String(image.width), "height": String(image.height)])
        return Self.dto(row)
    }

    // MARK: Binding to a message

    /// Checks (before the message is written) that every id is a usable pending upload of `side` to `session`. Unknown, foreign, other
    /// conversation, other side, already sent and expired ids are all the same `404`.
    static func pendingRows(_ ids: [AttachmentID]?, session: ConversationSessionRecord, side: Side, now: Date, on db: any Database) async throws -> [MessageAttachmentRecord] {
        guard let ids, !ids.isEmpty else { return [] }
        guard MessageAttachmentPolicy.validate(ids) else {
            throw APIError.validation("A message can carry at most \(MessageAttachmentPolicy.maxPerMessage) different images.", details: ["attachmentIds": "invalid"])
        }
        let rows = try await MessageAttachmentRecord.query(on: db).filter(\.$id ~~ ids.map(\.uuid)).filter(\.$businessId == session.businessId)
            .filter(\.$sessionId == session.id!).filter(\.$side == side.rawValue).filter(\.$state == State.pending.rawValue).all()
        let byId = Dictionary(rows.map { ($0.id!, $0) }, uniquingKeysWith: { a, _ in a })
        var ordered: [MessageAttachmentRecord] = []
        for id in ids {
            guard let row = byId[id.uuid], let expires = row.expiresAt, expires > now else {
                throw APIError(.notFound, .notFound, "An image in this message was not found. Upload it to this conversation again.")
            }
            ordered.append(row)
        }
        return ordered
    }

    /// Claims the rows for `messageId` inside the message's transaction (compare-and-swap on `pending`): a concurrent send of the same upload
    /// loses and its whole transaction rolls back.
    static func claim(_ rows: [MessageAttachmentRecord], messageId: UUID, now: Date, on tx: any Database) async throws {
        for (position, row) in rows.enumerated() {
            guard try await DB.swap(tx, table: MessageAttachmentRecord.schema, id: row.id!, column: "state", expected: State.pending.rawValue,
                                    newValue: State.attached.rawValue,
                                    extra: [("message_id", messageId), ("position", position), ("attached_at", now)]) else {
                throw APIError(.notFound, .notFound, "An image in this message was not found. Upload it to this conversation again.")
            }
            row.state = State.attached.rawValue
            row.messageId = messageId
            row.position = position
            row.attachedAt = now
        }
    }

    // MARK: Download

    /// An image of a conversation the customer owns: attached to any message there, or one of their own pending uploads.
    func consumerDownload(consumer: ConsumerID, sessionId: SessionID, attachmentId: AttachmentID) async throws -> (MessageAttachmentRecord, Data) {
        let session = try await ConversationService(db: db, ctx: ctx).ownedSession(consumer: consumer, id: sessionId)
        guard let row = try await MessageAttachmentRecord.query(on: db).filter(\.$id == attachmentId.uuid).filter(\.$sessionId == session.id!)
            .filter(\.$businessId == session.businessId).filter(\.$consumerId == consumer.uuid).first(), Self.readable(row, by: .consumer, now: ctx.now)
        else { throw APIError.notFound }
        return (row, try await bytes(row))
    }

    /// An image of a conversation of this business (API key with `messages:write` and `message.send`, or the console).
    func businessDownload(businessId: UUID, session: ConversationSessionRecord, attachmentId: AttachmentID) async throws -> (MessageAttachmentRecord, Data) {
        guard session.businessId == businessId,
              let row = try await MessageAttachmentRecord.query(on: db).filter(\.$id == attachmentId.uuid).filter(\.$sessionId == session.id!)
            .filter(\.$businessId == businessId).first(), Self.readable(row, by: .business, now: ctx.now) else { throw APIError.notFound }
        return (row, try await bytes(row))
    }

    /// Attached images are readable by both participants; a pending upload only by the side that uploaded it, until it expires.
    static func readable(_ row: MessageAttachmentRecord, by side: Side, now: Date) -> Bool {
        switch State(rawValue: row.state) {
        case .attached?: return true
        case .pending?: return row.side == side.rawValue && (row.expiresAt.map { $0 > now } ?? false)
        default: return false
        }
    }

    /// The stored image: read, opened (bound to tenant and row) and checked against the row's digest. Anything else serves nothing.
    func bytes(_ row: MessageAttachmentRecord) async throws -> Data {
        guard let store = runtime.store else { throw APIError(.serviceUnavailable, .unavailable, "Images are not available right now.") }
        guard let sealed = try await store.read(name: row.objectName),
              let image = try? ctx.cipher.open(String(decoding: sealed, as: UTF8.self), context: Self.objectContext(business: row.businessId), rowId: row.id!),
              image.count == row.byteSize, Hex.encode(Data(SHA256.hash(data: image))) == row.sha256 else {
            ctx.logger.error("attachment unreadable or altered", metadata: ["attachment": "\(row.id?.uuidString.lowercased() ?? "")"])
            throw APIError.notFound
        }
        return image
    }

    /// The safe response for an attachment: the stored type, `nosniff`, a sandboxing CSP, never cached, never a redirect.
    static func imageResponse(_ data: Data, row: MessageAttachmentRecord, disposition: Disposition) -> Response {
        let response = Response(status: .ok, body: .init(data: data))
        let type = MessageAttachmentPolicy.storedMediaTypes.contains(row.mediaType) ? row.mediaType : "application/octet-stream"
        response.headers.replaceOrAdd(name: .contentType, value: type)
        response.headers.replaceOrAdd(name: "X-Content-Type-Options", value: "nosniff")
        response.headers.replaceOrAdd(name: "Content-Security-Policy", value: "default-src 'none'; sandbox")
        let ext = type == "image/png" ? "png" : "jpg"
        let name = "image-\(row.id!.uuidString.lowercased().prefix(8)).\(ext)"
        response.headers.replaceOrAdd(name: "Content-Disposition", value: disposition == .attachment ? "attachment; filename=\"\(name)\"" : "inline; filename=\"\(name)\"")
        response.headers.replaceOrAdd(name: .cacheControl, value: "private, no-store")
        response.headers.replaceOrAdd(name: "Cross-Origin-Resource-Policy", value: "same-origin")
        return response
    }

    enum Disposition { case attachment, inline }

    // MARK: Lifetime

    /// Marks rows for deletion (the sweep removes their objects). Used by retention, account deletion and tenant deletion, inside their
    /// transactions, so a deletion and its marking commit together.
    static func markDeleting(_ query: QueryBuilder<MessageAttachmentRecord>, now: Date) async throws {
        try await query.filter(\.$state != State.deleting.rawValue).set(\.$state, to: State.deleting.rawValue).set(\.$deleteRequestedAt, to: now).update()
    }

    /// Expired pending uploads are marked; marked rows lose their object, then the row. Idempotent; a store failure leaves the row for the
    /// next run. Returns the number of objects removed.
    func sweep(limit: Int = 500) async throws -> Int {
        let now = ctx.now
        try await Self.markDeleting(MessageAttachmentRecord.query(on: db).filter(\.$state == State.pending.rawValue).filter(\.$expiresAt < now), now: now)
        guard let store = runtime.store else { return 0 }
        var removed = 0
        for row in try await MessageAttachmentRecord.query(on: db).filter(\.$state == State.deleting.rawValue).limit(limit).all() {
            do {
                try await store.delete(name: row.objectName)
            } catch {
                ctx.logger.warning("attachment object delete failed", metadata: ["type": "\(type(of: error))"])
                continue
            }
            try await MessageAttachmentRecord.query(on: db).filter(\.$id == row.id!).filter(\.$state == State.deleting.rawValue).delete()
            removed += 1
        }
        return removed
    }
}
