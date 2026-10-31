import Fluent
import Foundation
import Vapor
import ViadereCore

/// Subject access export (LEG-PR-004, GDPR Art. 15/20): the account holder asks from a trusted device (a device-signed request), an asynchronous job
/// gathers their data, **seals it to that device's own key** (`E2EE`, P-256 HPKE: the server keeps nothing that can open it) and tells the device by
/// a generic push that it is ready. Nothing goes by email (the account has no address) and nothing readable is left on the server: the stored
/// bundle is ciphertext, expires after seven days and is erased by the retention job. Only the requesting device of the same account can fetch it.
struct ConsumerExports {
    let db: any Database
    let ctx: ServerContext

    static let lifetime: TimeInterval = 7 * 86_400
    static let maxDownloads = 5
    static let chunkBytes = 48_000
    static let maxChunks = 80
    static let purpose = "account-export"

    func status(of record: ConsumerExportRecord) -> AccountExportStatus {
        let ready = record.status == "ready" && record.expiresAt > ctx.now
        return AccountExportStatus(exportId: record.id!.uuidString.lowercased(), status: record.expiresAt <= ctx.now ? "expired" : (record.status == "building" ? "queued" : record.status), createdAt: record.createdAt,
                                   readyAt: record.readyAt, expiresAt: record.expiresAt,
                                   downloadPath: ready ? "/v1/account/exports/\(record.id!.uuidString.lowercased())/download" : nil)
    }

    // MARK: Request

    func request(principal: ConsumerPrincipal, recipientKey: String) async throws -> ConsumerExportRecord {
        // Same trust bar as account deletion: a long-enrolled app device, not an App Clip or a fresh enrollment.
        try await DeviceTrust.require(principal, db: db, now: ctx.now)
        guard let deviceId = principal.deviceId, let key = try? E2EEPublicKey(base64URL: recipientKey) else {
            throw APIError.validation("recipientKey must be the device's P-256 key-agreement public key (base64url).", details: ["recipientKey": "invalid"])
        }
        let consumerId = principal.consumerId.uuid
        let now = ctx.now
        guard try await ConsumerExportRecord.query(on: db).filter(\.$consumerId == consumerId).filter(\.$status == "queued").count() == 0 else {
            throw APIError.conflict("An export is already being prepared.")
        }
        guard try await ConsumerExportRecord.query(on: db).filter(\.$consumerId == consumerId).filter(\.$createdAt > now.addingTimeInterval(-86_400)).count() < 3 else {
            throw APIError.rateLimited(retryAfter: 3600)
        }
        let record = ConsumerExportRecord()
        record.id = UUID()
        record.consumerId = consumerId
        record.deviceId = deviceId.uuid
        record.status = "queued"
        record.recipientKey = key.base64URL
        record.createdAt = now
        record.expiresAt = now.addingTimeInterval(Self.lifetime)
        record.downloads = 0
        try await db.transaction { [ctx] tx in
            try await record.create(on: tx)
            try await Outbox.enqueue(QueueHandlers.consumerExport, ref: record.id!, on: tx, ctx: ctx)
        }
        _ = try await AuditService(db: db, ctx: ctx).record("account.export_requested", principal: principal, subjectType: "export", subjectId: record.id?.uuidString.lowercased())
        return record
    }

    /// Owner-only: the same account **and** the device that asked (the bundle can only be opened by that device's key anyway). Anything else is a plain 404.
    func owned(id: UUID, principal: ConsumerPrincipal) async throws -> ConsumerExportRecord {
        guard let record = try await ConsumerExportRecord.query(on: db).filter(\.$id == id).filter(\.$consumerId == principal.consumerId.uuid).first(),
              record.deviceId == principal.deviceId?.uuid else { throw APIError.notFound }
        return record
    }

    func download(id: UUID, principal: ConsumerPrincipal) async throws -> AccountExportBundle {
        let record = try await owned(id: id, principal: principal)
        guard record.status == "ready", record.expiresAt > ctx.now, let bundle = record.bundle,
              let data = bundle.data(using: .utf8), let envelopes = try? JSONDecoder().decode([String].self, from: data) else {
            throw APIError.gone("This export is not available any more.")
        }
        guard record.downloads < Self.maxDownloads else { throw APIError.gone("This export was downloaded too many times. Request a new one.") }
        record.downloads += 1
        try await record.update(on: db)
        _ = try await AuditService(db: db, ctx: ctx).record("account.export_downloaded", principal: principal, subjectType: "export", subjectId: id.uuidString.lowercased())
        return AccountExportBundle(exportId: id.uuidString.lowercased(), envelopes: envelopes)
    }

    // MARK: Job

    @discardableResult
    func processQueued(limit: Int = 5) async throws -> Int {
        // A worker that died mid-build leaves a "building" row behind; put it back after a lease.
        // (Read first: this runs on every tick of every instance, and an idle run must not take a write lock.)
        let stuck = ConsumerExportRecord.query(on: db).filter(\.$status == "building").filter(\.$createdAt < ctx.now.addingTimeInterval(-900))
        if try await stuck.count() > 0 {
            try await ConsumerExportRecord.query(on: db).filter(\.$status == "building").filter(\.$createdAt < ctx.now.addingTimeInterval(-900)).set(\.$status, to: "queued").update()
        }
        let queued = try await ConsumerExportRecord.query(on: db).filter(\.$status == "queued").sort(\.$createdAt, .ascending).limit(limit).all()
        var built = 0
        for record in queued {
            guard let id = record.id, try await DB.swap(db, table: ConsumerExportRecord.schema, id: id, column: "status", expected: "queued", newValue: "building") else { continue }
            if await buildClaimed(record) { built += 1 }
        }
        return built
    }

    /// Builds one claimed (`building`) export: the shared body of `processQueued` and the `consumer_export.process` queue handler. Returns whether the
    /// export is ready; a failure puts it back to `queued` for the next attempt.
    func buildClaimed(_ record: ConsumerExportRecord) async -> Bool {
        guard let id = record.id else { return false }
        do {
            let bundle = try await build(for: record)
            record.bundle = String(decoding: try JSONEncoder().encode(bundle), as: UTF8.self)
            record.status = "ready"
            record.readyAt = ctx.now
            try await record.update(on: db)
            // A generic push: no name, no business, no content.
            await Notifier(db: db, ctx: ctx).pushGeneric(to: record.consumerId, body: "Your Viadere data export is ready. Open Viadere on the device that requested it.")
            _ = try await AuditService(db: db, ctx: ctx).record("account.export_ready", actor: AuditActor(kind: .system), consumerId: ConsumerID(record.consumerId),
                                                              subjectType: "export", subjectId: id.uuidString.lowercased())
            return true
        } catch {
            ctx.logger.warning("export could not be built", metadata: ["type": "\(type(of: error))"])
            record.status = "queued"
            try? await record.update(on: db)
            return false
        }
    }

    private func build(for record: ConsumerExportRecord) async throws -> [String] {
        let document = try await document(for: record.consumerId)
        let plaintext = try JSONSerialization.data(withJSONObject: document, options: [.sortedKeys, .withoutEscapingSlashes])
        let recipient = try E2EEPublicKey(base64URL: record.recipientKey)
        var envelopes: [String] = []
        var offset = 0
        while offset < plaintext.count {
            let end = min(offset + Self.chunkBytes, plaintext.count)
            guard envelopes.count < Self.maxChunks else { throw APIError.internalError }
            let context = E2EEContext(purpose: Self.purpose, requestId: record.id!.uuidString.lowercased(), sender: "viadere",
                                      recipient: "device-" + record.deviceId.uuidString.lowercased(), expiresAt: record.expiresAt)
            let envelope = try E2EE.seal(plaintext.subdata(in: offset..<end), to: recipient, context: context)
            envelopes.append(Base64URL.encode(try envelope.serialized()))
            offset = end
        }
        return envelopes
    }

    /// Everything the server holds about the account, as the person would want it: no hashes of secrets, no signatures, no other people's data.
    func document(for consumerId: UUID) async throws -> [String: Any] {
        guard let consumer = try await ConsumerRecord.find(consumerId, on: db) else { throw APIError.notFound }
        let iso = { (date: Date?) -> Any in date.map { ViadereDate.format($0) } ?? NSNull() }
        var out: [String: Any] = ["format": "viadere-export-v1", "generatedAt": ViadereDate.format(ctx.now)]
        out["account"] = ["id": consumerId.uuidString.lowercased(), "displayName": consumer.displayName as Any? ?? NSNull(), "createdAt": iso(consumer.createdAt), "status": consumer.status]
        let devices = try await DeviceRecord.query(on: db).filter(\.$consumerId == consumerId).all()
        out["devices"] = devices.map { ["id": $0.id?.uuidString.lowercased() ?? "", "name": $0.name, "createdAt": iso($0.createdAt), "lastSeenAt": iso($0.lastSeenAt), "revokedAt": iso($0.revokedAt)] }
        let links = try await PhoneLinkRecord.query(on: db).filter(\.$consumerId == consumerId).all()
        out["phoneNumbers"] = links.map { ["masked": $0.phoneMasked, "last4": $0.phoneLast4, "state": $0.state] }
        let relationships = try await RelationshipRecord.query(on: db).filter(\.$consumerId == consumerId).all()
        let businesses = try await BusinessRecord.query(on: db).filter(\.$id ~~ Set(relationships.map(\.businessId)).map { $0 }).all()
        let names = Dictionary(businesses.compactMap { b in b.id.map { ($0, b.displayName) } }, uniquingKeysWith: { a, _ in a })
        out["relationships"] = relationships.map { ["business": names[$0.businessId] ?? "", "businessId": $0.businessId.uuidString.lowercased(), "status": $0.status, "since": iso($0.connectedAt)] }
        let consents = try await ConsentGrantRecord.query(on: db).filter(\.$consumerId == consumerId).sort(\.$createdAt, .ascending).limit(5000).all()
        out["consents"] = consents.map { ["businessId": $0.businessId.uuidString.lowercased(), "purpose": $0.purpose, "granted": $0.granted, "version": $0.version,
                                          "policyVersion": $0.policyVersion, "source": $0.source, "at": iso($0.createdAt)] }
        let interactions = try await InteractionRecord.query(on: db).filter(\.$consumerId == consumerId).filter(\.$livemode == true).sort(\.$createdAt, .descending).limit(2000).all()
        out["interactions"] = interactions.map { ["id": $0.id?.uuidString.lowercased() ?? "", "business": names[$0.businessId] ?? "", "kind": $0.kind, "purpose": $0.purpose, "status": $0.status,
                                                  "createdAt": iso($0.createdAt), "decidedAt": iso($0.decidedAt), "content": $0.contentErased ? "erased by retention" : $0.interactionJSON] }
        let decisions = try await DecisionRecord.query(on: db).filter(\.$consumerId == consumerId).sort(\.$decidedAt, .descending).limit(2000).all()
        out["decisions"] = decisions.map { ["interactionId": $0.interactionId.uuidString.lowercased(), "decision": $0.decision, "assurance": $0.assurance, "channel": $0.channel, "at": iso($0.decidedAt)] }
        let messages = try await ConversationMessageRecord.query(on: db).filter(\.$consumerId == consumerId).sort(\.$createdAt, .descending).limit(5000).all()
        out["messages"] = messages.map { message -> [String: Any] in
            let text = (try? ctx.cipher.openString(message.bodyCiphertext, context: "conversation_messages.body", rowId: message.id!)) ?? ""
            return ["business": names[message.businessId] ?? "", "direction": message.direction, "channel": message.channel, "text": text, "at": iso(message.createdAt)]
        }
        let loyalty = try await LoyaltyAccountRecord.query(on: db).filter(\.$consumerId == consumerId).all()
        out["loyalty"] = loyalty.map { ["businessId": $0.businessId.uuidString.lowercased(), "points": $0.pointsBalance] }
        let notices = try await SecurityNoticeRecord.query(on: db).filter(\.$consumerId == consumerId).sort(\.$createdAt, .descending).limit(500).all()
        out["profile"] = try await ProfileService(db: db, ctx: ctx).exportSection(consumer: consumerId)
        out["securityNotices"] = notices.map { ["kind": $0.kind, "message": $0.message, "at": iso($0.createdAt)] }
        return out
    }
}

enum ConsumerExportRoutes {
    static func register(_ routes: any RoutesBuilder) {
        routes.api(APIRoutes.accountExportCreate) { req in
            let body: AccountExportRequest = try req.decodeBody()
            let service = ConsumerExports(db: req.db, ctx: req.ctx)
            let record = try await service.request(principal: try req.consumer, recipientKey: body.recipientKey)
            return try req.jsonResponse(service.status(of: record), status: .accepted)
        }
        routes.api(APIRoutes.accountExportGet) { req in
            let service = ConsumerExports(db: req.db, ctx: req.ctx)
            let record = try await service.owned(id: try req.uuid("exportId"), principal: try req.consumer)
            return try req.jsonResponse(service.status(of: record))
        }
        routes.api(APIRoutes.accountExportDownload) { req in
            try req.jsonResponse(try await ConsumerExports(db: req.db, ctx: req.ctx).download(id: try req.uuid("exportId"), principal: try req.consumer))
        }
    }
}
