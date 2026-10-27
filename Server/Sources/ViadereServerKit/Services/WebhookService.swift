import Fluent
import Foundation
import ViadereCore

/// Webhook subscription management, event enqueueing and signed delivery with retry/dead-letter handling.
struct WebhookService {
    let db: any Database
    let ctx: ServerContext

    static let maxSubscriptionsPerBusiness = 10
    static let maxAttempts = 8
    /// Delay before retry N (seconds): 30 s, 2 min, 10 min, 1 h, 6 h, 12 h, 24 h.
    static let backoff: [TimeInterval] = [30, 120, 600, 3600, 6 * 3600, 12 * 3600, 24 * 3600]
    static let knownEvents: [WebhookEventType] = [
        .interactionDecided, .interactionExpired, .interactionCancelled, .messageReceived, .relationshipConnected,
        .relationshipDisconnected, .consentUpdated, .rewardRedeemed,
    ]
    static let rotationOverlap: TimeInterval = 24 * 3600

    // MARK: Subscriptions

    func dto(_ record: WebhookSubscriptionRecord) -> WebhookSubscription? {
        guard let id = record.id, let url = URL(string: record.url) else { return nil }
        return WebhookSubscription(id: WebhookSubscriptionID(id), url: url,
                                   events: record.events.split(separator: ",").map { WebhookEventType(rawValue: String($0)) },
                                   active: record.active, createdAt: record.createdAt)
    }

    func list(businessId: BusinessID) async throws -> [WebhookSubscription] {
        try await WebhookSubscriptionRecord.query(on: db).filter(\.$businessId == businessId.uuid).filter(\.$active == true)
            .sort(\.$createdAt, .ascending).all().compactMap(dto)
    }

    func create(businessId: BusinessID, request: CreateWebhookRequest) async throws -> WebhookSecretResponse {
        guard WebhookURLPolicy.validate(request.url, allowInsecure: ctx.config.allowInsecureWebhookURLs) else {
            throw APIError.validation("The webhook URL must be a public https URL.", details: ["url": "invalid"])
        }
        let events = Array(Set(request.events.map(\.rawValue)))
        guard !events.isEmpty, events.count <= 16, events.allSatisfy({ e in Self.knownEvents.contains { $0.rawValue == e } }) else {
            throw APIError.validation("Unknown or missing event types.", details: ["events": "invalid"])
        }
        let existing = try await WebhookSubscriptionRecord.query(on: db).filter(\.$businessId == businessId.uuid)
            .filter(\.$active == true).count()
        guard existing < Self.maxSubscriptionsPerBusiness else { throw APIError.conflict("Webhook limit reached.") }
        let secret = WebhookSignature.generateSecret()
        let record = WebhookSubscriptionRecord()
        record.id = UUID()
        record.businessId = businessId.uuid
        record.url = request.url.absoluteString
        record.events = events.sorted().joined(separator: ",")
        record.secretCiphertext = try ctx.cipher.seal(secret, context: "webhook_subscriptions.secret", rowId: record.id!)
        record.active = true
        record.createdAt = ctx.now
        try await record.create(on: db)
        guard let subscription = dto(record) else { throw APIError.internalError }
        _ = try await AuditService(db: db, ctx: ctx).record("webhook.created", actor: AuditActor(kind: .business, id: businessId.description),
                                                           businessId: businessId, subjectType: "webhook", subjectId: record.id?.uuidString.lowercased())
        return WebhookSecretResponse(subscription: subscription, secret: secret)
    }

    func delete(businessId: BusinessID, id: WebhookSubscriptionID) async throws {
        guard let record = try await WebhookSubscriptionRecord.query(on: db).filter(\.$id == id.uuid)
            .filter(\.$businessId == businessId.uuid).first() else { throw APIError.notFound }
        record.active = false
        try await record.update(on: db)
        // Stop pending deliveries for a removed endpoint.
        try await WebhookDeliveryRecord.query(on: db).filter(\.$subscriptionId == id.uuid).filter(\.$status == "pending")
            .set(\.$status, to: "dead").update()
        _ = try await AuditService(db: db, ctx: ctx).record("webhook.deleted", actor: AuditActor(kind: .business, id: businessId.description),
                                                           businessId: businessId, subjectType: "webhook", subjectId: id.description)
    }

    func rotate(businessId: BusinessID, id: WebhookSubscriptionID) async throws -> WebhookSecretResponse {
        guard let record = try await WebhookSubscriptionRecord.query(on: db).filter(\.$id == id.uuid)
            .filter(\.$businessId == businessId.uuid).filter(\.$active == true).first() else { throw APIError.notFound }
        let secret = WebhookSignature.generateSecret()
        // Keep the old secret signing for a while so receivers can switch over without dropping events.
        record.previousSecretCiphertext = record.secretCiphertext
        record.previousSecretExpiresAt = ctx.now.addingTimeInterval(Self.rotationOverlap)
        record.secretCiphertext = try ctx.cipher.seal(secret, context: "webhook_subscriptions.secret", rowId: record.id!)
        try await record.update(on: db)
        guard let subscription = dto(record) else { throw APIError.internalError }
        _ = try await AuditService(db: db, ctx: ctx).record("webhook.rotated", actor: AuditActor(kind: .business, id: businessId.description),
                                                           businessId: businessId, subjectType: "webhook", subjectId: id.description)
        return WebhookSecretResponse(subscription: subscription, secret: secret)
    }

    // MARK: Enqueue

    /// Queues one delivery per matching active subscription. Runs inside the caller's transaction so an
    /// event is queued if and only if the state change it describes committed.
    func enqueue<T: Encodable>(_ type: WebhookEventType, businessId: BusinessID, payload: T) async throws {
        let subscriptions = try await WebhookSubscriptionRecord.query(on: db).filter(\.$businessId == businessId.uuid)
            .filter(\.$active == true).all().filter { $0.events.split(separator: ",").contains { Substring(type.rawValue) == $0 } }
        guard !subscriptions.isEmpty else { return }
        let now = ctx.now
        let data = try ViadereJSON.decode(JSONValue.self, from: ViadereJSON.encode(payload))
        for subscription in subscriptions {
            let id = WebhookDeliveryID()
            let event = WebhookEvent(id: id, type: type, createdAt: now, businessId: businessId, data: data)
            let delivery = WebhookDeliveryRecord()
            delivery.id = id.uuid
            delivery.subscriptionId = subscription.id!
            delivery.businessId = businessId.uuid
            delivery.eventType = type.rawValue
            // The body can contain a consumer's message text: encrypted at rest (bound to this row) and purged after the retention window.
            delivery.body = try ctx.cipher.seal(try ViadereJSON.encode(event), context: "webhook_deliveries.body", rowId: delivery.id!)
            delivery.status = "pending"
            delivery.attempts = 0
            delivery.nextAttemptAt = now
            delivery.createdAt = now
            try await delivery.create(on: db)
        }
    }

    // MARK: Bodies at rest

    /// The exact body bytes of a delivery. Rows written before bodies were encrypted hold plaintext JSON; they are read as-is.
    func deliveryBody(_ delivery: WebhookDeliveryRecord) -> Data? {
        if delivery.body.hasPrefix("v1.") || delivery.body.hasPrefix("v2.") {
            return try? ctx.cipher.open(delivery.body, context: "webhook_deliveries.body", rowId: delivery.id!)
        }
        return Data(delivery.body.utf8)
    }

    /// Account deletion: replaces the body of every delivery that mentions this consumer's relationships, sessions or interactions.
    func scrubDeliveries(forConsumer consumer: UUID) async throws {
        var needles: [String] = []
        needles += try await RelationshipRecord.query(on: db).filter(\.$consumerId == consumer).all().compactMap { $0.id?.uuidString.lowercased() }
        needles += try await ConversationSessionRecord.query(on: db).filter(\.$consumerId == consumer).all().compactMap { $0.id?.uuidString.lowercased() }
        needles += try await InteractionRecord.query(on: db).filter(\.$consumerId == consumer).all().compactMap { $0.id?.uuidString.lowercased() }
        guard !needles.isEmpty else { return }
        let businesses = Set(try await RelationshipRecord.query(on: db).filter(\.$consumerId == consumer).all().map(\.businessId))
        // Only events that carry what the person wrote or decided; lifecycle events hold opaque ids and stay deliverable.
        let carrying = [WebhookEventType.messageReceived, .interactionDecided].map(\.rawValue)
        for delivery in try await WebhookDeliveryRecord.query(on: db).filter(\.$businessId ~~ Array(businesses)).filter(\.$eventType ~~ carrying).all() {
            guard let data = deliveryBody(delivery), let text = String(data: data, encoding: .utf8), needles.contains(where: { text.contains($0) }) else { continue }
            delivery.body = try ctx.cipher.seal(Data(#"{"erased":true}"#.utf8), context: "webhook_deliveries.body", rowId: delivery.id!)
            if ["pending", "sending"].contains(delivery.status) { delivery.status = "dead"; delivery.lastError = "account_deleted" }
            try await delivery.update(on: db)
        }
    }

    // MARK: Delivery

    /// Attempts every due delivery once. Returns the number of attempts made.
    @discardableResult
    func deliverDue(limit: Int = 50) async throws -> Int {
        let now = ctx.now
        let due = try await WebhookDeliveryRecord.query(on: db)
            .group(.or) { group in
                group.filter(\.$status == "pending")
                group.filter(\.$status == "sending")
            }
            .filter(\.$nextAttemptAt <= now).sort(\.$nextAttemptAt, .ascending).limit(limit).all()
        var attempted = 0
        for delivery in due {
            guard let id = delivery.id else { continue }
            // Claim by compare-and-swap on the attempt counter (one winner even when a stale lease is reclaimed),
            // then hold a 60 s lease; a crashed worker's claim becomes due again automatically.
            let claimed = try await DB.swap(db, table: WebhookDeliveryRecord.schema, id: id, column: "attempts",
                                            expected: delivery.attempts, newValue: delivery.attempts + 1)
            guard claimed else { continue }
            delivery.attempts += 1
            delivery.status = "sending"
            delivery.nextAttemptAt = now.addingTimeInterval(60)
            try await delivery.update(on: db)
            try await attempt(delivery, now: now)
            attempted += 1
        }
        return attempted
    }

    private func attempt(_ delivery: WebhookDeliveryRecord, now: Date) async throws {
        guard let id = delivery.id,
              let subscription = try await WebhookSubscriptionRecord.find(delivery.subscriptionId, on: db), subscription.active,
              let url = URL(string: subscription.url) else {
            delivery.status = "dead"
            delivery.lastError = "subscription_inactive"
            try await delivery.update(on: db)
            return
        }
        guard let body = deliveryBody(delivery) else {
            delivery.status = "dead"
            delivery.lastError = "body_unavailable"
            try await delivery.update(on: db)
            return
        }
        var secrets: [String] = []
        if let current = try? ctx.cipher.openString(subscription.secretCiphertext, context: "webhook_subscriptions.secret", rowId: subscription.id!) {
            secrets.append(current)
        }
        if let previous = subscription.previousSecretCiphertext, let expires = subscription.previousSecretExpiresAt, expires > now,
           let value = try? ctx.cipher.openString(previous, context: "webhook_subscriptions.secret", rowId: subscription.id!) {
            secrets.append(value)
        }
        let started = Date()
        var statusCode: Int?
        var errorText: String?
        if secrets.isEmpty {
            errorText = "secret_unavailable"
        } else {
            let request = WebhookHTTPRequest(url: url, headers: [
                "Content-Type": "application/json",
                "User-Agent": "Viadere-Webhooks/1",
                ViadereHeader.signature: WebhookSignature.header(secrets: secrets, body: body, now: now),
                ViadereHeader.eventId: id.uuidString.lowercased(),
                ViadereHeader.eventType: delivery.eventType,
            ], body: body)
            do {
                statusCode = try await ctx.webhookTransport.send(request).statusCode
            } catch {
                errorText = (error as? WebhookTransportError) == .blockedDestination ? "blocked_destination" : "network_error"
            }
        }
        let duration = Int(Date().timeIntervalSince(started) * 1000)
        delivery.lastStatusCode = statusCode
        let success = statusCode.map { (200..<300).contains($0) } ?? false
        if success {
            delivery.status = "succeeded"
            delivery.deliveredAt = now
            delivery.lastError = nil
        } else {
            delivery.lastError = errorText ?? "http_\(statusCode ?? 0)"
            if errorText == "blocked_destination" || delivery.attempts >= Self.maxAttempts {
                delivery.status = "dead" // dead-letter: kept for inspection, never retried automatically
            } else {
                delivery.status = "pending"
                delivery.nextAttemptAt = now.addingTimeInterval(Self.backoff[min(delivery.attempts - 1, Self.backoff.count - 1)])
            }
        }
        try await delivery.update(on: db)
        let attemptRecord = WebhookAttemptRecord()
        attemptRecord.id = UUID()
        attemptRecord.deliveryId = id
        attemptRecord.attempt = delivery.attempts
        attemptRecord.attemptedAt = now
        attemptRecord.statusCode = statusCode
        attemptRecord.durationMs = duration
        attemptRecord.error = success ? nil : delivery.lastError
        try await attemptRecord.create(on: db)
        if delivery.status == "dead" {
            _ = try await AuditService(db: db, ctx: ctx).record("webhook.dead_lettered", outcome: .failure,
                actor: AuditActor(kind: .system), businessId: BusinessID(delivery.businessId), subjectType: "webhook_delivery",
                subjectId: id.uuidString.lowercased(), metadata: ["event_type": delivery.eventType, "attempts_made": String(delivery.attempts)])
        }
    }
}
