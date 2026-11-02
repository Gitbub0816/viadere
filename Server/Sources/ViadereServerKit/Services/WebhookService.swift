import Fluent
import Foundation
import ViadereCore

/// Webhook subscription management, event enqueueing and signed delivery with retry/dead-letter handling.
struct WebhookService {
    let db: any Database
    let ctx: ServerContext

    static let maxSubscriptionsPerBusiness = 10
    static let maxAttempts = WebhookRetrySchedule.maxAttempts
    /// Delay before retry N (seconds): 30 s, 2 min, 10 min, 1 h, 6 h, 12 h, 24 h. One table in Core: the receivers' dedup horizon is derived from it (ADR-0025).
    static let backoff: [TimeInterval] = WebhookRetrySchedule.backoff
    static let knownEvents: [WebhookEventType] = [
        .interactionDecided, .interactionExpired, .interactionCancelled, .messageReceived, .relationshipConnected,
        .relationshipDisconnected, .consentUpdated, .rewardRedeemed, .verificationCompleted,
        .approveEnrollmentDeviceCompleted, .approveEnrollmentConfirmed, .approveKeyRevoked, .approveRequestDecided, .approveRequestExpired, .approveFrozen,
        .linkCompleted, .linkExpired, .profileAccessGranted, .profileAccessRevoked, .profileRequestExpired,
    ] + WebhookEventType.authEvents
    static let rotationOverlap: TimeInterval = 24 * 3600

    // MARK: Subscriptions

    func dto(_ record: WebhookSubscriptionRecord) -> WebhookSubscription? {
        guard let id = record.id, let url = URL(string: record.url) else { return nil }
        return WebhookSubscription(id: WebhookSubscriptionID(id), url: url,
                                   events: record.events.split(separator: ",").map { WebhookEventType(rawValue: String($0)) },
                                   active: record.active, createdAt: record.createdAt, envelopeVersion: record.envelopeVersion,
                                   secretVersion: record.secretVersion, verifiedAt: record.verifiedAt, pausedAt: record.pausedAt,
                                   signatureVersion: WebhookSignatureVersion(rawValue: record.signatureVersion) ?? .v1)
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
        guard !events.isEmpty, events.count <= 24, events.allSatisfy({ e in Self.knownEvents.contains { $0.rawValue == e } }) else {
            throw APIError.validation("Unknown or missing event types.", details: ["events": "invalid"])
        }
        // The opaque v2 envelope (spec 14.3) carries no payload, so a v2 subscription may only ask for events that have an opaque form.
        if let version = request.envelopeVersion {
            guard version == WebhookEnvelopeV2.version else {
                throw APIError.validation("Unknown envelope version.", details: ["envelopeVersion": "invalid"])
            }
            guard events.allSatisfy({ e in WebhookEventType.opaqueEvents.contains { $0.rawValue == e } }) else {
                throw APIError.validation("The opaque envelope supports only approval and interaction events.", details: ["events": "invalid"])
            }
        }
        // `auth.*` events exist only with signature v2 and the opaque envelope (ADR-0025 section 3): they never carry a `v1=` entry and have no v1 body.
        let signatureVersion = request.signatureVersion ?? .v1
        if events.contains(where: { $0.hasPrefix("auth.") }) {
            guard signatureVersion == .v2, request.envelopeVersion == WebhookEnvelopeV2.version else {
                throw APIError(.unprocessableEntity, .signatureVersionRequired, "auth.* events need signature_version v2 and the opaque envelope (envelopeVersion 2026-10-27).",
                               details: ["events": "signature_version_required"])
            }
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
        record.envelopeVersion = request.envelopeVersion
        record.signatureVersion = signatureVersion.rawValue
        record.secretVersion = 1
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
        record.secretVersion += 1
        try await record.update(on: db)
        guard let subscription = dto(record) else { throw APIError.internalError }
        _ = try await AuditService(db: db, ctx: ctx).record("webhook.rotated", actor: AuditActor(kind: .business, id: businessId.description),
                                                           businessId: businessId, subjectType: "webhook", subjectId: id.description)
        return WebhookSecretResponse(subscription: subscription, secret: secret)
    }

    // MARK: Enqueue

    /// Queues one delivery per matching active subscription. Runs inside the caller's transaction so an
    /// event is queued if and only if the state change it describes committed.
    /// `onlySubscription` limits delivery to one registered endpoint (a verification request's `callback_id`).
    ///
    /// `opaque` is the event's opaque form (spec 14.3: ids and a `result_ref`, no payload). Subscriptions that opted into the v2 envelope
    /// receive **only** events that provide one; every other subscription receives the v1 `WebhookEvent` with the payload.
    func enqueue<T: Encodable>(_ type: WebhookEventType, businessId: BusinessID, payload: T, onlySubscription: UUID? = nil,
                               opaque: OpaqueWebhookEvent? = nil) async throws {
        let subscriptions = try await WebhookSubscriptionRecord.query(on: db).filter(\.$businessId == businessId.uuid)
            .filter(\.$active == true).all().filter { onlySubscription == nil || $0.id == onlySubscription }
            .filter { $0.events.split(separator: ",").contains { Substring(type.rawValue) == $0 } }
            // `auth.*` events go only to v2-signed endpoints that use the opaque envelope, even if a row somehow names them (ST-WH-03).
            .filter { !type.isAuthEvent || ($0.signatureVersion == WebhookSignatureVersion.v2.rawValue && $0.envelopeVersion == WebhookEnvelopeV2.version) }
            // Ownership of the endpoint must be proven before it receives events (SEC-API-006); the check cannot be switched off in production.
            .filter { !ctx.config.operations.webhookOwnershipVerification || $0.verifiedAt != nil }
        guard !subscriptions.isEmpty else { return }
        let now = ctx.now
        let data = try ViadereJSON.decode(JSONValue.self, from: ViadereJSON.encode(payload))
        for subscription in subscriptions {
            let id = WebhookDeliveryID()
            let body: Data
            if subscription.envelopeVersion == WebhookEnvelopeV2.version {
                guard let opaque else { continue }
                body = try ViadereJSON.encode(WebhookEnvelopeV2(id: "evt_" + id.uuid.uuidString.lowercased(), type: type.rawValue, tenantId: tenantId(of: businessId),
                                                                requestId: opaque.requestId, occurredAt: now, resultRef: opaque.resultRef))
            } else {
                body = try ViadereJSON.encode(WebhookEvent(id: id, type: type, createdAt: now, businessId: businessId, data: data))
            }
            let delivery = WebhookDeliveryRecord()
            delivery.id = id.uuid
            delivery.subscriptionId = subscription.id!
            delivery.businessId = businessId.uuid
            delivery.eventType = type.rawValue
            // The body can contain a consumer's message text: encrypted at rest (bound to this row) and purged after the retention window.
            delivery.body = try ctx.cipher.seal(body, context: "webhook_deliveries.body", rowId: delivery.id!)
            delivery.status = "pending"
            delivery.attempts = 0
            delivery.nextAttemptAt = now
            delivery.createdAt = now
            try await db.transaction { [ctx] tx in
                try await delivery.create(on: tx)
                try await Outbox.enqueue(QueueHandlers.webhookDeliver, ref: delivery.id!, tenant: delivery.businessId, on: tx, ctx: ctx)
            }
        }
    }

    /// The business's opaque tenant identifier in v2 envelopes: stable per business, not derivable from the business id without the server pepper.
    func tenantId(of businessId: BusinessID) -> String { "ten_" + String(ctx.hasher.hmacHex("tenant-id", businessId.description).prefix(32)) }

    /// The versioned id of the key that signs a subscription's deliveries (SEC-API-006): `whk_{first 8 of the subscription id}_v{secret version}`.
    static func keyId(subscription: WebhookSubscriptionRecord) -> String {
        "whk_" + String((subscription.id?.uuidString.lowercased() ?? "").prefix(8)) + "_v\(subscription.secretVersion)"
    }

    // MARK: Bodies at rest

    /// The exact body bytes of a delivery. Rows written before bodies were encrypted hold plaintext JSON; they are read as-is.
    func storedBody(_ delivery: WebhookDeliveryRecord) -> Data? {
        if FieldCipher.isSealed(delivery.body) {
            return try? ctx.cipher.open(delivery.body, context: "webhook_deliveries.body", rowId: delivery.id!)
        }
        return Data(delivery.body.utf8)
    }

    func deliveryBody(_ delivery: WebhookDeliveryRecord) -> Data? {
        let raw = storedBody(delivery)
        // Deliveries queued before businesses stopped receiving the raw signed decision can still hold it (it names the global device
        // id). Whatever is queued is stripped on the way out, so a deploy never sends one.
        guard let raw, delivery.eventType == WebhookEventType.interactionDecided.rawValue else { return raw }
        return Self.strippingSignedDecision(raw) ?? raw
    }

    /// The event body without `data.signedDecision`; `nil` when there is nothing to strip (or the body is not an event).
    static func strippingSignedDecision(_ body: Data) -> Data? {
        guard var event = try? ViadereJSON.decode(JSONValue.self, from: body), case .object(var members) = event,
              case .object(var data)? = members["data"], data["signedDecision"] != nil else { return nil }
        data.removeValue(forKey: "signedDecision")
        members["data"] = .object(data)
        event = .object(members)
        return try? ViadereJSON.encode(event)
    }

    /// Account deletion: replaces the body of every delivery that mentions this consumer's relationships, sessions or interactions.
    func scrubDeliveries(forConsumer consumer: UUID) async throws {
        var needles: [String] = []
        needles += try await RelationshipRecord.query(on: db).filter(\.$consumerId == consumer).all().compactMap { $0.id?.uuidString.lowercased() }
        needles += try await ConversationSessionRecord.query(on: db).filter(\.$consumerId == consumer).all().compactMap { $0.id?.uuidString.lowercased() }
        needles += try await InteractionRecord.query(on: db).filter(\.$consumerId == consumer).all().compactMap { $0.id?.uuidString.lowercased() }
        guard !needles.isEmpty else { return }
        let businesses = Set(try await RelationshipRecord.query(on: db).filter(\.$consumerId == consumer).all().map(\.businessId))
        // Only events that carry what the person wrote or decided, or their public name (`relationship.connected`); other lifecycle events hold opaque ids.
        let carrying = [WebhookEventType.messageReceived, .interactionDecided, .relationshipConnected].map(\.rawValue)
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
        // Paused endpoints and businesses (G-5) keep their queued deliveries; nothing is sent until the pause is lifted. They are excluded in
        // the query so a long pause cannot starve the other tenants out of the batch.
        let pausedEndpoints = try await WebhookSubscriptionRecord.query(on: db).filter(\.$pausedAt != nil).all().compactMap(\.id)
        var pausedBusinesses = try await PlatformFlagRecord.query(on: db).filter(\.$flag == PlatformFlag.webhooksPause.rawValue).all()
        if pausedBusinesses.contains(where: { $0.scope == PlatformFlags.globalScope }) { return 0 }
        pausedBusinesses = pausedBusinesses.filter { $0.scope != PlatformFlags.globalScope }
        let pausedBusinessIds = pausedBusinesses.compactMap { UUID(uuidString: $0.scope) }
        var query = WebhookDeliveryRecord.query(on: db)
            .group(.or) { group in
                group.filter(\.$status == "pending")
                group.filter(\.$status == "sending")
            }
            .filter(\.$nextAttemptAt <= now)
        if !pausedEndpoints.isEmpty { query = query.filter(\.$subscriptionId !~ pausedEndpoints) }
        if !pausedBusinessIds.isEmpty { query = query.filter(\.$businessId !~ pausedBusinessIds) }
        let due = try await query.sort(\.$nextAttemptAt, .ascending).limit(limit).all()
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

    func attempt(_ delivery: WebhookDeliveryRecord, now: Date) async throws {
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
        var keyed: [(kid: String, secret: String)] = []
        let prefix = "whk_" + String((subscription.id?.uuidString.lowercased() ?? "").prefix(8))
        if let current = try? ctx.cipher.openString(subscription.secretCiphertext, context: "webhook_subscriptions.secret", rowId: subscription.id!) {
            secrets.append(current)
            keyed.append((Self.keyId(subscription: subscription), current))
        }
        if let previous = subscription.previousSecretCiphertext, let expires = subscription.previousSecretExpiresAt, expires > now,
           let value = try? ctx.cipher.openString(previous, context: "webhook_subscriptions.secret", rowId: subscription.id!) {
            secrets.append(value)
            keyed.append(("\(prefix)_v\(max(subscription.secretVersion - 1, 0))", value))
        }
        let started = Date()
        var statusCode: Int?
        var errorText: String?
        if secrets.isEmpty {
            errorText = "secret_unavailable"
        } else {
            var headers: [String: String] = [
                "Content-Type": "application/json",
                "User-Agent": "Viadere-Webhooks/1",
                ViadereHeader.signature: WebhookSignature.header(secrets: secrets, body: body, now: now),
                ViadereHeader.eventId: subscription.envelopeVersion == WebhookEnvelopeV2.version ? "evt_" + id.uuidString.lowercased() : id.uuidString.lowercased(),
                ViadereHeader.eventType: delivery.eventType,
                ViadereHeader.deliveryId: id.uuidString.lowercased(),
                ViadereHeader.keyId: Self.keyId(subscription: subscription),
                ViadereHeader.webhookVersion: subscription.envelopeVersion ?? "v1",
            ]
            var signable = true
            if subscription.signatureVersion == WebhookSignatureVersion.v2.rawValue {
                // Signature v2 (ADR-0025): method, host, path, timestamp, event id, tenant, key id and body digest. Event id and tenant travel as headers and are signed.
                let tenant = tenantId(of: BusinessID(delivery.businessId))
                let eventId = "evt_" + id.uuidString.lowercased()
                // `auth.*` events never carry a `v1=` entry; other events do for 30 days after the switch, so receivers can deploy the new verifier first.
                let dual = !delivery.eventType.hasPrefix("auth.") && (subscription.v2DualUntil.map { $0 > now } ?? false)
                if let context = WebhookSignatureV2.Context(endpoint: url, eventId: eventId, tenantId: tenant),
                   let header = WebhookSignatureV2.header(secrets: keyed, context: context, body: body, now: now, legacySecret: dual ? secrets.first : nil) {
                    headers[ViadereHeader.signature] = header
                    headers[ViadereHeader.eventId] = eventId
                    headers[ViadereHeader.tenant] = tenant
                    headers[ViadereHeader.contentDigest] = WebhookSignatureV2.contentDigest(body)
                } else {
                    signable = false
                }
            } else if delivery.eventType.hasPrefix("auth.") {
                // Defense in depth: a v1 subscription never receives an `auth.*` event.
                signable = false
            }
            if signable {
                do {
                    statusCode = try await ctx.webhookTransport.send(WebhookHTTPRequest(url: url, headers: headers, body: body)).statusCode
                } catch {
                    errorText = (error as? WebhookTransportError) == .blockedDestination ? "blocked_destination" : "network_error"
                }
            } else {
                errorText = "signature_unavailable"
            }
        }
        let duration = Int(Date().timeIntervalSince(started) * 1000)
        delivery.lastStatusCode = statusCode
        let success = statusCode.map { (200..<300).contains($0) } ?? false
        if success {
            delivery.status = "succeeded"
            delivery.deliveredAt = now
            delivery.lastError = nil
            // A delivered test event completes the "test event" step of onboarding.
            if delivery.eventType == WebhookEventType.test.rawValue {
                try? await OnboardingService(db: db, ctx: ctx).testEventSent(businessId: delivery.businessId)
            }
        } else {
            delivery.lastError = errorText ?? "http_\(statusCode ?? 0)"
            if errorText == "blocked_destination" || errorText == "signature_unavailable" || delivery.attempts >= Self.maxAttempts {
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
            ctx.metrics.count(.webhookDeadLettered)
            _ = try await AuditService(db: db, ctx: ctx).record("webhook.dead_lettered", outcome: .failure,
                actor: AuditActor(kind: .system), businessId: BusinessID(delivery.businessId), subjectType: "webhook_delivery",
                subjectId: id.uuidString.lowercased(), metadata: ["event_type": delivery.eventType, "attempts_made": String(delivery.attempts)])
        }
    }
}

extension WebhookService {
    /// `PATCH /v1/business/webhooks/{id}` (ADR-0025 M1): moves an endpoint to signature `v2`. There is no way back. For 30 days the pre-existing event types are
    /// signed with both `v2=` and `v1=` so the receiver can deploy the new verifier first; `auth.*` events are v2-only from the start.
    func moveToV2(businessId: BusinessID, id: WebhookSubscriptionID) async throws -> WebhookSubscription {
        guard let record = try await WebhookSubscriptionRecord.query(on: db).filter(\.$id == id.uuid).filter(\.$businessId == businessId.uuid)
            .filter(\.$active == true).first() else { throw APIError.notFound }
        if record.signatureVersion != WebhookSignatureVersion.v2.rawValue {
            record.signatureVersion = WebhookSignatureVersion.v2.rawValue
            record.v2DualUntil = ctx.now.addingTimeInterval(30 * 86_400)
            try await record.update(on: db)
            _ = try await AuditService(db: db, ctx: ctx).record("webhook.signature_v2", actor: AuditActor(kind: .business, id: businessId.description),
                                                               businessId: businessId, subjectType: "webhook", subjectId: id.description)
        }
        guard let subscription = dto(record) else { throw APIError.internalError }
        return subscription
    }

    /// `POST /v1/business/webhooks/test` (test keys only): a signed sample `auth.delivery.*` event with fixed sample ids, sent to one of the business's own v2
    /// endpoints through the ordinary delivery path (same signature, headers and retry rules).
    func enqueueAuthSample(businessId: BusinessID, subscriptionId: WebhookSubscriptionID, type: WebhookEventType) async throws -> String {
        guard type.isAuthEvent, WebhookEventType.authEvents.contains(type),
              let subscription = try await WebhookSubscriptionRecord.query(on: db).filter(\.$id == subscriptionId.uuid).filter(\.$businessId == businessId.uuid)
                  .filter(\.$active == true).first(),
              subscription.signatureVersion == WebhookSignatureVersion.v2.rawValue, subscription.envelopeVersion == WebhookEnvelopeV2.version else {
            throw APIError.notFound
        }
        // The same gates as `sendTestEvent` (SEC-API-006): a sample never goes to an endpoint whose ownership is unproven, nor to a paused one, and is rate limited.
        if ctx.config.operations.webhookOwnershipVerification, subscription.verifiedAt == nil {
            throw APIError.conflict("Verify the endpoint before sending events to it.")
        }
        guard subscription.pausedAt == nil else { throw APIError.conflict("This endpoint is paused.") }
        guard await ctx.limiter.allow("webhook-test", key: subscriptionId.description, rule: .perMinute(10, burst: 5)) else { throw APIError.rateLimited(retryAfter: 30) }
        let delivery = WebhookDeliveryRecord()
        delivery.id = UUID()
        let eventId = "evt_" + delivery.id!.uuidString.lowercased()
        // Fixed sample ids: the all-zero delivery id.
        let body = try ViadereJSON.encode(WebhookEnvelopeV2(id: eventId, type: type.rawValue, tenantId: tenantId(of: businessId),
                                                            requestId: AuthDeliveryID(UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))).description,
                                                            occurredAt: ctx.now, resultRef: nil))
        delivery.subscriptionId = subscription.id!
        delivery.businessId = businessId.uuid
        delivery.eventType = type.rawValue
        delivery.body = try ctx.cipher.seal(body, context: "webhook_deliveries.body", rowId: delivery.id!)
        delivery.status = "pending"
        delivery.attempts = 0
        delivery.nextAttemptAt = ctx.now
        delivery.createdAt = ctx.now
        try await db.transaction { [ctx] tx in
            try await delivery.create(on: tx)
            try await Outbox.enqueue(QueueHandlers.webhookDeliver, ref: delivery.id!, tenant: delivery.businessId, on: tx, ctx: ctx)
        }
        return eventId
    }
}

/// The opaque form of a webhook event (spec 14.3): what a v2 subscription receives instead of the payload.
struct OpaqueWebhookEvent: Sendable {
    /// The request the event is about (a business request id, an enrollment id, or a `subject_ref` for a freeze).
    var requestId: String
    /// Where to fetch the result with the business's own credentials, when there is one.
    var resultRef: String?
}
