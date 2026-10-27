import Fluent
import Foundation
import ViadereCore

extension WebhookEventType {
    /// Sent by "Send test event"; delivered like any event (signed, with a delivery id and key id) to one endpoint.
    static let test = WebhookEventType(rawValue: "webhook.test")
    /// The ownership challenge. Not a subscribable event.
    static let verification = WebhookEventType(rawValue: "webhook.verification")
}

/// Endpoint ownership, pause, test events, retry simulation and schema preview (SEC-API-006, spec §9.3, ops gap G-5).
extension WebhookService {
    static let challengeTTL: TimeInterval = 10 * 60
    static let verifyAttemptsPerHour: Double = 6

    // MARK: Ownership verification

    struct VerificationResult: Equatable {
        var verified: Bool
        /// `nil` when verified; otherwise `no_echo`, `http_<status>` or `unreachable`.
        var failure: String?
    }

    /// Proves that whoever registered the URL controls it: we POST a random single-use challenge (signed like any delivery) and the endpoint must
    /// answer 2xx and echo the challenge, as JSON `{"challenge": "..."}` or as the bare body. Until then it receives no events. The challenge is
    /// stored only as a hash and expires in ten minutes; each attempt uses a fresh one, so an old response can never verify a later attempt.
    func verifyOwnership(businessId: BusinessID, id: WebhookSubscriptionID) async throws -> VerificationResult {
        guard let record = try await WebhookSubscriptionRecord.query(on: db).filter(\.$id == id.uuid).filter(\.$businessId == businessId.uuid)
            .filter(\.$active == true).first(), let url = URL(string: record.url) else { throw APIError.notFound }
        if record.verifiedAt != nil { return VerificationResult(verified: true, failure: nil) }
        guard await ctx.limiter.allow("webhook-verify", key: id.description, rule: .perHour(Self.verifyAttemptsPerHour, burst: Self.verifyAttemptsPerHour)) else {
            throw APIError.rateLimited(retryAfter: 600)
        }
        let now = ctx.now
        let challenge = SecureToken.generate(byteCount: 32)
        record.verificationChallengeHash = SecureToken.hash(challenge)
        record.verificationExpiresAt = now.addingTimeInterval(Self.challengeTTL)
        try await record.update(on: db)
        var secret = ""
        if let opened = try? ctx.cipher.openString(record.secretCiphertext, context: "webhook_subscriptions.secret", rowId: record.id!) { secret = opened }
        let body = try ViadereJSON.encode(["type": WebhookEventType.verification.rawValue, "challenge": challenge, "endpointId": id.description])
        let request = WebhookHTTPRequest(url: url, headers: [
            "Content-Type": "application/json",
            "User-Agent": "Viadere-Webhooks/1",
            ViadereHeader.signature: WebhookSignature.header(secrets: [secret], body: body, now: now),
            ViadereHeader.eventType: WebhookEventType.verification.rawValue,
            ViadereHeader.keyId: Self.keyId(subscription: record),
            ViadereHeader.webhookVersion: record.envelopeVersion ?? "v1",
        ], body: body)
        var failure: String?
        do {
            let response = try await ctx.webhookTransport.send(request)
            if !(200..<300).contains(response.statusCode) {
                failure = "http_\(response.statusCode)"
            } else if !Self.echoes(challenge: challenge, body: response.body, expectedHash: record.verificationChallengeHash ?? "") {
                failure = "no_echo"
            }
        } catch {
            failure = "unreachable"
        }
        // Single use: whatever happened, this challenge is spent.
        record.verificationChallengeHash = nil
        record.verificationExpiresAt = nil
        record.lastVerifyError = failure
        if failure == nil { record.verifiedAt = ctx.now }
        try await record.update(on: db)
        if failure != nil { ctx.metrics.count(.webhookVerifyFailed) }
        _ = try await AuditService(db: db, ctx: ctx).record(failure == nil ? "webhook.verified" : "webhook.verification_failed", outcome: failure == nil ? .success : .failure,
            actor: AuditActor(kind: .business, id: businessId.description), businessId: businessId, subjectType: "webhook", subjectId: id.description,
            metadata: failure.map { ["reason": $0] } ?? [:])
        return VerificationResult(verified: failure == nil, failure: failure)
    }

    /// The response must contain the challenge (bare, or as the `challenge` member of a JSON object). Compared via the stored hash, in constant time.
    static func echoes(challenge: String, body: Data, expectedHash: String) -> Bool {
        var candidates = [String(decoding: body, as: UTF8.self).trimmingCharacters(in: .whitespacesAndNewlines)]
        if let object = try? JSONDecoder().decode([String: String].self, from: body), let echoed = object["challenge"] { candidates.append(echoed) }
        return candidates.contains { !$0.isEmpty && SecureToken.matches($0, hash: expectedHash) }
    }

    // MARK: Pause (G-5)

    /// Pauses or resumes one endpoint. Queued deliveries stay queued; they are sent after a resume or expire with the retention window.
    func setPaused(businessId: BusinessID, id: WebhookSubscriptionID, paused: Bool, reason: String, actor: AuditActor) async throws {
        guard let record = try await WebhookSubscriptionRecord.query(on: db).filter(\.$id == id.uuid).filter(\.$businessId == businessId.uuid).first() else { throw APIError.notFound }
        guard (record.pausedAt != nil) != paused else { return }
        record.pausedAt = paused ? ctx.now : nil
        record.pausedBy = paused ? actor.id : nil
        record.pauseReason = paused ? String(reason.prefix(200)) : nil
        try await record.update(on: db)
        if paused { ctx.metrics.count(.webhookPaused) }
        _ = try await AuditService(db: db, ctx: ctx).record(paused ? "webhook.paused" : "webhook.resumed", actor: actor, businessId: businessId, subjectType: "webhook",
            subjectId: id.description, metadata: paused ? ["reason": String(reason.prefix(200))] : [:])
    }

    // MARK: Test events

    /// Queues a signed `webhook.test` event for one endpoint. It is delivered by the normal worker (signature, delivery id, key id, retries),
    /// so a receiver exercises exactly the path real events take.
    @discardableResult
    func sendTestEvent(businessId: BusinessID, id: WebhookSubscriptionID) async throws -> UUID {
        guard let record = try await WebhookSubscriptionRecord.query(on: db).filter(\.$id == id.uuid).filter(\.$businessId == businessId.uuid)
            .filter(\.$active == true).first() else { throw APIError.notFound }
        if ctx.config.operations.webhookOwnershipVerification, record.verifiedAt == nil {
            throw APIError.conflict("Verify the endpoint before sending events to it.")
        }
        guard record.pausedAt == nil else { throw APIError.conflict("This endpoint is paused.") }
        guard await ctx.limiter.allow("webhook-test", key: id.description, rule: .perMinute(10, burst: 5)) else { throw APIError.rateLimited(retryAfter: 30) }
        let now = ctx.now
        let deliveryId = WebhookDeliveryID()
        let payload = WebhookTestPayload(message: "This is a test event from Viadere. No customer data is included.", endpointId: id.description)
        let body: Data
        if record.envelopeVersion == WebhookEnvelopeV2.version {
            body = try ViadereJSON.encode(WebhookEnvelopeV2(id: "evt_" + deliveryId.uuid.uuidString.lowercased(), type: WebhookEventType.test.rawValue,
                                                            tenantId: tenantId(of: businessId), requestId: "test-" + deliveryId.uuid.uuidString.lowercased(), occurredAt: now, resultRef: nil))
        } else {
            body = try ViadereJSON.encode(WebhookEvent(id: deliveryId, type: .test, createdAt: now, businessId: businessId,
                                                      data: try ViadereJSON.decode(JSONValue.self, from: ViadereJSON.encode(payload))))
        }
        let delivery = WebhookDeliveryRecord()
        delivery.id = deliveryId.uuid
        delivery.subscriptionId = id.uuid
        delivery.businessId = businessId.uuid
        delivery.eventType = WebhookEventType.test.rawValue
        delivery.body = try ctx.cipher.seal(body, context: "webhook_deliveries.body", rowId: delivery.id!)
        delivery.status = "pending"
        delivery.attempts = 0
        delivery.nextAttemptAt = now
        delivery.createdAt = now
        try await delivery.create(on: db)
        _ = try await AuditService(db: db, ctx: ctx).record("webhook.test_sent", actor: AuditActor(kind: .business, id: businessId.description), businessId: businessId,
            subjectType: "webhook", subjectId: id.description)
        return delivery.id!
    }

    /// A simulated customer reply (`message.received`) from the business's sandbox customer, delivered to the verified, unpaused endpoints that
    /// subscribed to it. Sandbox only: it needs a test relationship and writes no message.
    func simulateReply(businessId: BusinessID, relationshipId: UUID, text: String) async throws {
        guard let relationship = try await RelationshipRecord.query(on: db).filter(\.$id == relationshipId).filter(\.$businessId == businessId.uuid).first(),
              let consumer = try await ConsumerRecord.find(relationship.consumerId, on: db), consumer.isSandbox else { throw APIError.notFound }
        let clean = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (1...280).contains(clean.count) else { throw APIError.validation("Write a reply of up to 280 characters.", details: ["text": "invalid"]) }
        try await enqueue(.messageReceived, businessId: businessId,
                          payload: MessageReceivedPayload(sessionId: SessionID(UUID()), relationshipId: RelationshipID(relationshipId),
                                                          subjectRef: ctx.subjects.subjectRef(businessId: businessId, consumerId: ConsumerID(relationship.consumerId)),
                                                          messageId: MessageID(UUID()), text: clean, channel: .inApp, receivedAt: ctx.now))
        try await OnboardingService(db: db, ctx: ctx).testEventSent(businessId: businessId.uuid)
        _ = try await AuditService(db: db, ctx: ctx).record("webhook.sandbox_reply_simulated", actor: AuditActor(kind: .business, id: businessId.description),
            businessId: businessId, subjectType: "relationship", subjectId: relationshipId.uuidString.lowercased())
    }
}

struct WebhookTestPayload: Codable, Sendable {
    var message: String
    var endpointId: String
}

/// Retry simulation (spec §9.3): the schedule a delivery follows if the endpoint fails N times, computed from the real backoff table. Nothing is sent.
enum WebhookRetrySimulation {
    struct Step: Equatable {
        var attempt: Int
        var at: Date
        var outcome: String
    }

    /// `failures` consecutive failures then (if attempts remain) a success.
    static func plan(failures: Int, from start: Date, maxAttempts: Int = WebhookService.maxAttempts, backoff: [TimeInterval] = WebhookService.backoff) -> [Step] {
        var steps: [Step] = []
        var at = start
        let failures = max(0, min(failures, maxAttempts))
        for attempt in 1...maxAttempts {
            if attempt > failures {
                steps.append(Step(attempt: attempt, at: at, outcome: "succeeds: the delivery is complete"))
                return steps
            }
            if attempt == maxAttempts {
                steps.append(Step(attempt: attempt, at: at, outcome: "fails: moved to the dead-letter queue (replay it from the delivery log)"))
                return steps
            }
            steps.append(Step(attempt: attempt, at: at, outcome: "fails: retry in \(Int(backoff[min(attempt - 1, backoff.count - 1)])) s"))
            at = at.addingTimeInterval(backoff[min(attempt - 1, backoff.count - 1)])
        }
        return steps
    }
}

/// Example bodies for every event a business can subscribe to, built from the real types where one exists.
enum WebhookSchemaPreview {
    struct Sample {
        var type: String
        var json: String
    }

    static func samples(now: Date) -> [Sample] {
        func event(_ type: WebhookEventType, _ data: JSONValue) -> String {
            let e = WebhookEvent(id: WebhookDeliveryID(UUID(uuidString: "00000000-0000-4000-8000-0000000000e1")!), type: type, createdAt: now,
                                 businessId: BusinessID(UUID(uuidString: "00000000-0000-4000-8000-0000000000b1")!), data: data)
            return pretty(e)
        }
        let id = "00000000-0000-4000-8000-000000000001"
        return [
            Sample(type: "interaction.decided", json: event(.interactionDecided, .object(["interactionId": .string(id), "status": .string("approved"), "decidedAt": .string(ViadereDate.format(now))]))),
            Sample(type: "interaction.expired", json: event(.interactionExpired, .object(["interactionId": .string(id)]))),
            Sample(type: "interaction.cancelled", json: event(.interactionCancelled, .object(["interactionId": .string(id)]))),
            Sample(type: "message.received", json: event(.messageReceived, .object(["sessionId": .string(id), "relationshipId": .string(id), "text": .string("Thanks, that works."),
                                                                                    "channel": .string("in_app"), "receivedAt": .string(ViadereDate.format(now))]))),
            Sample(type: "relationship.connected", json: event(.relationshipConnected, .object(["relationshipId": .string(id)]))),
            Sample(type: "relationship.disconnected", json: event(.relationshipDisconnected, .object(["relationshipId": .string(id)]))),
            Sample(type: "consent.updated", json: event(.consentUpdated, .object(["relationshipId": .string(id), "purpose": .string("marketing"), "granted": .bool(false)]))),
            Sample(type: "reward.redeemed", json: event(.rewardRedeemed, .object(["rewardId": .string(id)]))),
            Sample(type: "webhook.test", json: event(.test, .object(["message": .string("This is a test event from Viadere. No customer data is included."), "endpointId": .string(id)]))),
            Sample(type: "v2 opaque envelope (approve and verify events)", json: pretty(WebhookEnvelopeV2(id: "evt_" + id, type: "approve.request.decided", tenantId: "ten_0123456789abcdef0123456789abcdef",
                                                                                                                     requestId: "req_example", occurredAt: now, resultRef: "/v1/business/approve/requests/req_example/result"))),
        ]
    }

    static func pretty<T: Encodable>(_ value: T) -> String { InteractionTemplates.pretty(value) }
}
