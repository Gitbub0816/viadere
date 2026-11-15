import Fluent
import Foundation
import XCTest
import ViadereCore
@testable import ViadereServerKit

/// Regression tests added by the Stage 2-3 code review (docs/reviews/STAGE2_3_CODE_REVIEW.md). Each one fails if its control is removed.
final class AuthDeliveryReviewTests: AuthDeliveryTestBase {
    /// R23-01: the stored create-request hash is keyed, so it cannot be enumerated back to the OTP by a database reader.
    func testTheStoredCreateHashIsKeyedAndCannotBeEnumeratedToTheCode() async throws {
        try await harness { h in
            let s = try await scene(h)
            let body = otpBody(s, id: "hash-1")
            let r = try await create(h, s.b, body, key: "hk1")
            XCTAssertEqual(r.status, .created, r.text)
            guard case .request(let request) = AuthDeliveryValidation.decodeCreate(body) else { return XCTFail("decode") }
            let unkeyed = SecureToken.sha256Hex(Data("auth_delivery.create\n".utf8) + (try ViadereJSON.encode(request)))
            let found = try await AuthDeliveryRecord.query(on: h.db).filter(\.$requestId == "hash-1").first()
            let row = try XCTUnwrap(found)
            XCTAssertNotEqual(row.requestHash, unkeyed)
            let idem = try await BusinessIdempotencyRecord.query(on: h.db).filter(\.$businessId == s.b.id.uuid).all()
            XCTAssertFalse(idem.isEmpty)
            XCTAssertFalse(idem.contains { $0.requestHash == unkeyed })
            // Replay and conflict still work with the keyed hash.
            try await eq(try await create(h, s.b, body, key: "hk2").status, .ok)
            try await eq(try await create(h, s.b, otpBody(s, id: "hash-1", extra: ["otp": ["code": "111111", "code_kind": "otp"]]), key: "hk3").errorCode, .idempotencyConflict)
        }
    }

    /// R23-02: sample auth events obey the same gates as `webhook.test` (ownership proven, not paused).
    func testSampleAuthEventsNeedAVerifiedUnpausedEndpoint() async throws {
        try await harness({ $0.operations.webhookOwnershipVerification = true }) { h in
            let s = try await scene(h)
            let row = WebhookSubscriptionRecord()
            row.id = UUID(); row.businessId = s.b.id.uuid; row.url = "https://hooks.example.com/unverified"; row.events = "auth.delivery.created"
            row.secretCiphertext = try h.ctx.cipher.seal("whsec_x", context: "webhook_subscriptions.secret", rowId: row.id!)
            row.active = true; row.createdAt = h.clock.now(); row.secretVersion = 1; row.signatureVersion = "v2"; row.envelopeVersion = WebhookEnvelopeV2.version
            try await row.create(on: h.db)
            let test = try await BusinessAPIKeys.issue(businessId: s.b.id.uuid, name: "t", live: false, scopes: BusinessAPIKeys.Scope.all, capabilities: Capability.operational,
                                                       now: h.clock.now(), on: h.db).key
            let body = try ViadereJSON.encode(AuthWebhookTestRequest(webhookId: WebhookSubscriptionID(row.id!), type: "auth.delivery.opened"))
            let unverified = try await h.business(s.b, .POST, "/v1/business/webhooks/test", body: body, key: test)
            XCTAssertEqual(unverified.status, .conflict, unverified.text)
            row.verifiedAt = h.clock.now(); row.pausedAt = h.clock.now()
            try await row.update(on: h.db)
            try await eq(try await h.business(s.b, .POST, "/v1/business/webhooks/test", body: body, key: test).status, .conflict, "paused")
            row.pausedAt = nil
            try await row.update(on: h.db)
            try await eq(try await h.business(s.b, .POST, "/v1/business/webhooks/test", body: body, key: test).status, .ok, "verified")
            try await eq(try await WebhookDeliveryRecord.query(on: h.db).filter(\.$subscriptionId == row.id!).count(), 1)
        }
    }

    /// Mutation check of the enqueue-time filter (ST-WH-03): a v1 row naming an auth event is not given a delivery, even though it is otherwise eligible.
    func testEnqueueSkipsAV1RowNamingAnAuthEventButQueuesForAV2Row() async throws {
        try await harness { h in
            let s = try await scene(h)
            func sub(_ path: String, _ version: String, envelope: String?) async throws -> UUID {
                let row = WebhookSubscriptionRecord()
                row.id = UUID(); row.businessId = s.b.id.uuid; row.url = "https://hooks.example.com/\(path)"; row.events = "auth.delivery.created"
                row.secretCiphertext = try h.ctx.cipher.seal("whsec_x", context: "webhook_subscriptions.secret", rowId: row.id!)
                row.active = true; row.createdAt = h.clock.now(); row.secretVersion = 1; row.signatureVersion = version; row.envelopeVersion = envelope
                row.verifiedAt = h.clock.now()
                try await row.create(on: h.db)
                return row.id!
            }
            let v1Opaque = try await sub("v1opaque", "v1", envelope: WebhookEnvelopeV2.version)
            let v1Plain = try await sub("v1plain", "v1", envelope: nil)
            let v2 = try await sub("v2", "v2", envelope: WebhookEnvelopeV2.version)
            _ = try await created(h, s)
            try await eq(try await WebhookDeliveryRecord.query(on: h.db).filter(\.$subscriptionId == v1Opaque).count(), 0, "v1 + opaque envelope")
            try await eq(try await WebhookDeliveryRecord.query(on: h.db).filter(\.$subscriptionId == v1Plain).count(), 0, "v1 + v1 envelope")
            try await eq(try await WebhookDeliveryRecord.query(on: h.db).filter(\.$subscriptionId == v2).count(), 1, "v2 control")
        }
    }

    /// Mutation check of the delivery-time block: an `auth.*` delivery already queued for a v1 subscription is never sent and is dead-lettered.
    func testAQueuedAuthDeliveryForAV1SubscriptionIsNeverSent() async throws {
        try await harness { h in
            let s = try await scene(h)
            let row = WebhookSubscriptionRecord()
            row.id = UUID(); row.businessId = s.b.id.uuid; row.url = "https://hooks.example.com/legacy"; row.events = "auth.delivery.created"
            row.secretCiphertext = try h.ctx.cipher.seal("whsec_x", context: "webhook_subscriptions.secret", rowId: row.id!)
            row.active = true; row.createdAt = h.clock.now(); row.secretVersion = 1; row.signatureVersion = "v1"; row.envelopeVersion = WebhookEnvelopeV2.version
            row.verifiedAt = h.clock.now()
            try await row.create(on: h.db)
            let delivery = WebhookDeliveryRecord()
            delivery.id = UUID()
            delivery.subscriptionId = row.id!
            delivery.businessId = s.b.id.uuid
            delivery.eventType = AuthDeliveryEventName.created.rawValue
            delivery.body = try h.ctx.cipher.seal(Data(#"{"id":"evt_x","type":"auth.delivery.created"}"#.utf8), context: "webhook_deliveries.body", rowId: delivery.id!)
            delivery.status = "pending"; delivery.attempts = 0; delivery.nextAttemptAt = h.clock.now(); delivery.createdAt = h.clock.now()
            try await delivery.create(on: h.db)
            try await Outbox.enqueue(QueueHandlers.webhookDeliver, ref: delivery.id!, tenant: delivery.businessId, on: h.db, ctx: h.ctx)
            try await h.runJobs()
            try await h.runJobs()
            XCTAssertTrue(h.webhooks.received.filter { $0.url.path == "/legacy" }.isEmpty)
            let reloaded = try await WebhookDeliveryRecord.find(delivery.id!, on: h.db)
            let after = try XCTUnwrap(reloaded)
            XCTAssertEqual(after.status, "dead")
            XCTAssertEqual(after.lastError, "signature_unavailable")
        }
    }
}
