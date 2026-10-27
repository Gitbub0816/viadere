@preconcurrency import Crypto
import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// WP1 webhooks (spec 14.3, SEC-API-006): the opaque v2 envelope is opt-in per subscription, v1 keeps working, and every delivery carries a
/// delivery id and a versioned signing key id.
final class ApproveWebhookTests: XCTestCase {
    private let url = URL(string: "https://hooks.example.com/viadere")!

    private func subscribe(_ h: TestHarness, _ b: TestBusiness, events: [WebhookEventType], version: String?) async throws -> WebhookSecretResponse {
        let result = try await h.businessPost(b, "/v1/business/webhooks", CreateWebhookRequest(url: url, events: events, envelopeVersion: version))
        XCTAssertEqual(result.status, .created, result.text)
        return try result.json(WebhookSecretResponse.self)
    }

    private func decideOne(_ h: TestHarness, _ f: ApproveFixture) async throws -> (String, String) {
        let (created, body) = try await h.createRequest(f)
        XCTAssertEqual(created.status, .created)
        let request = try await h.pendingRequests(f.phone.consumer).first { $0.requestId == body.requestId }!
        aeq(try await h.submit(f.phone, deliveryId: request.id, result: try await h.answer(f.phone, request)).status, .ok)
        return (body.requestId, try await h.requestView(f, body.requestId).resultRef!)
    }

    func testTheOpaqueEnvelopeCarriesIdsOnlyAndIsSignedWithAVersionedKey() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            let v2 = try await subscribe(h, f.business, events: [.approveRequestDecided], version: WebhookEnvelopeV2.version)
            XCTAssertEqual(v2.subscription.envelopeVersion, "2026-10-27")
            XCTAssertEqual(v2.subscription.secretVersion, 1)
            let (requestId, ref) = try await decideOne(h, f)
            try await h.runJobs()
            let delivery = try XCTUnwrap(h.webhooks.received.last)
            // Body: exactly the spec 14.3 members, no amount, no payee, no status, no decision.
            let envelope = try ViadereJSON.decode(WebhookEnvelopeV2.self, from: delivery.body)
            XCTAssertEqual(envelope.type, "approve.request.decided")
            XCTAssertEqual(envelope.version, "2026-10-27")
            XCTAssertEqual(envelope.requestId, requestId)
            XCTAssertEqual(envelope.resultRef, ref)
            XCTAssertTrue(envelope.id.hasPrefix("evt_"))
            XCTAssertTrue(envelope.tenantId.hasPrefix("ten_"))
            XCTAssertEqual(envelope.tenantId, WebhookService(db: h.db, ctx: h.ctx).tenantId(of: f.business.id))
            let text = String(decoding: delivery.body, as: UTF8.self)
            for forbidden in ["status", "decision", "amount", "payee", "Example Merchant", "250000", "approved"] { XCTAssertFalse(text.contains(forbidden), forbidden) }
            guard case .object(let members) = try JSONDecoder().decode(JSONValue.self, from: delivery.body) else { return XCTFail() }
            XCTAssertEqual(Set(members.keys), ["id", "type", "version", "tenant_id", "request_id", "occurred_at", "result_ref"])
            // Headers: delivery id, versioned key id, event id equal to the envelope id, format version; signature verifies with the secret.
            let h2 = delivery.headers
            XCTAssertEqual(h2[ViadereHeader.eventId], envelope.id)
            XCTAssertEqual(h2[ViadereHeader.deliveryId].map { "evt_" + $0 }, envelope.id)
            XCTAssertEqual(h2[ViadereHeader.webhookVersion], "2026-10-27")
            XCTAssertEqual(h2[ViadereHeader.keyId], "whk_\(v2.subscription.id.description.prefix(8))_v1")
            XCTAssertNoThrow(try WebhookSignature.verify(header: try XCTUnwrap(h2[ViadereHeader.signature]), body: delivery.body, secrets: [v2.secret], now: h.clock.now()))
            // The business retrieves the result with its own credentials, using the reference from the envelope.
            aeq(try await h.business(f.business, .GET, "/v1/business/approve/results/\(try XCTUnwrap(envelope.resultRef))").status, .ok)
        }
    }

    func testRotationBumpsTheKeyVersionAndRetriesKeepTheDeliveryId() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            let v2 = try await subscribe(h, f.business, events: [.approveRequestDecided, .approveRequestExpired], version: WebhookEnvelopeV2.version)
            let rotated = try await h.business(f.business, .POST, "/v1/business/webhooks/\(v2.subscription.id)/rotate-secret", body: Data("{}".utf8)).json(WebhookSecretResponse.self)
            XCTAssertEqual(rotated.subscription.secretVersion, 2)
            XCTAssertEqual(rotated.subscription.envelopeVersion, "2026-10-27")
            h.webhooks.respond(with: [500], then: 200)
            _ = try await decideOne(h, f)
            try await h.runJobs()
            h.clock.advance(by: 31)
            try await h.runJobs()
            XCTAssertEqual(h.webhooks.received.count, 2)
            let ids = h.webhooks.received.map { $0.headers[ViadereHeader.deliveryId] }
            XCTAssertEqual(ids[0], ids[1], "a retry is the same delivery")
            XCTAssertEqual(h.webhooks.received.map(\.body).uniqued().count, 1, "and the same bytes")
            XCTAssertEqual(h.webhooks.received[1].headers[ViadereHeader.keyId], "whk_\(v2.subscription.id.description.prefix(8))_v2")
            // During the overlap the delivery is signed with both secrets; the old one still verifies.
            let header = try XCTUnwrap(h.webhooks.received[1].headers[ViadereHeader.signature])
            XCTAssertNoThrow(try WebhookSignature.verify(header: header, body: h.webhooks.received[1].body, secrets: [v2.secret], now: h.clock.now()))
            XCTAssertNoThrow(try WebhookSignature.verify(header: header, body: h.webhooks.received[1].body, secrets: [rotated.secret], now: h.clock.now()))
        }
    }

    func testV1SubscriptionsKeepTheirShapeAndOnlyGetIds() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            let v1 = try await subscribe(h, f.business, events: [.approveRequestDecided], version: nil)
            XCTAssertNil(v1.subscription.envelopeVersion)
            let (requestId, ref) = try await decideOne(h, f)
            try await h.runJobs()
            let delivery = try XCTUnwrap(h.webhooks.received.last)
            let event = try ViadereJSON.decode(WebhookEvent.self, from: delivery.body)
            XCTAssertEqual(event.type.rawValue, "approve.request.decided")
            let payload = try event.decodeData(ApproveEventPayload.self)
            XCTAssertEqual(payload.requestId, requestId)
            XCTAssertEqual(payload.resultRef, ref)
            let text = String(decoding: delivery.body, as: UTF8.self)
            for forbidden in ["decision", "amount", "payee", "Example Merchant", "approved", "denied"] { XCTAssertFalse(text.contains(forbidden), forbidden) }
            XCTAssertEqual(delivery.headers[ViadereHeader.webhookVersion], "v1")
            XCTAssertNotNil(delivery.headers[ViadereHeader.keyId])
        }
    }

    func testOptingIntoV2IsValidatedAndPayloadEventsAreNeverEmbedded() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            // Events that carry content (a customer's message) have no opaque form, so a v2 subscription cannot ask for them.
            for version in ["2026-10-27"] {
                let r = try await h.businessPost(b, "/v1/business/webhooks", CreateWebhookRequest(url: url, events: [.messageReceived], envelopeVersion: version))
                XCTAssertEqual(r.status, .unprocessableEntity, r.text)
                let mixed = try await h.businessPost(b, "/v1/business/webhooks", CreateWebhookRequest(url: url, events: [.approveRequestDecided, .consentUpdated], envelopeVersion: version))
                XCTAssertEqual(mixed.status, .unprocessableEntity)
            }
            let unknown = try await h.businessPost(b, "/v1/business/webhooks", CreateWebhookRequest(url: url, events: [.approveRequestDecided], envelopeVersion: "2099-01-01"))
            XCTAssertEqual(unknown.status, .unprocessableEntity)
            let ok = try await h.businessPost(b, "/v1/business/webhooks", CreateWebhookRequest(url: url, events: [.interactionDecided, .approveKeyRevoked], envelopeVersion: "2026-10-27"))
            XCTAssertEqual(ok.status, .created, ok.text)
        }
    }

    func testLegacyInteractionEventsReachV2SubscribersAsIdsOnly() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let sub = try await subscribe(h, b, events: [.interactionDecided], version: "2026-10-27")
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b)
            _ = try await h.issue(b, relationship: rel, payload: .authorize(.sample()))
            let interaction = try await h.consumerInteraction(consumer, id: try unwrap(try await InteractionRecord.query(on: h.db).first()?.id.map { InteractionID($0) }))
            aeq(try await h.decide(consumer, id: interaction.id, signed: try await h.decision(consumer, interaction: interaction)).status, .ok)
            try await h.runJobs()
            let delivery = try XCTUnwrap(h.webhooks.received.last)
            let envelope = try ViadereJSON.decode(WebhookEnvelopeV2.self, from: delivery.body)
            XCTAssertEqual(envelope.type, "interaction.decided")
            XCTAssertEqual(envelope.requestId, interaction.id.description)
            XCTAssertFalse(String(decoding: delivery.body, as: UTF8.self).contains("Walmart"))
            XCTAssertNoThrow(try WebhookSignature.verify(header: try XCTUnwrap(delivery.headers[ViadereHeader.signature]), body: delivery.body, secrets: [sub.secret], now: h.clock.now()))
        }
    }

    func testEnrollmentAndFreezeEventsAreOpaqueToo() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            let keys = try await h.publishDirectory(b)
            _ = try await subscribe(h, b, events: [.approveEnrollmentDeviceCompleted, .approveEnrollmentConfirmed, .approveFrozen, .approveKeyRevoked], version: "2026-10-27")
            let consumer = try await h.readyConsumer()
            _ = try await h.connect(consumer, to: b)
            let phone = try await h.enrollApproval(consumer, business: b, keys: keys)
            _ = try await h.signedPost(consumer, "/v1/approve/freeze", ApproveFreezeRequest(scope: .account, frozen: true))
            _ = try await h.signedPost(consumer, "/v1/approve/keys/\(phone.kid)/revoke", EmptyBody())
            try await h.runJobs()
            let types = try h.webhooks.received.map { try ViadereJSON.decode(WebhookEnvelopeV2.self, from: $0.body).type }
            XCTAssertEqual(Set(types), ["approve.enrollment.device_completed", "approve.enrollment.confirmed", "approve.frozen", "approve.key.revoked"])
            for delivery in h.webhooks.received { XCTAssertFalse(String(decoding: delivery.body, as: UTF8.self).contains(phone.kid), "no key id in the envelope") }
        }
    }
}

private extension Array where Element: Hashable {
    func uniqued() -> [Element] { Array(Set(self)) }
}
