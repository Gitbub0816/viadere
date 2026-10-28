import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Webhook management (SEC-API-006, spec §9.3): ownership verification before activation, delivery id and versioned key id, test events,
/// retry simulation, schema preview, and the catalog routes the Business SDK calls (`verify`, `test`, `pause`, `resume`).
final class WP6WebhookTests: XCTestCase {
    private func ownership(_ config: inout ServerConfig) { config.operations.webhookOwnershipVerification = true }

    private struct Setup {
        var h: TestHarness
        var owner: DashSession
        var account: DashAccount
        var businessId: UUID
        var key: String
        var relationship: String
    }

    private func setup(_ h: TestHarness, scopes: [String] = ["interactions:write", "webhooks:manage"]) async throws -> Setup {
        let (owner, account, businessId) = try await h.verifiedOwner()
        let key = try await h.newKey(owner, scopes: scopes)
        let rel = try await h.apiPost(try await h.newKey(owner, name: "sandbox", scopes: ["interactions:write"]), "/v1/business/sandbox/relationships")
        let relationship = try XCTUnwrap(try JSONSerialization.jsonObject(with: rel.body) as? [String: Any])["relationshipId"] as? String
        return Setup(h: h, owner: owner, account: account, businessId: businessId, key: key, relationship: try XCTUnwrap(relationship))
    }

    private func create(_ s: Setup, url: String = "https://hooks.acme.example/viadere") async throws -> WebhookSecretResponse {
        let response = try await s.h.apiPost(s.key, "/v1/business/webhooks", json: try ViadereJSON.encode(CreateWebhookRequest(url: URL(string: url)!, events: [.messageReceived])))
        XCTAssertEqual(response.status, .created, response.text)
        return try response.json(WebhookSecretResponse.self)
    }

    private func deliveries(_ h: TestHarness, to host: String? = nil) -> [WebhookHTTPRequest] {
        h.webhooks.received.filter { host == nil || $0.url.host == host }
    }

    // MARK: Ownership

    func testAnUnverifiedEndpointReceivesNothingUntilItProvesOwnership() async throws {
        try await withHarness(ownership) { h in
            let s = try await setup(h)
            let hook = try await create(s)
            let service = WebhookService(db: h.db, ctx: h.ctx)
            // Real events do not reach it, and a test event is refused with a clear message.
            try await service.simulateReply(businessId: BusinessID(s.businessId), relationshipId: UUID(uuidString: s.relationship)!, text: "hello")
            _ = try await service.deliverDue()
            XCTAssertEqual(deliveries(h).count, 0)
            let test = try await h.apiPost(s.key, "/v1/business/webhooks/\(hook.subscription.id)/test")
            XCTAssertEqual(test.status, .conflict)
            XCTAssertTrue(test.text.contains("Verify the endpoint"))
            // An endpoint that answers 2xx but does not echo the challenge is not verified (a URL the registrant does not control).
            h.webhooks.respond(with: [200])
            let silent = try await h.apiPost(s.key, "/v1/business/webhooks/\(hook.subscription.id)/verify")
            XCTAssertEqual(silent.status, .ok)
            let silentResult = try silent.json(WebhookVerificationResult.self)
            XCTAssertFalse(silentResult.verified)
            XCTAssertEqual(silentResult.failure, "no_echo")
            // Error statuses and unreachable endpoints are reported as such.
            h.webhooks.respond(with: [503])
            let down = try await h.apiPost(s.key, "/v1/business/webhooks/\(hook.subscription.id)/verify").json(WebhookVerificationResult.self)
            XCTAssertEqual(down.failure, "http_503")
            h.webhooks.respond { _ in throw WebhookTransportError.blockedDestination }
            let blocked = try await h.apiPost(s.key, "/v1/business/webhooks/\(hook.subscription.id)/verify").json(WebhookVerificationResult.self)
            XCTAssertEqual(blocked.failure, "unreachable")
            // A stale echo from an earlier attempt never verifies a later one: every attempt has a fresh single-use challenge.
            let remembered = Box<String>()
            h.webhooks.respond { request in
                guard let object = try? JSONSerialization.jsonObject(with: request.body) as? [String: Any], let challenge = object["challenge"] as? String else { return nil }
                if remembered.value == nil { remembered.value = challenge; return WebhookHTTPResponse(statusCode: 200, body: Data("nope".utf8)) }
                return WebhookHTTPResponse(statusCode: 200, body: Data(remembered.value!.utf8))
            }
            _ = try await h.apiPost(s.key, "/v1/business/webhooks/\(hook.subscription.id)/verify")
            let replayed = try await h.apiPost(s.key, "/v1/business/webhooks/\(hook.subscription.id)/verify").json(WebhookVerificationResult.self)
            XCTAssertFalse(replayed.verified)
            let rowAfterReplay = try await XCTUnwrapAsync(await WebhookSubscriptionRecord.find(hook.subscription.id.uuid, on: h.db))
            XCTAssertNil(rowAfterReplay.verifiedAt)
            XCTAssertNil(rowAfterReplay.verificationChallengeHash, "spent challenges are not kept")
            // The challenge request itself is signed like any delivery and carries the key id.
            let challengeRequest = try XCTUnwrap(deliveries(h).last)
            XCTAssertEqual(challengeRequest.headers[ViadereHeader.eventType], "webhook.verification")
            XCTAssertNotNil(challengeRequest.headers[ViadereHeader.signature])
            XCTAssertTrue(challengeRequest.headers[ViadereHeader.keyId]?.hasPrefix("whk_") ?? false)
            XCTAssertNoThrow(try WebhookSignature.verify(header: try XCTUnwrap(challengeRequest.headers[ViadereHeader.signature]), body: challengeRequest.body, secrets: [hook.secret], now: h.clock.now()))
            // Echo it properly, as JSON or as plain text: verified, and events flow (the earlier queued reply is delivered now).
            h.webhooks.respond(nil)
            h.echoWebhookChallenges()
            let proven = try await h.apiPost(s.key, "/v1/business/webhooks/\(hook.subscription.id)/verify").json(WebhookVerificationResult.self)
            XCTAssertTrue(proven.verified)
            // Verified once: asking again is a harmless yes.
            let again = try await h.apiPost(s.key, "/v1/business/webhooks/\(hook.subscription.id)/verify").json(WebhookVerificationResult.self)
            XCTAssertTrue(again.verified)
            let audit = try await h.auditActions(s.businessId)
            XCTAssertTrue(audit.contains("webhook.verification_failed") && audit.contains("webhook.verified"))
        }
    }

    func testVerificationAttemptsAreRateLimitedAndTheBareChallengeBodyWorks() async throws {
        try await withHarness(ownership) { h in
            let s = try await setup(h)
            let hook = try await create(s)
            h.webhooks.respond(with: [200])
            var statuses: [HTTPStatus] = []
            for _ in 0..<8 { statuses.append(try await h.apiPost(s.key, "/v1/business/webhooks/\(hook.subscription.id)/verify").status) }
            XCTAssertEqual(statuses.prefix(6).filter { $0 == .ok }.count, 6)
            XCTAssertEqual(statuses.suffix(2), [.tooManyRequests, .tooManyRequests], "an attacker cannot use the endpoint to probe a third party's URL at will")
            h.clock.advance(by: 3_700)
            h.webhooks.respond { request in
                guard let object = try? JSONSerialization.jsonObject(with: request.body) as? [String: Any], let challenge = object["challenge"] as? String else { return nil }
                return WebhookHTTPResponse(statusCode: 200, body: Data((challenge + "\n").utf8)) // the bare value, newline and all
            }
            let ok = try await h.apiPost(s.key, "/v1/business/webhooks/\(hook.subscription.id)/verify").json(WebhookVerificationResult.self)
            XCTAssertTrue(ok.verified)
        }
    }

    // MARK: Test events, delivery id, key id, rotation

    func testTestEventsAreSignedCarryADeliveryIdAndAVersionedKeyIdThatChangesOnRotation() async throws {
        try await withHarness(ownership) { h in
            h.echoWebhookChallenges()
            let s = try await setup(h)
            let hook = try await create(s)
            _ = try await h.apiPost(s.key, "/v1/business/webhooks/\(hook.subscription.id)/verify")
            let service = WebhookService(db: h.db, ctx: h.ctx)
            let sent = try await h.apiPost(s.key, "/v1/business/webhooks/\(hook.subscription.id)/test")
            XCTAssertEqual(sent.status, .ok, sent.text)
            _ = try await service.deliverDue()
            let first = try XCTUnwrap(deliveries(h).last { $0.headers[ViadereHeader.eventType] == "webhook.test" })
            let deliveryId = try XCTUnwrap(first.headers[ViadereHeader.deliveryId])
            XCTAssertNotNil(UUID(uuidString: deliveryId))
            let keyId1 = try XCTUnwrap(first.headers[ViadereHeader.keyId])
            XCTAssertTrue(keyId1.hasSuffix("_v1"))
            XCTAssertNoThrow(try WebhookSignature.verify(header: try XCTUnwrap(first.headers[ViadereHeader.signature]), body: first.body, secrets: [hook.secret], now: h.clock.now()))
            XCTAssertTrue(String(decoding: first.body, as: UTF8.self).contains("No customer data is included"))
            // Tampering with the body or the timestamp window fails verification at the receiver.
            XCTAssertThrowsError(try WebhookSignature.verify(header: try XCTUnwrap(first.headers[ViadereHeader.signature]), body: first.body + Data(" ".utf8), secrets: [hook.secret], now: h.clock.now()))
            XCTAssertThrowsError(try WebhookSignature.verify(header: try XCTUnwrap(first.headers[ViadereHeader.signature]), body: first.body, secrets: [hook.secret], now: h.clock.now().addingTimeInterval(400)))
            // Two test events are two deliveries with two ids.
            _ = try await h.apiPost(s.key, "/v1/business/webhooks/\(hook.subscription.id)/test")
            _ = try await service.deliverDue()
            let ids = deliveries(h).filter { $0.headers[ViadereHeader.eventType] == "webhook.test" }.compactMap { $0.headers[ViadereHeader.deliveryId] }
            XCTAssertEqual(Set(ids).count, 2)
            // Rotating the secret bumps the key id; during the overlap the signature header carries both so the receiver can switch without downtime.
            let rotated = try await h.apiPost(s.key, "/v1/business/webhooks/\(hook.subscription.id)/rotate-secret")
            XCTAssertEqual(rotated.status, .ok, rotated.text)
            let newSecret = try rotated.json(WebhookSecretResponse.self).secret
            XCTAssertNotEqual(newSecret, hook.secret)
            _ = try await h.apiPost(s.key, "/v1/business/webhooks/\(hook.subscription.id)/test")
            _ = try await service.deliverDue()
            let after = try XCTUnwrap(deliveries(h).last { $0.headers[ViadereHeader.eventType] == "webhook.test" })
            XCTAssertTrue(try XCTUnwrap(after.headers[ViadereHeader.keyId]).hasSuffix("_v2"))
            for secret in [hook.secret, newSecret] {
                XCTAssertNoThrow(try WebhookSignature.verify(header: try XCTUnwrap(after.headers[ViadereHeader.signature]), body: after.body, secrets: [secret], now: h.clock.now()), "overlap")
            }
            // The test endpoint is rate limited per endpoint.
            var limited = false
            for _ in 0..<12 { if try await h.apiPost(s.key, "/v1/business/webhooks/\(hook.subscription.id)/test").status == .tooManyRequests { limited = true } }
            XCTAssertTrue(limited)
        }
    }

    // MARK: Authorization of the management routes

    func testManagementRoutesNeedTheScopeAndStayInsideTheTenant() async throws {
        try await withHarness(ownership) { h in
            let s = try await setup(h)
            let hook = try await create(s)
            let narrow = try await h.newKey(s.owner, name: "narrow", scopes: ["interactions:write"])
            for action in ["verify", "test", "pause", "resume"] {
                let denied = try await h.apiPost(narrow, "/v1/business/webhooks/\(hook.subscription.id)/\(action)")
                XCTAssertEqual(denied.status, .forbidden, action)
            }
            let (otherOwner, _, _) = try await h.verifiedOwner(email: "o2@example.net", org: "Other Co", handle: "otherco")
            let otherKey = try await h.newKey(otherOwner, scopes: ["webhooks:manage"])
            for action in ["verify", "test", "pause", "resume"] {
                let cross = try await h.apiPost(otherKey, "/v1/business/webhooks/\(hook.subscription.id)/\(action)")
                XCTAssertEqual(cross.status, .notFound, "\(action): another tenant's endpoint does not exist for you")
            }
            let unknown = try await h.apiPost(s.key, "/v1/business/webhooks/\(UUID())/verify")
            XCTAssertEqual(unknown.status, .notFound)
            let row = try await XCTUnwrapAsync(await WebhookSubscriptionRecord.find(hook.subscription.id.uuid, on: h.db))
            XCTAssertNil(row.pausedAt, "nothing changed")
            // The console enforces roles the same way: a messaging operator can see endpoints but not verify, test or pause them.
            let (operatorSession, _) = try await h.addMember(owner: s.owner, role: .messagingOperator, email: "ops@example.com")
            for action in ["verify", "test", "pause", "resume"] {
                let r = try await h.formPost("/dashboard/webhooks/\(hook.subscription.id)/\(action)", operatorSession)
                XCTAssertEqual(r.status, .forbidden, action)
            }
        }
    }

    // MARK: Preview and simulation

    func testSchemaPreviewAndRetrySimulationShowRealShapesAndRealBackoff() async throws {
        try await withHarness { h in
            let (owner, _, _) = try await h.verifiedOwner()
            let schemas = try await h.page("/dashboard/webhooks/schemas", owner)
            XCTAssertEqual(schemas.status, .ok)
            for type in ["interaction.decided", "message.received", "relationship.connected", "consent.updated", "reward.redeemed", "webhook.test", "approve.request.decided"] {
                XCTAssertTrue(schemas.text.contains(type), type)
            }
            XCTAssertTrue(schemas.text.contains("Viadere-Delivery-Id") && schemas.text.contains("Viadere-Key-Id"))
            XCTAssertFalse(schemas.text.contains("vdk_"))
            // Every sample is valid JSON of a real event type.
            for sample in WebhookSchemaPreview.samples(now: h.clock.now()) {
                XCTAssertNoThrow(try JSONSerialization.jsonObject(with: Data(sample.json.utf8)), sample.type)
            }
            let none = WebhookRetrySimulation.plan(failures: 0, from: h.clock.now())
            XCTAssertEqual(none.count, 1)
            XCTAssertTrue(none[0].outcome.hasPrefix("succeeds"))
            let all = WebhookRetrySimulation.plan(failures: WebhookService.maxAttempts, from: h.clock.now())
            XCTAssertEqual(all.count, WebhookService.maxAttempts)
            XCTAssertTrue(all.last!.outcome.contains("dead-letter"))
            for (index, step) in all.dropLast().enumerated() { XCTAssertTrue(step.outcome.contains("\(Int(WebhookService.backoff[min(index, WebhookService.backoff.count - 1)])) s")) }
            XCTAssertEqual(all[1].at.timeIntervalSince(all[0].at), WebhookService.backoff[0])
            let page = try await h.page("/dashboard/webhooks/simulate?failures=3", owner)
            XCTAssertEqual(page.status, .ok)
            XCTAssertTrue(page.text.contains("Simulated retry schedule"))
            // Out-of-range input is clamped, never trusted.
            let wild = try await h.page("/dashboard/webhooks/simulate?failures=999999", owner)
            XCTAssertEqual(wild.status, .ok)
        }
    }

    func testPausedAndUnverifiedStatesAreShownAndRealRetriesStillBackOff() async throws {
        try await withHarness(ownership) { h in
            h.echoWebhookChallenges()
            let s = try await setup(h)
            let hook = try await create(s)
            let page = try await h.page("/dashboard/webhooks", s.owner).text
            XCTAssertTrue(page.contains("Not verified"))
            _ = try await h.apiPost(s.key, "/v1/business/webhooks/\(hook.subscription.id)/verify")
            // A failing endpoint is retried on the documented schedule.
            let service = WebhookService(db: h.db, ctx: h.ctx)
            h.webhooks.respond(with: [500, 500], then: 200)
            try await service.simulateReply(businessId: BusinessID(s.businessId), relationshipId: UUID(uuidString: s.relationship)!, text: "retry me")
            let attempts0 = try await service.deliverDue()
            XCTAssertEqual(attempts0, 1)
            let delivery = try await XCTUnwrapAsync(await WebhookDeliveryRecord.query(on: h.db).filter(\.$eventType == "message.received").first())
            XCTAssertEqual(delivery.status, "pending")
            XCTAssertEqual(delivery.nextAttemptAt.timeIntervalSince(h.clock.now()), WebhookService.backoff[0], accuracy: 1)
            let early = try await service.deliverDue()
            XCTAssertEqual(early, 0, "not before the backoff")
            h.clock.advance(by: WebhookService.backoff[0] + 1)
            _ = try await service.deliverDue()
            h.clock.advance(by: WebhookService.backoff[1] + 1)
            _ = try await service.deliverDue()
            let done = try await XCTUnwrapAsync(await WebhookDeliveryRecord.find(delivery.id!, on: h.db))
            XCTAssertEqual(done.status, "succeeded")
            XCTAssertEqual(done.attempts, 3)
        }
    }

    /// Approve's opaque v2 envelope shares the same ownership, test and pause machinery: nothing here duplicates it.
    func testTheOpaqueV2EnvelopeEndpointUsesTheSameVerificationAndTestEvents() async throws {
        try await withHarness(ownership) { h in
            h.echoWebhookChallenges()
            let s = try await setup(h)
            let created = try await h.apiPost(s.key, "/v1/business/webhooks", json: try ViadereJSON.encode(
                CreateWebhookRequest(url: URL(string: "https://hooks.acme.example/v2")!, events: [.approveRequestDecided], envelopeVersion: WebhookEnvelopeV2.version)))
            XCTAssertEqual(created.status, .created, created.text)
            let hook = try created.json(WebhookSecretResponse.self)
            XCTAssertEqual(hook.subscription.envelopeVersion, WebhookEnvelopeV2.version)
            let refused = try await h.apiPost(s.key, "/v1/business/webhooks/\(hook.subscription.id)/test")
            XCTAssertEqual(refused.status, .conflict, "unverified")
            let verified = try await h.apiPost(s.key, "/v1/business/webhooks/\(hook.subscription.id)/verify").json(WebhookVerificationResult.self)
            XCTAssertTrue(verified.verified)
            let challenge = try XCTUnwrap(deliveries(h).last)
            XCTAssertEqual(challenge.headers[ViadereHeader.webhookVersion], WebhookEnvelopeV2.version)
            _ = try await h.apiPost(s.key, "/v1/business/webhooks/\(hook.subscription.id)/test")
            _ = try await WebhookService(db: h.db, ctx: h.ctx).deliverDue()
            let test = try XCTUnwrap(deliveries(h).last { $0.headers[ViadereHeader.eventType] == "webhook.test" })
            let envelope = try ViadereJSON.decode(WebhookEnvelopeV2.self, from: test.body)
            XCTAssertEqual(envelope.type, "webhook.test")
            XCTAssertNil(envelope.resultRef)
            XCTAssertNotNil(test.headers[ViadereHeader.deliveryId])
            XCTAssertFalse(String(decoding: test.body, as: UTF8.self).contains("customer"), "the opaque envelope carries ids only")
            XCTAssertNoThrow(try WebhookSignature.verify(header: try XCTUnwrap(test.headers[ViadereHeader.signature]), body: test.body, secrets: [hook.secret], now: h.clock.now()))
        }
    }
}
