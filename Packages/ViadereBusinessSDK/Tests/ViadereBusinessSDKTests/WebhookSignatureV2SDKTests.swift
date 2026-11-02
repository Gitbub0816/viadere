import Foundation
import Testing
import ViadereCore
@testable import ViadereBusinessSDK

/// SDK half of ST-WH-01/02/06/07: v2 verification, the tenant, the registered endpoint, durable dedup and the destination signer.
@Suite("Webhook signature v2 (SDK)")
struct WebhookSignatureV2SDKTests {
    static let endpoint = URL(string: "https://hooks.example.com/viadere/events")!
    static let tenant = "ten_7a1b2c3d4e5f60718293a4b5c6d7e8f9"
    static let kid = "whk_1a2b3c4d_v1"
    static let secret = "whsec_testsecret_one"
    static let now = Date(timeIntervalSince1970: 1_793_620_800)
    static let body = Data(#"{"id":"evt_0f6c1d2e3a4b4c5d8e9f0a1b2c3d4e5f","occurred_at":"2026-11-02T12:00:00.000Z","request_id":"adl_AAAAAAAAAAAAAAAAAAAAAA","tenant_id":"ten_7a1b2c3d4e5f60718293a4b5c6d7e8f9","type":"auth.delivery.opened","version":"2026-10-27"}"#.utf8)

    static func headers(eventId: String = "evt_0f6c1d2e3a4b4c5d8e9f0a1b2c3d4e5f", endpoint: URL = endpoint, body: Data = body, extra: [(String, String)] = []) -> [String: String] {
        let context = WebhookSignatureV2.Context(endpoint: endpoint, eventId: eventId, tenantId: tenant)!
        let signature = WebhookSignatureV2.header(secrets: [(kid, secret)], context: context, body: body, now: now)!
        return [ViadereHeader.signature: signature, ViadereHeader.eventId: eventId, ViadereHeader.tenant: tenant, ViadereHeader.contentDigest: WebhookSignatureV2.contentDigest(body)]
    }

    static func verifier(endpoint: URL = endpoint, tenant: String = tenant, at: Date = now) -> WebhookVerifierV2 {
        WebhookVerifierV2(endpoint: endpoint, tenantId: tenant, keys: [kid: secret], clock: { at })
    }

    @Test func aValidDeliveryVerifiesAndDecodes() throws {
        let verified = try Self.verifier().verify(headers: Self.headers(), body: Self.body)
        #expect(verified.tenantId == Self.tenant)
        let envelope = try Self.verifier().verifyEnvelope(headers: Self.headers(), body: Self.body)
        #expect(envelope.type == "auth.delivery.opened")
    }

    @Test func theRegisteredEndpointTenantBodyAndWindowAreBound() {
        #expect(throws: WebhookVerifierV2.Failure.noMatchingSignature) { try Self.verifier(endpoint: URL(string: "https://hooks.example.com/other")!).verify(headers: Self.headers(), body: Self.body) }
        #expect(throws: WebhookVerifierV2.Failure.tenantMismatch) { try Self.verifier(tenant: "ten_mine").verify(headers: Self.headers(), body: Self.body) }
        #expect(throws: WebhookVerifierV2.Failure.digestMismatch) { try Self.verifier().verify(headers: Self.headers(), body: Self.body + Data(" ".utf8)) }
        #expect(throws: WebhookVerifierV2.Failure.timestampOutsideTolerance) { try Self.verifier(at: Self.now.addingTimeInterval(400)).verify(headers: Self.headers(), body: Self.body) }
        var missing = Self.headers(); missing.removeValue(forKey: ViadereHeader.tenant)
        #expect(throws: WebhookVerifierV2.Failure.missingHeader(ViadereHeader.tenant)) { try Self.verifier().verify(headers: missing, body: Self.body) }
        // A v1-only delivery is never accepted by a v2 verifier.
        var v1 = Self.headers(); v1[ViadereHeader.signature] = WebhookSignature.header(secret: Self.secret, body: Self.body, now: Self.now)
        #expect(throws: WebhookVerifierV2.Failure.malformedSignature) { try Self.verifier().verify(headers: v1, body: Self.body) }
    }

    /// ST-WH-02 / ST-WH-06: a repeated event id is refused; a forged delivery cannot burn a genuine id; the id is still remembered at the final retry offset.
    @Test func durableDedupRefusesARepeatInsideTheHorizon() throws {
        let store = InMemoryWebhookReplayStore()
        let verifier = Self.verifier()
        _ = try verifier.verify(headers: Self.headers(), body: Self.body, replayStore: store)
        #expect(throws: WebhookVerifierV2.Failure.duplicateEvent) { try verifier.verify(headers: Self.headers(), body: Self.body, replayStore: store) }
        // A forged copy (bad signature) is refused before it can record anything.
        let fresh = InMemoryWebhookReplayStore()
        var forged = Self.headers(eventId: "evt_ffffffffffffffffffffffffffffffff"); forged[ViadereHeader.eventId] = "evt_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        #expect(throws: WebhookVerifierV2.Failure.noMatchingSignature) { try verifier.verify(headers: forged, body: Self.body, replayStore: fresh) }
        #expect(fresh.recordFirstReceipt(eventId: "evt_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", at: Self.now))
        // The last retry arrives `maxHorizon` after the first receipt: still deduplicated; after the full horizon plus margin it may be forgotten.
        let s = InMemoryWebhookReplayStore(horizon: WebhookRetrySchedule.dedupHorizon)
        #expect(s.recordFirstReceipt(eventId: "evt_x", at: Self.now))
        #expect(!s.recordFirstReceipt(eventId: "evt_x", at: Self.now.addingTimeInterval(WebhookRetrySchedule.maxHorizon)))
        #expect(s.recordFirstReceipt(eventId: "evt_x", at: Self.now.addingTimeInterval(WebhookRetrySchedule.dedupHorizon + 1)))
    }

    @Test func signAuthDestinationProducesAStatementTheDeviceCanVerify() async throws {
        let key = SoftwareP256SigningKey()
        let subject = SubjectRef("sub_" + Base64URL.encode(Data(repeating: 3, count: 32)))!
        let url = "https://login.example.com/m?t=1"
        let jws = try await signAuthDestination(url: url, subjectRef: subject, requestId: "r1", purpose: .signIn, tenantId: Self.tenant, kid: "tk1", key: key, issuedAt: Self.now)
        let expectation = AuthDestinationStatement.Expectation(keys: ["tk1": (key.publicKey, nil)], allowedHosts: ["login.example.com"], tenantId: Self.tenant, requestId: "r1",
                                                               purpose: .signIn, subjectRef: subject, now: Self.now)
        let statement = try AuthDestinationStatement.verifyForDevice(jws, expectation: expectation) { _ in true }
        try statement.verifyOpened(url: url, allowedHosts: ["login.example.com"])
        #expect(throws: AuthDestinationError.self) { _ = try AuthDestinationStatement.build(url: "http://login.example.com/", tenantId: Self.tenant, subjectRef: subject, requestId: "r", purpose: .signIn, kid: "k", issuedAt: Self.now) }
    }
}
