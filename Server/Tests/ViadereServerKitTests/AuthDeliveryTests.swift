@preconcurrency import Crypto
import Fluent
import Foundation
import NIOHTTP1
import XCTest
import ViadereCore
@testable import ViadereServerKit

/// Authentication delivery (ADR-0020 and friends). Test names carry the THREAT_MODEL catalogue ids.
final class TestTenantKeys: TenantDestinationKeyDirectory, @unchecked Sendable {
    private let lock = NSLock()
    private var keys: [String: [String: (key: DevicePublicKey, notAfter: Date?)]] = [:]
    func set(tenant: String, kid: String, key: DevicePublicKey, notAfter: Date? = nil) { lock.withLock { keys[tenant, default: [:]][kid] = (key, notAfter) } }
    func activeKeys(tenantId: String) async -> [String: (key: DevicePublicKey, notAfter: Date?)] { lock.withLock { keys[tenantId] ?? [:] } }
}

class AuthDeliveryTestBase: XCTestCase {
    let tenantKeys = TestTenantKeys()
    let signingKey = SoftwareP256SigningKey()

    struct Scene {
        var b: TestBusiness
        var consumer: TestConsumer
        var subject: SubjectRef
        var host: String
    }

    func harness(_ adjust: @escaping (inout ServerConfig) -> Void = { _ in }, _ body: (TestHarness) async throws -> Void) async throws {
        let keys = tenantKeys
        try await withHarness(overrides: { $0.tenantDestinationKeys = keys }, { config in
            config.authDelivery.destinationSignatureRequired = true
            adjust(&config)
        }, body)
    }

    func scene(_ h: TestHarness, name: String = "Northwind", handle: String = "northwind", push: Bool = true) async throws -> Scene {
        let b = try await h.makeBusiness(name: name, handle: handle)
        let consumer = try await h.readyConsumer()
        _ = try await h.connect(consumer, to: b)
        if push {
            let token = String(repeating: "ab", count: 32)
            _ = try await h.signedPost(consumer, "/v1/push/apns-token", APNsTokenRegistration(token: token, environment: .sandbox, bundleId: "com.viadere.app"))
        }
        try await h.ensureVerifiedDomain(b.id.uuid)
        let domain = try await BusinessDomainRecord.query(on: h.db).filter(\.$businessId == b.id.uuid).first()!.domain
        let host = "login." + domain
        let row = AuthDestinationHostRecord()
        row.id = UUID(); row.businessId = b.id.uuid; row.host = host; row.createdBy = "test"; row.createdAt = h.clock.now(); row.activatedAt = h.clock.now()
        try await row.create(on: h.db)
        tenantKeys.set(tenant: WebhookService(db: h.db, ctx: h.ctx).tenantId(of: b.id), kid: "tk_1", key: signingKey.publicKey)
        return Scene(b: b, consumer: consumer, subject: h.subjectRef(b, consumer), host: host)
    }

    func otpBody(_ s: Scene, id: String = UUID().uuidString, extra: [String: Any] = [:]) -> Data {
        var o: [String: Any] = ["method": "otp", "request_id": id, "subject_ref": s.subject.rawValue, "purpose": "sign_in", "template": "auth.sign_in_code.v1",
                                "otp": ["code": "482913", "code_kind": "otp"]]
        for (k, v) in extra { o[k] = v }
        return try! JSONSerialization.data(withJSONObject: o)
    }

    func create(_ h: TestHarness, _ b: TestBusiness, _ body: Data, key: String = UUID().uuidString, apiKey: String? = nil) async throws -> HTTPResult {
        try await h.business(b, .POST, "/v1/business/auth-deliveries", body: body, idempotencyKey: key, key: apiKey)
    }

    func created(_ h: TestHarness, _ s: Scene, id: String = UUID().uuidString, extra: [String: Any] = [:]) async throws -> AuthDeliveryView {
        let r = try await create(h, s.b, otpBody(s, id: id, extra: extra))
        XCTAssertEqual(r.status, .created, r.text)
        return try r.json(AuthDeliveryView.self)
    }

    func linkBody(_ h: TestHarness, _ s: Scene, id: String = "link-1", url: String? = nil, sign: Bool = true, statementURL: String? = nil) async throws -> Data {
        let url = url ?? "https://\(s.host)/m?t=abc"
        var destination: [String: Any] = ["link_mode": "business", "url": url]
        if sign {
            let st = try AuthDestinationStatement.build(url: statementURL ?? url, tenantId: WebhookService(db: h.db, ctx: h.ctx).tenantId(of: s.b.id), subjectRef: s.subject,
                                                        requestId: id, purpose: .signIn, kid: "tk_1", issuedAt: h.clock.now())
            destination["signature"] = try await st.sign(with: signingKey)
        }
        return try JSONSerialization.data(withJSONObject: ["method": "magic_link", "request_id": id, "subject_ref": s.subject.rawValue, "purpose": "sign_in",
                                                           "template": "auth.sign_in_link.v1", "destination": destination])
    }

    func get(_ h: TestHarness, _ s: Scene, _ id: AuthDeliveryID) async throws -> AuthDeliveryView {
        try await h.business(s.b, .GET, "/v1/business/auth-deliveries/\(id)").json(AuthDeliveryView.self)
    }

}

final class AuthDeliveryTests: AuthDeliveryTestBase {
    // MARK: Happy path, secrets, push (ST-OTP-01, ST-PRIV-02/03, ST-DLV-03, ST-UX-05)

    func testOTPFlowPushIsOpaqueAndTheSecretIsRevealedOnce() async throws {
        try await harness { h in
            let s = try await scene(h)
            let view = try await created(h, s)
            XCTAssertEqual(view.status, .queued)
            try await h.runJobs()
            try await eq(try await get(h, s, view.id).status, .sent)
            // The push: generic text, category, delivery id only (ST-PRIV-02).
            let message = try XCTUnwrap(h.push.sent.last)
            XCTAssertEqual(message.category, "viadere.auth.code")
            XCTAssertEqual(message.body, AuthPushPayloadPolicy.alertBody)
            XCTAssertEqual(message.authDeliveryId, view.id.description)
            XCTAssertNil(message.interactionId)
            for field in [message.title, message.body, message.category, message.threadID] { XCTAssertFalse(field.contains("482913") || field.contains("Northwind")) }
            let json = try JSONEncoder().encode(APNSwiftSender.notification(for: message))
            let payload = try XCTUnwrap(JSONSerialization.jsonObject(with: json) as? [String: Any])
            XCTAssertTrue(AuthPushPayloadPolicy.isAllowed(payload), String(decoding: json, as: UTF8.self))
            XCTAssertFalse(String(decoding: json, as: UTF8.self).contains("482913"))
            // Never a Live Activity (ST-UX-05).
            XCTAssertTrue(h.push.liveActivities.isEmpty)
            // The business never sees the code, in the view or in the status.
            let raw = try await h.business(s.b, .GET, "/v1/business/auth-deliveries/\(view.id)").text
            XCTAssertFalse(raw.contains("482913"))
            // Device: inbox, display (marks delivered), open once.
            let inbox = try await h.signed(s.consumer, .GET, "/v1/auth-deliveries").json([AuthDeliveryDisplay].self)
            XCTAssertEqual(inbox.map(\.id), [view.id])
            let display = try await h.signed(s.consumer, .GET, "/v1/auth-deliveries/\(view.id)")
            XCTAssertEqual(try display.json(AuthDeliveryDisplay.self).status, .delivered)
            XCTAssertFalse(display.text.contains("482913"))
            try await eq(try await get(h, s, view.id).status, .delivered)
            // ST-DLV-03: opened is not completion.
            let open = try await h.signed(s.consumer, .POST, "/v1/auth-deliveries/\(view.id)/open")
            XCTAssertEqual(open.status, .ok, open.text)
            XCTAssertEqual(try open.json(AuthDeliveryOpenResponse.self).code, "482913")
            XCTAssertEqual(open.headers.first(name: .cacheControl), "no-store")
            try await eq(try await get(h, s, view.id).status, .opened)
            let again = try await h.signed(s.consumer, .POST, "/v1/auth-deliveries/\(view.id)/open")
            XCTAssertEqual(again.status, .conflict); XCTAssertEqual(again.errorCode, .alreadyOpened)
            // The secret row is gone (ST-PRIV-03).
            try await eq(try await AuthDeliverySecretRecord.query(on: h.db).count(), 0)
            let done = try await h.business(s.b, .POST, "/v1/business/auth-deliveries/\(view.id)/complete", body: try ViadereJSON.encode(AuthDeliveryCompleteRequest(outcome: .succeeded)), idempotencyKey: "c1")
            XCTAssertEqual(try done.json(AuthDeliveryView.self).status, .completed)
        }
    }

    /// ST-DLV-03: only the business completes, and only after an open.
    func testCompleteBeforeOpenIsRefusedAndSentNeverMeansSuccess() async throws {
        try await harness { h in
            let s = try await scene(h)
            let view = try await created(h, s)
            try await h.runJobs()
            for _ in 0..<2 {
                let r = try await h.business(s.b, .POST, "/v1/business/auth-deliveries/\(view.id)/complete", body: try ViadereJSON.encode(AuthDeliveryCompleteRequest(outcome: .succeeded)), idempotencyKey: UUID().uuidString)
                XCTAssertEqual(r.status, .conflict, r.text)
            }
            try await eq(try await get(h, s, view.id).status, .sent)
        }
    }

    // MARK: Strict body, idempotency (ST-GW-10, ST-GW-11, ST-TOTP-01, ST-DLV-04/05)

    func testTenantIdAudienceUnknownMembersAndOtpauthAndSmsAreRefused() async throws {
        try await harness { h in
            let s = try await scene(h)
            for extra: [String: Any] in [["tenant_id": "x"], ["audience": "x"], ["channels": ["sms"]], ["channels": ["email"]], ["fallback": ["email": ["address": "a@b.co"]]],
                                         ["correlation_id": "otpauth://totp/x"], ["variables": ["reference": "OTPAUTH://x"]]] {
                let r = try await create(h, s.b, otpBody(s, extra: extra))
                XCTAssertEqual(r.status, .unprocessableEntity, "\(extra) \(r.text)")
                XCTAssertEqual(r.errorCode, .validationFailed)
            }
            try await eq(try await AuthDeliveryRecord.query(on: h.db).count(), 0)
        }
    }

    func testIdempotencyReplayConflictAndRequestIdUniqueness() async throws {
        try await harness { h in
            let s = try await scene(h)
            let body = otpBody(s, id: "r-1")
            let first = try await create(h, s.b, body, key: "k1")
            XCTAssertEqual(first.status, .created)
            let replay = try await create(h, s.b, body, key: "k1")
            XCTAssertEqual(replay.status, .ok)
            XCTAssertEqual(try replay.json(AuthDeliveryView.self).id, try first.json(AuthDeliveryView.self).id)
            let other = otpBody(s, id: "r-2")
            try await eq(try await create(h, s.b, other, key: "k1").errorCode, .idempotencyConflict)
            // Same request id, different request, new key.
            let changed = otpBody(s, id: "r-1", extra: ["otp": ["code": "111111", "code_kind": "otp"]])
            try await eq(try await create(h, s.b, changed, key: "k2").errorCode, .idempotencyConflict)
            // Same request id and same request under a new key replays.
            try await eq(try await create(h, s.b, body, key: "k3").status, .ok)
            try await eq(try await AuthDeliveryRecord.query(on: h.db).count(), 1)
            // The header is required.
            let missing = try await h.business(s.b, .POST, "/v1/business/auth-deliveries", body: body)
            XCTAssertEqual(missing.status, .unprocessableEntity)
        }
    }

    // MARK: Tenancy (ST-TEN-01, 02, 04, 06)

    func testCrossTenantAccessIsAnIndistinguishable404AndAudited() async throws {
        try await harness { h in
            let s = try await scene(h)
            let other = try await h.makeBusiness(name: "Contoso", handle: "contoso")
            let view = try await created(h, s)
            let unknown = AuthDeliveryID()
            let foreign = try await h.business(other, .GET, "/v1/business/auth-deliveries/\(view.id)")
            let missing = try await h.business(other, .GET, "/v1/business/auth-deliveries/\(unknown)")
            XCTAssertEqual(foreign.status, .notFound)
            XCTAssertEqual(foreign.text.replacingOccurrences(of: #""requestId":"[^"]*""#, with: "", options: .regularExpression),
                           missing.text.replacingOccurrences(of: #""requestId":"[^"]*""#, with: "", options: .regularExpression))
            for path in ["cancel", "complete"] {
                let r = try await h.business(other, .POST, "/v1/business/auth-deliveries/\(view.id)/\(path)", body: path == "complete" ? try ViadereJSON.encode(AuthDeliveryCompleteRequest(outcome: .succeeded)) : nil, idempotencyKey: UUID().uuidString)
                XCTAssertEqual(r.status, .notFound)
            }
            try await eq(try await get(h, s, view.id).status, .queued)
            let refused = try await AuditEventRecord.query(on: h.db).filter(\.$action == "auth_delivery.cross_tenant_refused").count()
            XCTAssertGreaterThan(refused, 0)
            // ST-TEN-02: another tenant cannot address this customer.
            let r = try await create(h, other, otpBody(s))
            XCTAssertEqual(r.status, .notFound); XCTAssertEqual(r.errorCode, .notDeliverable)
        }
    }

    func testNonDisclosureUnknownSubjectAndNoDeviceLookIdentical() async throws {
        try await harness { h in
            let s = try await scene(h)
            var unknownS = s
            unknownS.subject = SubjectRef("sub_" + Base64URL.encode(Data(repeating: 7, count: 32)))!
            let noDevice = try await h.readyConsumer(name: "NoApp")
            _ = try await h.connect(noDevice, to: s.b)
            try await DeviceRecord.query(on: h.db).filter(\.$consumerId == noDevice.id.uuid).set(\.$revokedAt, to: h.clock.now()).update()
            var noDeviceS = s
            noDeviceS.subject = h.subjectRef(s.b, noDevice)
            let a = try await create(h, s.b, otpBody(unknownS))
            let b = try await create(h, s.b, otpBody(noDeviceS))
            XCTAssertEqual(a.status, .notFound); XCTAssertEqual(b.status, .notFound)
            let scrub: (HTTPResult) -> String = { $0.text.replacingOccurrences(of: #""requestId":"[^"]*""#, with: "", options: .regularExpression) }
            XCTAssertEqual(scrub(a), scrub(b))
            XCTAssertEqual(a.errorCode, .notDeliverable)
        }
    }

    func testDelegatesNeverSeeOpenOrDenyAPrincipalsDelivery() async throws {
        try await harness { h in
            let s = try await scene(h)
            let delegate = try await h.readyConsumer(name: "Sam")
            _ = try await h.shareAccess(from: s.consumer, to: delegate, purposes: [.transactional], businesses: [s.b])
            let view = try await created(h, s)
            try await eq(try await h.signed(delegate, .GET, "/v1/auth-deliveries").json([AuthDeliveryDisplay].self).count, 0)
            for (method, path) in [(NIOHTTP1.HTTPMethod.GET, ""), (.POST, "/open"), (.POST, "/deny")] {
                try await eq(try await h.signed(delegate, method, "/v1/auth-deliveries/\(view.id)\(path)").status, .notFound, path)
            }
            try await eq(try await get(h, s, view.id).status, .queued)
        }
    }

    // MARK: Budgets, silence, grouping (ST-DLV-09, revision 3)

    /// ST-DLV-09: exhausting every per-subject budget never stops the victim's own sign-in: created, silent, openable from the inbox.
    func testOverBudgetDeliveriesAreStillCreatedSilentAndOpenable() async throws {
        try await harness { h in
            let s = try await scene(h)
            for i in 0..<5 { _ = try await created(h, s, id: "spam-\(i)") }
            try await h.runJobs()
            let pushed = h.push.sent.count
            XCTAssertEqual(pushed, 5)
            let victim = try await created(h, s, id: "mine")
            try await h.runJobs()
            XCTAssertEqual(h.push.sent.count, pushed, "silent: no alert push")
            let inbox = try await h.signed(s.consumer, .GET, "/v1/auth-deliveries").json([AuthDeliveryDisplay].self)
            XCTAssertTrue(inbox.first { $0.id == victim.id }?.silent == true)
            let open = try await h.signed(s.consumer, .POST, "/v1/auth-deliveries/\(victim.id)/open")
            XCTAssertEqual(open.status, .ok, open.text)
        }
    }

    /// Revision 3: replacement only with a matching `session_handle`; nothing is cancelled by count.
    func testSupersessionNeedsAMatchingSessionHandle() async throws {
        try await harness { h in
            let s = try await scene(h)
            let mine = try await created(h, s, id: "mine", extra: ["session_handle": "sess_mine"])
            // An attacker's sign-ins (no handle, or another handle) never cancel it.
            _ = try await created(h, s, id: "att-1")
            _ = try await created(h, s, id: "att-2", extra: ["session_handle": "sess_other"])
            try await eq(try await get(h, s, mine.id).status, .queued)
            // The same session asking again replaces its own earlier prompt.
            let again = try await created(h, s, id: "mine-2", extra: ["session_handle": "sess_mine"])
            let old = try await get(h, s, mine.id)
            XCTAssertEqual(old.status, .cancelled); XCTAssertEqual(old.reason, "superseded")
            try await eq(try await get(h, s, again.id).status, .queued)
            let open = try await h.signed(s.consumer, .GET, "/v1/auth-deliveries").json([AuthDeliveryDisplay].self)
            XCTAssertEqual(open.count, 3)
            try await eq(try await h.business(s.b, .POST, "/v1/business/auth-deliveries", body: otpBody(s, extra: ["session_handle": "bad handle"]), idempotencyKey: "x").status, .unprocessableEntity)
        }
    }

    /// Revision 3: a `destination_unverified` denial does not count toward the fatigue limit; reported denials do (and only make alerts quiet).
    func testDestinationUnverifiedDenialsDoNotCountTowardFatigue() async throws {
        try await harness { h in
            let s = try await scene(h)
            func deny(_ body: AuthDeliveryDenyRequest, _ i: Int) async throws {
                let v = try await created(h, s, id: "d-\(i)-\(body.reason ?? "r")")
                let r = try await h.signed(s.consumer, .POST, "/v1/auth-deliveries/\(v.id)/deny", body: try ViadereJSON.encode(body))
                XCTAssertEqual(r.status, .ok, r.text)
                try await eq(try await get(h, s, v.id).status, .denied)
            }
            for i in 0..<3 { try await deny(AuthDeliveryDenyRequest(reason: "destination_unverified"), i) }
            try await eq(try await AuthDeliveryService(db: h.db, ctx: h.ctx).reportedDenials(businessId: s.b.id.uuid, consumerId: s.consumer.id.uuid), 0)
            for i in 0..<3 { try await deny(AuthDeliveryDenyRequest(report: true), i + 10) }
            try await eq(try await AuthDeliveryService(db: h.db, ctx: h.ctx).reportedDenials(businessId: s.b.id.uuid, consumerId: s.consumer.id.uuid), 3)
            // Reports make the next delivery silent, never refused.
            let next = try await created(h, s, id: "after")
            let row = try await AuthDeliveryRecord.find(next.id.uuid, on: h.db)
            XCTAssertEqual(row?.silent, true)
            let unverified = try await AuditEventRecord.query(on: h.db).filter(\.$action == "auth_delivery.destination_unverified").count()
            XCTAssertGreaterThan(unverified, 0)
        }
    }

    // MARK: Destinations (ST-ML-03/04/10/13)

    func testBusinessLinksFailClosedUntilAnAuthorityKeyExists() async throws {
        try await harness { h in
            let s = try await scene(h)
            // The default directory (no authority yet) knows no key: fail closed (ST-ML-13).
            let r = try await h.business(s.b, .POST, "/v1/business/auth-deliveries", body: try await linkBody(h, s), idempotencyKey: "a")
            XCTAssertEqual(r.status, .created, "keys registered by the fixture: \(r.text)")
            let unsigned = try await h.business(s.b, .POST, "/v1/business/auth-deliveries", body: try await linkBody(h, s, id: "l2", sign: false), idempotencyKey: "b")
            XCTAssertEqual(unsigned.status, .unprocessableEntity); XCTAssertEqual(unsigned.errorCode, .destinationSignatureRequired)
            // A statement for another URL (tampered after signing) is refused at create too.
            let swapped = try await h.business(s.b, .POST, "/v1/business/auth-deliveries",
                                               body: try await linkBody(h, s, id: "l3", url: "https://\(s.host)/m?t=evil", statementURL: "https://\(s.host)/m?t=abc"), idempotencyKey: "c")
            XCTAssertEqual(swapped.errorCode, .destinationSignatureRequired)
        }
        // No tenant key at all (default directory): every business-mode link fails closed.
        try await withHarness { h in
            let s = try await scene(h)
            let r = try await h.business(s.b, .POST, "/v1/business/auth-deliveries", body: try await linkBody(h, s), idempotencyKey: "a")
            XCTAssertEqual(r.status, .unprocessableEntity); XCTAssertEqual(r.errorCode, .destinationSignatureRequired)
            try await eq(try await AuthDeliveryRecord.query(on: h.db).count(), 0)
        }
    }

    func testDestinationHostPolicy() async throws {
        try await harness { h in
            let s = try await scene(h)
            for url in ["https://evil.example.net/m", "https://\(s.host)/m?next=https://evil.example.net/", "http://\(s.host)/m", "https://\(s.host):8443/m", "https://user@\(s.host)/m"] {
                let r = try await h.business(s.b, .POST, "/v1/business/auth-deliveries", body: try await linkBody(h, s, id: "u-\(url.hashValue.magnitude)", url: url, sign: false), idempotencyKey: UUID().uuidString)
                XCTAssertEqual(r.errorCode, .destinationNotAllowed, "\(url) \(r.text)")
            }
            // A host that exists but is still in its hold is not usable.
            let held = AuthDestinationHostRecord()
            held.id = UUID(); held.businessId = s.b.id.uuid; held.host = "held." + s.host.dropFirst(6); held.createdBy = "t"; held.createdAt = h.clock.now(); held.activatedAt = h.clock.now().addingTimeInterval(86_400)
            try await held.create(on: h.db)
            let r = try await h.business(s.b, .POST, "/v1/business/auth-deliveries", body: try await linkBody(h, s, id: "held", url: "https://\(held.host)/m", sign: false), idempotencyKey: "h")
            XCTAssertEqual(r.errorCode, .destinationNotAllowed)
        }
    }

    /// ST-ML-10: the api cannot rewrite a stored URL undetected: the device compares the bytes it receives with the signed digest and refuses.
    func testARewrittenStoredUrlFailsTheDeviceDigestCheck() async throws {
        try await harness { h in
            let s = try await scene(h)
            let r = try await h.business(s.b, .POST, "/v1/business/auth-deliveries", body: try await linkBody(h, s), idempotencyKey: "a")
            let id = try r.json(AuthDeliveryView.self).id
            let display = try await h.signed(s.consumer, .GET, "/v1/auth-deliveries/\(id)").json(AuthDeliveryDisplay.self)
            let statement = try AuthDestinationStatement.parse(display.destinationStatement).statement
            XCTAssertEqual(display.destinationHost, s.host)
            // Honest path.
            let open = try await h.signed(s.consumer, .POST, "/v1/auth-deliveries/\(id)/open").json(AuthDeliveryOpenResponse.self)
            try statement.verifyOpened(url: try XCTUnwrap(open.url), allowedHosts: [s.host])
        }
        try await harness { h in
            let s = try await scene(h)
            let r = try await h.business(s.b, .POST, "/v1/business/auth-deliveries", body: try await linkBody(h, s), idempotencyKey: "a")
            let id = try r.json(AuthDeliveryView.self).id
            // AS-1: rewrite the sealed URL (the api holds the key) to a look-alike on the same host.
            let found = try await AuthDeliverySecretRecord.find(id.uuid, on: h.db)
            let row = try XCTUnwrap(found)
            let evil = AuthSecretPayload(url: "https://\(s.host)/m?t=attacker", code: nil, variables: nil)
            row.ciphertext = try h.ctx.config.authDelivery.cipher.seal(try ViadereJSON.encode(evil), context: AuthDeliverySecretRecord.sealContext, rowId: id.uuid)
            try await row.update(on: h.db)
            let display = try await h.signed(s.consumer, .GET, "/v1/auth-deliveries/\(id)").json(AuthDeliveryDisplay.self)
            let statement = try AuthDestinationStatement.parse(display.destinationStatement).statement
            let open = try await h.signed(s.consumer, .POST, "/v1/auth-deliveries/\(id)/open").json(AuthDeliveryOpenResponse.self)
            XCTAssertThrowsError(try statement.verifyOpened(url: try XCTUnwrap(open.url), allowedHosts: [s.host])) { XCTAssertEqual($0 as? AuthDestinationStatementError, .urlMismatch) }
        }
    }

    // MARK: Gate, credentials (ST-GW-09, flag)

    func testTheFeatureFlagMakesEveryRouteA404() async throws {
        try await harness({ $0.authDelivery.enabled = false }) { h in
            let s = try await scene(h)
            try await eq(try await create(h, s.b, otpBody(s)).status, .notFound)
            try await eq(try await h.business(s.b, .GET, "/v1/business/auth-deliveries/\(AuthDeliveryID())").status, .notFound)
            try await eq(try await h.signed(s.consumer, .GET, "/v1/auth-deliveries").status, .notFound)
        }
    }

    func testStrictEnvironmentsDefaultTheFlagOffAndRefuseUnsafeSettings() throws {
        var env = ["ENVIRONMENT": "development"]
        XCTAssertTrue(try ServerConfig.fromEnvironment(env.merging([:]) { $1 }).authDelivery.enabled)
        var c = ServerConfig.testing()
        try c.applyAuthDeliveryEnvironment([:], production: true)
        XCTAssertFalse(c.authDelivery.enabled)
        XCTAssertEqual(c.authDelivery.liveKeyAssurance, .mtls)
        XCTAssertThrowsError(try { var x = ServerConfig.testing(); try x.applyAuthDeliveryEnvironment(["AUTH_DESTINATION_SIGNATURE_REQUIRED": "false"], production: true) }())
        XCTAssertThrowsError(try { var x = ServerConfig.testing(); try x.applyAuthDeliveryEnvironment(["AUTH_LIVE_KEY_ASSURANCE": "none"], production: true) }())
        XCTAssertThrowsError(try { var x = ServerConfig.testing(); try x.applyAuthDeliveryEnvironment(["AUTH_DELIVERY_ENABLED": "true"], production: true) }(), "needs AUTH_SECRET_KEY")
        env["X"] = "y"
    }

    func testALiveKeyNeedsMutualTLSButATestKeyReachesSandboxOnly() async throws {
        try await harness({ $0.authDelivery.liveKeyAssurance = .mtls }) { h in
            let s = try await scene(h)
            let live = try await create(h, s.b, otpBody(s))
            XCTAssertEqual(live.status, .unauthorized); XCTAssertEqual(live.errorCode, .signatureRequired)
            let test = try await BusinessAPIKeys.issue(businessId: s.b.id.uuid, name: "t", live: false, scopes: BusinessAPIKeys.Scope.all, capabilities: Capability.operational, now: h.clock.now(), on: h.db).key
            var sb = s
            sb.subject = try await h.business(s.b, .POST, "/v1/business/sandbox/relationships", key: test).json(SandboxRelationship.self).subjectRef!
            let ok = try await create(h, s.b, otpBody(sb), apiKey: test)
            XCTAssertEqual(ok.status, .created, ok.text)
            // A test key cannot reach a real customer.
            try await eq(try await create(h, s.b, otpBody(s), apiKey: test).status, .notFound)
        }
    }

    // MARK: Delivery engine (ST-DLV-01, 02, 06, 08, 07)

    func testTheDispatchDoorbellRingingTwiceSendsOnce() async throws {
        try await harness { h in
            let s = try await scene(h)
            let view = try await created(h, s)
            let dispatcher = AuthDeliveryDispatcher(db: h.db, ctx: h.ctx)
            _ = try await dispatcher.dispatch(id: view.id.uuid)
            _ = try await dispatcher.dispatch(id: view.id.uuid)
            try await h.runJobs()
            XCTAssertEqual(h.push.sent.count, 1)
            try await eq(try await get(h, s, view.id).status, .sent)
        }
    }

    func testAnAPNsFailureNeverClaimsSuccessAndTheInboxStillWorks() async throws {
        try await harness { h in
            let s = try await scene(h)
            h.push.setOutcome(.failed)
            let view = try await created(h, s)
            _ = try await AuthDeliveryDispatcher(db: h.db, ctx: h.ctx).dispatch(id: view.id.uuid)
            try await eq(try await get(h, s, view.id).status, .queued)
            let inbox = try await h.signed(s.consumer, .GET, "/v1/auth-deliveries").json([AuthDeliveryDisplay].self)
            XCTAssertEqual(inbox.count, 1)
        }
    }

    func testConcurrentOpensRevealTheSecretToExactlyOne() async throws {
        try await harness { h in
            let s = try await scene(h)
            let view = try await created(h, s)
            async let a = h.signed(s.consumer, .POST, "/v1/auth-deliveries/\(view.id)/open")
            async let b = h.signed(s.consumer, .POST, "/v1/auth-deliveries/\(view.id)/open")
            let statuses = try await [a.status, b.status].map(\.code).sorted()
            XCTAssertEqual(statuses, [200, 409])
        }
    }

    func testExpiryEndsTheDeliveryAndDeletesTheSecret() async throws {
        try await harness { h in
            let s = try await scene(h)
            let view = try await created(h, s, extra: ["expires_in_seconds": 60])
            h.clock.advance(by: 61)
            let open = try await h.signed(s.consumer, .POST, "/v1/auth-deliveries/\(view.id)/open")
            XCTAssertEqual(open.status, .gone)
            try await eq(try await get(h, s, view.id).status, .expired)
            try await eq(try await AuthDeliverySecretRecord.query(on: h.db).count(), 0)
        }
    }

    /// ST-PRIV-03/04: only ciphertext at rest while open (bound to the row), gone at the end, metadata purged after 30 days.
    func testSecretsAreSealedRowBoundDeletedAtTheEndAndMetadataPurged() async throws {
        try await harness { h in
            let s = try await scene(h)
            let view = try await created(h, s, extra: ["variables": ["reference": "INV 77"]])
            let foundSecret = try await AuthDeliverySecretRecord.find(view.id.uuid, on: h.db)
            let secret = try XCTUnwrap(foundSecret)
            XCTAssertFalse(secret.ciphertext.contains("482913"))
            XCTAssertThrowsError(try h.ctx.config.authDelivery.cipher.open(secret.ciphertext, context: AuthDeliverySecretRecord.sealContext, rowId: UUID()))
            XCTAssertThrowsError(try h.ctx.cipher.open(secret.ciphertext, context: AuthDeliverySecretRecord.sealContext, rowId: view.id.uuid), "not the data key")
            let foundRow = try await AuthDeliveryRecord.find(view.id.uuid, on: h.db)
            let row = try XCTUnwrap(foundRow)
            XCTAssertNotNil(row.variablesSHA256)
            // The business view and the audit trail carry no secret or variable.
            let viewText = try await h.business(s.b, .GET, "/v1/business/auth-deliveries/\(view.id)").text
            XCTAssertFalse(viewText.contains("INV 77"))
            let audits = try await AuditEventRecord.query(on: h.db).all()
            XCTAssertFalse(audits.contains { $0.metadataJSON.contains("482913") || $0.metadataJSON.contains("INV 77") })
            let cancel = try await h.business(s.b, .POST, "/v1/business/auth-deliveries/\(view.id)/cancel", idempotencyKey: "x")
            XCTAssertEqual(try cancel.json(AuthDeliveryView.self).status, .cancelled)
            try await eq(try await AuthDeliverySecretRecord.query(on: h.db).count(), 0)
            try await eq(try await h.signed(s.consumer, .POST, "/v1/auth-deliveries/\(view.id)/open").status, .gone)
            h.clock.advance(by: 31 * 86_400)
            _ = try await AuthDeliveryService(db: h.db, ctx: h.ctx).sweep()
            try await eq(try await AuthDeliveryRecord.query(on: h.db).count(), 0)
            try await eq(try await AuthDeliveryEventRecord.query(on: h.db).count(), 0)
        }
    }

    func testRateLimitNamespacesFailClosedWhenTheStoreIsDown() async {
        let store = DatabaseRateLimitStore(database: { nil })
        for name in ["authdl-tenant", "authdl-subject", "authdl-open", "authdl-deny", "authlink-redeem", "bizsig-nonce", "authority-challenge"] {
            let d = await store.take(key: "\(name)|k", rule: .perMinute(100), cost: 1, now: Date())
            XCTAssertFalse(d.allowed, name)
        }
        let other = await store.take(key: "harmless|k", rule: .perMinute(100), cost: 1, now: Date())
        XCTAssertTrue(other.allowed)
    }

    func testTenantFloodIsTheOnlyBudgetThatRefuses() async throws {
        try await harness({ $0.authDelivery.tenantRate = RateRule(capacity: 2, perMinute: 1) }) { h in
            let s = try await scene(h)
            for i in 0..<2 { _ = try await created(h, s, id: "f-\(i)") }
            let r = try await create(h, s.b, otpBody(s, id: "f-3"))
            XCTAssertEqual(r.status, .tooManyRequests)
        }
    }

    // MARK: Webhooks (ST-WH-03, ST-WH-05, migration)

    func testAuthEventsAreV2OnlyOpaqueAndSignedWithV2() async throws {
        try await harness { h in
            let s = try await scene(h)
            let url = URL(string: "https://hooks.example.com/viadere?x=1")!
            let events: [WebhookEventType] = [.authDeliveryCreated, .authDeliveryOpened, .authDeliverySent]
            let v1 = try await h.businessPost(s.b, "/v1/business/webhooks", CreateWebhookRequest(url: url, events: events, envelopeVersion: WebhookEnvelopeV2.version))
            XCTAssertEqual(v1.status, .unprocessableEntity); XCTAssertEqual(v1.errorCode, .signatureVersionRequired)
            let noEnvelope = try await h.businessPost(s.b, "/v1/business/webhooks", CreateWebhookRequest(url: url, events: events, signatureVersion: .v2))
            XCTAssertEqual(noEnvelope.errorCode, .signatureVersionRequired)
            let ok = try await h.businessPost(s.b, "/v1/business/webhooks", CreateWebhookRequest(url: url, events: events, envelopeVersion: WebhookEnvelopeV2.version, signatureVersion: .v2))
            XCTAssertEqual(ok.status, .created, ok.text)
            let secret = try ok.json(WebhookSecretResponse.self)
            _ = try await created(h, s)
            try await h.runJobs()
            try await h.runJobs()
            let received = h.webhooks.received.filter { $0.headers[ViadereHeader.eventType]?.hasPrefix("auth.") == true }
            XCTAssertGreaterThanOrEqual(received.count, 2)
            let first = try XCTUnwrap(received.first)
            let header = try XCTUnwrap(first.headers[ViadereHeader.signature])
            XCTAssertFalse(header.contains("v1="), "auth events never carry a v1 entry")
            XCTAssertFalse(String(decoding: first.body, as: UTF8.self).contains("482913"))
            let context = try XCTUnwrap(WebhookSignatureV2.Context(endpoint: url, eventId: try XCTUnwrap(first.headers[ViadereHeader.eventId]), tenantId: try XCTUnwrap(first.headers[ViadereHeader.tenant])))
            let kid = try XCTUnwrap(first.headers[ViadereHeader.keyId])
            XCTAssertNoThrow(try WebhookSignatureV2.verify(header: header, body: first.body, contentDigestHeader: first.headers[ViadereHeader.contentDigest], context: context,
                                                           expectedTenant: context.tenantId, keys: [kid: secret.secret], now: h.clock.now()))
            // A replay to another endpoint path fails.
            let other = WebhookSignatureV2.Context(host: "hooks.example.com", pathAndQuery: "/other", eventId: context.eventId, tenantId: context.tenantId)
            XCTAssertThrowsError(try WebhookSignatureV2.verify(header: header, body: first.body, contentDigestHeader: first.headers[ViadereHeader.contentDigest], context: other,
                                                               expectedTenant: context.tenantId, keys: [kid: secret.secret], now: h.clock.now()))
            // Other tenant's subscription never receives this tenant's events (ST-TEN-03).
            let b2 = try await h.makeBusiness(name: "Contoso", handle: "contoso")
            _ = try await h.businessPost(b2, "/v1/business/webhooks", CreateWebhookRequest(url: URL(string: "https://other.example.com/x")!, events: events, envelopeVersion: WebhookEnvelopeV2.version, signatureVersion: .v2))
            let before = h.webhooks.received.count
            _ = try await created(h, s, id: "again")
            try await h.runJobs()
            XCTAssertTrue(h.webhooks.received.dropFirst(before).allSatisfy { $0.url.host != "other.example.com" })
        }
    }

    /// ST-WH-03 (defense in depth): even a v1 subscription row that somehow names an auth event never receives it.
    func testAV1SubscriptionNeverReceivesAuthEvents() async throws {
        try await harness { h in
            let s = try await scene(h)
            let row = WebhookSubscriptionRecord()
            row.id = UUID(); row.businessId = s.b.id.uuid; row.url = "https://hooks.example.com/v1only"; row.events = "auth.delivery.created"
            row.secretCiphertext = try h.ctx.cipher.seal("whsec_x", context: "webhook_subscriptions.secret", rowId: row.id!)
            row.active = true; row.createdAt = h.clock.now(); row.secretVersion = 1; row.signatureVersion = "v1"
            try await row.create(on: h.db)
            _ = try await created(h, s)
            try await h.runJobs()
            let queued = try await WebhookDeliveryRecord.query(on: h.db).filter(\.$subscriptionId == row.id!).count()
            XCTAssertEqual(queued, 0)
            XCTAssertTrue(h.webhooks.received.filter { $0.url.host == "hooks.example.com" }.isEmpty)
        }
    }

    func testMovingAV1EndpointToV2DualSignsOldEventsForThirtyDays() async throws {
        try await harness { h in
            let s = try await scene(h)
            let url = URL(string: "https://hooks.example.com/old")!
            let sub = try await h.businessPost(s.b, "/v1/business/webhooks", CreateWebhookRequest(url: url, events: [.relationshipDisconnected])).json(WebhookSecretResponse.self)
            let patch = try await h.business(s.b, .PATCH, "/v1/business/webhooks/\(sub.subscription.id)", body: try ViadereJSON.encode(UpdateWebhookRequest(signatureVersion: .v2)), idempotencyKey: "p1")
            XCTAssertEqual(patch.status, .ok, patch.text)
            XCTAssertEqual(try patch.json(WebhookSubscription.self).signatureVersion, .v2)
            let again = try await h.business(s.b, .PATCH, "/v1/business/webhooks/\(sub.subscription.id)", body: try ViadereJSON.encode(UpdateWebhookRequest(signatureVersion: .v2)), idempotencyKey: "p2")
            XCTAssertEqual(again.status, .ok)
            _ = try await h.business(s.b, .POST, "/v1/business/webhooks/\(sub.subscription.id)/test")
            try await h.runJobs()
            let sent = try XCTUnwrap(h.webhooks.received.last { $0.url == url })
            let header = try XCTUnwrap(sent.headers[ViadereHeader.signature])
            XCTAssertTrue(header.contains("v2=") && header.contains("v1="), header)
            XCTAssertNotNil(sent.headers[ViadereHeader.tenant])
            // After the window the v1 entry disappears.
            h.clock.advance(by: 31 * 86_400)
            _ = try await h.business(s.b, .POST, "/v1/business/webhooks/\(sub.subscription.id)/test")
            try await h.runJobs()
            XCTAssertFalse(try XCTUnwrap(h.webhooks.received.last { $0.url == url }.flatMap { $0.headers[ViadereHeader.signature] }).contains("v1="))
        }
    }

    func testSampleAuthEventsGoToV2EndpointsWithTestKeysOnly() async throws {
        try await harness { h in
            let s = try await scene(h)
            let url = URL(string: "https://hooks.example.com/v")!
            let sub = try await h.businessPost(s.b, "/v1/business/webhooks", CreateWebhookRequest(url: url, events: [.authDeliveryCreated], envelopeVersion: WebhookEnvelopeV2.version, signatureVersion: .v2)).json(WebhookSecretResponse.self)
            let body = try ViadereJSON.encode(AuthWebhookTestRequest(webhookId: sub.subscription.id, type: "auth.delivery.opened"))
            try await eq(try await h.business(s.b, .POST, "/v1/business/webhooks/test", body: body).status, .forbidden, "live key")
            let test = try await BusinessAPIKeys.issue(businessId: s.b.id.uuid, name: "t", live: false, scopes: BusinessAPIKeys.Scope.all, capabilities: Capability.operational, now: h.clock.now(), on: h.db).key
            let r = try await h.business(s.b, .POST, "/v1/business/webhooks/test", body: body, key: test)
            XCTAssertEqual(r.status, .ok, r.text)
            try await h.runJobs()
            XCTAssertNotNil(h.webhooks.received.last { $0.url == url })
        }
    }

    // MARK: Logging (ST-PRIV-01)

    func testAuthRoutesLogOnlyAllowListedFields() {
        let id = AuthDeliveryID().description
        XCTAssertEqual(AuthLogAllowList.routeTemplate("/v1/auth-deliveries/\(id)/open?token=SECRET"), "/v1/auth-deliveries/:id/open")
        XCTAssertTrue(AuthLogAllowList.isAuthPath("/v1/business/auth-deliveries"))
        let kept = AuthLogAllowList.filter(["method": "POST", "path": "/x", "status": "200", "ms": "1", "requestId": "r", "query": "token=SECRET", "body": "482913", "authorization": "Bearer x"])
        XCTAssertEqual(Set(kept.keys), ["method", "path", "status", "ms", "requestId"])
    }

    // MARK: Contract

    func testNoSMSAdapterOrOTPVerificationRouteExists() async throws {
        try await harness { h in
            let s = try await scene(h)
            for path in ["/v1/auth-deliveries/verify", "/v1/business/auth-deliveries/verify", "/v1/business/otp/verify"] {
                let r = try await h.business(s.b, .POST, path, body: Data("{}".utf8), idempotencyKey: "z")
                XCTAssertTrue([.notFound, .methodNotAllowed].contains(r.status), path)
            }
            _ = try await created(h, s); try await h.runJobs()
            XCTAssertTrue(h.texts.sent.isEmpty, "no SMS for any auth method")
        }
    }
}
