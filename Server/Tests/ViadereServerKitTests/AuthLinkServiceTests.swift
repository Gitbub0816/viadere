@preconcurrency import Crypto
import Fluent
import Foundation
import NIOHTTP1
import Vapor
import ViadereAuthorityKit
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// The Viadere link service end to end (`link_mode: "viadere"`, ADR-0021 §5; ledger S6-05) against an in-process authority, and the tenant-record
/// relay (ADR-0031 §2). Each exploit-path test fails if the control it names is removed.
final class AuthLinkServiceTests: AuthDeliveryTestBase {
    static let verifier = AuthLinkRedemptionTests.verifier
    static var challenge: String { Base64URL.encode(Data(SHA256.hash(data: Data(verifier.utf8)))) }

    func linkServiceBody(_ s: Scene, id: String = UUID().uuidString, client: String = AuthLinkRedemptionTests.linkClient,
                         returnURL: String = AuthLinkRedemptionTests.returnURL, purpose: String = "sign_in", crossDevice: Bool? = nil) -> Data {
        var destination: [String: Any] = ["link_mode": "viadere", "link_client_id": client, "return_url": returnURL,
                                          "code_challenge": Self.challenge, "code_challenge_method": "S256"]
        if let crossDevice { destination["cross_device"] = crossDevice }
        return try! JSONSerialization.data(withJSONObject: ["method": "magic_link", "request_id": id, "subject_ref": s.subject.rawValue, "purpose": purpose,
                                                            "template": "auth.sign_in_link.v1", "destination": destination])
    }

    func linkHarness(_ body: (TestHarness) async throws -> Void) async throws {
        try await harness({ $0.authDelivery.linkServiceEnabled = true }, body)
    }

    /// A scene whose customer's account is in the authority, with the business's link client registered there.
    func setUp(_ h: TestHarness) async throws -> (Scene, AuthLinkRedemptionTests.Authority) {
        let s = try await scene(h)
        let authority = try await AuthLinkRedemptionTests.makeAuthority(businessId: s.b.id.uuid, accountId: s.consumer.id.uuid)
        h.app.authorityTransport = InProcessAuthorityTransport(app: authority.app)
        return (s, authority)
    }

    func display(_ h: TestHarness, _ s: Scene, _ id: AuthDeliveryID) async throws -> AuthDeliveryDisplay {
        try await h.signed(s.consumer, .GET, "/v1/auth-deliveries/\(id)").json(AuthDeliveryDisplay.self)
    }

    func challengeStatement(_ h: TestHarness, _ s: Scene, _ id: AuthDeliveryID) async throws -> String {
        let shown = try await display(h, s, id)
        return try XCTUnwrap(shown.authorityChallenge)
    }

    /// The device: verify the relayed challenge against the pinned key and answer it with a code hash (same device).
    func factor(_ authority: AuthLinkRedemptionTests.Authority, statement: String, code: String, key: SoftwareP256SigningKey? = nil) async throws -> String {
        let verified = try AuthorityStatementVerifier.verifyChallenge(statement, pinnedKeys: [authority.statementKey], environment: .staging, now: AuthLinkRedemptionTests.now)
        XCTAssertEqual(verified.purpose, .linkOpen)
        XCTAssertEqual(verified.returnURL, AuthLinkRedemptionTests.returnURL)
        let claims = try FactorAssertionClaims.answering(verified, decision: .approve, userVerification: .biometric, match: nil,
                                                         codeHash: Base64URL.encode(Data(SHA256.hash(data: Data(code.utf8)))), now: AuthLinkRedemptionTests.now)
        return try await FactorAssertion.sign(claims, with: key ?? authority.deviceKey)
    }

    /// The device answering any challenge with exactly the members given (to exercise every mismatch between the two modes).
    func answer(_ authority: AuthLinkRedemptionTests.Authority, statement: String, decision: FactorDecision = .approve, match: String?, codeHash: String?) async throws -> String {
        let verified = try AuthorityStatementVerifier.verifyChallenge(statement, pinnedKeys: [authority.statementKey], environment: .staging, now: AuthLinkRedemptionTests.now)
        let claims = try FactorAssertionClaims.answering(verified, decision: decision, userVerification: .biometric, match: match, codeHash: codeHash,
                                                         now: AuthLinkRedemptionTests.now)
        return try await FactorAssertion.sign(claims, with: authority.deviceKey)
    }

    func redeem(_ h: TestHarness, _ b: TestBusiness, ach: String, verifier: String = AuthLinkServiceTests.verifier) async throws -> HTTPResult {
        try await h.business(b, .POST, "/v1/business/auth-links/redeem",
                             body: try ViadereJSON.encode(AuthLinkRedeemRequest(linkClientId: AuthLinkRedemptionTests.linkClient, ach: ach, codeVerifier: verifier)))
    }

    func evidence(_ h: TestHarness, _ s: Scene, _ id: AuthDeliveryID, _ factor: String) async throws -> HTTPResult {
        try await h.signedPost(s.consumer, "/v1/auth-deliveries/\(id)/link-evidence", AuthLinkEvidenceRequest(factor: factor))
    }

    func redeem(_ h: TestHarness, _ b: TestBusiness, code: String, verifier: String = AuthLinkServiceTests.verifier) async throws -> HTTPResult {
        try await h.business(b, .POST, "/v1/business/auth-links/redeem",
                             body: try ViadereJSON.encode(AuthLinkRedeemRequest(linkClientId: AuthLinkRedemptionTests.linkClient, code: code, codeVerifier: verifier)))
    }

    // MARK: The flow

    func testCreateWithAnAuthorityChallengeApproveOnTheDeviceAndCompleteOnRedemption() async throws {
        try await linkHarness { h in
            let (s, authority) = try await setUp(h)
            let created = try await create(h, s.b, linkServiceBody(s))
            XCTAssertEqual(created.status, .created, created.text)
            let view = try created.json(AuthDeliveryView.self)
            try await h.runJobs()
            let shown = try await display(h, s, view.id)
            XCTAssertEqual(shown.linkMode, .viadere)
            XCTAssertNil(shown.destinationStatement)
            XCTAssertEqual(shown.destinationHost, "shop.example.com")
            let statement = try XCTUnwrap(shown.authorityChallenge)
            let code = Base64URL.encode(SecureToken.randomBytes(32))
            let answered = try await evidence(h, s, view.id, try await factor(authority, statement: statement, code: code))
            XCTAssertEqual(answered.status, .ok, answered.text)
            XCTAssertEqual(try answered.json(AuthLinkEvidenceResponse.self).decision, .approve)
            try await eq(try await get(h, s, view.id).status, .opened)
            let grant = try await redeem(h, s.b, code: code)
            XCTAssertEqual(grant.status, .ok, grant.text)
            XCTAssertEqual(try grant.json(AuthLinkRedeemResponse.self).deliveryId, view.id.description)
            try await eq(try await get(h, s, view.id).status, .completed)
            // Single use: the same code again is refused, and the delivery stays completed.
            await XCTAssertEqualAsync(try await redeem(h, s.b, code: code).status, .badRequest)
            try await eq(try await get(h, s, view.id).status, .completed)
            try await authority.app.asyncShutdown()
        }
    }

    // MARK: Cross device (ADR-0021 §6)

    func testCrossDeviceTheBusinessShowsTheNumberThePhoneTypesItAndTheSessionRedeemsWithoutACode() async throws {
        try await linkHarness { h in
            let (s, authority) = try await setUp(h)
            let created = try await create(h, s.b, linkServiceBody(s, crossDevice: true))
            XCTAssertEqual(created.status, .created, created.text)
            let view = try created.json(AuthDeliveryView.self)
            // The business gets the number to show on its initiating screen and the challenge reference to redeem with.
            let cross = try XCTUnwrap(view.crossDevice)
            XCTAssertTrue(AuthorityChallengeID.isValid(cross.ach))
            let number = try XCTUnwrap(cross.matchCode)
            XCTAssertTrue(number.count == 2 && number.allSatisfy(\.isNumber), number)
            try await h.runJobs()
            // The phone sees the authority's statement asking for a number; the api never hands the number to the phone.
            let shown = try await h.signed(s.consumer, .GET, "/v1/auth-deliveries/\(view.id)")
            XCTAssertFalse(shown.text.contains("match_code") || shown.text.contains(cross.ach), shown.text)
            let statement = try XCTUnwrap(try shown.json(AuthDeliveryDisplay.self).authorityChallenge)
            let verified = try AuthorityStatementVerifier.verifyChallenge(statement, pinnedKeys: [authority.statementKey], environment: .staging, now: AuthLinkRedemptionTests.now)
            XCTAssertTrue(verified.matchRequired)
            // Typed correctly: accepted, and the answer carries a decision only (no code, no grant, nothing to open).
            let answered = try await evidence(h, s, view.id, try await answer(authority, statement: statement, match: number, codeHash: nil))
            XCTAssertEqual(answered.status, .ok, answered.text)
            XCTAssertEqual(try JSONSerialization.jsonObject(with: Data(answered.text.utf8)) as? [String: String], ["decision": "approve"])
            // The initiating session polls, sees `opened`, and redeems with the challenge reference and its PKCE verifier.
            let polled = try await get(h, s, view.id)
            XCTAssertEqual(polled.status, .opened)
            XCTAssertEqual(polled.crossDevice?.ach, cross.ach)
            XCTAssertNil(polled.crossDevice?.matchCode, "the number is gone once the delivery is answered")
            let grant = try await redeem(h, s.b, ach: cross.ach)
            XCTAssertEqual(grant.status, .ok, grant.text)
            XCTAssertEqual(try grant.json(AuthLinkRedeemResponse.self).deliveryId, view.id.description)
            try await eq(try await get(h, s, view.id).status, .completed)
            // Single use.
            await XCTAssertEqualAsync(try await redeem(h, s.b, ach: cross.ach).status, .badRequest)
            try await authority.app.asyncShutdown()
        }
    }

    func testACrossDeviceApprovalNeverRevealsOrRegistersACode() async throws {
        try await linkHarness { h in
            let (s, authority) = try await setUp(h)
            let view = try await create(h, s.b, linkServiceBody(s, crossDevice: true)).json(AuthDeliveryView.self)
            let number = try XCTUnwrap(view.crossDevice?.matchCode)
            let statement = try await challengeStatement(h, s, view.id)
            // A phone (or a relay) that also slips in a code hash is refused: the cross-device path never registers a code.
            let code = Base64URL.encode(SecureToken.randomBytes(32))
            let hash = Base64URL.encode(Data(SHA256.hash(data: Data(code.utf8))))
            await XCTAssertEqualAsync(try await evidence(h, s, view.id, try await answer(authority, statement: statement, match: number, codeHash: hash)).status, .unauthorized)
            // The genuine answer is accepted; the code above was never registered, so it redeems nothing.
            await XCTAssertEqualAsync(try await evidence(h, s, view.id, try await answer(authority, statement: statement, match: number, codeHash: nil)).status, .ok)
            await XCTAssertEqualAsync(try await redeem(h, s.b, code: code).status, .badRequest)
            try await eq(try await get(h, s, view.id).status, .opened)
            try await authority.app.asyncShutdown()
        }
    }

    func testASameDeviceChallengeCannotBeAnsweredAsCrossDeviceAndViceVersa() async throws {
        try await linkHarness { h in
            let (s, authority) = try await setUp(h)
            // Same device (the default): a number and no code hash is refused, and the challenge reference never redeems it.
            let same = try await create(h, s.b, linkServiceBody(s)).json(AuthDeliveryView.self)
            XCTAssertNil(same.crossDevice, "a same-device delivery shows no number and no challenge reference")
            let sameStatement = try await challengeStatement(h, s, same.id)
            await XCTAssertEqualAsync(try await evidence(h, s, same.id, try await answer(authority, statement: sameStatement, match: "42", codeHash: nil)).status, .unauthorized)
            await XCTAssertEqualAsync(try await evidence(h, s, same.id, try await answer(authority, statement: sameStatement, match: nil, codeHash: nil)).status, .unauthorized)
            let code = Base64URL.encode(SecureToken.randomBytes(32))
            await XCTAssertEqualAsync(try await evidence(h, s, same.id, try await factor(authority, statement: sameStatement, code: code)).status, .ok)
            let sameRow = try await AuthDeliveryRecord.find(same.id.uuid, on: h.app.db)
            let sameAch = try XCTUnwrap(sameRow?.linkChallengeId)
            await XCTAssertEqualAsync(try await redeem(h, s.b, ach: sameAch).status, .badRequest)
            await XCTAssertEqualAsync(try await redeem(h, s.b, code: code).status, .ok)
            // Cross device: a code hash without the number is refused, and so is an approve without the number.
            let cross = try await create(h, s.b, linkServiceBody(s, crossDevice: true)).json(AuthDeliveryView.self)
            let crossStatement = try await challengeStatement(h, s, cross.id)
            let hash = Base64URL.encode(Data(SHA256.hash(data: Data(code.utf8))))
            await XCTAssertEqualAsync(try await evidence(h, s, cross.id, try await answer(authority, statement: crossStatement, match: nil, codeHash: hash)).status, .unauthorized)
            await XCTAssertEqualAsync(try await evidence(h, s, cross.id, try await answer(authority, statement: crossStatement, match: nil, codeHash: nil)).status, .unauthorized)
            try await eq(try await get(h, s, cross.id).status, .delivered)
            // `cross_device` belongs to the link service only.
            let business = try JSONSerialization.data(withJSONObject: ["method": "magic_link", "request_id": "bm", "subject_ref": s.subject.rawValue, "purpose": "sign_in",
                                                                       "template": "auth.sign_in_link.v1",
                                                                       "destination": ["link_mode": "business", "url": "https://\(s.host)/x", "cross_device": true]])
            await XCTAssertEqualAsync(try await create(h, s.b, business).status, .unprocessableEntity)
            try await authority.app.asyncShutdown()
        }
    }

    func testCrossDeviceRelayAndReplayAreRefused() async throws {
        try await linkHarness { h in
            let (s, authority) = try await setUp(h)
            let view = try await create(h, s.b, linkServiceBody(s, crossDevice: true)).json(AuthDeliveryView.self)
            let cross = try XCTUnwrap(view.crossDevice)
            let number = try XCTUnwrap(cross.matchCode)
            let statement = try await challengeStatement(h, s, view.id)
            // Before the phone answered there is nothing to redeem.
            await XCTAssertEqualAsync(try await redeem(h, s.b, ach: cross.ach).status, .badRequest)
            // Another business cannot see the delivery (so not its number or reference) nor redeem the reference.
            let other = try await scene(h, name: "Globex", handle: "globex")
            await XCTAssertEqualAsync(try await h.business(other.b, .GET, "/v1/business/auth-deliveries/\(view.id)").status, .notFound)
            let accepted = try await answer(authority, statement: statement, match: number, codeHash: nil)
            await XCTAssertEqualAsync(try await evidence(h, s, view.id, accepted).status, .ok)
            await XCTAssertEqualAsync(try await redeem(h, other.b, ach: cross.ach).status, .badRequest)
            // A session without the initiating browser's PKCE verifier cannot redeem.
            await XCTAssertEqualAsync(try await redeem(h, s.b, ach: cross.ach, verifier: String(repeating: "x", count: 43)).status, .badRequest)
            // The accepted answer replayed: refused on this delivery, and never relayed under another one.
            await XCTAssertEqualAsync(try await evidence(h, s, view.id, accepted).status, .conflict)
            let second = try await create(h, s.b, linkServiceBody(s, crossDevice: true)).json(AuthDeliveryView.self)
            await XCTAssertEqualAsync(try await evidence(h, s, second.id, accepted).status, .unauthorized)
            // The genuine session redeems once; the reference cannot be redeemed again.
            await XCTAssertEqualAsync(try await redeem(h, s.b, ach: cross.ach).status, .ok)
            await XCTAssertEqualAsync(try await redeem(h, s.b, ach: cross.ach).status, .badRequest)
            // Three wrong numbers end the second challenge: the right number afterwards is refused too.
            let secondStatement = try await challengeStatement(h, s, second.id)
            let right = try XCTUnwrap(second.crossDevice?.matchCode)
            let wrong = right == "10" ? "11" : "10"
            for _ in 0..<3 {
                await XCTAssertEqualAsync(try await evidence(h, s, second.id, try await answer(authority, statement: secondStatement, match: wrong, codeHash: nil)).status, .unauthorized)
            }
            await XCTAssertEqualAsync(try await evidence(h, s, second.id, try await answer(authority, statement: secondStatement, match: right, codeHash: nil)).status, .unauthorized)
            await XCTAssertEqualAsync(try await redeem(h, s.b, ach: try XCTUnwrap(second.crossDevice?.ach)).status, .badRequest)
            try await authority.app.asyncShutdown()
        }
    }

    // MARK: Exploit paths

    func testNoRedemptionOnGetHeadOrLinkPrefetch() async throws {
        try await linkHarness { h in
            let (s, authority) = try await setUp(h)
            let view = try await create(h, s.b, linkServiceBody(s)).json(AuthDeliveryView.self)
            try await h.runJobs()
            // A link preview or prefetch fetches the display (GET) and the redeem URL with GET or HEAD: nothing is consumed, nothing is granted.
            for _ in 0..<3 { _ = try await display(h, s, view.id) }
            for method in [NIOHTTP1.HTTPMethod.GET, .HEAD] {
                let r = try await h.business(s.b, method, "/v1/business/auth-links/redeem")
                XCTAssertTrue([.notFound, .methodNotAllowed].contains(r.status), "\(method): \(r.status)")
            }
            try await eq(try await get(h, s, view.id).status, .delivered)
            // The link-service delivery holds no URL: `open` hands out nothing.
            await XCTAssertEqualAsync(try await h.signed(s.consumer, .POST, "/v1/auth-deliveries/\(view.id)/open").status, .notFound)
            // Before the device answered, no code exists to redeem.
            await XCTAssertEqualAsync(try await redeem(h, s.b, code: Base64URL.encode(SecureToken.randomBytes(32))).status, .badRequest)
            try await authority.app.asyncShutdown()
        }
    }

    func testAnotherTenantsLinkClientIsRefusedAtCreateAndAtRedemption() async throws {
        try await linkHarness { h in
            let (s, authority) = try await setUp(h)
            // Another business presents this business's reviewed link client: the authority compares the creating business with the client record.
            let other = try await scene(h, name: "Globex", handle: "globex")
            let refused = try await create(h, other.b, linkServiceBody(other))
            XCTAssertEqual(refused.status, .unprocessableEntity, refused.text)
            // And a genuine code cannot be redeemed with another business's key.
            let view = try await create(h, s.b, linkServiceBody(s)).json(AuthDeliveryView.self)
            let statement = try await challengeStatement(h, s, view.id)
            let code = Base64URL.encode(SecureToken.randomBytes(32))
            _ = try await evidence(h, s, view.id, try await factor(authority, statement: statement, code: code))
            await XCTAssertEqualAsync(try await redeem(h, other.b, code: code).status, .badRequest)
            try await eq(try await get(h, s, view.id).status, .opened)
            // An unregistered return URL is refused too.
            let wrongURL = try await create(h, s.b, linkServiceBody(s, returnURL: "https://shop.example.com/other"))
            XCTAssertEqual(wrongURL.status, .unprocessableEntity)
            try await authority.app.asyncShutdown()
        }
    }

    func testRedemptionOnlyByTheBoundDeviceAndSession() async throws {
        try await linkHarness { h in
            let (s, authority) = try await setUp(h)
            let view = try await create(h, s.b, linkServiceBody(s)).json(AuthDeliveryView.self)
            let statement = try await challengeStatement(h, s, view.id)
            let code = Base64URL.encode(SecureToken.randomBytes(32))
            // A key that is not in the account's log cannot answer (the authority checks the logged key).
            let stranger = try await evidence(h, s, view.id, try await factor(authority, statement: statement, code: code, key: SoftwareP256SigningKey()))
            XCTAssertEqual(stranger.status, .unauthorized)
            // Another customer cannot answer this customer's delivery (it is not theirs: 404, nothing relayed).
            let intruder = try await h.readyConsumer()
            _ = try await h.connect(intruder, to: s.b)
            let foreign = try await h.signedPost(intruder, "/v1/auth-deliveries/\(view.id)/link-evidence",
                                                 AuthLinkEvidenceRequest(factor: try await factor(authority, statement: statement, code: code)))
            XCTAssertEqual(foreign.status, .notFound)
            // A factor for another delivery's challenge is never relayed under this one.
            let second = try await create(h, s.b, linkServiceBody(s)).json(AuthDeliveryView.self)
            let otherStatement = try await challengeStatement(h, s, second.id)
            let crossed = try await evidence(h, s, view.id, try await factor(authority, statement: otherStatement, code: code))
            XCTAssertEqual(crossed.status, .unauthorized)
            // The genuine device answers; only the initiating session (its PKCE verifier) redeems.
            let genuine = try await factor(authority, statement: statement, code: code)
            await XCTAssertEqualAsync(try await evidence(h, s, view.id, genuine).status, .ok)
            await XCTAssertEqualAsync(try await redeem(h, s.b, code: code, verifier: String(repeating: "x", count: 43)).status, .badRequest)
            await XCTAssertEqualAsync(try await redeem(h, s.b, code: code).status, .ok)
            // A second answer for the same delivery is refused.
            await XCTAssertEqualAsync(try await evidence(h, s, view.id, try await factor(authority, statement: statement, code: code)).status, .conflict)
            try await authority.app.asyncShutdown()
        }
    }

    func testAnExpiredDeliveryCannotBeAnswered() async throws {
        try await linkHarness { h in
            let (s, authority) = try await setUp(h)
            let view = try await create(h, s.b, linkServiceBody(s)).json(AuthDeliveryView.self)
            let statement = try await challengeStatement(h, s, view.id)
            h.clock.advance(by: view.expiresAt.timeIntervalSince(h.clock.now()) + 1)
            let late = try await evidence(h, s, view.id, try await factor(authority, statement: statement, code: Base64URL.encode(SecureToken.randomBytes(32))))
            XCTAssertEqual(late.status, .gone)
            try await eq(try await get(h, s, view.id).status, .expired)
            try await authority.app.asyncShutdown()
        }
    }

    func testTheLinkServiceIsOffByDefaultAndFailsClosedWithoutAnAuthority() async throws {
        try await harness { h in
            let s = try await scene(h)
            let refused = try await create(h, s.b, linkServiceBody(s))
            XCTAssertEqual(refused.status, .unprocessableEntity)
            XCTAssertTrue(refused.text.contains("not available yet"))
            await XCTAssertEqualAsync(try await h.signedPost(s.consumer, "/v1/auth-deliveries/\(AuthDeliveryID())/link-evidence",
                                                             AuthLinkEvidenceRequest(factor: "a.b.c")).status, .notFound)
        }
        try await linkHarness { h in
            let s = try await scene(h)
            await XCTAssertEqualAsync(try await create(h, s.b, linkServiceBody(s)).status, .serviceUnavailable)
            // Business-mode members are refused with the link service, and only sign_in / step_up are served.
            let mixed = try JSONSerialization.data(withJSONObject: ["method": "magic_link", "request_id": "mixed", "subject_ref": s.subject.rawValue, "purpose": "sign_in",
                                                                    "template": "auth.sign_in_link.v1", "destination": ["link_mode": "viadere", "url": "https://\(s.host)/x",
                                                                    "link_client_id": AuthLinkRedemptionTests.linkClient, "return_url": AuthLinkRedemptionTests.returnURL,
                                                                    "code_challenge": Self.challenge, "code_challenge_method": "S256"]])
            await XCTAssertEqualAsync(try await create(h, s.b, mixed).status, .unprocessableEntity)
            await XCTAssertEqualAsync(try await create(h, s.b, linkServiceBody(s, purpose: "verify_contact")).status, .unprocessableEntity)
        }
    }

    func testProductionRefusesTheLinkServiceFlag() throws {
        var env = ["ENVIRONMENT": "production", "AUTH_LINK_SERVICE_ENABLED": "true", "AUTH_DELIVERY_ENABLED": "false"]
        var config = ServerConfig.testing()
        XCTAssertThrowsError(try config.applyAuthDeliveryEnvironment(env, production: true))
        env["ENVIRONMENT"] = "staging"
        config = ServerConfig.testing()
        XCTAssertNoThrow(try config.applyAuthDeliveryEnvironment(env, production: true))
        XCTAssertTrue(config.authDelivery.linkServiceEnabled)
        config = ServerConfig.testing()
        XCTAssertNoThrow(try config.applyAuthDeliveryEnvironment(["ENVIRONMENT": "staging", "AUTH_DELIVERY_ENABLED": "false"], production: true))
        XCTAssertFalse(config.authDelivery.linkServiceEnabled, "the link service ships off")
        XCTAssertFalse(config.authDelivery.destinationRecordsEnabled, "the tenant-record relay ships off")
    }

    // MARK: Tenant-record relay (ADR-0031 §2)

    func testTheTenantRecordRelayIsOffByDefaultAndPassesTheAuthorityStatementsThroughUnchanged() async throws {
        try await harness { h in
            let s = try await scene(h)
            await XCTAssertEqualAsync(try await h.signed(s.consumer, .GET, "/v1/auth-tenants/ten_x/destination-keys").status, .notFound)
        }
        try await harness({ $0.authDelivery.destinationRecordsEnabled = true }) { h in
            let s = try await scene(h)
            // No authority: 503, so the device shows S-LINK-11 and the link waits.
            h.app.authorityTransport = nil
            await XCTAssertEqualAsync(try await h.signed(s.consumer, .GET, "/v1/auth-tenants/ten_x/destination-keys").status, .serviceUnavailable)
            let record = "eyJhbGciOiJFUzI1NiJ9.e30.c2ln"
            h.app.authorityTransport = StaticAuthorityTransport(status: 200, body: Data("{\"record\":\"\(record)\"}".utf8))
            let relayed = try await h.signed(s.consumer, .GET, "/v1/auth-tenants/ten_x/destination-keys")
            XCTAssertEqual(relayed.status, .ok)
            XCTAssertEqual(try relayed.json(AuthTenantDestinationKeys.self).record, record, "relayed byte for byte; the device verifies it")
            // An authority answer with an extra member is never passed on.
            h.app.authorityTransport = StaticAuthorityTransport(status: 200, body: Data("{\"record\":\"a.b.c\",\"hint\":\"trust me\"}".utf8))
            await XCTAssertEqualAsync(try await h.signed(s.consumer, .GET, "/v1/auth-tenants/ten_x/destination-keys").status, .serviceUnavailable)
            h.app.authorityTransport = StaticAuthorityTransport(status: 404, body: Data())
            await XCTAssertEqualAsync(try await h.signed(s.consumer, .GET, "/v1/auth-tenants/ten_x/destination-keys").status, .notFound)
            // Without a device signature: refused.
            await XCTAssertEqualAsync(try await h.request(.GET, "/v1/auth-tenants/ten_x/destination-keys").status, .unauthorized)
        }
    }
}

/// A transport that answers every call with one fixed response (the api must relay or refuse it, never sign or alter it).
struct StaticAuthorityTransport: AuthorityTransport {
    let status: Int
    let body: Data
    func send(method: NIOHTTP1.HTTPMethod, path: String, contentType: String?, body: Data?) async throws -> (status: Int, body: Data) { (status, self.body) }
}

fileprivate func XCTAssertEqualAsync<T: Equatable>(_ expression: @autoclosure () async throws -> T, _ expected: @autoclosure () throws -> T,
                                                  file: StaticString = #filePath, line: UInt = #line) async {
    do {
        let value = try await expression()
        XCTAssertEqual(value, try expected(), file: file, line: line)
    } catch {
        XCTFail("threw \(error)", file: file, line: line)
    }
}
