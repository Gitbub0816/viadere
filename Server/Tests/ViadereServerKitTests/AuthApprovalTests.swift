@preconcurrency import Crypto
import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Stage 5: `POST /v1/business/auth-approvals` (push MFA with number matching, ADR-0022), the reduce-only notification Deny (R4-03), the Approve push
/// (`req`, `active`, collapse id) and the THREAT_MODEL ST-MFA tests that run against the server (ST-MFA-02, -03, -05, -07, -10, -11).
final class AuthApprovalTests: XCTestCase {
    static let sdkSecret = SymmetricKey(data: Data(repeating: 9, count: 32))
    static var kMatch: SymmetricKey { AuthSDKKeys.derive(secret: sdkSecret, label: AuthSDKKeys.matchTagLabel) }

    func body(_ f: ApproveFixture, code: String, requestId: String = TestHarness.makeRequestId(), handle: String? = nil,
              capability: Capability = .authChallenge) -> AuthApprovalCreateRequest {
        let tags = AuthMatchTags.tags(key: Self.kMatch, subjectRef: f.subject, code: code)!
        let digits = code.count
        if capability == .transactionApprove {
            return AuthApprovalCreateRequest(requestId: requestId, subjectRef: f.subject, capability: capability, challenge: SecureToken.generate(byteCount: 24),
                                             transaction: TransactionDetails(currency: "USD", amountMinor: 100, payeeDisplay: "Shop", transactionReference: "r1"),
                                             numberMatch: AuthApprovalNumberMatch(digits: digits, code: code), matchTag: tags.tag, matchPrefixTag: tags.prefixTag)
        }
        return AuthApprovalCreateRequest(requestId: requestId, subjectRef: f.subject, capability: .authChallenge, challenge: SecureToken.generate(byteCount: 24),
                                         authentication: AuthenticationDetails(actionDisplay: "Sign in to Northwind Bank", matchDigits: digits),
                                         numberMatch: AuthApprovalNumberMatch(digits: digits, code: code), matchTag: tags.tag, matchPrefixTag: tags.prefixTag,
                                         sessionHandle: handle)
    }

    func create(_ h: TestHarness, _ f: ApproveFixture, _ body: AuthApprovalCreateRequest) async throws -> HTTPResult {
        try await h.businessPost(f.business, APIRoutes.businessAuthApprovalCreate.template, body, idempotencyKey: SecureToken.generate(byteCount: 12))
    }

    /// The phone's v2 answer for a server-visible auth approval.
    func answer(_ h: TestHarness, _ f: ApproveFixture, _ request: ApproveDeviceRequest, decision: ApprovalDecision = .approve, match: String?,
                denyReason: ApprovalDenyReason? = nil) async throws -> String {
        let content = ApprovalRequestContent(businessId: request.business.id, subject: request.subjectRef, requestId: request.requestId, challenge: request.challenge ?? "",
                                            details: .authentication(request.authentication!), toKid: f.phone.kid, issuedAt: request.createdAt, expiresAt: request.expiresAt)
        return try await ApprovalResultFactory.sign(displayed: content, decision: decision, amr: .biometric, key: f.phone.approvalKey, now: h.clock.now(),
                                                    numberMatch: ApprovalNumberMatchAnswer(match: match, denyReason: denyReason, invalidMatchAttempts: 0))
    }

    func registerPush(_ h: TestHarness, _ f: ApproveFixture) async throws {
        _ = try await h.signedPost(f.phone.consumer, "/v1/push/apns-token", APNsTokenRegistration(token: String(repeating: "cd", count: 32), environment: .sandbox, bundleId: "com.viadere.app"))
    }

    // MARK: End to end (ST-MFA-01 server half, ST-MFA-02, ST-MFA-03)

    func testNumberMatchedApprovalEndToEndAndTheBusinessVerifiesTheTypedNumber() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            try await self.registerPush(h, f)
            let request = self.body(f, code: "47")
            let created = try await self.create(h, f, request)
            XCTAssertEqual(created.status, .created, created.text)
            // The push: `req` = this device's id, `active`, collapse id, no business text (ADR-0022 §5.5, R4-03, R23-05).
            let push = try XCTUnwrap(h.push.sent.last { $0.category == "viadere.approve" })
            XCTAssertEqual(push.interruptionLevel, "active")
            let pending = try await h.pendingRequests(f.phone.consumer)
            let device = try XCTUnwrap(pending.first { $0.requestId == request.requestId })
            XCTAssertEqual(push.approveRequestId, device.id.uuidString.lowercased())
            XCTAssertEqual(push.collapseID, device.id.uuidString.lowercased())
            XCTAssertFalse(push.body.contains("Northwind"))
            XCTAssertEqual(device.numberMatch, AuthApprovalNumberMatch(digits: 2, code: "47"))

            // The relay refuses a wrong number and a downgraded v1 result (defense in depth) and counts them as invalid submissions.
            let wrong = try await self.answer(h, f, device, match: "74")
            aeq(try await h.submit(f.phone, deliveryId: device.id, result: wrong).status, .forbidden)
            let v1 = try await h.answer(f.phone, device)
            aeq(try await h.submit(f.phone, deliveryId: device.id, result: v1).status, .forbidden)

            let good = try await self.answer(h, f, device, match: "47")
            let submitted = try await h.submit(f.phone, deliveryId: device.id, result: good)
            XCTAssertEqual(submitted.status, .ok, submitted.text)
            // The match tags are gone at the terminal state (class T).
            aeq(try await AuthMatchGroups(db: h.db, ctx: h.ctx).openCount(businessId: f.business.id.uuid, consumerId: f.relationship.consumerId.uuid), 0)

            let viewResult = try await h.business(f.business, .GET, "/v1/business/auth-approvals/\(request.requestId)")
            XCTAssertEqual(viewResult.status, .ok, viewResult.text)
            let ref = try XCTUnwrap(try viewResult.json(ApprovalRequestView.self).resultRef)
            let fetched = try await h.business(f.business, .GET, "/v1/business/approve/results/\(ref)").json(ApprovalResultResponse.self)
            let keys = try await h.enrolledKeys(f)
            let details = ApprovalSubject.authentication(request.authentication!)
            func expectation(_ code: String) -> ApprovalExpectation {
                ApprovalExpectation(audience: f.business.id, subject: f.subject, requestId: request.requestId, challenge: request.challenge!, subjectDetails: details,
                                    numberMatch: .required(code: code), minimumAMR: .biometric)
            }
            // ST-MFA-02: the business's own record of a different code refuses the result.
            XCTAssertThrowsError(try ApprovalResultVerifier.verify(fetched.result, expecting: expectation("48"), keys: keys, now: h.clock.now())) {
                XCTAssertEqual($0 as? ApprovalVerificationError, .numberMismatch)
            }
            // ST-MFA-03: verified once, then `replayed`.
            let replay = InMemoryReplayGuard()
            let verified = try await ApprovalResultVerifier.verifyAndConsume(fetched.result, expecting: expectation("47"), keys: keys, now: h.clock.now(), replayGuard: replay)
            XCTAssertEqual(verified.claims.match, "47")
            do {
                _ = try await ApprovalResultVerifier.verifyAndConsume(fetched.result, expecting: expectation("47"), keys: keys, now: h.clock.now(), replayGuard: replay)
                XCTFail("replay accepted")
            } catch { XCTAssertEqual(error as? ApprovalVerificationError, .replayed) }
            // The relay refuses a second submission of the same result.
            aeq(try await h.submit(f.phone, deliveryId: device.id, result: good).status, .conflict)
        }
    }

    func testTheRouteIsShapedAndGated() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            // Payments over the relay in the clear are refused (ADR-0022 §4.3).
            let payment = try await self.create(h, f, self.body(f, code: "470", capability: .transactionApprove))
            XCTAssertEqual(payment.status, .unprocessableEntity, payment.text)
            XCTAssertTrue(payment.text.contains("e2ee_required"))
            // Number matching is required; a 2-digit payment is malformed; unknown members are refused; the Idempotency-Key is required.
            var noDigits = self.body(f, code: "47")
            noDigits.authentication = AuthenticationDetails(actionDisplay: "Sign in")
            aeq(try await self.create(h, f, noDigits).status, .unprocessableEntity)
            let noKey = try await h.businessPost(f.business, APIRoutes.businessAuthApprovalCreate.template, self.body(f, code: "47"))
            ane(noKey.status, .created)
            // R23-09: an invalid prefix tag is refused.
            var badPrefix = self.body(f, code: "470")
            badPrefix.matchPrefixTag = "x"
            aeq(try await self.create(h, f, badPrefix).status, .unprocessableEntity)
        }
        try await withHarness({ $0.authDelivery.enabled = false }) { h in
            let f = try await h.approveFixture()
            aeq(try await self.create(h, f, self.body(f, code: "47")).status, .notFound)
        }
    }

    // MARK: ST-MFA-11: collision-free, prefix-free allocation and the SDK redraw contract

    func testCollisionsArePreventedAndTheVictimsRequestIsCompletable() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            // 20 attacker requests with distinct 3-digit codes (no session handle).
            var attackerCodes: [String] = []
            for i in 0..<20 {
                let code = String(200 + i * 10)
                let r = try await self.create(h, f, self.body(f, code: code))
                XCTAssertEqual(r.status, .created, r.text)
                attackerCodes.append(code)
            }
            // The group-pressure alert fired above 10 (count only, no code or tag).
            let pressure = try await h.approvalAudit("auth_delivery.group_pressure")
            XCTAssertEqual(pressure.count, 1)
            XCTAssertFalse(pressure[0].metadataJSON.contains("200"))
            // Equal code, a 2-digit prefix of an open 3-digit code, and a 3-digit code extending an open 2-digit code: `409 match_code_in_use`.
            let equal = try await self.create(h, f, self.body(f, code: "200"))
            XCTAssertEqual(equal.errorCode, .matchCodeInUse, equal.text)
            let prefix = try await self.create(h, f, self.body(f, code: "20"))
            XCTAssertEqual(prefix.errorCode, .matchCodeInUse, prefix.text)
            // The victim's own request gets a distinct code and is created, never refused by count.
            let victim = self.body(f, code: "47")
            let created = try await self.create(h, f, victim)
            XCTAssertEqual(created.status, .created, created.text)
            let extends = try await self.create(h, f, self.body(f, code: "470"))
            XCTAssertEqual(extends.errorCode, .matchCodeInUse, extends.text)
            // The victim types 47 on the phone's screen (Stage 5 review S5-01: the open group mixes 20 three-digit codes with the victim's two-digit one, and the screen
            // logic, not the harness, selects the request): exactly one open request has it, and approving it supersedes the attacker's.
            let typed = try await h.phoneSelects(f, digits: "47")
            XCTAssertTrue(typed.canApprove)
            let device = try XCTUnwrap(typed.selected)
            aeq(device.requestId, victim.requestId)
            let ok = try await h.submit(f.phone, deliveryId: device.id, result: try await self.answer(h, f, device, match: "47"))
            XCTAssertEqual(ok.status, .ok, ok.text)
            let statuses = try await ApproveRequestRecord.query(on: h.db).filter(\.$businessId == f.business.id.uuid).all()
            XCTAssertEqual(statuses.filter { $0.statusValue == .approved }.map(\.requestId), [victim.requestId])
            XCTAssertEqual(statuses.filter { $0.reason == "superseded" }.count, 20)
        }
    }

    func testFromThirtyOpenTwoDigitCodesAreRefusedWithDigitsRequired() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            for i in 0..<30 { aeq(try await self.create(h, f, self.body(f, code: String(300 + i))).status, .created) }
            let two = try await self.create(h, f, self.body(f, code: "47"))
            XCTAssertEqual(two.errorCode, .matchDigitsRequired, two.text)
            aeq(try await self.create(h, f, self.body(f, code: "470")).status, .created)
        }
    }

    // MARK: ST-MFA-05 / ST-MFA-10: budgets limit alerting, not availability; supersession only by session handle

    func testOverBudgetRequestsAreCreatedSilentlyAndOnlyTheSameSessionHandleSupersedes() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            try await self.registerPush(h, f)
            // More than 6 requests in an hour (ADR-0022 §5.1; open requests do not count, S5-04): never `429`; the extra ones get no push.
            for i in 0..<8 { aeq(try await self.create(h, f, self.body(f, code: String(11 + i))).status, .created) }
            let pushes = h.push.sent.filter { $0.category == "viadere.approve" }.count
            XCTAssertEqual(pushes, 6)
            // An attacker without the victim's session handle cancels nothing.
            let victim = self.body(f, code: "50", handle: "victim_session_handle_1")
            aeq(try await self.create(h, f, victim).status, .created)
            aeq(try await self.create(h, f, self.body(f, code: "51", handle: "attacker_handle")).status, .created)
            aeq(try await ApproveRequestRecord.query(on: h.db).filter(\.$requestId == victim.requestId).first()?.statusValue, .pending)
            // The victim's own retry with the same handle supersedes the earlier one.
            aeq(try await self.create(h, f, self.body(f, code: "52", handle: "victim_session_handle_1")).status, .created)
            let old = try await ApproveRequestRecord.query(on: h.db).filter(\.$requestId == victim.requestId).first()
            aeq(old?.statusValue, .cancelled)
            aeq(old?.reason, "superseded")
        }
    }

    // MARK: Reduce-only Deny (R4-03), ST-MFA-07 pause

    func testTheNotificationDenyIsReduceOnlyAndCountsTowardThePause() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            let other = try await h.readyConsumer()
            var requests: [ApproveDeviceRequest] = []
            for code in ["21", "22", "23"] {
                let b = self.body(f, code: code)
                aeq(try await self.create(h, f, b).status, .created)
                requests.append(try unwrap(try await h.pendingRequests(f.phone.consumer).first { $0.requestId == b.requestId }))
            }
            // Another customer's device cannot deny it (404), and the deny body is strict.
            aeq(try await h.signedPost(other, "/v1/approve/requests/\(requests[0].id.uuidString.lowercased())/deny", ApproveDenyRequest()).status, .notFound)
            // Request key only (no approval key, no result): denied, and nothing a business could mistake for a signed approval.
            let denied = try await h.signedPost(f.phone.consumer, "/v1/approve/requests/\(requests[0].id.uuidString.lowercased())/deny", ApproveDenyRequest())
            XCTAssertEqual(denied.status, .ok, denied.text)
            XCTAssertEqual(try denied.json(SubmitApprovalResultResponse.self).status, .denied)
            let row = try unwrap(try await ApproveRequestRecord.query(on: h.db).filter(\.$requestId == requests[0].requestId).first())
            anil(row.resultJWS)
            anil(row.resultRef)
            // It never turns into an approve afterwards.
            let late = try await h.submit(f.phone, deliveryId: requests[0].id, result: try await self.answer(h, f, requests[0], match: "21"))
            aeq(late.status, .conflict)
            let reported = try await h.signedPost(f.phone.consumer, "/v1/approve/requests/\(requests[1].id.uuidString.lowercased())/deny", ApproveDenyRequest(report: true))
            aeq(try reported.json(SubmitApprovalResultResponse.self).status, .reported)
            aeq(try await h.signedPost(f.phone.consumer, "/v1/approve/requests/\(requests[2].id.uuidString.lowercased())/deny", ApproveDenyRequest()).status, .ok)
            // Three refusals: the next request is paused (auto-denied, the customer is not prompted).
            let next = self.body(f, code: "24")
            let paused = try await self.create(h, f, next)
            aeq(try paused.json(ApprovalRequestView.self).reason, "auto_denied")
            // The tags of answered requests are released.
            aeq(try await AuthMatchGroups(db: h.db, ctx: h.ctx).openCount(businessId: f.business.id.uuid, consumerId: f.relationship.consumerId.uuid), 0)
        }
    }

    func testANumberMismatchDenyIsSignedV2AndCountsAsADenial() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            let b = self.body(f, code: "33")
            aeq(try await self.create(h, f, b).status, .created)
            let device = try unwrap(try await h.pendingRequests(f.phone.consumer).first { $0.requestId == b.requestId })
            let deny = try await self.answer(h, f, device, decision: .deny, match: nil, denyReason: .numberMismatch)
            let result = try await h.submit(f.phone, deliveryId: device.id, result: deny)
            XCTAssertEqual(try result.json(SubmitApprovalResultResponse.self).status, .denied)
            aeq(try await ApproveRequestRecord.query(on: h.db).filter(\.$requestId == b.requestId).first()?.denyReason, "number_mismatch")
        }
    }

    func testApprovePushPolicyRejectsTimeSensitiveAndBusinessText() {
        let good: [String: Any] = ["aps": ["alert": ["title": "Viadere", "body": "Action needed."], "category": "viadere.approve", "interruption-level": "active",
                                          "mutable-content": 1], "req": UUID().uuidString.lowercased()]
        XCTAssertTrue(ApprovePushPayloadPolicy.isAllowed(good))
        var timeSensitive = good
        timeSensitive["aps"] = ["alert": ["title": "Viadere", "body": "x"], "category": "viadere.approve", "interruption-level": "time-sensitive"]
        XCTAssertFalse(ApprovePushPayloadPolicy.isAllowed(timeSensitive))
        var extra = good
        extra["business"] = "Northwind"
        XCTAssertFalse(ApprovePushPayloadPolicy.isAllowed(extra))
        // The real APNs payload carries `req` and the collapse id.
        let message = PushMessage(deviceToken: "t", environment: .sandbox, topic: "com.viadere.app", title: "Viadere", body: "b", category: "viadere.approve",
                                  threadID: "viadere.approve", interruptionLevel: "active", interactionId: nil, highPriority: true, collapseID: "abc", approveRequestId: "abc")
        let notification = APNSwiftSender.notification(for: message)
        XCTAssertEqual(notification.collapseID, "abc")
        XCTAssertEqual(notification.payload.req, "abc")
    }
}
