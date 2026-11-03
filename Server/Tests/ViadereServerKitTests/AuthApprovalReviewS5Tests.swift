@preconcurrency import Crypto
import Fluent
import Foundation
import Vapor
import ViadereCore
import ViadereKit
import XCTest
@testable import ViadereServerKit

/// The Stage 5 code review (docs/reviews/STAGE5_CODE_REVIEW.md): S5-01 (ST-MFA-11 through the phone's screen logic), S5-02 (a group answer counts once),
/// S5-03 (`AUTH_NUMBER_MATCHING_REQUIRED`), S5-04 (silence), S5-05 (the Deny gate) and S5-07 (the missing control tests).
/// What the phone's number field does (ST-MFA-11, Stage 5 review S5-01): the open requests of the business are the candidates, the typed digits go through
/// `NumberMatchApprovalViewModel`, and the request the screen selects is the one the phone signs.
actor SelectingAnswering: ApprovalAnswering {
    private(set) var approved: [String] = []
    func answer(_ answer: AuthAnswer, requestIds: [String]) async throws { if case .approve = answer { approved = requestIds } }
}

extension TestHarness {
    @MainActor
    func phoneSelects(_ f: ApproveFixture, digits: String) async throws -> (selected: ApproveDeviceRequest?, canApprove: Bool, field: Int) {
        let open = try await pendingRequests(f.phone.consumer).filter { $0.numberMatch?.code != nil }
        let candidates = open.map { NumberMatchRequirement.Candidate(requestId: $0.requestId, code: $0.numberMatch!.code!) }
        let requirement = NumberMatchRequirement(digits: candidates.map { $0.code.utf8.count }.max() ?? 2, candidates: candidates)
        XCTAssertTrue(requirement.isWellFormed, "a group of 2- and 3-digit codes is a well-formed requirement")
        let now = clock.now()
        let context = NumberMatchApprovalContext(business: "Northwind Bank", expiresAt: now.addingTimeInterval(120), requirement: requirement,
                                                 openRequestCount: open.count, groupRequestIds: open.map(\.requestId))
        let answering = SelectingAnswering()
        let screen = NumberMatchApprovalViewModel(context: context, answering: answering, clock: { now })
        for character in digits { screen.edit(screen.entry + String(character)) }
        let canApprove = screen.canApprove
        await screen.approve()
        let chosen = await answering.approved.first
        return (open.first { $0.requestId == chosen }, canApprove, requirement.digits)
    }
}

final class AuthApprovalReviewS5Tests: XCTestCase {
    // MARK: Helpers

    func body(_ f: ApproveFixture, code: String, requestId: String = TestHarness.makeRequestId(), handle: String? = nil) -> AuthApprovalCreateRequest {
        let tags = AuthMatchTags.tags(key: AuthApprovalTests.kMatch, subjectRef: f.subject, code: code)!
        return AuthApprovalCreateRequest(requestId: requestId, subjectRef: f.subject, capability: .authChallenge, challenge: SecureToken.generate(byteCount: 24),
                                         authentication: AuthenticationDetails(actionDisplay: "Sign in to Northwind Bank", matchDigits: code.count),
                                         numberMatch: AuthApprovalNumberMatch(digits: code.count, code: code), matchTag: tags.tag, matchPrefixTag: tags.prefixTag,
                                         sessionHandle: handle)
    }

    func create(_ h: TestHarness, _ f: ApproveFixture, _ body: AuthApprovalCreateRequest) async throws -> HTTPResult {
        try await h.businessPost(f.business, APIRoutes.businessAuthApprovalCreate.template, body, idempotencyKey: SecureToken.generate(byteCount: 12))
    }

    func device(_ h: TestHarness, _ f: ApproveFixture, _ requestId: String) async throws -> ApproveDeviceRequest {
        try unwrap(try await h.pendingRequests(f.phone.consumer).first { $0.requestId == requestId })
    }

    /// The phone's v2 answer for a server-visible auth approval.
    func answer(_ h: TestHarness, _ f: ApproveFixture, _ request: ApproveDeviceRequest, decision: ApprovalDecision = .approve, match: String?,
                denyReason: ApprovalDenyReason? = nil) async throws -> String {
        let content = ApprovalRequestContent(businessId: request.business.id, subject: request.subjectRef, requestId: request.requestId, challenge: request.challenge ?? "",
                                            details: .authentication(request.authentication!), toKid: f.phone.kid, issuedAt: request.createdAt, expiresAt: request.expiresAt)
        return try await ApprovalResultFactory.sign(displayed: content, decision: decision, amr: .biometric, key: f.phone.approvalKey, now: h.clock.now(),
                                                    numberMatch: ApprovalNumberMatchAnswer(match: match, denyReason: denyReason, invalidMatchAttempts: 0))
    }

    func submit(_ h: TestHarness, _ f: ApproveFixture, _ request: ApproveDeviceRequest, _ result: String, group: String? = nil) async throws -> HTTPResult {
        try await h.signedPost(f.phone.consumer, "/v1/approve/requests/\(request.id.uuidString.lowercased())/result", SubmitApprovalResultRequest(result: result, answerGroup: group))
    }

    /// What the phone's number field does: the open requests of the business are the candidates, the typed digits go through `NumberMatchApprovalViewModel`, and the
    /// request it selects is the one the phone signs.
    actor Selecting: ApprovalAnswering {
        private(set) var approved: [String] = []
        func answer(_ answer: AuthAnswer, requestIds: [String]) async throws { if case .approve = answer { approved = requestIds } }
    }

    @MainActor
    func typeOnThePhone(_ h: TestHarness, _ f: ApproveFixture, digits: String) async throws -> (selected: ApproveDeviceRequest?, canApprove: Bool, field: Int) {
        let open = try await h.pendingRequests(f.phone.consumer).filter { $0.numberMatch?.code != nil }
        let candidates = open.map { NumberMatchRequirement.Candidate(requestId: $0.requestId, code: $0.numberMatch!.code!) }
        let requirement = NumberMatchRequirement(digits: candidates.map { $0.code.utf8.count }.max() ?? 2, candidates: candidates)
        XCTAssertTrue(requirement.isWellFormed, "a group of 2- and 3-digit codes is a well-formed requirement")
        let context = NumberMatchApprovalContext(business: "Northwind Bank", expiresAt: h.clock.now().addingTimeInterval(120), requirement: requirement,
                                                 openRequestCount: open.count, groupRequestIds: open.map(\.requestId))
        let answering = Selecting()
        let screen = NumberMatchApprovalViewModel(context: context, answering: answering, clock: { h.clock.now() })
        for character in digits { screen.edit(screen.entry + String(character)) }
        let canApprove = screen.canApprove
        await screen.approve()
        let chosen = await answering.approved.first
        return (open.first { $0.requestId == chosen }, canApprove, requirement.digits)
    }

    // MARK: S5-01 / ST-MFA-11 through the screen

    /// The api's own escalation: from 30 open two-digit requests the victim's request is forced to three digits, so the group mixes 2 and 3 digits. The phone's screen
    /// logic (`NumberMatchApprovalViewModel`) picks the request; the harness signs only what the screen selected.
    func testTheVictimsThreeDigitRequestIsCompletableAfterTheEscalationFromThirtyOpenCodes() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            for i in 0..<30 { aeq(try await self.create(h, f, self.body(f, code: String(30 + i))).status, .created) }
            let refused = try await self.create(h, f, self.body(f, code: "69"))
            XCTAssertEqual(refused.errorCode, .matchDigitsRequired, refused.text)
            let victim = self.body(f, code: "690")
            aeq(try await self.create(h, f, victim).status, .created)
            let typed = try await h.phoneSelects(f, digits: "690")
            XCTAssertTrue(typed.canApprove)
            XCTAssertEqual(typed.field, 3, "the field fits the longest code")
            let selected = try XCTUnwrap(typed.selected)
            aeq(selected.requestId, victim.requestId)
            // A two-digit attacker code is selected by its own two digits, never by the victim's three.
            let other = try await h.phoneSelects(f, digits: "31")
            aeq(other.selected?.numberMatch?.code, "31")
            let signed = try await self.answer(h, f, selected, match: "690")
            aeq(try await self.submit(h, f, selected, signed).status, .ok)
        }
    }

    // MARK: S5-02: a group answer counts once toward the pause

    func testOneGroupDenyOfThreeRequestsCountsOnceAndDoesNotPauseTheVictim() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            var open: [ApproveDeviceRequest] = []
            for code in ["21", "22", "23"] {
                let b = self.body(f, code: code)
                aeq(try await self.create(h, f, b).status, .created)
                open.append(try await self.device(h, f, b.requestId))
            }
            // The phone's group Deny: one signed deny per request, one shared `answer_group`.
            let group = ApprovalAnswerGroup.make()
            for request in open {
                let result = try await self.submit(h, f, request, try await self.answer(h, f, request, decision: .deny, match: nil), group: group)
                XCTAssertEqual(result.status, .ok, result.text)
            }
            let denied = try await ApproveRequestRecord.query(on: h.db).filter(\.$status == ApprovalRequestStatus.denied.rawValue).count()
            aeq(denied, 3)
            // Three rows, one refusal: the next request is delivered, not auto-denied.
            let next = try await self.create(h, f, self.body(f, code: "24"))
            XCTAssertEqual(next.status, .created, next.text)
            XCTAssertNil(try next.json(ApprovalRequestView.self).reason)
            // Two more refusals (separate answers) make three: now it pauses.
            for code in ["25", "26"] {
                let b = self.body(f, code: code)
                aeq(try await self.create(h, f, b).status, .created)
                let request = try await self.device(h, f, b.requestId)
                aeq(try await self.submit(h, f, request, try await self.answer(h, f, request, decision: .deny, match: nil)).status, .ok)
            }
            let paused = try await self.create(h, f, self.body(f, code: "27"))
            aeq(try paused.json(ApprovalRequestView.self).reason, "auto_denied")
        }
    }

    /// The exploit as the review wrote it: without a group id, three attacker requests plus one honest Deny are three refusals and pause the victim.
    func testWithoutAGroupIdEachDeniedRequestStillCountsAndAMalformedGroupIdIsRefused() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            var open: [ApproveDeviceRequest] = []
            for code in ["31", "32", "33"] {
                let b = self.body(f, code: code)
                aeq(try await self.create(h, f, b).status, .created)
                open.append(try await self.device(h, f, b.requestId))
            }
            let bad = try await self.submit(h, f, open[0], try await self.answer(h, f, open[0], decision: .deny, match: nil), group: "not-a-group-id")
            aeq(bad.status, .unprocessableEntity)
            aeq(try await ApproveRequestRecord.query(on: h.db).filter(\.$requestId == open[0].requestId).first()?.statusValue, .pending)
            for request in open { aeq(try await self.submit(h, f, request, try await self.answer(h, f, request, decision: .deny, match: nil)).status, .ok) }
            let paused = try await self.create(h, f, self.body(f, code: "34"))
            aeq(try paused.json(ApprovalRequestView.self).reason, "auto_denied")
        }
    }

    /// A group id cannot be used to hide refusals of another relationship: the count is per relationship, and an approve never carries one.
    func testAGroupIdOnAnApproveIsIgnoredAndTwoGroupsCountTwice() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            var open: [ApproveDeviceRequest] = []
            for code in ["41", "42", "43", "44"] {
                let b = self.body(f, code: code)
                aeq(try await self.create(h, f, b).status, .created)
                open.append(try await self.device(h, f, b.requestId))
            }
            let first = ApprovalAnswerGroup.make(), second = ApprovalAnswerGroup.make()
            aeq(try await self.submit(h, f, open[0], try await self.answer(h, f, open[0], decision: .deny, match: nil), group: first).status, .ok)
            aeq(try await self.submit(h, f, open[1], try await self.answer(h, f, open[1], decision: .deny, match: nil), group: first).status, .ok)
            aeq(try await self.submit(h, f, open[2], try await self.answer(h, f, open[2], decision: .deny, match: nil), group: second).status, .ok)
            // Two groups: two refusals, not yet paused.
            let notPaused = try await self.create(h, f, self.body(f, code: "45"))
            XCTAssertNil(try notPaused.json(ApprovalRequestView.self).reason)
            let record = try unwrap(try await ApproveRequestRecord.query(on: h.db).filter(\.$requestId == open[3].requestId).first())
            // An approve stores no group id.
            aeq(try await self.submit(h, f, open[3], try await self.answer(h, f, open[3], match: "44"), group: first).status, .ok)
            anil(try await ApproveRequestRecord.find(record.id!, on: h.db)?.answerGroup)
        }
    }

    /// ADR-0022 §5.4: a `destination_unverified` denial is an integrity signal about the business's link, not the customer's answer; it never counts.
    func testDestinationUnverifiedDenialsNeverPauseTheCustomer() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            for code in ["51", "52", "53"] {
                let b = self.body(f, code: code)
                aeq(try await self.create(h, f, b).status, .created)
                let request = try await self.device(h, f, b.requestId)
                let result = try await self.submit(h, f, request, try await self.answer(h, f, request, decision: .deny, match: nil, denyReason: .destinationUnverified))
                XCTAssertEqual(result.status, .ok, result.text)
            }
            let next = try await self.create(h, f, self.body(f, code: "54"))
            XCTAssertEqual(next.status, .created, next.text)
            XCTAssertNil(try next.json(ApprovalRequestView.self).reason, "not paused")
        }
    }

    // MARK: S5-03: AUTH_NUMBER_MATCHING_REQUIRED

    func testTheLegacyRouteCreatesNumberlessApprovalsWhileTheFlagIsOffAndNothingWhileItIsOn() async throws {
        try await withHarness { h in
            XCTAssertFalse(h.ctx.config.authDelivery.numberMatchingRequired, "default off")
            let f = try await h.approveFixture()
            let (payment, _) = try await h.createRequest(f)
            XCTAssertEqual(payment.status, .created, payment.text)
        }
        try await withHarness({ $0.authDelivery.numberMatchingRequired = true }) { h in
            let f = try await h.approveFixture()
            // Payment and sign-in alike: no number, no approval.
            let (payment, _) = try await h.createRequest(f)
            XCTAssertEqual(payment.status, .unprocessableEntity, payment.text)
            XCTAssertTrue(payment.text.contains("number_match_required"), payment.text)
            let signIn = CreateApprovalRequest(requestId: TestHarness.makeRequestId(), subjectRef: f.subject, capability: .authChallenge, challenge: SecureToken.generate(byteCount: 24),
                                               authentication: AuthenticationDetails(actionDisplay: "Sign in to Northwind Bank"))
            let refused = try await h.businessPost(f.business, "/v1/business/approve/requests", signIn)
            XCTAssertEqual(refused.status, .unprocessableEntity, refused.text)
            XCTAssertTrue(refused.text.contains("number_match_required"), refused.text)
            aeq(try await ApproveRequestRecord.query(on: h.db).count(), 0, "nothing was stored")
            // The route that always carries a number is unaffected.
            let ok = try await self.create(h, f, self.body(f, code: "47"))
            XCTAssertEqual(ok.status, .created, ok.text)
        }
    }

    func testTheFlagParsesFromTheEnvironmentAndDefaultsOff() throws {
        var config = ServerConfig.testing()
        try config.applyAuthDeliveryEnvironment([:], production: true)
        XCTAssertFalse(config.authDelivery.numberMatchingRequired)
        try config.applyAuthDeliveryEnvironment(["AUTH_NUMBER_MATCHING_REQUIRED": "true", "AUTH_DELIVERY_ENABLED": "false"], production: true)
        XCTAssertTrue(config.authDelivery.numberMatchingRequired)
        try config.applyAuthDeliveryEnvironment(["AUTH_NUMBER_MATCHING_REQUIRED": "false", "AUTH_DELIVERY_ENABLED": "false"], production: true)
        XCTAssertFalse(config.authDelivery.numberMatchingRequired)
        XCTAssertThrowsError(try { var x = ServerConfig.testing(); try x.applyAuthDeliveryEnvironment(["AUTH_NUMBER_MATCHING_REQUIRED": "yes"], production: false) }())
    }

    // MARK: S5-04: silence

    func testOpenRequestsDoNotSilenceTheNextOneOnlyMoreThanSixAnHourDo() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            _ = try await h.signedPost(f.phone.consumer, "/v1/push/apns-token", APNsTokenRegistration(token: String(repeating: "cd", count: 32), environment: .sandbox, bundleId: "com.viadere.app"))
            var ids: [String] = []
            for i in 0..<8 {
                let b = self.body(f, code: String(61 + i))
                aeq(try await self.create(h, f, b).status, .created)
                ids.append(b.requestId)
            }
            // Six alert pushes (the first six requests of the hour); the seventh and eighth are silent.
            aeq(h.push.sent.filter { $0.category == "viadere.approve" }.count, 6)
            let pending = try await h.pendingRequests(f.phone.consumer)
            for (index, id) in ids.enumerated() {
                let request = try unwrap(pending.first { $0.requestId == id })
                aeq(request.silent, index >= 6 ? true : nil, "request \(index + 1)")
            }
        }
    }

    // MARK: S5-05: the reduce-only Deny does not depend on AUTH_DELIVERY_ENABLED

    func testTheNotificationDenyWorksWithAuthDeliveryOffAndForLegacyApprovals() async throws {
        try await withHarness({ $0.authDelivery.enabled = false }) { h in
            let f = try await h.approveFixture()
            let (created, request) = try await h.createRequest(f)
            XCTAssertEqual(created.status, .created, created.text)
            let device = try await self.device(h, f, request.requestId)
            // Approve v2 is on, auth delivery is off: the auth routes are gone (404) but a Lock Screen Deny still reaches the relay.
            aeq(try await self.create(h, f, self.body(f, code: "47")).status, .notFound)
            let denied = try await h.signedPost(f.phone.consumer, "/v1/approve/requests/\(device.id.uuidString.lowercased())/deny", ApproveDenyRequest())
            XCTAssertEqual(denied.status, .ok, denied.text)
            aeq(try denied.json(SubmitApprovalResultResponse.self).status, .denied)
        }
        // With Approve itself off the endpoint is still gone.
        try await withHarness({ $0.approve.enabled = false }) { h in
            let denied = try await h.signedPost(try await h.readyConsumer(), "/v1/approve/requests/\(UUID().uuidString.lowercased())/deny", ApproveDenyRequest())
            aeq(denied.status, .notFound)
        }
    }

    // MARK: S5-07: the controls that had no test

    /// "Two concurrent requests cannot both take the same code" (ADR-0020 §2a): the reservation re-checks under the customer row lock.
    func testTwoConcurrentCreatesOfTheSameCodeCannotBothSucceed() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            for round in 0..<3 {
                let code = String(70 + round * 10 + 5)
                let bodies = (0..<4).map { _ in self.body(f, code: code) }
                let statuses = try await withThrowingTaskGroup(of: HTTPStatus.self) { group -> [HTTPStatus] in
                    for request in bodies {
                        group.addTask {
                            try await h.businessPost(f.business, APIRoutes.businessAuthApprovalCreate.template, request, idempotencyKey: SecureToken.generate(byteCount: 12)).status
                        }
                    }
                    var out: [HTTPStatus] = []
                    for try await status in group { out.append(status) }
                    return out
                }
                aeq(statuses.filter { $0 == .created }.count, 1, "code \(code): exactly one winner, got \(statuses)")
                aeq(statuses.filter { $0 == .conflict }.count, 3, "code \(code): the others get match_code_in_use, got \(statuses)")
            }
        }
    }

    /// The relay's `relayRequired` path (`ApprovalResult` v2, end to end): the relay cannot read the code, so it checks that the result is v2 and that `match` has the
    /// right length. A v1 result and a wrong-length `match` are refused and counted as invalid submissions.
    func testTheRelayRequiresAV2ResultWithAMatchOfTheRightLengthForAnEndToEndApproval() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            let requestId = TestHarness.makeRequestId(), challenge = SecureToken.generate(byteCount: 24)
            let now = h.clock.now()
            let details = ApprovalSubject.authentication(AuthenticationDetails(actionDisplay: "Sign in to Northwind Bank", matchDigits: 2))
            func content(number: Bool) -> ApprovalRequestContent {
                ApprovalRequestContent(businessId: f.business.id, subject: f.subject, requestId: requestId, challenge: challenge, details: details, toKid: f.phone.kid,
                                       issuedAt: now, expiresAt: now.addingTimeInterval(120), numberMatch: number ? ApprovalNumberMatch(digits: 2, code: "47") : nil)
            }
            let plaintext = try await content(number: true).sealedPlaintext(signedWith: f.keys.requestSigning)
            let envelope = try E2EE.seal(plaintext, to: f.phone.hpke.publicKey, context: E2EEContext(purpose: "approve.request", requestId: requestId, sender: ApproveIdentifiers.sender(f.business.id),
                                                                                                     recipient: ApproveIdentifiers.recipient(kid: f.phone.kid), expiresAt: now.addingTimeInterval(120)))
            let tags = AuthMatchTags.tags(key: AuthApprovalTests.kMatch, subjectRef: f.subject, code: "47")!
            let request = AuthApprovalCreateRequest(requestId: requestId, subjectRef: f.subject, capability: .authChallenge, envelopes: [ApprovalEnvelopeDelivery(kid: f.phone.kid, envelope: envelope)],
                                                    numberMatch: AuthApprovalNumberMatch(digits: 2), matchTag: tags.tag, matchPrefixTag: tags.prefixTag)
            let created = try await self.create(h, f, request)
            XCTAssertEqual(created.status, .created, created.text)
            let device = try await self.device(h, f, requestId)
            XCTAssertNil(device.numberMatch?.code, "the relay holds no code for an end-to-end request")
            func sign(_ displayed: ApprovalRequestContent, match: String?) async throws -> String {
                try await ApprovalResultFactory.sign(displayed: displayed, decision: .approve, amr: .biometric, key: f.phone.approvalKey, now: h.clock.now(),
                                                     numberMatch: match.map { ApprovalNumberMatchAnswer(match: $0, denyReason: nil, invalidMatchAttempts: 0) })
            }
            // A downgrade to v1 (the displayed content carries no number): refused.
            let v1 = try await sign(content(number: false), match: nil)
            aeq(try await self.submit(h, f, device, v1).status, .forbidden)
            // A `match` of the wrong length: refused.
            aeq(try await self.submit(h, f, device, try await sign(content(number: true), match: "470")).status, .forbidden)
            let invalid = try unwrap(try await ApproveRequestRecord.query(on: h.db).filter(\.$requestId == requestId).first())
            aeq(invalid.attempts, 2, "both refusals count as invalid submissions")
            aeq(invalid.statusValue, .pending)
            // The right length is accepted (the business checks the digits against its own code).
            let ok = try await self.submit(h, f, device, try await sign(content(number: true), match: "47"))
            XCTAssertEqual(ok.status, .ok, ok.text)
        }
    }

    /// The relay records each result's `jti` per business (ADR-0023 §7). The second submission of the same result is normally stopped by the status check first, so the
    /// store is exercised directly: after an accepted result its `jti` is registered, and a result whose `jti` the store already holds is refused as replayed.
    func testTheRelayRegistersEveryAcceptedJtiAndRefusesOneItAlreadyHolds() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            func jti(of result: String) throws -> String {
                let parts = result.split(separator: ".")
                let payload = try unwrap(Base64URL.decode(String(parts[1])))
                let object = try unwrap(try JSONSerialization.jsonObject(with: payload) as? [String: Any])
                return try unwrap(object["jti"] as? String)
            }
            let scope = "approval-jti:\(f.business.id.uuid)"
            let guardian = DatabaseReplayGuard(db: h.db)

            let accepted = self.body(f, code: "47")
            aeq(try await self.create(h, f, accepted).status, .created)
            let first = try await self.device(h, f, accepted.requestId)
            let result = try await self.answer(h, f, first, match: "47")
            aeq(try await self.submit(h, f, first, result).status, .ok)
            let registered = try await guardian.registerIfFresh(nonce: try jti(of: result), scope: scope, expiresAt: h.clock.now().addingTimeInterval(600), now: h.clock.now())
            XCTAssertFalse(registered, "the accepted result's jti is in the relay's store")

            // A jti the store already holds (the same signed bytes presented through another path) is refused and the request stays open.
            let replayed = self.body(f, code: "58")
            aeq(try await self.create(h, f, replayed).status, .created)
            let second = try await self.device(h, f, replayed.requestId)
            let replayedResult = try await self.answer(h, f, second, match: "58")
            let fresh = try await guardian.registerIfFresh(nonce: try jti(of: replayedResult), scope: scope, expiresAt: h.clock.now().addingTimeInterval(600), now: h.clock.now())
            XCTAssertTrue(fresh)
            let refused = try await self.submit(h, f, second, replayedResult)
            aeq(refused.status, .conflict, refused.text)
            aeq(refused.errorCode, .replayDetected)
            aeq(try await ApproveRequestRecord.query(on: h.db).filter(\.$requestId == replayed.requestId).first()?.statusValue, .pending)
            // The scope names the business: another business's store is separate.
            let other = try await guardian.registerIfFresh(nonce: try jti(of: replayedResult), scope: "approval-jti:\(UUID())", expiresAt: h.clock.now().addingTimeInterval(600), now: h.clock.now())
            XCTAssertTrue(other)
        }
    }

    /// `authdl-deny`: the reduce-only Deny is rate limited per device.
    func testTheDenyEndpointIsRateLimitedPerDevice() async throws {
        try await withHarness({ $0.authDelivery.denyRate = .perMinute(1, burst: 2) }) { h in
            let f = try await h.approveFixture()
            var devices: [ApproveDeviceRequest] = []
            for code in ["81", "82", "83"] {
                let b = self.body(f, code: code)
                aeq(try await self.create(h, f, b).status, .created)
                devices.append(try await self.device(h, f, b.requestId))
            }
            func deny(_ request: ApproveDeviceRequest) async throws -> HTTPResult {
                try await h.signedPost(f.phone.consumer, "/v1/approve/requests/\(request.id.uuidString.lowercased())/deny", ApproveDenyRequest())
            }
            aeq(try await deny(devices[0]).status, .ok)
            aeq(try await deny(devices[1]).status, .ok)
            let limited = try await deny(devices[2])
            aeq(limited.status, .tooManyRequests, limited.text)
            aeq(try await ApproveRequestRecord.query(on: h.db).filter(\.$requestId == devices[2].requestId).first()?.statusValue, .pending)
        }
    }
}
