@preconcurrency import Crypto
import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// WP1 requests and signed results (APP-003..005, SEC-CR-004/005/007, spec 14.2): acceptance 3 (replay and substitution), 5 (the business
/// verifies independently; a forged relay status is rejected), plus freezes (APP-007) and prompt-fatigue protection (SEC-DEV-008).
final class ApproveRequestTests: XCTestCase {
    /// The decided request's result as the business verifies it.
    private func decide(_ h: TestHarness, _ f: ApproveFixture, amount: Int64 = 250_000, payee: String = "Example Merchant") async throws -> (CreateApprovalRequest, ApprovalRequestView, ApproveDeviceRequest) {
        let (created, body) = try await h.createRequest(f, details: h.transaction(payee: payee, amount: amount))
        XCTAssertEqual(created.status, .created, created.text)
        let pending = try await h.pendingRequests(f.phone.consumer)
        let request = try XCTUnwrap(pending.first { $0.requestId == body.requestId })
        return (body, try created.json(ApprovalRequestView.self), request)
    }

    // MARK: Happy path (acceptance 5)

    func testTheBusinessVerifiesTheSignedResultItselfAndTheRelaysStatusIsNeverEnough() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            let (body, view, request) = try await decide(h, f)
            XCTAssertEqual(view.protection, .serverVisible)
            XCTAssertEqual(view.status, .pending)
            XCTAssertEqual(request.protection, .serverVisible)
            XCTAssertEqual(request.transaction?.payeeDisplay, "Example Merchant")
            XCTAssertEqual(request.business.id, f.business.id)
            let jws = try await h.answer(f.phone, request)
            let submitted = try await h.submit(f.phone, deliveryId: request.id, result: jws)
            XCTAssertEqual(submitted.status, .ok, submitted.text)
            XCTAssertEqual(try submitted.json(SubmitApprovalResultResponse.self).status, .approved)

            let decided = try await h.requestView(f, body.requestId)
            XCTAssertEqual(decided.status, .approved)
            let ref = try XCTUnwrap(decided.resultRef)
            XCTAssertTrue(ref.hasPrefix("res_"))
            // The business enrolled-key records come from ITS OWN confirmed enrollment statements; it verifies everything itself.
            let keys = try await h.enrolledKeys(f)
            let verified = try await h.businessVerifies(f, request: body, resultRef: ref, keys: keys, replay: InMemoryReplayGuard())
            XCTAssertEqual(verified.decision, .approve)
            XCTAssertEqual(verified.claims.amr, .biometric)
            XCTAssertEqual(verified.claims.audience, f.business.id)
            XCTAssertEqual(verified.claims.subject, f.subject)
            XCTAssertEqual(verified.claims.transactionDigest, try ApprovalSubject.transaction(body.transaction!).digest())
            // Audit: the decision is recorded with the method, never with the amount or payee.
            let events = try await h.approvalAudit("approve.request_decided")
            XCTAssertEqual(events.count, 1)
            XCTAssertFalse(events[0].metadataJSON.contains("Example Merchant") || events[0].metadataJSON.contains("250000"))
        }
    }

    func testAuthChallengeRequestsWorkTheSameWay() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            let body = CreateApprovalRequest(requestId: TestHarness.makeRequestId(), subjectRef: f.subject, capability: .authChallenge, challenge: SecureToken.generate(byteCount: 24),
                                             authentication: AuthenticationDetails(actionDisplay: "Sign in to Northwind Bank", reference: "login_77"), expiresInSeconds: 60)
            let created = try await h.businessPost(f.business, "/v1/business/approve/requests", body)
            XCTAssertEqual(created.status, .created, created.text)
            let request = try await h.pendingRequests(f.phone.consumer)[0]
            XCTAssertEqual(request.authentication?.actionDisplay, "Sign in to Northwind Bank")
            let submitted = try await h.submit(f.phone, deliveryId: request.id, result: try await h.answer(f.phone, request))
            XCTAssertEqual(submitted.status, .ok, submitted.text)
            let ref = try unwrap(try await h.requestView(f, body.requestId).resultRef)
            let fetched = try await h.business(f.business, .GET, "/v1/business/approve/results/\(ref)").json(ApprovalResultResponse.self)
            let expectation = ApprovalExpectation(audience: f.business.id, subject: f.subject, requestId: body.requestId, challenge: body.challenge!, subjectDetails: .authentication(body.authentication!))
            let enrolled = try await h.enrolledKeys(f)
            XCTAssertNoThrow(try ApprovalResultVerifier.verify(fetched.result, expecting: expectation, keys: enrolled, now: h.clock.now()))
        }
    }

    // MARK: Acceptance 3: replay

    func testReplayOfASignedApprovalFailsAtTheRelayAndAtTheBusiness() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            let (body, _, request) = try await decide(h, f)
            let jws = try await h.answer(f.phone, request)
            aeq(try await h.submit(f.phone, deliveryId: request.id, result: jws).status, .ok)
            // Replayed to the relay: the request is already decided.
            let replay = try await h.submit(f.phone, deliveryId: request.id, result: jws)
            XCTAssertEqual(replay.status, .conflict)
            // Fetched twice by the business: the second consumption of the one-time challenge fails in its replay cache.
            let ref = try unwrap(try await h.requestView(f, body.requestId).resultRef)
            let cache = InMemoryReplayGuard()
            let keys = try await h.enrolledKeys(f)
            _ = try await h.businessVerifies(f, request: body, resultRef: ref, keys: keys, replay: cache)
            do {
                _ = try await h.businessVerifies(f, request: body, resultRef: ref, keys: keys, replay: cache)
                XCTFail("the same signed approval was accepted twice")
            } catch { XCTAssertEqual(error as? ApprovalVerificationError, .replayed) }
            // The same result cannot authorize a NEW request, even one with identical details (new request id, new challenge).
            let (second, body2) = try await h.createRequest(f)
            XCTAssertEqual(second.status, .created)
            let expectation = ApprovalExpectation(audience: f.business.id, subject: f.subject, requestId: body2.requestId, challenge: body2.challenge!, subjectDetails: .transaction(body2.transaction!))
            XCTAssertThrowsError(try ApprovalResultVerifier.verify(jws, expecting: expectation, keys: keys, now: h.clock.now())) { XCTAssertEqual($0 as? ApprovalVerificationError, .wrongRequest) }
            let sameChallenge = ApprovalExpectation(audience: f.business.id, subject: f.subject, requestId: body.requestId, challenge: body2.challenge!, subjectDetails: .transaction(body.transaction!))
            XCTAssertThrowsError(try ApprovalResultVerifier.verify(jws, expecting: sameChallenge, keys: keys, now: h.clock.now())) { XCTAssertEqual($0 as? ApprovalVerificationError, .challengeMismatch) }
        }
    }

    // MARK: Acceptance 3: substitution of amount, payee, business, nonce, expiry

    func testASubstitutionByACompromisedRelayIsCaughtByTheBusiness() async throws {
        try await withHarness { h in
            // The relay is malicious: between the business's request and the customer's phone it rewrites what the customer is shown.
            // The customer approves what they SEE; the relay's own checks pass (it holds the rewritten copy); the business's check fails.
            let cases: [(String, (inout TransactionDetails) -> Void, ApprovalVerificationError)] = [
                ("amount", { $0.amountMinor = 25_000_000 }, .transactionMismatch),
                ("payee", { $0.payeeDisplay = "Mallory Ltd" }, .transactionMismatch),
                ("currency", { $0.currency = "EUR" }, .transactionMismatch),
                ("reference", { $0.transactionReference = "bank_tx_999" }, .transactionMismatch),
            ]
            for (name, tamper, expected) in cases {
                let f = try await h.approveFixture(name: "Bank \(name)", handle: "bank\(name)")
                let (body, _, _) = try await decide(h, f)
                let record = try unwrap(try await ApproveRequestRecord.query(on: h.db).filter(\.$requestId == body.requestId).first())
                var details = try ViadereJSON.decode(ApproveRequestService.StoredDetails.self, from: try h.ctx.cipher.open(try XCTUnwrap(record.detailsSealed), context: ApproveRequestService.sealContext, rowId: record.id!))
                tamper(&details.transaction!)
                record.detailsSealed = try h.ctx.cipher.seal(try ViadereJSON.encode(details), context: ApproveRequestService.sealContext, rowId: record.id!)
                try await record.update(on: h.db)
                let shown = try await h.pendingRequests(f.phone.consumer)[0]
                let submitted = try await h.submit(f.phone, deliveryId: shown.id, result: try await h.answer(f.phone, shown))
                XCTAssertEqual(submitted.status, .ok, "\(name): the relay's own copy matches what the customer saw, so the relay cannot notice")
                let ref = try unwrap(try await h.requestView(f, body.requestId).resultRef)
                do {
                    _ = try await h.businessVerifies(f, request: body, resultRef: ref, keys: try await h.enrolledKeys(f), replay: InMemoryReplayGuard())
                    XCTFail("\(name) substitution accepted by the business")
                } catch { XCTAssertEqual(error as? ApprovalVerificationError, expected, name) }
            }
            // Nonce: the relay rewrites the stored challenge (so the customer signs another nonce): the business's nonce does not match.
            let f = try await h.approveFixture(name: "Bank nonce", handle: "banknonce")
            let (body, _, _) = try await decide(h, f)
            try await ApproveRequestRecord.query(on: h.db).filter(\.$requestId == body.requestId).set(\.$challenge, to: SecureToken.generate(byteCount: 24)).update()
            let shown = try await h.pendingRequests(f.phone.consumer)[0]
            aeq(try await h.submit(f.phone, deliveryId: shown.id, result: try await h.answer(f.phone, shown)).status, .ok)
            let ref = try unwrap(try await h.requestView(f, body.requestId).resultRef)
            do {
                _ = try await h.businessVerifies(f, request: body, resultRef: ref, keys: try await h.enrolledKeys(f), replay: InMemoryReplayGuard())
                XCTFail()
            } catch { XCTAssertEqual(error as? ApprovalVerificationError, .challengeMismatch) }
        }
    }

    func testTheRelayRefusesResultsThatDoNotBindTheRequest() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            let (body, _, request) = try await decide(h, f)
            let display: ApprovalSubject = .transaction(body.transaction!)
            func content(business: BusinessID? = nil, requestId: String? = nil, challenge: String? = nil, subject: SubjectRef? = nil, details: ApprovalSubject? = nil) -> ApprovalRequestContent {
                ApprovalRequestContent(businessId: business ?? f.business.id, subject: subject ?? f.subject, requestId: requestId ?? body.requestId, challenge: challenge ?? body.challenge!,
                                       details: details ?? display, toKid: f.phone.kid, issuedAt: h.clock.now(), expiresAt: h.clock.now().addingTimeInterval(120))
            }
            func sign(_ c: ApprovalRequestContent, amr: ApprovalAMR = .biometric, at: Date? = nil, key: SoftwareP256SigningKey? = nil) async throws -> String {
                try await ApprovalResultFactory.sign(displayed: c, decision: .approve, amr: amr, key: key ?? f.phone.approvalKey, now: at ?? h.clock.now())
            }
            func rejected(_ jws: String, _ status: HTTPStatus, _ message: String) async throws {
                let r = try await h.submit(f.phone, deliveryId: request.id, result: jws)
                XCTAssertEqual(r.status, status, "\(message): \(r.text)")
            }
            try await rejected(try await sign(content(business: BusinessID())), .forbidden, "other audience")
            try await rejected(try await sign(content(requestId: "req_someone_elses_req_id")), .forbidden, "other request")
            try await rejected(try await sign(content(subject: SubjectRef("sub_" + Base64URL.encode(Data(repeating: 2, count: 32))))), .forbidden, "other subject")
            try await rejected(try await sign(content(challenge: SecureToken.generate(byteCount: 24))), .conflict, "other nonce")
            try await rejected(try await sign(content(details: .transaction(h.transaction(amount: 1)))), .conflict, "other amount")
            try await rejected(try await sign(content(details: .authentication(AuthenticationDetails(actionDisplay: "Sign in")))), .forbidden, "other capability")
            try await rejected(try await sign(content(), at: h.clock.now().addingTimeInterval(-3600)), .gone, "result already expired")
            try await rejected(try await sign(content(), at: h.clock.now().addingTimeInterval(3600)), .unauthorized, "from the future")
            try await rejected(try await sign(content(), key: SoftwareP256SigningKey()), .forbidden, "signed by another key, under its own kid")
            let claims = ApprovalResultClaims(kid: f.phone.kid, audience: f.business.id, subject: f.subject, requestId: body.requestId, challenge: body.challenge!, capability: .transactionApprove,
                                              decision: .approve, amr: .biometric, issuedAt: h.clock.now(), expiresAt: h.clock.now().addingTimeInterval(120), transactionDigest: try display.digest())
            try await rejected(try await ApprovalResultJWS.sign(claims, with: SoftwareP256SigningKey()), .unauthorized, "signed by another key, under the real kid")
            try await rejected(try await sign(content(), amr: .presence), .forbidden, "weaker authentication than the capability needs")
            try await rejected("not.a.jws", .badRequest, "garbage")
            // Algorithm downgrade and unknown critical headers never reach signature verification.
            let header = Base64URL.encode(try CanonicalJSON.serialize(.object(["alg": .string("none"), "kid": .string(f.phone.kid), "typ": .string(ApprovalResultJWS.type)])))
            let good = try await sign(content())
            let payload = good.split(separator: ".")[1]
            try await rejected(header + "." + payload + ".", .badRequest, "alg none")
            let crit = Base64URL.encode(try CanonicalJSON.serialize(.object(["alg": .string("ES256"), "kid": .string(f.phone.kid), "typ": .string(ApprovalResultJWS.type),
                                                                              "crit": .array([.string("x")]), "x": .integer(1)])))
            try await rejected(crit + "." + payload + "." + good.split(separator: ".")[2], .badRequest, "unknown crit")
            // The request is still undecided after all of that, and the real answer still works.
            aeq(try await h.requestView(f, body.requestId).status, .pending)
            aeq(try await h.submit(f.phone, deliveryId: request.id, result: good).status, .ok)
            aeq(try await h.approvalAudit("approve.decision_rejected").count, 14)
        }
    }

    func testAnExpiredRequestCannotBeDecidedAndTheBusinessIsToldOnce() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            let (body, _, request) = try await decide(h, f)
            let jws = try await h.answer(f.phone, request)
            h.clock.advance(by: 125)
            let late = try await h.submit(f.phone, deliveryId: request.id, result: jws)
            XCTAssertEqual(late.status, .gone)
            aeq(try await h.requestView(f, body.requestId).status, .expired)
            try await h.runJobs()
            aeq(try await h.approvalAudit("approve.request_expired").count, 1)
        }
    }

    // MARK: Acceptance 5: a forged relay status

    func testAForgedRelayStatusOrResultIsRejectedByTheBusiness() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            let (body, _, _) = try await decide(h, f)
            // The relay marks the request approved without any customer action. The business sees "approved" and a result reference...
            let ref = ApproveIdentifiers.newResultRef()
            let attackerKey = SoftwareP256SigningKey()
            let attackerKid = KeyIdentifier.make(try attackerKey.publicKey.signingKey())
            let content = ApprovalRequestContent(businessId: f.business.id, subject: f.subject, requestId: body.requestId, challenge: body.challenge!, details: .transaction(body.transaction!),
                                                 toKid: attackerKid, issuedAt: h.clock.now(), expiresAt: h.clock.now().addingTimeInterval(120))
            // ... backed by a "signed result" from the relay's own key, labelled with the customer's real kid.
            let forged = try await ApprovalResultJWS.sign(ApprovalResultClaims(kid: f.phone.kid, audience: f.business.id, subject: f.subject, requestId: body.requestId, challenge: body.challenge!,
                                                                               capability: .transactionApprove, decision: .approve, amr: .biometric, issuedAt: h.clock.now(),
                                                                               expiresAt: h.clock.now().addingTimeInterval(120), transactionDigest: try content.details.digest()), with: attackerKey)
            try await ApproveRequestRecord.query(on: h.db).filter(\.$requestId == body.requestId).set(\.$status, to: "approved").set(\.$resultRef, to: ref).set(\.$resultJWS, to: forged)
                .set(\.$decidedKid, to: f.phone.kid).set(\.$decidedAt, to: h.clock.now()).update()
            let status = try await h.requestView(f, body.requestId)
            XCTAssertEqual(status.status, .approved, "the relay's status says approved")
            do {
                _ = try await h.businessVerifies(f, request: body, resultRef: ref, keys: try await h.enrolledKeys(f), replay: InMemoryReplayGuard())
                XCTFail("a forged relay result authorized a transaction")
            } catch { XCTAssertEqual(error as? ApprovalVerificationError, .badSignature) }
            // Signed by an attacker key under the attacker's own kid: not an enrolled key.
            let ownKid = try await ApprovalResultJWS.sign(ApprovalResultClaims(kid: attackerKid, audience: f.business.id, subject: f.subject, requestId: body.requestId, challenge: body.challenge!,
                                                                              capability: .transactionApprove, decision: .approve, amr: .biometric, issuedAt: h.clock.now(),
                                                                              expiresAt: h.clock.now().addingTimeInterval(120), transactionDigest: try content.details.digest()), with: attackerKey)
            try await ApproveRequestRecord.query(on: h.db).filter(\.$requestId == body.requestId).set(\.$resultJWS, to: ownKid).update()
            do {
                _ = try await h.businessVerifies(f, request: body, resultRef: ref, keys: try await h.enrolledKeys(f), replay: InMemoryReplayGuard())
                XCTFail()
            } catch { XCTAssertEqual(error as? ApprovalVerificationError, .unknownKey) }
            // And "approved" with no result at all is nothing: there is no result to fetch.
            let bare = try await h.createRequest(f)
            try await ApproveRequestRecord.query(on: h.db).filter(\.$requestId == bare.1.requestId).set(\.$status, to: "approved").update()
            aeq(try await h.requestView(f, bare.1.requestId).resultRef, nil)
            aeq(try await h.business(f.business, .GET, "/v1/business/approve/results/\(ApproveIdentifiers.newResultRef())").status, .notFound)
        }
    }

    func testResultsAreRecipientBound() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            let (body, _, request) = try await decide(h, f)
            aeq(try await h.submit(f.phone, deliveryId: request.id, result: try await h.answer(f.phone, request)).status, .ok)
            let ref = try unwrap(try await h.requestView(f, body.requestId).resultRef)
            let other = try await h.makeBusiness(name: "Other Bank", handle: "otherbank4")
            aeq(try await h.business(other, .GET, "/v1/business/approve/results/\(ref)").status, .notFound)
            aeq(try await h.business(other, .GET, "/v1/business/approve/requests/\(body.requestId)").status, .notFound)
            // A key without the approval capability cannot read it either.
            let messaging = try await BusinessAPIKeys.issue(businessId: f.business.record.id!, name: "m", live: true, scopes: BusinessAPIKeys.Scope.all, capabilities: Capability.messaging, now: h.clock.now(), on: h.db).key
            aeq(try await h.business(f.business, .GET, "/v1/business/approve/results/\(ref)", key: messaging).status, .forbidden)
            // A test-mode key of the same business cannot read live results.
            let test = try await BusinessAPIKeys.issue(businessId: f.business.record.id!, name: "t", live: false, scopes: BusinessAPIKeys.Scope.all, capabilities: Capability.operational, now: h.clock.now(), on: h.db).key
            aeq(try await h.business(f.business, .GET, "/v1/business/approve/results/\(ref)", key: test).status, .notFound)
            // The webhook carries only the reference, never the result.
            XCTAssertFalse(ref.isEmpty)
        }
    }

    func testDenyAndReportAreSignedAndNeverAuthorize() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            for (decision, status) in [(ApprovalDecision.deny, ApprovalRequestStatus.denied), (.report, .reported)] {
                let (body, _, request) = try await decide(h, f)
                aeq(try await h.submit(f.phone, deliveryId: request.id, result: try await h.answer(f.phone, request, decision: decision)).status, .ok)
                let view = try await h.requestView(f, body.requestId)
                XCTAssertEqual(view.status, status)
                let ref = try XCTUnwrap(view.resultRef)
                do {
                    _ = try await h.businessVerifies(f, request: body, resultRef: ref, keys: try await h.enrolledKeys(f), replay: InMemoryReplayGuard())
                    XCTFail("a refusal authorized something")
                } catch { XCTAssertEqual(error as? ApprovalVerificationError, .notApproved(decision)) }
            }
            aeq(try await h.approvalAudit("approve.reported_suspicious").count, 1)
        }
    }

    // MARK: Request creation rules

    func testCreationIsIdempotentValidatedAndPolicyChecked() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            let id = TestHarness.makeRequestId()
            let challenge = SecureToken.generate(byteCount: 24)
            let first = try await h.createRequest(f, requestId: id, challenge: challenge)
            XCTAssertEqual(first.0.status, .created)
            let replay = try await h.createRequest(f, requestId: id, challenge: challenge)
            XCTAssertEqual(replay.0.status, .ok, "same id, same request: the original")
            let different = try await h.createRequest(f, requestId: id, challenge: challenge, details: h.transaction(amount: 999))
            XCTAssertEqual(different.0.status, .conflict)
            XCTAssertEqual(different.0.errorCode, .idempotencyConflict)
            aeq(try await ApproveRequestRecord.query(on: h.db).count(), 1)
            // Validation: nonce, amounts, hostile display text, ids, lifetimes.
            let bad: [(String, CreateApprovalRequest)] = [
                ("short nonce", CreateApprovalRequest(requestId: TestHarness.makeRequestId(), subjectRef: f.subject, capability: .transactionApprove, challenge: "abc", transaction: h.transaction())),
                ("no nonce", CreateApprovalRequest(requestId: TestHarness.makeRequestId(), subjectRef: f.subject, capability: .transactionApprove, transaction: h.transaction())),
                ("zero amount", CreateApprovalRequest(requestId: TestHarness.makeRequestId(), subjectRef: f.subject, capability: .transactionApprove, challenge: challenge, transaction: h.transaction(amount: 0))),
                ("bidi payee", CreateApprovalRequest(requestId: TestHarness.makeRequestId(), subjectRef: f.subject, capability: .transactionApprove, challenge: challenge, transaction: h.transaction(payee: "Mer\u{202E}tnahc"))),
                ("short id", CreateApprovalRequest(requestId: "short", subjectRef: f.subject, capability: .transactionApprove, challenge: challenge, transaction: h.transaction())),
                ("both modes", CreateApprovalRequest(requestId: TestHarness.makeRequestId(), subjectRef: f.subject, capability: .transactionApprove, challenge: challenge, transaction: h.transaction(),
                                                     envelopes: [])),
                ("long ttl", CreateApprovalRequest(requestId: TestHarness.makeRequestId(), subjectRef: f.subject, capability: .transactionApprove, challenge: challenge, transaction: h.transaction(), expiresInSeconds: 3600)),
                ("wrong capability", CreateApprovalRequest(requestId: TestHarness.makeRequestId(), subjectRef: f.subject, capability: .transactionApprove, challenge: challenge,
                                                           authentication: AuthenticationDetails(actionDisplay: "Sign in"))),
            ]
            for (name, request) in bad {
                let result = try await h.businessPost(f.business, "/v1/business/approve/requests", request)
                XCTAssertEqual(result.status, .unprocessableEntity, "\(name): \(result.text)")
            }
            // Raw phone number or a customer of another business.
            let phone = try await h.business(f.business, .POST, "/v1/business/approve/requests", body: Data(#"{"request_id":"req_0123456789abcdefg","subject_ref":"+15555550100","capability":"transaction.approve"}"#.utf8))
            XCTAssertEqual(phone.status, .badRequest)
            // Policy: a messaging key, an unentitled business, a revoked entitlement and the operator kill switch all stop it before the customer is touched.
            let messaging = try await BusinessAPIKeys.issue(businessId: f.business.record.id!, name: "m", live: true, scopes: BusinessAPIKeys.Scope.all, capabilities: Capability.messaging, now: h.clock.now(), on: h.db).key
            let denied = try await h.businessPost(f.business, "/v1/business/approve/requests", CreateApprovalRequest(requestId: TestHarness.makeRequestId(), subjectRef: f.subject, capability: .transactionApprove,
                                                                                                                  challenge: challenge, transaction: h.transaction()), key: messaging)
            XCTAssertEqual(denied.errorCode, .insufficientScope)
            try await CapabilitySwitchRecord(capability: Capability.transactionApprove.rawValue, scope: CapabilitySwitchRecord.globalScope, disabled: true, reason: "test", updatedBy: "test", now: h.clock.now()).create(on: h.db)
            await h.ctx.policyCache.invalidate()
            let switched = try await h.createRequest(f)
            XCTAssertEqual(switched.0.status, .forbidden)
            XCTAssertEqual(switched.0.errorCode, .capabilityDisabled)
        }
    }

    func testTestKeysAndSandboxesStayApart() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            let test = try await BusinessAPIKeys.issue(businessId: f.business.record.id!, name: "t", live: false, scopes: BusinessAPIKeys.Scope.all, capabilities: Capability.operational, now: h.clock.now(), on: h.db).key
            // A test key cannot reach a real customer, cannot publish to the production log, and cannot start enrollments for one.
            let body = CreateApprovalRequest(requestId: TestHarness.makeRequestId(), subjectRef: f.subject, capability: .transactionApprove, challenge: SecureToken.generate(byteCount: 24), transaction: h.transaction())
            aeq(try await h.businessPost(f.business, "/v1/business/approve/requests", body, key: test).status, .forbidden)
            let enroll = try await h.businessPost(f.business, "/v1/business/approve/enrollments", CreateApprovalEnrollmentRequest(subjectRef: f.subject, capability: .transactionApprove), key: test)
            XCTAssertEqual(enroll.status, .forbidden)
            let keys = TestBusinessKeys()
            let entry = try await KeyLogEntry.sign(.root(RootRegistration(businessId: f.business.id, publicKey: keys.root.publicKey, createdAt: h.clock.now())), rootKey: keys.root)
            aeq(try await h.publishEntry(f.business, entry, key: test).status, .forbidden)
        }
    }

    // MARK: Freeze (APP-007)

    func testAConsumerFreezeStopsEverythingImmediatelyAndOnlyABiometricProofFromATrustedDeviceLiftsIt() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            let (body, _, request) = try await decide(h, f)
            // Freeze the account: pending requests are cancelled, the app sees nothing, new requests are refused.
            let freeze = try await h.signedPost(f.phone.consumer, "/v1/approve/freeze", ApproveFreezeRequest(scope: .account, frozen: true))
            XCTAssertEqual(freeze.status, .ok, freeze.text)
            XCTAssertTrue(try freeze.json(ApproveFreezeState.self).accountFrozen)
            aeq(try await h.requestView(f, body.requestId).status, .cancelled)
            atrue(try await h.pendingRequests(f.phone.consumer).isEmpty)
            let refused = try await h.createRequest(f)
            XCTAssertEqual(refused.0.status, .conflict)
            XCTAssertEqual(refused.0.errorCode, .approvalsFrozen)
            aeq(try await h.submit(f.phone, deliveryId: request.id, result: try await h.answer(f.phone, request)).status, .conflict, "a stale answer to a cancelled request")
            // Enrollment is blocked while frozen too.
            let enroll = try await h.businessPost(f.business, "/v1/business/approve/enrollments", CreateApprovalEnrollmentRequest(subjectRef: f.subject, capability: .transactionApprove))
            XCTAssertEqual(enroll.errorCode, .approvalsFrozen)
            // Audit and notice.
            aeq(try await h.approvalAudit("approve.frozen").count, 1)
            atrue(try await SecurityNoticeRecord.query(on: h.db).filter(\.$kind == SecurityNoticeTopic.approvalsFrozen.rawValue).count() > 0)

            // Lifting needs a biometric proof. None / wrong key / a request key / the passcode key: all refused.
            let device = f.phone.consumer.device!
            func unfreeze(_ proof: SignedStatement?) async throws -> HTTPResult {
                try await h.signedPost(f.phone.consumer, "/v1/approve/freeze", ApproveFreezeRequest(scope: .account, frozen: false, proof: proof))
            }
            aeq(try await unfreeze(nil).status, .forbidden)
            let proof = ApproveFreezeProof(scope: .account, relationshipId: nil, deviceId: device.id, signedAt: h.clock.now())
            aeq(try await unfreeze(try await proof.sign(with: device.passcodeKey)).status, .forbidden)
            aeq(try await unfreeze(try await proof.sign(with: device.requestKey)).status, .forbidden)
            aeq(try await unfreeze(try await proof.sign(with: SoftwareP256SigningKey())).status, .forbidden)
            // A proof for another scope, another device, or a stale one.
            let relationshipScoped = ApproveFreezeProof(scope: .relationship, relationshipId: f.relationship.id, deviceId: device.id, signedAt: h.clock.now())
            aeq(try await unfreeze(try await relationshipScoped.sign(with: device.biometricKey)).status, .forbidden)
            let otherDevice = ApproveFreezeProof(scope: .account, relationshipId: nil, deviceId: DeviceID(), signedAt: h.clock.now())
            aeq(try await unfreeze(try await otherDevice.sign(with: device.biometricKey)).status, .forbidden)
            let stale = ApproveFreezeProof(scope: .account, relationshipId: nil, deviceId: device.id, signedAt: h.clock.now().addingTimeInterval(-3600))
            aeq(try await unfreeze(try await stale.sign(with: device.biometricKey)).status, .forbidden)
            aeq(try await h.createRequest(f).0.status, .conflict, "still frozen")
            // The real proof works once; replayed after a re-freeze it is refused.
            let good = try await proof.sign(with: device.biometricKey)
            aeq(try await unfreeze(good).status, .ok)
            aeq(try await h.createRequest(f).0.status, .created)
            aeq(try await h.signedPost(f.phone.consumer, "/v1/approve/freeze", ApproveFreezeRequest(scope: .account, frozen: true)).status, .ok)
            aeq(try await unfreeze(good).status, .conflict)
            aeq(try await h.approvalAudit("approve.unfreeze_rejected").count, 7)
        }
    }

    func testANewDeviceInItsCoolDownCannotLiftAFreeze() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            aeq(try await h.signedPost(f.phone.consumer, "/v1/approve/freeze", ApproveFreezeRequest(scope: .account, frozen: true)).status, .ok)
            // The thief's new device can freeze (safe) but never unfreeze.
            let thief = try await h.enrollDevice(f.phone.consumer)
            let device = thief.device!
            let proof = ApproveFreezeProof(scope: .account, relationshipId: nil, deviceId: device.id, signedAt: h.clock.now())
            let result = try await h.signedPost(thief, "/v1/approve/freeze", ApproveFreezeRequest(scope: .account, frozen: false, proof: try await proof.sign(with: device.biometricKey)))
            XCTAssertEqual(result.status, .forbidden)
            XCTAssertEqual(result.errorCode, .deviceCoolDown)
            aeq(try await h.createRequest(f).0.errorCode, .approvalsFrozen)
        }
    }

    func testRelationshipFreezesAreIndependentAndBusinessesCanFreezeToo() async throws {
        try await withHarness { h in
            let f1 = try await h.approveFixture(name: "Bank One", handle: "bankone")
            let b2 = try await h.makeBusiness(name: "Bank Two", handle: "banktwo")
            let k2 = try await h.publishDirectory(b2)
            let rel2 = try await h.connect(f1.phone.consumer, to: b2)
            let phone2 = try await h.enrollApproval(f1.phone.consumer, business: b2, keys: k2)
            let f2 = ApproveFixture(business: b2, keys: k2, relationship: rel2, subject: h.subjectRef(b2, f1.phone.consumer), phone: phone2)
            // Freezing business one leaves business two untouched.
            aeq(try await h.signedPost(f1.phone.consumer, "/v1/approve/freeze", ApproveFreezeRequest(scope: .relationship, relationshipId: f1.relationship.id, frozen: true)).status, .ok)
            aeq(try await h.createRequest(f1).0.errorCode, .approvalsFrozen)
            aeq(try await h.createRequest(f2).0.status, .created)
            // A relationship the caller does not own is a 404.
            let stranger = try await h.readyConsumer(name: "Stranger")
            aeq(try await h.signedPost(stranger, "/v1/approve/freeze", ApproveFreezeRequest(scope: .relationship, relationshipId: f1.relationship.id, frozen: true)).status, .notFound)
            // The business freezes the second relationship: its requests stop, and the customer's unfreezing cannot undo the business's freeze.
            let freeze = try await h.businessPost(b2, "/v1/business/approve/freeze", BusinessFreezeRequest(subjectRef: f2.subject, frozen: true, reason: "fraud review"))
            XCTAssertEqual(freeze.status, .ok, freeze.text)
            XCTAssertTrue(try freeze.json(FreezeStatus.self).frozen)
            aeq(try await h.createRequest(f2).0.errorCode, .approvalsFrozen)
            atrue(try await h.pendingRequests(f1.phone.consumer).isEmpty, "the earlier request of the frozen relationship was cancelled")
            let device = f1.phone.consumer.device!
            let proof = ApproveFreezeProof(scope: .relationship, relationshipId: f2.relationship.id, deviceId: device.id, signedAt: h.clock.now())
            aeq(try await h.signedPost(f1.phone.consumer, "/v1/approve/freeze", ApproveFreezeRequest(scope: .relationship, relationshipId: f2.relationship.id, frozen: false, proof: try await proof.sign(with: device.biometricKey))).status, .ok)
            aeq(try await h.createRequest(f2).0.errorCode, .approvalsFrozen, "the business's own freeze stays")
            // The business lifts only its own.
            aeq(try await h.businessPost(b2, "/v1/business/approve/freeze", BusinessFreezeRequest(subjectRef: f2.subject, frozen: false)).status, .ok)
            aeq(try await h.createRequest(f2).0.status, .created)
            // Another business can't freeze someone else's customer.
            aeq(try await h.businessPost(b2, "/v1/business/approve/freeze", BusinessFreezeRequest(subjectRef: f1.subject, frozen: true)).status, .notFound)
        }
    }

    // MARK: Prompt fatigue (SEC-DEV-008)

    func testRepeatedDenialsAutoDenyAndTooManyRequestsAreRateLimited() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            // The app is told when the customer has received several requests.
            var flags: [Bool] = []
            for index in 0..<3 {
                let (_, _, request) = try await decide(h, f)
                flags.append(request.showFatigueWarning)
                XCTAssertEqual(request.requestsInWindow, index + 1)
                aeq(try await h.submit(f.phone, deliveryId: request.id, result: try await h.answer(f.phone, request, decision: .deny)).status, .ok)
            }
            XCTAssertEqual(flags, [false, false, true])
            // Three denials: further requests are auto-denied without a prompt, with a notice to the customer (once).
            let (auto, autoBody) = try await h.createRequest(f)
            XCTAssertEqual(auto.status, .created, auto.text)
            let view = try auto.json(ApprovalRequestView.self)
            XCTAssertEqual(view.status, .denied)
            XCTAssertEqual(view.reason, "auto_denied")
            XCTAssertEqual(view.deliveredTo, 0)
            XCTAssertNil(view.resultRef, "an auto-denial has no signed result: there is nothing to trust")
            atrue(try await h.pendingRequests(f.phone.consumer).isEmpty)
            _ = try await h.createRequest(f)
            aeq(try await SecurityNoticeRecord.query(on: h.db).filter(\.$kind == SecurityNoticeTopic.approvalRequestsPaused.rawValue).count(), 1)
            aeq(try await h.requestView(f, autoBody.requestId).status, .denied)
            // After the pause an honest request goes through again.
            h.clock.advance(by: 610)
            let ok = try await ApproveRequestService(db: h.db, ctx: h.ctx).promptVerdict(relationshipId: f.relationship.id.uuid, now: h.clock.now())
            if case .autoDeny = ok { h.clock.advance(by: 3000) }
        }
    }

    func testRequestFloodsAreRateLimitedPerRelationship() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            var statuses: [HTTPStatus] = []
            for _ in 0..<12 {
                let (result, _) = try await h.createRequest(f)
                statuses.append(result.status)
                if result.status == .created, let view = try? result.json(ApprovalRequestView.self) {
                    // Approve each so the pending cap is not what limits them.
                    if let request = try await h.pendingRequests(f.phone.consumer).first(where: { $0.requestId == view.requestId }) {
                        _ = try await h.submit(f.phone, deliveryId: request.id, result: try await h.answer(f.phone, request))
                    }
                }
            }
            XCTAssertEqual(statuses.prefix(6).filter { $0 == .created }.count, 6)
            XCTAssertTrue(statuses.dropFirst(6).allSatisfy { $0 == .tooManyRequests }, "\(statuses)")
        }
    }

    func testOpenRequestsPerCustomerAreCapped() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            var statuses: [HTTPStatus] = []
            for _ in 0..<5 { statuses.append(try await h.createRequest(f).0.status) }
            XCTAssertEqual(statuses, [.created, .created, .created, .tooManyRequests, .tooManyRequests])
        }
    }

    // MARK: Gate

    func testEveryApproveAndDirectoryRouteAnswers404WhileTheGateIsOff() async throws {
        try await withHarness({ $0.approve.enabled = false }) { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            let consumer = try await h.readyConsumer()
            let routes: [AnyEndpoint] = APIRoutes.all.filter { $0.template.contains("/approve") || $0.template.contains("/key-directory") }
            XCTAssertGreaterThanOrEqual(routes.count, 24)
            for route in routes {
                let path = route.template.replacingOccurrences(of: "{enrollmentId}", with: UUID().uuidString.lowercased()).replacingOccurrences(of: "{approvalId}", with: UUID().uuidString.lowercased())
                    .replacingOccurrences(of: "{requestId}", with: "req_0123456789abcdefg").replacingOccurrences(of: "{resultRef}", with: ApproveIdentifiers.newResultRef())
                    .replacingOccurrences(of: "{kid}", with: String(repeating: "A", count: 43)).replacingOccurrences(of: "{businessId}", with: b.id.description)
                let method = NIOHTTP1.HTTPMethod(rawValue: route.method.rawValue)
                let result: HTTPResult
                switch route.auth {
                case .businessAPIKey: result = try await h.business(b, method, path, body: method == .GET ? nil : Data("{}".utf8))
                case .deviceSignedBearer: result = try await h.signed(consumer, method, path, body: method == .GET ? nil : Data("{}".utf8))
                default: result = try await h.request(method, path)
                }
                XCTAssertEqual(result.status, .notFound, "\(route.method) \(path)")
            }
        }
    }

    func testTheGateParsesFromTheEnvironment() throws {
        func config(_ env: [String: String]) throws -> ServerConfig {
            var base = ["ENVIRONMENT": "development"]
            for (k, v) in env { base[k] = v }
            return try ServerConfig.fromEnvironment(base)
        }
        XCTAssertTrue(try config([:]).approve.enabled, "on in development")
        XCTAssertFalse(try config(["APPROVE_V2_ENABLED": "false"]).approve.enabled)
        XCTAssertThrowsError(try config(["APPROVE_V2_ENABLED": "yes"]))
        XCTAssertThrowsError(try config(["KEY_DIRECTORY_LOG_KEY": "not-a-key"]))
        let key = SoftwareP256SigningKey()
        XCTAssertEqual(try config(["KEY_DIRECTORY_LOG_KEY": Base64URL.encode(key.rawRepresentation)]).approve.logKey.publicKey, key.publicKey)
        // With a database the log key is mandatory: an ephemeral one would orphan every signed head after a restart.
        XCTAssertThrowsError(try config(["DATABASE_URL": "postgres://x/y", "CONNECT_LINK_SIGNING_KEY": Base64URL.encode(Data(repeating: 1, count: 32)), "SERVER_PEPPER": Base64URL.encode(Data(repeating: 2, count: 32)),
                                          "DATA_ENCRYPTION_KEY": Base64URL.encode(Data(repeating: 3, count: 32)), "AUDIT_CHAIN_KEY": Base64URL.encode(Data(repeating: 4, count: 32)),
                                          "SUBJECT_REF_KEY": Base64URL.encode(Data(repeating: 5, count: 32))]))
    }
}
