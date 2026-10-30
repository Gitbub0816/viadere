@preconcurrency import Crypto
import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// What the customer's phone holds after completing a link session.
struct TestLinkPhone {
    var consumer: TestConsumer
    var offer: LinkSessionOffer
    var statement: SignedStatement
    var approvalStatement: SignedStatement?
    var approvalKey: SoftwareP256SigningKey?
    var hpke: SoftwareE2EEPrivateKey?
    var connectionKey: SoftwareP256SigningKey
    var bindingTag: String?
}

/// What the business holds for one session (its secret never goes to Viadere).
struct TestLinkInvitation {
    var ticket: LinkSessionTicket
    var secret: LinkSessionSecret
}

extension TestHarness {
    func createLinkSession(_ b: TestBusiness, capabilities: [Capability] = [.messageSend, .transactionApprove], customerRef: String = "cust_" + SecureToken.generate(byteCount: 8),
                           hint: String? = "Account ending 4821", expiresIn: Int? = nil, key: String? = nil) async throws -> (HTTPResult, TestLinkInvitation?) {
        let result = try await businessPost(b, APIRoutes.businessLinkSessionCreate.template,
                                            CreateLinkSessionRequest(customerRef: customerRef, capabilities: capabilities, displayHint: hint, expiresInSeconds: expiresIn), key: key)
        guard result.status == .created else { return (result, nil) }
        return (result, TestLinkInvitation(ticket: try result.json(LinkSessionTicket.self), secret: LinkSessionSecret()))
    }

    func lookupLink(_ consumer: TestConsumer, code: String) async throws -> HTTPResult {
        try await signedPost(consumer, APIRoutes.linkSessionLookup.template, LinkSessionLookupRequest(code: code))
    }

    /// The phone: looks the code up, verifies the descriptor with Viadere's pinned key, signs, completes.
    func completeLink(_ consumer: TestConsumer, _ invitation: TestLinkInvitation, useSecret: Bool = true, assurance: ApprovalAMR = .biometric,
                      tamper: ((inout LinkStatement) -> Void)? = nil, expect: HTTPStatus? = .created) async throws -> (HTTPResult, TestLinkPhone?) {
        let looked = try await lookupLink(consumer, code: LinkSessionCode.display(invitation.ticket.code))
        guard looked.status == .ok else { return (looked, nil) }
        let offer = try looked.json(LinkSessionOffer.self)
        let descriptor = try LinkSessionDescriptor.verify(offer.descriptor, trustedKeys: [config.approve.linkDescriptorKey.publicKey], now: clock.now())
        var approvalSigned: SignedStatement?
        var approvalKey: SoftwareP256SigningKey?
        var hpke: SoftwareE2EEPrivateKey?
        if !LinkCapabilities.approval(descriptor.capabilities).isEmpty {
            let key = SoftwareP256SigningKey()
            let h = SoftwareE2EEPrivateKey()
            approvalSigned = try await ApprovalEnrollmentStatement(businessId: descriptor.businessId, subject: descriptor.subject, enrollmentId: descriptor.sessionId,
                                                                   publicKey: key.publicKey, hpkePublicKey: h.publicKey, assurance: assurance, createdAt: clock.now()).sign(with: key)
            approvalKey = key
            hpke = h
        }
        let connectionKey = SoftwareP256SigningKey()
        var statement = try LinkStatement(sessionId: descriptor.sessionId, businessId: descriptor.businessId, subject: descriptor.subject, capabilities: descriptor.capabilities,
                                          descriptorDigest: LinkSessionDescriptor.digest(of: offer.descriptor), publicKey: connectionKey.publicKey,
                                          approvalStatement: approvalSigned, createdAt: clock.now())
        tamper?(&statement)
        let signed = try await statement.sign(with: connectionKey)
        let tag = useSecret ? invitation.secret.bindingTag(for: signed) : nil
        let completed = try await signedPost(consumer, "/v1/link-sessions/\(descriptor.sessionId.uuidString.lowercased())/complete",
                                             CompleteLinkSessionRequest(statement: signed, bindingTag: tag, approvalStatement: approvalSigned))
        if let expect { XCTAssertEqual(completed.status, expect, completed.text) }
        return (completed, TestLinkPhone(consumer: consumer, offer: offer, statement: signed, approvalStatement: approvalSigned, approvalKey: approvalKey, hpke: hpke,
                                         connectionKey: connectionKey, bindingTag: tag))
    }

    func linkView(_ b: TestBusiness, _ sessionId: UUID, key: String? = nil) async throws -> HTTPResult {
        try await business(b, .GET, "/v1/business/link-sessions/\(sessionId.uuidString.lowercased())", key: key)
    }

    /// The business: verifies the statement itself (binding tag or SAS), then confirms with its directory key.
    func confirmLink(_ b: TestBusiness, keys: TestBusinessKeys, _ invitation: TestLinkInvitation, sas: String? = nil, signer: SoftwareP256SigningKey? = nil,
                     key: String? = nil) async throws -> HTTPResult {
        let view = try await linkView(b, invitation.ticket.sessionId).json(LinkSessionView.self)
        let signed = try XCTUnwrap(view.statement)
        let statement = try LinkStatement.verify(signed)
        if let tag = view.bindingTag { XCTAssertTrue(invitation.secret.verifyBindingTag(tag, for: signed)) }
        if let sas { XCTAssertTrue(invitation.secret.verifySAS(sas, for: signed)) }
        let confirmKey = signer ?? keys.confirmation
        let confirmation = try await LinkConfirmation(confirming: statement, signed: signed, verification: sas == nil ? .sasCompared : .sasTyped, at: clock.now())
            .sign(with: confirmKey)
        var approvalConfirmation: BusinessSignedStatement?
        if let approval = view.approvalStatement {
            approvalConfirmation = try await ApprovalEnrollmentConfirmation(confirming: try ApprovalEnrollmentStatement.verify(approval), signed: approval, at: clock.now())
                .sign(with: confirmKey)
        }
        return try await businessPost(b, "/v1/business/link-sessions/\(invitation.ticket.sessionId.uuidString.lowercased())/confirm",
                                      ConfirmLinkSessionRequest(confirmation: confirmation, approvalConfirmation: approvalConfirmation), key: key)
    }
}

/// WP-C1 business link sessions (`docs/SECURITY.md` §2.59), spec §12 "Business linking": the QR expires and is one-time; session swapping, tenant
/// confusion and unauthorized linking are rejected. Plus the cross-tenant checks of spec v4 D3 for every new endpoint.
final class LinkSessionTests: XCTestCase {
    // MARK: Happy path

    func testTheConnectionIsActiveOnlyAfterTheBusinessConfirms() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            let keys = try await h.publishDirectory(b)
            let consumer = try await h.readyConsumer()
            let (created, invitation) = try await h.createLinkSession(b)
            XCTAssertEqual(created.status, .created, created.text)
            let ticket = try XCTUnwrap(invitation).ticket
            XCTAssertEqual(ticket.link, "https://viadere.com/k/\(ticket.code)", "the relay's suggestion carries no secret")
            XCTAssertEqual(ticket.rootKid, keys.rootKid)
            // The device's descriptor is signed by Viadere's link-descriptor key and names the business, the account and the capabilities.
            let (completed, phone) = try await h.completeLink(consumer, try XCTUnwrap(invitation))
            let device = try completed.json(LinkSessionDeviceView.self)
            XCTAssertEqual(device.status, .deviceCompleted)
            XCTAssertEqual(device.connection?.status, .pending)
            XCTAssertEqual(device.alert.category, .linkConfirmation)
            XCTAssertTrue(device.alert.actionable)
            let subject = h.subjectRef(b, consumer)
            XCTAssertEqual(try XCTUnwrap(phone).offer.subjectRef, subject)

            // Before confirmation: nothing is connected. The customer does not list it; the business cannot message or ask.
            let listed = try await h.signed(consumer, .GET, APIRoutes.relationshipsList.template).json([Relationship].self)
            XCTAssertTrue(listed.isEmpty)
            let early = try await h.createRequest(ApproveFixture(business: b, keys: keys, relationship: Relationship(id: RelationshipID(), consumerId: consumer.id,
                business: b.summary, status: .active, source: .qr, connectedAt: h.clock.now()), subject: subject,
                phone: TestApprovalDevice(consumer: consumer, approvalKey: SoftwareP256SigningKey(), hpke: SoftwareE2EEPrivateKey(), assurance: .biometric))).0
            XCTAssertEqual(early.status, .conflict, early.text)

            // The business view: subject_ref (= connection_id), the statement, the tag, the approval statement, and Viadere's signed result.
            let view = try await h.linkView(b, ticket.sessionId).json(LinkSessionView.self)
            XCTAssertEqual(view.status, .deviceCompleted)
            XCTAssertEqual(view.subjectRef, subject)
            XCTAssertEqual(view.connectionId, subject)
            let result = try LinkResult.verify(try XCTUnwrap(view.result), trustedKeys: [h.config.approve.linkDescriptorKey.publicKey])
            XCTAssertEqual(result.subject, subject)
            XCTAssertEqual(result.statementDigest, LinkStatement.digest(of: try XCTUnwrap(view.statement)))
            // The SAS the phone shows equals the one the business computes from its secret.
            let phoneSAS = try XCTUnwrap(LinkSAS.compute(checkCode: try XCTUnwrap(invitation).secret.checkCode, statement: try XCTUnwrap(phone).statement))
            let confirmed = try await h.confirmLink(b, keys: keys, try XCTUnwrap(invitation), sas: phoneSAS)
            XCTAssertEqual(confirmed.status, .ok, confirmed.text)
            XCTAssertEqual(try confirmed.json(LinkSessionView.self).status, .confirmed)

            // Now: active, scoped, with its evidence; the approval key is active and an approval round trip works.
            let relationship = try await XCTUnwrapAsync(try await RelationshipRecord.query(on: h.db).filter(\.$consumerId == consumer.id.uuid).filter(\.$businessId == b.id.uuid).first())
            XCTAssertTrue(relationship.isActive)
            XCTAssertEqual(relationship.linkSessionId, ticket.sessionId)
            XCTAssertEqual(relationship.evidenceDigest, result.statementDigest)
            XCTAssertEqual(relationship.scopeList.map(\.rawValue), ["message.send", "transaction.approve"])
            XCTAssertEqual(relationship.connectionMethod, "link_session")
            let approvalKid = try XCTUnwrap(try XCTUnwrap(phone).approvalStatement.map { try ApprovalEnrollmentStatement.verify($0).kid })
            let key = try await XCTUnwrapAsync(try await ApproveKeyRecord.query(on: h.db).filter(\.$kid == approvalKid).first())
            XCTAssertTrue(key.isActive)
            XCTAssertEqual(key.enrollmentId, ticket.sessionId)
            let deviceAfter = try await h.signed(consumer, .GET, "/v1/link-sessions/\(ticket.sessionId.uuidString.lowercased())").json(LinkSessionDeviceView.self)
            // The phone verifies the business's confirmation against the directory and its own statement.
            let confirmation = try LinkConfirmation.verify(try XCTUnwrap(deviceAfter.confirmation), confirmationKey: keys.confirmation.publicKey)
            try confirmation.checkMatches(try LinkStatement.verify(try XCTUnwrap(phone).statement), signed: try XCTUnwrap(phone).statement)
            XCTAssertEqual(deviceAfter.connection?.status, .active)
            XCTAssertFalse(deviceAfter.alert.actionable, "a finished item is never actionable")

            let fixture = ApproveFixture(business: b, keys: keys, relationship: try await h.signed(consumer, .GET, APIRoutes.relationshipsList.template).json([Relationship].self)[0],
                                         subject: subject, phone: TestApprovalDevice(consumer: consumer, approvalKey: try XCTUnwrap(try XCTUnwrap(phone).approvalKey),
                                                                                     hpke: try XCTUnwrap(try XCTUnwrap(phone).hpke), assurance: .biometric))
            let (request, body) = try await h.createRequest(fixture)
            XCTAssertEqual(request.status, .created, request.text)
            let pending = try await XCTUnwrapAsync(try await h.pendingRequests(consumer).first { $0.requestId == body.requestId })
            XCTAssertEqual(pending.alert?.category, .approval)
            let refetched = try await h.pendingRequests(consumer).first?.alert?.eventId
            XCTAssertEqual(pending.alert?.eventId, refetched, "the event id is stable across fetches")
            aeq(try await h.submit(fixture.phone, deliveryId: pending.id, result: try await h.answer(fixture.phone, pending)).status, .ok)
            atrue(try await h.approvalAudit("link.session_confirmed").count == 1)
            atrue(try await SecurityNoticeRecord.query(on: h.db).filter(\.$kind == SecurityNoticeTopic.businessLinked.rawValue).count() == 1)
        }
    }

    // MARK: One-time and expiring (spec §12)

    func testASecondConsumeIsAConflictAndTheCodeIsSpent() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            _ = try await h.publishDirectory(b)
            let first = try await h.readyConsumer()
            let thief = try await h.readyConsumer(name: "Thief")
            let invitation = try unwrap(try await h.createLinkSession(b, capabilities: [.messageSend]).1)
            // The thief looked the code up too (a photographed QR), but only one completion wins.
            let thiefOffer = try await h.lookupLink(thief, code: invitation.ticket.code)
            XCTAssertEqual(thiefOffer.status, .ok)
            _ = try await h.completeLink(first, invitation)
            let (second, _) = try await h.completeLink(thief, invitation, expect: .notFound)
            XCTAssertEqual(second.status, .notFound, "a consumed code no longer looks up")
            // Replaying the winner's own completion is a conflict too.
            let view = try await h.linkView(b, invitation.ticket.sessionId).json(LinkSessionView.self)
            let replay = try await h.signedPost(first, "/v1/link-sessions/\(invitation.ticket.sessionId.uuidString.lowercased())/complete",
                                                CompleteLinkSessionRequest(statement: try XCTUnwrap(view.statement), bindingTag: view.bindingTag))
            XCTAssertEqual(replay.status, .conflict, replay.text)
        }
    }

    func testConcurrentCompletionsConsumeTheSessionExactlyOnce() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            _ = try await h.publishDirectory(b)
            let invitation = try unwrap(try await h.createLinkSession(b, capabilities: [.messageSend]).1)
            var consumers: [TestConsumer] = []
            for i in 0..<4 { consumers.append(try await h.readyConsumer(name: "Racer \(i)")) }
            let statuses = try await withThrowingTaskGroup(of: HTTPStatus.self) { group in
                for consumer in consumers {
                    group.addTask { try await h.completeLink(consumer, invitation, expect: nil).0.status }
                }
                var out: [HTTPStatus] = []
                for try await status in group { out.append(status) }
                return out
            }
            XCTAssertEqual(statuses.filter { $0 == .created }.count, 1, "\(statuses)")
            aeq(try await RelationshipRecord.query(on: h.db).filter(\.$businessId == b.id.uuid).count(), 1)
        }
    }

    func testAnExpiredSessionIsGoneAndNeverLooksUp() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            _ = try await h.publishDirectory(b)
            let consumer = try await h.readyConsumer()
            let invitation = try unwrap(try await h.createLinkSession(b, capabilities: [.messageSend], expiresIn: 60).1)
            let looked = try await h.lookupLink(consumer, code: invitation.ticket.code)
            let offer = try looked.json(LinkSessionOffer.self)
            h.clock.advance(by: 61)
            aeq(try await h.lookupLink(consumer, code: invitation.ticket.code).status, .notFound)
            // A statement made before the expiry, sent after it.
            let key = SoftwareP256SigningKey()
            let statement = try await LinkStatement(sessionId: offer.sessionId, businessId: b.id, subject: offer.subjectRef, capabilities: offer.capabilities,
                                                    descriptorDigest: LinkSessionDescriptor.digest(of: offer.descriptor), publicKey: key.publicKey, approvalStatement: nil,
                                                    createdAt: h.clock.now()).sign(with: key)
            let late = try await h.signedPost(consumer, "/v1/link-sessions/\(offer.sessionId.uuidString.lowercased())/complete", CompleteLinkSessionRequest(statement: statement))
            XCTAssertEqual(late.status, .gone, late.text)
            aeq(try await h.linkView(b, offer.sessionId).json(LinkSessionView.self).status, .expired)
            // The lifetime is capped at five minutes.
            aeq(try await h.createLinkSession(b, expiresIn: 301).0.status, .unprocessableEntity)
        }
    }

    // MARK: Unconfirmed sessions end and are reported

    func testAnUnconfirmedSessionIsEndedAndReported() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            let keys = try await h.publishDirectory(b)
            let consumer = try await h.readyConsumer()
            let invitation = try unwrap(try await h.createLinkSession(b).1)
            let (_, phone) = try await h.completeLink(consumer, invitation)
            let kid = try ApprovalEnrollmentStatement.verify(try XCTUnwrap(try XCTUnwrap(phone).approvalStatement)).kid
            h.clock.advance(by: 300 + 301)
            try await h.runJobs()
            aeq(try await h.linkView(b, invitation.ticket.sessionId).json(LinkSessionView.self).status, .expired)
            aeq(try await RelationshipRecord.query(on: h.db).filter(\.$consumerId == consumer.id.uuid).count(), 0, "the pending connection created by the session is gone")
            let key = try await XCTUnwrapAsync(try await ApproveKeyRecord.query(on: h.db).filter(\.$kid == kid).first())
            XCTAssertEqual(key.statusValue, .revoked)
            atrue(try await h.approvalAudit("link.session_unconfirmed").count == 1)
            atrue(try await SecurityNoticeRecord.query(on: h.db).filter(\.$kind == SecurityNoticeTopic.businessLinkUnconfirmed.rawValue).count() == 1)
            aeq(try await h.confirmLink(b, keys: keys, invitation).status, .gone, "a late confirmation is refused")
        }
    }

    func testAnExistingDisconnectedConnectionIsRestoredIfTheBusinessNeverConfirms() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            _ = try await h.publishDirectory(b)
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b)
            aeq(try await h.signed(consumer, .DELETE, "/v1/relationships/\(rel.id)").status, .ok)
            let invitation = try unwrap(try await h.createLinkSession(b, capabilities: [.messageSend]).1)
            _ = try await h.completeLink(consumer, invitation)
            aeq(try await RelationshipRecord.find(rel.id.uuid, on: h.db)?.status, RelationshipRecord.pendingLink)
            h.clock.advance(by: 601)
            try await h.runJobs()
            aeq(try await RelationshipRecord.find(rel.id.uuid, on: h.db)?.status, "disconnected")
        }
    }

    // MARK: Tenant confusion (spec §12, v4 D3)

    func testAnotherBusinessCanNeitherReadNorConfirmNorCancelTheSession() async throws {
        try await withHarness { h in
            let a = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            let aKeys = try await h.publishDirectory(a)
            let other = try await h.makeBusiness(name: "Contoso Bank", handle: "contosobank")
            let otherKeys = try await h.publishDirectory(other)
            let consumer = try await h.readyConsumer()
            let invitation = try unwrap(try await h.createLinkSession(a).1)
            _ = try await h.completeLink(consumer, invitation)
            let id = invitation.ticket.sessionId.uuidString.lowercased()
            // Business B with its own key: the session does not exist for it.
            aeq(try await h.linkView(other, invitation.ticket.sessionId).status, .notFound)
            aeq(try await h.business(other, .POST, "/v1/business/link-sessions/\(id)/cancel").status, .notFound)
            // B confirms A's session with B's credentials and B's directory key: 404 (it is not B's session).
            let view = try await h.linkView(a, invitation.ticket.sessionId).json(LinkSessionView.self)
            let signed = try XCTUnwrap(view.statement)
            let foreign = try await LinkConfirmation(confirming: try LinkStatement.verify(signed), signed: signed, verification: .sasCompared, at: h.clock.now()).sign(with: otherKeys.confirmation)
            aeq(try await h.businessPost(other, "/v1/business/link-sessions/\(id)/confirm", ConfirmLinkSessionRequest(confirmation: foreign)).status, .notFound)
            // A's credentials with B's confirmation key (not published for A): refused.
            let wrongKey = try await h.confirmLink(a, keys: aKeys, invitation, signer: otherKeys.confirmation)
            XCTAssertEqual(wrongKey.status, .forbidden, wrongKey.text)
            atrue(try await h.approvalAudit("link.confirm_rejected").count >= 1)
            // A's own key confirms.
            aeq(try await h.confirmLink(a, keys: aKeys, invitation).status, .ok)
            // The device side: another account cannot read the session it did not complete.
            let stranger = try await h.readyConsumer(name: "Stranger")
            aeq(try await h.signed(stranger, .GET, "/v1/link-sessions/\(id)").status, .notFound)
        }
    }

    func testAnotherAccountCannotClaimASessionThatTheBusinessAlreadyConfirmed() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            let keys = try await h.publishDirectory(b)
            let customer = try await h.readyConsumer()
            let invitation = try unwrap(try await h.createLinkSession(b, capabilities: [.messageSend]).1)
            let (_, phone) = try await h.completeLink(customer, invitation)
            aeq(try await h.confirmLink(b, keys: keys, invitation).status, .ok)
            let attacker = try await h.readyConsumer(name: "Attacker")
            aeq(try await h.lookupLink(attacker, code: invitation.ticket.code).status, .notFound)
            let replay = try await h.signedPost(attacker, "/v1/link-sessions/\(invitation.ticket.sessionId.uuidString.lowercased())/complete",
                                                CompleteLinkSessionRequest(statement: try XCTUnwrap(phone).statement, bindingTag: try XCTUnwrap(phone).bindingTag))
            XCTAssertEqual(replay.status, .conflict, replay.text)
        }
    }

    // MARK: Session swapping and unauthorized linking

    func testAStatementMadeForAnotherAccountOrSessionIsRefused() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            _ = try await h.publishDirectory(b)
            let victim = try await h.readyConsumer()
            let attacker = try await h.readyConsumer(name: "Attacker")
            let invitation = try unwrap(try await h.createLinkSession(b, capabilities: [.messageSend]).1)
            // The attacker submits a statement naming the victim's pairwise reference (to link the victim's account to his session): refused.
            let victimRef = h.subjectRef(b, victim)
            _ = try await h.completeLink(attacker, invitation, tamper: { $0.subject = victimRef }, expect: .unprocessableEntity)
            // More capabilities than the business asked for, or another session's id: refused.
            _ = try await h.completeLink(attacker, invitation, tamper: { $0.capabilities = [.messageSend, .consentRequest] }, expect: .unprocessableEntity)
            _ = try await h.completeLink(attacker, invitation, tamper: { $0.sessionId = UUID() }, expect: .unprocessableEntity)
            _ = try await h.completeLink(attacker, invitation, tamper: { $0.descriptorDigest = String(repeating: "0", count: 64) }, expect: .unprocessableEntity)
            // Nothing was consumed: the victim can still complete it.
            _ = try await h.completeLink(victim, invitation)
        }
    }

    func testOnlyRegisteredLinkableEntitledCapabilitiesCanBeRequested() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            _ = try await h.publishDirectory(b)
            let notLinkable = try await h.createLinkSession(b, capabilities: [.identityName]).0
            XCTAssertEqual(notLinkable.status, .unprocessableEntity, notLinkable.text)
            let unknown = try await h.business(b, .POST, APIRoutes.businessLinkSessionCreate.template,
                                               body: Data(#"{"customer_ref":"c1","capabilities":["loop.run_anything"]}"#.utf8))
            XCTAssertEqual(unknown.status, .unprocessableEntity, unknown.text)
            aeq(try await h.createLinkSession(b, capabilities: [.messageSend, .messageSend]).0.status, .unprocessableEntity)
            aeq(try await h.createLinkSession(b, capabilities: [.messageSend], customerRef: "has space").0.status, .unprocessableEntity)
            aeq(try await h.createLinkSession(b, capabilities: [.messageSend], hint: "Card 4111111111111111").0.status, .unprocessableEntity, "a card number is not a hint")
            // A business not entitled to transaction.approve cannot ask a customer to grant it.
            let messagingOnly = try await h.makeBusiness(name: "Contoso Air", handle: "contosoair", capabilities: Capability.messaging)
            _ = try await h.publishDirectory(messagingOnly)
            let refused = try await h.createLinkSession(messagingOnly, capabilities: [.transactionApprove]).0
            XCTAssertEqual(refused.status, .forbidden, refused.text)
            // A key without the links:manage scope: refused.
            let scoped = try await h.makeBusiness(name: "Fabrikam", handle: "fabrikam", scopes: [BusinessAPIKeys.Scope.approvalsManage, BusinessAPIKeys.Scope.keyDirectoryManage])
            _ = try await h.publishDirectory(scoped)
            aeq(try await h.createLinkSession(scoped, capabilities: [.messageSend]).0.status, .forbidden)
        }
    }

    func testABusinessWithoutAKeyDirectoryCannotLink() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            let result = try await h.createLinkSession(b, capabilities: [.messageSend]).0
            XCTAssertEqual(result.status, .conflict, result.text)
        }
    }

    func testAD0DeviceMayLinkMessagingButNotBindAnApprovalKey() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            _ = try await h.publishDirectory(b)
            let trusted = try await h.readyConsumer()
            let second = try await h.enrollDevice(trusted)          // a new device of an account that has a D1 device: D0 until approved
            let approval = try unwrap(try await h.createLinkSession(b).1)
            let (refused, _) = try await h.completeLink(second, approval, expect: .forbidden)
            XCTAssertEqual(refused.errorCode, .deviceCoolDown)
            let messaging = try unwrap(try await h.createLinkSession(b, capabilities: [.messageSend]).1)
            _ = try await h.completeLink(second, messaging)
        }
    }

    func testLinkSessionsAreRateLimitedPerCustomerAndPerBusiness() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            _ = try await h.publishDirectory(b)
            var statuses: [HTTPStatus] = []
            for _ in 0..<5 { statuses.append(try await h.createLinkSession(b, capabilities: [.messageSend], customerRef: "cust_same").0.status) }
            XCTAssertEqual(statuses.prefix(3), [.created, .created, .created])
            XCTAssertTrue(statuses.contains(.tooManyRequests), "\(statuses)")
            aeq(try await h.createLinkSession(b, capabilities: [.messageSend], customerRef: "cust_other").0.status, .created, "another customer is unaffected")
            var business: [HTTPStatus] = []
            for i in 0..<40 { business.append(try await h.createLinkSession(b, capabilities: [.messageSend], customerRef: "cust_\(i)").0.status) }
            XCTAssertTrue(business.contains(.tooManyRequests), "the business budget ends too")
        }
    }

    func testLookupFailuresAreUniformAndRationed() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            var statuses: [HTTPStatus] = []
            for _ in 0..<8 { statuses.append(try await h.lookupLink(consumer, code: LinkSessionCode.generate()).status) }
            XCTAssertEqual(statuses.prefix(5), [.notFound, .notFound, .notFound, .notFound, .notFound])
            XCTAssertTrue(statuses.contains(.tooManyRequests), "\(statuses)")
        }
    }

    func testTheReleaseGateClosesEveryLinkRoute() async throws {
        try await withHarness({ $0.approve.enabled = false }) { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            let consumer = try await h.readyConsumer()
            aeq(try await h.createLinkSession(b, capabilities: [.messageSend]).0.status, .notFound)
            aeq(try await h.lookupLink(consumer, code: "ABCDEFGH").status, .notFound)
        }
    }

    // MARK: Webhooks: opaque

    func testTheCompletedEventIsOpaque() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            _ = try await h.publishDirectory(b)
            let subscribed = try await h.businessPost(b, "/v1/business/webhooks", CreateWebhookRequest(url: URL(string: "https://hooks.example.com/v")!,
                                                                                                         events: [.linkCompleted, .linkExpired], envelopeVersion: WebhookEnvelopeV2.version))
            XCTAssertEqual(subscribed.status, .created, subscribed.text)
            let consumer = try await h.readyConsumer()
            let invitation = try unwrap(try await h.createLinkSession(b, capabilities: [.messageSend]).1)
            _ = try await h.completeLink(consumer, invitation)
            try await h.runJobs()
            let delivery = try XCTUnwrap(h.webhooks.received.last)
            let envelope = try ViadereJSON.decode(WebhookEnvelopeV2.self, from: delivery.body)
            XCTAssertEqual(envelope.type, "link.completed")
            XCTAssertEqual(envelope.requestId, invitation.ticket.sessionId.uuidString.lowercased())
            XCTAssertFalse(String(decoding: delivery.body, as: UTF8.self).contains("sub_"), "no subject reference in the event")
        }
    }

    // MARK: App Attest on the completion (WP-C2)

    func testAnAttestedDeviceMustAssertItsCompletionInRequireMode() async throws {
        try await withAttestHarness(mode: .off, { $0.approve.assertionMode = .require }) { h, _ in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            _ = try await h.publishDirectory(b)
            let consumer = try await h.readyConsumer()
            let attestKey = P256.Signing.PrivateKey()
            try await AppAttestKeyRecord(deviceId: try XCTUnwrap(consumer.device).id.uuid, consumerId: consumer.id.uuid,
                                         keyId: Hex.encode(SHA256.hash(data: attestKey.publicKey.x963Representation)),
                                         publicKey: Base64URL.encode(attestKey.publicKey.x963Representation), counter: 0, environment: "production", now: h.clock.now()).create(on: h.db)
            let invitation = try unwrap(try await h.createLinkSession(b, capabilities: [.messageSend]).1)
            let (missing, phone) = try await h.completeLink(consumer, invitation, expect: .unauthorized)
            XCTAssertEqual(missing.status, .unauthorized)
            let statement = try XCTUnwrap(phone).statement
            let assertion = try TestAppAttestPKI.assertion(key: attestKey, clientData: LinkAppAttest.clientData(sessionId: invitation.ticket.sessionId, statement: statement), counter: 1)
            let ok = try await h.signedPost(consumer, "/v1/link-sessions/\(invitation.ticket.sessionId.uuidString.lowercased())/complete",
                                            CompleteLinkSessionRequest(statement: statement, bindingTag: try XCTUnwrap(phone).bindingTag, appAttestAssertion: Base64URL.encode(assertion)))
            XCTAssertEqual(ok.status, .created, ok.text)
        }
    }

    // MARK: The descriptor key is configured, separate and printable

    func testTheLinkDescriptorKeyIsRequiredWithADatabaseAndMustDifferFromTheLogKey() throws {
        let log = Base64URL.encode(SoftwareP256SigningKey().rawRepresentation)
        let base = ["ENVIRONMENT": "development", "DATABASE_URL": "postgres://u:p@localhost/x", "CONNECT_LINK_SIGNING_KEY": Base64URL.encode(Data(repeating: 1, count: 32)),
                    "SERVER_PEPPER": Base64URL.encode(Data(repeating: 2, count: 32)), "DATA_ENCRYPTION_KEY": Base64URL.encode(Data(repeating: 3, count: 32)),
                    "AUDIT_CHAIN_KEY": Base64URL.encode(Data(repeating: 4, count: 32)), "SUBJECT_REF_KEY": Base64URL.encode(Data(repeating: 5, count: 32)),
                    "KEY_DIRECTORY_LOG_KEY": log]
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(base), "missing")
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(base.merging(["LINK_DESCRIPTOR_SIGNING_KEY": log]) { $1 }), "the log key reused")
        XCTAssertNoThrow(try ServerConfig.fromEnvironment(base.merging(["LINK_DESCRIPTOR_SIGNING_KEY": Base64URL.encode(SoftwareP256SigningKey().rawRepresentation)]) { $1 }))
    }

    func testAKMSThatReturnsAWrongSignatureIsNeverUsed() async throws {
        struct LyingKMS: KeyManagementService {
            let key = SoftwareP256SigningKey()
            func sign(keyRef: KMSKeyRef, digest: Data) async throws -> Data { Data(repeating: 7, count: 64) }
            func publicKey(keyRef: KMSKeyRef) async throws -> DevicePublicKey { key.publicKey }
        }
        let signer = KMSStatementSigner(kms: LyingKMS(), keyRef: .linkDescriptor)
        do { _ = try await signer.sign(payload: Data("{}".utf8), domain: LinkDomainSeparator.descriptor); XCTFail("must refuse") } catch {
            XCTAssertEqual(error as? KMSError, .invalidSignature)
        }
        // The local KMS signs digests that verify against the published key.
        let key = SoftwareP256SigningKey()
        let local = KMSStatementSigner(kms: LocalKMS(keys: [.linkDescriptor: key]), keyRef: .linkDescriptor)
        let signed = try await local.sign(payload: Data("{\"a\":1}".utf8), domain: LinkDomainSeparator.result)
        XCTAssertTrue(SignedStatement(payload: signed.payload, signature: signed.signature).isValid(domain: LinkDomainSeparator.result, publicKey: key.publicKey))
        XCTAssertEqual(signed.kid, KeyIdentifier.make(try key.publicKey.signingKey()))
    }
}
