@preconcurrency import Crypto
import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// WP1 enrollment (APP-001, APP-002, ADR-06): business-authorized, pairwise, confirmed by the business, device-loss resistant
/// (acceptance 7), and unlinkable across businesses.
final class ApproveEnrollmentTests: XCTestCase {
    func codeOf(_ ticket: ApprovalEnrollmentTicket) -> String { ApprovalEnrollmentCode.display(ticket.code) }

    // MARK: Happy path

    func testBusinessAuthorizedEnrollmentActivatesAKeyOnlyAfterTheBusinessConfirms() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            let keys = try await h.publishDirectory(b)
            let consumer = try await h.readyConsumer()
            let rel = try await h.connect(consumer, to: b)
            let subject = h.subjectRef(b, consumer)

            let created = try await h.businessPost(b, "/v1/business/approve/enrollments", CreateApprovalEnrollmentRequest(subjectRef: subject, capability: .transactionApprove))
            XCTAssertEqual(created.status, .created, created.text)
            let ticket = try created.json(ApprovalEnrollmentTicket.self)
            XCTAssertEqual(ticket.code.count, 8)
            XCTAssertTrue(ticket.deepLink.hasPrefix("https://viadere.com/a/\(ticket.code)?rk=\(keys.rootKid)"), "the link carries the business root key id out of band")
            let parsed = try XCTUnwrap(ApprovalEnrollmentCode.parse(link: URL(string: ticket.deepLink)!))
            XCTAssertEqual(parsed.code, ticket.code)
            XCTAssertEqual(parsed.rootKid, keys.rootKid)
            // The plaintext code is stored nowhere.
            let stored = try await ApproveEnrollmentRecord.find(ticket.enrollmentId, on: h.db)
            XCTAssertNotEqual(stored?.codeHash, ticket.code)
            XCTAssertFalse(stored?.codeHash.contains(ticket.code) ?? true)

            // The customer looks it up: sees the verified business and the assurance the key needs.
            let lookup = try await h.signedPost(consumer, "/v1/approve/enrollments/lookup", ApproveEnrollmentLookupRequest(code: codeOf(ticket).lowercased()))
            XCTAssertEqual(lookup.status, .ok, lookup.text)
            let preview = try lookup.json(ApproveEnrollmentPreview.self)
            XCTAssertEqual(preview.business.id, b.id)
            XCTAssertEqual(preview.business.verificationStatus, .verified)
            XCTAssertEqual(preview.requiredAssurance, .biometric)
            XCTAssertEqual(preview.subjectRef, subject)
            XCTAssertEqual(preview.relationshipId, rel.id)

            // The phone creates a pairwise key and signs the statement; until the business confirms, the key cannot approve anything.
            let key = SoftwareP256SigningKey()
            let hpke = SoftwareE2EEPrivateKey()
            let statement = try ApprovalEnrollmentStatement(businessId: b.id, subject: subject, enrollmentId: ticket.enrollmentId, publicKey: key.publicKey,
                                                            hpkePublicKey: hpke.publicKey, assurance: .biometric, createdAt: h.clock.now())
            let signed = try await statement.sign(with: key)
            let completed = try await h.signedPost(consumer, "/v1/approve/enrollments/\(ticket.enrollmentId.uuidString.lowercased())/complete", CompleteApproveEnrollmentRequest(statement: signed))
            XCTAssertEqual(completed.status, .created, completed.text)
            XCTAssertEqual(try completed.json(ApproveKey.self).status, .pending)
            let phone = TestApprovalDevice(consumer: consumer, approvalKey: key, hpke: hpke, assurance: .biometric)
            let earlyRequest = try await h.createRequest(ApproveFixture(business: b, keys: keys, relationship: rel, subject: subject, phone: phone))
            XCTAssertEqual(earlyRequest.0.status, .conflict, "a pending key can't be asked to approve")
            XCTAssertEqual(try earlyRequest.0.json(APIErrorResponse.self).error.details?["reason"], "no_active_key")

            // The business sees the device's statement, verifies it itself, and confirms with its directory-published key.
            let view = try await h.business(b, .GET, "/v1/business/approve/enrollments/\(ticket.enrollmentId.uuidString.lowercased())").json(ApprovalEnrollmentView.self)
            XCTAssertEqual(view.status, .deviceCompleted)
            let verified = try ApprovalEnrollmentStatement.verify(try XCTUnwrap(view.deviceStatement))
            XCTAssertEqual(verified.publicKey, key.publicKey)
            XCTAssertEqual(verified.hpkePublicKey, hpke.publicKey)
            let confirmation = try await ApprovalEnrollmentConfirmation(confirming: verified, signed: try XCTUnwrap(view.deviceStatement), at: h.clock.now()).sign(with: keys.confirmation)
            let confirmed = try await h.businessPost(b, "/v1/business/approve/enrollments/\(ticket.enrollmentId.uuidString.lowercased())/confirm", ConfirmApprovalEnrollmentRequest(confirmation: confirmation))
            XCTAssertEqual(confirmed.status, .ok, confirmed.text)
            XCTAssertEqual(try confirmed.json(ApprovalKeyView.self).status, .active)

            // The customer's app sees the confirmation and verifies it against the directory (the business's published key).
            let deviceKeys = try await h.signed(consumer, .GET, "/v1/approve/keys").json([ApproveKey].self)
            XCTAssertEqual(deviceKeys.count, 1)
            let deviceKey = deviceKeys[0]
            XCTAssertEqual(deviceKey.status, .active)
            let wire = try XCTUnwrap(deviceKey.confirmation)
            let parsedConfirmation = try ApprovalEnrollmentConfirmation.verify(wire, confirmationKey: keys.confirmation.publicKey)
            XCTAssertNoThrow(try parsedConfirmation.checkMatches(statement, signed: signed))
            // A notice tells the account's devices a key was enrolled; the audit trail has the whole story.
            for action in ["approve.enrollment_created", "approve.enrollment_device_completed", "approve.key_activated"] {
                let events = try await h.approvalAudit(action)
                XCTAssertEqual(events.count, 1, action)
            }
            atrue(try await SecurityNoticeRecord.query(on: h.db).filter(\.$kind == SecurityNoticeTopic.approvalKeyEnrolled.rawValue).count() > 0)
            // The enrollment code is single use.
            let again = try await h.signedPost(consumer, "/v1/approve/enrollments/lookup", ApproveEnrollmentLookupRequest(code: codeOf(ticket)))
            XCTAssertEqual(again.status, .notFound)
        }
    }

    // MARK: APP-001: only an existing relationship, never a phone number; capability and policy

    func testEnrollmentIsAddressedBySubjectRefOnlyAndNeedsTheCapability() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            _ = try await h.publishDirectory(b)
            let consumer = try await h.readyConsumer()
            _ = try await h.connect(consumer, to: b)
            // A raw phone number (or anything that is not a subject_ref) is not an address.
            let raw = try await h.business(b, .POST, "/v1/business/approve/enrollments", body: Data(#"{"subject_ref":"+15555550100","capability":"transaction.approve"}"#.utf8))
            XCTAssertEqual(raw.status, .badRequest)
            // A subject_ref of nobody (or of another business's customer) is a plain 404.
            let other = try await h.makeBusiness(name: "Other Bank", handle: "otherbank")
            let foreign = h.subjectRef(other, consumer)
            let unknown = try await h.businessPost(b, "/v1/business/approve/enrollments", CreateApprovalEnrollmentRequest(subjectRef: foreign, capability: .transactionApprove))
            XCTAssertEqual(unknown.status, .notFound)
            // A messaging-only key cannot start an enrollment (acceptance 1), and neither can a business without the entitlement.
            let messaging = try await BusinessAPIKeys.issue(businessId: b.record.id!, name: "m", live: true, scopes: BusinessAPIKeys.Scope.all, capabilities: Capability.messaging, now: h.clock.now(), on: h.db).key
            let denied = try await h.businessPost(b, "/v1/business/approve/enrollments", CreateApprovalEnrollmentRequest(subjectRef: h.subjectRef(b, consumer), capability: .authChallenge), key: messaging)
            XCTAssertEqual(denied.status, .forbidden)
            XCTAssertEqual(denied.errorCode, .insufficientScope)
            let plain = try await h.makeBusiness(name: "Plain Co", handle: "plainco", capabilities: Capability.messaging)
            _ = try await h.connect(consumer, to: plain)
            let notEntitled = try await h.businessPost(plain, "/v1/business/approve/enrollments", CreateApprovalEnrollmentRequest(subjectRef: h.subjectRef(plain, consumer), capability: .transactionApprove))
            XCTAssertEqual(notEntitled.status, .forbidden)
            // Any other capability is not an enrollment capability.
            let wrong = try await h.businessPost(b, "/v1/business/approve/enrollments", CreateApprovalEnrollmentRequest(subjectRef: h.subjectRef(b, consumer), capability: .messageSend))
            XCTAssertEqual(wrong.status, .unprocessableEntity)
            // Without the operational scope the route is closed whatever the capabilities.
            let noScope = try await BusinessAPIKeys.issue(businessId: b.record.id!, name: "n", live: true, scopes: [BusinessAPIKeys.Scope.interactionsWrite], now: h.clock.now(), on: h.db).key
            let closed = try await h.businessPost(b, "/v1/business/approve/enrollments", CreateApprovalEnrollmentRequest(subjectRef: h.subjectRef(b, consumer), capability: .authChallenge), key: noScope)
            XCTAssertEqual(closed.status, .forbidden)
        }
    }

    func testEnrollmentNeedsARegisteredRootAndConfirmationKey() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            let consumer = try await h.readyConsumer()
            _ = try await h.connect(consumer, to: b)
            let body = CreateApprovalEnrollmentRequest(subjectRef: h.subjectRef(b, consumer), capability: .transactionApprove)
            let none = try await h.businessPost(b, "/v1/business/approve/enrollments", body)
            XCTAssertEqual(none.status, .conflict)
            XCTAssertEqual(try none.json(APIErrorResponse.self).error.details?["reason"], "key_directory_required")
            // A root alone is not enough: the confirmation key must be published.
            let keys = TestBusinessKeys()
            let root = try await KeyLogEntry.sign(.root(RootRegistration(businessId: b.id, publicKey: keys.root.publicKey, createdAt: h.clock.now())), rootKey: keys.root)
            aeq(try await h.publishEntry(b, root).status, .created)
            let rootOnly = try await h.businessPost(b, "/v1/business/approve/enrollments", body)
            XCTAssertEqual(rootOnly.status, .conflict)
            try await h.publishKey(b, keys, .approvalEnrollmentConfirmation, keys.confirmation.publicKey.x963)
            let ok = try await h.businessPost(b, "/v1/business/approve/enrollments", body)
            XCTAssertEqual(ok.status, .created, ok.text)
        }
    }

    // MARK: The code

    func testOnlyTheRelationshipsCustomerCanRedeemTheCodeAndWrongGuessesAreRationed() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            _ = try await h.publishDirectory(b)
            let alice = try await h.readyConsumer(name: "Alice")
            let mallory = try await h.readyConsumer(name: "Mallory")
            _ = try await h.connect(alice, to: b)
            _ = try await h.connect(mallory, to: b)
            let ticket = try await h.businessPost(b, "/v1/business/approve/enrollments", CreateApprovalEnrollmentRequest(subjectRef: h.subjectRef(b, alice), capability: .transactionApprove)).json(ApprovalEnrollmentTicket.self)
            // Someone who saw the code (a shoulder surfer, another customer of the same business) cannot use it.
            let stolen = try await h.signedPost(mallory, "/v1/approve/enrollments/lookup", ApproveEnrollmentLookupRequest(code: ticket.code))
            XCTAssertEqual(stolen.status, .notFound)
            // Wrong guesses are rationed per customer.
            var statuses: [HTTPStatus] = []
            for _ in 0..<8 {
                statuses.append(try await h.signedPost(mallory, "/v1/approve/enrollments/lookup", ApproveEnrollmentLookupRequest(code: ApprovalEnrollmentCode.generate())).status)
            }
            XCTAssertTrue(statuses.contains(.tooManyRequests), "\(statuses)")
            // Malformed codes are the same 404, not a distinguishable error.
            let bad = try await h.signedPost(alice, "/v1/approve/enrollments/lookup", ApproveEnrollmentLookupRequest(code: "not a code"))
            XCTAssertEqual(bad.status, .notFound)
            // The rightful customer still can.
            let ok = try await h.signedPost(alice, "/v1/approve/enrollments/lookup", ApproveEnrollmentLookupRequest(code: ticket.code))
            XCTAssertEqual(ok.status, .ok, ok.text)
            // After expiry the code is dead.
            h.clock.advance(by: 650)
            let late = try await h.signedPost(alice, "/v1/approve/enrollments/lookup", ApproveEnrollmentLookupRequest(code: ticket.code))
            XCTAssertEqual(late.status, .notFound)
        }
    }

    // MARK: Statement binding

    func testTheStatementMustBindTheEnrollmentProveThePossessionAndMeetTheAssurance() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            _ = try await h.publishDirectory(b)
            let consumer = try await h.readyConsumer()
            _ = try await h.connect(consumer, to: b)
            let subject = h.subjectRef(b, consumer)

            func start(capability: Capability = .transactionApprove) async throws -> ApproveEnrollmentPreview {
                let ticket = try await h.businessPost(b, "/v1/business/approve/enrollments", CreateApprovalEnrollmentRequest(subjectRef: subject, capability: capability)).json(ApprovalEnrollmentTicket.self)
                return try await h.signedPost(consumer, "/v1/approve/enrollments/lookup", ApproveEnrollmentLookupRequest(code: ticket.code)).json(ApproveEnrollmentPreview.self)
            }
            func complete(_ preview: ApproveEnrollmentPreview, _ statement: SignedStatement) async throws -> HTTPResult {
                try await h.signedPost(consumer, "/v1/approve/enrollments/\(preview.enrollmentId.uuidString.lowercased())/complete", CompleteApproveEnrollmentRequest(statement: statement))
            }
            let key = SoftwareP256SigningKey()
            let hpke = SoftwareE2EEPrivateKey()
            func statement(_ preview: ApproveEnrollmentPreview, business: BusinessID? = nil, subject s: SubjectRef? = nil, enrollment: UUID? = nil, assurance: ApprovalAMR = .biometric,
                           key k: SoftwareP256SigningKey? = nil, at: Date? = nil) throws -> ApprovalEnrollmentStatement {
                try ApprovalEnrollmentStatement(businessId: business ?? b.id, subject: s ?? subject, enrollmentId: enrollment ?? preview.enrollmentId, publicKey: (k ?? key).publicKey,
                                                hpkePublicKey: hpke.publicKey, assurance: assurance, createdAt: at ?? h.clock.now())
            }

            // Another business, another customer reference, another enrollment: each refused (a statement can't be replayed elsewhere).
            let p1 = try await start()
            for bad in [try statement(p1, business: BusinessID()), try statement(p1, subject: SubjectRef("sub_" + Base64URL.encode(Data(repeating: 5, count: 32)))!), try statement(p1, enrollment: UUID())] {
                let r = try await complete(p1, try await bad.sign(with: key))
                XCTAssertEqual(r.status, .unprocessableEntity, r.text)
            }
            // No proof of possession: the statement names the attacker's key but the signature is not from it.
            let attacker = SoftwareP256SigningKey()
            let forged = SignedStatement(payload: try await statement(p1, key: attacker).sign(with: attacker).payload, signature: try await statement(p1).sign(with: key).signature)
            aeq(try await complete(p1, forged).status, .unprocessableEntity)
            // A key protected only by presence cannot be enrolled for a critical capability.
            let weak = try await complete(p1, try await statement(p1, assurance: .presence).sign(with: key))
            XCTAssertEqual(weak.status, .forbidden)
            XCTAssertEqual(weak.errorCode, .insufficientAssurance)
            // A stale statement.
            let stale = try await complete(p1, try await statement(p1, at: h.clock.now().addingTimeInterval(-3600)).sign(with: key))
            XCTAssertEqual(stale.status, .unprocessableEntity)
            // The good one still works (the failed attempts consumed nothing).
            aeq(try await complete(p1, try await statement(p1).sign(with: key)).status, .created)
            // Pairwise: the same key cannot be enrolled twice, not for the same relationship and not anywhere else.
            let p2 = try await start()
            let reuse = try await complete(p2, try await statement(p2).sign(with: key))
            XCTAssertEqual(reuse.status, .conflict, reuse.text)
            // Completing again is refused (single use).
            let again = SoftwareP256SigningKey()
            aeq(try await complete(p1, try await statement(p1, key: again).sign(with: again)).status, .conflict)
        }
    }

    // MARK: The business's confirmation

    func testConfirmationMustComeFromAPublishedKeyAndCoverTheExactStatement() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            let keys = try await h.publishDirectory(b)
            let consumer = try await h.readyConsumer()
            _ = try await h.connect(consumer, to: b)
            let phone = try await h.enrollApproval(consumer, business: b, keys: keys, confirm: false)
            let subject = h.subjectRef(b, consumer)
            let enrollmentId = try unwrap(try await ApproveEnrollmentRecord.query(on: h.db).first()?.id)
            let path = "/v1/business/approve/enrollments/\(enrollmentId.uuidString.lowercased())/confirm"
            let view = try await h.business(b, .GET, "/v1/business/approve/enrollments/\(enrollmentId.uuidString.lowercased())").json(ApprovalEnrollmentView.self)
            let signed = try XCTUnwrap(view.deviceStatement)
            let statement = try ApprovalEnrollmentStatement.verify(signed)

            // A key the business never published (a relay confirming on its behalf) is refused.
            let relayKey = SoftwareP256SigningKey()
            let relayConfirmation = try await ApprovalEnrollmentConfirmation(confirming: statement, signed: signed, at: h.clock.now()).sign(with: relayKey)
            let r1 = try await h.businessPost(b, path, ConfirmApprovalEnrollmentRequest(confirmation: relayConfirmation))
            XCTAssertEqual(r1.status, .forbidden, r1.text)
            // The request-signing key is a different purpose: it can't confirm.
            let wrongPurpose = try await ApprovalEnrollmentConfirmation(confirming: statement, signed: signed, at: h.clock.now()).sign(with: keys.requestSigning)
            aeq(try await h.businessPost(b, path, ConfirmApprovalEnrollmentRequest(confirmation: wrongPurpose)).status, .forbidden)
            // A confirmation of a different key (or statement) is refused.
            let otherKey = SoftwareP256SigningKey()
            let otherStatement = try ApprovalEnrollmentStatement(businessId: b.id, subject: subject, enrollmentId: enrollmentId, publicKey: otherKey.publicKey,
                                                                 hpkePublicKey: SoftwareE2EEPrivateKey().publicKey, assurance: .biometric, createdAt: h.clock.now())
            let otherSigned = try await otherStatement.sign(with: otherKey)
            let mismatched = try await ApprovalEnrollmentConfirmation(confirming: otherStatement, signed: otherSigned, at: h.clock.now()).sign(with: keys.confirmation)
            aeq(try await h.businessPost(b, path, ConfirmApprovalEnrollmentRequest(confirmation: mismatched)).status, .unprocessableEntity)
            // Another business cannot confirm it (a plain 404).
            let other = try await h.makeBusiness(name: "Other Bank", handle: "otherbank2")
            let otherKeys = try await h.publishDirectory(other)
            let foreign = try await ApprovalEnrollmentConfirmation(confirming: statement, signed: signed, at: h.clock.now()).sign(with: otherKeys.confirmation)
            aeq(try await h.businessPost(other, path, ConfirmApprovalEnrollmentRequest(confirmation: foreign)).status, .notFound)
            // Nothing above activated the key.
            aeq(try await ApproveKeyRecord.query(on: h.db).filter(\.$status == "active").count(), 0)
            // The real one does, once.
            let good = try await ApprovalEnrollmentConfirmation(confirming: statement, signed: signed, at: h.clock.now()).sign(with: keys.confirmation)
            aeq(try await h.businessPost(b, path, ConfirmApprovalEnrollmentRequest(confirmation: good)).status, .ok)
            aeq(try await h.businessPost(b, path, ConfirmApprovalEnrollmentRequest(confirmation: good)).status, .conflict)
            _ = phone
        }
    }

    func testARelaySubstitutingTheDevicesKeyIsCaughtByTheDevice() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            let keys = try await h.publishDirectory(b)
            let consumer = try await h.readyConsumer()
            _ = try await h.connect(consumer, to: b)
            let subject = h.subjectRef(b, consumer)
            let deviceKey = SoftwareP256SigningKey()
            let phone = try await h.enrollApproval(consumer, business: b, keys: keys, confirm: false, approvalKey: deviceKey)
            let record = try unwrap(try await ApproveEnrollmentRecord.query(on: h.db).first())
            let genuineSigned = try XCTUnwrap(record.deviceStatement)
            let genuine = try ApprovalEnrollmentStatement.verify(genuineSigned)

            // Compromised relay: it swaps in a statement for ITS OWN key (it can make one: nothing stops it creating a key of its own).
            let attackerKey = SoftwareP256SigningKey()
            let attackerStatement = try ApprovalEnrollmentStatement(businessId: b.id, subject: subject, enrollmentId: record.id!, publicKey: attackerKey.publicKey,
                                                                    hpkePublicKey: SoftwareE2EEPrivateKey().publicKey, assurance: .biometric, createdAt: h.clock.now())
            let attackerSigned = try await attackerStatement.sign(with: attackerKey)
            let key = try unwrap(try await ApproveKeyRecord.query(on: h.db).first())
            try await ApproveEnrollmentRecord.query(on: h.db).set(\.$statementPayload, to: attackerSigned.payload).set(\.$statementSignature, to: attackerSigned.signature).set(\.$kid, to: attackerStatement.kid).update()
            try await ApproveKeyRecord.query(on: h.db).filter(\.$id == key.id!).set(\.$kid, to: attackerStatement.kid).set(\.$publicKey, to: attackerKey.publicKey.base64URL)
                .set(\.$statementPayload, to: attackerSigned.payload).set(\.$statementSignature, to: attackerSigned.signature).update()

            // The relay holds the attacker's key and cannot tell the business apart from the customer. WHAT STOPS THIS IS NOT ON THE SERVER: the
            // business SDK refuses any statement that lacks a binding tag (or SAS) made with the enrollment secret the relay never sees
            // (`ApproveSDKTests.aRelayForgedStatementIsRefusedByTheBusinessSdk`). The server, which cannot know the secret, still confirms what it is told.
            let view = try await h.business(b, .GET, "/v1/business/approve/enrollments/\(record.id!.uuidString.lowercased())").json(ApprovalEnrollmentView.self)
            let handed = try XCTUnwrap(view.deviceStatement)
            let verified = try ApprovalEnrollmentStatement.verify(handed)
            let confirmation = try await ApprovalEnrollmentConfirmation(confirming: verified, signed: handed, at: h.clock.now()).sign(with: keys.confirmation)
            let confirmed = try await h.businessPost(b, "/v1/business/approve/enrollments/\(record.id!.uuidString.lowercased())/confirm", ConfirmApprovalEnrollmentRequest(confirmation: confirmation))
            XCTAssertEqual(confirmed.status, .ok, confirmed.text)

            // But the confirmation names the attacker's key and statement. The device, which still has its own statement, rejects it.
            let wire = try unwrap(try await ApproveKeyRecord.query(on: h.db).first()?.confirmation)
            let signedConfirmation = try ViadereJSON.decode(BusinessSignedStatement.self, from: Data(wire.utf8))
            let parsed = try ApprovalEnrollmentConfirmation.verify(signedConfirmation, confirmationKey: keys.confirmation.publicKey)
            XCTAssertThrowsError(try parsed.checkMatches(genuine, signed: genuineSigned)) { XCTAssertEqual($0 as? ApprovalEnrollmentError, .keyMismatch) }
            _ = phone
        }
    }

    // MARK: Acceptance 7: device loss and recovery cannot silently replace an enrolled key

    func testALostOrReplacedDeviceNeverCarriesApprovalKeysAndANewOneNeedsANewBusinessAuthorizedEnrollment() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            var consumer = f.phone.consumer
            // A thief signs in with the stolen passkey and enrolls a NEW device. It starts in its cool-down and holds no approval key.
            let thief = try await h.enrollDevice(consumer)
            aeq(try await h.signed(thief, .GET, "/v1/approve/keys").json([ApproveKey].self).count, 1, "the account's keys are visible, but they belong to the old device")
            let pendingForThief = try await h.pendingRequests(thief)
            XCTAssertTrue(pendingForThief.isEmpty)
            // A request is created for the legitimate phone; the thief's device can neither see nor decide it.
            let (created, body) = try await h.createRequest(f)
            XCTAssertEqual(created.status, .created, created.text)
            atrue(try await h.pendingRequests(thief).isEmpty)
            let delivery = try unwrap(try await ApproveDeliveryRecord.query(on: h.db).first())
            let theirs = TestApprovalDevice(consumer: thief, approvalKey: SoftwareP256SigningKey(), hpke: SoftwareE2EEPrivateKey(), assurance: .biometric)
            let stolenAnswer = try await h.answer(f.phone, try await h.pendingRequests(consumer)[0])
            aeq(try await h.submit(theirs, deliveryId: delivery.id!, result: stolenAnswer).status, .notFound, "a delivery is bound to the device that holds the key")
            // Even a JWS signed with the real approval key (somehow exfiltrated) is refused from the wrong device.
            // The thief cannot enroll a key without a business-authorized code: it cannot look one up (the code is shown in the business session).
            let guess = try await h.signedPost(thief, "/v1/approve/enrollments/lookup", ApproveEnrollmentLookupRequest(code: ApprovalEnrollmentCode.generate()))
            XCTAssertEqual(guess.status, .notFound)
            // Even with a code (the thief got into the business account too) the new device is untrusted until its cool-down ends.
            let ticket = try await h.businessPost(f.business, "/v1/business/approve/enrollments", CreateApprovalEnrollmentRequest(subjectRef: f.subject, capability: .transactionApprove)).json(ApprovalEnrollmentTicket.self)
            let preview = try await h.signedPost(thief, "/v1/approve/enrollments/lookup", ApproveEnrollmentLookupRequest(code: ticket.code)).json(ApproveEnrollmentPreview.self)
            let statement = try ApprovalEnrollmentStatement(businessId: f.business.id, subject: f.subject, enrollmentId: preview.enrollmentId, publicKey: theirs.approvalKey.publicKey,
                                                            hpkePublicKey: theirs.hpke.publicKey, assurance: .biometric, createdAt: h.clock.now())
            let enroll = try await h.signedPost(thief, "/v1/approve/enrollments/\(preview.enrollmentId.uuidString.lowercased())/complete", CompleteApproveEnrollmentRequest(statement: try await statement.sign(with: theirs.approvalKey)))
            XCTAssertEqual(enroll.status, .forbidden, enroll.text)
            XCTAssertEqual(enroll.errorCode, .deviceCoolDown)
            aeq(try await ApproveKeyRecord.query(on: h.db).count(), 1, "no second key exists")

            // The owner revokes the lost phone. Its keys stop working at once, and the account has no way to approve until the business enrolls a new key.
            let revoke = try await h.signed(thief, .DELETE, "/v1/devices/\(f.phone.consumer.device!.id)")
            XCTAssertTrue([.ok, .forbidden].contains(revoke.status), revoke.text)
            try await DeviceRecord.query(on: h.db).filter(\.$id == f.phone.consumer.device!.id.uuid).set(\.$revokedAt, to: h.clock.now()).update()
            let afterLoss = try await h.createRequest(f, requestId: TestHarness.makeRequestId())
            XCTAssertEqual(afterLoss.0.status, .conflict, "no active key on a live device: a new enrollment is required")
            XCTAssertEqual(try afterLoss.0.json(APIErrorResponse.self).error.details?["reason"], "no_active_key")
            consumer = thief
            _ = consumer
        }
    }

    func testRecoveryAndSetUpAgainNeverCopyApprovalKeys() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            // The old device is revoked ("Set up again" after a biometric change, or recovery): a new device enrolls.
            try await DeviceRecord.query(on: h.db).filter(\.$id == f.phone.consumer.device!.id.uuid).set(\.$revokedAt, to: h.clock.now()).update()
            let fresh = try await h.enrollDevice(try await h.login(f.phone.consumer))
            // The account's approval key is still on record, but the relay refuses to use it: its device is gone.
            let keys = try await h.signed(fresh, .GET, "/v1/approve/keys").json([ApproveKey].self)
            XCTAssertEqual(keys.count, 1)
            let request = try await h.createRequest(f)
            XCTAssertEqual(request.0.status, .conflict)
            // A new business-authorized enrollment on the new device is the only way back, and it gets a new pairwise key.
            await Task.yield()
            try await DeviceRecord.query(on: h.db).filter(\.$id == fresh.device!.id.uuid).set(\.$approvalsLockedUntil, to: nil).update()
            let phone = try await h.enrollApproval(fresh, business: f.business, keys: f.keys)
            XCTAssertNotEqual(phone.kid, f.phone.kid)
            var fixture = f
            fixture.phone = phone
            let again = try await h.createRequest(fixture)
            XCTAssertEqual(again.0.status, .created, again.0.text)
        }
    }

    // MARK: Revocation

    func testEachKeyIsRevokedOnItsOwnByTheCustomerOrTheBusiness() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            // A second device with its own key for the same relationship.
            let second = try await h.enrollDevice(f.phone.consumer)
            // The owner's trusted phone approves it (time alone never would).
            try await eq(try await h.confirm(second, from: f.phone.consumer).status, .ok)
            let secondPhone = try await h.enrollApproval(second, business: f.business, keys: f.keys)
            XCTAssertNotEqual(secondPhone.kid, f.phone.kid)
            let (created, _) = try await h.createRequest(f)
            XCTAssertEqual(try created.json(ApprovalRequestView.self).deliveredTo, 2)
            // The customer revokes the first device's key: only it stops working.
            let revoked = try await h.signedPost(f.phone.consumer, "/v1/approve/keys/\(f.phone.kid)/revoke", EmptyBody())
            XCTAssertEqual(revoked.status, .ok, revoked.text)
            XCTAssertEqual(try revoked.json(ApproveKey.self).status, .revoked)
            atrue(try await h.pendingRequests(f.phone.consumer).isEmpty)
            aeq(try await h.pendingRequests(second).count, 1)
            // The business revokes the second: the request has nobody left and is cancelled.
            let biz = try await h.businessPost(f.business, "/v1/business/approve/keys/\(secondPhone.kid)/revoke", RevokeApprovalKeyRequest(reason: "lost"))
            XCTAssertEqual(biz.status, .ok, biz.text)
            XCTAssertEqual(try biz.json(ApprovalKeyView.self).revokedBy, "business")
            atrue(try await h.pendingRequests(second).isEmpty)
            let record = try unwrap(try await ApproveRequestRecord.query(on: h.db).first())
            XCTAssertEqual(record.status, "cancelled")
            // Revocation is idempotent, owned (another business gets a 404) and audited.
            aeq(try await h.businessPost(f.business, "/v1/business/approve/keys/\(secondPhone.kid)/revoke", RevokeApprovalKeyRequest()).status, .ok)
            let other = try await h.makeBusiness(name: "Other Bank", handle: "otherbank3")
            aeq(try await h.businessPost(other, "/v1/business/approve/keys/\(f.phone.kid)/revoke", RevokeApprovalKeyRequest()).status, .notFound)
            aeq(try await h.approvalAudit("approve.key_revoked").count, 2)
            // A revoked key can't sign a result any more.
            let late = try await h.createRequest(f)
            XCTAssertEqual(late.0.status, .conflict)
        }
    }

    func testDisconnectingTheBusinessAndDeletingTheAccountRemoveTheKeys() async throws {
        try await withHarness { h in
            // Disconnecting the business revokes the relationship's keys, and a request has nobody left to answer it.
            let f = try await h.approveFixture()
            let (created, _) = try await h.createRequest(f)
            XCTAssertEqual(created.status, .created, created.text)
            let disconnect = try await h.signed(f.phone.consumer, .DELETE, "/v1/relationships/\(f.relationship.id)")
            XCTAssertEqual(disconnect.status, .ok, disconnect.text)
            let key = try unwrap(try await ApproveKeyRecord.query(on: h.db).filter(\.$kid == f.phone.kid).first())
            XCTAssertEqual(key.status, "revoked")
            atrue(try await h.pendingRequests(f.phone.consumer).isEmpty)
            let late = try await h.createRequest(f)
            XCTAssertEqual(late.0.status, .conflict, "no active key and no relationship")
            aeq(try await h.approvalAudit("approve.key_revoked").count, 1)

            // Deleting the account revokes every key (the revoked rows stay as audit evidence, with no personal data), forgets the displayed
            // details and challenges, and removes deliveries and freezes.
            let g = try await h.approveFixture(name: "Contoso Bank", handle: "contosobank")
            let (made, _) = try await h.createRequest(g)
            _ = try await h.signedPost(g.phone.consumer, "/v1/approve/freeze", ApproveFreezeRequest(scope: .account, frozen: true))
            XCTAssertEqual(made.status, .created, made.text)
            let deleted = try await h.signed(g.phone.consumer, .DELETE, "/v1/account")
            XCTAssertEqual(deleted.status, .ok, deleted.text)
            let owner = g.phone.consumer.id.uuid
            let keys = try await ApproveKeyRecord.query(on: h.db).filter(\.$consumerId == owner).all()
            XCTAssertFalse(keys.isEmpty)
            XCTAssertTrue(keys.allSatisfy { $0.status == "revoked" })
            let requests = try await ApproveRequestRecord.query(on: h.db).filter(\.$consumerId == owner).all()
            XCTAssertTrue(requests.allSatisfy { $0.detailsSealed == nil && $0.challenge == nil })
            aeq(try await ApproveDeliveryRecord.query(on: h.db).filter(\.$consumerId == owner).count(), 0)
            aeq(try await ApproveFreezeRecord.query(on: h.db).filter(\.$consumerId == owner).count(), 0)
        }
    }

    // MARK: Unlinkability (ADR-06, A3)

    func testTwoBusinessesNeverSeeTheSameKeySubjectOrDevice() async throws {
        try await withHarness { h in
            let b1 = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            let b2 = try await h.makeBusiness(name: "Contoso Pay", handle: "contosopay")
            let k1 = try await h.publishDirectory(b1)
            let k2 = try await h.publishDirectory(b2)
            let consumer = try await h.readyConsumer()
            _ = try await h.connect(consumer, to: b1)
            _ = try await h.connect(consumer, to: b2)
            let p1 = try await h.enrollApproval(consumer, business: b1, keys: k1)
            let p2 = try await h.enrollApproval(consumer, business: b2, keys: k2)
            XCTAssertNotEqual(p1.kid, p2.kid)
            XCTAssertNotEqual(p1.hpke.publicKey.kid, p2.hpke.publicKey.kid)
            XCTAssertNotEqual(h.subjectRef(b1, consumer), h.subjectRef(b2, consumer))
            let f1 = ApproveFixture(business: b1, keys: k1, relationship: try await h.connect(consumer, to: b1), subject: h.subjectRef(b1, consumer), phone: p1)
            let f2 = ApproveFixture(business: b2, keys: k2, relationship: try await h.connect(consumer, to: b2), subject: h.subjectRef(b2, consumer), phone: p2)
            let keys1 = try await h.business(b1, .GET, "/v1/business/approve/keys?subject_ref=\(f1.subject.rawValue)").json([ApprovalKeyView].self)
            let keys2 = try await h.business(b2, .GET, "/v1/business/approve/keys?subject_ref=\(f2.subject.rawValue)").json([ApprovalKeyView].self)
            XCTAssertEqual(keys1.map(\.kid), [p1.kid])
            XCTAssertEqual(keys2.map(\.kid), [p2.kid])
            XCTAssertTrue(Set(keys1.map(\.publicKey)).isDisjoint(with: Set(keys2.map(\.publicKey))))
            // One business can neither list nor revoke the other's keys, nor learn that they exist.
            aeq(try await h.business(b1, .GET, "/v1/business/approve/keys?subject_ref=\(f2.subject.rawValue)").status, .notFound)
            aeq(try await h.businessPost(b1, "/v1/business/approve/keys/\(p2.kid)/revoke", RevokeApprovalKeyRequest()).status, .notFound)
            // The same key can't be enrolled at two businesses (the kid is globally unique).
            let reuse = try await h.createEnrollmentAttempt(consumer: consumer, business: b2, keys: k2, reuse: p1)
            XCTAssertEqual(reuse.status, .conflict)
            // Results are addressed (aud) to one business: a result for b1 is not valid for b2 whatever happens to it.
            let (r1, body1) = try await h.createRequest(f1)
            XCTAssertEqual(r1.status, .created)
            let pending = try await h.pendingRequests(consumer)
            let jws = try await h.answer(p1, try XCTUnwrap(pending.first { $0.requestId == body1.requestId }))
            let asB2 = ApprovalExpectation(audience: b2.id, subject: f2.subject, requestId: body1.requestId, challenge: body1.challenge!, subjectDetails: .transaction(body1.transaction!))
            XCTAssertThrowsError(try ApprovalResultVerifier.verify(jws, expecting: asB2, keys: [EnrolledApprovalKey(kid: p1.kid, publicKey: p1.approvalKey.publicKey, subject: f2.subject, assurance: .biometric)], now: h.clock.now()))
        }
    }
}

extension TestHarness {
    /// Tries to enroll `reuse`'s approval key again for another business.
    func createEnrollmentAttempt(consumer: TestConsumer, business: TestBusiness, keys: TestBusinessKeys, reuse: TestApprovalDevice) async throws -> HTTPResult {
        let subject = subjectRef(business, consumer)
        let ticket = try await businessPost(business, "/v1/business/approve/enrollments", CreateApprovalEnrollmentRequest(subjectRef: subject, capability: .transactionApprove)).json(ApprovalEnrollmentTicket.self)
        let preview = try await signedPost(consumer, "/v1/approve/enrollments/lookup", ApproveEnrollmentLookupRequest(code: ticket.code)).json(ApproveEnrollmentPreview.self)
        let statement = try ApprovalEnrollmentStatement(businessId: business.id, subject: subject, enrollmentId: preview.enrollmentId, publicKey: reuse.approvalKey.publicKey,
                                                        hpkePublicKey: SoftwareE2EEPrivateKey().publicKey, assurance: .biometric, createdAt: clock.now())
        return try await signedPost(consumer, "/v1/approve/enrollments/\(preview.enrollmentId.uuidString.lowercased())/complete",
                                    CompleteApproveEnrollmentRequest(statement: try await statement.sign(with: reuse.approvalKey)))
    }

    // MARK: Gate finding F1: the binding tag travels through the relay, and a key the business never confirms is ended

    func testTheBindingTagIsStoredAndHandedToTheBusinessAndOnlyItsShapeIsChecked() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            let keys = try await h.publishDirectory(b)
            let consumer = try await h.readyConsumer()
            _ = try await h.connect(consumer, to: b)
            let secret = ApprovalEnrollmentSecret()
            let phone = try await h.enrollApproval(consumer, business: b, keys: keys, confirm: false, bindingSecret: secret)
            let record = try unwrap(try await ApproveEnrollmentRecord.query(on: h.db).first())
            let view = try await h.business(b, .GET, "/v1/business/approve/enrollments/\(record.id!.uuidString.lowercased())").json(ApprovalEnrollmentView.self)
            let statement = try unwrap(view.deviceStatement)
            aeq(view.bindingTag, secret.bindingTag(for: statement))
            atrue(secret.verifyBindingTag(try unwrap(view.bindingTag), for: statement))
            // A malformed tag is refused by the device endpoint.
            let other = try await h.makeBusiness(name: "Contoso", handle: "contoso")
            let otherKeys = try await h.publishDirectory(other)
            let rel = try await h.connect(consumer, to: other)
            _ = rel
            let subject = h.subjectRef(other, consumer)
            let ticket = try await h.businessPost(other, "/v1/business/approve/enrollments", CreateApprovalEnrollmentRequest(subjectRef: subject, capability: .transactionApprove)).json(ApprovalEnrollmentTicket.self)
            let preview = try await h.signedPost(consumer, APIRoutes.approveEnrollmentLookup.template, ApproveEnrollmentLookupRequest(code: ticket.code)).json(ApproveEnrollmentPreview.self)
            let key = SoftwareP256SigningKey()
            let signed = try await ApprovalEnrollmentStatement(businessId: other.id, subject: subject, enrollmentId: preview.enrollmentId, publicKey: key.publicKey,
                                                              hpkePublicKey: SoftwareE2EEPrivateKey().publicKey, assurance: .biometric, createdAt: h.clock.now()).sign(with: key)
            let bad = try await h.signedPost(consumer, "/v1/approve/enrollments/\(preview.enrollmentId.uuidString.lowercased())/complete", CompleteApproveEnrollmentRequest(statement: signed, bindingTag: "short"))
            aeq(bad.status, .badRequest, bad.text)
            _ = (phone, otherKeys)
        }
    }

    func testAKeyTheBusinessNeverConfirmsIsEndedAlertedAndCannotBeConfirmedLater() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            let keys = try await h.publishDirectory(b)
            let consumer = try await h.readyConsumer()
            _ = try await h.connect(consumer, to: b)
            let phone = try await h.enrollApproval(consumer, business: b, keys: keys, confirm: false)
            let record = try unwrap(try await ApproveEnrollmentRecord.query(on: h.db).first())
            let service = ApproveEnrollmentService(db: h.db, ctx: h.ctx)
            aeq(try await service.expireUnconfirmed(), 0, "still inside the enrollment lifetime")
            // A relay that holds the confirmation back until later cannot revive the key: past expiry + grace the business cannot confirm...
            h.clock.advance(by: 600 + 300 + 5)
            let path = "/v1/business/approve/enrollments/\(record.id!.uuidString.lowercased())"
            let view = try await h.business(b, .GET, path).json(ApprovalEnrollmentView.self)
            let handed = try unwrap(view.deviceStatement)
            let confirmation = try await ApprovalEnrollmentConfirmation(confirming: try ApprovalEnrollmentStatement.verify(handed), signed: handed, at: h.clock.now()).sign(with: keys.confirmation)
            aeq(try await h.businessPost(b, path + "/confirm", ConfirmApprovalEnrollmentRequest(confirmation: confirmation)).status, .gone)
            // ...and the sweep ends it: key revoked, enrollment expired, customer told, business alerted.
            aeq(try await service.expireUnconfirmed(), 1)
            aeq(try await ApproveKeyRecord.query(on: h.db).filter(\.$kid == phone.kid).first()?.status, "revoked")
            aeq(try await ApproveEnrollmentRecord.find(record.id!, on: h.db)?.status, "expired")
            aeq(try await h.approvalAudit("approve.enrollment_unconfirmed").count, 1)
            aeq(try await SecurityNoticeRecord.query(on: h.db).filter(\.$kind == "approvalKeyUnconfirmed").count(), 1)
            aeq(try await service.expireUnconfirmed(), 0, "once")
            aeq(try await h.businessPost(b, path + "/confirm", ConfirmApprovalEnrollmentRequest(confirmation: confirmation)).status, .gone)
        }
    }
}
