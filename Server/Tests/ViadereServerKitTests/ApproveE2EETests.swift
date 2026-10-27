@preconcurrency import Crypto
import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// WP1 end-to-end encryption (SEC-CR-001/002, ADR-07, acceptance 4): a relay-only compromise cannot read approval details, and cannot
/// make the device act on details the business did not send.
final class ApproveE2EETests: XCTestCase {
    static let secretPayee = "Mallory Secret Holdings"
    static let secretAmount: Int64 = 987_654

    /// What the business does: encrypts the (signed) request to the device HPKE key it took from the device's verified enrollment statement.
    private func sealed(_ h: TestHarness, _ f: ApproveFixture, requestId: String, challenge: String, details: ApprovalSubject, signer: SoftwareP256SigningKey? = nil,
                        lifetime: TimeInterval = 120, sender: String? = nil, recipientKid: String? = nil, hpke: E2EEPublicKey? = nil) async throws -> ApprovalEnvelopeDelivery {
        let now = h.clock.now()
        let content = ApprovalRequestContent(businessId: f.business.id, subject: f.subject, requestId: requestId, challenge: challenge, details: details, toKid: f.phone.kid,
                                            issuedAt: now, expiresAt: now.addingTimeInterval(lifetime))
        let plaintext = try await content.sealedPlaintext(signedWith: signer ?? f.keys.requestSigning)
        let context = E2EEContext(purpose: "approve.request", requestId: requestId, sender: sender ?? ApproveIdentifiers.sender(f.business.id),
                                  recipient: ApproveIdentifiers.recipient(kid: recipientKid ?? f.phone.kid), expiresAt: now.addingTimeInterval(lifetime))
        return ApprovalEnvelopeDelivery(kid: f.phone.kid, envelope: try E2EE.seal(plaintext, to: hpke ?? f.phone.hpke.publicKey, context: context))
    }

    private func createEncrypted(_ h: TestHarness, _ f: ApproveFixture, requestId: String = TestHarness.makeRequestId(), challenge: String = SecureToken.generate(byteCount: 24),
                                 details: ApprovalSubject? = nil, delivery: ApprovalEnvelopeDelivery? = nil) async throws -> (HTTPResult, CreateApprovalRequest, ApprovalSubject) {
        let subject = details ?? .transaction(h.transaction(payee: Self.secretPayee, amount: Self.secretAmount))
        let envelope: ApprovalEnvelopeDelivery
        if let delivery { envelope = delivery } else { envelope = try await sealed(h, f, requestId: requestId, challenge: challenge, details: subject) }
        let body = CreateApprovalRequest(requestId: requestId, subjectRef: f.subject, capability: .transactionApprove, envelopes: [envelope], expiresInSeconds: 120)
        return (try await h.businessPost(f.business, "/v1/business/approve/requests", body), body, subject)
    }

    /// What the device does with an end-to-end request: open it, check it came from the business (directory key), and return what to show.
    private func deviceOpens(_ h: TestHarness, _ f: ApproveFixture, _ request: ApproveDeviceRequest, key: E2EEPrivateKey? = nil, expectedRequestId: String? = nil) async throws -> ApprovalRequestContent {
        let envelope = try XCTUnwrap(request.envelope)
        let plaintext = try E2EE.open(envelope, using: key ?? f.phone.hpke, expecting: E2EEExpectation(purpose: "approve.request", requestId: expectedRequestId ?? request.requestId,
                                                                                                        sender: ApproveIdentifiers.sender(request.business.id),
                                                                                                        recipient: ApproveIdentifiers.recipient(kid: f.phone.kid)), now: h.clock.now())
        let signed = try ApprovalRequestContent.parseSigned(plaintext)
        // The directory, verified from the pinned log key; the request must be signed by a key it publishes for this business.
        let response = try await h.request(.GET, "/v1/key-directory/businesses/\(request.business.id)").json(KeyDirectoryResponse.self)
        let verified = try KeyDirectoryVerifier(logKeys: [h.ctx.config.approve.logKey.publicKey], logId: h.ctx.config.approve.logId)
            .verify(response, businessId: request.business.id, lastSeen: nil, now: h.clock.now())
        guard let published = verified.state.validKey(kid: signed.kid, purpose: .approvalRequestSigning, at: h.clock.now())?.signingKey else { throw ApprovalRequestError.badSignature }
        return try ApprovalRequestContent.verify(signed, signingKey: published, expectedBusiness: request.business.id, expectedSubject: request.subjectRef, expectedKid: f.phone.kid,
                                                 expectedRequestId: request.requestId, now: h.clock.now())
    }

    /// An envelope with its JSON members edited, as a relay could rewrite what it stores.
    private func rewrite(_ envelope: E2EEEnvelope, _ edit: (inout [String: JSONValue]) -> Void) throws -> E2EEEnvelope {
        guard case .object(var members) = try JSONDecoder().decode(JSONValue.self, from: try envelope.serialized()) else { throw E2EEError.malformed("object") }
        edit(&members)
        return try E2EEEnvelope.parse(try JSONEncoder().encode(JSONValue.object(members)))
    }

    /// Every table an end-to-end request touches, as one searchable string.
    private func relayDump(_ h: TestHarness) async throws -> String {
        var text = ""
        for r in try await ApproveRequestRecord.query(on: h.db).all() {
            text += [r.requestId, r.subjectRef, r.capability, r.protection, r.requestHash, r.challenge ?? "", r.detailsSealed ?? "", r.status, r.reason ?? "", r.resultJWS ?? ""].joined(separator: "|")
        }
        for d in try await ApproveDeliveryRecord.query(on: h.db).all() { text += (d.envelope ?? "") + d.kid }
        for a in try await AuditEventRecord.query(on: h.db).all() { text += a.metadataJSON + (a.subjectId ?? "") + (a.correlationId ?? "") }
        for w in try await WebhookDeliveryRecord.query(on: h.db).all() { text += String(decoding: WebhookService(db: h.db, ctx: h.ctx).storedBody(w) ?? Data(), as: UTF8.self) }
        for n in try await SecurityNoticeRecord.query(on: h.db).all() { text += n.message }
        for e in try await KDLogEntryRecord.query(on: h.db).all() { text += e.entry }
        return text
    }

    // MARK: Acceptance 4

    func testARelayOnlyCompromiseSeesCiphertextAndTheDeviceStillApprovesWhatTheBusinessSent() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            let (created, body, subject) = try await createEncrypted(h, f)
            XCTAssertEqual(created.status, .created, created.text)
            XCTAssertEqual(try created.json(ApprovalRequestView.self).protection, .endToEnd)
            // The wire the relay saw, and everything it stored, contain none of the details.
            XCTAssertFalse(created.text.contains(Self.secretPayee))
            let dump = try await relayDump(h)
            for needle in [Self.secretPayee, "Mallory", "987654", "9876.54", "bank_tx_123", body.requestId.isEmpty ? "x" : "Example Merchant"] {
                XCTAssertFalse(dump.contains(needle), "the relay's database contains \(needle)")
            }
            XCTAssertFalse(dump.contains(Base64URL.encode(Data(Self.secretPayee.utf8))))
            // The device gets ciphertext only from the relay; the DTO carries no details and no challenge.
            let request = try await h.pendingRequests(f.phone.consumer)[0]
            XCTAssertEqual(request.protection, .endToEnd)
            XCTAssertNil(request.transaction)
            XCTAssertNil(request.challenge)
            XCTAssertNotNil(request.envelope)
            // It decrypts on the device, verifies the business's signature against the directory, and shows the real details.
            let content = try await deviceOpens(h, f, request)
            guard case .transaction(let shown) = content.details else { return XCTFail() }
            XCTAssertEqual(shown.payeeDisplay, Self.secretPayee)
            XCTAssertEqual(shown.amountMinor, Self.secretAmount)
            XCTAssertEqual(content.challenge, body.requestId.isEmpty ? "" : content.challenge)
            // The signed digest covers what was displayed; the relay verifies the rest without knowing the amount.
            let jws = try await ApprovalResultFactory.sign(displayed: content, decision: .approve, amr: .biometric, key: f.phone.approvalKey, now: h.clock.now())
            let submitted = try await h.submit(f.phone, deliveryId: request.id, result: jws)
            XCTAssertEqual(submitted.status, .ok, submitted.text)
            // The business verifies against ITS OWN record of the transaction (which it never had to disclose to the relay).
            let ref = try unwrap(try await h.requestView(f, body.requestId).resultRef)
            let fetched = try await h.business(f.business, .GET, "/v1/business/approve/results/\(ref)").json(ApprovalResultResponse.self)
            let expectation = ApprovalExpectation(audience: f.business.id, subject: f.subject, requestId: body.requestId, challenge: content.challenge, subjectDetails: subject, minimumAMR: .biometric)
            let verified = try ApprovalResultVerifier.verify(fetched.result, expecting: expectation, keys: try await h.enrolledKeys(f), now: h.clock.now())
            XCTAssertEqual(verified.decision, .approve)
            // And a different amount in the business's record would not have verified.
            let other = ApprovalExpectation(audience: f.business.id, subject: f.subject, requestId: body.requestId, challenge: content.challenge,
                                            subjectDetails: .transaction(h.transaction(payee: Self.secretPayee, amount: 1)))
            let enrolled = try await h.enrolledKeys(f)
            XCTAssertThrowsError(try ApprovalResultVerifier.verify(fetched.result, expecting: other, keys: enrolled, now: h.clock.now()))
            // After the whole flow, still nothing in the relay.
            let after = try await relayDump(h)
            XCTAssertFalse(after.contains("Mallory") || after.contains("987654"))
        }
    }

    func testTheRelayCannotDecryptEvenWithTheDatabaseAndItsOwnKeys() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            _ = try await createEncrypted(h, f)
            let delivery = try unwrap(try await ApproveDeliveryRecord.query(on: h.db).first())
            let envelope = try E2EEEnvelope.parse(Data(try XCTUnwrap(delivery.envelope).utf8))
            let relayKey = SoftwareE2EEPrivateKey()
            // Everything the server holds: the log key, the pepper, the data-encryption key, the public keys. None opens it.
            XCTAssertThrowsError(try E2EE.open(envelope, using: relayKey, expecting: E2EEExpectation(purpose: "approve.request"), now: h.clock.now())) { XCTAssertEqual($0 as? E2EEError, .wrongRecipientKey) }
            let asDevice = envelope
            XCTAssertThrowsError(try E2EE.open(asDevice, using: f.phone.hpke, expecting: E2EEExpectation(purpose: "verify.result"), now: h.clock.now()), "a different purpose")
            XCTAssertNoThrow(try E2EE.open(asDevice, using: f.phone.hpke, expecting: E2EEExpectation(purpose: "approve.request"), now: h.clock.now()))
        }
    }

    // MARK: Relay tampering: the device rejects

    func testTamperedOrForgedEnvelopesAreRejectedByTheDevice() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            let (_, body, _) = try await createEncrypted(h, f)
            let honest = try await h.pendingRequests(f.phone.consumer)[0]

            // (a) The relay flips a ciphertext bit.
            let delivery = try unwrap(try await ApproveDeliveryRecord.query(on: h.db).first())
            var envelope = try E2EEEnvelope.parse(Data(try XCTUnwrap(delivery.envelope).utf8))
            envelope = try rewrite(envelope) { members in
                var ct = Base64URL.decode(members["ct"]!.stringValue!)!
                ct[3] ^= 0x01
                members["ct"] = .string(Base64URL.encode(ct))
            }
            var tampered = honest
            tampered.envelope = envelope
            do { _ = try await deviceOpens(h, f, tampered); XCTFail("tampered ciphertext was accepted") } catch { aeq(error as? E2EEError, .authenticationFailed) }

            // (b) The relay re-labels the envelope as a different request (to replay an old approval prompt as a new one).
            var relabelled = honest
            relabelled.envelope = honest.envelope
            do { _ = try await deviceOpens(h, f, honest, expectedRequestId: "req_a_different_request_id") ; XCTFail() } catch { aeq(error as? E2EEError, .contextMismatch("request_id")) }

            // (c) The relay forges its own request: it knows the device's public HPKE key (it is in the enrollment statement), so it can
            // encrypt anything to it. It cannot sign as the business.
            let relayKey = SoftwareP256SigningKey()
            let forgedDetails = ApprovalSubject.transaction(h.transaction(payee: "Relay Payee", amount: 5_000_000))
            let forged = try await sealed(h, f, requestId: body.requestId, challenge: SecureToken.generate(byteCount: 24), details: forgedDetails, signer: relayKey)
            var forgedRequest = honest
            forgedRequest.envelope = forged.envelope
            do { _ = try await deviceOpens(h, f, forgedRequest); XCTFail("a relay-signed request was accepted") } catch { aeq(error as? ApprovalRequestError, .badSignature) }
            // Even signed with a key the business published for ANOTHER purpose (the enrollment-confirmation key), it is not accepted as a request.
            let wrongPurpose = try await sealed(h, f, requestId: body.requestId, challenge: SecureToken.generate(byteCount: 24), details: forgedDetails, signer: f.keys.confirmation)
            forgedRequest.envelope = wrongPurpose.envelope
            do { _ = try await deviceOpens(h, f, forgedRequest); XCTFail() } catch { aeq(error as? ApprovalRequestError, .badSignature) }

            // (d) The relay replays a genuine, older signed request: it is expired.
            h.clock.advance(by: 200)
            do { _ = try await deviceOpens(h, f, honest); XCTFail() } catch { aeq(error as? E2EEError, .expired) }
        }
    }

    func testARequestForAnotherDeviceOrAnotherBusinessIsNotAccepted() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            let (_, _, _) = try await createEncrypted(h, f)
            let honest = try await h.pendingRequests(f.phone.consumer)[0]
            // The relay shows the request under another business's name: the signed business id disagrees.
            let other = try await h.makeBusiness(name: "Other Bank", handle: "otherbank8")
            var misattributed = honest
            misattributed.business = other.summary
            do { _ = try await deviceOpens(h, f, misattributed); XCTFail() } catch { aeq(error as? E2EEError, .contextMismatch("sender")) }
            // A signed copy addressed to another of the customer's keys (another device) is not for this device.
            let signed = try ApprovalRequestContent.parseSigned(try E2EE.open(try XCTUnwrap(honest.envelope), using: f.phone.hpke, expecting: E2EEExpectation(purpose: "approve.request"), now: h.clock.now()))
            XCTAssertThrowsError(try ApprovalRequestContent.verify(signed, signingKey: f.keys.requestSigning.publicKey, expectedBusiness: f.business.id, expectedSubject: f.subject,
                                                                   expectedKid: KeyIdentifier.make(try SoftwareP256SigningKey().publicKey.signingKey()), expectedRequestId: honest.requestId, now: h.clock.now())) {
                XCTAssertEqual($0 as? ApprovalRequestError, .wrongDevice)
            }
        }
    }

    // MARK: The relay's own checks on the way in

    func testTheRelayRefusesEnvelopesThatAreNotBoundToTheRequestBusinessAndKey() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            let id = TestHarness.makeRequestId()
            let challenge = SecureToken.generate(byteCount: 24)
            let details = ApprovalSubject.transaction(h.transaction())
            func post(_ delivery: ApprovalEnvelopeDelivery, requestId: String? = nil) async throws -> HTTPResult {
                try await h.businessPost(f.business, "/v1/business/approve/requests", CreateApprovalRequest(requestId: requestId ?? id, subjectRef: f.subject, capability: .transactionApprove, envelopes: [delivery]))
            }
            // Sealed for another request id, another sender, another recipient key id, to a key that is not the device's HPKE key, already expired.
            aeq(try await post(try await sealed(h, f, requestId: "req_some_other_request_id", challenge: challenge, details: details)).status, .unprocessableEntity)
            aeq(try await post(try await sealed(h, f, requestId: id, challenge: challenge, details: details, sender: "biz_attacker")).status, .unprocessableEntity)
            aeq(try await post(try await sealed(h, f, requestId: id, challenge: challenge, details: details, recipientKid: String(repeating: "A", count: 43))).status, .unprocessableEntity)
            aeq(try await post(try await sealed(h, f, requestId: id, challenge: challenge, details: details, hpke: SoftwareE2EEPrivateKey().publicKey)).status, .unprocessableEntity)
            aeq(try await post(try await sealed(h, f, requestId: id, challenge: challenge, details: details, lifetime: -10)).status, .unprocessableEntity)
            // Addressed to a key that does not belong to this customer's relationship.
            var wrongKey = try await sealed(h, f, requestId: id, challenge: challenge, details: details)
            wrongKey = ApprovalEnvelopeDelivery(kid: KeyIdentifier.make(try SoftwareP256SigningKey().publicKey.signingKey()), envelope: wrongKey.envelope)
            aeq(try await post(wrongKey).status, .unprocessableEntity)
            // An end-to-end request may not also carry cleartext details.
            let both = try await h.businessPost(f.business, "/v1/business/approve/requests", CreateApprovalRequest(requestId: id, subjectRef: f.subject, capability: .transactionApprove, challenge: challenge,
                                                                                                                  transaction: h.transaction(), envelopes: [try await sealed(h, f, requestId: id, challenge: challenge, details: details)]))
            XCTAssertEqual(both.status, .unprocessableEntity)
            aeq(try await ApproveRequestRecord.query(on: h.db).count(), 0)
            // The correct one is accepted.
            aeq(try await post(try await sealed(h, f, requestId: id, challenge: challenge, details: details)).status, .created)
        }
    }

    func testServerVisibleRequestsAreClearlyMarkedAndKeepTheirOwnPath() async throws {
        try await withHarness { h in
            let f = try await h.approveFixture()
            let (created, _) = try await h.createRequest(f)
            XCTAssertEqual(try created.json(ApprovalRequestView.self).protection, .serverVisible)
            let request = try await h.pendingRequests(f.phone.consumer)[0]
            XCTAssertEqual(request.protection, .serverVisible)
            XCTAssertNil(request.envelope)
            // The relay holds the details for these (sealed per row), and says so to the device.
            anotnil(try await ApproveRequestRecord.query(on: h.db).first()?.detailsSealed)
        }
    }

    func testTheDeviceCanVerifyWhoSignedTheRequestOnlyThroughTheDirectory() async throws {
        try await withHarness { h in
            // A business that never published a request-signing key can use server-visible requests but not end-to-end ones.
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            let keys = try await h.publishDirectory(b, hpke: false, signing: false)
            let consumer = try await h.readyConsumer()
            _ = try await h.connect(consumer, to: b)
            let phone = try await h.enrollApproval(consumer, business: b, keys: keys)
            var f = ApproveFixture(business: b, keys: keys, relationship: try await h.connect(consumer, to: b), subject: h.subjectRef(b, consumer), phone: phone)
            f.phone = phone
            let (created, _, _) = try await createEncrypted(h, f)
            XCTAssertEqual(created.status, .created, "the relay cannot tell; it relays ciphertext")
            let request = try await h.pendingRequests(consumer)[0]
            do { _ = try await deviceOpens(h, f, request); XCTFail() } catch { aeq(error as? ApprovalRequestError, .badSignature) }
        }
    }
}
