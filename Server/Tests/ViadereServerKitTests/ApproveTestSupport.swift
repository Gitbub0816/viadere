@preconcurrency import Crypto
import Fluent
import Foundation
import NIOHTTP1
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Everything a business holds in its own KMS: the root key and the three operational keys. The server never sees a private half.
final class TestBusinessKeys: @unchecked Sendable {
    let root = SoftwareP256SigningKey()
    var confirmation = SoftwareP256SigningKey()
    var requestSigning = SoftwareP256SigningKey()
    var hpke = SoftwareE2EEPrivateKey()
    var serial: Int64 = 0
    var rootKid: String { KeyIdentifier.make(try! root.publicKey.signingKey()) }
    var confirmationKid: String { KeyIdentifier.make(try! confirmation.publicKey.signingKey()) }
    var requestSigningKid: String { KeyIdentifier.make(try! requestSigning.publicKey.signingKey()) }
}

/// The customer's phone for one relationship: a pairwise approval key and a per-relationship HPKE key, in software.
struct TestApprovalDevice {
    var consumer: TestConsumer
    var approvalKey: SoftwareP256SigningKey
    var hpke: SoftwareE2EEPrivateKey
    var assurance: ApprovalAMR
    var kid: String { KeyIdentifier.make(try! approvalKey.publicKey.signingKey()) }
}

/// A fully enrolled relationship: business, customer, active key.
struct ApproveFixture {
    var business: TestBusiness
    var keys: TestBusinessKeys
    var relationship: Relationship
    var subject: SubjectRef
    var phone: TestApprovalDevice
}

extension TestHarness {
    // MARK: Business side

    func publishEntry(_ business: TestBusiness, _ entry: KeyLogEntry, key: String? = nil) async throws -> HTTPResult {
        try await businessPost(business, APIRoutes.businessKeyDirectoryPublish.template, PublishKeyEntryRequest(entry: Base64URL.encode(try entry.leafData())), key: key)
    }

    /// Registers the root and publishes the confirmation, request-signing and HPKE keys, as the business's tooling would.
    func publishDirectory(_ business: TestBusiness, hpke: Bool = true, signing: Bool = true) async throws -> TestBusinessKeys {
        let keys = TestBusinessKeys()
        let root = try await KeyLogEntry.sign(.root(RootRegistration(businessId: business.id, publicKey: keys.root.publicKey, createdAt: clock.now())), rootKey: keys.root)
        let registered = try await publishEntry(business, root)
        XCTAssertEqual(registered.status, .created, registered.text)
        try await publishKey(business, keys, .approvalEnrollmentConfirmation, keys.confirmation.publicKey.x963)
        if signing { try await publishKey(business, keys, .approvalRequestSigning, keys.requestSigning.publicKey.x963) }
        if hpke { try await publishKey(business, keys, .hpkeEncryption, keys.hpke.publicKey.x963) }
        return keys
    }

    @discardableResult
    func publishKey(_ business: TestBusiness, _ keys: TestBusinessKeys, _ purpose: BusinessKeyPurpose, _ publicKey: Data, days: Double = 30) async throws -> HTTPResult {
        keys.serial += 1
        let statement = try KeyPublication(businessId: business.id, rootKid: keys.rootKid, purpose: purpose, publicKey: publicKey,
                                           notBefore: clock.now().addingTimeInterval(-60), notAfter: clock.now().addingTimeInterval(days * 86_400), serial: keys.serial)
        let result = try await publishEntry(business, try await KeyLogEntry.sign(.key(statement), rootKey: keys.root))
        XCTAssertEqual(result.status, .created, result.text)
        return result
    }

    func subjectRef(_ business: TestBusiness, _ consumer: TestConsumer) -> SubjectRef {
        ctx.subjects.subjectRef(businessId: business.id, consumerId: consumer.id)
    }

    // MARK: Enrollment, end to end

    /// Runs the whole business-authorized enrollment and returns the phone. `confirm: false` stops before the business confirms.
    func enrollApproval(_ consumer: TestConsumer, business: TestBusiness, keys: TestBusinessKeys, capability: Capability = .transactionApprove,
                        assurance: ApprovalAMR = .biometric, confirm: Bool = true, hpke: SoftwareE2EEPrivateKey = SoftwareE2EEPrivateKey(),
                        approvalKey: SoftwareP256SigningKey = SoftwareP256SigningKey()) async throws -> TestApprovalDevice {
        let subject = subjectRef(business, consumer)
        let created = try await businessPost(business, APIRoutes.businessApproveEnrollmentCreate.template, CreateApprovalEnrollmentRequest(subjectRef: subject, capability: capability))
        XCTAssertEqual(created.status, .created, created.text)
        let ticket = try created.json(ApprovalEnrollmentTicket.self)
        let lookup = try await signedPost(consumer, APIRoutes.approveEnrollmentLookup.template, ApproveEnrollmentLookupRequest(code: ApprovalEnrollmentCode.display(ticket.code)))
        XCTAssertEqual(lookup.status, .ok, lookup.text)
        let preview = try lookup.json(ApproveEnrollmentPreview.self)
        let statement = try ApprovalEnrollmentStatement(businessId: business.id, subject: preview.subjectRef, enrollmentId: preview.enrollmentId, publicKey: approvalKey.publicKey,
                                                        hpkePublicKey: hpke.publicKey, assurance: assurance, createdAt: clock.now())
        let signed = try await statement.sign(with: approvalKey)
        let completed = try await signedPost(consumer, "/v1/approve/enrollments/\(preview.enrollmentId.uuidString.lowercased())/complete", CompleteApproveEnrollmentRequest(statement: signed))
        XCTAssertEqual(completed.status, .created, completed.text)
        if confirm {
            let view = try await self.business(business, .GET, "/v1/business/approve/enrollments/\(preview.enrollmentId.uuidString.lowercased())").json(ApprovalEnrollmentView.self)
            let deviceStatement = try XCTUnwrap(view.deviceStatement)
            let verified = try ApprovalEnrollmentStatement.verify(deviceStatement)       // the business verifies the device's statement itself
            let confirmation = try await ApprovalEnrollmentConfirmation(confirming: verified, signed: deviceStatement, at: clock.now()).sign(with: keys.confirmation)
            let confirmed = try await businessPost(business, "/v1/business/approve/enrollments/\(preview.enrollmentId.uuidString.lowercased())/confirm", ConfirmApprovalEnrollmentRequest(confirmation: confirmation))
            XCTAssertEqual(confirmed.status, .ok, confirmed.text)
        }
        return TestApprovalDevice(consumer: consumer, approvalKey: approvalKey, hpke: hpke, assurance: assurance)
    }

    /// Business + directory + connected customer + enrolled key.
    func approveFixture(name: String = "Northwind Bank", handle: String = "northwindbank", hpkeKeys: Bool = true) async throws -> ApproveFixture {
        let b = try await makeBusiness(name: name, handle: handle)
        let keys = try await publishDirectory(b, hpke: hpkeKeys)
        let consumer = try await readyConsumer()
        let rel = try await connect(consumer, to: b)
        let phone = try await enrollApproval(consumer, business: b, keys: keys)
        return ApproveFixture(business: b, keys: keys, relationship: rel, subject: subjectRef(b, consumer), phone: phone)
    }

    // MARK: Requests

    static func makeRequestId() -> String { "req_" + SecureToken.generate(byteCount: 12) }

    func transaction(payee: String = "Example Merchant", amount: Int64 = 250_000, reference: String = "bank_tx_123") -> TransactionDetails {
        TransactionDetails(currency: "USD", amountMinor: amount, payeeDisplay: payee, transactionReference: reference)
    }

    func createRequest(_ f: ApproveFixture, requestId: String = TestHarness.makeRequestId(), challenge: String = SecureToken.generate(byteCount: 24),
                       details: TransactionDetails? = nil, expiresIn: Int = 120) async throws -> (HTTPResult, CreateApprovalRequest) {
        let body = CreateApprovalRequest(requestId: requestId, subjectRef: f.subject, capability: .transactionApprove, challenge: challenge,
                                         transaction: details ?? transaction(), expiresInSeconds: expiresIn)
        return (try await businessPost(f.business, APIRoutes.businessApproveRequestCreate.template, body), body)
    }

    func pendingRequests(_ consumer: TestConsumer) async throws -> [ApproveDeviceRequest] {
        let result = try await signed(consumer, .GET, APIRoutes.approveRequests.template)
        XCTAssertEqual(result.status, .ok, result.text)
        return try result.json([ApproveDeviceRequest].self)
    }

    /// The phone's answer for a server-visible request: signs exactly what it displays.
    func answer(_ phone: TestApprovalDevice, _ request: ApproveDeviceRequest, decision: ApprovalDecision = .approve, amr: ApprovalAMR = .biometric,
                at: Date? = nil) async throws -> String {
        let subject: ApprovalSubject
        if let t = request.transaction { subject = .transaction(t) } else if let a = request.authentication { subject = .authentication(a) } else { throw XCTSkip("end-to-end request") }
        let content = ApprovalRequestContent(businessId: request.business.id, subject: request.subjectRef, requestId: request.requestId, challenge: request.challenge ?? "",
                                            details: subject, toKid: phone.kid, issuedAt: request.createdAt, expiresAt: request.expiresAt)
        return try await ApprovalResultFactory.sign(displayed: content, decision: decision, amr: amr, key: phone.approvalKey, now: at ?? clock.now())
    }

    func submit(_ phone: TestApprovalDevice, deliveryId: UUID, result: String) async throws -> HTTPResult {
        try await signedPost(phone.consumer, "/v1/approve/requests/\(deliveryId.uuidString.lowercased())/result", SubmitApprovalResultRequest(result: result))
    }

    func requestView(_ f: ApproveFixture, _ requestId: String) async throws -> ApprovalRequestView {
        let result = try await business(f.business, .GET, "/v1/business/approve/requests/\(requestId)")
        XCTAssertEqual(result.status, .ok, result.text)
        return try result.json(ApprovalRequestView.self)
    }

    /// What a business does with a decided request: fetch the result, then verify it against its **own** record (never the relay's status).
    func businessVerifies(_ f: ApproveFixture, request: CreateApprovalRequest, resultRef: String, keys: [EnrolledApprovalKey], replay: any ReplayGuard,
                          minimum: ApprovalAMR? = .biometric) async throws -> VerifiedApproval {
        let fetched = try await business(f.business, .GET, "/v1/business/approve/results/\(resultRef)")
        XCTAssertEqual(fetched.status, .ok, fetched.text)
        let response = try fetched.json(ApprovalResultResponse.self)
        let details: ApprovalSubject = request.transaction.map { .transaction($0) } ?? .authentication(request.authentication!)
        let expectation = ApprovalExpectation(audience: f.business.id, subject: f.subject, requestId: request.requestId, challenge: request.challenge ?? "",
                                              subjectDetails: details, requestExpiresAt: nil, minimumAMR: minimum)
        return try await ApprovalResultVerifier.verifyAndConsume(response.result, expecting: expectation, keys: keys, now: clock.now(), replayGuard: replay)
    }

    func enrolledKeys(_ f: ApproveFixture) async throws -> [EnrolledApprovalKey] {
        let result = try await business(f.business, .GET, "/v1/business/approve/keys?subject_ref=\(f.subject.rawValue)")
        XCTAssertEqual(result.status, .ok, result.text)
        return try result.json([ApprovalKeyView].self).map { try $0.enrolledKey() }
    }

    func approvalAudit(_ action: String) async throws -> [AuditEventRecord] {
        try await AuditEventRecord.query(on: db).filter(\.$action == action).all()
    }
}

// MARK: Assertions whose operands are awaited (XCTest's autoclosures cannot suspend)

func aeq<T: Equatable>(_ lhs: T, _ rhs: T, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) { XCTAssertEqual(lhs, rhs, message, file: file, line: line) }
func ane<T: Equatable>(_ lhs: T, _ rhs: T, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) { XCTAssertNotEqual(lhs, rhs, message, file: file, line: line) }
func atrue(_ value: Bool, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) { XCTAssertTrue(value, message, file: file, line: line) }
func afalse(_ value: Bool, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) { XCTAssertFalse(value, message, file: file, line: line) }
func anil<T>(_ value: T?, _ message: String = "", file: StaticString = #filePath, line: UInt = #line) { XCTAssertNil(value, message, file: file, line: line) }
