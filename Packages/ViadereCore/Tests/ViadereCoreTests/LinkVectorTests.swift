import Crypto
import Foundation
import Testing
@testable import ViadereCore

/// Cross-language vectors of the link-session protocol (`docs/protocol/vectors/link-session-v1.json`, `docs/SECURITY.md` §2.59). Generated with
/// `VIADERE_WRITE_VECTORS=1 swift test --filter LinkVectorTests`; otherwise only read and checked.
@Suite("Link-session vectors")
struct LinkVectorTests {
    struct SignedVector: Codable, Equatable {
        var kid: String
        var publicKey: String
        /// `domain ‖ payload bytes` as UTF-8 text (the exact signing input).
        var signingInput: String
        var payload: String
        var signature: String
    }

    struct Vectors: Codable, Equatable {
        var name: String
        var version: Int
        var description: String
        var linkDomain: String
        var sessionId: String
        var businessId: String
        var subjectRef: String
        var code: String
        var secret: String
        var link: String
        var checkCode: String
        var descriptor: SignedVector
        var descriptorDigest: String
        var approvalStatement: SignedVector
        var approvalStatementDigest: String
        var statement: SignedVector
        var statementDigest: String
        var bindingTag: String
        var sas: String
        var pseudonym: String
        var confirmation: SignedVector
        var result: SignedVector
        var appAttestClientData: String
    }

    static let sessionId = UUID(uuidString: "5a0e9c2b-3f41-4d6a-9b7c-0d1e2f3a4b5c")!
    static let businessId = BusinessID(UUID(uuidString: "b0b1b2b3-c4c5-4d6d-8e7e-f8f9fafbfcfd")!)
    static let subject = SubjectRef("sub_" + Base64URL.encode(Data(SHA256.hash(data: Data("viadere-vector-subject".utf8)))))!
    static let issuedAt = Date(timeIntervalSince1970: 1_800_000_000)
    static let domain = LinkDomain("viadere.cksites.dev")!
    static let secret = LinkSessionSecret(base64URL: Base64URL.encode(Data(SHA256.hash(data: Data("viadere-vector-es".utf8)))))!

    static func vector(_ signed: SignedStatement, domain: String, kid: String, key: DevicePublicKey) -> SignedVector {
        SignedVector(kid: kid, publicKey: key.base64URL, signingInput: domain + String(decoding: Base64URL.decode(signed.payload)!, as: UTF8.self),
                     payload: signed.payload, signature: signed.signature)
    }

    static func generate() async throws -> Vectors {
        let viadere = try ProtocolVectorTests.fixedKey("link-descriptor")
        let business = try ProtocolVectorTests.fixedKey("business-confirmation")
        let connection = try ProtocolVectorTests.fixedKey("connection")
        let approval = try ProtocolVectorTests.fixedKey("approval")
        let hpke = try SoftwareE2EEPrivateKey(rawRepresentation: Data(SHA256.hash(data: Data("viadere-vector-hpke".utf8))))
        let viadereKid = KeyIdentifier.make(try viadere.publicKey.signingKey())
        let businessKid = KeyIdentifier.make(try business.publicKey.signingKey())
        let rootKid = KeyIdentifier.make(try ProtocolVectorTests.fixedKey("business-root").publicKey.signingKey())

        let descriptor = LinkSessionDescriptor(sessionId: sessionId, businessId: businessId, businessName: "Northwind Bank", businessDomain: "northwind.example",
                                               rootKid: rootKid, capabilities: [.transactionApprove, .messageSend], displayHint: "Account ending 4821",
                                               subject: subject, issuedAt: issuedAt, expiresAt: issuedAt.addingTimeInterval(300))
        let descriptorSigned = try await SignedStatement.sign(descriptor.object(signerKid: viadereKid), domain: LinkDomainSeparator.descriptor, with: viadere)
        let wrappedDescriptor = ViadereSignedStatement(kid: viadereKid, payload: descriptorSigned.payload, signature: descriptorSigned.signature)
        let approvalSigned = try await ApprovalEnrollmentStatement(businessId: businessId, subject: subject, enrollmentId: sessionId, publicKey: approval.publicKey,
                                                                   hpkePublicKey: hpke.publicKey, assurance: .biometric, createdAt: issuedAt.addingTimeInterval(10)).sign(with: approval)
        let statement = try LinkStatement(sessionId: sessionId, businessId: businessId, subject: subject, capabilities: descriptor.capabilities,
                                          descriptorDigest: LinkSessionDescriptor.digest(of: wrappedDescriptor), publicKey: connection.publicKey,
                                          approvalStatement: approvalSigned, createdAt: issuedAt.addingTimeInterval(10))
        let statementSigned = try await statement.sign(with: connection)
        let confirmation = try await LinkConfirmation(confirming: statement, signed: statementSigned, verification: .sasTyped, at: issuedAt.addingTimeInterval(40))
            .sign(with: business)
        let result = LinkResult(sessionId: sessionId, businessId: businessId, subject: subject, statementDigest: LinkStatement.digest(of: statementSigned),
                                approvalStatementDigest: ApprovalEnrollmentStatement.digest(of: approvalSigned), completedAt: issuedAt.addingTimeInterval(11))
        let resultSigned = try await SignedStatement.sign(result.object(signerKid: viadereKid), domain: LinkDomainSeparator.result, with: viadere)
        return Vectors(
            name: "link-session-v1", version: 1,
            description: "Business link sessions (SECURITY.md 2.59): Viadere's descriptor (VIADERE-LINK-DESCRIPTOR-V1, key link-descriptor), the device's approval-key statement (VIADERE-APPROVAL-ENROLL-V1, enrollment id = session id) and link statement (VIADERE-LINK-V1, signed by the connection key it contains), the binding tag, check code and SAS keyed by the business-held secret es, the account pseudonym, the business's confirmation (VIADERE-LINK-CONFIRM-V1), Viadere's result (VIADERE-LINK-RESULT-V1) and the App Attest client data of the completion. Payloads are canonical JSON (2.2), base64url; signatures ECDSA P-256 / SHA-256 raw r||s, low-S: verify them, do not compare them.",
            linkDomain: domain.host, sessionId: sessionId.uuidString.lowercased(), businessId: businessId.description, subjectRef: subject.rawValue,
            code: "K7QFM2XA", secret: secret.base64URL, link: LinkSessionLink.build(code: "K7QFM2XA", secret: secret, domain: domain), checkCode: secret.checkCode,
            descriptor: vector(descriptorSigned, domain: LinkDomainSeparator.descriptor, kid: viadereKid, key: viadere.publicKey),
            descriptorDigest: LinkSessionDescriptor.digest(of: wrappedDescriptor),
            approvalStatement: vector(approvalSigned, domain: ApproveDomain.enrollment, kid: KeyIdentifier.make(try approval.publicKey.signingKey()), key: approval.publicKey),
            approvalStatementDigest: ApprovalEnrollmentStatement.digest(of: approvalSigned),
            statement: vector(statementSigned, domain: LinkDomainSeparator.statement, kid: statement.kid, key: connection.publicKey),
            statementDigest: LinkStatement.digest(of: statementSigned),
            bindingTag: secret.bindingTag(for: statementSigned), sas: secret.expectedSAS(for: statementSigned), pseudonym: LinkPseudonym.make(subject),
            confirmation: vector(SignedStatement(payload: confirmation.payload, signature: confirmation.signature), domain: LinkDomainSeparator.confirmation,
                                 kid: businessKid, key: business.publicKey),
            result: vector(resultSigned, domain: LinkDomainSeparator.result, kid: viadereKid, key: viadere.publicKey),
            appAttestClientData: String(decoding: LinkAppAttest.clientData(sessionId: sessionId, statement: statementSigned), as: UTF8.self))
    }

    @Test func linkSessionVectorsHold() async throws {
        let url = ProtocolVectorTests.vectorsDirectory.appendingPathComponent("link-session-v1.json")
        if ProcessInfo.processInfo.environment["VIADERE_WRITE_VECTORS"] == "1" {
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
            try (try encoder.encode(try await Self.generate()) + Data("\n".utf8)).write(to: url)
        }
        let v = try JSONDecoder().decode(Vectors.self, from: try Data(contentsOf: url))
        let now = Self.issuedAt.addingTimeInterval(20)
        func statement(_ s: SignedVector) -> SignedStatement { SignedStatement(payload: s.payload, signature: s.signature) }
        func check(_ s: SignedVector, domain: String) throws {
            let payload = try #require(Base64URL.decode(s.payload))
            #expect(domain + String(decoding: payload, as: UTF8.self) == s.signingInput)
            #expect(statement(s).isValid(domain: domain, publicKey: try DevicePublicKey(base64URL: s.publicKey)))
        }
        try check(v.descriptor, domain: LinkDomainSeparator.descriptor)
        try check(v.approvalStatement, domain: ApproveDomain.enrollment)
        try check(v.statement, domain: LinkDomainSeparator.statement)
        try check(v.confirmation, domain: LinkDomainSeparator.confirmation)
        try check(v.result, domain: LinkDomainSeparator.result)

        let viadereKey = try DevicePublicKey(base64URL: v.descriptor.publicKey)
        let descriptor = try LinkSessionDescriptor.verify(ViadereSignedStatement(kid: v.descriptor.kid, payload: v.descriptor.payload, signature: v.descriptor.signature),
                                                          trustedKeys: [viadereKey], now: now)
        #expect(descriptor.sessionId.uuidString.lowercased() == v.sessionId)
        #expect(LinkSessionDescriptor.digest(of: ViadereSignedStatement(kid: v.descriptor.kid, payload: v.descriptor.payload, signature: v.descriptor.signature)) == v.descriptorDigest)
        let linkStatement = try LinkStatement.verify(statement(v.statement))
        try linkStatement.checkBinding(sessionId: descriptor.sessionId, businessId: descriptor.businessId, subject: descriptor.subject,
                                       capabilities: descriptor.capabilities, descriptorDigest: v.descriptorDigest)
        #expect(try linkStatement.checkApprovalStatement(statement(v.approvalStatement)) != nil)
        #expect(LinkStatement.digest(of: statement(v.statement)) == v.statementDigest)
        #expect(ApprovalEnrollmentStatement.digest(of: statement(v.approvalStatement)) == v.approvalStatementDigest)

        let secret = try #require(LinkSessionSecret(base64URL: v.secret))
        let domain = try #require(LinkDomain(v.linkDomain))
        #expect(LinkSessionLink.build(code: v.code, secret: secret, domain: domain) == v.link)
        #expect(secret.checkCode == v.checkCode)
        #expect(secret.bindingTag(for: statement(v.statement)) == v.bindingTag)
        #expect(secret.expectedSAS(for: statement(v.statement)) == v.sas)
        #expect(LinkSAS.compute(checkCode: v.checkCode, statement: statement(v.statement)) == v.sas)
        #expect(LinkPseudonym.make(try #require(SubjectRef(v.subjectRef))) == v.pseudonym)

        let confirmation = try LinkConfirmation.verify(BusinessSignedStatement(kid: v.confirmation.kid, payload: v.confirmation.payload, signature: v.confirmation.signature),
                                                       confirmationKey: try DevicePublicKey(base64URL: v.confirmation.publicKey))
        try confirmation.checkMatches(linkStatement, signed: statement(v.statement))
        let result = try LinkResult.verify(ViadereSignedStatement(kid: v.result.kid, payload: v.result.payload, signature: v.result.signature), trustedKeys: [viadereKey])
        #expect(result.statementDigest == v.statementDigest)
        #expect(result.approvalStatementDigest == v.approvalStatementDigest)
        #expect(String(decoding: LinkAppAttest.clientData(sessionId: descriptor.sessionId, statement: statement(v.statement)), as: UTF8.self) == v.appAttestClientData)
    }
}
