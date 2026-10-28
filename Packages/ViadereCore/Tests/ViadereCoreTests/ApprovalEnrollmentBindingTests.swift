import Crypto
import Foundation
import XCTest
@testable import ViadereCore

/// Gate finding F1: the business authenticates the device's statement over a channel the relay does not see.
final class ApprovalEnrollmentBindingTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)
    private let businessId = BusinessID()
    private let subject = SubjectRef("sub_" + Base64URL.encode(Data(repeating: 7, count: 32)))!

    private func statement(key: SoftwareP256SigningKey = SoftwareP256SigningKey(), enrollment: UUID = UUID()) async throws -> SignedStatement {
        try await ApprovalEnrollmentStatement(businessId: businessId, subject: subject, enrollmentId: enrollment, publicKey: key.publicKey,
                                              hpkePublicKey: SoftwareE2EEPrivateKey().publicKey, assurance: .biometric, createdAt: now).sign(with: key)
    }

    func testTheBindingTagIsVerifiedWithTheBusinessSecretOnlyAndOnlyForTheStatementItCovers() async throws {
        let es = ApprovalEnrollmentSecret()
        let genuine = try await statement()
        let tag = es.bindingTag(for: genuine)
        XCTAssertEqual(tag.utf8.count, 43)
        XCTAssertTrue(es.verifyBindingTag(tag, for: genuine))
        // A relay that swaps in a statement for its own key cannot reuse the device's tag...
        let forged = try await statement()
        XCTAssertFalse(es.verifyBindingTag(tag, for: forged))
        // ...nor make one: it does not know the secret.
        XCTAssertFalse(es.verifyBindingTag(ApprovalEnrollmentSecret().bindingTag(for: forged), for: forged))
        XCTAssertFalse(es.verifyBindingTag("", for: genuine))
        XCTAssertFalse(es.verifyBindingTag(String(tag.dropLast()), for: genuine))
        // The tag of one secret is not the tag of another (cross-enrollment replay).
        XCTAssertFalse(ApprovalEnrollmentSecret().verifyBindingTag(tag, for: genuine))
    }

    func testTheSecretRoundTripsStrictly() {
        let es = ApprovalEnrollmentSecret()
        XCTAssertEqual(ApprovalEnrollmentSecret(base64URL: es.base64URL), es)
        XCTAssertNil(ApprovalEnrollmentSecret(base64URL: String(es.base64URL.dropLast())))
        XCTAssertNil(ApprovalEnrollmentSecret(base64URL: es.base64URL + "A"))
        XCTAssertNil(ApprovalEnrollmentSecret(base64URL: String(repeating: "A", count: 42) + "B"), "non-canonical trailing bits")
        XCTAssertNil(ApprovalEnrollmentSecret(base64URL: String(es.base64URL.dropLast()) + "+"))
        XCTAssertNotEqual(ApprovalEnrollmentSecret(), ApprovalEnrollmentSecret())
    }

    func testTheSASNeedsTheCheckCodeTheRelayNeverSees() async throws {
        let es = ApprovalEnrollmentSecret()
        let genuine = try await statement()
        // The device computes the SAS from the check code the person typed; the business from `es`: same value.
        let onDevice = try XCTUnwrap(ApprovalEnrollmentSAS.compute(checkCode: ApprovalEnrollmentCode.display(es.checkCode), statement: genuine))
        XCTAssertEqual(onDevice.count, 6)
        XCTAssertTrue(es.verifySAS(onDevice, for: genuine))
        XCTAssertTrue(es.verifySAS(ApprovalEnrollmentSAS.display(onDevice), for: genuine))
        // A relay-forged statement has another SAS; the relay cannot compute the right one without the check code.
        let forged = try await statement()
        XCTAssertFalse(es.verifySAS(onDevice, for: forged))
        let guessed = try XCTUnwrap(ApprovalEnrollmentSAS.compute(checkCode: "ABCDEFGH", statement: forged))
        XCTAssertFalse(es.verifySAS(guessed, for: forged))
        XCTAssertFalse(es.verifySAS("12345", for: genuine))
        XCTAssertFalse(es.verifySAS("12345a", for: genuine))
        XCTAssertNil(ApprovalEnrollmentSAS.compute(checkCode: "short", statement: genuine))
        XCTAssertEqual(ApprovalEnrollmentCode.canonical(es.checkCode), es.checkCode)
    }

    func testTheLinkCarriesTheSecretInTheFragmentAndParsesStrictly() throws {
        let es = ApprovalEnrollmentSecret()
        let kid = KeyIdentifier.make(try SoftwareP256SigningKey().publicKey.signingKey())
        let link = ApprovalEnrollmentCode.deepLink(code: "ABCDEFGH", rootKid: kid, secret: es)
        XCTAssertEqual(link, "https://\(ViadereCore.domain)/a/ABCDEFGH?rk=\(kid)#es=\(es.base64URL)")
        let url = try XCTUnwrap(URL(string: link))
        XCTAssertEqual(url.query, "rk=\(kid)", "the secret is not in the query, which would reach a server")
        let parsed = try XCTUnwrap(ApprovalEnrollmentCode.parse(link: url))
        XCTAssertEqual(parsed.code, "ABCDEFGH")
        XCTAssertEqual(parsed.rootKid, kid)
        XCTAssertEqual(parsed.secret, es)
        // Without a secret (typed or older links) it still parses, with `nil`.
        XCTAssertNil(ApprovalEnrollmentCode.parse(link: try XCTUnwrap(URL(string: "https://\(ViadereCore.domain)/a/ABCDEFGH")))?.secret)
        // Anything else in the fragment, or a malformed secret, is refused.
        for bad in ["#", "#es=", "#es=short", "#x=\(es.base64URL)", "#es=\(es.base64URL)&x=1", "#\(es.base64URL)"] {
            XCTAssertNil(ApprovalEnrollmentCode.parse(link: try XCTUnwrap(URL(string: "https://\(ViadereCore.domain)/a/ABCDEFGH?rk=\(kid)\(bad)"))), bad)
        }
        // A secret in the query is not a secret.
        XCTAssertNil(ApprovalEnrollmentCode.parse(link: try XCTUnwrap(URL(string: "https://\(ViadereCore.domain)/a/ABCDEFGH?es=\(es.base64URL)"))))
    }
}
