@preconcurrency import Crypto
import Foundation
import ViadereCore
import XCTest
@preconcurrency import X509
@testable import ViadereServerKit

/// The Wallet verifier (ISO/IEC 18013-5 mdoc inside Apple's HPKE envelope) against synthetic credentials from our own IACA.
final class MDocVerifierTests: XCTestCase {
    let pki = TestMDocPKI()
    let merchantKey = P256.KeyAgreement.PrivateKey()
    let nonce = SecureToken.randomBytes(32)
    var now: Date { pki.now }
    var iso: String { WalletElementPlan.isoNamespace }

    func age21() -> Set<MDocElement> { WalletElementPlan.readableElements(for: .ageAtLeast(21)) }

    /// Seals `mdoc` as Wallet would, opens it as the server would, and verifies it.
    func run(_ mdoc: TestMDoc, requested: Set<MDocElement>? = nil, trust: IACATrustStore? = nil, nonce serverNonce: Data? = nil, seal: ((TestMDoc) throws -> Data)? = nil,
             keys: [P256.KeyAgreement.PrivateKey]? = nil, at: Date? = nil) async throws -> MDocVerification {
        let envelopeBytes = try seal?(mdoc) ?? TestWalletSealer.seal(mdoc, nonce: nonce, recipient: merchantKey.publicKey)
        let envelope = try AppleIdentityEnvelope(parsing: envelopeBytes)
        let opened = try envelope.open(keys: keys ?? [merchantKey], nonce: serverNonce ?? nonce, merchantIdentifier: TestWalletSealer.merchant, teamIdentifier: TestWalletSealer.teamID)
        return try await MDocVerifier(trust: trust ?? pki.trustStore()).verify(plaintext: opened.plaintext, sessionTranscript: opened.sessionTranscript,
                                                                               requested: requested ?? age21(), now: at ?? now)
    }

    func expectFailure(_ expected: MDocFailure, _ mdoc: TestMDoc, requested: Set<MDocElement>? = nil, trust: IACATrustStore? = nil, nonce: Data? = nil,
                       seal: ((TestMDoc) throws -> Data)? = nil, keys: [P256.KeyAgreement.PrivateKey]? = nil, at: Date? = nil,
                       file: StaticString = #filePath, line: UInt = #line) async {
        do {
            _ = try await run(mdoc, requested: requested, trust: trust, nonce: nonce, seal: seal, keys: keys, at: at)
            XCTFail("expected \(expected)", file: file, line: line)
        } catch let failure as MDocFailure {
            XCTAssertEqual(failure, expected, file: file, line: line)
        } catch {
            XCTFail("unexpected \(error)", file: file, line: line)
        }
    }

    func mdoc(_ elements: [String: [(String, CBORValue)]]? = nil, _ adjust: (inout TestMDoc.Flaws) -> Void = { _ in }) -> TestMDoc {
        var doc = TestMDoc(pki: pki, elements: elements ?? TestMDoc.ageOver(21, true))
        adjust(&doc.flaws)
        return doc
    }

    // MARK: Valid

    func testAValidPresentationYieldsOnlyTheRequestedElement() async throws {
        let doc = mdoc(TestMDoc.ageOver(21, true, extra: [("family_name", .text("Doe")), ("given_name", .text("Jane")), ("birth_date", .tagged(1004, .text("1990-02-03"))),
                                                          ("portrait", .bytes(Data(repeating: 9, count: 64)))]))
        // The app asked for age_over_21 only; the response carries more. Only the age_over element may come out.
        let verified = try await run(doc, requested: [MDocElement(namespace: iso, identifier: "age_over_21")])
        XCTAssertEqual(verified.elements.count, 1)
        XCTAssertEqual(verified.elements[MDocElement(namespace: iso, identifier: "age_over_21")], .bool(true))
        XCTAssertEqual(verified.docType, WalletElementPlan.docType)
        XCTAssertEqual(verified.issuerAnchor, String(pki.fingerprint.prefix(16)))
        XCTAssertTrue(verified.validUntil > now)
        // The whole structure of what the verifier returns holds none of the unrequested values.
        let dump = String(describing: verified)
        for secret in ["Doe", "Jane", "1990-02-03"] { XCTAssertFalse(dump.contains(secret), "\(secret) must not leave the verifier") }
    }

    func testAgeOverWithoutABirthdateAnswersTheThreshold() async throws {
        let verified = try await run(mdoc(TestMDoc.ageOver(21, true)))
        let claims = try XCTUnwrap(WalletClaims.claims(from: verified, plan: .ageAtLeast(21), now: now))
        XCTAssertNil(claims.birthDate)
        XCTAssertEqual(claims.ageOver, [21: true])
        XCTAssertEqual(ClaimsBuilder.meetsThreshold(claims, years: 21, now: now), true)
        XCTAssertEqual(ClaimsBuilder.meetsThreshold(claims, years: 18, now: now), true, "an issuer's age_over_21 answers 18")
        XCTAssertNil(ClaimsBuilder.meetsThreshold(claims, years: 25, now: now), "an issuer's age_over_21 alone cannot answer 25")
    }

    func testAgeOverFalseAnswersNoAndAgeInYearsIsAFallback() async throws {
        let no = try await run(mdoc(TestMDoc.ageOver(21, false)))
        XCTAssertEqual(ClaimsBuilder.meetsThreshold(try XCTUnwrap(WalletClaims.claims(from: no, plan: .ageAtLeast(21), now: now)), years: 21, now: now), false)
        let fallback = try await run(mdoc([iso: [("age_in_years", .unsigned(34))]]))
        let claims = try XCTUnwrap(WalletClaims.claims(from: fallback, plan: .ageAtLeast(21), now: now))
        XCTAssertEqual(ClaimsBuilder.meetsThreshold(claims, years: 21, now: now), true)
        XCTAssertEqual(ClaimsBuilder.meetsThreshold(claims, years: 40, now: now), nil)
        // birth_date answers in memory, in either encoding.
        let dob = try await run(mdoc([iso: [("birth_date", .tagged(1004, .text("2010-05-05")))]]))
        let dobClaims = try XCTUnwrap(WalletClaims.claims(from: dob, plan: .ageAtLeast(18), now: now))
        XCTAssertEqual(ClaimsBuilder.meetsThreshold(dobClaims, years: 18, now: now), false)
    }

    func testIdentityElementsAreExtractedPerPlan() async throws {
        let doc = mdoc([iso: [("given_name", .text("Jane")), ("family_name", .text("Doe")), ("resident_city", .text("Mesa")), ("resident_address", .text("1 Main St")),
                              ("issuing_authority", .text("AZ MVD")), ("document_number", .text("D1234567"))]])
        let name = try await run(doc, requested: WalletElementPlan.readableElements(for: .givenAndFamilyName))
        let nameClaims = try XCTUnwrap(WalletClaims.claims(from: name, plan: .givenAndFamilyName, now: now))
        XCTAssertEqual([nameClaims.givenName, nameClaims.familyName], ["Jane", "Doe"])
        XCTAssertEqual(name.elements.count, 2, "the document number is never read")
        let address = try await run(doc, requested: WalletElementPlan.readableElements(for: .residentAddress))
        let addressClaims = try XCTUnwrap(WalletClaims.claims(from: address, plan: .residentAddress, now: now))
        XCTAssertEqual(addressClaims.address?["locality"], .string("Mesa"))
        XCTAssertEqual(addressClaims.address?["street"], .string("1 Main St"))
        let present = try await run(doc, requested: WalletElementPlan.readableElements(for: .documentPresented))
        XCTAssertTrue(try XCTUnwrap(WalletClaims.claims(from: present, plan: .documentPresented, now: now)).documentPresented)
        // A name request with only one of the two names is not a name.
        let partial = try await run(mdoc([iso: [("given_name", .text("Jane"))]]), requested: WalletElementPlan.readableElements(for: .givenAndFamilyName))
        XCTAssertNil(WalletClaims.claims(from: partial, plan: .givenAndFamilyName, now: now))
    }

    func testItemsInUnknownNamespacesAreDroppedUnread() async throws {
        let doc = mdoc([iso: [("age_over_21", .bool(true))], "com.example.private": [("secret", .text("never"))], WalletElementPlan.aamvaNamespace: [("DHS_compliance", .text("F"))]])
        let verified = try await run(doc, requested: [MDocElement(namespace: iso, identifier: "age_over_21"), MDocElement(namespace: "com.example.private", identifier: "secret")])
        XCTAssertEqual(verified.elements.keys.map(\.identifier), ["age_over_21"])
    }

    func testTheAAMVANamespaceIsReadableWhenRequested() async throws {
        let doc = mdoc([iso: [("age_over_21", .bool(true))], WalletElementPlan.aamvaNamespace: [("DHS_compliance", .text("F"))]])
        let aamva = MDocElement(namespace: WalletElementPlan.aamvaNamespace, identifier: "DHS_compliance")
        let verified = try await run(doc, requested: [aamva])
        XCTAssertEqual(verified.elements[aamva], .text("F"))
    }

    func testBothDocumentedEncodingsOfThePublicKeyHashAreAccepted() async throws {
        for encoding in [TestWalletSealer.HashEncoding.x963, .spki] {
            let verified = try await run(mdoc(), seal: { try TestWalletSealer.seal($0, nonce: self.nonce, recipient: self.merchantKey.publicKey, encoding: encoding) })
            XCTAssertEqual(verified.elements.count, 1)
        }
    }

    func testARotatedKeyStillOpensResponsesToTheOldOne() async throws {
        let newKey = P256.KeyAgreement.PrivateKey()
        let verified = try await run(mdoc(), keys: [newKey, merchantKey])
        XCTAssertEqual(verified.elements.count, 1)
    }

    // MARK: Issuer authentication

    func testATamperedElementFailsTheDigestCheck() async {
        await expectFailure(.digestMismatch, mdoc { $0.tamperElement = (self.iso, "age_over_21", .bool(false)) })
    }

    func testOnlySHA2DigestAlgorithmsAreAccepted() async throws {
        let sha384 = try await run(mdoc { $0.digestAlgorithm = "SHA-384" })
        XCTAssertEqual(sha384.elements.count, 1)
        await expectFailure(.badMobileSecurityObject, mdoc { $0.digestAlgorithm = "SHA-1" })
        await expectFailure(.badMobileSecurityObject, mdoc { $0.digestAlgorithm = "MD5" })
    }

    func testAnIssuerOutsideTheTrustStoreIsRefused() async {
        let stranger = TestMDocPKI(now: now, name: "Unknown State IACA")
        await expectFailure(.untrustedIssuer, mdoc { $0.otherPKI = stranger })
        await expectFailure(.untrustedIssuer, mdoc(), trust: IACATrustStore(entries: []))
    }

    func testTheIssuerCertificateMustBeInTheChainTheTrustStoreAnchors() async {
        // A trust store holding a *different* IACA (same name, other key) must not trust this issuer.
        let lookalike = TestMDocPKI(now: now, name: "Test State IACA")
        await expectFailure(.untrustedIssuer, mdoc(), trust: lookalike.trustStore())
    }

    func testAnExpiredDocumentSignerCertificateIsRefused() async {
        let expired = TestMDocPKI(now: now, options: .init(dsNotAfter: now.addingTimeInterval(-86_400)))
        await expectFailure(.untrustedIssuer, TestMDoc(pki: expired, elements: TestMDoc.ageOver(21, true)), trust: expired.trustStore())
    }

    func testTheMSOValidityWindowIsEnforced() async {
        await expectFailure(.outsideValidity, mdoc { $0.validUntil = self.now.addingTimeInterval(-60) })
        await expectFailure(.outsideValidity, mdoc { $0.validFrom = self.now.addingTimeInterval(3600); $0.signed = self.now.addingTimeInterval(-60) })
        await expectFailure(.outsideValidity, mdoc { $0.signed = self.now.addingTimeInterval(3600) })
        // A document signer certificate that did not cover the signing time.
        await expectFailure(.outsideValidity, mdoc { $0.signed = self.now.addingTimeInterval(-86_400 * 90) })
        // Verified one year later the same document is expired.
        await expectFailure(.outsideValidity, mdoc(), at: now.addingTimeInterval(86_400 * 45))
    }

    func testAnUnsupportedSignatureAlgorithmIsRefused() async {
        await expectFailure(.unsupportedAlgorithm, mdoc { $0.issuerAlgorithm = -8 })  // EdDSA
        await expectFailure(.unsupportedAlgorithm, mdoc { $0.issuerAlgorithm = -257 }) // RS256
        await expectFailure(.unsupportedAlgorithm, mdoc { $0.issuerAlgorithm = -35 })  // ES384 over a P-256 key
        await expectFailure(.unsupportedAlgorithm, mdoc { $0.algorithmInUnprotected = true })
    }

    func testAMissingCertificateChainIsRefused() async {
        await expectFailure(.noIssuerCertificate, mdoc { $0.omitX5Chain = true })
    }

    func testTheDocumentSignerNeedsTheMDLProfile() async {
        let noEKU = TestMDocPKI(now: now, options: .init(dsEKU: false))
        await expectFailure(.badIssuerCertificateUsage, TestMDoc(pki: noEKU, elements: TestMDoc.ageOver(21, true)), trust: noEKU.trustStore())
        let noSig = TestMDocPKI(now: now, options: .init(dsDigitalSignature: false))
        await expectFailure(.badIssuerCertificateUsage, TestMDoc(pki: noSig, elements: TestMDoc.ageOver(21, true)), trust: noSig.trustStore())
    }

    func testDocTypeMismatchesAreRefused() async {
        await expectFailure(.badMobileSecurityObject, mdoc { $0.msoDocType = "org.iso.23220.photoid.1" })
        var other = mdoc()
        other.docType = "eu.europa.ec.eudi.pid.1"
        await expectFailure(.unsupportedDocType, other)
    }

    func testDuplicateAndWeakItemsAreRefused() async {
        await expectFailure(.digestMismatch, mdoc { $0.duplicateFirstItem = true })
        await expectFailure(.digestMismatch, mdoc { $0.shortRandom = true; $0.tamperElement = (self.iso, "age_over_21", .bool(true)) })
    }

    func testAdocumentErrorListIsRefused() async {
        await expectFailure(.malformedResponse, mdoc { $0.documentErrors = true })
    }

    // MARK: Device authentication and the transcript

    func testADeviceSignatureOverAnotherTranscriptFails() async {
        let other = TestWalletSealer.transcript(nonce: Data(repeating: 1, count: 32), key: merchantKey.publicKey).transcript
        await expectFailure(.badDeviceSignature, mdoc { $0.deviceTranscript = other })
    }

    func testDeviceMacAndMissingDeviceAuthenticationAreRefused() async {
        await expectFailure(.missingDeviceAuthentication, mdoc { $0.useDeviceMac = true })
        await expectFailure(.missingDeviceAuthentication, mdoc { $0.omitDeviceSignature = true })
        await expectFailure(.unexpectedDeviceNamespaces, mdoc { $0.deviceNameSpacesNotEmpty = true })
    }

    func testAWrongNonceOrMerchantOrTeamCannotOpenTheEnvelope() async {
        await expectFailure(.transcriptMismatch, mdoc(), nonce: SecureToken.randomBytes(32))
        await expectFailure(.transcriptMismatch, mdoc(), seal: { try TestWalletSealer.seal($0, nonce: self.nonce, recipient: self.merchantKey.publicKey, merchant: "merchant.com.other") })
        await expectFailure(.transcriptMismatch, mdoc(), seal: { try TestWalletSealer.seal($0, nonce: self.nonce, recipient: self.merchantKey.publicKey, team: "OTHERTEAM1") })
    }

    func testAWrongRecipientKeyCannotOpenTheEnvelope() async {
        await expectFailure(.wrongRecipientKey, mdoc(), keys: [P256.KeyAgreement.PrivateKey()])
        await expectFailure(.wrongRecipientKey, mdoc(), seal: { try TestWalletSealer.seal($0, nonce: self.nonce, recipient: self.merchantKey.publicKey, encoding: .wrong) })
    }

    func testAnInfoHashThatDoesNotMatchTheTranscriptIsRefused() async {
        await expectFailure(.transcriptMismatch, mdoc(), seal: { try TestWalletSealer.seal($0, nonce: self.nonce, recipient: self.merchantKey.publicKey, infoOverride: Data("x".utf8)) })
    }

    func testATamperedCiphertextFailsDecryption() async throws {
        var bytes = try TestWalletSealer.seal(mdoc(), nonce: nonce, recipient: merchantKey.publicKey)
        bytes[bytes.count - 5] ^= 0x01
        let envelope = try AppleIdentityEnvelope(parsing: bytes)
        XCTAssertThrowsError(try envelope.open(keys: [merchantKey], nonce: nonce, merchantIdentifier: TestWalletSealer.merchant, teamIdentifier: TestWalletSealer.teamID)) {
            XCTAssertEqual($0 as? MDocFailure, .decryptionFailed)
        }
    }

    func testEnvelopeParsingIsStrict() throws {
        let key = merchantKey.publicKey
        let good = try TestWalletSealer.seal(mdoc(), nonce: nonce, recipient: key)
        XCTAssertNoThrow(try AppleIdentityEnvelope(parsing: good))
        for bad in [Data(), Data([0xA0]), good.dropLast(), good + Data([0]), try TestWalletSealer.seal(mdoc(), nonce: nonce, recipient: key, algorithm: "APPLE-HPKE-v2"),
                    try TestWalletSealer.seal(mdoc(), nonce: nonce, recipient: key, mode: 1)] {
            XCTAssertThrowsError(try AppleIdentityEnvelope(parsing: Data(bad)))
        }
        // An extra member is refused.
        let extra = CBOR.encode(.textMap([("algorithm", .text("APPLE-HPKE-v1")), ("params", .textMap([("mode", .unsigned(0)), ("pkEm", .bytes(Data([4]) + Data(repeating: 1, count: 64))),
                                                                                                    ("pkRHash", .bytes(Data(repeating: 1, count: 32))), ("infoHash", .bytes(Data(repeating: 1, count: 32)))])),
                                          ("data", .bytes(Data(repeating: 1, count: 40))), ("extra", .bool(true))]))
        XCTAssertThrowsError(try AppleIdentityEnvelope(parsing: extra))
    }

    func testTheTranscriptHasTheDocumentedShape() throws {
        let transcript = AppleIdentityEnvelope.sessionTranscript(nonce: Data([1, 2, 3]), merchantIdentifier: "merchant.x", teamIdentifier: "TEAM", recipientKeyHash: Data(repeating: 7, count: 32))
        let value = try CBOR.decode(transcript)
        let items = try XCTUnwrap(value.arrayValue)
        XCTAssertEqual(items.count, 3)
        XCTAssertEqual(items[0], .null)
        XCTAssertEqual(items[1], .null)
        let handover = try XCTUnwrap(items[2].arrayValue)
        XCTAssertEqual(handover, [.text("AppleIdentityPresentment_1.0"), .bytes(Data([1, 2, 3])), .text("merchant.x"), .text("TEAM"), .bytes(Data(repeating: 7, count: 32))])
    }

    // MARK: Trust store

    func testTheTrustStoreLoadsFromADirectoryAndPinsFingerprints() throws {
        let directory = NSTemporaryDirectory() + "iaca-\(UUID().uuidString)"
        try FileManager.default.createDirectory(atPath: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(atPath: directory) }
        let second = TestMDocPKI(now: now, name: "Second State IACA")
        let pem = try pki.iaca.serializeAsPEM().pemString
        try pem.write(toFile: directory + "/state-a.pem", atomically: true, encoding: .utf8)
        try second.iacaDER.write(to: URL(fileURLWithPath: directory + "/state-b.der"))
        try "not a certificate".write(toFile: directory + "/junk.pem", atomically: true, encoding: .utf8)
        try "ignored".write(toFile: directory + "/notes.txt", atomically: true, encoding: .utf8)
        let open = try IACATrustStore.load(directory: directory, now: now, pinned: nil)
        XCTAssertEqual(open.store.fingerprints, [pki.fingerprint, second.fingerprint])
        XCTAssertEqual(open.report.rejected["junk.pem"], "unparseable")
        // Pinned: only the listed fingerprint is trusted; the other file is rejected even though it is a valid IACA.
        let pinned = try IACATrustStore.load(directory: directory, now: now, pinned: [pki.fingerprint])
        XCTAssertEqual(pinned.store.fingerprints, [pki.fingerprint])
        XCTAssertEqual(pinned.report.rejected["state-b.der"], "not_pinned")
        XCTAssertThrowsError(try IACATrustStore.load(directory: directory + "/missing", now: now, pinned: nil))
    }

    func testTheTrustStoreRefusesBadRoots() throws {
        let notCA = TestMDocPKI(now: now, options: .init(iacaIsCA: false))
        XCTAssertThrowsError(try IACATrustStore.entry(der: notCA.iacaDER, now: now, pinned: nil)) { XCTAssertEqual($0 as? IACATrustStore.IACARejection, .notCA) }
        let noCertSign = TestMDocPKI(now: now, options: .init(iacaKeyCertSign: false))
        XCTAssertThrowsError(try IACATrustStore.entry(der: noCertSign.iacaDER, now: now, pinned: nil)) { XCTAssertEqual($0 as? IACATrustStore.IACARejection, .keyUsage) }
        let expired = TestMDocPKI(now: now, options: .init(iacaNotAfter: now.addingTimeInterval(-1)))
        XCTAssertThrowsError(try IACATrustStore.entry(der: expired.iacaDER, now: now, pinned: nil)) { XCTAssertEqual($0 as? IACATrustStore.IACARejection, .notValidNow) }
        // A document-signer certificate is not a root.
        XCTAssertThrowsError(try IACATrustStore.entry(der: pki.dsDER, now: now, pinned: nil)) { XCTAssertEqual($0 as? IACATrustStore.IACARejection, .notSelfSigned) }
        XCTAssertThrowsError(try IACATrustStore.entry(der: Data(repeating: 1, count: 20), now: now, pinned: nil))
    }
}
