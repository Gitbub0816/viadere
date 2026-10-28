@preconcurrency import Crypto
import Foundation
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Phase 3 gate F8 (issuer certificate profile) and the CBOR parser-differential hardening.
extension MDocVerifierTests {
    func pkiWith(_ adjust: (inout TestMDocPKI.Options) -> Void) -> TestMDocPKI {
        var options = TestMDocPKI.Options()
        adjust(&options)
        return TestMDocPKI(options: options)
    }

    func presentation(_ p: TestMDocPKI, _ elements: [String: [(String, CBORValue)]]? = nil) -> TestMDoc {
        TestMDoc(pki: p, elements: elements ?? TestMDoc.ageOver(21, true))
    }

    /// F8 exploit: a document signer issued through an intermediate CA validated (Annex B defines IACA -> DS only).
    func testADocumentSignerBehindAnIntermediateCAIsRefused() async {
        let p = pkiWith { $0.intermediate = true }
        await expectFailure(.issuerChainNotDirect, presentation(p), trust: p.trustStore())
    }

    func testADirectChainReportsItsIssuingCountry() async throws {
        let direct = try await run(presentation(pki))
        XCTAssertEqual(direct.issuerCountry, "US")
    }

    /// F8 exploit: the document signer certificate names another country than the IACA that issued it.
    func testTheDocumentSignerAndIACACountriesMustAgree() async {
        let p = pkiWith { $0.dsCountry = "CA" }
        await expectFailure(.issuerCountryMismatch, presentation(p), trust: p.trustStore())
        let noCountry = pkiWith { $0.dsCountry = "ZZ" }
        await expectFailure(.issuerCountryMismatch, presentation(noCountry), trust: noCountry.trustStore())
    }

    /// F8: the `issuing_country` element, when the response carries it, must be the certificates' country.
    func testTheIssuingCountryElementMustMatchTheCertificates() async throws {
        let wrong = TestMDoc.ageOver(21, true, extra: [("issuing_country", .text("CA"))])
        await expectFailure(.issuerCountryMismatch, presentation(pki, wrong))
        let right = try await run(presentation(pki, TestMDoc.ageOver(21, true, extra: [("issuing_country", .text("US"))])))
        XCTAssertEqual(right.issuerCountry, "US")
        XCTAssertNil(right.elements[MDocElement(namespace: iso, identifier: "issuing_country")], "read for the check, not released")
        let longForm = TestMDoc.ageOver(21, true, extra: [("issuing_country", .text("USA"))])
        await expectFailure(.issuerCountryMismatch, presentation(pki, longForm))
    }

    // MARK: CBOR parser differential

    func rawResponse(_ mdoc: TestMDoc) -> (response: Data, transcript: Data) {
        let transcript = TestWalletSealer.transcript(nonce: nonce, key: merchantKey.publicKey).transcript
        return (mdoc.deviceResponse(sessionTranscript: transcript), transcript)
    }

    func verifyRaw(_ raw: Data, _ transcript: Data) async throws {
        _ = try await MDocVerifier(trust: pki.trustStore()).verify(deviceResponse: raw, sessionTranscript: transcript, requested: age21(), now: now)
    }

    /// The untouched response verifies (control for the two tests below).
    func testTheRawResponseHelperProducesAVerifiableResponse() async throws {
        let (raw, transcript) = rawResponse(presentation(pki))
        try await verifyRaw(raw, transcript)
    }

    /// Info exploit: a non-shortest head on the response map (a second encoding of the same structure) was accepted.
    func testANonShortestFormHeadIsRefusedInStrictMode() async throws {
        let (raw, transcript) = rawResponse(presentation(pki))
        XCTAssertEqual(raw.first, 0xA3)
        var widened = Data([0xB8, 0x03])
        widened.append(raw.dropFirst())
        do { try await verifyRaw(widened, transcript); XCTFail("a non-shortest map head must be refused") }
        catch let failure as MDocFailure { XCTAssertEqual(failure, .malformedResponse) }
        // Shortest-form lengths for text keys: "version" with a one-byte length head instead of 0x67.
        let version = Data([0x67]) + Data("version".utf8)
        let range = try XCTUnwrap(raw.range(of: version))
        var longText = raw
        longText.replaceSubrange(range, with: Data([0x78, 0x07]) + Data("version".utf8))
        do { try await verifyRaw(longText, transcript); XCTFail("a non-shortest text head must be refused") }
        catch let failure as MDocFailure { XCTAssertEqual(failure, .malformedResponse) }
    }

    /// Info exploit: the same key twice, the second under another encoding, passed the raw-bytes duplicate check.
    func testADuplicateKeyBehindAnotherEncodingIsRefused() async throws {
        let (raw, transcript) = rawResponse(presentation(pki))
        // {"version": "1.0", "documents": ..., "status": 0} -> append a second "version" using a long text head and a different value.
        var duplicated = Data([0xA4]) + raw.dropFirst()
        duplicated.append(Data([0x78, 0x07]) + Data("version".utf8) + CBOR.encode(.text("9.9")))
        do { try await verifyRaw(duplicated, transcript); XCTFail("duplicate keys must be refused") }
        catch let failure as MDocFailure { XCTAssertEqual(failure, .malformedResponse) }
        // The slice reader agrees: it refuses the same structure instead of returning the last match.
        XCTAssertThrowsError(try RawCBOR.mapValue(duplicated, key: "version"))
        XCTAssertThrowsError(try CBOR.decode(duplicated, limits: RawCBOR.limits))
        XCTAssertEqual(try RawCBOR.mapValue(raw, key: "version"), CBOR.encode(.text("1.0")))
    }
}
