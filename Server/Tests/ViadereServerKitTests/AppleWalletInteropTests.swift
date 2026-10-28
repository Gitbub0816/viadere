@preconcurrency import Crypto
import Foundation
import ViadereCore
@preconcurrency import X509
import XCTest
@testable import ViadereServerKit

/// Interop with Apple's published sample (`identity_verification_sample.zip`, `sample_mdl/`): a real HPKE envelope produced by Apple's
/// implementation, encrypted to Apple's test merchant key, carrying a test mobile driver's license with valid issuer and device
/// signatures from a test issuer. This is the check that our reading of the envelope, the session transcript, the HPKE suite and the
/// COSE structures matches Apple's, not just our own.
final class AppleWalletInteropTests: XCTestCase {
    static let directory = URL(fileURLWithPath: #filePath).deletingLastPathComponent().appendingPathComponent("Fixtures/AppleWalletSample")
    /// Inside the sample's mobile security object validity (2022-03-31 to 2023-03-22).
    let verifyAt = Date(timeIntervalSince1970: 1_654_041_600) // 2022-06-01T00:00:00Z

    func text(_ name: String) throws -> String { try String(contentsOf: Self.directory.appendingPathComponent(name), encoding: .utf8).trimmingCharacters(in: .whitespacesAndNewlines) }

    func hex(_ name: String) throws -> Data { try XCTUnwrap(Hex.decode(try text(name))) }

    struct Parameters {
        var nonce: Data
        var merchant: String
        var team: String
        var keyHash: Data
    }

    func parameters() throws -> Parameters {
        var values: [String: String] = [:]
        for line in try text("session_transcript_parameters.txt").split(separator: "\n") {
            let parts = line.split(separator: ":", maxSplits: 1).map { $0.trimmingCharacters(in: .whitespaces) }
            if parts.count == 2 { values[parts[0]] = parts[1] }
        }
        return Parameters(nonce: try XCTUnwrap(Hex.decode(try XCTUnwrap(values["Nonce"]))), merchant: try XCTUnwrap(values["Merchant ID"]), team: try XCTUnwrap(values["Team ID"]),
                          keyHash: try XCTUnwrap(Hex.decode(try XCTUnwrap(values["Encryption Key Hash"]))))
    }

    func privateKey() throws -> P256.KeyAgreement.PrivateKey {
        try P256.KeyAgreement.PrivateKey(pemRepresentation: try text("merchant_encryption.key"))
    }

    func testOurTranscriptAndHashesMatchApplesSample() throws {
        let p = try parameters()
        let key = try privateKey()
        // pkRHash is the SHA-256 of the uncompressed public key, as Apple's README says.
        XCTAssertEqual(Data(SHA256.hash(data: key.publicKey.x963Representation)), p.keyHash)
        let transcript = AppleIdentityEnvelope.sessionTranscript(nonce: p.nonce, merchantIdentifier: p.merchant, teamIdentifier: p.team, recipientKeyHash: p.keyHash)
        XCTAssertEqual(transcript, try hex("session_transcript.txt"), "byte-for-byte the transcript Apple documents")
        XCTAssertEqual(Data(SHA256.hash(data: transcript)), try hex("info_hash.txt"))
    }

    func testApplesEnvelopeDecryptsAndVerifiesEndToEnd() async throws {
        let p = try parameters()
        let envelope = try AppleIdentityEnvelope(parsing: try hex("hpke_envelope.cbor"))
        XCTAssertEqual(envelope.recipientKeyHash, p.keyHash)
        XCTAssertEqual(envelope.infoHash, try hex("info_hash.txt"))
        let opened = try envelope.open(keys: [try privateKey()], nonce: p.nonce, merchantIdentifier: p.merchant, teamIdentifier: p.team)
        XCTAssertEqual(opened.sessionTranscript, try hex("session_transcript.txt"))

        // Trust only the sample's test issuer root.
        let rootPEM = try text("issuer_root.crt")
        let der = try XCTUnwrap(Data(base64Encoded: rootPEM.components(separatedBy: "\n").filter { !$0.hasPrefix("-----") }.joined()))
        let trust = IACATrustStore(entries: [try IACATrustStore.entry(der: der, now: verifyAt, pinned: nil)])
        let iso = WalletElementPlan.isoNamespace
        // Discover what the sample contains by asking for a broad, fixed set of ISO elements; the verifier digest-checks every item.
        let requested = Set(["family_name", "given_name", "birth_date", "issue_date", "expiry_date", "issuing_country", "issuing_authority", "document_number", "age_over_18",
                             "age_over_21", "age_in_years", "resident_address", "portrait"].map { MDocElement(namespace: iso, identifier: $0) })
        // Apple's sample is signed by a *test* issuer whose root carries no countryName. ISO 18013-5 Annex B requires the IACA and the
        // document signer to name the issuing country, and the verifier enforces that profile (verify gate F8), so the sample is refused
        // at that step. It is the last issuer check: the HPKE envelope, the transcript, the x5chain to the pinned root, the validity
        // period and the document-signer key usage all passed to get there. Real IACAs (e.g. US state roots, C=US) carry the country.
        do {
            _ = try await MDocVerifier(trust: trust).verify(plaintext: opened.plaintext, sessionTranscript: opened.sessionTranscript, requested: requested, now: verifyAt)
            XCTFail("an issuer chain without a country must be refused")
        } catch { XCTAssertEqual(error as? MDocFailure, .issuerCountryMismatch) }
        XCTAssertNil(IACATrustStore.country(of: try Certificate(pemEncoded: rootPEM)), "the sample root names no country")

        // The same response is refused before that step if the root is not trusted.
        do {
            _ = try await MDocVerifier(trust: IACATrustStore(entries: [])).verify(plaintext: opened.plaintext, sessionTranscript: opened.sessionTranscript, requested: requested, now: verifyAt)
            XCTFail("untrusted issuer must be refused")
        } catch { XCTAssertEqual(error as? MDocFailure, .untrustedIssuer) }
        // And the envelope itself does not open for another nonce.
        XCTAssertThrowsError(try envelope.open(keys: [try privateKey()], nonce: Data(repeating: 1, count: 64), merchantIdentifier: p.merchant, teamIdentifier: p.team))
    }
}
