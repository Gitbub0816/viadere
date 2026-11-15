@preconcurrency import Crypto
import Fluent
import Foundation
import SwiftASN1
import Vapor
import ViadereCore
import ViadereServiceSupport
import XCTest
@preconcurrency import X509
@testable import ViadereAuthorityKit

/// A synthetic App Attest PKI (root, intermediate, per-attestation credential certificate). Production trusts only Apple's root; the tests inject this
/// one through `AuthorityOverrides.appAttest`, which a strict deployment refuses.
struct AuthorityTestAppAttestPKI: Sendable {
    let rootKey = P256.Signing.PrivateKey()
    let intermediateKey = P256.Signing.PrivateKey()
    let root: Certificate
    let intermediate: Certificate
    let rootName = try! DistinguishedName { CommonName("Test App Attestation Root CA") }
    let intermediateName = try! DistinguishedName { CommonName("Test App Attestation CA 1") }

    init(now: Date = Date(timeIntervalSince1970: 1_800_000_000)) {
        root = try! Certificate(version: .v3, serialNumber: .init(), publicKey: .init(rootKey.publicKey), notValidBefore: now.addingTimeInterval(-86_400 * 400),
                                notValidAfter: now.addingTimeInterval(86_400 * 4000), issuer: rootName, subject: rootName, signatureAlgorithm: .ecdsaWithSHA256,
                                extensions: try! Certificate.Extensions { Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil)) },
                                issuerPrivateKey: .init(rootKey))
        intermediate = try! Certificate(version: .v3, serialNumber: .init(), publicKey: .init(intermediateKey.publicKey), notValidBefore: now.addingTimeInterval(-86_400 * 300),
                                        notValidAfter: now.addingTimeInterval(86_400 * 3000), issuer: rootName, subject: intermediateName,
                                        signatureAlgorithm: .ecdsaWithSHA256,
                                        extensions: try! Certificate.Extensions { Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0)) },
                                        issuerPrivateKey: .init(rootKey))
    }

    var verifier: AppAttestAttestation { AppAttestAttestation(trustedRoots: [root], aaguid: AppAttestAttestation.developmentAAGUID) }

    /// `integrity: {key_id, attestation}` for `clientDataHash`, made by an App Attest key of its own (`key`), with optional flaws.
    func integrity(clientDataHash: Data, key: P256.Signing.PrivateKey = P256.Signing.PrivateKey(), teamID: String = "TEAMIDDEV0",
                   aaguid: Data = AppAttestAttestation.developmentAAGUID, now: Date = Date(timeIntervalSince1970: 1_800_000_000)) throws -> JSONValue {
        let x963 = key.publicKey.x963Representation
        let keyId = Data(SHA256.hash(data: x963))
        var authData = AppAttestAttestation.rpIdHash(teamID: teamID, bundleID: "com.viadere.app")
        authData.append(0x40)
        authData.append(contentsOf: [0, 0, 0, 0])
        authData.append(aaguid)
        authData.append(contentsOf: [0, UInt8(keyId.count)])
        authData.append(keyId)
        let nonce = Data(SHA256.hash(data: authData + clientDataHash))
        var inner: [UInt8] = [0x04, UInt8(nonce.count)]
        inner.append(contentsOf: nonce)
        var tagged: [UInt8] = [0xA1, UInt8(inner.count)]
        tagged.append(contentsOf: inner)
        var extensionValue: [UInt8] = [0x30, UInt8(tagged.count)]
        extensionValue.append(contentsOf: tagged)
        var extensions = try Certificate.Extensions { Critical(BasicConstraints.notCertificateAuthority) }
        try extensions.append(Certificate.Extension(oid: AppAttestAttestation.nonceExtensionOID, critical: false, value: ArraySlice(extensionValue)))
        let leaf = try Certificate(version: .v3, serialNumber: .init(), publicKey: .init(key.publicKey), notValidBefore: now.addingTimeInterval(-60),
                                   notValidAfter: now.addingTimeInterval(86_400 * 3), issuer: intermediateName,
                                   subject: try DistinguishedName { CommonName(String(repeating: "0", count: 64)) }, signatureAlgorithm: .ecdsaWithSHA256,
                                   extensions: extensions, issuerPrivateKey: .init(intermediateKey))
        func der(_ certificate: Certificate) throws -> Data {
            var serializer = DER.Serializer()
            try serializer.serialize(certificate)
            return Data(serializer.serializedBytes)
        }
        let object = CBOR.encode(.map([
            .init(key: .text("fmt"), value: .text("apple-appattest")),
            .init(key: .text("attStmt"), value: .map([.init(key: .text("x5c"), value: .array([.bytes(try der(leaf)), .bytes(try der(intermediate))])),
                                                      .init(key: .text("receipt"), value: .bytes(Data("receipt".utf8)))])),
            .init(key: .text("authData"), value: .bytes(authData)),
        ]))
        return .object(["key_id": .string(Base64URL.encode(keyId)), "attestation": .string(Base64URL.encode(object))])
    }
}

/// App Attest at key-log genesis (ADR-0023 §4, ADR-0032 §1.3): the authority verifies an attestation bound to its own nonce and the entry's keys.
final class AuthorityGenesisAttestationTests: XCTestCase {
    let pki = AuthorityTestAppAttestPKI()

    func harness(_ mode: AuthorityAppAttestMode) async throws -> AuthorityHarness {
        var options = AuthorityHarness.Options()
        options.appAttest = pki.verifier
        return try await AuthorityHarness.makeWith(options) { $0.appAttestMode = mode }
    }

    func genesis(_ h: AuthorityHarness, keys: [(SoftwareP256SigningKey, DeviceKeyPurpose)], integrity: ((String, [String]) throws -> JSONValue?)?) async throws
        -> (status: HTTPStatus, body: [String: JSONValue]) {
        let nonce = try await h.nonce("genesis")
        var body: [String: JSONValue] = ["nonce_id": .string(nonce.id), "keys": try await h.submitted(keys, type: "genesis", nonce: nonce.value)]
        if let integrity, let value = try integrity(nonce.value, keys.map { AuthorityHarness.kid($0.0) }) { body["integrity"] = value }
        return try await h.post(AuthorityKeyLogRoute.genesis, body)
    }

    func hash(_ nonce: String, _ kids: [String]) -> Data {
        AuthorityKeyLogFormat.genesisAttestationClientDataHash(environment: .staging, nonce: nonce, kids: kids)
    }

    /// The exploit path: with attestation required, a genesis by anything but a genuine app instance (no attestation, one bound to another nonce, to
    /// other keys, to another app, or an App Attest key already used) mints no account.
    func testRequireRefusesEveryGenesisWithoutAFreshBoundAttestation() async throws {
        let h = try await harness(.require)
        addTeardownBlock { try? await h.shutdown() }
        let device = [(SoftwareP256SigningKey(), DeviceKeyPurpose.approvalBiometric), (SoftwareP256SigningKey(), DeviceKeyPurpose.approvalUserPresence)]
        let before = try await AuthorityAccount.query(on: h.app.db).count()
        let refused: [((String, [String]) throws -> JSONValue?)?] = [
            nil,
            { _, kids in try self.pki.integrity(clientDataHash: self.hash(AuthorityNonce.generate(), kids)) },
            { nonce, kids in try self.pki.integrity(clientDataHash: self.hash(nonce, Array(kids.dropLast()))) },
            { nonce, kids in try self.pki.integrity(clientDataHash: self.hash(nonce, kids), teamID: "OTHERTEAM1") },
            { nonce, kids in try self.pki.integrity(clientDataHash: self.hash(nonce, kids), aaguid: AppAttestAttestation.productionAAGUID) },
            { nonce, kids in try AuthorityTestAppAttestPKI().integrity(clientDataHash: self.hash(nonce, kids)) },
            { _, _ in .object(["key_id": .string("AAAA"), "attestation": .string("AAAA")]) },
        ]
        for integrity in refused {
            let result = try await genesis(h, keys: device, integrity: integrity)
            XCTAssertEqual(result.status, .forbidden, "\(result.body)")
        }
        await XCTAssertEqualAsync(try await AuthorityAccount.query(on: h.app.db).count(), before)
        let reasons = Set(try await AuthorityAuditEvent.query(on: h.app.db).filter(\.$event == "authority.genesis").filter(\.$outcome == "denied").all().compactMap(\.reason))
        XCTAssertTrue(reasons.isSuperset(of: ["attestation_not_provided", "attestation_bad_nonce", "attestation_bad_rp_id", "attestation_bad_aaguid",
                                              "attestation_bad_chain", "attestation_malformed_object"]), "\(reasons)")

        // A genuine attestation: the account exists, its genesis keys are recorded as attested and the log says so.
        let appAttestKey = P256.Signing.PrivateKey()
        let accepted = try await genesis(h, keys: device) { nonce, kids in try self.pki.integrity(clientDataHash: self.hash(nonce, kids), key: appAttestKey) }
        XCTAssertEqual(accepted.status, .ok, "\(accepted.body)")
        for (key, _) in device { await XCTAssertEqualAsync(try await AuthorityKey.find(AuthorityHarness.kid(key), on: h.app.db)?.hardwareAttested, true) }
        let ref = try XCTUnwrap(accepted.body["account_ref"]?.stringValue)
        let entries = try await AuthorityKeylogEntry.query(on: h.app.db).filter(\.$accountRef == ref).all()
        XCTAssertTrue(entries.allSatisfy { $0.detail.contains("\"attestation\":\"apple_app_attest\"") })
        await XCTAssertEqualAsync(try await AuthorityAppAttestKey.query(on: h.app.db).filter(\.$accountRef == ref).count(), 1)

        // The same App Attest key cannot vouch for a second account, even with a fresh, correctly bound attestation.
        let second = [(SoftwareP256SigningKey(), DeviceKeyPurpose.approvalBiometric)]
        let reused = try await genesis(h, keys: second) { nonce, kids in try self.pki.integrity(clientDataHash: self.hash(nonce, kids), key: appAttestKey) }
        XCTAssertEqual(reused.status, .forbidden)
        let after = Set(try await AuthorityAuditEvent.query(on: h.app.db).filter(\.$event == "authority.genesis").filter(\.$outcome == "denied").all().compactMap(\.reason))
        XCTAssertTrue(after.contains("attestation_key_reused"))
    }

    /// `report`: an unattested genesis is accepted, recorded as unattested and audited; a verified one is recorded as attested.
    func testReportAcceptsUnattestedGenesisAndRecordsIt() async throws {
        let h = try await harness(.report)
        addTeardownBlock { try? await h.shutdown() }
        let key = SoftwareP256SigningKey()
        let plain = try await genesis(h, keys: [(key, .approvalBiometric)], integrity: nil)
        XCTAssertEqual(plain.status, .ok)
        await XCTAssertEqualAsync(try await AuthorityKey.find(AuthorityHarness.kid(key), on: h.app.db)?.hardwareAttested, false)
        let ref = try XCTUnwrap(plain.body["account_ref"]?.stringValue)
        let audit = try await AuthorityAuditEvent.query(on: h.app.db).filter(\.$event == "authority.genesis").filter(\.$accountRef == ref).first()
        XCTAssertEqual(audit?.reason, "unattested_not_provided")
        let attestedKey = SoftwareP256SigningKey()
        let attested = try await genesis(h, keys: [(attestedKey, .approvalBiometric)]) { nonce, kids in try self.pki.integrity(clientDataHash: self.hash(nonce, kids)) }
        XCTAssertEqual(attested.status, .ok)
        await XCTAssertEqualAsync(try await AuthorityKey.find(AuthorityHarness.kid(attestedKey), on: h.app.db)?.hardwareAttested, true)
        // A malformed `integrity` member in report mode: accepted as unattested (require refuses it, above).
        let odd = try await genesis(h, keys: [(SoftwareP256SigningKey(), .approvalBiometric)]) { _, _ in .object(["key_id": .string("AA==")]) }
        XCTAssertEqual(odd.status, .ok)
    }

    func testStrictDeploymentsRequireAttestationAndTheTeamAndRefuseARootOverride() throws {
        var env = AuthorityControlTests.strictEnv
        XCTAssertEqual(try AuthorityConfig.fromEnvironment(env).appAttestMode, .require)
        env["AUTHORITY_APP_ATTEST_MODE"] = "off"
        XCTAssertThrowsError(try AuthorityConfig.fromEnvironment(env))
        env["AUTHORITY_APP_ATTEST_MODE"] = "report"
        XCTAssertEqual(try AuthorityConfig.fromEnvironment(env).appAttestMode, .report)
        env["AUTHORITY_KEYLOG_ENABLED"] = "true"
        XCTAssertThrowsError(try AuthorityConfig.fromEnvironment(env)) { XCTAssertTrue("\($0)".contains("APPLE_TEAM_ID")) }
        env["APPLE_TEAM_ID"] = "ABCDE12345"
        XCTAssertEqual(try AuthorityConfig.fromEnvironment(env).appleTeamID, "ABCDE12345")
        env["ENVIRONMENT"] = "production"
        env["APP_ATTEST_ENVIRONMENT"] = "development"
        XCTAssertThrowsError(try AuthorityConfig.fromEnvironment(env))
        let strict = AuthorityConfig(deployment: .staging)
        XCTAssertThrowsError(try GenesisAttestation.verifier(config: strict, override: pki.verifier))
        // Without an override the only root is Apple's (fingerprint-checked).
        XCTAssertEqual(try GenesisAttestation.verifier(config: strict, override: nil).roots, [try AppleAppAttestRoot.certificate()])
    }
}
