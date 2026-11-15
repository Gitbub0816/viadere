@preconcurrency import Crypto
import Foundation
import SwiftASN1
import ViadereCore
import ViadereServiceSupport
@_spi(FixedExpiryValidationTime) @preconcurrency import X509

// `AppleAppAttestRoot`, `AppAttestFailure` and the attestation checks live in `ViadereServiceSupport` (`AppAttestAttestation`), shared with the
// private authority's key-log genesis (ADR-0032 §1.3), so the two tiers verify attestations with one implementation.
typealias AppleAppAttestRoot = ViadereServiceSupport.AppleAppAttestRoot
typealias AppAttestFailure = ViadereServiceSupport.AppAttestFailure

/// Verifies Apple App Attest attestations and assertions **on the server**, as Apple documents
/// (<https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server>).
///
/// Attestation object: CBOR `{fmt: "apple-appattest", attStmt: {x5c: [credCert, intermediate…], receipt}, authData}`.
/// 1. `x5c` validates (RFC 5280, at the current time) to the trusted root (`AppleAppAttestRoot`).
/// 2. `nonce = SHA-256(authData ‖ clientDataHash)` equals the credential certificate's extension `1.2.840.113635.100.8.2`.
/// 3. `SHA-256(credCert public key, X9.63)` equals the key identifier the client sent.
/// 4. `authData`: `rpIdHash = SHA-256("{teamID}.{bundleID}")`, `counter == 0`, `aaguid` is `appattestdevelop` (development) or
///    `appattest` + 7 zero bytes (production) for the configured environment, and `credentialId` equals the key identifier.
/// The receipt is not used (it is for Apple's fraud-metric service, not needed to trust the key).
///
/// `clientDataHash` is `AppAttestBinding.clientDataHash(...)`: it names the enrollment challenge, the account and the SHA-256 of the
/// canonical key list, so one attestation cannot vouch for different keys or another enrollment.
public struct AppAttestVerifier: DeviceIntegrityVerifier {
    let teamID: String
    let appBundleID: String
    let clipBundleID: String
    let environment: AppAttestEnvironment
    let roots: [Certificate]
    let clock: any ServerClock
    /// Android evidence goes here (the stub unless Play Integrity is configured, SECURITY.md §2.114).
    public let android: AndroidKeyAttestationVerifier

    /// `trustedRoots` is a test seam: production code builds the verifier with `AppAttestVerifier.apple(...)`, whose only root is Apple's.
    init(teamID: String, appBundleID: String, clipBundleID: String, environment: AppAttestEnvironment, trustedRoots: [Certificate],
         clock: any ServerClock, android: AndroidKeyAttestationVerifier = AndroidKeyAttestationVerifier()) {
        self.android = android
        self.teamID = teamID
        self.appBundleID = appBundleID
        self.clipBundleID = clipBundleID
        self.environment = environment
        roots = trustedRoots
        self.clock = clock
    }

    /// The production verifier: trusts only Apple's App Attestation Root CA (fingerprint-checked).
    static func apple(config: ServerConfig, clock: any ServerClock) throws -> AppAttestVerifier {
        AppAttestVerifier(teamID: config.appleTeamID, appBundleID: config.appBundleID, clipBundleID: config.appClipBundleID,
                          environment: config.appAttestEnvironment, trustedRoots: [try AppleAppAttestRoot.certificate()], clock: clock,
                          android: AndroidKeyAttestationVerifier.configured(config, clock: clock))
    }

    static let nonceExtensionOID: ASN1ObjectIdentifier = AppAttestAttestation.nonceExtensionOID
    static let notBeforeLeeway = AppAttestAttestation.notBeforeLeeway

    func rpIdHash(clientKind: DeviceClientKind) -> Data {
        let bundle = clientKind == .appClip ? clipBundleID : appBundleID
        return Data(SHA256.hash(data: Data("\(teamID).\(bundle)".utf8)))
    }

    // MARK: DeviceIntegrityVerifier

    public func verifyEnrollment(_ evidence: AppAttestEvidence?, consumerId: ConsumerID, challenge: String, keys: [DeviceKeyRegistration],
                                 clientKind: DeviceClientKind) async -> AttestationResult {
        guard let evidence else { return AttestationResult(attested: false, reason: AppAttestFailure.notProvided.rawValue) }
        guard evidence.keyId.count <= 128, evidence.attestation.count <= 48 * 1024,
              let keyId = Self.decodeBase64(evidence.keyId), keyId.count == 32,
              let object = Self.decodeBase64(evidence.attestation) else {
            return AttestationResult(attested: false, reason: AppAttestFailure.malformedObject.rawValue)
        }
        let clientDataHash = AppAttestBinding.clientDataHash(consumerId: consumerId, challenge: challenge, keys: keys)
        do {
            let attested = try await verifyAttestation(object: object, keyId: keyId, clientDataHash: clientDataHash, clientKind: clientKind)
            return AttestationResult(attested: true, reason: "verified", keyId: Hex.encode(keyId), publicKey: Base64URL.encode(attested.publicKeyX963),
                                     counter: 0, environment: environment.rawValue)
        } catch let failure as AppAttestFailure {
            return AttestationResult(attested: false, reason: failure.rawValue)
        } catch {
            return AttestationResult(attested: false, reason: AppAttestFailure.malformedObject.rawValue)
        }
    }

    public func assessSensitiveRequest(deviceId: DeviceID, purpose: String) async -> IntegrityVerdict { .unverified }

    // MARK: Attestation

    struct Attested: Equatable {
        var publicKeyX963: Data
    }

    func verifyAttestation(object: Data, keyId: Data, clientDataHash: Data, clientKind: DeviceClientKind) async throws -> Attested {
        let x963 = try await AppAttestAttestation(trustedRoots: roots, aaguid: environment.aaguid)
            .verify(object: object, keyId: keyId, clientDataHash: clientDataHash, rpIdHash: rpIdHash(clientKind: clientKind), now: clock.now())
        return Attested(publicKeyX963: x963)
    }

    /// The extension value is `SEQUENCE { [1] EXPLICIT { OCTET STRING nonce } }`.
    static func parseNonce(_ value: [UInt8]) -> [UInt8]? { AppAttestAttestation.parseNonce(value) }

    // MARK: Assertion

    /// Verifies an assertion made with a previously attested key and returns its counter, which must be **strictly greater** than
    /// `storedCounter`. `assertion` is the CBOR `{signature, authenticatorData}` object `generateAssertion` returned; `clientData` is
    /// the exact bytes the app hashed for it. The caller must persist the new counter with a compare-and-swap on `storedCounter`.
    public func verifyAssertion(_ assertion: Data, clientData: Data, publicKeyX963: Data, storedCounter: Int,
                                clientKind: DeviceClientKind) throws -> Int {
        guard let object = try? CBOR.decode(assertion), let signature = object["signature"]?.byteString,
              let authData = object["authenticatorData"]?.byteString, authData.count == 37 else { throw AppAttestFailure.malformedObject }
        let bytes = Array(authData)
        guard ConstantTime.equals(Data(bytes[0..<32]), rpIdHash(clientKind: clientKind)) else { throw AppAttestFailure.badRpId }
        let counter = Int(bytes[33]) << 24 | Int(bytes[34]) << 16 | Int(bytes[35]) << 8 | Int(bytes[36])
        guard counter > storedCounter else { throw AppAttestFailure.badCounter }
        let nonce = Data(SHA256.hash(data: authData + Data(SHA256.hash(data: clientData))))
        guard let key = try? P256.Signing.PublicKey(x963Representation: publicKeyX963),
              let parsed = try? P256.Signing.ECDSASignature(derRepresentation: signature),
              key.isValidSignature(parsed, for: nonce) else { throw AppAttestFailure.badSignature }
        return counter
    }

    // MARK: Helpers

    /// Standard or URL-safe base64, with or without padding.
    static func decodeBase64(_ string: String) -> Data? { AppAttestAttestation.decodeBase64(string) }
}

extension ServerConfig {
    /// `APP_ATTEST_MODE` (`off`, `report`, `require`; default `require` in production and staging, otherwise `off`; `off` refuses to boot in
    /// production and staging) and
    /// `APP_ATTEST_ENVIRONMENT` (`development` or `production`; default `production` in production, otherwise `development`).
    mutating func applyIdentityEnvironment(_ env: [String: String], production: Bool) throws {
        if let raw = env["APP_ATTEST_MODE"], !raw.isEmpty {
            guard let mode = AppAttestMode(rawValue: raw.lowercased()) else { throw ServerConfigError.invalid("APP_ATTEST_MODE (off, report or require)") }
            // `off` does not evaluate integrity, so integrity stops being a D1 condition (§2.5a): development and tests only.
            guard !(production && mode == .off) else { throw ServerConfigError.invalid("APP_ATTEST_MODE (off is not allowed in staging or production)") }
            appAttestMode = mode
        } else {
            appAttestMode = production ? .require : .off
        }
        if let raw = env["APP_ATTEST_ENVIRONMENT"], !raw.isEmpty {
            guard let value = AppAttestEnvironment(rawValue: raw.lowercased()) else {
                throw ServerConfigError.invalid("APP_ATTEST_ENVIRONMENT (development or production)")
            }
            appAttestEnvironment = value
        } else {
            appAttestEnvironment = environment == .production ? .production : .development
        }
    }
}
