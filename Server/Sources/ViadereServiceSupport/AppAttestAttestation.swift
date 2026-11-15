@preconcurrency import Crypto
import Foundation
import SwiftASN1
import ViadereCore
@_spi(FixedExpiryValidationTime) @preconcurrency import X509

// Apple App Attest **attestation** checks, shared by the ordinary server (`ViadereServerKit.AppAttestVerifier`, device enrollment) and the private
// authority (key-log genesis, ADR-0032 §1.3). One implementation, so the two tiers cannot drift; each passes its own `clientDataHash` binding.

/// Apple's **App Attestation Root CA**, the only trust anchor for App Attest attestations in production.
///
/// Source: <https://www.apple.com/certificateauthority/Apple_App_Attestation_Root_CA.pem> (Apple PKI page, "Apple App Attestation
/// Root CA"), fetched and checked on 2026-10-27. ECDSA P-384, subject `CN=Apple App Attestation Root CA, O=Apple Inc., ST=California`,
/// valid 2020-03-18 to 2045-03-15. **SHA-256 fingerprint (DER):**
/// `1CB9823BA28BA6AD2D33A006941DE2AE4F513EF1D4E831B9F7E0FA7B6242C932`. `certificate()` checks the constant against it, so a corrupted or
/// swapped constant refuses to boot. Tests inject a synthetic root through `AppAttestAttestation(trustedRoots:)`; no environment variable or
/// configuration key can replace the root.
public enum AppleAppAttestRoot {
    static let pem = """
    -----BEGIN CERTIFICATE-----
    MIICITCCAaegAwIBAgIQC/O+DvHN0uD7jG5yH2IXmDAKBggqhkjOPQQDAzBSMSYw
    JAYDVQQDDB1BcHBsZSBBcHAgQXR0ZXN0YXRpb24gUm9vdCBDQTETMBEGA1UECgwK
    QXBwbGUgSW5jLjETMBEGA1UECAwKQ2FsaWZvcm5pYTAeFw0yMDAzMTgxODMyNTNa
    Fw00NTAzMTUwMDAwMDBaMFIxJjAkBgNVBAMMHUFwcGxlIEFwcCBBdHRlc3RhdGlv
    biBSb290IENBMRMwEQYDVQQKDApBcHBsZSBJbmMuMRMwEQYDVQQIDApDYWxpZm9y
    bmlhMHYwEAYHKoZIzj0CAQYFK4EEACIDYgAERTHhmLW07ATaFQIEVwTtT4dyctdh
    NbJhFs/Ii2FdCgAHGbpphY3+d8qjuDngIN3WVhQUBHAoMeQ/cLiP1sOUtgjqK9au
    Yen1mMEvRq9Sk3Jm5X8U62H+xTD3FE9TgS41o0IwQDAPBgNVHRMBAf8EBTADAQH/
    MB0GA1UdDgQWBBSskRBTM72+aEH/pwyp5frq5eWKoTAOBgNVHQ8BAf8EBAMCAQYw
    CgYIKoZIzj0EAwMDaAAwZQIwQgFGnByvsiVbpTKwSga0kP0e8EeDS4+sQmTvb7vn
    53O5+FRXgeLhpJ06ysC5PrOyAjEAp5U4xDgEgllF7En3VcE3iexZZtKeYnpqtijV
    oyFraWVIyd/dganmrduC1bmTBGwD
    -----END CERTIFICATE-----
    """

    public static let fingerprint = "1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932"

    public static func certificate() throws -> Certificate {
        let certificate = try Certificate(pemEncoded: pem)
        var serializer = DER.Serializer()
        try serializer.serialize(certificate)
        guard SecureToken.sha256Hex(serializer.serializedBytes) == fingerprint else { throw AppAttestFailure.rootFingerprintMismatch }
        return certificate
    }
}

/// Why an attestation or assertion was refused. The raw value is the audit `attestation` reason.
public enum AppAttestFailure: String, Error, Sendable {
    case notProvided = "not_provided"
    case malformedObject = "malformed_object"
    case badFormat = "bad_format"
    case badChain = "bad_chain"
    case badNonce = "bad_nonce"
    case badKeyId = "bad_key_id"
    case badRpId = "bad_rp_id"
    case badCounter = "bad_counter"
    case badAAGUID = "bad_aaguid"
    case badCredentialId = "bad_credential_id"
    case badSignature = "bad_signature"
    case rootFingerprintMismatch = "root_fingerprint_mismatch"
}

/// An App Attest attestation, verified **on the server** as Apple documents
/// (<https://developer.apple.com/documentation/devicecheck/validating-apps-that-connect-to-your-server>).
///
/// Attestation object: CBOR `{fmt: "apple-appattest", attStmt: {x5c: [credCert, intermediate…], receipt}, authData}`.
/// 1. `x5c` validates (RFC 5280, at the given time) to the trusted root (`AppleAppAttestRoot`).
/// 2. `nonce = SHA-256(authData ‖ clientDataHash)` equals the credential certificate's extension `1.2.840.113635.100.8.2`.
/// 3. `SHA-256(credCert public key, X9.63)` equals the key identifier the client sent.
/// 4. `authData`: `rpIdHash` is one of the allowed `SHA-256("{teamID}.{bundleID}")`, `counter == 0`, `aaguid` is the environment's
///    (`appattestdevelop` or `appattest` + 7 zero bytes), and `credentialId` equals the key identifier.
/// The receipt is not used (it is for Apple's fraud-metric service, not needed to trust the key).
public struct AppAttestAttestation: Sendable {
    public let roots: [Certificate]
    public let aaguid: Data

    public static let nonceExtensionOID: ASN1ObjectIdentifier = [1, 2, 840, 113635, 100, 8, 2]
    /// A credential certificate issued a moment "in the future" (clock skew between Apple and this server) is still accepted.
    public static let notBeforeLeeway: TimeInterval = 300
    public static let developmentAAGUID = Data("appattestdevelop".utf8)
    public static let productionAAGUID = Data("appattest".utf8) + Data(repeating: 0, count: 7)

    /// `trustedRoots` is a test seam: production code passes `[AppleAppAttestRoot.certificate()]` and nothing else.
    public init(trustedRoots: [Certificate], aaguid: Data) {
        roots = trustedRoots
        self.aaguid = aaguid
    }

    public static func rpIdHash(teamID: String, bundleID: String) -> Data { Data(SHA256.hash(data: Data("\(teamID).\(bundleID)".utf8))) }

    /// Standard or URL-safe base64, with or without padding (as `DCAppAttestService` callers send it).
    public static func decodeBase64(_ string: String) -> Data? {
        if let data = Base64URL.decode(string) { return data }
        var padded = string
        while padded.count % 4 != 0 { padded.append("=") }
        return Data(base64Encoded: padded)
    }

    /// Verifies `object` for `keyId` and `clientDataHash` at time `now`; returns the attested public key (X9.63).
    public func verify(object: Data, keyId: Data, clientDataHash: Data, rpIdHash: Data, now: Date) async throws -> Data {
        guard let root = try? CBOR.decode(object), root["fmt"]?.textString == "apple-appattest" else {
            throw (try? CBOR.decode(object)) == nil ? AppAttestFailure.malformedObject : AppAttestFailure.badFormat
        }
        guard let statement = root["attStmt"], let chain = statement["x5c"]?.arrayValue, (2...4).contains(chain.count),
              let authData = root["authData"]?.byteString else { throw AppAttestFailure.malformedObject }
        var certificates: [Certificate] = []
        for item in chain {
            guard let der = item.byteString, der.count <= 4096, let certificate = try? Certificate(derEncoded: Array(der)) else {
                throw AppAttestFailure.malformedObject
            }
            certificates.append(certificate)
        }
        let leaf = certificates[0]

        // 1. The chain validates to the trusted root.
        var validationTime = now
        let notBefore = leaf.notValidBefore
        if notBefore > validationTime, notBefore.timeIntervalSince(validationTime) <= Self.notBeforeLeeway { validationTime = notBefore }
        var verifier = Verifier(rootCertificates: CertificateStore(roots)) { RFC5280Policy(fixedExpiryValidationTime: validationTime) }
        let outcome = await verifier.validate(leaf: leaf, intermediates: CertificateStore(certificates.dropFirst()))
        guard case .validCertificate = outcome else { throw AppAttestFailure.badChain }

        // 2. The nonce in the credential certificate.
        guard let nonceExtension = leaf.extensions[oid: Self.nonceExtensionOID], let certificateNonce = Self.parseNonce(Array(nonceExtension.value)) else {
            throw AppAttestFailure.badNonce
        }
        let expectedNonce = Data(SHA256.hash(data: authData + clientDataHash))
        guard ConstantTime.equals(Data(certificateNonce), expectedNonce) else { throw AppAttestFailure.badNonce }

        // 3. The key identifier is the hash of the credential public key.
        guard let publicKey = P256.Signing.PublicKey(leaf.publicKey) else { throw AppAttestFailure.badKeyId }
        let x963 = publicKey.x963Representation
        guard ConstantTime.equals(Data(SHA256.hash(data: x963)), keyId) else { throw AppAttestFailure.badKeyId }

        // 4. authData.
        guard authData.count >= 55 else { throw AppAttestFailure.malformedObject }
        let bytes = Array(authData)
        guard ConstantTime.equals(Data(bytes[0..<32]), rpIdHash) else { throw AppAttestFailure.badRpId }
        guard bytes[33..<37].allSatisfy({ $0 == 0 }) else { throw AppAttestFailure.badCounter }
        guard ConstantTime.equals(Data(bytes[37..<53]), aaguid) else { throw AppAttestFailure.badAAGUID }
        let credentialLength = Int(bytes[53]) << 8 | Int(bytes[54])
        guard credentialLength == 32, bytes.count >= 55 + credentialLength,
              ConstantTime.equals(Data(bytes[55..<(55 + credentialLength)]), keyId) else { throw AppAttestFailure.badCredentialId }
        return x963
    }

    /// The extension value is `SEQUENCE { [1] EXPLICIT { OCTET STRING nonce } }`.
    public static func parseNonce(_ value: [UInt8]) -> [UInt8]? {
        guard let node = try? DER.parse(value), node.identifier == .sequence, case .constructed(let outer) = node.content else { return nil }
        var iterator = outer.makeIterator()
        guard let tagged = iterator.next(), iterator.next() == nil,
              tagged.identifier == ASN1Identifier(tagWithNumber: 1, tagClass: .contextSpecific),
              case .constructed(let inner) = tagged.content else { return nil }
        var innerIterator = inner.makeIterator()
        guard let octets = innerIterator.next(), innerIterator.next() == nil, octets.identifier == .octetString,
              case .primitive(let bytes) = octets.content else { return nil }
        return Array(bytes)
    }
}
