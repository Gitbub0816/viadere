@preconcurrency import Crypto
import Foundation
import ViadereCore

/// A `DeviceSigningKey` whose private half lives in the KMS (the key-directory log key, `kd-log-signing`): the public key is fetched once at boot and
/// every signature is checked against it before use.
public struct KMSSigningKey: DeviceSigningKey {
    public let kms: any KeyManagementService
    public let keyRef: String
    public let publicKey: DevicePublicKey

    /// Resolves the public key now, so a missing or wrong key fails the boot instead of the first signature.
    public static func load(kms: any KeyManagementService, keyRef: String) async throws -> KMSSigningKey {
        KMSSigningKey(kms: kms, keyRef: keyRef, publicKey: DevicePublicKey(try await kms.publicKey(keyRef: keyRef)))
    }

    public func signature(for data: Data) async throws -> P256.Signing.ECDSASignature {
        let raw = try await kms.sign(keyRef: keyRef, message: data)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: raw)
        guard try publicKey.signingKey().isValidSignature(signature, for: data) else { throw KMSError.signatureMismatch }
        return signature
    }
}

/// Signs canonical statements (`ViadereSignedStatement`) with a server signing key: the `link-descriptor` key (WP-C1, SECURITY.md §2.59), held in
/// Key Vault on Azure (`KMSSigningKey`) or supplied as an environment secret elsewhere (`SoftwareP256SigningKey`). The signature over
/// `domain ‖ payload` is normalized to low-S and **verified locally against the key's public half** before it is used, so a misbehaving key service
/// (or a stand-in that should never sign) cannot hand out a statement that does not verify.
struct KMSStatementSigner {
    let key: any DeviceSigningKey

    func kid() throws -> String { KeyIdentifier.make(try key.publicKey.signingKey()) }

    func sign(payload: Data, domain: String) async throws -> ViadereSignedStatement {
        let message = Data(domain.utf8) + payload
        let produced = try await key.signature(for: message)
        guard let signature = try? P256.Signing.ECDSASignature(rawRepresentation: ViadereSignatureEncoding.normalizedRaw(produced.rawRepresentation)),
              try key.publicKey.signingKey().isValidSignature(signature, for: message) else { throw KMSError.signatureMismatch }
        return ViadereSignedStatement(kid: try kid(), payload: Base64URL.encode(payload), signature: ViadereSignatureEncoding.encode(signature))
    }
}

/// A signing key that refuses to sign: what a process holds for a key it must never use (the queue worker's key-directory log key), so a code
/// path that reaches it fails instead of signing with a throwaway key whose signatures nobody could verify.
public struct UnavailableSigningKey: DeviceSigningKey {
    public struct Refused: Error {}
    public let publicKey = SoftwareP256SigningKey().publicKey
    public init() {}
    public func signature(for data: Data) async throws -> P256.Signing.ECDSASignature { throw Refused() }
}

