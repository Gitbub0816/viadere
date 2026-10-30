@preconcurrency import Crypto
import Foundation
import ViadereCore

/// A named signing key held by a key management service. The name is the **role** (`link-descriptor`); which vault, key version or HSM backs it is
/// the implementation's business (Azure Key Vault in Milestone B, `LocalKMS` until then).
public struct KMSKeyRef: Hashable, Sendable, CustomStringConvertible {
    public let name: String
    public init(_ name: String) { self.name = name }
    public var description: String { name }

    /// Viadere's P-256 key that signs link-session descriptors and results (`docs/SECURITY.md` §2.59). EC-HSM P-256 in Key Vault (ADR-0012).
    public static let linkDescriptor = KMSKeyRef("link-descriptor")
}

public enum KMSError: Error, Sendable, Equatable {
    /// The service holds no key for this reference.
    case unknownKey(String)
    /// The digest is not 32 bytes (SHA-256).
    case invalidDigest
    /// The service answered with something that is not a 64-byte raw P-256 signature.
    case invalidSignature
    case unavailable
}

/// Signing keys whose private half never enters this process (Milestone B: Azure Key Vault; ADR-0012). Every implementation:
/// * signs a **SHA-256 digest** with ECDSA P-256 and returns the **raw `r‖s`** (64 bytes), as Key Vault's `ES256` `sign` operation does;
/// * returns the X9.63 public key of the current version, so the server can publish its key id and callers can check what they signed.
///
/// The caller builds the digest over `domain ‖ payload` itself (`KMSStatementSigner`), so a service can never be asked to sign something whose
/// domain the caller did not choose.
public protocol KeyManagementService: Sendable {
    func sign(keyRef: KMSKeyRef, digest: Data) async throws -> Data
    func publicKey(keyRef: KMSKeyRef) async throws -> DevicePublicKey
}

/// Keys from the environment, in process memory: the interim implementation until the Key Vault adapter (WP-B2) replaces it. Covered by the
/// residual risk "server signing keys are environment secrets until KMS" (§2.58 item 3).
public struct LocalKMS: KeyManagementService {
    private let keys: [KMSKeyRef: SoftwareP256SigningKey]

    public init(keys: [KMSKeyRef: SoftwareP256SigningKey]) { self.keys = keys }

    public func sign(keyRef: KMSKeyRef, digest: Data) async throws -> Data {
        guard let key = keys[keyRef] else { throw KMSError.unknownKey(keyRef.name) }
        guard let sha = PrecomputedSHA256Digest(digest) else { throw KMSError.invalidDigest }
        return try P256.Signing.PrivateKey(rawRepresentation: key.rawRepresentation).signature(for: sha).rawRepresentation
    }

    public func publicKey(keyRef: KMSKeyRef) async throws -> DevicePublicKey {
        guard let key = keys[keyRef] else { throw KMSError.unknownKey(keyRef.name) }
        return key.publicKey
    }
}

/// Signs canonical statements with a KMS key: `SHA-256(domain ‖ payload)` is signed remotely, the raw signature is normalized to low-S and
/// **verified locally against the key's public half** before it is used (a misbehaving service cannot hand out a signature that does not verify).
struct KMSStatementSigner {
    let kms: any KeyManagementService
    let keyRef: KMSKeyRef

    func kid() async throws -> String { KeyIdentifier.make(try await kms.publicKey(keyRef: keyRef).signingKey()) }

    func sign(payload: Data, domain: String) async throws -> ViadereSignedStatement {
        let publicKey = try await kms.publicKey(keyRef: keyRef)
        let message = Data(domain.utf8) + payload
        let raw = try await kms.sign(keyRef: keyRef, digest: Data(SHA256.hash(data: message)))
        guard raw.count == 64, let signature = try? P256.Signing.ECDSASignature(rawRepresentation: ViadereSignatureEncoding.normalizedRaw(raw)),
              (try publicKey.signingKey()).isValidSignature(signature, for: message) else { throw KMSError.invalidSignature }
        return ViadereSignedStatement(kid: KeyIdentifier.make(try publicKey.signingKey()), payload: Base64URL.encode(payload),
                                      signature: ViadereSignatureEncoding.encode(signature))
    }
}

/// A SHA-256 digest the caller computed, as a `Digest` the signing API accepts (signing a digest, not a message, is the KMS contract).
struct PrecomputedSHA256Digest: Digest {
    static var byteCount: Int { SHA256.byteCount }
    private let bytes: [UInt8]

    init?(_ data: Data) {
        guard data.count == SHA256.byteCount else { return nil }
        bytes = Array(data)
    }

    func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R { try bytes.withUnsafeBytes(body) }
    func makeIterator() -> Array<UInt8>.Iterator { bytes.makeIterator() }
    var description: String { "SHA256 digest: " + Hex.encode(Data(bytes)) }
}
