@preconcurrency import Crypto
import _CryptoExtras
import Foundation
import ViadereCore

/// Service keys behind one interface (ADR-0003's promise, implemented for ADR-0012): signing keys and key-encryption keys that the server can
/// **use** but never read. Implementations: `AzureKeyVaultKMS` (Key Vault Standard and Premium share the REST data plane) and `LocalKMS`
/// (development and tests only; refused in staging and production).
///
/// Key references are `name` (the current version) or `name/version` (a pinned version), e.g. `audit-head-signing` or
/// `kek-data/4c1e…`. Implementations must never return private key material and never log key bytes, digests of secrets or plaintexts.
public protocol KeyManagementService: Sendable {
    /// ES256 over a 32-byte SHA-256 `digest`: returns the raw `r ‖ s` signature (64 bytes) in Viadere's canonical low-S form
    /// (`ViadereSignatureEncoding`, SECURITY.md §2.1). Implementations verify the signature against `publicKey(keyRef:)` before returning it.
    func sign(keyRef: String, digest: Data) async throws -> Data
    /// The P-256 public key of an EC signing key (the version `keyRef` names, or the current one).
    func publicKey(keyRef: String) async throws -> P256.Signing.PublicKey
    /// RSA-OAEP-256 key wrap under a key-encryption key. The result names the exact key version that unwrapping needs.
    func wrap(keyRef: String, plaintext: Data) async throws -> KMSWrappedKey
    /// RSA-OAEP-256 unwrap. `keyRef` must name the version used to wrap (as `KMSWrappedKey.keyRef` does).
    func unwrap(keyRef: String, ciphertext: Data) async throws -> Data
    /// The explicit `name/version` that `keyRef` means now (so a signature can record the exact key version that verifies it).
    func resolveVersion(keyRef: String) async throws -> String
    /// RS256 (RSASSA-PKCS1-v1_5 with SHA-256) over a 32-byte SHA-256 `digest` with an RSA signing key (the authority's `oidc-signing-rs256`,
    /// ADR-0028 §2). Implementations verify the signature against `rsaPublicKey(keyRef:)` before returning it, like `sign`.
    func signRS256(keyRef: String, digest: Data) async throws -> Data
    /// The public half of an RSA signing key (the version `keyRef` names).
    func rsaPublicKey(keyRef: String) async throws -> _RSA.Signing.PublicKey
}

extension KeyManagementService {
    /// Services without RSA signing keys refuse.
    public func signRS256(keyRef: String, digest: Data) async throws -> Data { throw KMSError.wrongKeyType }
    public func rsaPublicKey(keyRef: String) async throws -> _RSA.Signing.PublicKey { throw KMSError.wrongKeyType }
}

/// A wrapped value and the versioned key reference that unwraps it.
public struct KMSWrappedKey: Sendable, Equatable {
    public var keyRef: String
    public var ciphertext: Data
    public init(keyRef: String, ciphertext: Data) {
        self.keyRef = keyRef
        self.ciphertext = ciphertext
    }
}

public enum KMSError: Error, Sendable, Equatable {
    /// The key reference is malformed or names no key.
    case unknownKey
    /// The digest is not 32 bytes.
    case invalidDigest
    /// The service refused or failed (status code only; never the response body, which can echo inputs).
    case service(status: Int)
    /// A signature did not verify against the key's published public key (wrong key version, corrupted response).
    case signatureMismatch
    /// Unwrap failed (wrong key, wrong version, tampered ciphertext).
    case unwrapFailed
    /// The key is of the wrong type for the operation.
    case wrongKeyType
}

/// Key references: `name` or `name/version`; names follow Key Vault's rules (1-127 of `[0-9A-Za-z-]`), versions are 32 hex digits.
public enum KMSKeyRef {
    public static func parse(_ ref: String) -> (name: String, version: String?)? {
        let parts = ref.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard (1...2).contains(parts.count), isName(parts[0]) else { return nil }
        if parts.count == 2 {
            guard (1...64).contains(parts[1].count), parts[1].allSatisfy({ $0.isHexDigit }) else { return nil }
            return (parts[0], parts[1].lowercased())
        }
        return (parts[0], nil)
    }

    package static func isName(_ name: String) -> Bool {
        (1...127).contains(name.count) && name.unicodeScalars.allSatisfy { ($0.isASCII && ($0.properties.isAlphabetic || ("0"..."9").contains($0))) || $0 == "-" }
    }
}

extension KeyManagementService {
    /// Signs `message` (hashing it with SHA-256) and returns the canonical raw signature.
    public func sign(keyRef: String, message: Data) async throws -> Data {
        try await sign(keyRef: keyRef, digest: Data(SHA256.hash(data: message)))
    }
}

/// Software KMS for development and tests: P-256 signing keys and RSA-3072 key-encryption keys held in memory, with versions, so the same code paths
/// (versioned references, wrong-version failures) run without Azure. `ServerConfig` refuses it in staging and production.
public final class LocalKMS: KeyManagementService, @unchecked Sendable {
    private let lock = NSLock()
    private var signing: [String: [(version: String, key: P256.Signing.PrivateKey)]] = [:]
    private var wrapping: [String: [(version: String, key: _RSA.Encryption.PrivateKey)]] = [:]
    private var rsaSigning: [String: [(version: String, key: _RSA.Signing.PrivateKey)]] = [:]

    public init() {}

    /// Adds a new version of an EC P-256 signing key and returns its version.
    @discardableResult
    public func createSigningKey(_ name: String, key: P256.Signing.PrivateKey = P256.Signing.PrivateKey()) -> String {
        let version = Self.newVersion()
        lock.withLock { signing[name, default: []].append((version, key)) }
        return version
    }

    /// Adds a new version of an RSA key-encryption key (3072 bits unless a key is given) and returns its version.
    @discardableResult
    public func createWrappingKey(_ name: String, key: _RSA.Encryption.PrivateKey? = nil) throws -> String {
        let version = Self.newVersion()
        let material = try key ?? _RSA.Encryption.PrivateKey(keySize: .bits3072)
        lock.withLock { wrapping[name, default: []].append((version, material)) }
        return version
    }

    /// Adds a new version of an RSA signing key (3072 bits unless a key is given) and returns its version.
    @discardableResult
    public func createRSASigningKey(_ name: String, key: _RSA.Signing.PrivateKey? = nil) throws -> String {
        let version = Self.newVersion()
        let material = try key ?? _RSA.Signing.PrivateKey(keySize: .bits3072)
        lock.withLock { rsaSigning[name, default: []].append((version, material)) }
        return version
    }

    private func rsaSigningKey(_ ref: String) throws -> _RSA.Signing.PrivateKey {
        guard let (name, version) = KMSKeyRef.parse(ref) else { throw KMSError.unknownKey }
        return try lock.withLock {
            guard let versions = rsaSigning[name], !versions.isEmpty else { throw KMSError.unknownKey }
            if let version { guard let match = versions.first(where: { $0.version == version }) else { throw KMSError.unknownKey }; return match.key }
            return versions.last!.key
        }
    }

    public func signRS256(keyRef: String, digest: Data) async throws -> Data {
        guard digest.count == 32 else { throw KMSError.invalidDigest }
        let key = try rsaSigningKey(keyRef)
        return try key.signature(for: SHA256Digest(bytes: digest), padding: .insecurePKCS1v1_5).rawRepresentation
    }

    /// The public half of an RSA signing key, or of a key-encryption key (Key Vault returns the public JWK of either; the authority reads a KEK's to
    /// verify a reviewed inventory row).
    public func rsaPublicKey(keyRef: String) async throws -> _RSA.Signing.PublicKey {
        if let key = try? rsaSigningKey(keyRef) { return key.publicKey }
        let (_, wrappingKey) = try wrappingKey(keyRef)
        return try _RSA.Signing.PublicKey(derRepresentation: wrappingKey.publicKey.derRepresentation)
    }

    package static func newVersion() -> String { Hex.encode(SecureToken.randomBytes(16)) }

    private func signingKey(_ ref: String) throws -> P256.Signing.PrivateKey {
        guard let (name, version) = KMSKeyRef.parse(ref) else { throw KMSError.unknownKey }
        return try lock.withLock {
            guard let versions = signing[name], !versions.isEmpty else { throw KMSError.unknownKey }
            if let version { guard let match = versions.first(where: { $0.version == version }) else { throw KMSError.unknownKey }; return match.key }
            return versions.last!.key
        }
    }

    private func wrappingKey(_ ref: String) throws -> (String, _RSA.Encryption.PrivateKey) {
        guard let (name, version) = KMSKeyRef.parse(ref) else { throw KMSError.unknownKey }
        return try lock.withLock {
            guard let versions = wrapping[name], !versions.isEmpty else { throw KMSError.unknownKey }
            if let version { guard let match = versions.first(where: { $0.version == version }) else { throw KMSError.unknownKey }; return ("\(name)/\(match.version)", match.key) }
            let last = versions.last!
            return ("\(name)/\(last.version)", last.key)
        }
    }

    public func sign(keyRef: String, digest: Data) async throws -> Data {
        guard digest.count == 32 else { throw KMSError.invalidDigest }
        let key = try signingKey(keyRef)
        let raw = ViadereSignatureEncoding.normalizedRaw(try key.signature(for: SHA256Digest(bytes: digest)).rawRepresentation)
        return raw
    }

    public func publicKey(keyRef: String) async throws -> P256.Signing.PublicKey { try signingKey(keyRef).publicKey }

    public func resolveVersion(keyRef: String) async throws -> String {
        guard let (name, version) = KMSKeyRef.parse(keyRef) else { throw KMSError.unknownKey }
        if let version { return "\(name)/\(version)" }
        return try lock.withLock {
            if let last = signing[name]?.last { return "\(name)/\(last.version)" }
            if let last = wrapping[name]?.last { return "\(name)/\(last.version)" }
            if let last = rsaSigning[name]?.last { return "\(name)/\(last.version)" }
            throw KMSError.unknownKey
        }
    }

    public func wrap(keyRef: String, plaintext: Data) async throws -> KMSWrappedKey {
        let (resolved, key) = try wrappingKey(keyRef)
        return KMSWrappedKey(keyRef: resolved, ciphertext: try key.publicKey.encrypt(plaintext, padding: .PKCS1_OAEP_SHA256))
    }

    public func unwrap(keyRef: String, ciphertext: Data) async throws -> Data {
        let (_, key) = try wrappingKey(keyRef)
        do { return try key.decrypt(ciphertext, padding: .PKCS1_OAEP_SHA256) } catch { throw KMSError.unwrapFailed }
    }
}

extension SHA256Digest {
    /// A digest computed elsewhere (the KMS signs digests, not messages). Only 32-byte inputs are accepted by callers.
    /// swift-crypto has no public initializer from bytes; the digest is a plain 32-byte value type, so it is loaded from the bytes (the
    /// LocalKMS tests verify every signature against the message, which would catch any layout change).
    package init(bytes: Data) {
        precondition(bytes.count == 32 && MemoryLayout<SHA256Digest>.size == 32)
        self = bytes.withUnsafeBytes { $0.loadUnaligned(as: SHA256Digest.self) }
    }
}
