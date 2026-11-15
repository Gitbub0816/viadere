import Crypto
import Foundation

/// Key identifiers (`kid`) shared by every public key Viadere names: approval keys, HPKE encryption keys, business root and operational
/// keys, the transparency-log key.
///
/// `kid = base64url( SHA-256( DER SubjectPublicKeyInfo of the P-256 key ) )`, **not truncated** (43 characters). The identifier is a lookup
/// handle: every verifier compares the full public key it holds, never the `kid` alone.
public enum KeyIdentifier {
    /// DER `SubjectPublicKeyInfo` header of an uncompressed P-256 key (`id-ecPublicKey`, `prime256v1`, BIT STRING of 66 bytes); the 65-byte
    /// X9.63 point follows.
    static let p256SPKIPrefix = Data([0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
                                      0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00])

    /// The `kid` of a P-256 public key given as X9.63 uncompressed bytes (validated as a point on the curve).
    public static func make(p256X963 x963: Data) throws -> String {
        guard x963.count == 65, (try? P256.KeyAgreement.PublicKey(x963Representation: x963)) != nil else { throw E2EEError.invalidKey }
        return Base64URL.encode(Data(SHA256.hash(data: p256SPKIPrefix + x963)))
    }

    /// The `kid` of a signing key.
    public static func make(_ key: P256.Signing.PublicKey) -> String { Base64URL.encode(Data(SHA256.hash(data: key.derRepresentation))) }

    /// The `kid` of a key-agreement key.
    public static func make(_ key: P256.KeyAgreement.PublicKey) -> String { Base64URL.encode(Data(SHA256.hash(data: key.derRepresentation))) }

    /// True for a well-formed `kid` (43 base64url characters).
    public static func isValid(_ kid: String) -> Bool { Base64URL.isValid(kid, minLength: 43, maxLength: 43) && Base64URL.decode(kid)?.count == 32 }

    /// First 20 hex characters grouped in fives, for showing a fingerprint to a person (`ab12c-d34ef-…`). Comparison by a person is a
    /// second check: software always compares the full key.
    public static func displayFingerprint(_ kid: String) -> String {
        guard let bytes = Base64URL.decode(kid), bytes.count == 32 else { return "" }
        let hex = Hex.encode(bytes.prefix(10))
        return stride(from: 0, to: hex.count, by: 5).map { index in
            let start = hex.index(hex.startIndex, offsetBy: index)
            return String(hex[start..<hex.index(start, offsetBy: 5)])
        }.joined(separator: "-")
    }
}

/// A recipient's HPKE public key (`DHKEM(P-256, HKDF-SHA256)`) with its `kid`.
public struct E2EEPublicKey: Sendable, Hashable, Codable {
    public let x963: Data
    public let kid: String

    /// - Throws: `E2EEError.invalidKey` unless `x963` is a valid uncompressed P-256 point.
    public init(x963: Data) throws {
        kid = try KeyIdentifier.make(p256X963: x963)
        self.x963 = x963
    }

    public init(base64URL: String) throws {
        guard let bytes = Base64URL.decode(base64URL) else { throw E2EEError.invalidKey }
        try self.init(x963: bytes)
    }

    public init(_ key: P256.KeyAgreement.PublicKey) {
        x963 = key.x963Representation
        kid = KeyIdentifier.make(key)
    }

    public var base64URL: String { Base64URL.encode(x963) }

    func agreementKey() throws -> P256.KeyAgreement.PublicKey {
        do { return try P256.KeyAgreement.PublicKey(x963Representation: x963) } catch { throw E2EEError.invalidKey }
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        do { try self.init(base64URL: try container.decode(String.self)) } catch {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid P-256 HPKE public key")
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(base64URL)
    }
}

/// A private HPKE key that can open envelopes. A device keeps its per-relationship key in the Keychain (`ThisDeviceOnly`); a business keeps
/// its HPKE key in its KMS. Software implementation for tests and tools.
public protocol E2EEPrivateKey: Sendable {
    var publicKey: E2EEPublicKey { get }
    /// An HPKE recipient context for `DHKEM(P-256, HKDF-SHA256) / HKDF-SHA256 / AES-256-GCM`, base mode.
    func recipient(info: Data, encapsulatedKey: Data) throws -> HPKE.Recipient
}

/// A software P-256 HPKE private key.
public struct SoftwareE2EEPrivateKey: E2EEPrivateKey {
    private let raw: Data
    public let publicKey: E2EEPublicKey

    /// Generates a new key with the system CSPRNG.
    public init() {
        let key = P256.KeyAgreement.PrivateKey()
        raw = key.rawRepresentation
        publicKey = E2EEPublicKey(key.publicKey)
    }

    /// Restores a key from its 32-byte raw scalar.
    public init(rawRepresentation: Data) throws {
        guard let key = try? P256.KeyAgreement.PrivateKey(rawRepresentation: rawRepresentation) else { throw E2EEError.invalidKey }
        raw = key.rawRepresentation
        publicKey = E2EEPublicKey(key.publicKey)
    }

    /// The 32-byte raw private scalar. Handle with care: store it in the Keychain or a KMS, never in logs.
    public var rawRepresentation: Data { raw }

    public func recipient(info: Data, encapsulatedKey: Data) throws -> HPKE.Recipient {
        guard let key = try? P256.KeyAgreement.PrivateKey(rawRepresentation: raw) else { throw E2EEError.invalidKey }
        return try HPKE.Recipient(privateKey: key, ciphersuite: .P256_SHA256_AES_GCM_256, info: info, encapsulatedKey: encapsulatedKey)
    }
}
