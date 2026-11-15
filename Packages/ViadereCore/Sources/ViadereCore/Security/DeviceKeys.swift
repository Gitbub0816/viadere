import Crypto
import Foundation

/// A P-256 public key as carried on the wire: base64url of the X9.63 uncompressed point
/// (65 bytes, leading `0x04`). Parsing also accepts the 64-byte raw (`x || y`) form.
public struct DevicePublicKey: Hashable, Sendable, Codable {
    /// Key-parsing failure.
    public enum Error: Swift.Error, Sendable, Equatable { case invalidEncoding, invalidKey }

    /// Canonical X9.63 bytes (65 bytes).
    public let x963: Data

    /// Accepts X9.63 (65 bytes) or raw (64 bytes) representations.
    public init(bytes: Data) throws {
        let key: P256.Signing.PublicKey
        do {
            switch bytes.count {
            case 65: key = try P256.Signing.PublicKey(x963Representation: bytes)
            case 64: key = try P256.Signing.PublicKey(rawRepresentation: bytes)
            default: throw Error.invalidKey
            }
        } catch {
            throw Error.invalidKey
        }
        x963 = key.x963Representation
    }

    /// Wraps a CryptoKit / swift-crypto public key.
    public init(_ key: P256.Signing.PublicKey) { x963 = key.x963Representation }

    /// Parses the base64url wire form.
    public init(base64URL: String) throws {
        guard let bytes = Base64URL.decode(base64URL) else { throw Error.invalidEncoding }
        try self.init(bytes: bytes)
    }

    /// Base64url of the X9.63 bytes (wire form).
    public var base64URL: String { Base64URL.encode(x963) }

    /// The usable verification key.
    public func signingKey() throws -> P256.Signing.PublicKey {
        do { return try P256.Signing.PublicKey(x963Representation: x963) } catch { throw Error.invalidKey }
    }

    /// Stable key fingerprint: lowercase hex SHA-256 of the X9.63 bytes.
    public var fingerprint: String { SecureToken.sha256Hex(x963) }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        do { try self.init(base64URL: try container.decode(String.self)) } catch {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid P-256 public key")
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(base64URL)
    }
}

/// Why a device key exists. Each enrolled device registers one key per purpose.
public enum DeviceKeyPurpose: String, Sendable, Codable, CaseIterable {
    /// Signs API requests (`VIADERE-SIG-V1`). Secure Enclave, no user-presence requirement.
    case request
    /// Signs decisions with `.userPresence` (passcode or biometrics).
    case approvalUserPresence
    /// Signs decisions with `.biometryCurrentSet` (biometrics only; invalidated on enrollment change).
    case approvalBiometric

    /// The key purpose that must have produced a decision claiming `assurance`.
    public static func required(for assurance: DecisionAssurance) -> DeviceKeyPurpose {
        switch assurance {
        case .none: .request
        case .devicePasscode: .approvalUserPresence
        case .biometric: .approvalBiometric
        }
    }
}

/// Abstraction over a P-256 signing key so iOS can supply a Secure Enclave key
/// (`SecureEnclave.P256.Signing.PrivateKey`) while servers/tests use a software key.
///
/// Implementations return ECDSA-SHA256 signatures over `data` (the implementation hashes).
public protocol DeviceSigningKey: Sendable {
    /// The public half, registered at device enrollment.
    var publicKey: DevicePublicKey { get }
    /// Signs `data` (ECDSA P-256 / SHA-256). May prompt for user verification.
    func signature(for data: Data) async throws -> P256.Signing.ECDSASignature
}

/// A software P-256 key (tests, server-side tooling, simulator fallback).
public struct SoftwareP256SigningKey: DeviceSigningKey {
    private let rawPrivateKey: Data
    public let publicKey: DevicePublicKey

    /// Generates a new random key.
    public init() {
        let key = P256.Signing.PrivateKey()
        rawPrivateKey = key.rawRepresentation
        publicKey = DevicePublicKey(key.publicKey)
    }

    /// Restores a key from its 32-byte raw representation.
    public init(rawRepresentation: Data) throws {
        let key = try P256.Signing.PrivateKey(rawRepresentation: rawRepresentation)
        rawPrivateKey = key.rawRepresentation
        publicKey = DevicePublicKey(key.publicKey)
    }

    /// 32-byte raw private scalar (handle with care).
    public var rawRepresentation: Data { rawPrivateKey }

    public func signature(for data: Data) async throws -> P256.Signing.ECDSASignature {
        try P256.Signing.PrivateKey(rawRepresentation: rawPrivateKey).signature(for: data)
    }
}

/// ECDSA signature encoding used everywhere in Viadere: **raw** `r || s` (64 bytes),
/// base64url without padding (86 characters).
///
/// **Low-S canonical form.** For every valid ECDSA signature `(r, s)`, `(r, n - s)` is also valid (malleability).
/// Secure Enclave signatures may come out with either `s`, so Viadere neither rejects high-S nor trusts the
/// signature bytes for identity: `encode` and `decode` both normalise to `s <= n/2`, so every Viadere signature
/// has exactly one canonical encoding, and replay guards are keyed on signed *content* (challenge, nonce,
/// `deviceId|signedAt|scopeDigest`), never on the signature string.
public enum ViadereSignatureEncoding {
    /// Order `n` of the P-256 group, big endian.
    private static let order: [UInt8] = [
        0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
    ]
    /// `n / 2` (floor), big endian.
    private static let halfOrder: [UInt8] = [
        0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
        0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42, 0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
    ]

    /// Whether the 32-byte big-endian value `a` is strictly greater than `b`.
    private static func greater(_ a: [UInt8], than b: [UInt8]) -> Bool {
        for (x, y) in zip(a, b) where x != y { return x > y }
        return false
    }

    /// Returns the 64-byte raw signature with `s` folded into the lower half of the group (`s <= n/2`).
    /// Values that are not valid scalars (`s >= n`) are returned unchanged and simply fail verification.
    public static func normalizedRaw(_ raw: Data) -> Data {
        guard raw.count == 64 else { return raw }
        let bytes = [UInt8](raw)
        let s = Array(bytes[32..<64])
        guard greater(s, than: halfOrder), greater(order, than: s) else { return raw }
        // n - s, big-endian subtraction.
        var result = [UInt8](repeating: 0, count: 32)
        var borrow = 0
        for i in stride(from: 31, through: 0, by: -1) {
            var difference = Int(order[i]) - Int(s[i]) - borrow
            if difference < 0 { difference += 256; borrow = 1 } else { borrow = 0 }
            result[i] = UInt8(difference)
        }
        return Data(bytes[0..<32] + result)
    }

    /// Whether `signature` is already in the canonical low-S form.
    public static func isCanonical(_ signature: P256.Signing.ECDSASignature) -> Bool {
        normalizedRaw(signature.rawRepresentation) == signature.rawRepresentation
    }

    /// Encodes a signature as base64url(raw r||s), normalised to low-S.
    public static func encode(_ signature: P256.Signing.ECDSASignature) -> String {
        Base64URL.encode(normalizedRaw(signature.rawRepresentation))
    }

    /// Decodes base64url(raw r||s) and normalises it to low-S. Rejects DER and any length other than 64 bytes.
    public static func decode(_ string: String) -> P256.Signing.ECDSASignature? {
        guard Base64URL.isValid(string, minLength: 86, maxLength: 86), let bytes = Base64URL.decode(string),
              bytes.count == 64 else { return nil }
        return try? P256.Signing.ECDSASignature(rawRepresentation: normalizedRaw(bytes))
    }

    /// The canonical (low-S) base64url form of a wire signature string; `nil` when it is malformed.
    public static func canonicalString(_ string: String) -> String? {
        decode(string).map { Base64URL.encode($0.rawRepresentation) }
    }
}
