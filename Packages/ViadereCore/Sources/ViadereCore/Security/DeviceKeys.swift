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
public enum ViadereSignatureEncoding {
    /// Encodes a signature as base64url(raw r||s).
    public static func encode(_ signature: P256.Signing.ECDSASignature) -> String {
        Base64URL.encode(signature.rawRepresentation)
    }

    /// Decodes base64url(raw r||s). Rejects DER and any length other than 64 bytes.
    public static func decode(_ string: String) -> P256.Signing.ECDSASignature? {
        guard Base64URL.isValid(string, minLength: 86, maxLength: 86), let bytes = Base64URL.decode(string),
              bytes.count == 64 else { return nil }
        return try? P256.Signing.ECDSASignature(rawRepresentation: bytes)
    }
}
