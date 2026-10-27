import Crypto
import Foundation

/// A signed canonical-JSON statement: `{"payload": base64url(canonical JSON), "signature": base64url(raw r‖s)}`. The signature is
/// ECDSA P-256 / SHA-256 (low-S, section 2.1) over `domain ‖ payload bytes`; every statement type has its own domain string, so a
/// signature made for one purpose can never verify as another.
public struct SignedStatement: Sendable, Hashable, Codable {
    public static let maxPayloadBytes = 8 * 1024

    public var payload: String
    public var signature: String

    public init(payload: String, signature: String) {
        self.payload = payload
        self.signature = signature
    }

    /// Signs `object` (canonical JSON) with `key` under `domain`.
    public static func sign(_ object: [String: JSONValue], domain: String, with key: any DeviceSigningKey) async throws -> SignedStatement {
        let bytes = try CanonicalJSON.serialize(.object(object))
        let signature = try await key.signature(for: Data(domain.utf8) + bytes)
        return SignedStatement(payload: Base64URL.encode(bytes), signature: ViadereSignatureEncoding.encode(signature))
    }

    /// The canonical payload bytes, only if `payload` is well-formed base64url within the size limit.
    public var payloadBytes: Data? {
        guard payload.utf8.count <= Self.maxPayloadBytes * 4 / 3 + 4 else { return nil }
        return Base64URL.decode(payload)
    }

    /// Whether `signature` verifies under `publicKey` and `domain` over the payload bytes.
    public func isValid(domain: String, publicKey: DevicePublicKey) -> Bool {
        guard let bytes = payloadBytes, bytes.count <= Self.maxPayloadBytes, let signature = ViadereSignatureEncoding.decode(signature),
              let key = try? publicKey.signingKey() else { return false }
        return key.isValidSignature(signature, for: Data(domain.utf8) + bytes)
    }

    /// Parses the payload as a JSON object and requires it to be **exactly canonical** (one serialization per statement, so a signature
    /// covers one byte string and a statement has one hash).
    func canonicalObject() -> [String: JSONValue]? {
        guard let bytes = payloadBytes, bytes.count <= Self.maxPayloadBytes,
              case .object(let object)? = try? JSONDecoder().decode(JSONValue.self, from: bytes),
              (try? CanonicalJSON.serialize(.object(object))) == bytes else { return nil }
        return object
    }
}

extension JSONValue {
    /// The integer value, if this is an integer.
    var int64Value: Int64? {
        if case .integer(let value) = self { return value }
        return nil
    }
}
