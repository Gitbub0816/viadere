@preconcurrency import Crypto
import Foundation
import ViadereCore

/// AES-256-GCM field encryption for data at rest (phone numbers, message bodies, webhook secrets,
/// SMS conversation contexts). Wire form: `v1.` + base64url(nonce ‖ ciphertext ‖ tag).
/// The `context` string is bound as additional authenticated data so a ciphertext cannot be
/// moved to a different column or table.
public struct FieldCipher: Sendable {
    public enum Failure: Error, Sendable { case malformed, authenticationFailed }

    private let key: SymmetricKey
    private static let prefix = "v1."

    public init(key: SymmetricKey) { self.key = key }

    public func seal(_ plaintext: String, context: String) throws -> String {
        try seal(Data(plaintext.utf8), context: context)
    }

    public func seal(_ plaintext: Data, context: String) throws -> String {
        let box = try AES.GCM.seal(plaintext, using: key, authenticating: Data(context.utf8))
        guard let combined = box.combined else { throw Failure.malformed }
        return Self.prefix + Base64URL.encode(combined)
    }

    public func open(_ sealed: String, context: String) throws -> Data {
        guard sealed.hasPrefix(Self.prefix), let combined = Base64URL.decode(String(sealed.dropFirst(Self.prefix.count))) else {
            throw Failure.malformed
        }
        do {
            let box = try AES.GCM.SealedBox(combined: combined)
            return try AES.GCM.open(box, using: key, authenticating: Data(context.utf8))
        } catch {
            throw Failure.authenticationFailed
        }
    }

    public func openString(_ sealed: String, context: String) throws -> String {
        guard let string = String(data: try open(sealed, context: context), encoding: .utf8) else { throw Failure.malformed }
        return string
    }
}

/// Keyed hashing helpers (all keyed with the server pepper so database leaks do not enable offline guessing).
public struct Hasher256: Sendable {
    private let pepper: SymmetricKey

    public init(pepper: Data) { self.pepper = SymmetricKey(data: pepper) }

    /// Lowercase hex HMAC-SHA256.
    public func hmacHex(_ domain: String, _ value: String) -> String {
        let message = Data("\(domain)\n\(value)".utf8)
        return Hex.encode(HMAC<SHA256>.authenticationCode(for: message, using: pepper))
    }

    /// Stable lookup hash for a phone number (the database never needs to index plaintext numbers).
    public func phoneHash(_ phone: PhoneNumber) -> String { hmacHex("phone", phone.e164) }

    /// Per-business pseudonymous reference for a consumer: the same consumer looks different to every business.
    public func consumerReference(businessId: BusinessID, consumerId: ConsumerID) -> ConsumerID {
        let digest = HMAC<SHA256>.authenticationCode(for: Data("ref\n\(businessId)\n\(consumerId)".utf8), using: pepper)
        var bytes = Array(digest.prefix(16))
        bytes[6] = (bytes[6] & 0x0F) | 0x40
        bytes[8] = (bytes[8] & 0x3F) | 0x80
        let uuid = UUID(uuid: (bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7], bytes[8], bytes[9],
                               bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]))
        return ConsumerID(uuid)
    }
}
