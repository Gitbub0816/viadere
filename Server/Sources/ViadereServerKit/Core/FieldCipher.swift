@preconcurrency import Crypto
import Foundation
import ViadereCore

/// AES-256-GCM field encryption for data at rest (phone numbers, message bodies, webhook secrets and bodies,
/// SMS conversation contexts).
///
/// Wire forms: `v2.` + base64url(nonce ‖ ciphertext ‖ tag), authenticated with the additional data
/// `"{column}#{rowId}"` (for example `sms_outbound.body#9c1f…`); and the legacy `v1.` form whose additional data is
/// only the column (`sms_outbound.body`). New writes are always `v2`, so a ciphertext cannot be moved to a different
/// column **or a different row** (an attacker with database write access cannot swap two people's phone numbers).
/// `open` still reads `v1` so existing rows keep working until `ViadereServer reencrypt-fields` rewrites them.
public struct FieldCipher: Sendable {
    public enum Failure: Error, Sendable { case malformed, authenticationFailed }

    private let key: SymmetricKey
    private static let legacyPrefix = "v1."
    private static let rowBoundPrefix = "v2."

    public init(key: SymmetricKey) { self.key = key }

    private static func aad(_ context: String, rowId: UUID) -> Data {
        Data("\(context)#\(rowId.uuidString.lowercased())".utf8)
    }

    // MARK: Row-bound (v2)

    public func seal(_ plaintext: String, context: String, rowId: UUID) throws -> String {
        try seal(Data(plaintext.utf8), context: context, rowId: rowId)
    }

    public func seal(_ plaintext: Data, context: String, rowId: UUID) throws -> String {
        let box = try AES.GCM.seal(plaintext, using: key, authenticating: Self.aad(context, rowId: rowId))
        guard let combined = box.combined else { throw Failure.malformed }
        return Self.rowBoundPrefix + Base64URL.encode(combined)
    }

    /// Opens a `v2` value (bound to `context` and `rowId`) or, for rows written before row binding, a `v1` value (bound to `context` only).
    public func open(_ sealed: String, context: String, rowId: UUID) throws -> Data {
        if sealed.hasPrefix(Self.rowBoundPrefix) {
            return try open(String(sealed.dropFirst(Self.rowBoundPrefix.count)), aad: Self.aad(context, rowId: rowId))
        }
        return try openLegacy(sealed, context: context)
    }

    public func openString(_ sealed: String, context: String, rowId: UUID) throws -> String {
        guard let string = String(data: try open(sealed, context: context, rowId: rowId), encoding: .utf8) else { throw Failure.malformed }
        return string
    }

    /// Whether `sealed` is in the legacy column-bound form (and should be rewritten).
    public static func isLegacy(_ sealed: String) -> Bool { sealed.hasPrefix(legacyPrefix) }

    // MARK: Legacy (v1)

    /// Column-bound only. Kept to read (and, in tests, to produce) rows written before row binding.
    public func sealLegacy(_ plaintext: String, context: String) throws -> String {
        let box = try AES.GCM.seal(Data(plaintext.utf8), using: key, authenticating: Data(context.utf8))
        guard let combined = box.combined else { throw Failure.malformed }
        return Self.legacyPrefix + Base64URL.encode(combined)
    }

    public func openLegacy(_ sealed: String, context: String) throws -> Data {
        guard sealed.hasPrefix(Self.legacyPrefix) else { throw Failure.malformed }
        return try open(String(sealed.dropFirst(Self.legacyPrefix.count)), aad: Data(context.utf8))
    }

    private func open(_ body: String, aad: Data) throws -> Data {
        guard let combined = Base64URL.decode(body) else { throw Failure.malformed }
        do {
            let box = try AES.GCM.SealedBox(combined: combined)
            return try AES.GCM.open(box, using: key, authenticating: aad)
        } catch {
            throw Failure.authenticationFailed
        }
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

    /// Per-business pseudonym of a device: stable for one business, unlinkable across businesses and to the device id.
    public func deviceReference(businessId: BusinessID, deviceId: DeviceID) -> String {
        String(hmacHex("device-ref", "\(businessId)\n\(deviceId)").prefix(32))
    }

    /// Opaque reference to a stored signed decision, quoted in disputes.
    public func evidenceReference(decisionId: UUID) -> String {
        String(hmacHex("decision-evidence", decisionId.uuidString.lowercased()).prefix(32))
    }

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
