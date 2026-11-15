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
    public enum Failure: Error, Sendable { case malformed, authenticationFailed, unknownKey }

    /// The implicit key id of every `v1.` / `v2.` ciphertext (written before key ids existed) and the default id of `DATA_ENCRYPTION_KEY`.
    public static let legacyKeyId = "k1"

    private let key: SymmetricKey
    private let keyId: String
    private let previous: [String: SymmetricKey]
    private static let legacyPrefix = "v1."
    private static let rowBoundPrefix = "v2."
    private static let keyedPrefix = "v3."

    public init(key: SymmetricKey) {
        self.key = key
        keyId = Self.legacyKeyId
        previous = [:]
    }

    /// Multi-key (G-8): new values are sealed under `key` (id `keyId`); values sealed under any key in `previous` still open. The legacy id `k1`
    /// is written in the `v2.` form, any other id as `v3.<id>.`.
    public init(key: SymmetricKey, keyId: String, previous: [String: SymmetricKey]) {
        self.key = key
        self.keyId = keyId
        self.previous = previous
    }

    /// The id of the key new values are sealed under.
    public var currentKeyId: String { keyId }

    private static func aad(_ context: String, rowId: UUID) -> Data {
        Data("\(context)#\(rowId.uuidString.lowercased())".utf8)
    }

    private func key(for id: String) -> SymmetricKey? {
        if id == keyId { return key }
        return previous[id]
    }

    // MARK: Row-bound (v2, v3)

    public func seal(_ plaintext: String, context: String, rowId: UUID) throws -> String {
        try seal(Data(plaintext.utf8), context: context, rowId: rowId)
    }

    public func seal(_ plaintext: Data, context: String, rowId: UUID) throws -> String {
        let box = try AES.GCM.seal(plaintext, using: key, authenticating: Self.aad(context, rowId: rowId))
        guard let combined = box.combined else { throw Failure.malformed }
        let body = Base64URL.encode(combined)
        return keyId == Self.legacyKeyId ? Self.rowBoundPrefix + body : "\(Self.keyedPrefix)\(keyId).\(body)"
    }

    /// Opens a `v3` value (key chosen by its id), a `v2` value (bound to `context` and `rowId`, key `k1`) or, for rows written before row
    /// binding, a `v1` value (bound to `context` only, key `k1`).
    public func open(_ sealed: String, context: String, rowId: UUID) throws -> Data {
        if sealed.hasPrefix(Self.keyedPrefix) {
            let rest = sealed.dropFirst(Self.keyedPrefix.count)
            guard let dot = rest.firstIndex(of: "."), dot != rest.startIndex else { throw Failure.malformed }
            guard let selected = key(for: String(rest[rest.startIndex..<dot])) else { throw Failure.unknownKey }
            return try open(String(rest[rest.index(after: dot)...]), aad: Self.aad(context, rowId: rowId), key: selected)
        }
        guard let legacy = key(for: Self.legacyKeyId) else { throw Failure.unknownKey }
        if sealed.hasPrefix(Self.rowBoundPrefix) {
            return try open(String(sealed.dropFirst(Self.rowBoundPrefix.count)), aad: Self.aad(context, rowId: rowId), key: legacy)
        }
        return try openLegacy(sealed, context: context)
    }

    public func openString(_ sealed: String, context: String, rowId: UUID) throws -> String {
        guard let string = String(data: try open(sealed, context: context, rowId: rowId), encoding: .utf8) else { throw Failure.malformed }
        return string
    }

    /// Whether `sealed` is in the legacy column-bound form (and should be rewritten).
    public static func isLegacy(_ sealed: String) -> Bool { sealed.hasPrefix(legacyPrefix) }

    /// Whether `value` looks like something this cipher produced (as opposed to a plaintext stored before encryption existed).
    public static func isSealed(_ value: String) -> Bool {
        value.hasPrefix(legacyPrefix) || value.hasPrefix(rowBoundPrefix) || value.hasPrefix(keyedPrefix)
    }

    /// The id of the key `sealed` was written under (`k1` for `v1.` / `v2.`), or `nil` if it is not a sealed value.
    public static func keyId(of sealed: String) -> String? {
        if sealed.hasPrefix(keyedPrefix) {
            let rest = sealed.dropFirst(keyedPrefix.count)
            guard let dot = rest.firstIndex(of: "."), dot != rest.startIndex else { return nil }
            return String(rest[rest.startIndex..<dot])
        }
        return sealed.hasPrefix(rowBoundPrefix) || sealed.hasPrefix(legacyPrefix) ? legacyKeyId : nil
    }

    // MARK: Legacy (v1)

    /// Column-bound only. Kept to read (and, in tests, to produce) rows written before row binding.
    public func sealLegacy(_ plaintext: String, context: String) throws -> String {
        guard let legacy = key(for: Self.legacyKeyId) else { throw Failure.unknownKey }
        let box = try AES.GCM.seal(Data(plaintext.utf8), using: legacy, authenticating: Data(context.utf8))
        guard let combined = box.combined else { throw Failure.malformed }
        return Self.legacyPrefix + Base64URL.encode(combined)
    }

    public func openLegacy(_ sealed: String, context: String) throws -> Data {
        guard sealed.hasPrefix(Self.legacyPrefix) else { throw Failure.malformed }
        guard let legacy = key(for: Self.legacyKeyId) else { throw Failure.unknownKey }
        return try open(String(sealed.dropFirst(Self.legacyPrefix.count)), aad: Data(context.utf8), key: legacy)
    }

    private func open(_ body: String, aad: Data, key: SymmetricKey) throws -> Data {
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
    /// The implicit id of `SERVER_PEPPER` before pepper ids existed.
    public static let legacyPepperId = "p1"

    private let pepper: SymmetricKey
    private let pepperId: String
    private let previousPeppers: [String: SymmetricKey]

    public init(pepper: Data) {
        self.pepper = SymmetricKey(data: pepper)
        pepperId = Self.legacyPepperId
        previousPeppers = [:]
    }

    /// Versioned pepper (G-8). `hmacHex` (and every hash already stored) keeps using the **current** pepper; rotating it changes them all, so
    /// existing peppered hashes need their re-issue flows (docs/ops/KEY-ROTATION.md). New hashes that should survive a rotation use
    /// `versionedHex`, which names the pepper it used and stays verifiable with `verifyVersioned` while the old pepper is configured.
    public init(pepper: Data, pepperId: String, previous: [String: Data]) {
        self.pepper = SymmetricKey(data: pepper)
        self.pepperId = pepperId
        previousPeppers = previous.mapValues { SymmetricKey(data: $0) }
    }

    /// `<pepper id>:<hex HMAC>`: a hash that carries the id of the pepper it was made with.
    public func versionedHex(_ domain: String, _ value: String) -> String {
        "\(pepperId):" + Self.mac(domain, value, key: pepper)
    }

    /// Verifies a `versionedHex` value against any configured pepper (current or previous), in constant time.
    public func verifyVersioned(_ stored: String, domain: String, value: String) -> Bool {
        guard let colon = stored.firstIndex(of: ":") else { return false }
        let id = String(stored[stored.startIndex..<colon])
        let key: SymmetricKey? = id == pepperId ? pepper : previousPeppers[id]
        guard let key else { return false }
        return ConstantTime.equals(String(stored[stored.index(after: colon)...]), Self.mac(domain, value, key: key))
    }

    /// Whether `stored` was made with the current pepper (the others should be re-issued the next time the value is seen).
    public func isCurrentVersion(_ stored: String) -> Bool { stored.hasPrefix("\(pepperId):") }

    private static func mac(_ domain: String, _ value: String, key: SymmetricKey) -> String {
        Hex.encode(HMAC<SHA256>.authenticationCode(for: Data("\(domain)\n\(value)".utf8), using: key))
    }

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
