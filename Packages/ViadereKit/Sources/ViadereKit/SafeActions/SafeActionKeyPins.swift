import Crypto
import Foundation
import ViadereCore

/// An issuer's Ed25519 key this build trusts for CKey Safe Actions (SECURITY.md §2.104 "Safe Actions").
public struct PinnedSafeActionKey: Sendable, Equatable {
    /// The issuing site's DNS name: always this build's link-domain host.
    public var issuer: String
    public var keyId: String
    /// 32 bytes.
    public var publicKey: Data

    public init(issuer: String, keyId: String, publicKey: Data) {
        self.issuer = issuer
        self.keyId = keyId
        self.publicKey = publicKey
    }
}

/// Build-pinned Safe Action issuer keys. **Pinned keys only**: the app never fetches `/.well-known/ckey-safe-actions.json` (the spec prefers
/// pins for sign-in), so a network position or a compromised web host cannot introduce a key.
///
/// Wire form of the build setting `VIADERE_CKEY_SAFE_ACTION_KEYS` (Info.plist `ViadereCKeySafeActionKeys`): `keyId:publicKey`, comma
/// separated (a second entry during a rotation), where `publicKey` is 64 hex digits (what `ViadereServer ckey-safe-action-key` prints and
/// the key file serves) and `keyId` is the issuer's key id (`A-Z a-z 0-9 . _ -`, 1 to 32). The issuer is not part of the setting: it is the
/// build's link domain, so a pin can never vouch for another site. **All-or-nothing**: one malformed entry, an unexpanded `$(…)` or a
/// duplicate key id rejects the whole list. An empty list means every Safe Action is refused (`unknownKey`); the plain sign-in link and
/// the QR code are unaffected.
public enum SafeActionKeyPins {
    public static func parse(_ raw: String?, issuer: String) -> [PinnedSafeActionKey] {
        guard let raw, LinkDomain(issuer)?.host == issuer else { return [] }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.contains("$(") else { return [] }
        var keys: [PinnedSafeActionKey] = []
        for entry in trimmed.split(separator: ",", omittingEmptySubsequences: false) {
            let parts = entry.trimmingCharacters(in: .whitespaces).split(separator: ":", omittingEmptySubsequences: false).map(String.init)
            guard parts.count == 2, CKeySafeAction.isValid(Array(parts[0].utf8)[...], as: .keyId), let bytes = hex(parts[1]), bytes.count == 32,
                  (try? Curve25519.Signing.PublicKey(rawRepresentation: bytes)) != nil,
                  !keys.contains(where: { $0.keyId == parts[0] }) else { return [] }
            keys.append(PinnedSafeActionKey(issuer: issuer, keyId: parts[0], publicKey: bytes))
        }
        return keys
    }

    static func hex(_ text: String) -> Data? {
        let digits = Array(text.utf8)
        guard digits.count % 2 == 0 else { return nil }
        func value(_ c: UInt8) -> UInt8? {
            switch c {
            case 0x30...0x39: c - 0x30
            case 0x61...0x66: c - 0x61 + 10
            case 0x41...0x46: c - 0x41 + 10
            default: nil
            }
        }
        var out = Data(capacity: digits.count / 2)
        for index in stride(from: 0, to: digits.count, by: 2) {
            guard let high = value(digits[index]), let low = value(digits[index + 1]) else { return nil }
            out.append(high << 4 | low)
        }
        return out
    }
}

extension ViadereConfiguration {
    /// Reads `ViadereCKeySafeActionKeys` for this build's link domain. Called by `resolve(info:allowLocalHTTP:)` after the link domain is set.
    mutating func applySafeActionKeyPins(from info: [String: Any]) {
        safeActionKeys = SafeActionKeyPins.parse(info["ViadereCKeySafeActionKeys"] as? String, issuer: linkDomain.host)
    }
}
