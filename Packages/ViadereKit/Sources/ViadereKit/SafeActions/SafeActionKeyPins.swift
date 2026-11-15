import Crypto
import Foundation
import ViadereCore

/// An issuer key this build trusts for CKey Safe Actions (SECURITY.md §2.104 "Safe Actions"): ES256 (Viadere's issuer, the authority's
/// Key Vault key) or Ed25519, as the pin names it.
public struct PinnedSafeActionKey: Sendable, Equatable {
    /// The issuing site's DNS name: always this build's link-domain host.
    public var issuer: String
    public var keyId: String
    /// The key with its algorithm: the envelope does not name one, so the pin decides how it is verified.
    public var publicKey: CKeySafeAction.PublicKey

    public init(issuer: String, keyId: String, publicKey: CKeySafeAction.PublicKey) {
        self.issuer = issuer
        self.keyId = keyId
        self.publicKey = publicKey
    }
}

/// Build-pinned Safe Action issuer keys. **Pinned keys only**: the app never fetches `/.well-known/ckey-safe-actions.json` (the spec prefers
/// pins for sign-in), so a network position or a compromised web host cannot introduce a key.
///
/// Wire form of the build setting `VIADERE_CKEY_SAFE_ACTION_KEYS` (Info.plist `ViadereCKeySafeActionKeys`): `keyId:alg:publicKey`, comma
/// separated (a second entry during a rotation), exactly as `/.well-known/ckey-safe-actions.json` lists them: `keyId` is the issuer's key id
/// (`A-Z a-z 0-9 . _ -`, 1 to 32), `alg` is `ES256` (publicKey: SEC 1 hex, 66 digits compressed or 130 uncompressed, a point on P-256) or
/// `Ed25519` (64 hex digits). The issuer is not part of the setting: it is the
/// build's link domain, so a pin can never vouch for another site. **All-or-nothing**: one malformed entry, an unknown `alg`, a point off
/// the curve, an unexpanded `$(…)` or a duplicate key id rejects the whole list. An empty list means every Safe Action is refused (`unknownKey`); the plain sign-in link and
/// the QR code are unaffected.
public enum SafeActionKeyPins {
    public static func parse(_ raw: String?, issuer: String) -> [PinnedSafeActionKey] {
        guard let raw, LinkDomain(issuer)?.host == issuer else { return [] }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.contains("$(") else { return [] }
        var keys: [PinnedSafeActionKey] = []
        for entry in trimmed.split(separator: ",", omittingEmptySubsequences: false) {
            let parts = entry.trimmingCharacters(in: .whitespaces).split(separator: ":", omittingEmptySubsequences: false).map(String.init)
            guard parts.count == 3, CKeySafeAction.isValid(Array(parts[0].utf8)[...], as: .keyId),
                  let key = try? CKeySafeAction.PublicKey(alg: parts[1], hex: parts[2]),
                  !keys.contains(where: { $0.keyId == parts[0] }) else { return [] }
            keys.append(PinnedSafeActionKey(issuer: issuer, keyId: parts[0], publicKey: key))
        }
        return keys
    }
}

extension ViadereConfiguration {
    /// Reads `ViadereCKeySafeActionKeys` for this build's link domain. Called by `resolve(info:allowLocalHTTP:)` after the link domain is set.
    mutating func applySafeActionKeyPins(from info: [String: Any]) {
        safeActionKeys = SafeActionKeyPins.parse(info["ViadereCKeySafeActionKeys"] as? String, issuer: linkDomain.host)
    }
}
