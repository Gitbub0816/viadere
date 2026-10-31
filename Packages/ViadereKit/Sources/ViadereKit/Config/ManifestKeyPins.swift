import Foundation
import ViadereCore

/// Build-pinned verification keys for v4 manifests (`brand-manifest`, `loop-publication`; SECURITY.md §2.92, §2.93).
///
/// Wire form of the build setting (Info.plist string, comma separated, the second entry during a rotation): `kid:publicKey`, where
/// `publicKey` is base64url X9.63 (65 bytes, a point on P-256) and `kid` is `KeyIdentifier` of that key (base64url SHA-256 of its SPKI;
/// what `ViadereServer brand-manifest-key` prints). A bare `publicKey` is accepted and its `kid` derived. **All-or-nothing:** one malformed
/// entry, a `kid` that does not match its key, an unexpanded `$(…)` or a duplicate rejects the whole list, so a half-configured pin set can
/// never look configured. An empty list means every manifest fails verification: Brand Kits render neutral, Loops show the safe fallback.
public enum ManifestKeyPins {
    public static func parse(_ raw: String?) -> [PinnedManifestKey] {
        guard let raw else { return [] }
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.contains("$(") else { return [] }
        var keys: [PinnedManifestKey] = []
        for entry in trimmed.split(separator: ",", omittingEmptySubsequences: false) {
            let item = entry.trimmingCharacters(in: .whitespaces)
            let parts = item.split(separator: ":", omittingEmptySubsequences: false).map(String.init)
            guard parts.count == 1 || parts.count == 2, let encoded = parts.last, let bytes = Base64URL.decode(encoded), bytes.count == 65,
                  let key = try? DevicePublicKey(bytes: bytes), let derived = try? KeyIdentifier.make(p256X963: bytes) else { return [] }
            if parts.count == 2, parts[0] != derived { return [] }
            guard !keys.contains(where: { $0.kid == derived }) else { return [] }
            keys.append(PinnedManifestKey(kid: derived, publicKey: key))
        }
        return keys
    }

    /// The Loop publication keys to verify with: the build pins, narrowed to those the server still lists (`GET /v1/loops/keys`) when that
    /// list is known. A key the server lists but the build does not pin is **never** trusted (a relay must not be able to vouch for itself);
    /// the server can only retire a pinned key early, never add one.
    public static func effectiveLoopKeys(pinned: [PinnedManifestKey], served: LoopPublicationKeySet?) -> [PinnedManifestKey] {
        guard let served else { return pinned }
        let listed = Set(served.keys.compactMap(\.pinned))
        return pinned.filter { listed.contains($0) }
    }
}

extension ViadereConfiguration {
    /// Reads `ViadereBrandManifestKeys` and `ViadereLoopPublicationKeys` (build settings `VIADERE_BRAND_MANIFEST_KEYS`,
    /// `VIADERE_LOOP_PUBLICATION_KEYS`). Called by `resolve(info:allowLocalHTTP:)`.
    mutating func applyManifestKeyPins(from info: [String: Any]) {
        brandManifestKeys = ManifestKeyPins.parse(info["ViadereBrandManifestKeys"] as? String)
        loopPublicationKeys = ManifestKeyPins.parse(info["ViadereLoopPublicationKeys"] as? String)
    }
}
