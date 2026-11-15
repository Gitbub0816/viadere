import Foundation
import ViadereCore

/// Opaque, signed, single-use RCS postback tokens: `vrp1.{43 chars CSPRNG}.{32 hex MAC}`.
///
/// * **Opaque** — 256 random bits, no interaction id, option id or decision inside.
/// * **Signed** — the suffix is a truncated keyed HMAC (server pepper) of the random part, so malformed or
///   forged postbacks are rejected before any database lookup.
/// * **Single use** — only the SHA-256 of the whole token is stored; consuming it is a compare-and-swap.
/// The token is *not* authentication of the user: an RCS postback is an unauthenticated reply at best
/// (`ProvidedAssurance.unauthenticatedReply`), which is why `AssurancePolicy` decides what it may satisfy.
struct RCSPostbackTokens {
    static let prefix = "vrp1."
    static let maxLength = 96
    let hasher: Hasher256

    func mint() -> String {
        let random = SecureToken.generate(byteCount: 32)
        return Self.prefix + random + "." + mac(random)
    }

    /// Structure and MAC check only (no database).
    func isWellFormed(_ token: String) -> Bool {
        guard token.count <= Self.maxLength, token.hasPrefix(Self.prefix) else { return false }
        let parts = token.dropFirst(Self.prefix.count).split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 2, parts[0].count == 43, parts[1].count == 32, Base64URL.isValid(String(parts[0]), minLength: 43, maxLength: 43)
        else { return false }
        return ConstantTime.equals(String(parts[1]), mac(String(parts[0])))
    }

    static func storedHash(_ token: String) -> String { SecureToken.hash(token) }

    private func mac(_ random: String) -> String { String(hasher.hmacHex("rcs-postback", random).prefix(32)) }
}
