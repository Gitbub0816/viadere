import Foundation

/// Phone-number ownership without SMS authentication (ADR-0027, owner decisions 1 and 9).
///
/// Viadere never texts a code or a link to prove a number. The app shows a server-issued nonce on a trusted device; the customer
/// sends it **from their phone** to the Viadere number (a customer-originated message, "MO") with a compose sheet that only the
/// person can send. The server binds the number to the account when an inbound message from that number carries the nonce within
/// `ttl`. The proof is *control of the number at that moment*, nothing more: it satisfies no `AssurancePolicy` level, is never an
/// authenticator and never raises device trust (`assuranceLabel`).
public enum PhoneLinkMO {
    /// Nonce prefix (`VDR-` + eight Crockford base32 characters = 40 bits).
    public static let prefix = "VDR-"
    /// Crockford base32 without I, L, O, U.
    public static let alphabet: [Character] = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
    public static let nonceLength = 8
    /// How long a begun link waits for the text.
    public static let ttl: TimeInterval = 10 * 60
    /// Assurance label recorded on a link proven this way: control of the number only.
    public static let assuranceLabel = "phone_control_mo"

    /// A new nonce from the system CSPRNG (32 symbols divide 256 evenly, so a byte modulo 32 is unbiased).
    public static func generateNonce() -> String {
        let bytes = SecureToken.randomBytes(nonceLength)
        return prefix + String(bytes.map { alphabet[Int($0) % alphabet.count] })
    }

    /// The text the compose sheet is pre-filled with (UX_COPY S-PH-02). It says what sending it does.
    public static func prefill(nonce: String) -> String { "Link my number to my Viadere app \(nonce)" }

    /// The nonce inside an inbound body: `VDR-` and eight characters, case-insensitive, whitespace-tolerant between the pieces, found
    /// anywhere in the message. Crockford confusions fold (I and L read as 1, O as 0). The match must not touch other letters or digits,
    /// so a longer token never yields a shorter match. Returns the canonical form, or nil.
    public static func extractNonce(from body: String) -> String? {
        let scalars = Array(body.uppercased().unicodeScalars)
        func isWord(_ s: Unicode.Scalar) -> Bool { (s.value >= 48 && s.value <= 57) || (s.value >= 65 && s.value <= 90) }
        func isSpace(_ s: Unicode.Scalar) -> Bool { CharacterSet.whitespacesAndNewlines.contains(s) }
        var i = 0
        while i < scalars.count {
            guard scalars[i] == "V", i == 0 || !isWord(scalars[i - 1]), i + 2 < scalars.count, scalars[i + 1] == "D", scalars[i + 2] == "R" else {
                i += 1
                continue
            }
            var j = i + 3
            while j < scalars.count, isSpace(scalars[j]) { j += 1 }
            guard j < scalars.count, scalars[j] == "-" else { i += 1; continue }
            j += 1
            var chars: [Character] = []
            while j < scalars.count, chars.count < nonceLength {
                let s = scalars[j]
                if isSpace(s) { j += 1; continue }
                guard isWord(s) else { break }
                chars.append(fold(Character(s)))
                j += 1
            }
            if chars.count == nonceLength, chars.allSatisfy({ alphabet.contains($0) }), j >= scalars.count || !isWord(scalars[j]) {
                return prefix + String(chars)
            }
            i += 1
        }
        return nil
    }

    private static func fold(_ c: Character) -> Character {
        switch c {
        case "I", "L": return "1"
        case "O": return "0"
        default: return c
        }
    }
}
