import Foundation

/// A permanent six-character business code, e.g. `AF2345`.
///
/// Normalization (`canonical`):
/// 1. Trim surrounding whitespace.
/// 2. Remove separators: space, `-`, `.`, `_`, and `/` (users type "AF-2345", "af 2345").
/// 3. Uppercase (ASCII only; any non-ASCII character is rejected).
/// 4. Map `I` → `1` and `O` → `0`. `L` stays distinct.
/// 5. Require exactly 6 characters from `[0-9A-Z]` minus `I`/`O`.
///
/// So `IO3456`, `io3456`, `1O-3456`, and `103456` are the same code; `L03456` is different.
/// Codes are never reassigned; the server enforces uniqueness on `canonical`.
public struct BusinessCode: Hashable, Sendable, Codable, CustomStringConvertible {
    /// Required length of a code.
    public static let length = 6

    /// Characters the generator emits: digits plus A–Z without `I`, `L`, `O`
    /// (`L` is excluded from *issuance* to avoid 1/L confusion, but remains valid input).
    public static let issuanceAlphabet: [Character] = Array("0123456789ABCDEFGHJKMNPQRSTUVWXYZ")

    /// Separator characters stripped from user input.
    public static let separators: Set<Character> = [" ", "-", ".", "_", "/", "\t"]

    /// Validation failures.
    public enum ValidationError: Error, Sendable, Equatable {
        case empty
        case invalidLength(Int)
        case invalidCharacter(Character)
    }

    /// Canonical 6-character form (uppercase, I→1, O→0). Store and compare this.
    public let canonical: String

    /// Parses and canonicalizes user input. Throws `ValidationError`.
    public init(_ input: String) throws {
        let trimmed = input.asciiTrimmed
        guard !trimmed.isEmpty else { throw ValidationError.empty }
        var out = ""
        for character in trimmed where !Self.separators.contains(character) {
            guard character.isASCII, let ascii = character.asciiValue else {
                throw ValidationError.invalidCharacter(character)
            }
            let upper = Character(Unicode.Scalar(ascii >= 97 && ascii <= 122 ? ascii - 32 : ascii))
            switch upper {
            case "I": out.append("1")
            case "O": out.append("0")
            case "0"..."9", "A"..."Z": out.append(upper)
            default: throw ValidationError.invalidCharacter(character)
            }
        }
        guard out.count == Self.length else { throw ValidationError.invalidLength(out.count) }
        canonical = out
    }

    /// Failable convenience initializer.
    public init?(parsing input: String) {
        guard let code = try? BusinessCode(input) else { return nil }
        self = code
    }

    /// True when `input` is a valid code (after normalization).
    public static func isValid(_ input: String) -> Bool { BusinessCode(parsing: input) != nil }

    /// Display form: two characters, hyphen, four characters (`AF-2345`).
    /// Reads well in print/voice and round-trips through parsing.
    public var display: String {
        let chars = Array(canonical)
        return String(chars[0..<2]) + "-" + String(chars[2...])
    }

    public var description: String { canonical }

    /// Generates a new random code from `issuanceAlphabet` using the system CSPRNG.
    /// The caller (server) must check uniqueness of `canonical` and retry on collision.
    public static func generate() -> BusinessCode {
        var rng = SystemRandomNumberGenerator()
        return generate(using: &rng)
    }

    /// Generates a code using the supplied generator (tests may inject a seeded one).
    public static func generate<G: RandomNumberGenerator>(using generator: inout G) -> BusinessCode {
        var out = ""
        for _ in 0..<length {
            let index = Int(generator.next(upperBound: UInt64(issuanceAlphabet.count)))
            out.append(issuanceAlphabet[index])
        }
        // Issuance alphabet is a subset of canonical characters, so this is already canonical.
        return BusinessCode(uncheckedCanonical: out)
    }

    private init(uncheckedCanonical: String) { canonical = uncheckedCanonical }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let string = try container.decode(String.self)
        do {
            try self.init(string)
        } catch {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid business code")
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(canonical)
    }
}
