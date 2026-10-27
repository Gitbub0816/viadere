import Foundation

/// A public business handle such as `@starbucks`.
///
/// Rules:
/// - Input may include one leading `@` and surrounding whitespace; it is lowercased.
/// - ASCII only. Any non-ASCII scalar (Cyrillic `а`, full-width letters, zero-width
///   characters, …) is rejected outright, which removes the Unicode homoglyph class.
/// - 3–30 characters from `[a-z0-9_]`, starting with a letter, not ending with `_`,
///   no `__`.
/// - For registration only (`validateForRegistration`): not a reserved word, not
///   *confusable* with one (see `confusableSkeleton`), and never containing `viadere`.
///
/// The server must additionally reject a new handle whose `confusableSkeleton` equals the
/// skeleton of any existing handle (e.g. `@amaz0n` vs `@amazon`).
public struct BusinessHandle: Hashable, Sendable, Codable, CustomStringConvertible {
    public static let minLength = 3
    public static let maxLength = 30

    /// Words that may never be registered (also matched by skeleton).
    public static let reservedWords: Set<String> = [
        "viadere", "admin", "administrator", "root", "system", "support", "help", "info",
        "stop", "stopall", "unsubscribe", "cancel", "end", "quit", "start", "unstop", "yes", "no",
        "menu", "back", "optout", "revoke", "security", "official", "verify", "verified",
        "account", "accounts", "login", "signin", "signup", "settings", "billing", "abuse",
        "postmaster", "webmaster", "hostmaster", "staff", "team", "moderator", "api", "www",
        "mail", "sms", "null", "undefined", "apple", "trust", "safety", "fraud", "privacy",
    ]

    /// Validation failures.
    public enum ValidationError: Error, Sendable, Equatable {
        case empty
        case tooShort
        case tooLong
        case nonASCII
        case invalidCharacter(Character)
        case mustStartWithLetter
        case invalidUnderscore
        case reserved
        case confusableWithReserved(String)
    }

    /// Normalized handle without `@`.
    public let value: String

    /// Parses user input such as `"@Amazon"` or `" amazon "`.
    public init(_ input: String) throws {
        var body = Substring(input.asciiTrimmed)
        if body.hasPrefix("@") { body = body.dropFirst() }
        guard !body.isEmpty else { throw ValidationError.empty }
        guard body.unicodeScalars.allSatisfy(\.isASCII) else { throw ValidationError.nonASCII }
        let lowered = body.lowercased()
        guard lowered.count >= Self.minLength else { throw ValidationError.tooShort }
        guard lowered.count <= Self.maxLength else { throw ValidationError.tooLong }
        for character in lowered {
            switch character {
            case "a"..."z", "0"..."9", "_": continue
            default: throw ValidationError.invalidCharacter(character)
            }
        }
        guard let first = lowered.first, ("a"..."z").contains(first) else { throw ValidationError.mustStartWithLetter }
        guard !lowered.hasSuffix("_"), !lowered.contains("__") else { throw ValidationError.invalidUnderscore }
        value = lowered
    }

    /// Validates a handle for **registration**: structural rules plus reserved-word and
    /// confusable-with-reserved checks. Use this when a business claims a handle; use
    /// `init(_:)` for lookups and decoding (so adding a reserved word never breaks stored data).
    public static func validateForRegistration(_ input: String) throws -> BusinessHandle {
        let handle = try BusinessHandle(input)
        try handle.checkNotReserved()
        return handle
    }

    /// Throws `.reserved` / `.confusableWithReserved` if this handle may not be registered.
    public func checkNotReserved() throws {
        if Self.reservedWords.contains(value) || value.contains("viadere") { throw ValidationError.reserved }
        let skeleton = confusableSkeleton
        if skeleton.contains(Self.confusableSkeleton("viadere")) { throw ValidationError.confusableWithReserved("viadere") }
        if let match = Self.reservedSkeletons[skeleton] { throw ValidationError.confusableWithReserved(match) }
    }

    /// True when two handles would be visually confusable (equal skeletons).
    public func isConfusable(with other: BusinessHandle) -> Bool {
        confusableSkeleton == other.confusableSkeleton
    }

    /// Failable convenience initializer.
    public init?(parsing input: String) {
        guard let handle = try? BusinessHandle(input) else { return nil }
        self = handle
    }

    /// `@value`.
    public var display: String { "@" + value }
    public var description: String { display }

    /// The confusable skeleton used for collision checks. Maps visually similar ASCII
    /// sequences to one representative: `0→o`, `1/i/|→l`, `5→s`, `rn→m`, `vv→w`,
    /// `cl→d`, `3→e`, `8→b`, `_` removed.
    public var confusableSkeleton: String { Self.confusableSkeleton(value) }

    /// Skeleton for an arbitrary lowercase ASCII string.
    public static func confusableSkeleton(_ string: String) -> String {
        var s = string.lowercased().replacingOccurrences(of: "_", with: "")
        let multi: [(String, String)] = [("rn", "m"), ("vv", "w"), ("cl", "d")]
        for (from, to) in multi { s = s.replacingOccurrences(of: from, with: to) }
        let single: [Character: Character] = ["0": "o", "1": "l", "i": "l", "|": "l", "5": "s", "3": "e", "8": "b"]
        return String(s.map { single[$0] ?? $0 })
    }

    private static let reservedSkeletons: [String: String] = {
        var map: [String: String] = [:]
        for word in reservedWords { map[confusableSkeleton(word)] = word }
        return map
    }()

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let string = try container.decode(String.self)
        do {
            try self.init(string)
        } catch {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid business handle")
        }
    }

    /// Encodes as the bare lowercase handle without `@`.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(value)
    }
}
