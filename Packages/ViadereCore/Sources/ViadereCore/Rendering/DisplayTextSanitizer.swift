import Foundation

/// Shared handling of **business-supplied display text**: the strings an approval screen, notification, SMS or
/// watch face shows next to a security decision ("Sign-in to {service}", "Pay {merchant}", ...).
///
/// The server uses `validate` to *reject* hostile text when a business submits it, and every client presenter uses
/// `sanitize` as a second line of defence (a business could have been compromised, or an older server stored the
/// text before the rules existed). Both share one definition of "hostile":
///
/// * **Invisible or reordering characters**: bidirectional controls (U+202A–202E, U+2066–2069, U+200E/F, U+061C),
///   zero-width characters (U+200B–200D, U+2060, U+FEFF), U+180E, soft hyphen, tag characters, Hangul/Braille fillers,
///   the combining grapheme joiner, variation selectors other than the emoji pair, invisible math operators.
///   In general: every control, format, line/paragraph separator, private-use and unassigned scalar.
/// * **Line breaks** (including U+0085, U+2028, U+2029), which let text forge a second "line" such as an
///   `Amount:` row. They are only allowed in long free-text fields, and clients collapse them to spaces.
/// * **Size**: grapheme count *and* unicode-scalar count *and* UTF-8 byte count are capped (a zalgo string is one
///   grapheme per base letter but hundreds of scalars).
/// * **Impersonating Viadere**: display strings that start with (or, for identity fields, contain) the brand —
///   after normalising width, case, homoglyphs and punctuation — could pass as a message from the platform.
public enum DisplayTextSanitizer {
    /// A scalar budget of `scalarsPerCharacter` and a byte budget of `bytesPerCharacter` per permitted character.
    public static let scalarsPerCharacter = 2
    public static let bytesPerCharacter = 4

    /// Why a text was rejected.
    public enum Violation: String, Sendable, Hashable, Codable {
        case disallowedCharacters, tooLong, impersonation
    }

    // MARK: Scalars

    private static let invisibleLookalikes: Set<UInt32> = [
        0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x2800, 0x3164, 0xFFA0,
    ]

    /// Whether `scalar` may never appear in display text. `allowNewlines` permits a plain line feed.
    public static func isDisallowed(_ scalar: Unicode.Scalar, allowNewlines: Bool = false) -> Bool {
        if scalar == "\n" { return !allowNewlines }
        let value = scalar.value
        if invisibleLookalikes.contains(value) { return true }
        if (0x180B...0x180D).contains(value) || (0xE0100...0xE01EF).contains(value) { return true }
        // Variation selectors: only the emoji text/presentation pair is useful.
        if (0xFE00...0xFE0F).contains(value) { return value != 0xFE0E && value != 0xFE0F }
        switch scalar.properties.generalCategory {
        case .control, .format, .lineSeparator, .paragraphSeparator, .privateUse, .surrogate, .unassigned: return true
        default: return false
        }
    }

    /// True when `text` contains a scalar that `isDisallowed`.
    public static func containsDisallowedScalars(_ text: String, allowNewlines: Bool = false) -> Bool {
        text.unicodeScalars.contains { isDisallowed($0, allowNewlines: allowNewlines) }
    }

    // MARK: Size

    /// Whether `text` fits `maxCharacters` graphemes and the derived scalar and UTF-8 byte budgets.
    public static func isWithinLimits(_ text: String, maxCharacters: Int) -> Bool {
        text.count <= maxCharacters
            && text.unicodeScalars.count <= maxCharacters * scalarsPerCharacter
            && text.utf8.count <= maxCharacters * bytesPerCharacter
    }

    // MARK: Impersonation

    private static let homoglyphs: [Character: Character] = [
        // Cyrillic and Greek lookalikes of the letters in the brand (and of common Latin letters).
        "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "у": "y", "х": "x", "і": "i", "ј": "j", "ѵ": "v", "ԁ": "d", "ɡ": "g",
        "ᴠ": "v", "ɪ": "i", "ᴅ": "d", "ᴇ": "e", "ʀ": "r", "ᴀ": "a",
        "α": "a", "ε": "e", "ι": "i", "ο": "o", "ν": "v", "ρ": "p", "υ": "u", "κ": "k", "τ": "t",
    ]

    /// Letters and digits of `text` reduced to a width-, case- and homoglyph-insensitive skeleton.
    private static func skeleton(of text: String) -> String {
        var letters = ""
        for scalar in text.decomposedStringWithCompatibilityMapping.unicodeScalars {
            if isDisallowed(scalar, allowNewlines: true) { continue }
            // Combining marks add nothing visible to the base letter.
            if scalar.properties.generalCategory == .nonspacingMark || scalar.properties.generalCategory == .enclosingMark { continue }
            for character in String(scalar).lowercased() {
                let mapped = homoglyphs[character] ?? character
                if mapped.isLetter || mapped.isNumber { letters.append(mapped) }
            }
        }
        return BusinessHandle.confusableSkeleton(letters)
    }

    private static let brandSkeleton = BusinessHandle.confusableSkeleton("viadere")

    /// Whether `text` looks like it comes from Viadere itself: it *starts with* the brand ("Viadere: ...",
    /// "[V.I.A.D.E.R.E] ..."), or, with `anywhere`, mentions it at all (use for names: service, merchant, titles).
    public static func impersonatesViadere(_ text: String, anywhere: Bool = false) -> Bool {
        let reduced = skeleton(of: text)
        return anywhere ? reduced.contains(brandSkeleton) : reduced.hasPrefix(brandSkeleton)
    }

    // MARK: Validation (server) and presentation (clients)

    /// Returns why `text` must be rejected, or `nil` when it is acceptable display text.
    public static func violation(of text: String, maxCharacters: Int, allowNewlines: Bool = false, identity: Bool = false) -> Violation? {
        if containsDisallowedScalars(text, allowNewlines: allowNewlines) { return .disallowedCharacters }
        if !isWithinLimits(text, maxCharacters: maxCharacters) { return .tooLong }
        if impersonatesViadere(text, anywhere: identity) { return .impersonation }
        return nil
    }

    /// Cleans text for display: drops disallowed scalars, collapses every line break and run of whitespace to one
    /// space (unless `allowNewlines`, which keeps single `\n` separators), trims, and truncates with an ellipsis so the
    /// grapheme, scalar and byte caps hold.
    public static func sanitize(_ text: String, maxCharacters: Int, allowNewlines: Bool = false) -> String {
        var cleaned = String.UnicodeScalarView()
        for scalar in text.unicodeScalars {
            switch scalar {
            case "\n", "\r", "\t", "\u{0B}", "\u{0C}", "\u{85}", "\u{2028}", "\u{2029}":
                cleaned.append(scalar == "\n" && allowNewlines ? "\n" : " ")
            default:
                if !isDisallowed(scalar, allowNewlines: false) { cleaned.append(scalar) }
            }
        }
        var lines: [String] = []
        for line in String(cleaned).split(separator: "\n", omittingEmptySubsequences: allowNewlines ? false : true) {
            lines.append(line.split(whereSeparator: { $0 == " " || $0.isWhitespace }).joined(separator: " "))
        }
        var collapsed = lines.joined(separator: allowNewlines ? "\n" : " ").trimmingCharacters(in: .whitespacesAndNewlines)
        if isWithinLimits(collapsed, maxCharacters: maxCharacters) { return collapsed }
        var kept = String(collapsed.prefix(max(0, maxCharacters - 1)))
        while !isWithinLimits(kept + "…", maxCharacters: maxCharacters) && !kept.isEmpty { kept.removeLast() }
        collapsed = kept + "…"
        return collapsed
    }
}
