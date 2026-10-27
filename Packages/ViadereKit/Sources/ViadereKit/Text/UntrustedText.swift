import Foundation
import ViadereCore

/// The single presenter-side sanitizer for **business-supplied strings** (names, merchants, services, locations,
/// descriptions, labels...). Every client surface that shows such text (the Face ID prompt, the approval sheet,
/// notification banners and cards, the watch list, Live Activities) goes through here, so one rule set decides
/// what can reach a person's eyes. The server rejects the same characters at the boundary; this is the
/// defence in depth for data that predates the check or arrives through another channel.
///
/// What it does, in order:
/// 1. Drops invisible and reordering characters: all bidi controls (U+200E/F, U+202A-E, U+2066-9, **U+061C**),
///    zero-width characters (U+200B-D, U+2060-4, U+FEFF), the Mongolian vowel separator **U+180E** and free
///    variation selectors, soft hyphen, invisible fillers, interlinear annotations, tag characters, other
///    format (Cf), private-use, surrogate and unassigned scalars, and every control character.
/// 2. Turns every kind of line break and space (CR, LF, NEL, U+2028/9, tab, no-break and wide spaces) into one
///    plain space and collapses runs, so text can never start a new line or fake a table row.
/// 3. Limits stacked combining marks (so "zalgo" text cannot overflow its line).
/// 4. Caps the length in characters with an ellipsis. Callers cap each free-text piece on its own and put
///    money first, so truncating a long merchant can never hide the amount.
public enum UntrustedText {
    public static let ellipsis = "\u{2026}"
    /// Hard bound on how much of any input is even examined.
    static let maxInputScalars = 4_096
    static let maxStackedMarks = 2

    // MARK: Single-line text

    /// Sanitized, single-line text with no length cap.
    public static func clean(_ text: String) -> String {
        var out = String.UnicodeScalarView()
        var pendingSpace = false
        var marks = 0
        for scalar in text.unicodeScalars.prefix(maxInputScalars) {
            switch classify(scalar) {
            case .drop:
                continue
            case .space:
                pendingSpace = !out.isEmpty
                marks = 0
            case .mark:
                if out.isEmpty || pendingSpace { continue } // a mark with no base
                marks += 1
                if marks <= maxStackedMarks { out.append(scalar) }
            case .keep:
                if pendingSpace { out.append(" "); pendingSpace = false }
                marks = 0
                out.append(scalar)
            }
        }
        return String(out)
    }

    /// Sanitized, single-line text capped at `max` characters (ellipsis included).
    public static func line(_ text: String, max: Int) -> String {
        truncate(clean(text), max: max)
    }

    /// Like `line`, but `nil` when there is no text or nothing printable is left (so empty rows are omitted).
    public static func optionalLine(_ text: String?, max: Int) -> String? {
        guard let text else { return nil }
        let value = line(text, max: max)
        return value.isEmpty ? nil : value
    }

    // MARK: Paragraphs (consent documents, long details)

    /// Like `line` but keeps up to one blank line between paragraphs. Used only where text is long-form and
    /// not placed next to labelled facts (acknowledgment bodies). Never contains controls, bidi or zero-width.
    public static func paragraphs(_ text: String, max: Int) -> String {
        let normalized = String(String.UnicodeScalarView(text.unicodeScalars.prefix(maxInputScalars).map { scalar in
            switch scalar.value {
            case 0x0D, 0x85, 0x2028, 0x2029: "\n"
            default: scalar
            }
        }))
        let parts = normalized.split(separator: "\n", omittingEmptySubsequences: false).map { clean(String($0)) }
        var lines: [String] = []
        for part in parts {
            if part.isEmpty {
                if let last = lines.last, !last.isEmpty { lines.append("") }
            } else {
                lines.append(part)
            }
        }
        while lines.last?.isEmpty == true { lines.removeLast() }
        return truncate(lines.joined(separator: "\n"), max: max)
    }

    static func truncate(_ text: String, max: Int) -> String {
        guard max > 0 else { return "" }
        if text.count <= max { return text }
        guard max > 1 else { return ellipsis }
        var head = String(text.prefix(max - 1))
        while head.last == " " { head.removeLast() }
        return head + ellipsis
    }

    // MARK: Entities (names that people might mistake for Viadere itself)

    /// Display text for a name the business chose (its own name, a merchant, a service).
    public struct SafeName: Sendable, Equatable {
        /// What to display.
        public var text: String
        /// True when the raw name looks like "Viadere" (including look-alikes such as "V1adere Secur1ty").
        public var impersonatesViadere: Bool
    }

    /// Sanitizes a business-chosen name. A name that spells or imitates "Viadere" is shown **quoted and
    /// attributed** (`Business "Viadere Security"`) so it can never read as a message from the app itself.
    public static func name(_ raw: String, max: Int = 40, attribution: String? = "Business") -> SafeName {
        let cleaned = line(raw, max: max)
        let shown = cleaned.isEmpty ? "Unnamed business" : cleaned
        guard looksLikeViadere(raw) else { return SafeName(text: shown, impersonatesViadere: false) }
        let quoted = "\u{201C}\(shown)\u{201D}"
        return SafeName(text: attribution.map { "\($0) \(quoted)" } ?? quoted, impersonatesViadere: true)
    }

    /// Whether `raw` contains "viadere" after removing separators and folding case, width, accents and
    /// common look-alikes (digits for letters, Cyrillic and Greek homoglyphs).
    public static func looksLikeViadere(_ raw: String) -> Bool {
        skeleton(raw).contains("viadere")
    }

    static func skeleton(_ raw: String) -> String {
        let folded = String(raw.unicodeScalars.prefix(maxInputScalars))
            .precomposedStringWithCompatibilityMapping
            .folding(options: [.caseInsensitive, .diacriticInsensitive], locale: nil)
        var out = ""
        for scalar in folded.unicodeScalars {
            if classify(scalar) != .keep && classify(scalar) != .mark { continue } // drop invisibles and spaces
            if let mapped = confusables[scalar.value] { out += mapped; continue }
            if scalar.isASCII, scalar.properties.isAlphabetic { out += String(scalar).lowercased(); continue }
            if scalar.isASCII, scalar.properties.numericType != nil { out += String(scalar); continue }
            // Other scripts: keep letters/digits (so unrelated text is not collapsed into matches).
            if scalar.properties.isAlphabetic || scalar.properties.numericType != nil { out += String(scalar).lowercased() }
        }
        return out
    }

    private static let confusables: [UInt32: String] = [
        0x30: "o", 0x31: "i", 0x33: "e", 0x34: "a", 0x35: "s", 0x37: "t", 0x6C: "i", // 0 1 3 4 5 7 l
        0x40: "a", 0x24: "s", 0x21: "i", 0x7C: "i",
        0x430: "a", 0x435: "e", 0x43E: "o", 0x440: "p", 0x441: "c", 0x445: "x", 0x456: "i", 0x475: "v", 0x501: "d", 0x4CF: "i", // Cyrillic
        0x3B1: "a", 0x3B5: "e", 0x3BF: "o", 0x3BD: "v", 0x3B9: "i", 0x3C1: "p", // Greek
        0x131: "i", 0x2170: "i", 0x2171: "i", 0x2174: "v",
    ]

    // MARK: Scalar classification

    enum ScalarClass { case keep, mark, space, drop }

    static func classify(_ scalar: Unicode.Scalar) -> ScalarClass {
        let v = scalar.value
        switch v {
        case 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x20, 0x85, 0xA0, 0x1680, 0x2000...0x200A, 0x2028, 0x2029, 0x202F, 0x205F, 0x3000:
            return .space
        case 0x00...0x1F, 0x7F...0x9F: // controls
            return .drop
        case 0x061C, 0x180B...0x180F, 0x00AD, 0x034F, 0x115F, 0x1160, 0x17B4, 0x17B5, 0x3164, 0xFFA0, 0x2800: // fillers, ALM, MVS, soft hyphen
            return .drop
        case 0x200B...0x200F, 0x202A...0x202E, 0x2060...0x206F, 0xFEFF, 0xFFF9...0xFFFC, 0xFE00...0xFE0D, 0xE0000...0xE0FFF:
            return .drop // zero-width, bidi, invisible operators, annotations, variation selectors, tags
        default:
            break
        }
        switch scalar.properties.generalCategory {
        case .control, .format, .surrogate, .privateUse, .unassigned, .lineSeparator, .paragraphSeparator:
            return .drop
        case .spaceSeparator:
            return .space
        case .nonspacingMark, .enclosingMark:
            return .mark
        default:
            return .keep
        }
    }
}

// MARK: - Business convenience

extension BusinessSummary {
    /// Sanitized, impersonation-safe display name.
    public var safeName: String { UntrustedText.name(displayName).text }
    public var safeNameInfo: UntrustedText.SafeName { UntrustedText.name(displayName) }
}

extension BusinessProfile {
    public var safeName: String { UntrustedText.name(displayName).text }
}
