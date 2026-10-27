import Foundation

/// SMS character-set and segmentation analysis (GSM 03.38 vs UCS-2).
public enum SMSEncoding {
    /// Encoding an SMS will use.
    public enum Kind: String, Sendable, Codable { case gsm7, ucs2 }

    /// Result of analysing a message body.
    public struct Info: Sendable, Hashable, Codable {
        public var kind: Kind
        /// Septets (GSM-7, extension characters count 2) or UTF-16 code units (UCS-2).
        public var units: Int
        public var segments: Int
    }

    static let basic: Set<Character> = Set(
        "@£$¥èéùìòÇ\nØø\rÅåΔ_ΦΓΛΩΠΨΣΘΞÆæßÉ !\"#¤%&'()*+,-./0123456789:;<=>?¡ABCDEFGHIJKLMNOPQRSTUVWXYZÄÖÑÜ§¿abcdefghijklmnopqrstuvwxyzäöñüà"
    )
    static let extended: Set<Character> = Set("^{}\\[~]|€\u{0C}")

    /// Single-segment and per-segment (concatenated) capacities.
    public static let gsm7Single = 160, gsm7Concatenated = 153, ucs2Single = 70, ucs2Concatenated = 67

    /// Whether `text` fits the GSM-7 alphabet.
    public static func isGSM7(_ text: String) -> Bool {
        text.allSatisfy { basic.contains($0) || extended.contains($0) }
    }

    /// Analyses `text`.
    public static func analyze(_ text: String) -> Info {
        if isGSM7(text) {
            let units = text.reduce(0) { $0 + (extended.contains($1) ? 2 : 1) }
            let segments = units == 0 ? 1 : units <= gsm7Single ? 1 : Int((Double(units) / Double(gsm7Concatenated)).rounded(.up))
            return Info(kind: .gsm7, units: units, segments: segments)
        }
        let units = text.utf16.count
        let segments = units <= ucs2Single ? 1 : Int((Double(units) / Double(ucs2Concatenated)).rounded(.up))
        return Info(kind: .ucs2, units: units, segments: segments)
    }

    /// Replaces common typographic characters with GSM-7 equivalents (smart quotes, dashes,
    /// ellipsis, non-breaking spaces, bullets) so ordinary copy stays in GSM-7.
    public static func gsmFriendly(_ text: String) -> String {
        let map: [Character: String] = [
            "\u{2018}": "'", "\u{2019}": "'", "\u{201A}": "'", "\u{201B}": "'",
            "\u{201C}": "\"", "\u{201D}": "\"", "\u{201E}": "\"",
            "\u{2013}": "-", "\u{2014}": "-", "\u{2212}": "-",
            "\u{2026}": "...", "\u{00A0}": " ", "\u{2022}": "-", "\u{00B7}": "-",
        ]
        var out = ""
        for c in text { out += map[c] ?? String(c) }
        return out
    }

    /// Removes characters that can visually spoof content: C0/C1 controls (except `\n`),
    /// bidi overrides/isolates, zero-width characters, and the BOM.
    public static func stripSpoofingCharacters(_ text: String, allowNewlines: Bool) -> String {
        var scalars = String.UnicodeScalarView()
        for scalar in text.unicodeScalars {
            let v = scalar.value
            if scalar == "\n" { if allowNewlines { scalars.append(scalar) } else { scalars.append(" ") }; continue }
            if v < 0x20 || (0x7F...0x9F).contains(v) { continue }
            if (0x202A...0x202E).contains(v) || (0x2066...0x2069).contains(v) || v == 0x200E || v == 0x200F { continue }
            if (0x200B...0x200D).contains(v) || v == 0x2060 || v == 0xFEFF { continue }
            scalars.append(scalar)
        }
        return String(scalars)
    }

    /// Single-line, spoof-stripped, whitespace-collapsed, length-capped field text.
    public static func field(_ text: String, maxLength: Int) -> String {
        let cleaned = stripSpoofingCharacters(gsmFriendly(text), allowNewlines: false)
        let collapsed = cleaned.split(whereSeparator: { $0 == " " || $0 == "\t" }).joined(separator: " ")
        if collapsed.count <= maxLength { return collapsed }
        return String(collapsed.prefix(max(0, maxLength - 3))) + "..."
    }
}
