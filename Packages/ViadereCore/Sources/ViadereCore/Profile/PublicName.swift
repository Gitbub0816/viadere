import Foundation

/// The customer's **public name** (docs/PROFILES.md §Public name): the one piece of the profile every connected business receives, with the
/// relationship, next to the `subjectRef`. It is not treated as private.
///
/// Default: the first name plus the last initial (`"John D."`), derived from the name the customer entered (profile first and last name,
/// else the account display name). The customer may set a custom public name instead; it must pass the display-text rules (no hostile
/// characters, length limits, no "Viadere") and must not pose as staff, a verification status or contact data.
public enum PublicName {
    public static let maxCharacters = 32
    public static let minCharacters = 2

    /// Words that would make a name read as an official or platform voice (compared on the confusable skeleton of each word).
    public static let reservedWords: Set<String> = ["support", "admin", "administrator", "official", "verified", "security", "staff", "moderator",
                                                    "helpdesk", "system", "team", "service", "fraud", "bank", "customer care"]

    public enum Issue: String, Sendable, Codable, Hashable, Error {
        case empty, tooShort = "too_short", tooLong = "too_long", disallowedCharacters = "disallowed_characters", impersonation
        /// Looks like contact data or an identifier (an e-mail, a link, a phone or card number).
        case contactData = "contact_data"
    }

    /// `"First L."` from a first and last name; the first name alone when there is no last name. `nil` when nothing usable remains.
    public static func derive(givenName: String?, familyName: String?) -> String? {
        let given = clean(givenName ?? "").split(separator: " ").first.map(String.init) ?? ""
        let family = clean(familyName ?? "")
        guard !given.isEmpty else { return nil }
        var name = given
        if let initial = family.first(where: { $0.isLetter }) { name += " " + String(initial).uppercased() + "." }
        let result = truncate(name)
        return validate(result) == nil ? result : nil
    }

    /// The default from a single full name ("John Doe" -> "John D.", "Cher" -> "Cher").
    public static func derive(fullName: String?) -> String? {
        let parts = clean(fullName ?? "").split(separator: " ").map(String.init)
        guard let first = parts.first else { return nil }
        return derive(givenName: first, familyName: parts.count > 1 ? parts.last : nil)
    }

    /// The name businesses receive: the custom name when set, else the derived default.
    public static func effective(custom: String?, givenName: String?, familyName: String?, accountName: String?) -> String? {
        if let custom, !custom.isEmpty { return custom }
        return derive(givenName: givenName, familyName: familyName) ?? derive(fullName: accountName)
    }

    /// Trimmed, whitespace collapsed.
    public static func clean(_ text: String) -> String {
        text.split(whereSeparator: { $0.isWhitespace }).joined(separator: " ")
    }

    private static func truncate(_ text: String) -> String {
        DisplayTextSanitizer.isWithinLimits(text, maxCharacters: maxCharacters) ? text : DisplayTextSanitizer.sanitize(text, maxCharacters: maxCharacters)
    }

    /// Why `name` cannot be a public name, or `nil`. Validate the **cleaned** form (`clean`); hostile scalars are refused before cleaning.
    public static func validate(_ name: String) -> Issue? {
        if DisplayTextSanitizer.containsDisallowedScalars(name) { return .disallowedCharacters }
        let cleaned = clean(name)
        if cleaned.isEmpty { return .empty }
        if !DisplayTextSanitizer.isWithinLimits(cleaned, maxCharacters: maxCharacters) { return .tooLong }
        if cleaned.count < minCharacters { return .tooShort }
        if DisplayTextSanitizer.impersonatesViadere(cleaned, anywhere: true) { return .impersonation }
        let lower = cleaned.lowercased()
        if lower.contains("@") || lower.contains("://") || lower.contains("www.") || lower.contains(".com") { return .contactData }
        if cleaned.filter({ $0.isNumber }).count >= 5 || ProfileCatalog.looksLikeForbiddenIdentifier(cleaned) { return .contactData }
        let words = lower.split(whereSeparator: { !$0.isLetter && !$0.isNumber }).map { BusinessHandle.confusableSkeleton(String($0)) }
        let reserved = Set(reservedWords.map { BusinessHandle.confusableSkeleton($0.replacingOccurrences(of: " ", with: "")) })
        if words.contains(where: { reserved.contains($0) }) { return .impersonation }
        let joined = BusinessHandle.confusableSkeleton(words.joined())
        if reserved.contains(where: { $0.count >= 6 && joined.contains($0) }) { return .impersonation }
        return nil
    }
}
