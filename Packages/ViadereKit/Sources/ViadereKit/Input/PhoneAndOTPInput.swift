import Foundation
import ViadereCore

/// Phone entry: accepts `+14805550123`, `(480) 555-0123`, `480 555 0123`, `1-480-555-0123`.
/// Numbers without a `+` are assumed to be in the default country (the U.S. at launch).
public enum PhoneInput {
    public static func normalize(_ raw: String, defaultCountryCode: String = "1") -> PhoneNumber? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("+") { return PhoneNumber(trimmed) }
        let digits = trimmed.filter { $0.isASCII && $0.isNumber }
        if defaultCountryCode == "1" {
            if digits.count == 10 { return PhoneNumber("+1" + digits) }
            if digits.count == 11, digits.hasPrefix("1") { return PhoneNumber("+" + digits) }
            return nil
        }
        return PhoneNumber("+" + defaultCountryCode + digits)
    }

    /// Light U.S. grouping as the person types: `(480) 555-0123`. Non-U.S. (`+…`) input is left as typed.
    public static func displayFormat(_ raw: String) -> String {
        if raw.hasPrefix("+") { return raw }
        let digits = String(raw.filter { $0.isASCII && $0.isNumber }.prefix(10))
        var out = ""
        for (index, character) in digits.enumerated() {
            if index == 0 { out += "(" }
            if index == 3 { out += ") " }
            if index == 6 { out += "-" }
            out.append(character)
        }
        return out
    }
}

/// One-time code entry: digits only, six of them.
public enum OTPInput {
    public static let length = 6

    public static func normalize(_ raw: String) -> String {
        String(raw.filter { $0.isASCII && $0.isNumber }.prefix(length))
    }

    public static func isComplete(_ value: String) -> Bool { normalize(value).count == length }
}
