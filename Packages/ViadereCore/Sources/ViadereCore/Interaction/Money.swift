import Foundation

/// An ISO 4217 alphabetic currency code (three uppercase ASCII letters).
public struct CurrencyCode: Hashable, Sendable, Codable, CustomStringConvertible {
    public let value: String

    /// Validates and uppercases `code`.
    public init?(_ code: String) {
        let upper = code.uppercased()
        guard upper.count == 3, upper.unicodeScalars.allSatisfy({ ("A"..."Z").contains($0) }) else { return nil }
        value = upper
    }

    public var description: String { value }

    /// Minor-unit digits for common currencies (ISO 4217); defaults to 2.
    public var minorUnits: Int {
        switch value {
        case "JPY", "KRW", "VND", "CLP", "ISK", "UGX", "XAF", "XOF": 0
        case "BHD", "KWD", "OMR", "JOD", "TND", "LYD", "IQD": 3
        default: 2
        }
    }

    public static let usd = CurrencyCode(uncheckedValue: "USD")
    public static let eur = CurrencyCode(uncheckedValue: "EUR")

    private init(uncheckedValue: String) { value = uncheckedValue }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let raw = try container.decode(String.self)
        guard let code = CurrencyCode(raw) else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid currency code")
        }
        self = code
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(value)
    }
}

/// A monetary amount. Wire format: `{"value":"285.28","currency":"USD"}` — the value is a
/// decimal **string** so no binary floating point is ever involved.
public struct MoneyAmount: Hashable, Sendable, Codable {
    public enum ValidationError: Error, Sendable, Equatable {
        case negative
        case tooManyFractionDigits
        case malformed
    }

    public let value: Decimal
    public let currency: CurrencyCode

    /// Validates non-negativity and fraction digits against the currency's minor units.
    public init(_ value: Decimal, currency: CurrencyCode) throws {
        guard value >= 0 else { throw ValidationError.negative }
        guard Self.fractionDigits(of: value) <= currency.minorUnits else { throw ValidationError.tooManyFractionDigits }
        self.value = value
        self.currency = currency
    }

    /// Parses a decimal string such as `"285.28"`.
    public init(string: String, currency: CurrencyCode) throws {
        guard Self.isPlainDecimal(string), let decimal = Decimal(string: string, locale: Locale(identifier: "en_US_POSIX")) else {
            throw ValidationError.malformed
        }
        try self.init(decimal, currency: currency)
    }

    /// Plain decimal string with exactly `minorUnits` fraction digits, e.g. `"285.28"`.
    public var decimalString: String {
        var rounded = Decimal()
        var copy = value
        NSDecimalRound(&rounded, &copy, currency.minorUnits, .plain)
        let base = NSDecimalNumber(decimal: rounded).stringValue
        guard currency.minorUnits > 0 else { return base }
        let parts = base.split(separator: ".", omittingEmptySubsequences: false)
        let whole = String(parts[0])
        let fraction = parts.count > 1 ? String(parts[1]) : ""
        return whole + "." + fraction + String(repeating: "0", count: max(0, currency.minorUnits - fraction.count))
    }

    /// Human formatting, e.g. `$285.28`, `€12.00`, `1,000 JPY`-style fallback `12.00 CHF`.
    public var formatted: String {
        let symbols: [String: String] = ["USD": "$", "EUR": "€", "GBP": "£", "JPY": "¥", "CAD": "CA$", "AUD": "A$"]
        if let symbol = symbols[currency.value] { return symbol + decimalString }
        return decimalString + " " + currency.value
    }

    private enum CodingKeys: String, CodingKey { case value, currency }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let raw = try container.decode(String.self, forKey: .value)
        let currency = try container.decode(CurrencyCode.self, forKey: .currency)
        do {
            try self.init(string: raw, currency: currency)
        } catch {
            throw DecodingError.dataCorruptedError(forKey: .value, in: container, debugDescription: "Invalid amount")
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encode(decimalString, forKey: .value)
        try container.encode(currency, forKey: .currency)
    }

    static func isPlainDecimal(_ s: String) -> Bool {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard (1...2).contains(parts.count), !parts[0].isEmpty, parts[0].count <= 15 else { return false }
        guard parts.allSatisfy({ $0.allSatisfy { $0.isASCII && $0.isNumber } }) else { return false }
        if parts.count == 2 && parts[1].isEmpty { return false }
        return true
    }

    static func fractionDigits(of value: Decimal) -> Int {
        let s = NSDecimalNumber(decimal: value).stringValue
        guard let dot = s.firstIndex(of: ".") else { return 0 }
        return s.distance(from: s.index(after: dot), to: s.endIndex)
    }
}
