import Crypto
import Foundation

/// RFC 4648 base32 (`A–Z`, `2–7`) as TOTP secrets are written. Decoding is tolerant of case, spaces and hyphens and of `=` padding, and
/// strict about everything else (a typo'd secret is an error, never a silently different secret).
public enum Base32 {
    private static let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".utf8)

    public static func encode(_ data: Data, padded: Bool = false) -> String {
        var out = [UInt8]()
        var buffer: UInt32 = 0
        var bits = 0
        for byte in data {
            buffer = buffer << 8 | UInt32(byte)
            bits += 8
            while bits >= 5 {
                out.append(alphabet[Int(buffer >> UInt32(bits - 5)) & 31])
                bits -= 5
            }
            buffer &= (1 << UInt32(bits)) - 1
        }
        if bits > 0 { out.append(alphabet[Int(buffer << UInt32(5 - bits)) & 31]) }
        if padded { while out.count % 8 != 0 { out.append(UInt8(ascii: "=")) } }
        return String(decoding: out, as: UTF8.self)
    }

    public static func decode(_ string: String) -> Data? {
        var body = Array(string.utf8).filter { $0 != UInt8(ascii: " ") && $0 != UInt8(ascii: "-") }
        while body.last == UInt8(ascii: "=") { body.removeLast() }
        guard !body.isEmpty else { return nil }
        var out = Data()
        var buffer: UInt32 = 0
        var bits = 0
        for char in body {
            let value: UInt32
            switch char {
            case UInt8(ascii: "A")...UInt8(ascii: "Z"): value = UInt32(char - UInt8(ascii: "A"))
            case UInt8(ascii: "a")...UInt8(ascii: "z"): value = UInt32(char - UInt8(ascii: "a"))
            case UInt8(ascii: "2")...UInt8(ascii: "7"): value = UInt32(char - UInt8(ascii: "2")) + 26
            default: return nil
            }
            buffer = buffer << 5 | value
            bits += 5
            if bits >= 8 {
                out.append(UInt8((buffer >> UInt32(bits - 8)) & 0xFF))
                bits -= 8
                buffer &= (1 << UInt32(bits)) - 1
            }
        }
        // Leftover bits must be zero padding (a base32 length of 1, 3 or 6 mod 8 never occurs in a valid encoding).
        guard bits < 5, buffer == 0 else { return nil }
        return out
    }
}

public enum TOTPAlgorithm: String, Codable, Sendable, CaseIterable {
    case sha1 = "SHA1", sha256 = "SHA256", sha512 = "SHA512"
}

/// A TOTP credential (RFC 6238 over HOTP, RFC 4226).
public struct TOTPParameters: Codable, Sendable, Equatable {
    public var secret: Data
    public var algorithm: TOTPAlgorithm
    public var digits: Int
    public var period: Int
    public var issuer: String?
    public var accountName: String

    public init(secret: Data, algorithm: TOTPAlgorithm = .sha1, digits: Int = 6, period: Int = 30, issuer: String? = nil, accountName: String) {
        self.secret = secret
        self.algorithm = algorithm
        self.digits = digits
        self.period = period
        self.issuer = issuer
        self.accountName = accountName
    }
}

public enum TOTPError: Error, Equatable, Sendable {
    case invalidSecret, invalidDigits, invalidPeriod, invalidAlgorithm
    case invalidURI(String)
}

public enum TOTP {
    /// Accepted secret sizes. RFC 4226 §4 requires at least 128 bits and recommends 160, but real services issue 80-bit secrets; 80 is the
    /// floor here and the ceiling bounds hostile input.
    public static let secretByteRange = 10...64
    public static let digitRange = 6...8
    public static let periodRange = 5...300

    public static func validate(_ p: TOTPParameters) throws {
        guard secretByteRange.contains(p.secret.count) else { throw TOTPError.invalidSecret }
        guard digitRange.contains(p.digits) else { throw TOTPError.invalidDigits }
        guard periodRange.contains(p.period) else { throw TOTPError.invalidPeriod }
    }

    /// RFC 4226 HOTP: HMAC over the 8-byte big-endian counter, dynamic truncation, `digits` decimal digits.
    public static func hotp(secret: Data, counter: UInt64, algorithm: TOTPAlgorithm = .sha1, digits: Int = 6) -> String {
        var message = Data(count: 8)
        for i in 0..<8 { message[7 - i] = UInt8((counter >> (8 * UInt64(i))) & 0xFF) }
        let key = SymmetricKey(data: secret)
        let mac: [UInt8]
        switch algorithm {
        case .sha1: mac = Array(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: key))
        case .sha256: mac = Array(HMAC<SHA256>.authenticationCode(for: message, using: key))
        case .sha512: mac = Array(HMAC<SHA512>.authenticationCode(for: message, using: key))
        }
        let offset = Int(mac[mac.count - 1] & 0x0F)
        let binary = (UInt32(mac[offset] & 0x7F) << 24) | (UInt32(mac[offset + 1]) << 16) | (UInt32(mac[offset + 2]) << 8) | UInt32(mac[offset + 3])
        var modulus: UInt32 = 1
        for _ in 0..<digits { modulus *= 10 }
        let value = String(binary % modulus)
        return String(repeating: "0", count: max(0, digits - value.count)) + value
    }

    /// The time-step counter `T = floor(unixTime / period)`.
    public static func counter(at date: Date, period: Int) -> UInt64 {
        UInt64(max(0, date.timeIntervalSince1970.rounded(.down))) / UInt64(max(1, period))
    }

    /// The current code. `parameters` must be valid (`validate`).
    public static func code(for p: TOTPParameters, at date: Date) -> String {
        hotp(secret: p.secret, counter: counter(at: date, period: p.period), algorithm: p.algorithm, digits: p.digits)
    }

    /// Whole seconds until the current code changes (1...period).
    public static func secondsRemaining(period: Int, at date: Date) -> Int {
        let p = max(1, period)
        // Int64: on watchOS (`arm64_32`) `Int` is 32-bit and Unix seconds pass Int32.max in 2038.
        let elapsed = Int(Int64(max(0, date.timeIntervalSince1970.rounded(.down))) % Int64(p))
        return p - elapsed
    }
}

/// `otpauth://totp/Issuer:account?secret=…&issuer=…&algorithm=…&digits=…&period=…` (the de-facto Key URI Format).
public enum OTPAuthURI {
    public static let maxLength = 2048
    public static let maxLabel = 256

    /// Strictly parses a TOTP key URI. HOTP (`otpauth://hotp`), other schemes, a missing or malformed secret, repeated parameters,
    /// out-of-range digits or period, unknown algorithms, control or invisible characters in the label and an issuer that contradicts
    /// the label prefix are all errors.
    public static func parse(_ string: String) throws -> TOTPParameters {
        let text = string.trimmingCharacters(in: .whitespacesAndNewlines)
        guard text.utf8.count <= maxLength else { throw TOTPError.invalidURI("too long") }
        guard let components = URLComponents(string: text), components.scheme?.lowercased() == "otpauth" else { throw TOTPError.invalidURI("scheme") }
        guard components.host?.lowercased() == "totp" else { throw TOTPError.invalidURI("type") }
        guard components.user == nil, components.password == nil, components.port == nil, components.fragment == nil else { throw TOTPError.invalidURI("authority") }

        var query: [String: String] = [:]
        for item in components.queryItems ?? [] {
            guard query[item.name.lowercased()] == nil else { throw TOTPError.invalidURI("repeated \(item.name)") }
            query[item.name.lowercased()] = item.value ?? ""
        }
        guard let rawSecret = query["secret"], let secret = Base32.decode(rawSecret) else { throw TOTPError.invalidSecret }

        let algorithm: TOTPAlgorithm
        if let raw = query["algorithm"] {
            guard let value = TOTPAlgorithm(rawValue: raw.uppercased()) else { throw TOTPError.invalidAlgorithm }
            algorithm = value
        } else { algorithm = .sha1 }
        func integer(_ name: String, default fallback: Int) throws -> Int {
            guard let raw = query[name] else { return fallback }
            guard !raw.isEmpty, raw.utf8.count <= 4, raw.allSatisfy({ $0.isASCII && $0.isNumber }), let value = Int(raw) else {
                throw name == "digits" ? TOTPError.invalidDigits : TOTPError.invalidPeriod
            }
            return value
        }
        let digits = try integer("digits", default: 6)
        let period = try integer("period", default: 30)

        // `URLComponents.path` is already percent-decoded.
        var label = components.path
        if label.hasPrefix("/") { label.removeFirst() }
        guard !label.isEmpty, label.count <= maxLabel else { throw TOTPError.invalidURI("label") }
        var labelIssuer: String?
        var account = label
        if let colon = label.firstIndex(of: ":") {
            labelIssuer = String(label[..<colon]).trimmingCharacters(in: .whitespaces)
            account = String(label[label.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
        }
        let issuerParameter = query["issuer"].flatMap { $0.isEmpty ? nil : $0 }
        if let labelIssuer, !labelIssuer.isEmpty, let issuerParameter, labelIssuer != issuerParameter {
            throw TOTPError.invalidURI("issuer mismatch")
        }
        let issuer = issuerParameter ?? labelIssuer.flatMap { $0.isEmpty ? nil : $0 }
        guard !account.isEmpty else { throw TOTPError.invalidURI("account") }
        for text in [account, issuer ?? ""] where DisplayTextSanitizer.containsDisallowedScalars(text) || text.count > maxLabel {
            throw TOTPError.invalidURI("characters")
        }
        let parameters = TOTPParameters(secret: secret, algorithm: algorithm, digits: digits, period: period, issuer: issuer, accountName: account)
        try TOTP.validate(parameters)
        return parameters
    }

    /// The URI for `parameters` (export, tests). The issuer is written both as the label prefix and as the parameter.
    public static func uri(for p: TOTPParameters) -> String {
        var allowed = CharacterSet.urlPathAllowed
        allowed.remove(charactersIn: ":/?#[]@")
        var label = p.accountName.addingPercentEncoding(withAllowedCharacters: allowed) ?? ""
        if let issuer = p.issuer, !issuer.isEmpty { label = (issuer.addingPercentEncoding(withAllowedCharacters: allowed) ?? "") + ":" + label }
        var out = "otpauth://totp/\(label)?secret=\(Base32.encode(p.secret))"
        if let issuer = p.issuer, !issuer.isEmpty {
            var q = CharacterSet.urlQueryAllowed
            q.remove(charactersIn: "&=+#")
            out += "&issuer=\(issuer.addingPercentEncoding(withAllowedCharacters: q) ?? "")"
        }
        out += "&algorithm=\(p.algorithm.rawValue)&digits=\(p.digits)&period=\(p.period)"
        return out
    }
}
