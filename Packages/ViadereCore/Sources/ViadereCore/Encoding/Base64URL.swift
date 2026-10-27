import Foundation

/// Base64url (RFC 4648 §5) without padding.
public enum Base64URL {
    /// Encodes bytes as unpadded base64url.
    public static func encode<D: DataProtocol>(_ data: D) -> String {
        Data(data).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    /// Decodes unpadded (or padded) base64url. Returns `nil` on any invalid character.
    /// Standard-alphabet characters (`+`, `/`) are rejected so each value has one encoding.
    public static func decode(_ string: String) -> Data? {
        guard !string.isEmpty else { return Data() }
        var body = Substring(string)
        while body.hasSuffix("=") { body = body.dropLast() }
        for scalar in body.unicodeScalars {
            switch scalar {
            case "A"..."Z", "a"..."z", "0"..."9", "-", "_": continue
            default: return nil
            }
        }
        if body.count % 4 == 1 { return nil }
        var base64 = body.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        let remainder = base64.count % 4
        if remainder > 0 { base64 += String(repeating: "=", count: 4 - remainder) }
        return Data(base64Encoded: base64)
    }

    /// True when `string` is non-empty, unpadded base64url within the given length bounds.
    public static func isValid(_ string: String, minLength: Int = 1, maxLength: Int = .max) -> Bool {
        guard string.count >= minLength, string.count <= maxLength else { return false }
        return string.unicodeScalars.allSatisfy { scalar in
            switch scalar {
            case "A"..."Z", "a"..."z", "0"..."9", "-", "_": return true
            default: return false
            }
        }
    }
}

/// Lowercase hexadecimal helpers.
public enum Hex {
    private static let digits = Array("0123456789abcdef".utf8)

    /// Encodes bytes as lowercase hex.
    public static func encode<D: Sequence>(_ bytes: D) -> String where D.Element == UInt8 {
        var out = [UInt8]()
        for byte in bytes {
            out.append(digits[Int(byte >> 4)])
            out.append(digits[Int(byte & 0x0F)])
        }
        return String(decoding: out, as: UTF8.self)
    }

    /// Decodes hex (either case). Returns `nil` for odd length or invalid characters.
    public static func decode(_ string: String) -> Data? {
        let utf8 = Array(string.utf8)
        guard utf8.count % 2 == 0 else { return nil }
        var out = Data(capacity: utf8.count / 2)
        var index = 0
        while index < utf8.count {
            guard let high = nibble(utf8[index]), let low = nibble(utf8[index + 1]) else { return nil }
            out.append(high << 4 | low)
            index += 2
        }
        return out
    }

    private static func nibble(_ char: UInt8) -> UInt8? {
        switch char {
        case UInt8(ascii: "0")...UInt8(ascii: "9"): return char - UInt8(ascii: "0")
        case UInt8(ascii: "a")...UInt8(ascii: "f"): return char - UInt8(ascii: "a") + 10
        case UInt8(ascii: "A")...UInt8(ascii: "F"): return char - UInt8(ascii: "A") + 10
        default: return nil
        }
    }
}
