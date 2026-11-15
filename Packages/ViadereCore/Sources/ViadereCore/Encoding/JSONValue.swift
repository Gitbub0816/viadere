import Foundation

/// A loosely typed JSON value, used for forward-compatible payloads (unknown interaction
/// kinds, opaque extension data) and for canonical JSON serialization.
///
/// Numbers are restricted to integers (`Int64`) or decimal strings; Viadere never puts
/// binary floating point on the wire.
public enum JSONValue: Sendable, Hashable, Codable {
    case null
    case bool(Bool)
    case integer(Int64)
    case number(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Int64.self) {
            self = .integer(value)
        } else if let value = try? container.decode(Double.self) {
            self = .number(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([JSONValue].self) {
            self = .array(value)
        } else if let value = try? container.decode([String: JSONValue].self) {
            self = .object(value)
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Unsupported JSON value")
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .null: try container.encodeNil()
        case .bool(let value): try container.encode(value)
        case .integer(let value): try container.encode(value)
        case .number(let value): try container.encode(value)
        case .string(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .object(let value): try container.encode(value)
        }
    }

    /// String value, if this is a string.
    public var stringValue: String? {
        if case .string(let value) = self { return value }
        return nil
    }

    /// Object value, if this is an object.
    public var objectValue: [String: JSONValue]? {
        if case .object(let value) = self { return value }
        return nil
    }
}

/// Canonical JSON serialization (a strict subset of RFC 8785 / JCS).
///
/// Rules (normative; see docs/SECURITY.md):
/// - UTF-8, no insignificant whitespace.
/// - Object members sorted by key, comparing UTF-16 code units (identical to byte order for ASCII keys).
/// - Strings: `"` → `\"`, `\` → `\\`, U+0008 `\b`, U+0009 `\t`, U+000A `\n`, U+000C `\f`,
///   U+000D `\r`, other U+0000–U+001F → `\u00xx` (lowercase hex). Everything else literal, including `/`.
/// - Integers in shortest decimal form. Floating point numbers are rejected.
/// - `null` members should be omitted by the producer.
public enum CanonicalJSON {
    /// Errors raised when a value cannot be represented canonically.
    public enum Error: Swift.Error, Sendable, Equatable {
        case floatingPointNotAllowed
    }

    /// Serializes `value` canonically.
    public static func serialize(_ value: JSONValue) throws -> Data {
        var out = ""
        try write(value, into: &out)
        return Data(out.utf8)
    }

    private static func write(_ value: JSONValue, into out: inout String) throws {
        switch value {
        case .null: out += "null"
        case .bool(let b): out += b ? "true" : "false"
        case .integer(let i): out += String(i)
        case .number: throw Error.floatingPointNotAllowed
        case .string(let s): writeString(s, into: &out)
        case .array(let items):
            out += "["
            for (index, item) in items.enumerated() {
                if index > 0 { out += "," }
                try write(item, into: &out)
            }
            out += "]"
        case .object(let members):
            out += "{"
            let keys = members.keys.sorted { Array($0.utf16).lexicographicallyPrecedes(Array($1.utf16)) }
            for (index, key) in keys.enumerated() {
                if index > 0 { out += "," }
                writeString(key, into: &out)
                out += ":"
                try write(members[key] ?? .null, into: &out)
            }
            out += "}"
        }
    }

    private static func writeString(_ s: String, into out: inout String) {
        out += "\""
        for scalar in s.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\u{08}": out += "\\b"
            case "\u{09}": out += "\\t"
            case "\u{0A}": out += "\\n"
            case "\u{0C}": out += "\\f"
            case "\u{0D}": out += "\\r"
            case "\u{00}"..."\u{1F}":
                let hex = String(scalar.value, radix: 16)
                out += "\\u" + String(repeating: "0", count: 4 - hex.count) + hex
            default: out.unicodeScalars.append(scalar)
            }
        }
        out += "\""
    }
}
