import Foundation

/// A strict CBOR (RFC 8949) value.
///
/// Shared by the server (App Attest objects), the WebAuthn authenticator (COSE keys, attestation objects) and the vault manifest
/// (deterministic encoding, so a signature covers exactly one byte string). Decoding accepts definite lengths only and refuses tags,
/// floats, duplicate map keys, trailing bytes, oversized or too deeply nested input; the limits are explicit parameters.
public enum CBORValue: Equatable, Sendable {
    public struct Entry: Equatable, Sendable {
        public var key: CBORValue
        public var value: CBORValue
        public init(key: CBORValue, value: CBORValue) {
            self.key = key
            self.value = value
        }
    }

    case unsigned(UInt64)
    case negative(Int64)
    case bytes(Data)
    case text(String)
    case array([CBORValue])
    case map([Entry])
    case bool(Bool)
    case null

    /// A map from text keys to values, in the given order (`CBOR.encode(_, deterministic:)` sorts them).
    public static func textMap(_ pairs: [(String, CBORValue)]) -> CBORValue {
        .map(pairs.map { Entry(key: .text($0.0), value: $0.1) })
    }

    /// A map from integer keys (COSE) to values.
    public static func intMap(_ pairs: [(Int64, CBORValue)]) -> CBORValue {
        .map(pairs.map { Entry(key: $0.0 >= 0 ? .unsigned(UInt64($0.0)) : .negative($0.0), value: $0.1) })
    }

    /// The value stored under a text key of a map (the first match; duplicate keys are rejected while decoding).
    public subscript(key: String) -> CBORValue? {
        guard case .map(let entries) = self else { return nil }
        return entries.first { $0.key == .text(key) }?.value
    }

    /// The value stored under an integer key of a map.
    public subscript(key: Int64) -> CBORValue? {
        guard case .map(let entries) = self else { return nil }
        let wanted: CBORValue = key >= 0 ? .unsigned(UInt64(key)) : .negative(key)
        return entries.first { $0.key == wanted }?.value
    }

    public var byteString: Data? { if case .bytes(let data) = self { data } else { nil } }
    public var textString: String? { if case .text(let text) = self { text } else { nil } }
    public var arrayValue: [CBORValue]? { if case .array(let items) = self { items } else { nil } }
    public var unsignedValue: UInt64? { if case .unsigned(let n) = self { n } else { nil } }
    public var boolValue: Bool? { if case .bool(let b) = self { b } else { nil } }
    /// An integer of either sign (`nil` when it does not fit `Int64`).
    public var intValue: Int64? {
        switch self {
        case .unsigned(let n): n <= UInt64(Int64.max) ? Int64(n) : nil
        case .negative(let n): n
        default: nil
        }
    }
    public var mapEntries: [Entry]? { if case .map(let entries) = self { entries } else { nil } }
}

public enum CBORError: Error, Equatable, Sendable { case truncated, malformed, unsupported, tooDeep, tooLarge, trailingBytes, duplicateKey, notCanonical }

public enum CBOR {
    /// Size and shape bounds applied while decoding.
    public struct Limits: Sendable, Equatable {
        public var maxDepth: Int
        public var maxBytes: Int
        public var maxItems: Int
        public init(maxDepth: Int = 8, maxBytes: Int = 64 * 1024, maxItems: Int = 1024) {
            self.maxDepth = maxDepth
            self.maxBytes = maxBytes
            self.maxItems = maxItems
        }
        public static let standard = Limits()
    }

    public static let maxDepth = Limits.standard.maxDepth
    public static let maxBytes = Limits.standard.maxBytes

    /// Decodes exactly one value that spans all of `data`.
    public static func decode(_ data: Data, limits: Limits = .standard) throws -> CBORValue {
        guard data.count <= limits.maxBytes else { throw CBORError.tooLarge }
        var reader = Reader(bytes: Array(data), limits: limits)
        let value = try reader.read(depth: 0)
        guard reader.isAtEnd else { throw CBORError.trailingBytes }
        return value
    }

    /// Decodes one value that spans all of `data` **and** is in deterministic form (shortest-form heads, map keys sorted): re-encoding
    /// the value must give back exactly `data`. Signed structures use this so one value has one signed byte string.
    public static func decodeDeterministic(_ data: Data, limits: Limits = .standard) throws -> CBORValue {
        let value = try decode(data, limits: limits)
        guard encode(value, deterministic: true) == data else { throw CBORError.notCanonical }
        return value
    }

    /// Reads one value from the front of `data` and returns it with the number of bytes it used. WebAuthn `authenticatorData` carries a
    /// COSE key followed by extension data, so the end of the key is not the end of the buffer.
    public static func decodePrefix(_ data: Data, limits: Limits = .standard) throws -> (value: CBORValue, length: Int) {
        var reader = Reader(bytes: Array(data), limits: limits)
        let value = try reader.read(depth: 0)
        return (value, reader.index)
    }

    private struct Reader {
        let bytes: [UInt8]
        let limits: Limits
        var index = 0
        var isAtEnd: Bool { index == bytes.count }

        init(bytes: [UInt8], limits: Limits) {
            self.bytes = bytes
            self.limits = limits
        }

        mutating func byte() throws -> UInt8 {
            guard index < bytes.count else { throw CBORError.truncated }
            defer { index += 1 }
            return bytes[index]
        }

        mutating func take(_ count: Int) throws -> [UInt8] {
            guard count >= 0, count <= bytes.count - index else { throw CBORError.truncated }
            defer { index += count }
            return Array(bytes[index..<index + count])
        }

        /// The argument of an initial byte (additional information 0...27); indefinite lengths (31) are refused.
        mutating func argument(_ info: UInt8) throws -> UInt64 {
            switch info {
            case 0...23: return UInt64(info)
            case 24...27:
                let width = 1 << Int(info - 24)
                var value: UInt64 = 0
                for b in try take(width) { value = value << 8 | UInt64(b) }
                return value
            default: throw CBORError.unsupported
            }
        }

        mutating func read(depth: Int) throws -> CBORValue {
            guard depth <= limits.maxDepth else { throw CBORError.tooDeep }
            let initial = try byte()
            let major = initial >> 5
            let info = initial & 0x1F
            switch major {
            case 0: return .unsigned(try argument(info))
            case 1:
                let n = try argument(info)
                guard n <= UInt64(Int64.max) else { throw CBORError.unsupported }
                return .negative(-1 - Int64(n))
            case 2:
                let n = try argument(info)
                guard n <= UInt64(limits.maxBytes) else { throw CBORError.tooLarge }
                return .bytes(Data(try take(Int(n))))
            case 3:
                let n = try argument(info)
                guard n <= UInt64(limits.maxBytes) else { throw CBORError.tooLarge }
                guard let text = String(data: Data(try take(Int(n))), encoding: .utf8) else { throw CBORError.malformed }
                return .text(text)
            case 4:
                let n = try argument(info)
                guard n <= UInt64(limits.maxItems) else { throw CBORError.tooLarge }
                var items: [CBORValue] = []
                for _ in 0..<Int(n) { items.append(try read(depth: depth + 1)) }
                return .array(items)
            case 5:
                let n = try argument(info)
                guard n <= UInt64(limits.maxItems) else { throw CBORError.tooLarge }
                var entries: [CBORValue.Entry] = []
                var seen = Set<[UInt8]>()
                for _ in 0..<Int(n) {
                    let start = index
                    let key = try read(depth: depth + 1)
                    guard seen.insert(Array(bytes[start..<index])).inserted else { throw CBORError.duplicateKey }
                    entries.append(.init(key: key, value: try read(depth: depth + 1)))
                }
                return .map(entries)
            case 7:
                switch info {
                case 20: return .bool(false)
                case 21: return .bool(true)
                case 22: return .null
                default: throw CBORError.unsupported
                }
            default: throw CBORError.unsupported
            }
        }
    }

    // MARK: Encoding

    /// Encodes with shortest-form definite lengths. With `deterministic` (RFC 8949 §4.2.1) map entries are sorted by the bytewise order
    /// of their encoded keys, which is also the CTAP2 canonical order for the short keys WebAuthn uses.
    public static func encode(_ value: CBORValue, deterministic: Bool = false) -> Data {
        var out = Data()
        func head(_ major: UInt8, _ n: UInt64) {
            let m = major << 5
            switch n {
            case 0...23: out.append(m | UInt8(n))
            case 24...0xFF: out.append(m | 24); out.append(UInt8(n))
            case 0x100...0xFFFF: out.append(m | 25); out.append(contentsOf: [UInt8(n >> 8), UInt8(n & 0xFF)])
            case 0x10000...0xFFFF_FFFF: out.append(m | 26); out.append(contentsOf: (0..<4).reversed().map { UInt8((n >> (8 * UInt64($0))) & 0xFF) })
            default: out.append(m | 27); out.append(contentsOf: (0..<8).reversed().map { UInt8((n >> (8 * UInt64($0))) & 0xFF) })
            }
        }
        func write(_ v: CBORValue) {
            switch v {
            case .unsigned(let n): head(0, n)
            case .negative(let n): head(1, UInt64(-1 - n))
            case .bytes(let d): head(2, UInt64(d.count)); out.append(d)
            case .text(let s): let d = Data(s.utf8); head(3, UInt64(d.count)); out.append(d)
            case .array(let items): head(4, UInt64(items.count)); items.forEach(write)
            case .map(let entries):
                head(5, UInt64(entries.count))
                if deterministic {
                    let encoded = entries.map { (key: encode($0.key, deterministic: true), value: $0.value) }
                        .sorted { $0.key.lexicographicallyPrecedes($1.key) }
                    for entry in encoded { out.append(entry.key); write(entry.value) }
                } else {
                    for entry in entries { write(entry.key); write(entry.value) }
                }
            case .bool(let b): out.append(b ? 0xF5 : 0xF4)
            case .null: out.append(0xF6)
            }
        }
        write(value)
        return out
    }
}
