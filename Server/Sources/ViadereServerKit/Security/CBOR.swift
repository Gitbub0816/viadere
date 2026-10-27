import Foundation

/// A minimal, strict CBOR (RFC 8949) reader for App Attest objects: definite lengths only, bounded depth and size, no tags, no
/// floats, and no trailing bytes. It exists so identity verification does not depend on a general-purpose decoder's leniency.
enum CBORValue: Equatable, Sendable {
    struct Entry: Equatable, Sendable {
        var key: CBORValue
        var value: CBORValue
    }

    case unsigned(UInt64)
    case negative(Int64)
    case bytes(Data)
    case text(String)
    case array([CBORValue])
    case map([Entry])
    case bool(Bool)
    case null

    /// The value stored under a text key of a map (the first match; duplicate keys are rejected while decoding).
    subscript(key: String) -> CBORValue? {
        guard case .map(let entries) = self else { return nil }
        return entries.first { $0.key == .text(key) }?.value
    }

    var byteString: Data? { if case .bytes(let data) = self { data } else { nil } }
    var textString: String? { if case .text(let text) = self { text } else { nil } }
    var arrayValue: [CBORValue]? { if case .array(let items) = self { items } else { nil } }
}

enum CBORError: Error, Equatable { case truncated, malformed, unsupported, tooDeep, tooLarge, trailingBytes, duplicateKey }

enum CBOR {
    static let maxDepth = 8
    static let maxBytes = 64 * 1024

    /// Decodes exactly one value that spans all of `data`.
    static func decode(_ data: Data) throws -> CBORValue {
        guard data.count <= maxBytes else { throw CBORError.tooLarge }
        var reader = Reader(bytes: Array(data))
        let value = try reader.read(depth: 0)
        guard reader.isAtEnd else { throw CBORError.trailingBytes }
        return value
    }

    private struct Reader {
        let bytes: [UInt8]
        var index = 0
        var isAtEnd: Bool { index == bytes.count }

        init(bytes: [UInt8]) { self.bytes = bytes }

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
            guard depth <= CBOR.maxDepth else { throw CBORError.tooDeep }
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
                guard n <= UInt64(CBOR.maxBytes) else { throw CBORError.tooLarge }
                return .bytes(Data(try take(Int(n))))
            case 3:
                let n = try argument(info)
                guard n <= UInt64(CBOR.maxBytes) else { throw CBORError.tooLarge }
                guard let text = String(data: Data(try take(Int(n))), encoding: .utf8) else { throw CBORError.malformed }
                return .text(text)
            case 4:
                let n = try argument(info)
                guard n <= 1024 else { throw CBORError.tooLarge }
                var items: [CBORValue] = []
                for _ in 0..<Int(n) { items.append(try read(depth: depth + 1)) }
                return .array(items)
            case 5:
                let n = try argument(info)
                guard n <= 1024 else { throw CBORError.tooLarge }
                var entries: [CBORValue.Entry] = []
                for _ in 0..<Int(n) {
                    let key = try read(depth: depth + 1)
                    guard !entries.contains(where: { $0.key == key }) else { throw CBORError.duplicateKey }
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

    // MARK: Encoding (used to build fixtures and the COSE keys of tests; shortest-form definite lengths)

    static func encode(_ value: CBORValue) -> Data {
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
            case .map(let entries): head(5, UInt64(entries.count)); entries.forEach { write($0.key); write($0.value) }
            case .bool(let b): out.append(b ? 0xF5 : 0xF4)
            case .null: out.append(0xF6)
            }
        }
        write(value)
        return out
    }
}
