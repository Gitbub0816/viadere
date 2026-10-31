import Crypto
import Foundation

/// A structural problem found while reading business- or server-supplied contract JSON (Loop definitions, brand manifests, surface
/// layouts). Contracts are **closed**: an unknown member is an error, never ignored (feature expansion v4, ADR-0015).
public struct ContractIssue: Sendable, Hashable, Codable, CustomStringConvertible {
    /// Machine code, `snake_case`. Each contract documents its own codes; the structural ones are shared.
    public var code: String
    /// JSON path of the offending member (`steps[1].fields[0].type`).
    public var path: String

    public init(code: String, path: String) {
        self.code = code
        self.path = path
    }

    public var description: String { "\(code) at \(path)" }

    public static let unknownMember = "unknown_member"
    public static let missingMember = "missing_member"
    public static let wrongType = "wrong_type"
    public static let invalidValue = "invalid_value"
}

/// Collects issues while a contract is read. Not thread-safe; used for one parse.
final class ContractIssueSink {
    private(set) var issues: [ContractIssue] = []

    func add(_ code: String, _ path: String) {
        // Bounded: a hostile document cannot make the report itself unbounded.
        if issues.count < 200 { issues.append(ContractIssue(code: code, path: path)) }
    }
}

/// A JSON object read strictly: members outside `allowed` are reported as `unknown_member`, members in `required` that are absent as
/// `missing_member`, and typed accessors report `wrong_type`.
struct StrictObject {
    let members: [String: JSONValue]
    let path: String
    let sink: ContractIssueSink

    init?(_ value: JSONValue?, path: String, allowed: Set<String>, required: Set<String> = [], sink: ContractIssueSink) {
        guard let value else {
            sink.add(ContractIssue.missingMember, path)
            return nil
        }
        guard case .object(let members) = value else {
            sink.add(ContractIssue.wrongType, path)
            return nil
        }
        self.members = members
        self.path = path
        self.sink = sink
        for key in members.keys.sorted() where !allowed.contains(key) { sink.add(ContractIssue.unknownMember, child(key)) }
        for key in required.sorted() where members[key] == nil { sink.add(ContractIssue.missingMember, child(key)) }
    }

    func child(_ key: String) -> String { path.isEmpty ? key : "\(path).\(key)" }

    func has(_ key: String) -> Bool { members[key] != nil }

    func string(_ key: String) -> String? {
        guard let value = members[key] else { return nil }
        guard case .string(let s) = value else { sink.add(ContractIssue.wrongType, child(key)); return nil }
        return s
    }

    func int(_ key: String) -> Int64? {
        guard let value = members[key] else { return nil }
        guard case .integer(let n) = value else { sink.add(ContractIssue.wrongType, child(key)); return nil }
        return n
    }

    func bool(_ key: String) -> Bool? {
        guard let value = members[key] else { return nil }
        guard case .bool(let b) = value else { sink.add(ContractIssue.wrongType, child(key)); return nil }
        return b
    }

    func array(_ key: String) -> [JSONValue]? {
        guard let value = members[key] else { return nil }
        guard case .array(let a) = value else { sink.add(ContractIssue.wrongType, child(key)); return nil }
        return a
    }

    func object(_ key: String, allowed: Set<String>, required: Set<String> = []) -> StrictObject? {
        guard let value = members[key] else { return nil }
        return StrictObject(value, path: child(key), allowed: allowed, required: required, sink: sink)
    }
}

/// Identifier grammar shared by the v4 contracts: ASCII lowercase letters, digits, `_` and `-`, starting with a letter or digit.
enum ContractIdentifier {
    static func isValid(_ value: String, maxLength: Int = 40) -> Bool {
        guard !value.isEmpty, value.utf8.count <= maxLength, let first = value.utf8.first,
              (first >= 0x61 && first <= 0x7A) || (first >= 0x30 && first <= 0x39) else { return false }
        return value.utf8.allSatisfy { ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x5F || $0 == 0x2D }
    }

    /// Dotted identifiers such as `viadere.frame.snow.v1`: identifier segments joined by `.`.
    static func isValidDotted(_ value: String, maxLength: Int = 64) -> Bool {
        guard value.utf8.count <= maxLength else { return false }
        let parts = value.split(separator: ".", omittingEmptySubsequences: false)
        return !parts.isEmpty && parts.allSatisfy { isValid(String($0), maxLength: maxLength) }
    }
}

/// Canonical-JSON helpers for the v4 contracts.
public enum ContractHash {
    /// `"sha256:" + lowercase hex SHA-256` of the canonical JSON bytes of `value`.
    public static func sha256(_ value: JSONValue) throws -> String {
        "sha256:" + Hex.encode(Data(SHA256.hash(data: try CanonicalJSON.serialize(value))))
    }

    /// Whether `value` has the form `sha256:<64 lowercase hex>`.
    public static func isValid(_ value: String) -> Bool {
        guard value.hasPrefix("sha256:") else { return false }
        return isLowerHex64(String(value.dropFirst(7)))
    }

    public static func isLowerHex64(_ value: String) -> Bool {
        value.utf8.count == 64 && value.utf8.allSatisfy { ($0 >= 0x30 && $0 <= 0x39) || ($0 >= 0x61 && $0 <= 0x66) }
    }
}

extension JSONValue {
    /// Decodes JSON bytes into a `JSONValue`, refusing floating point anywhere (contracts carry integers only).
    public static func parseContract(_ data: Data) -> JSONValue? {
        guard let value = try? JSONDecoder().decode(JSONValue.self, from: data), !value.containsFloatingPoint else { return nil }
        return value
    }

    var containsFloatingPoint: Bool {
        switch self {
        case .number: true
        case .array(let items): items.contains { $0.containsFloatingPoint }
        case .object(let members): members.values.contains { $0.containsFloatingPoint }
        default: false
        }
    }

    /// The JSON value of an `Encodable` (through `ViadereJSON`'s encoder).
    static func encoding<T: Encodable>(_ value: T) throws -> JSONValue {
        try JSONDecoder().decode(JSONValue.self, from: try JSONEncoder().encode(value))
    }
}
