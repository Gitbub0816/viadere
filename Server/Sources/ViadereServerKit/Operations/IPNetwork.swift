import Foundation

/// A CIDR block (`203.0.113.0/24`, `2001:db8::/32`) or a single address. Used by API-key and console IP allow-lists and by the
/// edge-lock's "internal network" test. Parsing is strict: anything that is not a plain address with an optional prefix length is rejected,
/// so a typo can never turn into "allow everything".
public struct IPNetwork: Sendable, Hashable, CustomStringConvertible {
    public let bytes: [UInt8]
    public let prefixLength: Int

    /// Parses `address` or `address/prefix`. Returns `nil` for anything else (names, wildcards, ranges, empty prefixes).
    public init?(_ text: String) {
        let trimmed = text.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, trimmed.count <= 64 else { return nil }
        let parts = trimmed.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard (1...2).contains(parts.count), let address = Self.addressBytes(parts[0]) else { return nil }
        var length = address.count * 8
        if parts.count == 2 {
            guard !parts[1].isEmpty, parts[1].allSatisfy(\.isASCII), parts[1].allSatisfy(\.isNumber), let value = Int(parts[1]),
                  (0...length).contains(value) else { return nil }
            length = value
        }
        // Normalise: clear the host bits so `10.1.2.3/8` and `10.0.0.0/8` are the same network.
        var masked = address
        for index in 0..<masked.count {
            let bitsKept = max(0, min(8, length - index * 8))
            masked[index] &= bitsKept == 0 ? 0 : UInt8(truncatingIfNeeded: 0xFF << (8 - bitsKept))
        }
        bytes = masked
        prefixLength = length
    }

    /// Whether `address` (textual) is inside this network. IPv4-mapped IPv6 addresses are compared as IPv4.
    public func contains(_ address: String) -> Bool {
        guard var candidate = Self.addressBytes(address) else { return false }
        if candidate.count == 16, bytes.count == 4, candidate[0..<10].allSatisfy({ $0 == 0 }), candidate[10] == 0xFF, candidate[11] == 0xFF {
            candidate = Array(candidate[12..<16])
        }
        guard candidate.count == bytes.count else { return false }
        for index in 0..<bytes.count {
            let bitsKept = max(0, min(8, prefixLength - index * 8))
            if bitsKept == 0 { break }
            let mask = UInt8(truncatingIfNeeded: 0xFF << (8 - bitsKept))
            if candidate[index] & mask != bytes[index] { return false }
        }
        return true
    }

    public var description: String {
        let text: String
        if bytes.count == 4 {
            text = bytes.map(String.init).joined(separator: ".")
        } else {
            text = stride(from: 0, to: 16, by: 2).map { String(format: "%x", Int(bytes[$0]) << 8 | Int(bytes[$0 + 1])) }.joined(separator: ":")
        }
        return "\(text)/\(prefixLength)"
    }

    static func addressBytes(_ text: String) -> [UInt8]? {
        let trimmed = text.trimmingCharacters(in: CharacterSet(charactersIn: "[] "))
        guard !trimmed.isEmpty else { return nil }
        var v4 = in_addr()
        if inet_pton(AF_INET, trimmed, &v4) == 1 { return withUnsafeBytes(of: &v4) { Array($0) } }
        var v6 = in6_addr()
        if !trimmed.contains("%"), inet_pton(AF_INET6, trimmed, &v6) == 1 { return withUnsafeBytes(of: &v6) { Array($0) } }
        return nil
    }

    /// Parses a comma/newline/space-separated list. Returns `nil` if **any** entry is invalid (nothing is silently dropped), and at most
    /// `limit` entries are accepted.
    public static func parseList(_ text: String, limit: Int = 50) -> [IPNetwork]? {
        let entries = text.split(whereSeparator: { $0 == "," || $0 == "\n" || $0 == " " || $0 == ";" }).map(String.init).filter { !$0.isEmpty }
        guard entries.count <= limit else { return nil }
        var out: [IPNetwork] = []
        for entry in entries {
            guard let network = IPNetwork(entry) else { return nil }
            if !out.contains(network) { out.append(network) }
        }
        return out
    }

    /// Whether `address` is allowed by `allowlist` (empty = no restriction).
    public static func allows(_ address: String, in allowlist: [IPNetwork]) -> Bool {
        allowlist.isEmpty || allowlist.contains { $0.contains(address) }
    }

    /// The address with its host part removed for display: IPv4 `/24`, IPv6 `/48` (`203.0.113.0`, `2001:db8:1::`).
    public static func masked(_ address: String) -> String {
        guard let raw = addressBytes(address) else { return "unknown" }
        var bytes = raw
        if bytes.count == 16, bytes[0..<10].allSatisfy({ $0 == 0 }), bytes[10] == 0xFF, bytes[11] == 0xFF { bytes = Array(bytes[12..<16]) }
        if bytes.count == 4 { return "\(bytes[0]).\(bytes[1]).\(bytes[2]).0" }
        let groups = stride(from: 0, to: 6, by: 2).map { String(format: "%x", Int(bytes[$0]) << 8 | Int(bytes[$0 + 1])) }
        return groups.joined(separator: ":") + "::"
    }
}
