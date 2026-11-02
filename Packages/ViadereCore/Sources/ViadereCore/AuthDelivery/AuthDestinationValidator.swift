import Foundation

/// Why a magic-link destination was refused (ADR-0021 section 3). The app and the server share this validator (CLAUDE.md "shared logic belongs in Core"):
/// the server refuses at create, the device runs it again before it opens anything.
public enum AuthDestinationError: String, Error, Sendable, Hashable, CaseIterable {
    case tooLong = "too_long"
    case scheme
    case userinfo
    case port
    case host
    case ipLiteral = "ip_literal"
    case trailingDot = "trailing_dot"
    case backslash
    case encoding
    case notAllowed = "not_allowed"
    case openRedirect = "open_redirect"
}

/// A validated destination. `url` is the exact input (never rewritten: the business-signed statement commits to its bytes).
public struct AuthDestination: Sendable, Hashable {
    public var url: String
    /// Lowercase A-label host.
    public var host: String
}

/// `AuthDestinationValidator`: strict `https` URLs on exactly the tenant's allowed hosts.
///
/// 1. scheme exactly `https`; no userinfo; **no port at all** (not even `:443`: the business signs the URL bytes, so nothing may be rewritten);
/// 2. host lowercase A-labels only (a U-label, a mixed script or any non-ASCII byte is refused), no IP literal, no trailing dot, no empty label,
///    no backslash anywhere, total length at most 2048;
/// 3. path and query are valid percent-encoded ASCII; the fragment is allowed;
/// 4. the host is **exactly** one of `allowedHosts`;
/// 5. open-redirect check: a query value (raw and after one percent-decode) that starts with `http:`, `https:`, `//`, `\\` or `/\` must itself be a URL
///    whose host passes rule 4, otherwise the URL is refused. Viadere never fetches or follows the URL.
public enum AuthDestinationValidator {
    public static let maxLength = 2048

    /// Syntax only (rules 1 to 3): the parsed host, without checking an allow-list.
    public static func parse(_ raw: String) throws(AuthDestinationError) -> AuthDestination {
        guard raw.utf8.count <= maxLength else { throw .tooLong }
        guard !raw.contains("\\") else { throw .backslash }
        guard raw.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7F }) else { throw .encoding }
        guard raw.hasPrefix("https://") else { throw .scheme }
        let afterScheme = raw.dropFirst("https://".count)
        let authorityEnd = afterScheme.firstIndex { $0 == "/" || $0 == "?" || $0 == "#" } ?? afterScheme.endIndex
        let authority = String(afterScheme[afterScheme.startIndex..<authorityEnd])
        let rest = String(afterScheme[authorityEnd...])
        guard !authority.contains("@") else { throw .userinfo }
        guard !authority.contains(":"), !authority.contains("[") else { throw .port }
        try validateHost(authority)
        try validateEncoding(rest)
        return AuthDestination(url: raw, host: authority)
    }

    /// Rules 1 to 5.
    public static func validate(_ raw: String, allowedHosts: Set<String>) throws(AuthDestinationError) -> AuthDestination {
        let destination = try parse(raw)
        guard allowedHosts.contains(destination.host) else { throw .notAllowed }
        try checkRedirects(in: raw, allowedHosts: allowedHosts)
        return destination
    }

    // MARK: Pieces

    static func validateHost(_ host: String) throws(AuthDestinationError) {
        guard !host.isEmpty, host.utf8.count <= 253 else { throw .host }
        guard host.utf8.allSatisfy({ $0 < 0x80 }) else { throw .host }
        if host.hasSuffix(".") { throw .trailingDot }
        let labels = host.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2, labels.allSatisfy({ !$0.isEmpty }) else { throw .host }
        for label in labels {
            guard label.utf8.count <= 63, !label.hasPrefix("-"), !label.hasSuffix("-"),
                  label.utf8.allSatisfy({ ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2D }) else { throw .host }
        }
        // An all-numeric last label makes the host an IPv4 address (or an obfuscated one such as `1.2.3.4`, `10.1`).
        if let last = labels.last, last.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) { throw .ipLiteral }
    }

    /// Path, query and fragment: printable ASCII, every `%` followed by two hex digits, none of the characters RFC 3986 never allows.
    static func validateEncoding(_ rest: String) throws(AuthDestinationError) {
        let bytes = Array(rest.utf8)
        var i = 0
        var fragments = 0
        while i < bytes.count {
            let b = bytes[i]
            if b == 0x23 { fragments += 1 }
            if b == 0x25 {
                guard i + 2 < bytes.count, isHex(bytes[i + 1]), isHex(bytes[i + 2]) else { throw .encoding }
                i += 3
                continue
            }
            if [0x22, 0x3C, 0x3E, 0x5C, 0x5E, 0x60, 0x7B, 0x7C, 0x7D].contains(b) { throw .encoding }
            i += 1
        }
        guard fragments <= 1 else { throw .encoding }
    }

    private static func isHex(_ b: UInt8) -> Bool { (b >= 0x30 && b <= 0x39) || (b >= 0x41 && b <= 0x46) || (b >= 0x61 && b <= 0x66) }

    /// Rule 5.
    static func checkRedirects(in raw: String, allowedHosts: Set<String>) throws(AuthDestinationError) {
        guard let question = raw.firstIndex(of: "?") else { return }
        var query = raw[raw.index(after: question)...]
        if let hash = query.firstIndex(of: "#") { query = query[query.startIndex..<hash] }
        for pair in query.split(whereSeparator: { $0 == "&" || $0 == ";" }) {
            let value = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false).dropFirst().first.map(String.init) ?? ""
            for candidate in [value, value.removingPercentEncoding ?? value] {
                let lower = candidate.lowercased()
                if lower.hasPrefix("\\\\") || lower.hasPrefix("/\\") { throw .openRedirect }
                if lower.hasPrefix("//") {
                    let rest = candidate.dropFirst(2)
                    let end = rest.firstIndex { $0 == "/" || $0 == "?" || $0 == "#" } ?? rest.endIndex
                    guard allowedHosts.contains(String(rest[rest.startIndex..<end])) else { throw .openRedirect }
                } else if lower.hasPrefix("http:") || lower.hasPrefix("https:") {
                    guard let nested = try? parse(candidate), allowedHosts.contains(nested.host) else { throw .openRedirect }
                }
            }
        }
    }
}
