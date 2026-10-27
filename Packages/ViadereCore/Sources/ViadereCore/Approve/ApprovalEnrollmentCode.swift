import Foundation

/// The short code a business shows its customer to start an Approve enrollment (APP-002): eight characters of a 32-letter alphabet without
/// look-alikes (40 bits), single use, valid for at most 15 minutes, and only redeemable by the customer the enrollment was created for.
/// Shown as `ABCD-EFGH`.
public enum ApprovalEnrollmentCode {
    static let alphabet = Array("ABCDEFGHJKLMNPQRSTUVWXYZ23456789".utf8)
    public static let length = 8

    /// A fresh random code (canonical form: eight alphabet characters, no separator).
    public static func generate() -> String {
        var bytes = SecureToken.randomBytes(length)
        defer { bytes = Data() }
        // 32 symbols and a byte has 256 values: `& 31` is unbiased.
        return String(decoding: bytes.map { alphabet[Int($0 & 31)] }, as: UTF8.self)
    }

    /// Canonical form of what a person typed or a link carried: upper case, separators removed. `nil` unless exactly eight alphabet characters.
    public static func canonical(_ input: String) -> String? {
        let cleaned = input.uppercased().filter { $0 != "-" && $0 != " " && $0 != "_" && $0 != "." }
        guard cleaned.utf8.count == length, cleaned.utf8.allSatisfy({ alphabet.contains($0) }) else { return nil }
        return cleaned
    }

    /// `ABCD-EFGH`.
    public static func display(_ canonical: String) -> String {
        guard canonical.count == length else { return canonical }
        return String(canonical.prefix(4)) + "-" + String(canonical.suffix(4))
    }

    /// `https://viadere.com/a/{CODE}[?rk={root kid}]`.
    public static func deepLink(code: String, rootKid: String?) -> String {
        var link = "https://\(ViadereCore.domain)/a/\(code)"
        if let rootKid { link += "?rk=\(rootKid)" }
        return link
    }

    /// Parses a deep link. Strict: https, the exact host, path `/a/{CODE}`, an optional single `rk` parameter holding a key id, nothing else.
    public static func parse(link: URL) -> (code: String, rootKid: String?)? {
        guard link.scheme == "https", link.host == ViadereCore.domain, link.user == nil, link.password == nil, link.port == nil, link.fragment == nil,
              let components = URLComponents(url: link, resolvingAgainstBaseURL: false) else { return nil }
        let parts = components.path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard parts.count == 3, parts[0].isEmpty, parts[1] == "a", let code = canonical(parts[2]), code == parts[2] else { return nil }
        let items = components.queryItems ?? []
        guard items.count <= 1 else { return nil }
        if let item = items.first {
            guard item.name == "rk", let value = item.value, KeyIdentifier.isValid(value) else { return nil }
            return (code, value)
        }
        return (code, nil)
    }
}
