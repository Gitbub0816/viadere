import Foundation

/// The web host every Viadere universal link uses (`https://{host}/c/…`, `/a/…`, `/k/…`, `/l/…`, `/h/…`) and the app's associated domain.
///
/// It is **configured, not assumed** (WP-C3): production uses `viadere.com`; staging uses its own host (`viadere.cksites.dev`), so a staging
/// QR code never points at production and a production link is never accepted by a staging build. The server reads it from `LINK_DOMAIN`
/// (`ServerConfig.linkDomain`) and passes it explicitly wherever it builds or parses a link; the app reads it from its build setting
/// `VIADERE_LINK_DOMAIN` (Info.plist `ViadereLinkDomain`) and installs it once at launch with `ViadereCore.configureLinkDomain`.
///
/// Every strict link parser accepts **only** the configured host (and, for connect links, its `www.` alias); a link for any other host,
/// including `viadere.com` in a staging build, is refused.
public struct LinkDomain: Sendable, Hashable, CustomStringConvertible {
    /// The production host, used when nothing else is configured.
    public static let production = LinkDomain(validated: "viadere.com")

    /// Lower-case DNS name (no scheme, port, path or trailing dot).
    public let host: String

    private init(validated host: String) { self.host = host }

    /// `nil` unless `host` is a plain DNS name: at least two labels of letters, digits and inner hyphens, at most 253 characters, no
    /// scheme, port, user info, path, wildcard or unexpanded build variable (`$(…)`).
    public init?(_ host: String) {
        let name = host.lowercased()
        guard Self.isValid(name) else { return nil }
        self.host = name
    }

    static func isValid(_ name: String) -> Bool {
        guard name.utf8.count <= 253, !name.isEmpty else { return false }
        let labels = name.split(separator: ".", omittingEmptySubsequences: false)
        guard labels.count >= 2 else { return false }
        for label in labels {
            guard (1...63).contains(label.utf8.count), label.first != "-", label.last != "-",
                  label.utf8.allSatisfy({ ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x2D }) else { return false }
        }
        // The top-level label is never numeric (rules out IP literals such as 10.0.0.1).
        return labels.last?.utf8.allSatisfy({ $0 >= 0x30 && $0 <= 0x39 }) == false
    }

    /// Whether a link's host is this domain exactly (case-insensitive). Strict parsers use this.
    public func matches(_ host: String?) -> Bool {
        guard let host else { return false }
        return host.lowercased() == self.host
    }

    /// Hosts a **connect** link may use: the domain and its `www.` alias (QR codes printed with either keep working).
    public var connectHosts: Set<String> { [host, "www." + host] }

    /// `https://{host}`.
    public var origin: String { "https://\(host)" }

    /// `https://{host}{path}` (`path` starts with `/`).
    public func url(_ path: String) -> URL? { URL(string: origin + path) }

    public var description: String { host }

    // MARK: Process-wide value

    private final class Storage: @unchecked Sendable {
        let lock = NSLock()
        var value = LinkDomain.production
    }
    private static let storage = Storage()

    /// The domain this process uses when a caller does not pass one: `viadere.com` until `ViadereCore.configureLinkDomain` installs another.
    /// The server never relies on it (it passes `ServerConfig.linkDomain`); the app installs the build's value once at launch.
    public static var current: LinkDomain {
        storage.lock.lock()
        defer { storage.lock.unlock() }
        return storage.value
    }

    static func install(_ domain: LinkDomain) {
        storage.lock.lock()
        storage.value = domain
        storage.lock.unlock()
    }
}

extension ViadereCore {
    /// The production web host. `domain` is what this process is configured to use.
    public static let defaultDomain = LinkDomain.production.host

    /// The configured link domain's host (`viadere.com` unless `configureLinkDomain` installed another).
    public static var domain: String { LinkDomain.current.host }

    /// Installs the link domain for this process (the app, at launch, from its build setting). Returns `false` and keeps the current value
    /// when `host` is not a valid DNS name.
    @discardableResult
    public static func configureLinkDomain(_ host: String) -> Bool {
        guard let domain = LinkDomain(host) else { return false }
        LinkDomain.install(domain)
        return true
    }
}
