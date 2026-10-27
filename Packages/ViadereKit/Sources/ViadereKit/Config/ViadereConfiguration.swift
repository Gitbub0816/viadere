import Foundation
import ViadereCore

/// Everything environment-specific, in one place. Built once at launch (`resolve(info:allowLocalHTTP:)`)
/// and passed to every service; the app, the extensions and the App Clip read the same values.
public struct ViadereConfiguration: Sendable {
    public enum Mode: String, Sendable { case production, local }

    public var mode: Mode
    public var apiBaseURL: URL
    /// WebAuthn relying party.
    public var relyingPartyID: String
    public var bundleID: String
    public var appGroupID: String
    /// Keychain service namespace.
    public var keychainService: String
    /// Full keychain access group (team prefix included), shared with extensions. `nil` in tests / unsigned builds.
    public var keychainAccessGroup: String?
    public var pinning: PinningConfiguration
    public var apnsEnvironment: APNsTokenRegistration.Environment
    /// True on release builds: unconfigured certificate pins deny connections.
    public var failClosedPinning: Bool

    public static let productionHost = "api.viadere.com"

    /// TODO(release): replace with the real SPKI SHA-256 pins (current key + backup). See `PinningConfiguration`.
    public static let productionPinning = PinningConfiguration(
        host: productionHost,
        pins: ["REPLACE_ME_PRIMARY_SPKI_SHA256_BASE64", "REPLACE_ME_BACKUP_SPKI_SHA256_BASE64"]
    )

    public init(mode: Mode, apiBaseURL: URL, relyingPartyID: String = ViadereCore.domain,
                bundleID: String = "\(ViadereCore.bundlePrefix).app", appGroupID: String = "group.\(ViadereCore.bundlePrefix).shared",
                keychainService: String = "\(ViadereCore.bundlePrefix).client", keychainAccessGroup: String? = nil,
                pinning: PinningConfiguration = ViadereConfiguration.productionPinning,
                apnsEnvironment: APNsTokenRegistration.Environment = .production, failClosedPinning: Bool = true) {
        self.mode = mode
        self.apiBaseURL = apiBaseURL
        self.relyingPartyID = relyingPartyID
        self.bundleID = bundleID
        self.appGroupID = appGroupID
        self.keychainService = keychainService
        self.keychainAccessGroup = keychainAccessGroup
        self.pinning = pinning
        self.apnsEnvironment = apnsEnvironment
        self.failClosedPinning = failClosedPinning
    }

    public static var production: ViadereConfiguration {
        ViadereConfiguration(mode: .production, apiBaseURL: literal("https://\(productionHost)"))
    }

    /// Local development server. Only reachable when the app is built with `allowLocalHTTP` (DEBUG).
    public static var local: ViadereConfiguration {
        ViadereConfiguration(mode: .local, apiBaseURL: literal("http://localhost:8080"),
                             apnsEnvironment: .sandbox, failClosedPinning: false)
    }

    /// Reads `ViadereAPIBaseURL` and `ViadereKeychainAccessGroup` from the Info.plist dictionary.
    ///
    /// Safety rules: release builds only accept `https` URLs (anything else falls back to production);
    /// plain `http` is accepted only when `allowLocalHTTP` is true **and** the host is a loopback / `.local` name.
    public static func resolve(info: [String: Any], allowLocalHTTP: Bool) -> ViadereConfiguration {
        var config = ViadereConfiguration.production
        if let raw = info["ViadereAPIBaseURL"] as? String, let url = sanitizedBaseURL(raw, allowLocalHTTP: allowLocalHTTP) {
            if url.scheme == "http" {
                config = .local
                config.apiBaseURL = url
            } else {
                config.apiBaseURL = url
                if let host = url.host?.lowercased(), host != productionHost {
                    // Staging etc.: pins for a different host are the integrator's responsibility.
                    config.pinning = PinningConfiguration(host: host, pins: productionPinning.pins)
                }
            }
        }
        // An explicit empty value opts out of app-group sharing (the App Clip has no shared container).
        if let appGroup = info["ViadereAppGroupID"] as? String { config.appGroupID = appGroup }
        if let group = info["ViadereKeychainAccessGroup"] as? String, !group.isEmpty, !group.contains("$(") {
            config.keychainAccessGroup = group
        }
        #if DEBUG
        config.apnsEnvironment = .sandbox
        #endif
        return config
    }

    /// Validates a configured base URL: no credentials, query, fragment or trailing path.
    public static func sanitizedBaseURL(_ raw: String, allowLocalHTTP: Bool) -> URL? {
        guard let components = URLComponents(string: raw.trimmingCharacters(in: .whitespaces)),
              let scheme = components.scheme?.lowercased(), let host = components.host?.lowercased(), !host.isEmpty,
              components.user == nil, components.password == nil, components.query == nil, components.fragment == nil,
              components.path.isEmpty || components.path == "/" else { return nil }
        switch scheme {
        case "https":
            break
        case "http":
            guard allowLocalHTTP, isLocalHost(host) else { return nil }
        default:
            return nil
        }
        var clean = components
        clean.path = ""
        return clean.url
    }

    static func isLocalHost(_ host: String) -> Bool {
        host == "localhost" || host == "127.0.0.1" || host == "::1" || host == "[::1]" || host.hasSuffix(".local")
    }

    private static func literal(_ string: String) -> URL { URL(string: string) ?? URL(fileURLWithPath: "/") }
}
