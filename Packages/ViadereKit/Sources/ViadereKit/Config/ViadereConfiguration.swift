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
    /// App-only access group for the approval keys (`approvalUserPresence`, `approvalBiometric`). Only the main app
    /// is entitled to it, so the notification extensions and the App Clip cannot even see those keys; they share
    /// just the request key and the access token through `keychainAccessGroup`. `nil` in extensions, tests and
    /// unsigned builds.
    public var approvalKeychainAccessGroup: String?
    public var pinning: PinningConfiguration
    public var apnsEnvironment: APNsTokenRegistration.Environment
    /// True on release builds: unconfigured certificate pins deny connections.
    public var failClosedPinning: Bool
    /// Base64url X9.63 public keys of the Viadere key-directory transparency log (more than one during a log-key rotation). **Pinned in the
    /// build**: a key taken from the network would let a relay vouch for itself. Empty = Approve v2 and E2EE fail closed.
    public var keyDirectoryLogKeys: [String] = []
    public var keyDirectoryLogId: String = TransparencyLog.defaultLogId
    /// The universal-link host (`VIADERE_LINK_DOMAIN`, Info.plist `ViadereLinkDomain`; defaults to the web domain). Every link parser in the app
    /// accepts only this host; `installLinkDomain()` makes it the process-wide `ViadereCore.domain`. The production API always uses `viadere.com`.
    public var linkDomain: LinkDomain = .production
    /// Base64url X9.63 public keys of Viadere's `link-descriptor` signing key (more than one during a rotation; Info.plist
    /// `ViadereLinkDescriptorKeys`). **Pinned in the build**: the app accepts a link-session descriptor only if one of these signed it.
    /// Empty = business link sessions fail closed.
    public var linkDescriptorKeys: [String] = []
    /// Whether Wallet screens carry a "Beta" label (Info.plist `ViadereWalletBetaLabel`, build setting `VIADERE_WALLET_BETA_LABEL`).
    /// On unless the build explicitly says `NO`/`false`: whether to drop it is an open owner decision (docs/WALLET.md).
    public var walletBetaLabel = true

    public static let productionHost = "api.viadere.com"

    /// TODO(release): replace with the real SPKI SHA-256 pins (current key + backup). See `PinningConfiguration`.
    public static let productionPinning = PinningConfiguration(
        host: productionHost,
        pins: ["REPLACE_ME_PRIMARY_SPKI_SHA256_BASE64", "REPLACE_ME_BACKUP_SPKI_SHA256_BASE64"]
    )

    public init(mode: Mode, apiBaseURL: URL, relyingPartyID: String = ViadereCore.defaultDomain,
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

    /// Reads `ViadereAPIBaseURL` and `ViadereKeychainAccessGroup` from the Info.plist dictionary. For a host other than production (the Staging
    /// build configuration) it also reads `ViadereAPIPins`, `ViadereAPNsEnvironment` (`sandbox` | `production`) and `ViadereRelyingPartyID`.
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
                    // Staging etc.: the pins come from the build (Info.plist `ViadereAPIPins`, filled from the xcconfig). Without valid
                    // pins the host gets placeholders and a fail-closed build cannot connect (the Staging archive is also stopped by
                    // Scripts/check-release-pins.sh). The production pins are never reused for another host.
                    config.pinning = PinningConfiguration(host: host, pins: pins(from: info) ?? placeholderPins)
                    // A non-production host may attest and register for pushes in the sandbox (development-signed builds).
                    if let raw = info["ViadereAPNsEnvironment"] as? String, let env = APNsTokenRegistration.Environment(rawValue: raw.lowercased()) {
                        config.apnsEnvironment = env
                    }
                    if let rp = info["ViadereRelyingPartyID"] as? String, isDomainName(rp) { config.relyingPartyID = rp.lowercased() }
                    // Staging links point at the staging web host (WP-C3); production keeps viadere.com whatever the plist says.
                    if let raw = info["ViadereLinkDomain"] as? String, let domain = LinkDomain(raw) { config.linkDomain = domain }
                }
            }
        }
        // An explicit empty value opts out of app-group sharing (the App Clip has no shared container).
        if let appGroup = info["ViadereAppGroupID"] as? String { config.appGroupID = appGroup }
        if let group = info["ViadereKeychainAccessGroup"] as? String, !group.isEmpty, !group.contains("$(") {
            config.keychainAccessGroup = group
        }
        if let group = info["ViadereApprovalKeychainAccessGroup"] as? String, !group.isEmpty, !group.contains("$(") {
            config.approvalKeychainAccessGroup = group
        }
        // The transparency-log key(s), pinned at build time (comma separated). Placeholders and malformed values are dropped, so a build
        // that forgot to set them has none and Approve v2 stays closed.
        if let raw = info["ViadereKeyDirectoryLogKeys"] as? String {
            config.keyDirectoryLogKeys = raw.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { (try? DevicePublicKey(base64URL: $0)) != nil }
        }
        if let id = info["ViadereKeyDirectoryLogId"] as? String, !id.isEmpty, !id.contains("$(") { config.keyDirectoryLogId = id }
        if let raw = info["ViadereLinkDescriptorKeys"] as? String {
            config.linkDescriptorKeys = raw.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { (try? DevicePublicKey(base64URL: $0)) != nil }
        }
        if let raw = info["ViadereWalletBetaLabel"] as? String, ["no", "false", "0"].contains(raw.lowercased()) { config.walletBetaLabel = false }
        if let flag = info["ViadereWalletBetaLabel"] as? Bool { config.walletBetaLabel = flag }
        #if DEBUG
        config.apnsEnvironment = .sandbox
        #endif
        return config
    }

    /// Placeholder pins for a non-production host whose build supplied none (never valid: the connection is refused when fail-closed).
    static let placeholderPins = ["\(PinningConfiguration.placeholderPrefix)_PRIMARY_PIN_NOT_SET", "\(PinningConfiguration.placeholderPrefix)_BACKUP_PIN_NOT_SET"]

    /// `ViadereAPIPins`: comma-separated base64 SHA-256 SPKI hashes. All-or-nothing: one malformed or placeholder entry rejects the lot
    /// (a half-configured pin set must not look configured), as do duplicates and fewer than two pins (current + backup).
    static func pins(from info: [String: Any]) -> [String]? {
        guard let raw = info["ViadereAPIPins"] as? String else { return nil }
        let pins = raw.split(separator: ",", omittingEmptySubsequences: false).map { $0.trimmingCharacters(in: .whitespaces) }
        guard pins.count >= 2, pins.allSatisfy(PinningConfiguration.isValidPin), Set(pins).count == pins.count else { return nil }
        return pins
    }

    /// A plain DNS name (letters, digits, dashes, dots), as a relying-party ID is. Rejects unexpanded `$(...)` variables.
    static func isDomainName(_ text: String) -> Bool {
        let name = text.lowercased()
        return name.contains(".") && name.count <= 253 && !name.hasPrefix(".") && !name.hasSuffix(".") && !name.contains("..")
            && name.unicodeScalars.allSatisfy { ($0.isASCII && ($0.properties.isAlphabetic || ("0"..."9").contains($0))) || $0 == "-" || $0 == "." }
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

extension ViadereConfiguration {
    /// The pinned log keys, parsed.
    public var parsedKeyDirectoryLogKeys: [DevicePublicKey] { keyDirectoryLogKeys.compactMap { try? DevicePublicKey(base64URL: $0) } }
}

extension ViadereConfiguration {
    /// Makes `linkDomain` the process-wide link domain (`ViadereCore.domain`, `LinkDomain.current`). Called once at launch.
    public func installLinkDomain() {
        ViadereCore.configureLinkDomain(linkDomain.host)
    }

    /// The pinned `link-descriptor` keys, parsed.
    public var parsedLinkDescriptorKeys: [DevicePublicKey] { linkDescriptorKeys.compactMap { try? DevicePublicKey(base64URL: $0) } }
}
