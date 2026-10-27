@preconcurrency import Crypto
import Foundation
import ViadereCore

/// Deployment environment.
public enum DeploymentEnvironment: String, Sendable {
    case development, testing, production
}

/// APNs token-auth configuration (`.p8` key).
public struct APNsConfig: Sendable {
    public var keyPEM: String
    public var keyID: String
    public var teamID: String
    public var topic: String
    public var useSandbox: Bool
}

/// Twilio (or Twilio-compatible) credentials.
public struct TwilioConfig: Sendable {
    public var accountSID: String
    public var authToken: String
    /// `From` number in E.164, or empty when a messaging service is used.
    public var fromNumber: String
    public var messagingServiceSID: String?
}

public enum ServerConfigError: Error, CustomStringConvertible, Sendable {
    case missing(String)
    case invalid(String)

    public var description: String {
        switch self {
        case .missing(let key): "Missing required configuration: \(key)"
        case .invalid(let key): "Invalid configuration: \(key)"
        }
    }
}

/// All server configuration. Secrets come only from the environment; nothing is hard-coded.
public struct ServerConfig: Sendable {
    public var environment: DeploymentEnvironment
    /// `postgres://…` URL (production/dev). `nil` selects in-memory SQLite (tests only).
    public var databaseURL: String?
    public var bindHost: String
    public var port: Int
    /// Public origin used to build links and to verify provider signatures (never taken from the Host header).
    public var publicBaseURL: String
    public var relyingPartyID: String
    public var relyingPartyName: String
    public var relyingPartyOrigin: String
    public var appleTeamID: String
    public var appStoreID: String?
    public var appBundleID: String
    public var appClipBundleID: String
    /// HMAC key for signed connect-link context.
    public var connectLinkKey: SymmetricKey
    /// Server-side secret for OTP hashing and pseudonymous per-business references.
    public var pepper: Data
    /// 32-byte AES-256-GCM key for encrypting phone numbers, message bodies, webhook secrets and SMS contexts.
    public var dataEncryptionKey: SymmetricKey
    public var apns: APNsConfig?
    public var twilio: TwilioConfig?
    /// Number of reverse proxies in front of the server whose `X-Forwarded-For` entries are trusted.
    public var trustedProxyCount: Int
    /// Exact origins allowed by CORS. Empty (the default) means no cross-origin access.
    public var corsAllowedOrigins: [String]
    public var runBackgroundJobs: Bool
    /// Seconds between background job runs (webhook/SMS delivery, expiry sweeps).
    public var jobIntervalSeconds: Double
    /// Run pending database migrations at startup (`AUTO_MIGRATE=true`). In-memory SQLite always migrates.
    public var autoMigrate: Bool
    public var maxBodyBytes: Int
    public var rateLimits: RateLimitSettings
    public var accessTokenTTL: TimeInterval
    public var refreshTokenTTL: TimeInterval
    /// Interactions a free-tier business may issue per UTC day.
    public var freeDailyInteractionQuota: Int
    public var allowInsecureWebhookURLs: Bool
    /// RCS Business Messaging provider (generic RBM-style). `nil` disables RCS.
    public var rcs: RCSConfig?
    public var channelFlags = ChannelFeatureFlags()
    public var dashboard = DashboardSettings.standard
    public var abuse = AbuseThresholds.standard
    public var billingRates = BillingRates.illustrative
    /// Origin the business dashboard / operator console passkeys are scoped to. `nil` = `relyingPartyOrigin`.
    /// The RP ID stays `relyingPartyID`, so a sub-domain origin such as `https://business.viadere.com` also works.
    public var dashboardOrigin: String?

    public var isProduction: Bool { environment == .production }

    /// Deterministic configuration for tests: no network, no background jobs, fixed secrets.
    public static func testing() -> ServerConfig {
        ServerConfig(
            environment: .testing, databaseURL: nil, bindHost: "127.0.0.1", port: 0,
            publicBaseURL: "https://viadere.com", relyingPartyID: "viadere.com", relyingPartyName: "Viadere",
            relyingPartyOrigin: "https://viadere.com", appleTeamID: "TEAMID1234", appStoreID: "1234567890",
            appBundleID: "com.viadere.app", appClipBundleID: "com.viadere.app.Clip",
            connectLinkKey: SymmetricKey(data: Data(repeating: 0x11, count: 32)),
            pepper: Data(repeating: 0x22, count: 32), dataEncryptionKey: SymmetricKey(data: Data(repeating: 0x33, count: 32)),
            apns: nil, twilio: nil, trustedProxyCount: 0, corsAllowedOrigins: [], runBackgroundJobs: false, jobIntervalSeconds: 5, autoMigrate: false,
            maxBodyBytes: 64 * 1024, rateLimits: .standard, accessTokenTTL: 15 * 60, refreshTokenTTL: 30 * 24 * 3600,
            freeDailyInteractionQuota: 1000, allowInsecureWebhookURLs: true)
    }

    /// Loads configuration from the process environment and validates it. Production requires every secret.
    public static func fromEnvironment(_ env: [String: String] = ProcessInfo.processInfo.environment) throws -> ServerConfig {
        let environment = DeploymentEnvironment(rawValue: (env["ENVIRONMENT"] ?? "development").lowercased()) ?? .development
        let production = environment == .production

        func secretBytes(_ name: String, minimum: Int) throws -> Data {
            if let raw = env[name], !raw.isEmpty {
                guard let data = Base64URL.decode(raw) ?? Data(base64Encoded: raw), data.count >= minimum else {
                    throw ServerConfigError.invalid("\(name) (base64url, at least \(minimum) bytes)")
                }
                return data
            }
            if production { throw ServerConfigError.missing(name) }
            // Development only: an ephemeral random secret (data encrypted with it will not survive a restart).
            return SecureToken.randomBytes(max(minimum, 32))
        }

        let databaseURL = env["DATABASE_URL"].flatMap { $0.isEmpty ? nil : $0 }
        if production && databaseURL == nil { throw ServerConfigError.missing("DATABASE_URL") }

        let publicBase = (env["PUBLIC_BASE_URL"] ?? "https://viadere.com").trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard let baseURL = URL(string: publicBase), let scheme = baseURL.scheme, baseURL.host != nil else {
            throw ServerConfigError.invalid("PUBLIC_BASE_URL")
        }
        if production && scheme != "https" { throw ServerConfigError.invalid("PUBLIC_BASE_URL (must be https in production)") }

        var apns: APNsConfig?
        if let key = env["APNS_KEY_P8"].flatMap({ $0.isEmpty ? nil : $0 }) ?? Self.readFile(env["APNS_KEY_PATH"]) {
            guard let keyID = env["APNS_KEY_ID"], let teamID = env["APNS_TEAM_ID"] ?? env["APPLE_TEAM_ID"] else {
                throw ServerConfigError.missing("APNS_KEY_ID / APNS_TEAM_ID")
            }
            apns = APNsConfig(keyPEM: key.replacingOccurrences(of: "\\n", with: "\n"), keyID: keyID, teamID: teamID,
                              topic: env["APNS_TOPIC"] ?? "com.viadere.app",
                              useSandbox: (env["APNS_ENVIRONMENT"] ?? (production ? "production" : "sandbox")) != "production")
        } else if production {
            throw ServerConfigError.missing("APNS_KEY_P8 or APNS_KEY_PATH")
        }

        var twilio: TwilioConfig?
        if let sid = env["TWILIO_ACCOUNT_SID"], let token = env["TWILIO_AUTH_TOKEN"], !sid.isEmpty, !token.isEmpty {
            let from = env["TWILIO_FROM_NUMBER"] ?? ""
            let service = env["TWILIO_MESSAGING_SERVICE_SID"].flatMap { $0.isEmpty ? nil : $0 }
            guard !from.isEmpty || service != nil else { throw ServerConfigError.missing("TWILIO_FROM_NUMBER or TWILIO_MESSAGING_SERVICE_SID") }
            twilio = TwilioConfig(accountSID: sid, authToken: token, fromNumber: from, messagingServiceSID: service)
        } else if production {
            throw ServerConfigError.missing("TWILIO_ACCOUNT_SID / TWILIO_AUTH_TOKEN")
        }

        let teamID = env["APPLE_TEAM_ID"] ?? ""
        if production && teamID.isEmpty { throw ServerConfigError.missing("APPLE_TEAM_ID") }

        var config = ServerConfig(
            environment: environment, databaseURL: databaseURL,
            bindHost: env["BIND_HOST"] ?? "0.0.0.0", port: Int(env["PORT"] ?? "") ?? 8080,
            publicBaseURL: publicBase, relyingPartyID: env["RP_ID"] ?? ViadereCore.domain,
            relyingPartyName: env["RP_NAME"] ?? "Viadere", relyingPartyOrigin: env["RP_ORIGIN"] ?? "https://\(ViadereCore.domain)",
            appleTeamID: teamID.isEmpty ? "TEAMIDDEV0" : teamID, appStoreID: env["APP_STORE_ID"].flatMap { $0.isEmpty ? nil : $0 },
            appBundleID: "\(ViadereCore.bundlePrefix).app", appClipBundleID: "\(ViadereCore.bundlePrefix).app.Clip",
            connectLinkKey: SymmetricKey(data: try secretBytes("CONNECT_LINK_SIGNING_KEY", minimum: 32)),
            pepper: try secretBytes("SERVER_PEPPER", minimum: 32),
            dataEncryptionKey: SymmetricKey(data: try secretBytes("DATA_ENCRYPTION_KEY", minimum: 32).prefix(32)),
            apns: apns, twilio: twilio, trustedProxyCount: Int(env["TRUSTED_PROXY_COUNT"] ?? "") ?? 0,
            corsAllowedOrigins: (env["CORS_ALLOWED_ORIGINS"] ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty },
            runBackgroundJobs: (env["RUN_BACKGROUND_JOBS"] ?? "true") != "false",
            jobIntervalSeconds: min(max(Double(env["JOB_INTERVAL_SECONDS"] ?? "") ?? 5, 0.05), 300),
            autoMigrate: env["AUTO_MIGRATE"] == "true",
            maxBodyBytes: Int(env["MAX_BODY_BYTES"] ?? "") ?? 64 * 1024, rateLimits: .standard,
            accessTokenTTL: 15 * 60, refreshTokenTTL: 30 * 24 * 3600,
            freeDailyInteractionQuota: Int(env["FREE_DAILY_INTERACTION_QUOTA"] ?? "") ?? 1000,
            allowInsecureWebhookURLs: !production && env["ALLOW_INSECURE_WEBHOOKS"] == "true")
        try config.applyPlatformEnvironment(env, production: production)
        return config
    }

    private static func readFile(_ path: String?) -> String? {
        guard let path, !path.isEmpty else { return nil }
        return try? String(contentsOfFile: path, encoding: .utf8)
    }
}

/// Token-bucket parameters for each limiter. `capacity` is the burst, `perMinute` the sustained rate.
public struct RateRule: Sendable, Hashable {
    public var capacity: Double
    public var perMinute: Double
    public init(capacity: Double, perMinute: Double) {
        self.capacity = capacity
        self.perMinute = perMinute
    }
    public static func perMinute(_ n: Double, burst: Double? = nil) -> RateRule { RateRule(capacity: burst ?? n, perMinute: n) }
    public static func perHour(_ n: Double, burst: Double? = nil) -> RateRule { RateRule(capacity: burst ?? n, perMinute: n / 60) }
}

public struct RateLimitSettings: Sendable {
    public var globalIP: RateRule
    public var authCeremony: RateRule
    public var refresh: RateRule
    public var directory: RateRule
    public var device: RateRule
    public var business: RateRule
    public var phoneLinkStartPerConsumer: RateRule
    public var phoneLinkStartPerPhone: RateRule
    public var phoneLinkVerify: RateRule
    public var linkRedeem: RateRule
    public var smsInboundPerPhone: RateRule
    public var smsInboundGlobal: RateRule
    public var providerIP: RateRule
    /// Dashboard / operator state-changing actions per signed-in user.
    public var dashboardAction: RateRule = .perMinute(60, burst: 30)
    /// Dashboard sign-in and sign-up ceremonies per IP.
    public var dashboardAuth: RateRule = .perMinute(30, burst: 20)
    /// Inbound RCS events per phone.
    public var rcsInboundPerPhone: RateRule = .perMinute(20, burst: 10)

    public static let standard = RateLimitSettings(
        globalIP: .perMinute(300), authCeremony: .perMinute(20, burst: 10), refresh: .perMinute(30, burst: 10),
        directory: .perMinute(60, burst: 30), device: .perMinute(240, burst: 60), business: .perMinute(600, burst: 120),
        phoneLinkStartPerConsumer: .perHour(5, burst: 5), phoneLinkStartPerPhone: .perHour(3, burst: 3),
        phoneLinkVerify: .perMinute(10, burst: 5), linkRedeem: .perMinute(10, burst: 5),
        smsInboundPerPhone: .perMinute(20, burst: 10), smsInboundGlobal: .perMinute(3000, burst: 500),
        providerIP: .perMinute(1200, burst: 300))
}
