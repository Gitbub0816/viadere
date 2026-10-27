@preconcurrency import Crypto
import Foundation
import ViadereCore

/// Deployment environment. `ENVIRONMENT` is **required** and must be one of `development`, `test`, `staging`, `production`:
/// a missing or misspelled value never silently becomes `development` (which would allow ephemeral secrets and skipped checks).
public enum DeploymentEnvironment: String, Sendable, CaseIterable {
    case development, testing, staging, production

    /// Parses the `ENVIRONMENT` value (`test` is the documented spelling; `testing` is accepted too).
    public static func parse(_ raw: String) -> DeploymentEnvironment? {
        switch raw.lowercased() {
        case "development": .development
        case "test", "testing": .testing
        case "staging": .staging
        case "production": .production
        default: nil
        }
    }

    /// Staging uses the production rules: every secret mandatory, https only, no seed data.
    public var isStrict: Bool { self == .production || self == .staging }
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
    /// Wallet pass signing material. `nil` disables pass issuance (the pass endpoints answer `501`).
    public var passes: PassConfig?
    /// HMAC key of the audit hash chain (`AUDIT_CHAIN_KEY`). Keeping it out of the database means an attacker who can
    /// write the database cannot recompute a forged chain.
    public var auditChainKey: SymmetricKey = SymmetricKey(data: Data(repeating: 0x44, count: 32))
    /// Destination countries (ISO 3166 regions) for verification codes. Default US and CA.
    public var otpAllowedCountries: [String] = ["US", "CA"]
    /// Digits of the E.164 number (after `+`) that identify a destination prefix for the per-prefix OTP budget.
    public var otpPrefixDigits = 5
    /// A digit reply this soon after a menu was issued is treated as a race with the menu change (SMS carries no
    /// timestamp): the menu is shown again instead of acting on the digit. `0` disables the guard.
    public var smsMenuRaceWindow: TimeInterval = 3
    public var retention = RetentionSettings()
    /// Audit events up to this sequence number may be legacy (unkeyed SHA-256, written before `AUDIT_CHAIN_KEY` existed). Set
    /// `AUDIT_CHAIN_LEGACY_THROUGH_SEQ` once, to the last event sequence of the pre-upgrade chain; the default 0 means every event
    /// must be keyed. It lives in the environment, not the database, so a database writer cannot downgrade the chain to an
    /// unkeyed one and recompute it.
    public var auditLegacyThroughSeq = 0
    /// What to do with an enrollment without a valid App Attest attestation (`APP_ATTEST_MODE`; default `require` in production/staging).
    public var appAttestMode: AppAttestMode = .off
    /// Which App Attest environment the app's builds attest in (`APP_ATTEST_ENVIRONMENT`).
    public var appAttestEnvironment: AppAttestEnvironment = .development
    /// Where rate-limit counters live (`RATE_LIMIT_STORE`): `database` (shared by every instance; the default in staging/production)
    /// or `memory` (per instance; development and tests).
    public var rateLimitStore: RateLimitStoreMode = .memory
    /// Transactional email provider (`EMAIL_API_URL`, `EMAIL_API_KEY`, `EMAIL_FROM_ADDRESS`). `nil` = log-only sender (never in staging/production).
    public var email: EmailConfig?

    /// True only for `production`.
    public var isProduction: Bool { environment == .production }
    /// True for `production` and `staging`.
    public var isStrict: Bool { environment.isStrict }

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
            freeDailyInteractionQuota: 1000, allowInsecureWebhookURLs: true, smsMenuRaceWindow: 0)
    }

    /// Loads configuration from the process environment and validates it. Production requires every secret.
    public static func fromEnvironment(_ env: [String: String] = ProcessInfo.processInfo.environment) throws -> ServerConfig {
        guard let rawEnvironment = env["ENVIRONMENT"], !rawEnvironment.isEmpty else {
            throw ServerConfigError.missing("ENVIRONMENT (development, test, staging or production)")
        }
        guard let environment = DeploymentEnvironment.parse(rawEnvironment) else {
            throw ServerConfigError.invalid("ENVIRONMENT (development, test, staging or production)")
        }
        let production = environment.isStrict
        let databaseURL = env["DATABASE_URL"].flatMap { $0.isEmpty ? nil : $0 }

        func secretBytes(_ name: String, minimum: Int) throws -> Data {
            if let raw = env[name], !raw.isEmpty {
                guard let data = Base64URL.decode(raw) ?? Data(base64Encoded: raw), data.count >= minimum else {
                    throw ServerConfigError.invalid("\(name) (base64url, at least \(minimum) bytes)")
                }
                return data
            }
            if production { throw ServerConfigError.missing(name) }
            // An ephemeral secret would make everything already stored under it unreadable after a restart, so it is
            // only allowed with the throwaway in-memory database.
            if databaseURL != nil { throw ServerConfigError.missing("\(name) (required whenever DATABASE_URL is set)") }
            return SecureToken.randomBytes(max(minimum, 32))
        }

        if production && databaseURL == nil { throw ServerConfigError.missing("DATABASE_URL") }

        let publicBase = (env["PUBLIC_BASE_URL"] ?? "https://viadere.com").trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        guard let baseURL = URL(string: publicBase), let scheme = baseURL.scheme, baseURL.host != nil else {
            throw ServerConfigError.invalid("PUBLIC_BASE_URL")
        }
        if production && scheme != "https" { throw ServerConfigError.invalid("PUBLIC_BASE_URL (must be https in production)") }
        // Passkeys are scoped to the origin: outside local development it must be an https origin of the relying party.
        let relyingPartyID = env["RP_ID"] ?? ViadereCore.domain
        let relyingPartyOrigin = env["RP_ORIGIN"] ?? "https://\(ViadereCore.domain)"
        if environment != .development {
            guard let origin = URL(string: relyingPartyOrigin), origin.scheme == "https", let host = origin.host,
                  host == relyingPartyID || host.hasSuffix("." + relyingPartyID), origin.user == nil, origin.path.isEmpty || origin.path == "/" else {
                throw ServerConfigError.invalid("RP_ORIGIN (must be an https origin of RP_ID outside development)")
            }
        }

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
            publicBaseURL: publicBase, relyingPartyID: relyingPartyID,
            relyingPartyName: env["RP_NAME"] ?? "Viadere", relyingPartyOrigin: relyingPartyOrigin,
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
        config.auditChainKey = SymmetricKey(data: try secretBytes("AUDIT_CHAIN_KEY", minimum: 32))
        if production {
            // Independent secrets: one leaked value must not unlock the others.
            let keys: [(String, Data)] = [("CONNECT_LINK_SIGNING_KEY", config.connectLinkKey.withUnsafeBytes { Data($0) }), ("SERVER_PEPPER", config.pepper),
                                          ("DATA_ENCRYPTION_KEY", config.dataEncryptionKey.withUnsafeBytes { Data($0) }),
                                          ("AUDIT_CHAIN_KEY", config.auditChainKey.withUnsafeBytes { Data($0) })]
            for (index, first) in keys.enumerated() {
                for second in keys[(index + 1)...] where first.1.prefix(32) == second.1.prefix(32) {
                    throw ServerConfigError.invalid("\(first.0) and \(second.0) must be different values")
                }
            }
        }
        if let raw = env["OTP_ALLOWED_COUNTRIES"], !raw.isEmpty {
            let countries = raw.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces).uppercased() }.filter { !$0.isEmpty }
            guard !countries.isEmpty, countries.allSatisfy({ PhoneRegions.callingCodes[$0] != nil }) else {
                throw ServerConfigError.invalid("OTP_ALLOWED_COUNTRIES (comma-separated ISO regions Viadere knows: \(PhoneRegions.callingCodes.keys.sorted().joined(separator: ", ")))")
            }
            config.otpAllowedCountries = countries
        }
        if let raw = env["AUDIT_CHAIN_LEGACY_THROUGH_SEQ"], !raw.isEmpty {
            guard let seq = Int(raw), seq >= 0 else { throw ServerConfigError.invalid("AUDIT_CHAIN_LEGACY_THROUGH_SEQ") }
            config.auditLegacyThroughSeq = seq
        }
        if let seconds = env["SMS_MENU_RACE_SECONDS"].flatMap(Double.init), seconds >= 0, seconds <= 30 { config.smsMenuRaceWindow = seconds }
        try config.retention.apply(env)
        try config.applyIdentityEnvironment(env, production: production)
        try config.applyPlatformEnvironment(env, production: production)
        try config.applyPassEnvironment(env)
        try config.applyInfrastructureEnvironment(env, production: production)
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
    /// Verification-code SMS across the whole platform (toll-fraud ceiling). Exceeding it is logged as an alert.
    public var otpGlobal: RateRule = .perHour(600, burst: 100)
    /// Verification-code SMS per destination prefix (country code plus the next digits), against pumping a premium range.
    public var otpPerPrefix: RateRule = .perHour(60, burst: 20)
    /// Dashboard / operator state-changing actions per signed-in user.
    public var dashboardAction: RateRule = .perMinute(60, burst: 30)
    /// Dashboard sign-in and sign-up ceremonies per IP.
    public var dashboardAuth: RateRule = .perMinute(30, burst: 20)
    /// Inbound RCS events per phone.
    public var rcsInboundPerPhone: RateRule = .perMinute(20, burst: 10)
    /// Redemption codes a business validates per minute (the brute-force bound on the 50-bit code space).
    public var redemptionConsume: RateRule = .perMinute(60, burst: 30)
    /// Redemption codes a consumer can request per minute.
    public var rewardRedeem: RateRule = .perMinute(10, burst: 5)
    /// Household invitation lookups (preview / accept) per consumer. A wrong code costs a token; the budget is small.
    public var inviteAttemptPerConsumer: RateRule = .perHour(10, burst: 5)
    /// Household invitation lookups across all consumers, against distributed guessing.
    public var inviteAttemptGlobal: RateRule = .perMinute(120, burst: 60)
    /// Sensitive delegation invitations a consumer can create per hour.
    public var inviteCreatePerConsumer: RateRule = .perHour(20, burst: 10)
    /// Household invitation previews per consumer (every preview, successful or not).
    public var invitePreviewPerConsumer: RateRule = .perHour(30, burst: 15)
    /// PassKit `log` posts per client IP.
    public var walletLogPerIP: RateRule = .perMinute(10, burst: 10)
    /// PassKit web service calls per client IP.
    public var walletWebServicePerIP: RateRule = .perMinute(120, burst: 60)
    /// Failed PassKit authentications per pass.
    public var walletAuthFailurePerPass: RateRule = .perMinute(10, burst: 10)

    public static let standard = RateLimitSettings(
        globalIP: .perMinute(300), authCeremony: .perMinute(20, burst: 10), refresh: .perMinute(30, burst: 10),
        directory: .perMinute(60, burst: 30), device: .perMinute(240, burst: 60), business: .perMinute(600, burst: 120),
        phoneLinkStartPerConsumer: .perHour(5, burst: 5), phoneLinkStartPerPhone: .perHour(3, burst: 3),
        phoneLinkVerify: .perMinute(10, burst: 5), linkRedeem: .perMinute(10, burst: 5),
        smsInboundPerPhone: .perMinute(20, burst: 10), smsInboundGlobal: .perMinute(3000, burst: 500),
        providerIP: .perMinute(1200, burst: 300))
}
