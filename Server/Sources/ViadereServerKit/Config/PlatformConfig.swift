@preconcurrency import Crypto
import Foundation
import ViadereCore

/// Generic RBM-style RCS provider credentials. `nil` in `ServerConfig.rcs` means RCS is disabled and every
/// interaction uses the SMS path.
public struct RCSConfig: Sendable {
    /// Provider API origin, e.g. `https://rcs-provider.example/v1` (https enforced in production).
    public var baseURL: URL
    /// Bearer credential for outbound calls.
    public var apiToken: String
    /// Shared secret for inbound webhook HMAC verification.
    public var webhookSecret: Data
    /// Verified agent identifier at the provider.
    public var agentId: String

    public init(baseURL: URL, apiToken: String, webhookSecret: Data, agentId: String) {
        self.baseURL = baseURL
        self.apiToken = apiToken
        self.webhookSecret = webhookSecret
        self.agentId = agentId
    }
}

/// Feature flags for channels that are policy-gated. Everything here defaults to off.
public struct ChannelFeatureFlags: Sendable, Equatable {
    /// Apple Messages for Business. Even when `true` the adapter is a non-functional placeholder: Apple has not
    /// approved a single Viadere identity as a multi-merchant switchboard (spec §14). Do not enable in production
    /// until written approval is on file.
    public var appleMessagesForBusiness = false
    public init(appleMessagesForBusiness: Bool = false) { self.appleMessagesForBusiness = appleMessagesForBusiness }
}

/// Business dashboard and operator console session policy.
public struct DashboardSettings: Sendable, Equatable {
    /// A session with no activity for this long is dead.
    public var idleTimeout: TimeInterval
    /// A session never lives longer than this, however active.
    public var absoluteTimeout: TimeInterval
    /// Sensitive actions need a passkey assertion this recent.
    public var reauthWindow: TimeInterval
    public var operatorIdleTimeout: TimeInterval
    public var operatorAbsoluteTimeout: TimeInterval
    public var inviteTTL: TimeInterval
    public var operatorEnrollmentTTL: TimeInterval

    public static let standard = DashboardSettings(
        idleTimeout: 30 * 60, absoluteTimeout: 12 * 3600, reauthWindow: 5 * 60,
        operatorIdleTimeout: 15 * 60, operatorAbsoluteTimeout: 8 * 3600,
        inviteTTL: 7 * 24 * 3600, operatorEnrollmentTTL: 3600)
}

/// Complaint / opt-out thresholds that trigger an automatic throttle.
public struct AbuseThresholds: Sendable, Equatable {
    /// Rolling window the rates are computed over.
    public var window: TimeInterval
    /// Below this many interactions (or relationships for opt-outs) in the window no rate is judged.
    public var minimumSample: Int
    /// "Not me / I don't recognize this" reports ÷ decided + reported interactions.
    public var complaintRate: Double
    /// Consent revocations + disconnects ÷ relationships active at any time in the window.
    public var optOutRate: Double
    /// Daily quota and API rate-limit multiplier while throttled (0 < factor <= 1).
    public var throttleFactor: Double

    public static let standard = AbuseThresholds(window: 7 * 24 * 3600, minimumSample: 20, complaintRate: 0.02,
                                                 optOutRate: 0.10, throttleFactor: 0.25)
}

/// Illustrative metering rates, in **micro-dollars** (1 USD = 1_000_000). Final pricing is undecided
/// (spec §15); platform fees and carrier/provider transport are always priced separately. Configure real
/// contracted rates in deployment; transport rates default to 0 so previews never imply a price.
public struct BillingRates: Sendable, Equatable {
    public var includedInteractionsPerMonth: Int
    public var platformMicrosPerInteraction: Int
    public var transportMicrosPerSMSSegment: Int
    public var transportMicrosPerRCSMessage: Int

    public static let illustrative = BillingRates(includedInteractionsPerMonth: 1000, platformMicrosPerInteraction: 5000,
                                                  transportMicrosPerSMSSegment: 0, transportMicrosPerRCSMessage: 0)
}

extension ServerConfig {
    /// RCS, feature flags, dashboard, abuse and billing settings from the environment.
    mutating func applyPlatformEnvironment(_ env: [String: String], production: Bool) throws {
        if let base = env["RCS_PROVIDER_BASE_URL"], !base.isEmpty {
            guard let url = URL(string: base), let scheme = url.scheme, url.host != nil,
                  scheme == "https" || (!production && scheme == "http") else {
                throw ServerConfigError.invalid("RCS_PROVIDER_BASE_URL (https required)")
            }
            guard let token = env["RCS_PROVIDER_TOKEN"], !token.isEmpty else { throw ServerConfigError.missing("RCS_PROVIDER_TOKEN") }
            guard let secretRaw = env["RCS_WEBHOOK_SECRET"], let secret = Base64URL.decode(secretRaw) ?? Data(base64Encoded: secretRaw),
                  secret.count >= 32 else { throw ServerConfigError.invalid("RCS_WEBHOOK_SECRET (base64url, at least 32 bytes)") }
            guard let agent = env["RCS_AGENT_ID"], !agent.isEmpty, agent.count <= 128 else { throw ServerConfigError.missing("RCS_AGENT_ID") }
            rcs = RCSConfig(baseURL: url, apiToken: token, webhookSecret: secret, agentId: agent)
        }
        channelFlags = ChannelFeatureFlags(appleMessagesForBusiness: env["FEATURE_APPLE_MESSAGES_FOR_BUSINESS"] == "true")
        if let origin = env["DASHBOARD_ORIGIN"], !origin.isEmpty {
            guard let url = URL(string: origin), url.scheme == "https" || !production, url.host != nil, url.path.isEmpty || url.path == "/" else {
                throw ServerConfigError.invalid("DASHBOARD_ORIGIN")
            }
            dashboardOrigin = origin.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        }
        func double(_ name: String) -> Double? { env[name].flatMap(Double.init) }
        if let v = double("ABUSE_COMPLAINT_RATE"), v > 0, v <= 1 { abuse.complaintRate = v }
        if let v = double("ABUSE_OPTOUT_RATE"), v > 0, v <= 1 { abuse.optOutRate = v }
        if let v = env["ABUSE_MIN_SAMPLE"].flatMap(Int.init), v >= 1 { abuse.minimumSample = v }
        if let v = double("ABUSE_WINDOW_DAYS"), v >= 1, v <= 90 { abuse.window = v * 86_400 }
        if let v = double("ABUSE_THROTTLE_FACTOR"), v > 0, v <= 1 { abuse.throttleFactor = v }
        if let v = double("DASHBOARD_IDLE_MINUTES"), v >= 1 { dashboard.idleTimeout = v * 60 }
        if let v = double("DASHBOARD_ABSOLUTE_HOURS"), v >= 1 { dashboard.absoluteTimeout = v * 3600 }
        if let v = env["BILLING_INCLUDED_INTERACTIONS"].flatMap(Int.init), v >= 0 { billingRates.includedInteractionsPerMonth = v }
        if let v = env["BILLING_PLATFORM_MICROS_PER_INTERACTION"].flatMap(Int.init), v >= 0 { billingRates.platformMicrosPerInteraction = v }
        if let v = env["BILLING_TRANSPORT_MICROS_PER_SMS_SEGMENT"].flatMap(Int.init), v >= 0 { billingRates.transportMicrosPerSMSSegment = v }
        if let v = env["BILLING_TRANSPORT_MICROS_PER_RCS_MESSAGE"].flatMap(Int.init), v >= 0 { billingRates.transportMicrosPerRCSMessage = v }
    }
}

/// How long operational records are kept. Everything here holds personal data or message text for delivery only.
public struct RetentionSettings: Sendable, Equatable {
    /// Delivered or dead-lettered webhook deliveries (their bodies hold consumer message text).
    public var webhookDeliveryDays = 30
    /// Finished `sms_outbound` and `channel_outbound` rows (they hold an encrypted phone number).
    public var outboundDays = 30
    /// Used or expired link tokens (they hold an encrypted phone number).
    public var linkTokenDays = 7

    public init() {}

    mutating func apply(_ env: [String: String]) throws {
        func days(_ name: String) throws -> Int? {
            guard let raw = env[name], !raw.isEmpty else { return nil }
            guard let value = Int(raw), (1...3650).contains(value) else { throw ServerConfigError.invalid("\(name) (1-3650 days)") }
            return value
        }
        if let v = try days("WEBHOOK_RETENTION_DAYS") { webhookDeliveryDays = v }
        if let v = try days("OUTBOUND_RETENTION_DAYS") { outboundDays = v }
        if let v = try days("LINK_TOKEN_RETENTION_DAYS") { linkTokenDays = v }
    }
}

/// Where rate-limit counters are kept.
public enum RateLimitStoreMode: String, Sendable, Equatable {
    case memory, database
}

/// A generic transactional-email HTTP API: `POST <url>` with a JSON body `{"from","to","subject","text"}` and the API key in a header
/// (default `Authorization: Bearer <key>`). See Server/README.md for how to point it at a provider.
public struct EmailConfig: Sendable, Equatable {
    public var apiURL: URL
    public var apiKey: String
    public var fromAddress: String
    /// Header carrying the key and the scheme prefix put before it (`Authorization` + `Bearer`; an empty scheme sends the bare key).
    public var authHeader: String = "Authorization"
    public var authScheme: String = "Bearer"

    public init(apiURL: URL, apiKey: String, fromAddress: String, authHeader: String = "Authorization", authScheme: String = "Bearer") {
        self.apiURL = apiURL
        self.apiKey = apiKey
        self.fromAddress = fromAddress
        self.authHeader = authHeader
        self.authScheme = authScheme
    }
}

extension ServerConfig {
    /// Rate-limit store and transactional email from the environment.
    mutating func applyInfrastructureEnvironment(_ env: [String: String], production: Bool) throws {
        let raw = (env["RATE_LIMIT_STORE"] ?? "").lowercased()
        switch raw {
        case "": rateLimitStore = isStrict ? .database : .memory
        case "memory": rateLimitStore = .memory
        case "database": rateLimitStore = .database
        default: throw ServerConfigError.invalid("RATE_LIMIT_STORE (memory or database)")
        }
        if rateLimitStore == .database, databaseURL == nil, isStrict { throw ServerConfigError.missing("DATABASE_URL (required for RATE_LIMIT_STORE=database)") }

        let url = env["EMAIL_API_URL"].flatMap { $0.isEmpty ? nil : $0 }
        let key = env["EMAIL_API_KEY"].flatMap { $0.isEmpty ? nil : $0 }
        let from = env["EMAIL_FROM_ADDRESS"].flatMap { $0.isEmpty ? nil : $0 }
        if url == nil && key == nil && from == nil {
            if isStrict { throw ServerConfigError.missing("EMAIL_API_URL / EMAIL_API_KEY / EMAIL_FROM_ADDRESS") }
            return
        }
        guard let url, let key, let from else { throw ServerConfigError.missing("EMAIL_API_URL, EMAIL_API_KEY and EMAIL_FROM_ADDRESS (all three or none)") }
        guard let parsed = URL(string: url), let scheme = parsed.scheme, parsed.host != nil, parsed.user == nil,
              scheme == "https" || (!isStrict && scheme == "http") else { throw ServerConfigError.invalid("EMAIL_API_URL (https required)") }
        guard DashboardAuthService.normalizeEmail(from) != nil || from.contains("<") && from.hasSuffix(">") else { throw ServerConfigError.invalid("EMAIL_FROM_ADDRESS") }
        var config = EmailConfig(apiURL: parsed, apiKey: key, fromAddress: from)
        if let header = env["EMAIL_API_AUTH_HEADER"], !header.isEmpty {
            guard header.unicodeScalars.allSatisfy({ $0.isASCII && ($0.properties.isAlphabetic || $0 == "-") }) else { throw ServerConfigError.invalid("EMAIL_API_AUTH_HEADER") }
            config.authHeader = header
        }
        if let scheme = env["EMAIL_API_AUTH_SCHEME"] { config.authScheme = scheme }
        email = config
    }
}
