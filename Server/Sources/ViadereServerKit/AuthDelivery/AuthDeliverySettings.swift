@preconcurrency import Crypto
import Foundation
import Vapor
import ViadereCore

/// Authentication delivery (ADR-0019 section 6, ADR-0020): release gate, secret key and limits.
///
/// **Release gate.** `AUTH_DELIVERY_ENABLED` defaults to **off in staging and production** and to on in development and tests. While it is off every
/// auth-delivery route (`/v1/business/auth-deliveries`, `/v1/auth-deliveries`, `/v1/business/webhooks/test`) answers `404` and the queue handlers do nothing;
/// stored rows are untouched. Turning it off is also the kill switch.
public struct AuthDeliverySettings: Sendable {
    public var enabled = true
    /// `AUTH_DESTINATION_SIGNATURE_REQUIRED` (ADR-0031 section 5): business-mode links need a business-signed destination statement. `false` exists only so the
    /// unit tests can exercise both paths; staging and production refuse it.
    public var destinationSignatureRequired = true
    /// `AUTH_LIVE_KEY_ASSURANCE`: what a live API key must carry on auth routes. `mtls` (the default in staging and production) needs a key bound to mutual TLS
    /// (Tier E); `none` is development and tests only. RFC 9421 request signatures (ADR-0020 section 3) follow in a later stage; until then a live key
    /// without mutual TLS is refused (`401 signature_required`), never accepted on a bearer alone. Test keys reach sandbox customers only and are exempt.
    public var liveKeyAssurance: LiveKeyAssurance = .none
    /// `AUTH_SECRET_KEY`: AES-256-GCM key of the pending secrets (`auth_delivery_secrets`), independent of `DATA_ENCRYPTION_KEY`.
    public var secretKey = SymmetricKey(size: .bits256)
    public var secretKeyId = "ak1"

    /// The only budget that refuses with `429` (ADR-0020 section 8): deliveries per tenant per minute.
    public var tenantRate: RateRule = .perMinute(120, burst: 60)
    /// Per-subject budgets limit **alerting, not availability** (S1-A2-6): above either, a new delivery is still created and openable from the inbox, but silent.
    public var subjectBurstRate = RateRule(capacity: 5, perMinute: 0.5)       // 5 per 10 minutes
    public var subjectDailyRate = RateRule(capacity: 20, perMinute: 20.0 / 1440) // 20 per day
    /// Per device.
    public var openRate: RateRule = .perMinute(30, burst: 10)
    public var denyRate: RateRule = .perMinute(60, burst: 30)
    /// "This wasn't me" reports for one (business, customer) inside `reportWindow` that make further deliveries silent (never refused: a count a stranger can
    /// raise by spamming must not be able to lock the customer out of their own sign-in).
    public var reportThreshold = 3
    public var reportWindow: TimeInterval = 3600
    public var maxDispatchAttempts = 3
    /// T-class metadata of ended deliveries is deleted after this (owner decision 10).
    public var metadataRetention: TimeInterval = 30 * 86_400

    public enum LiveKeyAssurance: String, Sendable { case mtls, none }

    public init() {}

    /// The cipher of the pending secrets.
    var cipher: FieldCipher { FieldCipher(key: secretKey, keyId: secretKeyId, previous: [:]) }
}

extension ServerConfig {
    /// `AUTH_DELIVERY_ENABLED`, `AUTH_DESTINATION_SIGNATURE_REQUIRED`, `AUTH_LIVE_KEY_ASSURANCE`, `AUTH_SECRET_KEY`.
    mutating func applyAuthDeliveryEnvironment(_ env: [String: String], production: Bool) throws {
        switch env["AUTH_DELIVERY_ENABLED"] {
        case "true": authDelivery.enabled = true
        case "false": authDelivery.enabled = false
        case nil, "": authDelivery.enabled = !production
        default: throw ServerConfigError.invalid("AUTH_DELIVERY_ENABLED (true or false)")
        }
        switch env["AUTH_DESTINATION_SIGNATURE_REQUIRED"] {
        case "true", nil, "": authDelivery.destinationSignatureRequired = true
        case "false":
            // The pilot release check refuses `false` too: the flag exists so the unit tests can exercise both paths.
            guard !production else { throw ServerConfigError.invalid("AUTH_DESTINATION_SIGNATURE_REQUIRED (false is not allowed in staging or production)") }
            authDelivery.destinationSignatureRequired = false
        default: throw ServerConfigError.invalid("AUTH_DESTINATION_SIGNATURE_REQUIRED (true or false)")
        }
        switch env["AUTH_LIVE_KEY_ASSURANCE"].map({ $0.lowercased() }) {
        case nil, "": authDelivery.liveKeyAssurance = production ? .mtls : .none
        case let raw?:
            guard let mode = AuthDeliverySettings.LiveKeyAssurance(rawValue: raw) else { throw ServerConfigError.invalid("AUTH_LIVE_KEY_ASSURANCE (mtls or none)") }
            guard !(production && mode == .none) else { throw ServerConfigError.invalid("AUTH_LIVE_KEY_ASSURANCE (none is not allowed in staging or production)") }
            authDelivery.liveKeyAssurance = mode
        }
        if let raw = env["AUTH_SECRET_KEY"], !raw.isEmpty {
            guard let bytes = Base64URL.decode(raw) ?? Data(base64Encoded: raw), bytes.count >= 32 else {
                throw ServerConfigError.invalid("AUTH_SECRET_KEY (base64url, at least 32 bytes)")
            }
            guard bytes.prefix(32) != dataEncryptionKey.withUnsafeBytes({ Data($0) }).prefix(32) else {
                throw ServerConfigError.invalid("AUTH_SECRET_KEY and DATA_ENCRYPTION_KEY must be different values")
            }
            authDelivery.secretKey = SymmetricKey(data: bytes.prefix(32))
        } else if authDelivery.enabled, production {
            // An ephemeral key would make every pending secret unreadable after a restart; with the gate off nothing is read.
            throw ServerConfigError.missing("AUTH_SECRET_KEY (required when AUTH_DELIVERY_ENABLED is true in staging or production)")
        }
    }
}

/// `404` while `AUTH_DELIVERY_ENABLED` is off: the feature does not exist, whatever the credentials.
enum AuthDeliveryGate {
    static func require(_ ctx: ServerContext) throws {
        guard ctx.config.authDelivery.enabled else { throw APIError.notFound }
    }
}
