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
    /// `AUTH_NUMBER_MATCHING_REQUIRED` (ADR-0019 §6, Stage 5 review S5-03), default **off**: when on, the legacy `POST /v1/business/approve/requests` route creates no
    /// approval (`422 number_match_required`); push approvals then exist only through `POST /v1/business/auth-approvals`, which always carries a number. Off keeps
    /// the legacy route working for businesses that have not migrated.
    public var numberMatchingRequired = false
    /// `AUTH_LINK_SERVICE_ENABLED` (ADR-0019 §6, ADR-0021 §5), default **off** everywhere: the link-service redemption
    /// `POST /v1/business/auth-links/redeem` answers `404` while off. On, it relays to the authority (`AUTHORITY_URL`) and fails closed (`503`) without one.
    public var linkServiceEnabled = false
    /// `AUTH_DESTINATION_RECORDS_ENABLED` (ADR-0031 §2), default **off** everywhere: the device route `GET /v1/auth-tenants/{tenantId}/destination-keys`
    /// answers `404` while off. On, it relays the authority's signed tenant record and revocation list (`AUTHORITY_URL`) and fails closed (`503`)
    /// without one; the api's own create-time check then also reads the authority record (`AuthorityRecordTenantKeys`).
    public var destinationRecordsEnabled = false
    /// `AUTH_DESTINATION_SIGNATURE_REQUIRED` (ADR-0031 section 5): business-mode links need a business-signed destination statement. `false` exists only so the
    /// unit tests can exercise both paths; staging and production refuse it.
    public var destinationSignatureRequired = true
    /// `AUTH_EMAIL_FALLBACK_ENABLED` (ADR-0020 section 7, decision 13, S1-A10-6), default **off** everywhere. On, a business whose tenant policy
    /// `allow_email_fallback` is on may ask, per `otp` request, for its code to be mailed to an address it supplies (`channels` with `email` and
    /// `fallback.email.address`). Off, such a request is `422 email_unavailable` as before. **Refused in staging and production** (strict
    /// `ENVIRONMENT`) until the owner records where the email provider stores message content and activity (IMPLEMENTATION_LEDGER L-8,
    /// `docs/ops/DATA-INVENTORY.md`) and lifts the refusal by a reviewed change.
    public var emailFallbackEnabled = false
    /// `AUTH_LIVE_KEY_ASSURANCE`: what a live API key must carry on auth routes, besides itself (ADR-0020 section 3). `mtls_or_signature` (the default in
    /// staging and production) accepts either a verified RFC 9421 request signature with a key registered for that API key (SECURITY §2.112) or a key bound
    /// to mutual TLS (Tier E); `mtls` accepts mutual TLS only (stricter); `none` is development and tests only. Without one a live key is refused
    /// (`401 signature_required`), never accepted on a bearer alone. Test keys reach sandbox customers only and are exempt.
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
    /// Per tenant: reads of a destination-key registration nonce (`POST /v1/business/destination-keys/registration-nonce`). Namespace `authdl-keynonce`,
    /// so it fails closed when the shared rate-limit store is down (`DatabaseRateLimitStore.defaultFailClosed`).
    public var registrationNonceRate: RateRule = .perHour(30, burst: 5)
    /// "This wasn't me" reports for one (business, customer) inside `reportWindow` that make further deliveries silent (never refused: a count a stranger can
    /// raise by spamming must not be able to lock the customer out of their own sign-in).
    public var reportThreshold = 3
    public var reportWindow: TimeInterval = 3600
    public var maxDispatchAttempts = 3
    /// Email fallback budgets (namespaces `authdl-email-*`, so they fail closed when the shared rate-limit store is down). Over any of them the
    /// delivery is still created and openable in the app, but **no email is sent** and the address is not stored; never a refusal, like the alert
    /// budgets (S1-A2-6). Per tenant, per (tenant, customer) and per recipient address (keyed hash), because the address is business-supplied.
    public var emailTenantRate: RateRule = .perHour(200, burst: 50)
    public var emailSubjectRate = RateRule(capacity: 3, perMinute: 0.3)              // 3 per 10 minutes
    public var emailSubjectDailyRate = RateRule(capacity: 10, perMinute: 10.0 / 1440) // 10 per day
    public var emailAddressRate: RateRule = .perHour(5, burst: 3)
    /// A code sent by email lives at most this long (ADR-0020 section 7, S1-A10-6: at most 15 minutes).
    public static let maxEmailLifetime = 900
    /// T-class metadata of ended deliveries is deleted after this (owner decision 10).
    public var metadataRetention: TimeInterval = 30 * 86_400

    public enum LiveKeyAssurance: String, Sendable {
        case mtlsOrSignature = "mtls_or_signature"
        case mtls
        case none
    }

    public init() {}

    /// The cipher of the pending secrets.
    var cipher: FieldCipher { FieldCipher(key: secretKey, keyId: secretKeyId, previous: [:]) }
}

extension ServerConfig {
    /// `AUTH_DELIVERY_ENABLED`, `AUTH_NUMBER_MATCHING_REQUIRED`, `AUTH_DESTINATION_SIGNATURE_REQUIRED`, `AUTH_LIVE_KEY_ASSURANCE`, `AUTH_SECRET_KEY`.
    mutating func applyAuthDeliveryEnvironment(_ env: [String: String], production: Bool) throws {
        switch env["AUTH_DELIVERY_ENABLED"] {
        case "true": authDelivery.enabled = true
        case "false": authDelivery.enabled = false
        case nil, "": authDelivery.enabled = !production
        default: throw ServerConfigError.invalid("AUTH_DELIVERY_ENABLED (true or false)")
        }
        switch env["AUTH_NUMBER_MATCHING_REQUIRED"] {
        case "true": authDelivery.numberMatchingRequired = true
        case "false", nil, "": authDelivery.numberMatchingRequired = false
        default: throw ServerConfigError.invalid("AUTH_NUMBER_MATCHING_REQUIRED (true or false)")
        }
        switch env["AUTH_LINK_SERVICE_ENABLED"]?.lowercased() {
        case "true":
            // Staging only until the owner enables it for production by a reviewed change (ADR-0021 §5; the pilot runs on staging), like
            // `OIDC_PROVIDER_ENABLED`: `ENVIRONMENT=production` refuses to start with it on.
            guard env["ENVIRONMENT"]?.lowercased() != "production" else {
                throw ServerConfigError.invalid("AUTH_LINK_SERVICE_ENABLED (refused with ENVIRONMENT=production until the owner enables the link service there)")
            }
            authDelivery.linkServiceEnabled = true
        case "false", nil, "": authDelivery.linkServiceEnabled = false
        default: throw ServerConfigError.invalid("AUTH_LINK_SERVICE_ENABLED (true or false)")
        }
        switch env["AUTH_DESTINATION_RECORDS_ENABLED"]?.lowercased() {
        case "true": authDelivery.destinationRecordsEnabled = true
        case "false", nil, "": authDelivery.destinationRecordsEnabled = false
        default: throw ServerConfigError.invalid("AUTH_DESTINATION_RECORDS_ENABLED (true or false)")
        }
        switch env["AUTH_EMAIL_FALLBACK_ENABLED"]?.lowercased() {
        case "true":
            // Email fallback gate (ADR-0020 section 7, decision 13): disabled in staging and production until the owner verifies and records the
            // email provider's storage location and retention (ledger L-8). Lifting this refusal is a reviewed code change, not a setting.
            guard !production else {
                throw ServerConfigError.invalid("AUTH_EMAIL_FALLBACK_ENABLED (refused in staging and production until the email-fallback gate, ledger L-8, is recorded)")
            }
            authDelivery.emailFallbackEnabled = true
        case "false", nil, "": authDelivery.emailFallbackEnabled = false
        default: throw ServerConfigError.invalid("AUTH_EMAIL_FALLBACK_ENABLED (true or false)")
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
        case nil, "": authDelivery.liveKeyAssurance = production ? .mtlsOrSignature : .none
        case let raw?:
            guard let mode = AuthDeliverySettings.LiveKeyAssurance(rawValue: raw) else {
                throw ServerConfigError.invalid("AUTH_LIVE_KEY_ASSURANCE (mtls_or_signature, mtls or none)")
            }
            guard !(production && mode == .none) else { throw ServerConfigError.invalid("AUTH_LIVE_KEY_ASSURANCE (none is not allowed in staging or production)") }
            authDelivery.liveKeyAssurance = mode
        }
        if let raw = env["REQUEST_SIGNATURE_AUTHORITIES"], !raw.isEmpty { requestSignatures.authorities = try RequestSignatureSettings.parse(raw) }
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
