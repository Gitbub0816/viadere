import Foundation
import ViadereCore

/// Verify (WP3) configuration. The release gate **defaults to off everywhere**: `VERIFY_ENABLED` must stay unset in production until the
/// Phase 3 gate (SECURITY-TRUST-PLATFORM-SPEC §17) is recorded; in staging and production enabling it also requires
/// `VERIFY_GATE_REFERENCE`, the identifier of that recorded gate decision, so the flag cannot be flipped without naming it. The flag is
/// also a kill switch: off makes every Verify route answer `404`, and the per-capability switches of WP2 apply on top.
public struct VerifySettings: Sendable {
    public var enabled = false
    /// The recorded Phase 3 gate decision (ticket or document id). Required to enable Verify in staging and production.
    public var gateReference: String?

    // Apple Wallet identity presentment
    /// The Apple merchant identifier of the app's `PKIdentityRequest`. Wallet is offered only when this and a key are configured.
    public var walletMerchantIdentifier: String?
    /// PEM file paths of the identity-encryption private key(s), current key first (`WALLET_ENCRYPTION_KEY_PATHS`). Development only;
    /// production uses a KMS-wrapped key through `WalletEncryptionKeySource`.
    public var walletEncryptionKeyPaths: [String] = []
    /// KMS-wrapped key blobs (base64url), current first (`WALLET_ENCRYPTION_KEY_WRAPPED`), unwrapped by the platform KMS.
    public var walletEncryptionKeyWrapped: [String] = []
    /// Directory of trusted IACA root certificates (`WALLET_IACA_DIR`).
    public var walletIACADirectory: String?
    /// SHA-256 fingerprints (lowercase hex of the DER) the trust store is pinned to (`WALLET_IACA_SHA256`).
    public var walletIACAPinned: Set<String> = []
    /// Wallet credential status (SECURITY §2.60 "Wallet credential status"). Hosts allowed to serve each issuer's status lists
    /// (`WALLET_STATUS_LIST_HOSTS`, `<IACA sha256>:<host>` entries): a status `uri` on any other host is never fetched.
    var walletStatusHosts = StatusListHostPolicy(hostsByAnchor: [:])
    /// Upper bound on how long a verified list is reused (`WALLET_STATUS_LIST_MAX_CACHE_SECONDS`, 60-3600, default 3600): the token's own `ttl` and
    /// `exp` shorten it, never lengthen it. One hour bounds how long a revocation can go unseen while keeping one fetch per issuer list per hour.
    public var walletStatusMaxCache: TimeInterval = 3600
    public static let walletStatusMaxCacheBounds: ClosedRange<Int> = 60...3600
    /// When a list cannot be obtained or trusted (`WALLET_STATUS_FAIL_MODE`): `high_assurance` (default) refuses for `high`/`critical` capabilities,
    /// `all` refuses for every capability. There is no fail-open setting.
    var walletStatusFailMode: WalletStatusPolicy.FailMode = .highAssurance
    /// `WALLET_STATUS_REQUIRED=true` refuses a Wallet credential that carries no status reference (default `false`).
    public var walletStatusRequired = false

    // Didit
    public var diditAPIKey: String?
    /// The **new sessions** switch (`DIDIT_NEW_SESSIONS_ENABLED`, default on). Off: no new document verification starts, but the provider client
    /// stays (it needs only `DIDIT_API_KEY`) so finished and abandoned sessions are still purged. Removing the API key is *not* the way to
    /// stop Didit; it would also stop the erasure of what Didit already holds.
    public var diditNewSessionsEnabled = true
    public var diditAPIBase = "https://verification.didit.me"
    /// The workflow that runs document capture, liveness and face match (the only one used for age thresholds and identity).
    public var diditWorkflowIdentity: String?
    /// Webhook signing secrets: the current one and, for 24 hours after a rotation, the previous one.
    public var diditWebhookSecrets: [String] = []
    /// How far a webhook's `X-Timestamp` may differ from now.
    public var diditWebhookTolerance: TimeInterval = 300

    /// Refuse `identity.name` / `identity.address` requests from a business that has not published an `hpke-encryption` key in the key
    /// directory (`VERIFY_REQUIRE_E2EE_IDENTITY`, default off). With it off, a business without a key retrieves identity attributes over its
    /// authenticated, recipient-bound, single-use API response; with a key, they are always end-to-end encrypted to it.
    public var requireEncryptedIdentity = false

    /// How often the consumer may start verification attempts, and request creation per business.
    public var createRate: RateRule = .perMinute(60, burst: 30)
    public var attemptRate: RateRule = .perMinute(30, burst: 20)
    /// Verification-session code lookups ("Verify with Viadere"): per account and globally, like link-session lookups (the 40-bit code space and the
    /// five-minute lifetime then make a search hopeless).
    public var sessionLookupRate: RateRule = .perHour(10, burst: 5)
    public var sessionLookupRateGlobal: RateRule = .perMinute(120, burst: 60)

    public init() {}

    public var walletConfigured: Bool {
        walletMerchantIdentifier?.isEmpty == false && !(walletEncryptionKeyPaths + walletEncryptionKeyWrapped).isEmpty && walletIACADirectory?.isEmpty == false
    }

    public var diditConfigured: Bool {
        diditAPIKey?.isEmpty == false && diditWorkflowIdentity?.isEmpty == false && !diditWebhookSecrets.isEmpty
    }
}

extension ServerConfig {
    mutating func applyVerifyEnvironment(_ env: [String: String], production: Bool) throws {
        func value(_ name: String) -> String? { env[name].flatMap { $0.isEmpty ? nil : $0 } }
        func list(_ name: String) -> [String] {
            (env[name] ?? "").split(separator: ",").map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }.filter { !$0.isEmpty }
        }
        var settings = VerifySettings()
        settings.enabled = env["VERIFY_ENABLED"] == "true"
        settings.gateReference = value("VERIFY_GATE_REFERENCE")
        settings.requireEncryptedIdentity = env["VERIFY_REQUIRE_E2EE_IDENTITY"] == "true"
        settings.walletMerchantIdentifier = value("WALLET_MERCHANT_ID")
        settings.walletEncryptionKeyPaths = list("WALLET_ENCRYPTION_KEY_PATHS")
        settings.walletEncryptionKeyWrapped = list("WALLET_ENCRYPTION_KEY_WRAPPED")
        settings.walletIACADirectory = value("WALLET_IACA_DIR")
        settings.walletIACAPinned = Set(list("WALLET_IACA_SHA256").map { $0.lowercased().replacingOccurrences(of: ":", with: "") })
        guard settings.walletIACAPinned.allSatisfy({ $0.count == 64 && $0.allSatisfy(\.isHexDigit) }) else {
            throw ServerConfigError.invalid("WALLET_IACA_SHA256 (comma-separated SHA-256 fingerprints, 64 hex characters each)")
        }
        if let raw = value("WALLET_STATUS_LIST_HOSTS") {
            settings.walletStatusHosts = try StatusListHostPolicy.parse(raw)
            // A host bound to an issuer the trust store will never accept is a typo.
            if !settings.walletIACAPinned.isEmpty, let stray = settings.walletStatusHosts.hostsByAnchor.keys.first(where: { !settings.walletIACAPinned.contains($0) }) {
                throw ServerConfigError.invalid("WALLET_STATUS_LIST_HOSTS (\(stray.prefix(16)) is not one of WALLET_IACA_SHA256)")
            }
        }
        if let raw = value("WALLET_STATUS_LIST_MAX_CACHE_SECONDS") {
            guard let seconds = Int(raw), VerifySettings.walletStatusMaxCacheBounds.contains(seconds) else {
                throw ServerConfigError.invalid("WALLET_STATUS_LIST_MAX_CACHE_SECONDS (60 to 3600; it can only shorten the default)")
            }
            settings.walletStatusMaxCache = TimeInterval(seconds)
        }
        switch value("WALLET_STATUS_FAIL_MODE")?.lowercased() {
        case nil, "high_assurance": settings.walletStatusFailMode = .highAssurance
        case "all": settings.walletStatusFailMode = .all
        default: throw ServerConfigError.invalid("WALLET_STATUS_FAIL_MODE (high_assurance or all; there is no fail-open mode)")
        }
        switch value("WALLET_STATUS_REQUIRED")?.lowercased() {
        case nil, "false": settings.walletStatusRequired = false
        case "true": settings.walletStatusRequired = true
        default: throw ServerConfigError.invalid("WALLET_STATUS_REQUIRED (true or false)")
        }
        settings.diditAPIKey = value("DIDIT_API_KEY")
        settings.diditNewSessionsEnabled = env["DIDIT_NEW_SESSIONS_ENABLED"] != "false"
        settings.diditWorkflowIdentity = value("DIDIT_WORKFLOW_ID_IDENTITY")
        settings.diditWebhookSecrets = [value("DIDIT_WEBHOOK_SECRET"), value("DIDIT_WEBHOOK_SECRET_PREVIOUS")].compactMap { $0 }
        if let base = value("DIDIT_API_BASE") {
            // The API key is sent to this host: it must be https (a plain-http base is accepted only outside strict environments, for local fakes).
            guard let url = URL(string: base), url.host != nil, url.scheme == "https" || (!production && url.scheme == "http"), url.user == nil else {
                throw ServerConfigError.invalid("DIDIT_API_BASE (an https URL)")
            }
            settings.diditAPIBase = base.trimmingCharacters(in: CharacterSet(charactersIn: "/"))
        }
        if settings.enabled, environment.isStrict {
            guard settings.gateReference != nil else { throw ServerConfigError.missing("VERIFY_GATE_REFERENCE (the recorded Phase 3 gate decision) to enable VERIFY_ENABLED") }
            guard settings.walletConfigured || settings.diditConfigured else {
                throw ServerConfigError.missing("a configured verification method (WALLET_MERCHANT_ID with WALLET_ENCRYPTION_KEY_PATHS or WALLET_ENCRYPTION_KEY_WRAPPED and WALLET_IACA_DIR, or DIDIT_API_KEY with DIDIT_WORKFLOW_ID_IDENTITY and DIDIT_WEBHOOK_SECRET)")
            }
            if settings.walletConfigured, settings.walletIACAPinned.isEmpty { throw ServerConfigError.missing("WALLET_IACA_SHA256 (IACA fingerprint pinning is required in staging and production)") }
            if settings.walletConfigured, !settings.walletEncryptionKeyPaths.isEmpty {
                throw ServerConfigError.invalid("WALLET_ENCRYPTION_KEY_PATHS (a key file is for development; use WALLET_ENCRYPTION_KEY_WRAPPED with the KMS in staging and production)")
            }
        }
        verify = settings
    }
}
