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

    // Didit
    public var diditAPIKey: String?
    public var diditAPIBase = "https://verification.didit.me"
    /// The workflow that runs document capture, liveness and face match (the only one used for age thresholds and identity).
    public var diditWorkflowIdentity: String?
    /// Webhook signing secrets: the current one and, for 24 hours after a rotation, the previous one.
    public var diditWebhookSecrets: [String] = []
    /// How far a webhook's `X-Timestamp` may differ from now.
    public var diditWebhookTolerance: TimeInterval = 300

    /// How often the consumer may start verification attempts, and request creation per business.
    public var createRate: RateRule = .perMinute(60, burst: 30)
    public var attemptRate: RateRule = .perMinute(30, burst: 20)

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
        settings.walletMerchantIdentifier = value("WALLET_MERCHANT_ID")
        settings.walletEncryptionKeyPaths = list("WALLET_ENCRYPTION_KEY_PATHS")
        settings.walletEncryptionKeyWrapped = list("WALLET_ENCRYPTION_KEY_WRAPPED")
        settings.walletIACADirectory = value("WALLET_IACA_DIR")
        settings.walletIACAPinned = Set(list("WALLET_IACA_SHA256").map { $0.lowercased().replacingOccurrences(of: ":", with: "") })
        guard settings.walletIACAPinned.allSatisfy({ $0.count == 64 && $0.allSatisfy(\.isHexDigit) }) else {
            throw ServerConfigError.invalid("WALLET_IACA_SHA256 (comma-separated SHA-256 fingerprints, 64 hex characters each)")
        }
        settings.diditAPIKey = value("DIDIT_API_KEY")
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
