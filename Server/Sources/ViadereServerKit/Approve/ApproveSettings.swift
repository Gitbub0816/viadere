import Crypto
import Foundation
import ViadereCore

/// Approve v2 and the business key directory (WP1): release gate, log key and limits.
///
/// **Release gate.** `APPROVE_V2_ENABLED` defaults to **off in production and staging** until the independent assessment of enrollment, key
/// substitution, replay and recovery has passed (`docs/SECURITY-TRUST-PLATFORM-SPEC.md` section 17, Phase 2 gate), and to on in development and
/// tests. Turning it off is also the kill switch: every `/v1/approve`, `/v1/business/approve`, `/v1/business/key-directory` and
/// `/v1/key-directory` route answers `404`; enrolled keys and the log are untouched.
public struct ApproveSettings: Sendable {
    public var enabled = true
    /// The transparency log's signing key (P-256). On Azure it is the Key Vault key `AZURE_KEY_VAULT_KD_LOG_KEY` (`kd-log-signing`, loaded at boot
    /// by `configure` as a `KMSSigningKey`: the private key never leaves Key Vault). Elsewhere `KEY_DIRECTORY_LOG_KEY` holds its 32-byte raw scalar,
    /// base64url (Fly staging, development; the interim covered in the risk register).
    public var logKey: any DeviceSigningKey = SoftwareP256SigningKey()
    public var logId = TransparencyLog.defaultLogId
    /// A new tree head is signed when the latest is older than this (devices refuse heads older than a week).
    public var treeHeadRefreshInterval: TimeInterval = 3600
    public var prompt = ApprovalPromptPolicy.standard
    public var enrollmentLifetime: TimeInterval = 600
    /// How long after the enrollment's expiry the business may still confirm a completed enrollment; after that the pending key is revoked and alerted.
    public var unconfirmedGrace: TimeInterval = 300
    public var maxKeysPerRelationship = 8
    public var maxOpenEnrollmentsPerRelationship = 3
    /// Wrong-code lookups per consumer.
    public var lookupRate: RateRule = .perHour(10, burst: 5)
    public var lookupRateGlobal: RateRule = .perMinute(120, burst: 60)
    /// Approval requests a business creates per minute.
    public var requestRate: RateRule = .perMinute(120, burst: 60)
    /// Directory entries a business publishes per hour.
    public var publishRate: RateRule = .perHour(60, burst: 20)
    /// Public directory reads per IP.
    public var directoryReadRate: RateRule = .perMinute(60, burst: 30)

    // MARK: Hardening (WP-C2)

    /// Invalid result submissions one request tolerates; the next one locks it (`locked`, nothing more is accepted).
    public var maxInvalidSubmissions = 5
    /// App Attest assertions on approval results and link completions (`APP_ATTEST_ASSERTION_MODE`): `report` records a missing or invalid
    /// assertion and lets the request through, `require` refuses it (`401`). Only devices enrolled with an attested key are asked for one.
    public var assertionMode: AppAttestAssertionMode = .off

    // MARK: Link sessions (WP-C1)

    /// Viadere's `link-descriptor` key (P-256), which signs link descriptors and results only. On Azure it is the Key Vault key
    /// `AZURE_KEY_VAULT_LINK_DESCRIPTOR_KEY` (`link-descriptor`, loaded at boot by `configure` as a `KMSSigningKey`); elsewhere
    /// `LINK_DESCRIPTOR_SIGNING_KEY` holds its 32-byte raw scalar, base64url (Fly staging, development; the same interim as the log key). Its public
    /// key is pinned in the app (`VIADERE_LINK_DESCRIPTOR_KEYS`) and in business SDKs.
    public var linkDescriptorKey: any DeviceSigningKey = SoftwareP256SigningKey()
    /// Link sessions a business creates.
    public var linkCreateRate: RateRule = .perMinute(60, burst: 30)
    /// Link sessions per business customer reference (one person rarely needs more than a couple of tries).
    public var linkPerCustomerRate: RateRule = .perHour(5, burst: 3)
    /// Lookups per account (a wrong code burns one) and globally.
    public var linkLookupRate: RateRule = .perHour(10, burst: 5)
    public var linkLookupRateGlobal: RateRule = .perMinute(120, burst: 60)
    /// Completions per account.
    public var linkCompleteRate: RateRule = .perHour(10, burst: 5)

    public init() {}
}

/// `APP_ATTEST_ASSERTION_MODE`.
public enum AppAttestAssertionMode: String, Sendable, CaseIterable {
    case off, report, require
}

extension ServerConfig {
    /// `APPROVE_V2_ENABLED` (`true`/`false`), `KEY_DIRECTORY_LOG_KEY`, `KEY_DIRECTORY_LOG_ID`, `APP_ATTEST_ASSERTION_MODE`, `LINK_DESCRIPTOR_SIGNING_KEY`.
    mutating func applyApproveEnvironment(_ env: [String: String], production: Bool) throws {
        switch env["APPROVE_V2_ENABLED"] {
        case "true": approve.enabled = true
        case "false": approve.enabled = false
        case nil, "": approve.enabled = !production
        default: throw ServerConfigError.invalid("APPROVE_V2_ENABLED (true or false)")
        }
        if let id = env["KEY_DIRECTORY_LOG_ID"], !id.isEmpty {
            guard id.utf8.count <= 64, id.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7F }) else { throw ServerConfigError.invalid("KEY_DIRECTORY_LOG_ID") }
            approve.logId = id
        }
        switch env["APP_ATTEST_ASSERTION_MODE"].map({ $0.lowercased() }) {
        case nil, "": approve.assertionMode = production ? .report : .off
        case let raw?:
            guard let mode = AppAttestAssertionMode(rawValue: raw) else { throw ServerConfigError.invalid("APP_ATTEST_ASSERTION_MODE (off, report or require)") }
            // `off` would silently stop checking assertions on approvals: development and tests only.
            guard !(production && mode == .off) else { throw ServerConfigError.invalid("APP_ATTEST_ASSERTION_MODE (off is not allowed in staging or production)") }
            approve.assertionMode = mode
        }
        // The link-descriptor key follows the log key's model: a Key Vault key on Azure (resolved by `configure`), an environment secret elsewhere.
        if azure.linkDescriptorKey != nil {
            if env["LINK_DESCRIPTOR_SIGNING_KEY"].map({ !$0.isEmpty }) == true {
                throw ServerConfigError.invalid("LINK_DESCRIPTOR_SIGNING_KEY (unset it when AZURE_KEY_VAULT_LINK_DESCRIPTOR_KEY is configured)")
            }
        } else if let raw = env["LINK_DESCRIPTOR_SIGNING_KEY"], !raw.isEmpty {
            guard let bytes = Base64URL.decode(raw), let key = try? SoftwareP256SigningKey(rawRepresentation: bytes) else {
                throw ServerConfigError.invalid("LINK_DESCRIPTOR_SIGNING_KEY (base64url, 32-byte P-256 private scalar)")
            }
            approve.linkDescriptorKey = key
        } else if role == .worker {
            // Only the api signs link descriptors and results; the worker holds no grant on the key (plan 5.3), so its stand-in refuses to sign.
            approve.linkDescriptorKey = UnavailableSigningKey()
        } else if approve.enabled, production || hasDatabase {
            // An ephemeral key would make every descriptor and result already handed out unverifiable after a restart, and the app pins the key.
            throw ServerConfigError.missing("LINK_DESCRIPTOR_SIGNING_KEY or AZURE_KEY_VAULT_LINK_DESCRIPTOR_KEY (required when Approve v2 is enabled with a database)")
        }
        if azure.kdLogKey != nil {
            // The key lives in Key Vault; `configure` resolves it. A second, software copy would defeat the point.
            if env["KEY_DIRECTORY_LOG_KEY"].map({ !$0.isEmpty }) == true {
                throw ServerConfigError.invalid("KEY_DIRECTORY_LOG_KEY (unset it when AZURE_KEY_VAULT_KD_LOG_KEY is configured)")
            }
        } else if let raw = env["KEY_DIRECTORY_LOG_KEY"], !raw.isEmpty {
            guard let bytes = Base64URL.decode(raw), let key = try? SoftwareP256SigningKey(rawRepresentation: bytes) else {
                throw ServerConfigError.invalid("KEY_DIRECTORY_LOG_KEY (base64url, 32-byte P-256 private scalar)")
            }
            approve.logKey = key
        } else if role == .worker {
            // The queue worker never signs tree heads (only the api does) and holds no grant on the log key (plan 5.3): its stand-in refuses to sign.
            approve.logKey = UnavailableSigningKey()
        } else if approve.enabled, production || hasDatabase {
            // An ephemeral log key would make every tree head already signed unverifiable after a restart.
            throw ServerConfigError.missing("KEY_DIRECTORY_LOG_KEY or AZURE_KEY_VAULT_KD_LOG_KEY (required when Approve v2 is enabled with a database)")
        }
        if let log = azure.kdLogKey, let link = azure.linkDescriptorKey, KMSKeyRef.parse(log)?.name == KMSKeyRef.parse(link)?.name {
            throw ServerConfigError.invalid("AZURE_KEY_VAULT_LINK_DESCRIPTOR_KEY and AZURE_KEY_VAULT_KD_LOG_KEY must name different keys")
        }
        // One key, one role: the log key signs tree heads only, the link-descriptor key signs link descriptors and results only. Key Vault keys
        // are compared again by `configure` once their public keys are loaded (`requireDistinctSigningKeys`).
        try requireDistinctSigningKeys()
    }

    /// One key, one role: the key-directory log key and the link-descriptor key must differ (whatever holds them).
    func requireDistinctSigningKeys() throws {
        if approve.linkDescriptorKey.publicKey == approve.logKey.publicKey {
            throw ServerConfigError.invalid("LINK_DESCRIPTOR_SIGNING_KEY and KEY_DIRECTORY_LOG_KEY must be different keys")
        }
    }

    /// The request-body limit for the key-directory publish route is the global one: entries are small.
    var approveEnabled: Bool { approve.enabled }
}
