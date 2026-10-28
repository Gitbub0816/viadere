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
    /// The transparency log's signing key (P-256). `KEY_DIRECTORY_LOG_KEY` holds its 32-byte raw scalar, base64url. Production keeps it in a
    /// managed key service (ADR-03); the environment variable is the interim, covered in the risk register.
    public var logKey: SoftwareP256SigningKey = SoftwareP256SigningKey()
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

    public init() {}
}

extension ServerConfig {
    /// `APPROVE_V2_ENABLED` (`true`/`false`), `KEY_DIRECTORY_LOG_KEY`, `KEY_DIRECTORY_LOG_ID`.
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
        if let raw = env["KEY_DIRECTORY_LOG_KEY"], !raw.isEmpty {
            guard let bytes = Base64URL.decode(raw), let key = try? SoftwareP256SigningKey(rawRepresentation: bytes) else {
                throw ServerConfigError.invalid("KEY_DIRECTORY_LOG_KEY (base64url, 32-byte P-256 private scalar)")
            }
            approve.logKey = key
        } else if approve.enabled, production || databaseURL != nil {
            // An ephemeral log key would make every tree head already signed unverifiable after a restart.
            throw ServerConfigError.missing("KEY_DIRECTORY_LOG_KEY (required when Approve v2 is enabled with a database)")
        }
    }

    /// The request-body limit for the key-directory publish route is the global one: entries are small.
    var approveEnabled: Bool { approve.enabled }
}
