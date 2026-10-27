import Foundation
import ViadereCore

/// Settings for credential-vault sync (Phase 4). The release gate **defaults to off everywhere**: until the independent vault
/// cryptography and recovery review has passed (`docs/SECURITY-TRUST-PLATFORM-SPEC.md` §17, Phase 4 gate), `VAULT_SYNC_ENABLED` must stay
/// unset in production. It doubles as the kill switch (closes ops gap G-4): turning it off makes every `/v1/vault` route answer `404` and
/// stops sync; devices keep working from their local, encrypted vault copies, and nothing is deleted.
public struct VaultSyncSettings: Sendable, Equatable {
    public var enabled = false
    /// Request bodies up to this size are accepted on `/v1/vault` routes while sync is enabled (a key rotation re-uploads every item).
    public var maxRequestBytes = 1_048_576
    /// Total ciphertext (blobs, envelopes, manifests) one vault may hold.
    public var maxVaultBytes = 16 * 1_048_576
    public var maxItems = VaultFormat.maxItems
    public var maxDevices = VaultFormat.maxDevices
    /// A join (new device waiting for approval) lives this long.
    public var joinLifetime: TimeInterval = 10 * 60
    public var maxOpenJoins = 3
    public var writeRate: RateRule = .perHour(120, burst: 30)
    public var readRate: RateRule = .perHour(1200, burst: 120)
    public var joinRate: RateRule = .perHour(30, burst: 10)
    /// Fetches of the recovery envelope per account. Useless without the recovery key, but each one is also an audit signal.
    public var recoveryRate: RateRule = .perHour(5, burst: 3)

    public init() {}
}

extension ServerConfig {
    /// `VAULT_SYNC_ENABLED` (`true` to enable; anything else, or unset, keeps it off).
    mutating func applyVaultEnvironment(_ env: [String: String]) {
        vaultSync.enabled = env["VAULT_SYNC_ENABLED"] == "true"
    }

    /// The request-body ceiling for `path`: the global one, except on `/v1/vault` routes while sync is enabled.
    public func maxBodyBytes(forPath path: String) -> Int {
        vaultSync.enabled && (path == "/v1/vault" || path.hasPrefix("/v1/vault/")) ? max(maxBodyBytes, vaultSync.maxRequestBytes) : maxBodyBytes
    }
}
