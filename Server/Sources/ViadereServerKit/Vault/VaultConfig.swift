import Foundation
import ViadereCore

/// Settings for credential-vault sync (Phase 4). The release gate **defaults to off everywhere**: until the independent vault
/// cryptography and recovery review has passed (`docs/SECURITY-TRUST-PLATFORM-SPEC.md` §17, Phase 4 gate), `VAULT_SYNC_ENABLED` must stay
/// unset in production. It doubles as the kill switch (closes ops gap G-4): turning it off makes every `/v1/vault` route answer `404` and
/// stops sync; devices keep working from their local, encrypted vault copies, and nothing is deleted.
public struct VaultSyncSettings: Sendable, Equatable {
    public var enabled = false
    /// Request bodies up to this size are accepted on `/v1/vault` routes while sync is enabled. A key rotation re-uploads every item in one
    /// request, so this must stay at or above `VaultFormat.maxRotationRequestBytes` (a test pins it).
    public var maxRequestBytes = 4 * 1_048_576
    /// Total item ciphertext one vault may hold. Re-encryption keeps blob sizes, so a vault at the cap can always rotate.
    public var maxVaultBytes = VaultFormat.maxTotalBlobBytes
    public var maxItems = VaultFormat.maxItems
    public var maxDevices = VaultFormat.maxDevices
    /// A join (new device waiting for approval) lives this long.
    public var joinLifetime: TimeInterval = 10 * 60
    public var maxOpenJoins = 3
    // Every bucket below is keyed by account **and device**: one account device (an attacker's, or a broken one) cannot use up what the
    // account's other devices need (gate review L5). Bound and unbound devices use different buckets.
    public var writeRate: RateRule = .perHour(120, burst: 30)
    public var readRate: RateRule = .perHour(1200, burst: 120)
    public var joinRate: RateRule = .perHour(30, burst: 10)
    /// Reads by an account device that is not a vault member (the recovery window), and every other unbound probe.
    public var unboundReadRate: RateRule = .perHour(60, burst: 20)
    /// Release requests, recovery-envelope fetches and recovery restores per device.
    public var recoveryRate: RateRule = .perHour(5, burst: 3)
    /// The hold before the recovery envelope is released, and how long it then stays released (to the requesting device only).
    public var recoveryHold: TimeInterval = VaultRecoveryRelease.holdSeconds
    public var recoveryWindow: TimeInterval = VaultRecoveryRelease.windowSeconds

    public init() {}
}

extension ServerConfig {
    /// `VAULT_SYNC_ENABLED` (`true` to enable; anything else, or unset, keeps it off).
    mutating func applyVaultEnvironment(_ env: [String: String]) {
        vaultSync.enabled = env["VAULT_SYNC_ENABLED"] == "true"
    }

    /// The request-body ceiling for `path`: the global one, except on `/v1/vault` routes while sync is enabled.
    public func maxBodyBytes(forPath path: String) -> Int {
        // Brand image uploads (WP-2.2): the 2 MB file plus multipart framing; the pipeline re-checks the file's own size.
        if path == ConsoleBrandStudio.uploadPath { return max(maxBodyBytes, ConsoleBrandStudio.uploadBodyLimit) }
        return vaultSync.enabled && (path == "/v1/vault" || path.hasPrefix("/v1/vault/")) ? max(maxBodyBytes, vaultSync.maxRequestBytes) : maxBodyBytes
    }
}
