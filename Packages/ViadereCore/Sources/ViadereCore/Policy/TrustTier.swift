import Foundation

/// Device trust tiers (spec §8, ADR-0013, SECURITY.md §2.5a). **Decided by the server only**: a client never sends a tier, and the value in
/// `Device.trustTier` is informational for the app's UI.
///
/// * **D0**: a registered pseudonymous account and device. Messaging, reading history, deny/report on any request.
/// * **D1**: D0 plus a hardware approval key with user verification (Face ID / Touch ID / passcode), verified platform integrity where the
///   platform supports it, and an explicit elevation (`TrustElevation`). Eligible for high-risk MFA, subject to business policy.
/// * **D2**: D1 plus a live Verify result for the claim being asked about (no new identity data). Evaluated per claim, never stored.
public enum DeviceTrustTier: String, Codable, Sendable, CaseIterable, Comparable {
    case d0, d1, d2

    private var rank: Int {
        switch self {
        case .d0: 0
        case .d1: 1
        case .d2: 2
        }
    }

    public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rank < rhs.rank }

    /// An unknown tier is the lowest one.
    public init(from decoder: any Decoder) throws {
        self = DeviceTrustTier(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .d0
    }
}

/// Why a device is D1. **There is no time-based reason**: a device never becomes trusted because a waiting period ended (owner decision,
/// 2026-10-29). Business (relying-party) re-enrollment is not a device elevation either: it authorizes one pairwise approval key for one
/// business (Approve v2), and is recorded on that key.
public enum TrustElevation: String, Codable, Sendable, CaseIterable {
    /// The first app device of a brand-new account (never had an app device, never recovered), with a user-verified approval key and
    /// verified integrity evidence (or integrity not evaluated in development, `APP_ATTEST_MODE=off`).
    case firstDeviceAttested = "first_device_attested"
    /// Approved by another D1 device of the same account with a user-verified (biometric) proof (`POST /v1/devices/{id}/confirm`).
    case trustedDeviceApproval = "trusted_device_approval"
    /// Set by migration `DeviceFirstAccounts.v1` for devices that already met every D1 condition.
    case migrationBackfill = "migration_backfill"
}

/// The facts a tier is decided from. All of them come from the server's own records, never from the request.
public struct DeviceTrustFacts: Sendable, Equatable {
    /// A full-app device (not an App Clip).
    public var isFullApp: Bool
    public var revoked: Bool
    public var expired: Bool
    /// The device registered an approval key protected by user verification (`approvalBiometric` or `approvalUserPresence`).
    public var hasUserVerifiedApprovalKey: Bool
    /// Platform integrity evidence for this device verified (App Attest today).
    public var integrityVerified: Bool
    /// Whether integrity is a condition at all: false only where the server does not evaluate attestation (`APP_ATTEST_MODE=off`,
    /// development and tests).
    public var integrityRequired: Bool
    /// No other app device was ever enrolled in the account (revoked and expired ones count).
    public var firstAppDeviceOfAccount: Bool
    /// The account was recovered (a recovery was activated). Its devices are never elevated automatically.
    public var accountRecovered: Bool

    public init(isFullApp: Bool, revoked: Bool, expired: Bool, hasUserVerifiedApprovalKey: Bool, integrityVerified: Bool, integrityRequired: Bool,
                firstAppDeviceOfAccount: Bool = false, accountRecovered: Bool = false) {
        self.isFullApp = isFullApp
        self.revoked = revoked
        self.expired = expired
        self.hasUserVerifiedApprovalKey = hasUserVerifiedApprovalKey
        self.integrityVerified = integrityVerified
        self.integrityRequired = integrityRequired
        self.firstAppDeviceOfAccount = firstAppDeviceOfAccount
        self.accountRecovered = accountRecovered
    }

    /// Live, hardware, user-verified, integrity: what any D1 device must satisfy.
    var meetsD1Conditions: Bool {
        isFullApp && !revoked && !expired && hasUserVerifiedApprovalKey && (integrityVerified || !integrityRequired)
    }
}

/// The tier policy, shared by the server (the authority) and the app (display only).
public enum TrustTierPolicy {
    /// Recorded on new accounts (`consumers.policy_version`) and on audit events (`audit_events.policy_version`). Bump when the rules below
    /// change meaning.
    public static let version = 1

    /// The elevation a device gets when it is enrolled, or `nil` (D0). Only a brand-new, never-recovered account's first app device that
    /// meets every D1 condition starts at D1; every other device starts at D0 and stays there until a D1 device approves it.
    public static func initialElevation(_ facts: DeviceTrustFacts) -> TrustElevation? {
        guard facts.meetsD1Conditions, facts.firstAppDeviceOfAccount, !facts.accountRecovered else { return nil }
        return .firstDeviceAttested
    }

    /// Whether a device with `approverTier` may elevate a device with `target` facts to D1 (trusted-device approval).
    public static func mayElevate(target: DeviceTrustFacts, approverTier: DeviceTrustTier) -> Bool {
        approverTier >= .d1 && target.meetsD1Conditions
    }

    /// The effective tier now: the stored decision, capped by what is true of the device right now. D2 needs D1 **and** a live
    /// verification of the claim being asked about; a stored `d2` is read as `d1`.
    public static func evaluate(stored: DeviceTrustTier, facts: DeviceTrustFacts, liveVerifiedClaim: Bool = false) -> DeviceTrustTier {
        guard stored >= .d1, facts.isFullApp, !facts.revoked, !facts.expired else { return .d0 }
        return liveVerifiedClaim ? .d2 : .d1
    }
}
