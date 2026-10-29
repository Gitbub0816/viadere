import Fluent
import Foundation
import ViadereCore

/// Device trust (SECURITY.md §2.5a, ADR-0013): **tiers decided by the server**, never by the client and never by the clock.
///
/// * `tier(_:at:)`: the stored decision (`devices.trust_tier`, set only by `TrustTierPolicy.initialElevation` at enrollment or by an approval
///   from another D1 device) capped by live facts (an App Clip, a revoked or expired device is D0). The hardware, user-verification and
///   integrity conditions are checked when the tier is granted (keys never change on a device).
/// * **D1 (`isTrusted`)** is what high-risk approvals (legacy decisions, Approve v2) and approving another device need.
/// * **Account management** (`require`): household invitations, phone links, revoking another device or session, account deletion and export,
///   dismissing notices, recovery codes and passkeys, vault membership, unfreezing approvals. It needs a D1 device, **or** a full-app device
///   outside its notice window on an account that has **no** live D1 device at all (a recovered account, or one whose only device is
///   unattested). There is then nobody else to protect, and refusing would lock the owner out of their own account; high-risk approvals
///   still need D1. A device that is not D1 can never act against an account that has a D1 device: the owner's trusted phone cannot be
///   removed, and its notices cannot be dismissed, by a device nobody approved.
enum DeviceTrust {
    /// Live facts about a device, for `TrustTierPolicy.evaluate`.
    static func facts(_ device: DeviceRecord, at now: Date) -> DeviceTrustFacts {
        DeviceTrustFacts(isFullApp: device.kind == .app, revoked: device.revokedAt != nil, expired: device.isExpired(at: now),
                         hasUserVerifiedApprovalKey: true, integrityVerified: true, integrityRequired: false)
    }

    static func tier(_ device: DeviceRecord, at now: Date) -> DeviceTrustTier {
        TrustTierPolicy.evaluate(stored: device.storedTier, facts: facts(device, at: now))
    }

    /// D1 or above: may approve high-risk requests and approve other devices.
    static func isTrusted(_ device: DeviceRecord, at now: Date) -> Bool { tier(device, at: now) >= .d1 }

    /// Whether the account has a live D1 device other than `except`.
    static func accountHasTrustedDevice(_ consumerId: UUID, except: UUID?, db: any Database, now: Date) async throws -> Bool {
        let devices = try await DeviceRecord.query(on: db).filter(\.$consumerId == consumerId).filter(\.$revokedAt == nil)
            .filter(\.$trustTier == DeviceTrustTier.d1.rawValue).all()
        return devices.contains { $0.id != except && isTrusted($0, at: now) }
    }

    /// May `device` manage the account (see the type's documentation)?
    static func mayManageAccount(_ device: DeviceRecord, db: any Database, now: Date) async throws -> Bool {
        if isTrusted(device, at: now) { return true }
        guard device.kind == .app, device.revokedAt == nil, !device.isExpired(at: now), !device.isCoolingDown(at: now) else { return false }
        return try await !accountHasTrustedDevice(device.consumerId, except: device.id, db: db, now: now)
    }

    /// The error a device that is not trusted enough gets. The code stays `device_cool_down` (what apps already understand).
    static func notTrustedError(_ device: DeviceRecord, at now: Date) -> APIError {
        guard device.kind == .app, device.revokedAt == nil, !device.isExpired(at: now) else { return APIError(.forbidden, .forbidden, "This device can't do that.") }
        return APIError(.forbidden, .deviceCoolDown,
                        "This device hasn't been approved yet. For your security it can't do this until one of your trusted devices approves it.")
    }

    /// The calling device, if it may manage the account; otherwise `403` (`device_cool_down` for a device that is not approved yet).
    @discardableResult
    static func require(_ principal: ConsumerPrincipal, db: any Database, now: Date) async throws -> DeviceRecord {
        let device = try await callingDevice(principal, db: db)
        guard try await mayManageAccount(device, db: db, now: now) else { throw notTrustedError(device, at: now) }
        return device
    }

    /// The calling device, if it is D1 (high-risk approvals, approving other devices); otherwise `403 device_cool_down`.
    @discardableResult
    static func requireTier(_ minimum: DeviceTrustTier, _ principal: ConsumerPrincipal, db: any Database, now: Date) async throws -> DeviceRecord {
        let device = try await callingDevice(principal, db: db)
        guard tier(device, at: now) >= minimum else { throw notTrustedError(device, at: now) }
        return device
    }

    private static func callingDevice(_ principal: ConsumerPrincipal, db: any Database) async throws -> DeviceRecord {
        guard let id = principal.deviceId, let device = try await DeviceRecord.find(id.uuid, on: db), device.consumerId == principal.consumerId.uuid else {
            throw APIError.signatureInvalid
        }
        return device
    }

    /// Approve v2 (`complete`): a D1 device, or a **business re-enrollment** of a D0 device: an enrollment the business created after this
    /// device was enrolled, on an account that has no D1 device that could approve the device instead (a recovered account). The business's
    /// own customer authentication and its signed confirmation are the authorization; the result is one pairwise key for that business only.
    static func mayCompleteBusinessEnrollment(_ device: DeviceRecord, enrollmentCreatedAt: Date, db: any Database, now: Date) async throws -> Bool {
        if isTrusted(device, at: now) { return true }
        guard device.kind == .app, device.revokedAt == nil, !device.isExpired(at: now), enrollmentCreatedAt >= device.createdAt else { return false }
        return try await !accountHasTrustedDevice(device.consumerId, except: device.id, db: db, now: now)
    }
}

extension DeviceRecord {
    /// `DeviceTrust.isTrusted(self, at:)`: D1 or above.
    func isTrusted(at now: Date) -> Bool { DeviceTrust.isTrusted(self, at: now) }
}
