import Fluent
import Foundation
import ViadereCore

/// The single definition of a **trusted device**: a full-app (`app`, not App Clip) device that is not revoked, not expired and not inside
/// its new-device cool-down. Everything that widens or ends access to an account (household invitations, linking a phone by code,
/// revoking other devices or sessions, deleting the account, confirming another device or a phone) requires the calling device to be
/// trusted, so a device an attacker just enrolled with a stolen passkey cannot use its first day to lock the owner out or add accomplices.
enum DeviceTrust {
    static func isTrusted(_ device: DeviceRecord, at now: Date) -> Bool {
        device.revokedAt == nil && device.kind == .app && !device.isExpired(at: now) && !device.isCoolingDown(at: now)
    }

    /// The calling device, if trusted; otherwise `403` (`device_cool_down` while it is cooling down).
    @discardableResult
    static func require(_ principal: ConsumerPrincipal, db: any Database, now: Date) async throws -> DeviceRecord {
        guard let id = principal.deviceId, let device = try await DeviceRecord.find(id.uuid, on: db), device.consumerId == principal.consumerId.uuid else {
            throw APIError.signatureInvalid
        }
        guard isTrusted(device, at: now) else {
            if device.isCoolingDown(at: now) {
                throw APIError(.forbidden, .deviceCoolDown,
                               "This device was added recently. For your security it can't do this until it has been confirmed on another of your devices, or after 24 hours.")
            }
            throw APIError(.forbidden, .forbidden, "This device can't do that.")
        }
        return device
    }
}

extension DeviceRecord {
    /// `DeviceTrust.isTrusted(self, at:)`.
    func isTrusted(at now: Date) -> Bool { DeviceTrust.isTrusted(self, at: now) }
}
