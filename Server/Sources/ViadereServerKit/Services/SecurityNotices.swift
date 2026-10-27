import Fluent
import Foundation
import ViadereCore

/// Tells an account that something sensitive happened (a device or phone was added, an App Clip session started): an **in-app notice**
/// that the app shows on its next open (`GET /v1/security-notices`) plus a push to the account's other devices. The in-app notice
/// matters for the account whose only other device has no push token, or none at all: nobody is "elsewhere" to tell otherwise.
struct SecurityNotices {
    let db: any Database
    let ctx: ServerContext

    enum Notice {
        case newDevice, newPhone, appClip, deviceReplaced, devicePendingReplacement, replacementCancelled
        case recoveryStarted, recoveryCancelled, recoveryAttemptsLocked, recoveryCompleted, delegationEnded

        var kind: SecurityNoticeTopic {
            switch self {
            case .newDevice: .newDevice
            case .newPhone: .newPhone
            case .appClip: .appClip
            case .deviceReplaced, .replacementCancelled: .deviceReplaced
            case .devicePendingReplacement: .devicePendingReplacement
            case .recoveryStarted: .recoveryStarted
            case .recoveryCancelled: .recoveryCancelled
            case .recoveryAttemptsLocked: .recoveryAttemptsLocked
            case .recoveryCompleted: .recoveryCompleted
            case .delegationEnded: .delegationEnded
            }
        }

        /// The "Not you? Cancel" button, acting on the notice's `subjectId`.
        var action: SecurityNoticeAction? {
            switch self {
            case .devicePendingReplacement: .cancelDeviceReplacement
            case .recoveryStarted: .cancelRecovery
            default: nil
            }
        }

        var body: String {
            switch self {
            case .newDevice: "A new device was added to your Viadere account. If this wasn't you, open Viadere and remove it."
            case .newPhone: "A phone number was linked to your Viadere account. If this wasn't you, open Viadere and remove it."
            case .appClip: "A Viadere App Clip session was started for your account. If this wasn't you, open Viadere and remove it."
            case .deviceReplaced: "A device on your Viadere account was set up again. If this wasn't you, open Viadere and review your devices."
            case .devicePendingReplacement:
                "A new device is about to replace one of your Viadere devices. Not you? Open Viadere and cancel it. Until then your current device keeps working."
            case .replacementCancelled: "A pending device replacement on your Viadere account was cancelled and the new device was removed."
            case .recoveryStarted:
                "Account recovery was started for your Viadere account. Not you? Open Viadere and cancel it now. It only takes effect after 72 hours."
            case .recoveryCancelled:
                "An account recovery was cancelled. Its recovery codes no longer work: create new ones in Viadere settings."
            case .recoveryAttemptsLocked:
                "Someone entered wrong recovery codes for your Viadere account, so recovery is locked for a while. If this wasn't you, make new recovery codes in settings."
            case .recoveryCompleted:
                "Your Viadere account was recovered. Household access was ended and your linked phone numbers need to be confirmed again from a trusted device."
            case .delegationEnded:
                "Household access between your Viadere account and another account was ended because that account was recovered. Ask them to invite you again if you still want to share."
            }
        }
    }

    /// Stores the in-app notice (throws when it cannot be stored: callers that must not lose the notice run this inside their transaction).
    func store(of consumer: UUID, except: UUID?, notice: Notice, subjectId: String? = nil) async throws {
        try await SecurityNoticeRecord(consumerId: consumer, kind: notice.kind.rawValue, message: notice.body, subjectId: subjectId,
                                       originDeviceId: except, now: ctx.now, action: notice.action?.rawValue).create(on: db)
    }

    /// Stores the in-app notice and pushes to every active app device of `consumer` except `except` (the device that just did it).
    func notifyOtherDevices(of consumer: UUID, except: UUID?, notice: Notice, subjectId: String? = nil) async {
        do {
            try await store(of: consumer, except: except, notice: notice, subjectId: subjectId)
        } catch {
            ctx.logger.warning("security notice could not be stored", metadata: ["kind": "\(notice.kind.rawValue)"])
        }
        await push(to: consumer, except: except, notice: notice)
    }

    /// The push half (best effort): the stored notice, the audit log and the device list remain the source of truth.
    func push(to consumer: UUID, except: UUID?, notice: Notice) async {
        let now = ctx.now
        do {
            let devices = try await DeviceRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$revokedAt == nil).all()
                .filter { $0.id != except && $0.kind == .app && !$0.isExpired(at: now) }
            let tokens = try await APNsTokenRecord.query(on: db).filter(\.$deviceId ~~ devices.compactMap(\.id)).filter(\.$invalidatedAt == nil).all()
            for token in tokens {
                var message = PushPayloadBuilder.securityNotice(body: notice.body, token: token.record, topic: ctx.config.appBundleID)
                // A notice with a "Not you? Cancel" button uses its own category so the app can attach the action to the notification.
                if notice.action != nil { message.category = "viadere.security.cancel" }
                if await ctx.apns.send(message) == .tokenInvalid {
                    try await APNsTokenRecord.query(on: db).filter(\.$id == token.id!).set(\.$invalidatedAt, to: now).update()
                }
            }
        } catch {
            // Best effort.
        }
    }

    /// The account's undismissed notices of the last 30 days, newest first, without the ones the caller's own device caused.
    func pending(for consumer: UUID, viewedBy device: UUID?) async throws -> [SecurityNotice] {
        let cutoff = ctx.now.addingTimeInterval(-30 * 86_400)
        return try await SecurityNoticeRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$dismissedAt == nil)
            .filter(\.$createdAt > cutoff).sort(\.$createdAt, .descending).limit(50).all()
            .filter { $0.originDeviceId == nil || $0.originDeviceId != device }
            .compactMap { row in
                row.id.map { SecurityNotice(id: $0, rawKind: row.kind, message: row.message,
                                            createdAt: row.createdAt, subjectId: row.subjectId,
                                            action: row.action.flatMap(SecurityNoticeAction.init(rawValue:))) }
            }
    }

    func dismiss(_ id: UUID, principal: ConsumerPrincipal) async throws {
        _ = try await DeviceTrust.require(principal, db: db, now: ctx.now)
        guard let row = try await SecurityNoticeRecord.query(on: db).filter(\.$id == id).filter(\.$consumerId == principal.consumerId.uuid).first()
        else { throw APIError.notFound }
        if row.dismissedAt == nil {
            row.dismissedAt = ctx.now
            try await row.update(on: db)
        }
    }
}
