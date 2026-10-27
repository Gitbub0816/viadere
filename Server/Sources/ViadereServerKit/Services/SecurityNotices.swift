import Fluent
import Foundation
import ViadereCore

/// Best-effort "something changed on your account" pushes to the person's other trusted devices.
struct SecurityNotices {
    let db: any Database
    let ctx: ServerContext

    enum Notice {
        case newDevice, newPhone

        var body: String {
            switch self {
            case .newDevice: "A new device was added to your Viadere account. If this wasn't you, open Viadere and remove it."
            case .newPhone: "A phone number was linked to your Viadere account. If this wasn't you, open Viadere and remove it."
            }
        }
    }

    /// Notifies every active app device of `consumer` except `except` (the device that just did it, if any).
    func notifyOtherDevices(of consumer: UUID, except: UUID?, notice: Notice) async {
        do {
            let now = ctx.now
            let devices = try await DeviceRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$revokedAt == nil).all()
                .filter { $0.id != except && $0.kind == .app && !$0.isExpired(at: now) }
            let tokens = try await APNsTokenRecord.query(on: db).filter(\.$deviceId ~~ devices.compactMap(\.id)).filter(\.$invalidatedAt == nil).all()
            for token in tokens {
                let message = PushPayloadBuilder.securityNotice(body: notice.body, token: token.record, topic: ctx.config.appBundleID)
                if await ctx.apns.send(message) == .tokenInvalid {
                    try await APNsTokenRecord.query(on: db).filter(\.$id == token.id!).set(\.$invalidatedAt, to: now).update()
                }
            }
        } catch {
            // Best effort: the audit log and the device list remain the source of truth.
        }
    }
}
