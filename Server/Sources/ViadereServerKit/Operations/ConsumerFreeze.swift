import Fluent
import Foundation
import ViadereCore

/// G-7: an operator freezes a consumer account (fraud, coercion, a reported compromise) and ends its sessions and devices. Every device-signed
/// and bearer route, sign-in and recovery already require `consumers.status == "active"`, so a frozen account is refused everywhere at once,
/// approvals included. The reason is recorded, the person is told (an in-app notice and a generic push, sent first because their devices are
/// revoked next), and the whole thing is audited with the operator as actor. Lifting the freeze restores the status only: sessions and devices
/// stay revoked, so the person returns through sign-in with their passkey and the recovery and device flows, which keep their own cool-downs.
struct ConsumerFreeze {
    let db: any Database
    let ctx: ServerContext

    static let noticeKind = "account_frozen"

    private func reason(_ raw: String) throws -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (8...300).contains(trimmed.count), !trimmed.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw APIError.validation("Record the reason (8 to 300 characters).", details: ["reason": "required"])
        }
        return trimmed
    }

    func freeze(consumerId: UUID, reason rawReason: String, operatorId: UUID) async throws {
        let reason = try reason(rawReason)
        guard let consumer = try await ConsumerRecord.find(consumerId, on: db) else { throw APIError.notFound }
        guard consumer.status == "active" else { throw APIError.conflict("Only an active account can be frozen.") }
        // Tell the person first: revoking their devices ends the sessions the notice would otherwise be read from.
        await Notifier(db: db, ctx: ctx).notifyConsumer(consumerId, kind: Self.noticeKind,
            message: "Viadere locked your account while we look into a security concern. Your devices were signed out. Contact Viadere support to continue.",
            subjectId: nil)
        let now = ctx.now
        let actor = AuditActor(kind: .operator_, id: operatorId.uuidString.lowercased())
        try await db.transaction { tx in
            guard try await DB.swap(tx, table: ConsumerRecord.schema, id: consumerId, column: "status", expected: "active", newValue: "frozen") else {
                throw APIError.conflict("Only an active account can be frozen.")
            }
            let freeze = AccountFreezeRecord()
            freeze.id = UUID()
            freeze.consumerId = consumerId
            freeze.reason = reason
            freeze.frozenBy = actor.id ?? ""
            freeze.frozenAt = now
            try await freeze.create(on: tx)
            try await ConsumerTokenService(db: tx, ctx: ctx).revokeAll(consumerId: consumerId, now: now)
            let devices = try await DeviceRecord.query(on: tx).filter(\.$consumerId == consumerId).filter(\.$revokedAt == nil).all().compactMap(\.id)
            if !devices.isEmpty { try await DeviceLifecycle(db: tx, ctx: ctx).revoke(deviceIds: devices, now: now) }
            _ = try await AuditService(db: tx, ctx: ctx).record("operator.account_frozen", actor: actor, consumerId: ConsumerID(consumerId), subjectType: "consumer",
                subjectId: consumerId.uuidString.lowercased(), metadata: ["reason": reason, "devices_revoked": String(devices.count)])
        }
        ctx.metrics.count(.accountFrozen)
    }

    func unfreeze(consumerId: UUID, reason rawReason: String, operatorId: UUID) async throws {
        let reason = try reason(rawReason)
        let now = ctx.now
        let actor = AuditActor(kind: .operator_, id: operatorId.uuidString.lowercased())
        try await db.transaction { tx in
            guard try await DB.swap(tx, table: ConsumerRecord.schema, id: consumerId, column: "status", expected: "frozen", newValue: "active") else {
                throw APIError.conflict("This account is not frozen.")
            }
            try await AccountFreezeRecord.query(on: tx).filter(\.$consumerId == consumerId).filter(\.$releasedAt == nil)
                .set(\.$releasedAt, to: now).set(\.$releasedBy, to: actor.id).update()
            _ = try await AuditService(db: tx, ctx: ctx).record("operator.account_unfrozen", actor: actor, consumerId: ConsumerID(consumerId), subjectType: "consumer",
                subjectId: consumerId.uuidString.lowercased(), metadata: ["reason": reason])
        }
    }

    func freezes(limit: Int = 50) async throws -> [AccountFreezeRecord] {
        try await AccountFreezeRecord.query(on: db).sort(\.$frozenAt, .descending).limit(limit).all()
    }
}
