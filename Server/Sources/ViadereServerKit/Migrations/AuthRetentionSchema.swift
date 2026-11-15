import Fluent
import Foundation
import ViadereCore

/// `AuthRetention.v1` (additive, forward-only; ADR-0026 section 3, owner decision 10, finding F-07): the one-time catch-up for the retention
/// move of approval requests from 400 to 30 days, and the emptying of `link_tokens`.
///
/// * Approval requests in a terminal state for more than 30 days: deleted with their deliveries, **unless** they carry a signed result (owner ruling
///   O-3): those keep their id, decision, key and signature as high-value evidence and lose the displayed details, the challenge and the device
///   policy. Afterwards the retention sweep keeps the 30-day rule.
/// * `link_tokens` (SMS account-link and hand-off tokens, retired by ADR-0027): every row is dead (no route redeems one) and holds an encrypted
///   phone number, so the table is emptied. The retention class stays for the table until it is dropped.
///
/// A legal hold that is active when this runs stops the catch-up for the approval requests (the sweep applies holds per scope afterwards); the link
/// tokens are bearer secrets and are never held.
struct CreateAuthRetentionAlignment: AsyncMigration {
    var name: String { "AuthRetention.v1" }

    func prepare(on db: any Database) async throws {
        try await LinkTokenRecord.query(on: db).delete()
        guard try await LegalHoldRecord.query(on: db).filter(\.$releasedAt == nil).count() == 0 else { return }
        let cutoff = Date().addingTimeInterval(-30 * 86_400)
        let pending = ApprovalRequestStatus.pending.rawValue
        func terminalBefore() -> QueryBuilder<ApproveRequestRecord> {
            ApproveRequestRecord.query(on: db).filter(\.$status != pending).group(.or) { either in
                either.filter(\.$decidedAt < cutoff)
                either.group(.and) { open in
                    open.filter(\.$decidedAt == nil)
                    open.filter(\.$expiresAt < cutoff)
                }
            }
        }
        while true {
            let ids = try await terminalBefore().filter(\.$resultJWS == nil).limit(500).all().compactMap(\.id)
            if ids.isEmpty { break }
            try await ApproveDeliveryRecord.query(on: db).filter(\.$requestId ~~ ids).delete()
            try await ApproveRequestRecord.query(on: db).filter(\.$id ~~ ids).delete()
        }
        try await terminalBefore().filter(\.$resultJWS != nil).set(\.$detailsSealed, to: nil).set(\.$challenge, to: nil).set(\.$devicePolicy, to: nil).update()
    }

    func revert(on db: any Database) async throws {}
}
