import Fluent
import Foundation
import ViadereCore

/// Enrolled pairwise approval keys: listing, views, revocation (per key, by the customer or by the business).
struct ApproveKeyService {
    let db: any Database
    let ctx: ServerContext

    // MARK: Views

    func businessView(_ key: ApproveKeyRecord) throws -> ApprovalKeyView {
        guard let subject = SubjectRef(key.subjectRef) else { throw APIError.internalError }
        return ApprovalKeyView(kid: key.kid, subjectRef: subject, status: key.statusValue, assurance: key.assuranceValue, publicKey: key.publicKey, hpkeKid: key.hpkeKid,
                               hpkePublicKey: key.hpkePublicKey, createdAt: key.createdAt, activatedAt: key.activatedAt, revokedAt: key.revokedAt,
                               revokedBy: key.revokedBy, deviceStatement: key.statement)
    }

    func deviceView(_ key: ApproveKeyRecord, business: BusinessSummary) throws -> ApproveKey {
        guard let subject = SubjectRef(key.subjectRef) else { throw APIError.internalError }
        let confirmation = key.confirmation.flatMap { try? ViadereJSON.decode(BusinessSignedStatement.self, from: Data($0.utf8)) }
        return ApproveKey(kid: key.kid, enrollmentId: key.enrollmentId, business: business, relationshipId: RelationshipID(key.relationshipId), subjectRef: subject,
                          deviceId: DeviceID(key.deviceId), status: key.statusValue, assurance: key.assuranceValue, createdAt: key.createdAt, activatedAt: key.activatedAt,
                          revokedAt: key.revokedAt, revokedBy: key.revokedBy, statement: key.statement, confirmation: confirmation)
    }

    func businessSummary(_ businessId: UUID) async throws -> BusinessSummary {
        guard let business = try await BusinessRecord.find(businessId, on: db), let summary = try await DirectoryService(db: db).summary(for: business) else { throw APIError.notFound }
        return summary
    }

    // MARK: Queries

    /// The relationship's active keys whose device is still usable (not revoked, not expired, a full app device).
    func activeKeys(relationshipId: UUID) async throws -> [(key: ApproveKeyRecord, device: DeviceRecord)] {
        let keys = try await ApproveKeyRecord.query(on: db).filter(\.$relationshipId == relationshipId).filter(\.$status == ApprovalKeyStatus.active.rawValue).all()
        guard !keys.isEmpty else { return [] }
        let devices = try await DeviceRecord.query(on: db).filter(\.$id ~~ Array(Set(keys.map(\.deviceId)))).all()
        let now = ctx.now
        let usable = Dictionary(uniqueKeysWithValues: devices.filter { $0.revokedAt == nil && $0.kind == .app && !$0.isExpired(at: now) }.compactMap { d in d.id.map { ($0, d) } })
        return keys.compactMap { key in usable[key.deviceId].map { (key, $0) } }
    }

    // MARK: Revocation

    enum Revoker: String { case consumer, business, system }

    /// Revokes one key. Pending deliveries to it stop working at once (every read and every decision checks the key's status).
    @discardableResult
    func revoke(_ key: ApproveKeyRecord, by revoker: Revoker, reason: String?, actor: AuditActor, except device: UUID? = nil) async throws -> ApproveKeyRecord {
        guard key.statusValue != .revoked else { return key }
        let now = ctx.now
        let swapped = try await DB.swap(db, table: ApproveKeyRecord.schema, id: key.id!, column: "status", expected: key.status, newValue: ApprovalKeyStatus.revoked.rawValue,
                                        extra: [("revoked_at", now), ("revoked_by", revoker.rawValue)])
        guard swapped else { return try await ApproveKeyRecord.find(key.id!, on: db) ?? key }
        if let reason { try await ApproveKeyRecord.query(on: db).filter(\.$id == key.id!).set(\.$revokeReason, to: String(reason.prefix(120))).update() }
        guard let fresh = try await ApproveKeyRecord.find(key.id!, on: db) else { return key }
        _ = try await AuditService(db: db, ctx: ctx).record("approve.key_revoked", actor: actor, consumerId: ConsumerID(fresh.consumerId), businessId: BusinessID(fresh.businessId),
            subjectType: "approve_key", subjectId: fresh.kid, metadata: ["by": revoker.rawValue])
        // An enrollment still waiting for the business can no longer complete.
        try await ApproveEnrollmentRecord.query(on: db).filter(\.$id == fresh.enrollmentId).filter(\.$status != ApprovalEnrollmentStatus.confirmed.rawValue)
            .set(\.$status, to: ApprovalEnrollmentStatus.cancelled.rawValue).set(\.$cancelledAt, to: now).update()
        // Pending requests addressed only to this key can no longer be decided.
        let deliveries = try await ApproveDeliveryRecord.query(on: db).filter(\.$kid == fresh.kid).all()
        for delivery in deliveries {
            guard let request = try await ApproveRequestRecord.find(delivery.requestId, on: db), request.statusValue == .pending else { continue }
            let others = try await ApproveDeliveryRecord.query(on: db).filter(\.$requestId == delivery.requestId).filter(\.$kid != fresh.kid).all()
            var alive = false
            for other in others where try await ApproveKeyRecord.query(on: db).filter(\.$kid == other.kid).filter(\.$status == ApprovalKeyStatus.active.rawValue).count() > 0 { alive = true }
            if !alive { _ = try await ApproveRequestService(db: db, ctx: ctx).finish(request, status: .cancelled, reason: "key_revoked", notify: true) }
        }
        try await ApproveWebhooks(db: db, ctx: ctx).keyRevoked(fresh)
        await ApproveNotifier(db: db, ctx: ctx).notice(.approvalKeyRevoked, consumerId: fresh.consumerId, except: revoker == .consumer ? device : nil, subjectId: fresh.kid)
        return fresh
    }
}
