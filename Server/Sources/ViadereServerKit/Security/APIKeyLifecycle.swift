import Fluent
import Foundation
import ViadereCore

/// Who is acting on a key: a console user, a Viadere operator (G-3: revoke without suspending the business) or the system (the rotation sweep).
enum KeyActor: Sendable {
    case user(UUID)
    case operatorUser(UUID)
    case system(String)

    var audit: AuditActor {
        switch self {
        case .user(let id): AuditActor(kind: .business, id: id.uuidString.lowercased())
        case .operatorUser(let id): AuditActor(kind: .operator_, id: id.uuidString.lowercased())
        case .system(let name): AuditActor(kind: .system, id: name)
        }
    }

    var label: String {
        switch self {
        case .user(let id): "user:" + id.uuidString.lowercased()
        case .operatorUser(let id): "operator:" + id.uuidString.lowercased()
        case .system(let name): "system:" + name
        }
    }

    var isOperator: Bool { if case .operatorUser = self { return true } else { return false } }
}

/// Key lifecycle beyond issuing (SEC-API-003): overlap rotation, immediate revocation (by the business or by an operator without suspending
/// it), and the sweep that ends rotation overlaps. Authorization (who may do this) is the caller's job; everything here is tenant-scoped.
struct APIKeyLifecycle {
    let db: any Database
    let ctx: ServerContext

    /// Overlap choices offered when rotating (seconds). `0` revokes the old key at once.
    static let overlapChoices: [TimeInterval] = [0, 3600, 86_400, 7 * 86_400, 30 * 86_400]

    func key(_ id: UUID, businessId: UUID) async throws -> BusinessAPIKeyRecord {
        guard let key = try await BusinessAPIKeyRecord.query(on: db).filter(\.$id == id).filter(\.$businessId == businessId).first() else { throw APIError.notFound }
        return key
    }

    // MARK: Revoke

    /// Immediate and idempotent (compare-and-swap on `revoked_at`). Returns whether this call revoked the key.
    @discardableResult
    func revoke(id: UUID, businessId: UUID, reason: String, actor: KeyActor) async throws -> Bool {
        let key = try await key(id, businessId: businessId)
        guard key.revokedAt == nil else { return false }
        let now = ctx.now
        guard try await DB.swapFromNull(db, table: BusinessAPIKeyRecord.schema, id: id, column: "revoked_at", newValue: now,
                                        extra: [("revoked_by", actor.label), ("revoke_reason", String(reason.prefix(200)))]) else { return false }
        ctx.metrics.count(.apiKeyRevoked)
        _ = try await AuditService(db: db, ctx: ctx).record(actor.isOperator ? "apikey.revoked_by_operator" : "apikey.revoked", actor: actor.audit,
            businessId: BusinessID(businessId), subjectType: "api_key", subjectId: id.uuidString.lowercased(),
            metadata: ["kid": key.kid ?? "legacy", "reason": String(reason.prefix(200)), "mode": key.livemode ? "live" : "test"])
        return true
    }

    /// Revokes every active key of the business (optionally only live or only test keys). The business stays active (ops gap G-3).
    @discardableResult
    func revokeAll(businessId: UUID, live: Bool?, reason: String, actor: KeyActor) async throws -> Int {
        var revoked = 0
        for key in try await BusinessAPIKeyRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$revokedAt == nil).all() {
            if let live, key.livemode != live { continue }
            if let id = key.id, try await revoke(id: id, businessId: businessId, reason: reason, actor: actor) { revoked += 1 }
        }
        return revoked
    }

    // MARK: Rotate with overlap

    /// Issues a replacement with the same scopes, capabilities, restrictions and expiry and ends the old key after `overlap`. Both work during
    /// the overlap so the integration can switch without downtime. The replacement never widens anything the old key could do.
    func rotate(id: UUID, businessId: UUID, overlap: TimeInterval, actor: KeyActor) async throws -> BusinessAPIKeys.Issued {
        guard Self.overlapChoices.contains(overlap), overlap <= ctx.config.operations.apiKeyMaxOverlap else {
            throw APIError.validation("Choose an overlap of none, 1 hour, 1 day, 7 days or 30 days.", details: ["overlap": "invalid"])
        }
        let old = try await key(id, businessId: businessId)
        let now = ctx.now
        guard old.isUsable(at: now) else { throw APIError.conflict("Only a working key can be rotated.") }
        guard old.rotatedTo == nil, old.autoRevokeAt == nil else { throw APIError.conflict("This key is already being rotated.") }
        var options = BusinessAPIKeys.Options(expiresAt: old.expiresAt)
        options.ipAllowlist = IPNetwork.parseList(old.ipAllowlist ?? "") ?? []
        options.requiresMTLS = old.requiresMTLS
        options.certBinding = old.certBinding
        options.createdBy = { if case .user(let id) = actor { return id } else { return old.createdBy } }()
        options.rotatedFrom = id
        let issued = try await BusinessAPIKeys.issue(businessId: businessId, name: String(old.name.prefix(52)) + " (rotated)", live: old.livemode,
                                                     scopes: Array(old.scopeSet).sorted(), capabilities: Array(old.capabilitySet), now: now, options: options, on: db)
        old.rotatedTo = issued.record.id
        if overlap == 0 {
            old.revokedAt = now
            old.revokedBy = actor.label
            old.revokeReason = "rotated"
        } else {
            old.autoRevokeAt = now.addingTimeInterval(overlap)
        }
        try await old.update(on: db)
        ctx.metrics.count(.apiKeyRotated)
        _ = try await AuditService(db: db, ctx: ctx).record("apikey.rotated", actor: actor.audit, businessId: BusinessID(businessId), subjectType: "api_key",
            subjectId: id.uuidString.lowercased(), metadata: ["new_key": issued.record.id?.uuidString.lowercased() ?? "", "overlap_seconds": String(Int(overlap)),
                                                              "kid": old.kid ?? "legacy"])
        return issued
    }

    // MARK: Sweep

    /// Stamps `revoked_at` on keys whose rotation overlap ended (they were already refused by the middleware; this makes the record say so).
    @discardableResult
    func sweep() async throws -> Int {
        let now = ctx.now
        let due = try await BusinessAPIKeyRecord.query(on: db).filter(\.$revokedAt == nil).filter(\.$autoRevokeAt != nil).filter(\.$autoRevokeAt <= now).all()
        var swept = 0
        for key in due {
            guard let id = key.id, try await DB.swapFromNull(db, table: BusinessAPIKeyRecord.schema, id: id, column: "revoked_at", newValue: key.autoRevokeAt ?? now,
                                                              extra: [("revoked_by", "system:rotation"), ("revoke_reason", "rotation overlap ended")]) else { continue }
            ctx.metrics.count(.apiKeyAutoRevoked)
            _ = try await AuditService(db: db, ctx: ctx).record("apikey.auto_revoked", actor: AuditActor(kind: .system), businessId: BusinessID(key.businessId),
                subjectType: "api_key", subjectId: id.uuidString.lowercased(), metadata: ["kid": key.kid ?? "legacy"])
            swept += 1
        }
        return swept
    }
}
