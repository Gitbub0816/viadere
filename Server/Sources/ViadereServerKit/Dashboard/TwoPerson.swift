import Fluent
import Foundation
import ViadereCore

/// Two-person approval (spec §9.2 "separation of duties for enterprise accounts"). When a business turns it on, creating or rotating an API key
/// and granting a role do not happen on the requester's say-so: the request waits as a *pending change* until a **different** member who may
/// approve it says yes (the approver is checked against the same role rules as the requester), and expires after 24 hours otherwise.
///
/// A key request is *completed by the requester* after approval (the requester alone sees the new secret, and the approver never handles it).
/// A role grant, a member removal or the switching-off of two-person approval itself is executed when the approver approves it; the approver must
/// be able to manage **both** the member's current role and the target role, and a change whose member role moved since the request is void.
/// The payload is sealed at rest and holds no secret.
struct PendingChanges {
    let db: any Database
    let ctx: ServerContext

    static let lifetime: TimeInterval = 24 * 3600
    static let maxOpenPerBusiness = 25
    static let sealContext = "pending_changes.payload"

    enum Kind: String, Sendable {
        case apiKey = "api_key"
        case apiKeyRotation = "api_key_rotation"
        case roleGrant = "role_grant"
        /// A change that weakens a security control (turning two-person approval off). Approved by someone who may manage security.
        case securitySetting = "security_setting"
    }

    /// What was asked for. Fields that do not apply to the kind are `nil`.
    struct Payload: Codable, Equatable, Sendable {
        // API key
        var name: String?
        var live: Bool?
        var scopes: [String]?
        var capabilities: [String]?
        var expiresInDays: Int?
        var ipAllowlist: String?
        var requiresMTLS: Bool?
        // Rotation
        var keyId: String?
        var overlapSeconds: Int?
        // Role grant
        var operation: String?   // invite | change | remove | disable_two_person
        var email: String?
        var role: String?
        var membershipId: String?
        /// The member's role when the change was requested. If it differs at approval time the request is void (platform gate M3).
        var currentRole: String?
        /// Whether executing this widens scope (Security Admin or Owner must approve).
        var elevates: Bool?
    }

    func open(businessId: UUID) async throws -> [PendingChangeRecord] {
        try await expireDue()
        return try await PendingChangeRecord.query(on: db).filter(\.$businessId == businessId)
            .group(.or) { $0.filter(\.$status == "pending"); $0.filter(\.$status == "approved") }.sort(\.$requestedAt, .descending).all()
    }

    func payload(of change: PendingChangeRecord) throws -> Payload {
        guard let id = change.id, let data = try? ctx.cipher.open(change.payloadJSON, context: Self.sealContext, rowId: id),
              let payload = try? JSONDecoder().decode(Payload.self, from: data) else { throw APIError.internalError }
        return payload
    }

    @discardableResult
    func request(businessId: UUID, kind: Kind, by userId: UUID, payload: Payload) async throws -> PendingChangeRecord {
        try await expireDue()
        guard try await PendingChangeRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$status == "pending").count() < Self.maxOpenPerBusiness else {
            throw APIError.conflict("Too many requests are waiting for approval.")
        }
        let record = PendingChangeRecord()
        record.id = UUID()
        record.businessId = businessId
        record.kind = kind.rawValue
        record.payloadJSON = try ctx.cipher.seal(JSONEncoder().encode(payload), context: Self.sealContext, rowId: record.id!)
        record.requestedBy = userId
        record.requestedAt = ctx.now
        record.expiresAt = ctx.now.addingTimeInterval(Self.lifetime)
        record.status = "pending"
        try await record.create(on: db)
        ctx.metrics.count(.twoPersonRequested)
        _ = try await AuditService(db: db, ctx: ctx).record("approval.requested", actor: AuditActor(kind: .business, id: userId.uuidString.lowercased()),
            businessId: BusinessID(businessId), subjectType: "pending_change", subjectId: record.id?.uuidString.lowercased(), metadata: ["kind": kind.rawValue])
        await Notifier(db: db, ctx: ctx).notifyBusiness(businessId, roles: [.owner, .securityAdmin, .orgAdmin], includeSecurityContacts: false, topic: .roleChanges,
            subject: "A change is waiting for your approval",
            text: "A team member asked for a \(kind == .roleGrant ? "team change" : kind == .securitySetting ? "security setting change" : "credential change") that needs a second person's approval. Review it in the console under Security.",
            kind: "approval-requested")
        return record
    }

    func expireDue() async throws {
        let now = ctx.now
        // Read first: an idle run (every console load, every maintenance minute) takes no write lock.
        for open in ["pending", "approved"] {
            guard try await PendingChangeRecord.query(on: db).filter(\.$status == open).filter(\.$expiresAt <= now).count() > 0 else { continue }
            try await PendingChangeRecord.query(on: db).filter(\.$status == open).filter(\.$expiresAt <= now).set(\.$status, to: "expired").update()
        }
    }

    private func load(_ id: UUID, businessId: UUID) async throws -> PendingChangeRecord {
        try await expireDue()
        guard let change = try await PendingChangeRecord.query(on: db).filter(\.$id == id).filter(\.$businessId == businessId).first() else { throw APIError.notFound }
        return change
    }

    /// Approver checks shared by approve and reject: not the requester, may approve at all, and holds the permission the request needs.
    func requireMayDecide(_ change: PendingChangeRecord, approver: DashboardPrincipal) throws {
        guard let approverId = approver.user.id, approverId != change.requestedBy else {
            throw APIError(.forbidden, .forbidden, "A different person has to decide this request.")
        }
        guard approver.can(.approveChanges) else { throw APIError.forbidden }
    }

    /// Approves. A role grant is executed here by `executeRoleGrant`; a key change becomes `approved` and the requester completes it.
    func approve(id: UUID, approver: DashboardPrincipal, note: String?, executeRoleGrant: (Payload, UUID) async throws -> Void) async throws {
        guard let businessId = approver.business?.id, let approverId = approver.user.id else { throw APIError.forbidden }
        let change = try await load(id, businessId: businessId)
        guard change.status == "pending" else { throw APIError.conflict("This request was already decided or has expired.") }
        try requireMayDecide(change, approver: approver)
        let payload = try payload(of: change)
        switch Kind(rawValue: change.kind) {
        case .apiKey, .apiKeyRotation:
            guard approver.can(.manageAPIKeys), !(payload.elevates ?? false) || approver.can(.elevateKeyScope) else {
                throw APIError(.forbidden, .forbidden, "This request widens a key's scope: a Security Admin or an Owner has to approve it.")
            }
        case .roleGrant:
            guard let actor = approver.role else { throw APIError.forbidden }
            if let raw = payload.role {
                guard let target = OrgRole(rawValue: raw), RoleGrantPolicy.mayManage(actor: actor, role: target) else {
                    throw APIError(.forbidden, .forbidden, "You cannot grant that role.")
                }
            }
            if payload.operation == "change" || payload.operation == "remove" {
                // The member's role now must still be the one the requester saw, and the approver must be able to manage it too.
                guard let raw = payload.membershipId, let memberId = UUID(uuidString: raw),
                      let member = try await OrgMembershipRecord.query(on: db).filter(\.$id == memberId).filter(\.$businessId == businessId).filter(\.$removedAt == nil).first(),
                      member.role == payload.currentRole, let current = OrgRole(rawValue: member.role) else {
                    _ = try await DB.swap(db, table: PendingChangeRecord.schema, id: id, column: "status", expected: "pending", newValue: "void")
                    _ = try await AuditService(db: db, ctx: ctx).record("approval.voided", outcome: .denied, actor: AuditActor(kind: .business, id: approverId.uuidString.lowercased()),
                        businessId: BusinessID(businessId), subjectType: "pending_change", subjectId: id.uuidString.lowercased(), metadata: ["kind": change.kind])
                    throw APIError.conflict("The member changed since this was requested, so the request is void. Ask again.")
                }
                guard RoleGrantPolicy.mayManage(actor: actor, role: current) else {
                    throw APIError(.forbidden, .forbidden, "You cannot change or remove a member with that role.")
                }
            }
        case .securitySetting:
            guard approver.can(.manageSecurity) else {
                throw APIError(.forbidden, .forbidden, "A Security Admin or an Owner has to approve a change to a security setting.")
            }
        case nil: throw APIError.internalError
        }
        guard try await DB.swap(db, table: PendingChangeRecord.schema, id: id, column: "status", expected: "pending", newValue: "approved",
                                extra: [("decided_by", approverId), ("decided_at", ctx.now), ("decision_note", String((note ?? "").prefix(300)))]) else {
            throw APIError.conflict("This request was already decided.")
        }
        _ = try await AuditService(db: db, ctx: ctx).record("approval.approved", actor: AuditActor(kind: .business, id: approverId.uuidString.lowercased()),
            businessId: BusinessID(businessId), subjectType: "pending_change", subjectId: id.uuidString.lowercased(), metadata: ["kind": change.kind])
        if change.kind == Kind.roleGrant.rawValue || change.kind == Kind.securitySetting.rawValue {
            try await executeRoleGrant(payload, change.requestedBy)
            _ = try await DB.swap(db, table: PendingChangeRecord.schema, id: id, column: "status", expected: "approved", newValue: "executed", extra: [("executed_at", ctx.now)])
        }
    }

    func reject(id: UUID, approver: DashboardPrincipal, note: String?) async throws {
        guard let businessId = approver.business?.id, let approverId = approver.user.id else { throw APIError.forbidden }
        let change = try await load(id, businessId: businessId)
        guard change.status == "pending" else { throw APIError.conflict("This request was already decided or has expired.") }
        try requireMayDecide(change, approver: approver)
        guard try await DB.swap(db, table: PendingChangeRecord.schema, id: id, column: "status", expected: "pending", newValue: "rejected",
                                extra: [("decided_by", approverId), ("decided_at", ctx.now), ("decision_note", String((note ?? "").prefix(300)))]) else {
            throw APIError.conflict("This request was already decided.")
        }
        _ = try await AuditService(db: db, ctx: ctx).record("approval.rejected", outcome: .denied, actor: AuditActor(kind: .business, id: approverId.uuidString.lowercased()),
            businessId: BusinessID(businessId), subjectType: "pending_change", subjectId: id.uuidString.lowercased(), metadata: ["kind": change.kind])
    }

    func cancel(id: UUID, requester: DashboardPrincipal) async throws {
        guard let businessId = requester.business?.id, let userId = requester.user.id else { throw APIError.forbidden }
        let change = try await load(id, businessId: businessId)
        guard change.requestedBy == userId else { throw APIError.forbidden }
        guard try await DB.swap(db, table: PendingChangeRecord.schema, id: id, column: "status", expected: "pending", newValue: "cancelled") else {
            throw APIError.conflict("This request can no longer be cancelled.")
        }
    }

    /// The requester completes an approved key change: returns the payload and marks it executed in one compare-and-swap (single use).
    func consumeApproved(id: UUID, businessId: UUID, requester: UUID, kind: Kind) async throws -> Payload {
        let change = try await load(id, businessId: businessId)
        guard change.requestedBy == requester, change.kind == kind.rawValue, change.status == "approved" else {
            throw APIError(.forbidden, .forbidden, "This request is not approved for you to complete.")
        }
        let payload = try payload(of: change)
        guard try await DB.swap(db, table: PendingChangeRecord.schema, id: id, column: "status", expected: "approved", newValue: "executed", extra: [("executed_at", ctx.now)]) else {
            throw APIError.conflict("This request was already completed.")
        }
        return payload
    }
}
