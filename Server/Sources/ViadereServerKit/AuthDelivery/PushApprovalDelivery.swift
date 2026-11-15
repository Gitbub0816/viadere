import Fluent
import Foundation
import ViadereCore

/// The `push_approval` auth-delivery record (ADR-0022 §1): every `POST /v1/business/auth-approvals` also writes one `auth_deliveries` row so push MFA shares
/// the delivery table's status, event history and 30-day retention with links, codes and notices.
///
/// The Approve v2 request stays the source of truth: the business verifies the device-signed `ApprovalResult` itself, and the row only **mirrors** the
/// request's state (same UUID as the `approve_requests` row). Since contract v1.x (ledger S6-09) it is exposed like a delivery, read-only:
/// `GET /v1/business/auth-deliveries/{id}` shows it with `method: push_approval` (OpenAPI `ViewMethod`) and `request_id` `push_approval#<request_id>`, and
/// each transition emits the same opaque `auth.delivery.*` webhook event as a delivery's. It stays out of the device inbox, cancel and complete on the
/// delivery routes answer `404` (the business acts through `/v1/business/auth-approvals/{request_id}`), and the delivery expiry never sweeps it (the
/// Approve expiry drives it).
enum PushApprovalDelivery {
    static let method = "push_approval"
    static let template = "push_approval.v1"
    /// `#` is outside the business identifier alphabet, so a mirrored row can never collide with a business's own delivery `request_id`.
    static func requestId(_ approvalRequestId: String) -> String { "push_approval#" + approvalRequestId }

    /// Written in the transaction that creates the Approve request.
    static func create(on db: any Database, ctx: ServerContext, request: ApproveRequestRecord, principal: BusinessPrincipal, now: Date) async throws {
        let row = AuthDeliveryRecord()
        row.id = request.id
        row.businessId = request.businessId
        row.requestId = requestId(request.requestId)
        row.requestHash = request.requestHash
        row.relationshipId = request.relationshipId
        row.consumerId = request.consumerId
        row.apiKeyId = principal.keyId
        row.livemode = principal.livemode
        row.method = method
        row.purpose = (request.capability == Capability.transactionApprove.rawValue ? AuthDeliveryPurpose.stepUp : AuthDeliveryPurpose.signIn).rawValue
        row.template = template
        let initial = status(for: request.statusValue)
        row.status = initial.rawValue
        row.version = 0
        row.reason = request.reason
        row.channels = AuthDeliveryChannel.push.rawValue
        row.silent = request.delivered == 0 && request.statusValue == .pending
        row.dispatchAttempts = 0
        row.createdAt = now
        row.expiresAt = request.expiresAt
        if initial.isTerminal { row.endedAt = now }
        try await row.create(on: db)
        try await event(on: db, row: row, status: .created, reason: nil, actor: .api, at: now)
        try await event(on: db, row: row, status: initial, reason: request.reason, actor: .api, at: now)
        let service = AuthDeliveryService(db: db, ctx: ctx)
        try await service.emitWebhook(row, status: .created, reason: nil)
        try await service.emitWebhook(row, status: initial, reason: request.reason)
    }

    /// The delivery state that mirrors an Approve request state.
    static func status(for approval: ApprovalRequestStatus) -> AuthDeliveryStatus {
        switch approval {
        case .pending: .sent
        case .approved: .completed
        case .denied, .reported: .denied
        case .expired: .expired
        case .cancelled: .cancelled
        case .locked, .unknown: .failed
        }
    }

    /// Called wherever the Approve request leaves `pending` (decision, reduce-only deny, cancel, supersession, expiry). Idempotent; a missing row (a
    /// request created through `/v1/business/approve/requests`) changes nothing.
    static func mirror(on db: any Database, ctx: ServerContext, approvalId: UUID, status approval: ApprovalRequestStatus, reason: String?, actor: AuthDeliveryActor,
                       now: Date) async throws {
        guard let row = try await AuthDeliveryRecord.find(approvalId, on: db), row.method == method, !row.statusValue.isTerminal else { return }
        let target = status(for: approval)
        guard target != row.statusValue else { return }
        // Serialized by the Approve request's own compare-and-swap, which every caller won before calling this (same transaction).
        try await AuthDeliveryRecord.query(on: db).filter(\.$id == approvalId)
            .set(\.$status, to: target.rawValue).set(\.$version, to: row.version + 1).set(\.$reason, to: reason)
            .set(\.$endedAt, to: target.isTerminal ? now : nil).update()
        row.status = target.rawValue
        try await event(on: db, row: row, status: target, reason: reason, actor: actor, at: now)
        try await AuthDeliveryService(db: db, ctx: ctx).emitWebhook(row, status: target, reason: reason)
    }

    private static func event(on db: any Database, row: AuthDeliveryRecord, status: AuthDeliveryStatus, reason: String?, actor: AuthDeliveryActor, at: Date) async throws {
        let event = AuthDeliveryEventRecord()
        event.id = UUID()
        event.deliveryId = row.id!
        event.businessId = row.businessId
        event.status = status.rawValue
        event.reason = reason
        event.actor = actor.rawValue
        event.at = at
        try await event.create(on: db)
    }
}

extension AuthDeliveryRecord {
    /// A mirrored `push_approval` row (read-only on the delivery routes: `GET` only).
    var isPushApproval: Bool { method == PushApprovalDelivery.method }
}
