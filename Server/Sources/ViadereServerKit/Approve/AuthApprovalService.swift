import Fluent
import Foundation
import Vapor
import ViadereCore

/// `AuthApprovals.v1` (additive, forward-only): three nullable columns on `approve_requests` for `auth-approvals` (ADR-0022): the number-match length, the
/// business `session_handle` (class T, never shown) and the v2 `deny_reason`. Rows created by `/v1/business/approve/requests` keep them null.
struct CreateAuthApprovalsSchema: AsyncMigration {
    var name: String { "AuthApprovals.v1" }

    func prepare(on db: any Database) async throws {
        // One column per statement: SQLite adds one column per ALTER TABLE.
        try await db.schema(ApproveRequestRecord.schema).field("match_digits", .int).update()
        try await db.schema(ApproveRequestRecord.schema).field("session_handle", .string).update()
        try await db.schema(ApproveRequestRecord.schema).field("deny_reason", .string).update()
    }

    func revert(on db: any Database) async throws {
        for column in ["match_digits", "session_handle", "deny_reason"] { try await db.schema(ApproveRequestRecord.schema).deleteField(.string(column)).update() }
    }
}

/// `ApproveStage5Review.v1` (additive, forward-only): two nullable columns on `approve_requests` from the Stage 5 code review: `answer_group` (S5-02, one group answer
/// counts once toward the pause) and `silent` (S5-04, the request was delivered without an alert push). Existing rows keep them null.
struct CreateApproveStage5ReviewSchema: AsyncMigration {
    var name: String { "ApproveStage5Review.v1" }

    func prepare(on db: any Database) async throws {
        // One column per statement: SQLite adds one column per ALTER TABLE.
        try await db.schema(ApproveRequestRecord.schema).field("answer_group", .string).update()
        try await db.schema(ApproveRequestRecord.schema).field("silent", .bool).update()
    }

    func revert(on db: any Database) async throws {
        for column in ["answer_group", "silent"] { try await db.schema(ApproveRequestRecord.schema).deleteField(.string(column)).update() }
    }
}

/// The number-match part of an `auth-approvals` create, handed to `ApproveRequestService.create`.
struct AuthApprovalExtras: Sendable {
    var digits: Int
    /// Server-visible requests only (sealed with the details). End-to-end requests: inside the envelope, never here.
    var code: String?
    var tags: AuthMatchTagMembers
    var sessionHandle: String?
    /// Keyed (server pepper) hash of the whole `auth-approvals` body: a reused `request_id` with another code is an idempotency conflict.
    var requestHash: String
}

/// `POST /v1/business/auth-approvals` and `GET /v1/business/auth-approvals/{requestId}` (ADR-0020 §1, §2a; ADR-0022 §1-§5).
///
/// An auth approval **is** an Approve v2 request (existing semantics, SECURITY §2.55) that always carries number matching: the business's SDK draws the code,
/// shows it on its own sign-in or payment screen and sends only its HMAC tags (plus, for a server-visible request, the code the device compares against).
/// Behind both `AUTH_DELIVERY_ENABLED` and `APPROVE_V2_ENABLED`; `404` while either is off.
struct AuthApprovalService {
    let db: any Database
    let ctx: ServerContext

    static func requireEnabled(_ ctx: ServerContext) throws {
        try AuthDeliveryGate.require(ctx)
        try ApproveGate.require(ctx)
    }

    /// The legacy `POST /v1/business/approve/requests` carries no number (Stage 5 review S5-03). With `AUTH_NUMBER_MATCHING_REQUIRED` on it creates nothing, so a fatigue
    /// attacker cannot get a number-less push approval out of a business that has not migrated, and a payment that the device could only deny is never delivered.
    static func requireNumberMatching(_ ctx: ServerContext) throws {
        guard ctx.config.authDelivery.numberMatchingRequired else { return }
        throw APIError(.unprocessableEntity, .validationFailed, "Approvals need number matching. Use POST /v1/business/auth-approvals.", details: ["reason": "number_match_required"])
    }

    func create(principal: BusinessPrincipal, body: Data) async throws -> (view: ApprovalRequestView, created: Bool) {
        try await AuthDeliveryService(db: db, ctx: ctx).requireLiveKeyAssurance(principal)
        let request: AuthApprovalCreateRequest
        do { request = try ViadereJSON.decode(AuthApprovalCreateRequest.self, from: body) } catch {
            throw APIError.validation("The request failed validation.")
        }
        if let issue = request.validate() { throw APIError.validation("The request failed validation.", details: [issue.field: issue.code]) }
        // ADR-0022 §4.3: payments and high or critical requests must be business-signed end to end; the relay may not hold their text.
        if request.effectiveRisk >= .high, request.envelopes == nil {
            throw APIError(.unprocessableEntity, .validationFailed, "High-risk and payment approvals must be end-to-end encrypted.", details: ["reason": "e2ee_required"])
        }
        let hash = ctx.hasher.hmacHex("auth_approval.create", Base64URL.encode(try ViadereJSON.encode(request)))
        let extras = AuthApprovalExtras(digits: request.numberMatch.digits, code: request.numberMatch.code,
                                        tags: AuthMatchTagMembers(matchTag: request.matchTag, matchPrefixTag: request.matchPrefixTag),
                                        sessionHandle: request.sessionHandle, requestHash: hash)
        return try await ApproveRequestService(db: db, ctx: ctx).create(principal: principal, body: request.approvalRequest, authApproval: extras)
    }

    /// `session_handle` supersession (ADR-0022 §5.2 item 1) inside the creating transaction: an open auth approval of the same (business, customer) with the
    /// same handle is cancelled `superseded`, unless the handle was seen on more than 3 request ids in 10 minutes (abuse rule: then it is treated as absent).
    func supersede(new record: ApproveRequestRecord, handle: String?) async throws {
        guard let handle, let id = record.id else { return }
        let recent = try await ApproveRequestRecord.query(on: db).filter(\.$businessId == record.businessId).filter(\.$consumerId == record.consumerId)
            .filter(\.$sessionHandle == handle).filter(\.$id != id).filter(\.$createdAt > ctx.now.addingTimeInterval(-AuthDeliveryGrouping.handleWindow)).all()
        if Set(recent.map(\.requestId)).count >= AuthDeliveryGrouping.handleDistinctLimit {
            _ = try? await AuditService(db: db, ctx: ctx).record("auth_delivery.session_handle_abuse", outcome: .denied, actor: AuditActor(kind: .system),
                consumerId: ConsumerID(record.consumerId), businessId: BusinessID(record.businessId), subjectType: "approve_request", subjectId: id.uuidString.lowercased())
            return
        }
        for older in recent where older.statusValue == .pending {
            _ = try await ApproveRequestService(db: db, ctx: ctx).finish(older, status: .cancelled, reason: "superseded", notify: true)
        }
    }

    /// Above 10 open approvals in one group: `auth_delivery.group_pressure` (count only; no code, no tag), at most once per group per hour. Never a refusal.
    func pressure(businessId: UUID, consumerId: UUID) async {
        guard let open = try? await AuthMatchGroups(db: db, ctx: ctx).openCount(businessId: businessId, consumerId: consumerId), open > MatchGroupPolicy.pressureThreshold,
              await ctx.limiter.allow("authdl-pressure", key: "\(businessId)|\(consumerId)", rule: .perHour(1, burst: 1)) else { return }
        ctx.logger.warning("auth approval group pressure", metadata: ["business": "\(businessId)", "open": "\(open)"])
        _ = try? await AuditService(db: db, ctx: ctx).record("auth_delivery.group_pressure", actor: AuditActor(kind: .system), consumerId: ConsumerID(consumerId),
                                                           businessId: BusinessID(businessId), subjectType: "auth_group", metadata: ["open": String(open)])
    }

    /// After the relay accepted a signed approve that the typed number selected, the group's other open auth approvals end `superseded` (ADR-0022 §5.2 item 2).
    func closeGroup(after decided: ApproveRequestRecord) async throws {
        guard decided.matchDigits != nil, let id = decided.id else { return }
        let others = try await ApproveRequestRecord.query(on: db).filter(\.$businessId == decided.businessId).filter(\.$consumerId == decided.consumerId)
            .filter(\.$status == ApprovalRequestStatus.pending.rawValue).filter(\.$id != id).all().filter { $0.matchDigits != nil }
        for other in others { _ = try await ApproveRequestService(db: db, ctx: ctx).finish(other, status: .cancelled, reason: "superseded", notify: true) }
    }

    // MARK: Device: reduce-only deny

    /// `POST /v1/approve/requests/{approvalId}/deny` (ADR-0022 §5.5, Stage 4 review R4-03). Authenticated by the ordinary device-signed request (the device
    /// `request` key; no approval key, no Face ID). **Reduce-only:** it can move a pending request only to `denied` or `reported`, never records a signed result,
    /// and counts as one denial toward the pause. A request of another device or customer is a plain `404`.
    func deny(principal: ConsumerPrincipal, deliveryId: UUID, report: Bool) async throws -> SubmitApprovalResultResponse {
        guard let deviceId = principal.deviceId,
              let delivery = try await ApproveDeliveryRecord.find(deliveryId, on: db), delivery.deviceId == deviceId.uuid, delivery.consumerId == principal.consumerId.uuid,
              let request = try await ApproveRequestRecord.find(delivery.requestId, on: db) else { throw APIError.notFound }
        try await ctx.limiter.enforce("authdl-deny", key: deviceId.description, rule: ctx.config.authDelivery.denyRate)
        let now = ctx.now
        let service = ApproveRequestService(db: db, ctx: ctx)
        guard request.statusValue == .pending else { throw APIError.conflict("This request has already been resolved.") }
        if request.expiresAt <= now {
            _ = try await service.finish(request, status: .expired, reason: nil, notify: true)
            throw APIError.gone("This request has expired.")
        }
        let status: ApprovalRequestStatus = report ? .reported : .denied
        let decision: ApprovalDecision = report ? .report : .deny
        let ctx = self.ctx
        try await db.transaction { tx in
            let swapped = try await DB.swap(tx, table: ApproveRequestRecord.schema, id: request.id!, column: "status", expected: ApprovalRequestStatus.pending.rawValue,
                                            newValue: status.rawValue, extra: [("decided_at", now), ("decision", decision.rawValue), ("reason", "device_deny")])
            guard swapped else { throw APIError(.conflict, .replayDetected, "This request was already decided.") }
            try await ApproveRequestRecord.query(on: tx).filter(\.$id == request.id!).set(\.$detailsSealed, to: nil).set(\.$challenge, to: nil)
                .set(\.$denyReason, to: report ? ApprovalDenyReason.notMe.rawValue : nil).update()
            try await AuthMatchGroups(db: tx, ctx: ctx).release(refId: request.id!)
            guard let decided = try await ApproveRequestRecord.find(request.id!, on: tx) else { throw APIError.internalError }
            try await ApproveWebhooks(db: tx, ctx: ctx).requestDecided(decided)
            _ = try await AuditService(db: tx, ctx: ctx).record("approve.request_denied_reduce_only", principal: principal, businessId: BusinessID(request.businessId),
                subjectType: "approve_request", subjectId: request.id?.uuidString.lowercased(), metadata: ["decision": decision.rawValue])
        }
        return SubmitApprovalResultResponse(id: deliveryId, status: status)
    }
}
