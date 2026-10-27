import Fluent
import Foundation
import Vapor
import ViadereCore

extension Request {
    /// A UUID path parameter, or `404`.
    func uuidPath(_ name: String) throws -> UUID {
        guard let raw = parameters.get(name), let id = UUID(uuidString: raw), id.uuidString.lowercased() == raw else { throw APIError.notFound }
        return id
    }

    /// The key must carry at least one of the approval capabilities, and the policy must allow it (scope, entitlement, tier, switches).
    func requireApprovalCapability() async throws {
        let principal = try business
        let carried = [Capability.authChallenge, .transactionApprove].filter { principal.capabilities.contains($0) }
        guard !carried.isEmpty else { try await requireCapability(.authChallenge); return }
        var lastError: (any Error)?
        for capability in carried {
            do { try await requireCapability(capability); return } catch { lastError = error }
        }
        throw lastError ?? APIError.forbidden
    }
}

/// `/v1/business/approve/...` (businesses) and `/v1/approve/...` (the customer's devices). Every handler checks the release gate first.
enum ApproveRoutes {
    typealias Scope = BusinessAPIKeys.Scope

    static func register(_ routes: any RoutesBuilder) {
        // MARK: Business
        routes.api(APIRoutes.businessApproveEnrollmentCreate, scope: Scope.approvalsManage) { req in
            try ApproveGate.require(req.ctx)
            let body: CreateApprovalEnrollmentRequest = try req.decodeBody()
            let ticket = try await ApproveEnrollmentService(db: req.db, ctx: req.ctx).create(principal: try req.business, request: body)
            return try req.jsonResponse(ticket, status: .created)
        }
        routes.api(APIRoutes.businessApproveEnrollmentGet, scope: Scope.approvalsManage) { req in
            try ApproveGate.require(req.ctx)
            try await req.requireApprovalCapability()
            let service = ApproveEnrollmentService(db: req.db, ctx: req.ctx)
            return try req.jsonResponse(try service.businessView(try await service.record(id: try req.uuidPath("enrollmentId"), principal: try req.business)))
        }
        routes.api(APIRoutes.businessApproveEnrollmentConfirm, scope: Scope.approvalsManage) { req in
            try ApproveGate.require(req.ctx)
            try await req.requireApprovalCapability()
            let body: ConfirmApprovalEnrollmentRequest = try req.decodeBody()
            let key = try await ApproveEnrollmentService(db: req.db, ctx: req.ctx).confirm(principal: try req.business, id: try req.uuidPath("enrollmentId"), request: body)
            return try req.jsonResponse(try ApproveKeyService(db: req.db, ctx: req.ctx).businessView(key))
        }
        routes.api(APIRoutes.businessApproveEnrollmentCancel, scope: Scope.approvalsManage) { req in
            try ApproveGate.require(req.ctx)
            try await req.requireApprovalCapability()
            let service = ApproveEnrollmentService(db: req.db, ctx: req.ctx)
            return try req.jsonResponse(try service.businessView(try await service.cancel(principal: try req.business, id: try req.uuidPath("enrollmentId"))))
        }
        routes.api(APIRoutes.businessApproveKeys, scope: Scope.approvalsManage) { req in
            try ApproveGate.require(req.ctx)
            try await req.requireApprovalCapability()
            let principal = try req.business
            guard let raw = req.query[String.self, at: "subject_ref"], let subject = SubjectRef(raw) else {
                throw APIError.validation("subject_ref is required.", details: ["subject_ref": "invalid"])
            }
            let relationship = try await SubjectResolver(db: req.db, ctx: req.ctx).relationship(businessId: principal.businessId, subjectRef: subject)
            guard try await Sandbox(db: req.db).matches(consumerId: relationship.consumerId, livemode: principal.livemode) else { throw APIError.notFound }
            let service = ApproveKeyService(db: req.db, ctx: req.ctx)
            let rows = try await ApproveKeyRecord.query(on: req.db).filter(\.$relationshipId == relationship.id!).sort(\.$createdAt, .ascending).all()
            return try req.jsonResponse(try rows.map(service.businessView))
        }
        routes.api(APIRoutes.businessApproveKeyRevoke, scope: Scope.approvalsManage) { req in
            try ApproveGate.require(req.ctx)
            try await req.requireApprovalCapability()
            let principal = try req.business
            let body: RevokeApprovalKeyRequest = (try? req.decodeBody()) ?? RevokeApprovalKeyRequest()
            guard let kid = req.parameters.get("kid"), KeyIdentifier.isValid(kid),
                  let key = try await ApproveKeyRecord.query(on: req.db).filter(\.$kid == kid).filter(\.$businessId == principal.businessId.uuid).first(),
                  try await Sandbox(db: req.db).matches(consumerId: key.consumerId, livemode: principal.livemode) else { throw APIError.notFound }
            let service = ApproveKeyService(db: req.db, ctx: req.ctx)
            let revoked = try await service.revoke(key, by: .business, reason: body.reason, actor: AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased()))
            return try req.jsonResponse(try service.businessView(revoked))
        }
        routes.api(APIRoutes.businessApproveRequestCreate, scope: Scope.approvalsManage) { req in
            try ApproveGate.require(req.ctx)
            let body: CreateApprovalRequest = try req.decodeBody()
            let result = try await ApproveRequestService(db: req.db, ctx: req.ctx).create(principal: try req.business, body: body)
            return try req.jsonResponse(result.view, status: result.created ? .created : .ok)
        }
        routes.api(APIRoutes.businessApproveRequestGet, scope: Scope.approvalsManage) { req in
            try ApproveGate.require(req.ctx)
            try await req.requireApprovalCapability()
            let service = ApproveRequestService(db: req.db, ctx: req.ctx)
            guard let id = req.parameters.get("requestId"), ApproveIdentifiers.isValidRequestId(id) else { throw APIError.notFound }
            return try req.jsonResponse(try service.view(try await service.record(requestId: id, principal: try req.business)))
        }
        routes.api(APIRoutes.businessApproveRequestCancel, scope: Scope.approvalsManage) { req in
            try ApproveGate.require(req.ctx)
            try await req.requireApprovalCapability()
            let service = ApproveRequestService(db: req.db, ctx: req.ctx)
            guard let id = req.parameters.get("requestId"), ApproveIdentifiers.isValidRequestId(id) else { throw APIError.notFound }
            return try req.jsonResponse(try service.view(try await service.cancel(principal: try req.business, requestId: id)))
        }
        routes.api(APIRoutes.businessApproveResult, scope: Scope.approvalsManage) { req in
            try ApproveGate.require(req.ctx)
            try await req.requireApprovalCapability()
            guard let ref = req.parameters.get("resultRef") else { throw APIError.notFound }
            return try req.jsonResponse(try await ApproveRequestService(db: req.db, ctx: req.ctx).result(principal: try req.business, resultRef: ref))
        }
        routes.api(APIRoutes.businessApproveFreeze, scope: Scope.approvalsManage) { req in
            try ApproveGate.require(req.ctx)
            try await req.requireApprovalCapability()
            let principal = try req.business
            let body: BusinessFreezeRequest = try req.decodeBody()
            let relationship = try await SubjectResolver(db: req.db, ctx: req.ctx).relationship(businessId: principal.businessId, subjectRef: body.subjectRef)
            guard try await Sandbox(db: req.db).matches(consumerId: relationship.consumerId, livemode: principal.livemode) else { throw APIError.notFound }
            let frozen = try await ApproveFreezeService(db: req.db, ctx: req.ctx).businessFreeze(principal: principal, relationship: relationship, frozen: body.frozen, reason: body.reason)
            return try req.jsonResponse(FreezeStatus(subjectRef: body.subjectRef, frozen: frozen))
        }

        // MARK: Devices
        routes.api(APIRoutes.approveEnrollmentLookup) { req in
            try ApproveGate.require(req.ctx)
            let body: ApproveEnrollmentLookupRequest = try req.decodeBody()
            return try req.jsonResponse(try await ApproveEnrollmentService(db: req.db, ctx: req.ctx).lookup(principal: try req.consumer, code: body.code))
        }
        routes.api(APIRoutes.approveEnrollmentComplete) { req in
            try ApproveGate.require(req.ctx)
            let body: CompleteApproveEnrollmentRequest = try req.decodeBody()
            return try req.jsonResponse(try await ApproveEnrollmentService(db: req.db, ctx: req.ctx).complete(principal: try req.consumer, enrollmentId: try req.uuidPath("enrollmentId"), request: body),
                                        status: .created)
        }
        routes.api(APIRoutes.approveKeys) { req in
            try ApproveGate.require(req.ctx)
            return try req.jsonResponse(try await ApproveEnrollmentService(db: req.db, ctx: req.ctx).deviceKeys(principal: try req.consumer))
        }
        routes.api(APIRoutes.approveKeyRevoke) { req in
            try ApproveGate.require(req.ctx)
            let principal = try req.consumer
            guard let kid = req.parameters.get("kid"), KeyIdentifier.isValid(kid),
                  let key = try await ApproveKeyRecord.query(on: req.db).filter(\.$kid == kid).filter(\.$consumerId == principal.consumerId.uuid).first() else { throw APIError.notFound }
            // Revoking is the safe direction, so any signed device of the account may do it, even one still in its cool-down.
            let service = ApproveKeyService(db: req.db, ctx: req.ctx)
            let revoked = try await service.revoke(key, by: .consumer, reason: nil, actor: AuditActor(kind: .consumer, id: principal.consumerId.description), except: principal.deviceId?.uuid)
            return try req.jsonResponse(try service.deviceView(revoked, business: try await service.businessSummary(revoked.businessId)))
        }
        routes.api(APIRoutes.approveRequests) { req in
            try ApproveGate.require(req.ctx)
            return try req.jsonResponse(try await ApproveRequestService(db: req.db, ctx: req.ctx).pending(principal: try req.consumer))
        }
        routes.api(APIRoutes.approveRequestGet) { req in
            try ApproveGate.require(req.ctx)
            return try req.jsonResponse(try await ApproveRequestService(db: req.db, ctx: req.ctx).get(principal: try req.consumer, deliveryId: try req.uuidPath("approvalId")))
        }
        routes.api(APIRoutes.approveRequestResult) { req in
            try ApproveGate.require(req.ctx)
            let body: SubmitApprovalResultRequest = try req.decodeBody()
            return try req.jsonResponse(try await ApproveRequestService(db: req.db, ctx: req.ctx).submit(principal: try req.consumer, deliveryId: try req.uuidPath("approvalId"), body: body))
        }
        routes.api(APIRoutes.approveFreezeGet) { req in
            try ApproveGate.require(req.ctx)
            return try req.jsonResponse(try await ApproveFreezeService(db: req.db, ctx: req.ctx).state(consumerId: try req.consumer.consumerId.uuid))
        }
        routes.api(APIRoutes.approveFreezeSet) { req in
            try ApproveGate.require(req.ctx)
            let body: ApproveFreezeRequest = try req.decodeBody()
            let service = ApproveFreezeService(db: req.db, ctx: req.ctx)
            let principal = try req.consumer
            let state = body.frozen ? try await service.freeze(principal: principal, scope: body.scope, relationshipId: body.relationshipId)
                                    : try await service.unfreeze(principal: principal, scope: body.scope, relationshipId: body.relationshipId, proof: body.proof)
            return try req.jsonResponse(state)
        }
    }
}
