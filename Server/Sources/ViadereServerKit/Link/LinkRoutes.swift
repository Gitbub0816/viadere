import Fluent
import Foundation
import Vapor
import ViadereCore

/// `/v1/business/link-sessions/...` (businesses, scope `links:manage`, live keys) and `/v1/link-sessions/...` (the customer's devices). Behind the
/// Approve v2 release gate: link sessions use the key directory and pairwise approval keys.
enum LinkRoutes {
    typealias Scope = BusinessAPIKeys.Scope

    static func register(_ routes: any RoutesBuilder) {
        // MARK: Business (tenant = the API key's business, never a parameter)
        routes.api(APIRoutes.businessLinkSessionCreate, scope: Scope.linksManage) { req in
            try ApproveGate.require(req.ctx)
            let body: CreateLinkSessionRequest = try req.decodeBody()
            let ticket = try await LinkSessionService(db: req.db, ctx: req.ctx).create(principal: try req.business, request: body)
            return try req.jsonResponse(ticket, status: .created)
        }
        routes.api(APIRoutes.businessLinkSessionGet, scope: Scope.linksManage) { req in
            try ApproveGate.require(req.ctx)
            let service = LinkSessionService(db: req.db, ctx: req.ctx)
            return try req.jsonResponse(service.businessView(try await service.record(id: try req.uuidPath("sessionId"), principal: try req.business)))
        }
        routes.api(APIRoutes.businessLinkSessionConfirm, scope: Scope.linksManage) { req in
            try ApproveGate.require(req.ctx)
            let body: ConfirmLinkSessionRequest = try req.decodeBody()
            let service = LinkSessionService(db: req.db, ctx: req.ctx)
            return try req.jsonResponse(service.businessView(try await service.confirm(principal: try req.business, id: try req.uuidPath("sessionId"), request: body)))
        }
        routes.api(APIRoutes.businessLinkSessionCancel, scope: Scope.linksManage) { req in
            try ApproveGate.require(req.ctx)
            let service = LinkSessionService(db: req.db, ctx: req.ctx)
            return try req.jsonResponse(service.businessView(try await service.cancel(principal: try req.business, id: try req.uuidPath("sessionId"))))
        }

        // MARK: Devices
        routes.api(APIRoutes.linkSessionLookup) { req in
            try ApproveGate.require(req.ctx)
            let body: LinkSessionLookupRequest = try req.decodeBody()
            return try req.jsonResponse(try await LinkSessionService(db: req.db, ctx: req.ctx).lookup(principal: try req.consumer, code: body.code))
        }
        routes.api(APIRoutes.linkSessionComplete) { req in
            try ApproveGate.require(req.ctx)
            let body: CompleteLinkSessionRequest = try req.decodeBody()
            return try req.jsonResponse(try await LinkSessionService(db: req.db, ctx: req.ctx).complete(principal: try req.consumer, sessionId: try req.uuidPath("sessionId"), request: body),
                                        status: .created)
        }
        routes.api(APIRoutes.linkSessionGet) { req in
            try ApproveGate.require(req.ctx)
            let service = LinkSessionService(db: req.db, ctx: req.ctx)
            return try req.jsonResponse(try await service.deviceView(try await service.deviceRecord(principal: try req.consumer, id: try req.uuidPath("sessionId"))))
        }
    }
}
