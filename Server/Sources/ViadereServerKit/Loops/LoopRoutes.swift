import Fluent
import Foundation
import Vapor
import ViadereCore

/// The consumer Loop API (WP-3.3, WP-3.5; SECURITY.md §2.98). Routes come from the Core catalog (`APIRoutes.loop*`); every one is
/// device-signed and takes the account from the principal.
enum LoopRoutes {
    static func register(_ routes: any RoutesBuilder) {
        routes.api(APIRoutes.loopConsentGet) { req in
            try req.jsonResponse(try await LoopRuntimeService(db: req.db, ctx: req.ctx).consentStatus(consumer: try req.consumer.consumerId.uuid))
        }
        routes.api(APIRoutes.loopConsentPut) { req in
            let body: LoopGlobalConsentRequest = try req.decodeBody()
            return try req.jsonResponse(try await LoopRuntimeService(db: req.db, ctx: req.ctx).grantGlobal(principal: try req.consumer, request: body))
        }
        routes.api(APIRoutes.loopConsentDelete) { req in
            try req.jsonResponse(try await LoopRuntimeService(db: req.db, ctx: req.ctx).revoke(principal: try req.consumer, business: nil))
        }
        routes.api(APIRoutes.loopBusinessConsentPut) { req in
            let business: BusinessID = try req.uuidParameter("businessId")
            let body: LoopBusinessConsentRequest = try req.decodeBody()
            return try req.jsonResponse(try await LoopRuntimeService(db: req.db, ctx: req.ctx).grantBusiness(principal: try req.consumer, business: business, request: body))
        }
        routes.api(APIRoutes.loopBusinessConsentDelete) { req in
            let business: BusinessID = try req.uuidParameter("businessId")
            return try req.jsonResponse(try await LoopRuntimeService(db: req.db, ctx: req.ctx).revoke(principal: try req.consumer, business: business))
        }
        routes.api(APIRoutes.loopsAvailable) { req in
            let filter = try OrganizationRoutes.businessFilter(req)
            return try req.jsonResponse(try await LoopRuntimeService(db: req.db, ctx: req.ctx).available(principal: try req.consumer, business: filter))
        }
        routes.api(APIRoutes.loopInstanceCreate) { req in
            let body: LoopInstanceCreateRequest = try req.decodeBody()
            return try req.jsonResponse(try await LoopRuntimeService(db: req.db, ctx: req.ctx).createInstance(principal: try req.consumer, request: body), status: .created)
        }
        routes.api(APIRoutes.loopInstanceGet) { req in
            let id: LoopInstanceID = try req.uuidParameter("instanceId")
            return try req.jsonResponse(try await LoopRuntimeService(db: req.db, ctx: req.ctx).getInstance(principal: try req.consumer, id: id.uuid))
        }
        routes.api(APIRoutes.loopInstanceAction) { req in
            let id: LoopInstanceID = try req.uuidParameter("instanceId")
            let body: LoopActionRequest = try req.decodeBody()
            let result = try await LoopRuntimeService(db: req.db, ctx: req.ctx).act(principal: try req.consumer, instanceId: id.uuid, request: body)
            return try req.jsonResponse(result, status: result.replayed ? .ok : .created)
        }
        routes.api(APIRoutes.loopInstanceReport) { req in
            let id: LoopInstanceID = try req.uuidParameter("instanceId")
            let body: LoopReportRequest = try req.decodeBody()
            try await LoopRuntimeService(db: req.db, ctx: req.ctx).report(principal: try req.consumer, instanceId: id.uuid, reason: body.reason)
            return try req.emptyOK()
        }
        routes.api(APIRoutes.loopKeys) { req in
            _ = try req.consumer
            return try req.jsonResponse(try LoopPublicationService(db: req.db, ctx: req.ctx).keySet())
        }
    }
}
