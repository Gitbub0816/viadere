import Fluent
import Foundation
import Vapor
import ViadereCore

/// The key directory and its transparency log (ADR-07).
///
/// * **Publishing** is for businesses (`keydirectory:manage`, live keys): signed entries only.
/// * **Reading** is public and unauthenticated (public keys and signatures only), rate-limited by IP.
enum KeyDirectoryRoutes {
    static func register(_ routes: any RoutesBuilder) {
        let limiter = IPRateLimitMiddleware(name: "key-directory") { $0.approve.directoryReadRate }

        routes.api(APIRoutes.keyDirectorySTH, limiter: limiter) { req in
            try ApproveGate.require(req.ctx)
            return try req.jsonResponse(try await KeyLogService(db: req.db, ctx: req.ctx).currentHead())
        }
        routes.api(APIRoutes.keyDirectoryConsistency, limiter: limiter) { req in
            try ApproveGate.require(req.ctx)
            guard let first = req.query[Int.self, at: "first"], let second = req.query[Int.self, at: "second"] else {
                throw APIError.validation("first and second are required.", details: ["first": "invalid", "second": "invalid"])
            }
            return try req.jsonResponse(try await KeyLogService(db: req.db, ctx: req.ctx).consistency(first: first, second: second))
        }
        routes.api(APIRoutes.keyDirectoryBusiness, limiter: limiter) { req in
            try ApproveGate.require(req.ctx)
            guard let raw = req.parameters.get("businessId"), let id = BusinessID(raw),
                  try await DirectoryService(db: req.db).verified(id: id.uuid) != nil else { throw APIError.notFound }
            return try req.jsonResponse(try await KeyLogService(db: req.db, ctx: req.ctx).response(for: id.uuid, since: req.query[Int.self, at: "since"]))
        }
        routes.api(APIRoutes.businessKeyDirectoryPublish, scope: BusinessAPIKeys.Scope.keyDirectoryManage) { req in
            try ApproveGate.require(req.ctx)
            let body: PublishKeyEntryRequest = try req.decodeBody()
            return try req.jsonResponse(try await KeyDirectoryService(db: req.db, ctx: req.ctx).publish(principal: try req.business, request: body), status: .created)
        }
        routes.api(APIRoutes.businessKeyDirectoryEntries, scope: BusinessAPIKeys.Scope.keyDirectoryManage) { req in
            try ApproveGate.require(req.ctx)
            return try req.jsonResponse(try await KeyLogService(db: req.db, ctx: req.ctx).response(for: try req.business.businessId.uuid, since: req.query[Int.self, at: "since"]))
        }
    }
}
