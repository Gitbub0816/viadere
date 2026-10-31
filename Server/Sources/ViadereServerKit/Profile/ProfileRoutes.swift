import Fluent
import Foundation
import Vapor
import ViadereCore

extension BusinessAPIKeys.Scope {
    /// Customer profiles: request fields and read granted ones (docs/PROFILES.md). Never part of a key unless chosen; the category entitlement
    /// of every field is checked as well.
    static let profilesRead = "profiles:read"
}

/// Profile routes (`APIRoutes.profile*`, `businessProfile*`).
enum ProfileRoutes {
    static func uuid(_ req: Request, _ name: String) throws -> UUID {
        guard let raw = req.parameters.get(name), let id = UUID(uuidString: raw) else { throw APIError.notFound }
        return id
    }

    static func register(_ routes: any RoutesBuilder) {
        // MARK: Customer
        routes.api(APIRoutes.profileGet) { req in
            try req.jsonResponse(try await ProfileService(db: req.db, ctx: req.ctx).profile(consumer: try req.consumer.consumerId.uuid))
        }
        routes.api(APIRoutes.profilePut) { req in
            let body: ProfileUpdateRequest = try req.decodeBody()
            return try req.jsonResponse(try await ProfileService(db: req.db, ctx: req.ctx).update(principal: try req.consumer, body))
        }
        routes.api(APIRoutes.profileAccessGet) { req in
            try req.jsonResponse(try await ProfileService(db: req.db, ctx: req.ctx).accessView(consumer: try req.consumer.consumerId.uuid, businessId: try uuid(req, "businessId")))
        }
        routes.api(APIRoutes.profileAccessPut) { req in
            let body: ProfileAccessUpdate = try req.decodeBody()
            return try req.jsonResponse(try await ProfileService(db: req.db, ctx: req.ctx).setAccess(principal: try req.consumer, businessId: try uuid(req, "businessId"), update: body))
        }
        routes.api(APIRoutes.profileRequestsList) { req in
            let pending = req.query[String.self, at: "status"] == "pending"
            return try req.jsonResponse(try await ProfileService(db: req.db, ctx: req.ctx).requests(consumer: try req.consumer.consumerId.uuid, pendingOnly: pending))
        }
        routes.api(APIRoutes.profileRequestGet) { req in
            try req.jsonResponse(try await ProfileService(db: req.db, ctx: req.ctx).request(consumer: try req.consumer.consumerId.uuid, id: try uuid(req, "requestId")))
        }
        routes.api(APIRoutes.profileRequestAnswer) { req in
            let body: ProfileRequestAnswer = try req.decodeBody()
            return try req.jsonResponse(try await ProfileService(db: req.db, ctx: req.ctx).answer(principal: try req.consumer, id: try uuid(req, "requestId"), answer: body))
        }
        routes.api(APIRoutes.profileReceiptsList) { req in
            try req.jsonResponse(try await ProfileService(db: req.db, ctx: req.ctx).receipts(consumer: try req.consumer.consumerId.uuid))
        }
        routes.api(APIRoutes.profileVerificationBegin) { req in
            let body: ProfileVerificationBegin = try req.decodeBody()
            return try req.jsonResponse(try await ProfileVerificationService(db: req.db, ctx: req.ctx, runtime: req.verify).begin(principal: try req.consumer, body: body))
        }
        routes.api(APIRoutes.profileVerificationComplete) { req in
            let body: ProfileVerificationComplete = try req.decodeBody()
            do {
                return try req.jsonResponse(try await ProfileVerificationService(db: req.db, ctx: req.ctx, runtime: req.verify)
                    .complete(principal: try req.consumer, attemptId: try uuid(req, "attemptId"), body: body))
            } catch is DiditError {
                throw VerifyService.methodUnavailable
            }
        }
        routes.api(APIRoutes.profileVerificationRemove) { req in
            let body: ProfileVerifiedFactsRemove = try req.decodeBody()
            return try req.jsonResponse(try await ProfileVerificationService(db: req.db, ctx: req.ctx, runtime: req.verify).remove(principal: try req.consumer, facts: body.facts))
        }

        // MARK: Business
        routes.api(APIRoutes.businessProfileRequestCreate, scope: BusinessAPIKeys.Scope.profilesRead) { req in
            let body: CreateProfileRequest = try req.decodeBody()
            let key = try BusinessIdempotency.requireKey(req.idempotencyHeader)
            let (resource, created) = try await ProfileBusinessService(db: req.db, ctx: req.ctx).create(principal: try req.business, body: body, idempotencyKey: key)
            return try req.jsonResponse(resource, status: created ? .created : .ok)
        }
        routes.api(APIRoutes.businessProfileRequestGet, scope: BusinessAPIKeys.Scope.profilesRead) { req in
            try req.jsonResponse(try await ProfileBusinessService(db: req.db, ctx: req.ctx).get(principal: try req.business, id: try uuid(req, "requestId")))
        }
        routes.api(APIRoutes.businessProfileGet, scope: BusinessAPIKeys.Scope.profilesRead) { req in
            guard let raw = req.parameters.get("subjectRef"), let subject = SubjectRef(raw) else { throw APIError.notFound }
            let response = try req.jsonResponse(try await ProfileBusinessService(db: req.db, ctx: req.ctx).read(principal: try req.business, subjectRef: subject))
            response.headers.replaceOrAdd(name: .cacheControl, value: "no-store")
            return response
        }
    }
}
