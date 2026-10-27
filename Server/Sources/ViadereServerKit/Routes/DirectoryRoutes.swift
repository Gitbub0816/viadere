import Fluent
import Foundation
import Vapor
import ViadereCore
import struct ViadereCore.Page
import typealias ViadereCore.SessionID

enum DirectoryRoutes {
    static func register(_ routes: any RoutesBuilder) {
        let limiter = IPRateLimitMiddleware(name: "directory") { $0.rateLimits.directory }

        routes.api(APIRoutes.directorySearch, limiter: limiter) { req in
            guard let q = req.query[String.self, at: "q"], !q.isEmpty, q.count <= 128 else {
                throw APIError.validation("A search query is required.", details: ["q": "invalid"])
            }
            let limit = req.queryInt("limit", default: 10, range: 1...20)
            let offset = req.query[String.self, at: "cursor"].flatMap { Int($0) }.map { max(0, $0) } ?? 0
            let directory = DirectoryService(db: req.db)
            let found = try await directory.search(q, limit: limit + 1, offset: offset)
            let summaries = try await directory.summaries(for: Array(found.prefix(limit)))
            return try req.jsonResponse(Page(items: summaries, nextCursor: found.count > limit ? String(offset + limit) : nil))
        }
        routes.api(APIRoutes.directoryHandle, limiter: limiter) { req in
            guard let raw = req.parameters.get("handle"), let handle = BusinessHandle(parsing: raw) else { throw APIError.notFound }
            let directory = DirectoryService(db: req.db)
            guard let business = try await directory.verified(handle: handle), let profile = try await directory.profile(for: business) else {
                throw APIError.notFound
            }
            return try req.jsonResponse(profile)
        }
        routes.api(APIRoutes.directoryCode, limiter: limiter) { req in
            guard let raw = req.parameters.get("code"), let code = BusinessCode(parsing: raw) else { throw APIError.notFound }
            let directory = DirectoryService(db: req.db)
            guard let business = try await directory.verified(code: code), let profile = try await directory.profile(for: business) else {
                throw APIError.notFound
            }
            return try req.jsonResponse(profile)
        }
        routes.api(APIRoutes.directoryResolve, limiter: limiter) { req in
            let body: DirectoryResolveRequest = try req.decodeBody()
            guard body.input.count <= 2048 else { throw APIError.validation("The input is too long.", details: ["input": "invalid"]) }
            return try req.jsonResponse(try await resolve(body.input, req: req))
        }
    }

    /// Resolution order mirrors `DirectoryInput`: connect link → @handle → code → name. All paths return
    /// verified businesses only.
    static func resolve(_ input: String, req: Request) async throws -> DirectoryResolveResponse {
        let directory = DirectoryService(db: req.db)
        switch DirectoryInput(parsing: String(input.prefix(2048))) {
        case .link(let link):
            guard let business = try await directory.verified(code: link.code), let summary = try await directory.summary(for: business) else {
                throw APIError.notFound
            }
            // A signed context is honoured only if its HMAC verifies and it has not expired; otherwise the plain code still resolves.
            let context = try? link.verifiedContext(key: req.ctx.config.connectLinkKey, now: req.ctx.now)
            return DirectoryResolveResponse(method: .link, matches: [summary], context: context)
        case .handle(let handle):
            guard let business = try await directory.verified(handle: handle), let summary = try await directory.summary(for: business) else {
                throw APIError.notFound
            }
            return DirectoryResolveResponse(method: .handle, matches: [summary])
        case .code(let code):
            guard let business = try await directory.verified(code: code), let summary = try await directory.summary(for: business) else {
                throw APIError.notFound
            }
            return DirectoryResolveResponse(method: .code, matches: [summary])
        case .name(let name):
            let found = try await directory.search(name, limit: 10)
            return DirectoryResolveResponse(method: .name, matches: try await directory.summaries(for: found))
        }
    }
}

enum RelationshipRoutes {
    static func register(_ routes: any RoutesBuilder) {
        routes.api(APIRoutes.relationshipConnect) { req in
            let body: ConnectRequest = try req.decodeBody()
            let principal = try req.consumer
            let result = try await RelationshipService(db: req.db, ctx: req.ctx).connect(consumer: principal.consumerId, request: body)
            return try req.jsonResponse(result.relationship, status: result.created ? .created : .ok)
        }
        routes.api(APIRoutes.relationshipsList) { req in
            try req.jsonResponse(try await RelationshipService(db: req.db, ctx: req.ctx).list(consumer: try req.consumer.consumerId))
        }
        routes.api(APIRoutes.relationshipDisconnect) { req in
            let id: RelationshipID = try req.uuidParameter("relationshipId")
            try await RelationshipService(db: req.db, ctx: req.ctx).disconnect(consumer: try req.consumer.consumerId, relationshipId: id)
            return try req.emptyOK()
        }
        routes.api(APIRoutes.consentsGet) { req in
            let id: RelationshipID = try req.uuidParameter("relationshipId")
            let principal = try req.consumer
            guard let relationship = try await RelationshipService(db: req.db, ctx: req.ctx).owned(id, by: principal.consumerId) else { throw APIError.notFound }
            return try req.jsonResponse(try await ConsentService(db: req.db, ctx: req.ctx).effective(relationship: relationship))
        }
        routes.api(APIRoutes.consentsUpdate) { req in
            let id: RelationshipID = try req.uuidParameter("relationshipId")
            let body: ConsentUpdateRequest = try req.decodeBody()
            let principal = try req.consumer
            let ctx = req.ctx
            guard let relationship = try await RelationshipService(db: req.db, ctx: ctx).owned(id, by: principal.consumerId), relationship.isActive else {
                throw APIError.notFound
            }
            let grants: [ConsentGrant] = try await req.db.transaction { tx in
                let service = ConsentService(db: tx, ctx: ctx)
                let applied = try await service.apply(changes: body.changes, policyVersion: body.policyVersion, relationship: relationship, source: .app)
                for change in applied {
                    try await WebhookService(db: tx, ctx: ctx).enqueue(.consentUpdated, businessId: BusinessID(relationship.businessId),
                        payload: ConsentEventPayload(relationshipId: id, subjectRef: ctx.subjects.subjectRef(businessId: BusinessID(relationship.businessId), consumerId: ConsumerID(relationship.consumerId)), purpose: change.purpose, granted: change.granted, occurredAt: ctx.now))
                    _ = try await AuditService(db: tx, ctx: ctx).record("consent.updated", principal: principal,
                        businessId: BusinessID(relationship.businessId), subjectType: "relationship", subjectId: id.description,
                        metadata: ["purpose": change.purpose.rawValue, "granted": change.granted ? "true" : "false"])
                }
                return try await service.effective(relationship: relationship)
            }
            return try req.jsonResponse(grants)
        }
    }
}

enum InteractionRoutes {
    static func register(_ routes: any RoutesBuilder) {
        routes.api(APIRoutes.interactionsList) { req in
            let principal = try req.consumer
            let page = try await InteractionService(db: req.db, ctx: req.ctx).list(
                consumer: principal.consumerId, status: req.query[String.self, at: "status"], cursor: req.query[String.self, at: "cursor"],
                limit: req.queryInt("limit", default: 20, range: 1...50))
            return try req.jsonResponse(page)
        }
        routes.api(APIRoutes.interactionGet) { req in
            let id: InteractionID = try req.uuidParameter("interactionId")
            return try req.jsonResponse(try await InteractionService(db: req.db, ctx: req.ctx).get(consumer: try req.consumer.consumerId, id: id))
        }
        routes.api(APIRoutes.interactionDecide) { req in
            let id: InteractionID = try req.uuidParameter("interactionId")
            let body: DecideInteractionRequest = try req.decodeBody()
            return try req.jsonResponse(try await InteractionService(db: req.db, ctx: req.ctx).decide(principal: try req.consumer, id: id, request: body))
        }
    }
}

enum ConversationRoutes {
    static func register(_ routes: any RoutesBuilder) {
        routes.api(APIRoutes.conversationsList) { req in
            try req.jsonResponse(try await ConversationService(db: req.db, ctx: req.ctx).summaries(consumer: try req.consumer.consumerId))
        }
        routes.api(APIRoutes.conversationStart) { req in
            let body: StartConversationRequest = try req.decodeBody()
            return try req.jsonResponse(try await ConversationService(db: req.db, ctx: req.ctx).start(consumer: try req.consumer.consumerId, businessId: body.businessId))
        }
        routes.api(APIRoutes.conversationMessages) { req in
            let id: SessionID = try req.uuidParameter("sessionId")
            return try req.jsonResponse(try await ConversationService(db: req.db, ctx: req.ctx).messages(
                consumer: try req.consumer.consumerId, sessionId: id, cursor: req.query[String.self, at: "cursor"], limit: req.queryInt("limit", default: 50, range: 1...100)))
        }
        routes.api(APIRoutes.conversationSend) { req in
            let id: SessionID = try req.uuidParameter("sessionId")
            let body: SendMessageRequest = try req.decodeBody()
            return try req.jsonResponse(try await ConversationService(db: req.db, ctx: req.ctx).send(consumer: try req.consumer.consumerId, sessionId: id, request: body), status: .created)
        }
    }
}
