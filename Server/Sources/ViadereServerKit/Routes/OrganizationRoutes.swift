import Fluent
import Foundation
import Vapor
import ViadereCore
import typealias ViadereCore.SessionID

/// The consumer Organization API (WP-1.1, WP-1.5, WP-1.6; SECURITY.md §2.96). Every handler takes the tenant from the authenticated
/// principal; a business filter is checked against the caller's own scope and answered `404` when it is not theirs.
enum OrganizationRoutes {
    static func register(_ routes: any RoutesBuilder) {
        routes.api(APIRoutes.alertsList) { req in
            let query: AlertQuery
            do { query = try AlertQuery.parse { req.query[String.self, at: $0] } } catch AlertQuery.ParseError.invalid(let field) {
                throw APIError.validation("Check the \(field) parameter.", details: [field: "invalid"])
            }
            return try req.jsonResponse(try await AlertService(db: req.db, ctx: req.ctx).list(principal: try req.consumer, query: query))
        }
        routes.api(APIRoutes.alertsSeen) { req in
            let body: AlertSeenRequest = try req.decodeBody()
            try await AlertService(db: req.db, ctx: req.ctx).markSeen(principal: try req.consumer, request: body)
            return try req.emptyOK()
        }
        routes.api(APIRoutes.benefitsList) { req in
            let principal = try req.consumer
            var filter: BenefitFilter?
            if let raw = req.query[String.self, at: "filter"] {
                guard let parsed = BenefitFilter(rawValue: raw) else { throw APIError.validation("Check the filter parameter.", details: ["filter": "invalid"]) }
                filter = parsed
            }
            let business = try businessFilter(req)
            // Benefits are the account's own (household delegation does not cover rewards): only an active own connection is a valid filter.
            if let business {
                guard try await RelationshipRecord.query(on: req.db).filter(\.$consumerId == principal.consumerId.uuid).filter(\.$businessId == business.uuid)
                    .filter(\.$status == "active").first() != nil else { throw APIError.notFound }
            }
            let overview = try await RewardsService(db: req.db, ctx: req.ctx).overview(consumer: principal.consumerId)
            let rewards = BenefitRules.sorted(overview.rewards.filter { entry in
                (business == nil || entry.business.id == business) && BenefitRules.matches(entry, filter: filter)
            })
            let accounts = overview.accounts.filter { business == nil || $0.business.id == business }
            return try req.jsonResponse(RewardsOverview(accounts: accounts, rewards: rewards))
        }
        routes.api(APIRoutes.businessesList) { req in
            try req.jsonResponse(try await PreferenceService(db: req.db, ctx: req.ctx).directory(consumer: try req.consumer.consumerId))
        }
        routes.api(APIRoutes.businessPreferencesGet) { req in
            let business: BusinessID = try req.uuidParameter("businessId")
            return try req.jsonResponse(try await PreferenceService(db: req.db, ctx: req.ctx).get(consumer: try req.consumer.consumerId, business: business))
        }
        routes.api(APIRoutes.businessPreferencesPut) { req in
            let business: BusinessID = try req.uuidParameter("businessId")
            let body: BusinessPreferencesUpdate = try req.decodeBody()
            return try req.jsonResponse(try await PreferenceService(db: req.db, ctx: req.ctx).update(principal: try req.consumer, business: business, update: body))
        }
        routes.api(APIRoutes.businessSurfaceGet) { req in
            let business: BusinessID = try req.uuidParameter("businessId")
            return try req.jsonResponse(try await SurfaceService(db: req.db, ctx: req.ctx).view(consumer: try req.consumer.consumerId, business: business))
        }
        routes.api(APIRoutes.conversationStatePut) { req in
            let session: SessionID = try req.uuidParameter("sessionId")
            let body: ConversationStateUpdate = try req.decodeBody()
            return try req.jsonResponse(try await PreferenceService(db: req.db, ctx: req.ctx).updateConversation(consumer: try req.consumer.consumerId, session: session, update: body))
        }
    }

    /// The optional `business_id` query filter: a malformed value is a validation error, never a silent All view.
    static func businessFilter(_ req: Request) throws -> BusinessID? {
        guard let raw = req.query[String.self, at: "business_id"] else { return nil }
        guard let id = UUID(uuidString: raw) else { throw APIError.validation("Check the business_id parameter.", details: ["business_id": "invalid"]) }
        return BusinessID(id)
    }
}
