import Fluent
import Foundation
import Vapor
import ViadereCore

/// Rewards, loyalty, Wallet, household and acknowledgment routes (P3). Every route comes from the shared `APIRoutes` catalog.
enum RewardRoutes {
    static func register(_ routes: any RoutesBuilder) {
        routes.api(APIRoutes.rewardsList) { req in
            try req.jsonResponse(try await RewardsService(db: req.db, ctx: req.ctx).list(consumer: try req.consumer.consumerId))
        }
        routes.api(APIRoutes.rewardsOverview) { req in
            try req.jsonResponse(try await RewardsService(db: req.db, ctx: req.ctx).overview(consumer: try req.consumer.consumerId))
        }
        routes.api(APIRoutes.loyaltyProgram) { req in
            let id: BusinessID = try req.uuidParameter("businessId")
            return try req.jsonResponse(try await RewardsService(db: req.db, ctx: req.ctx).programOverview(consumer: try req.consumer.consumerId, businessId: id))
        }
        routes.api(APIRoutes.loyaltyEnroll) { req in
            let id: BusinessID = try req.uuidParameter("businessId")
            let body: LoyaltyEnrollRequest = try req.decodeBody()
            let result = try await RewardsService(db: req.db, ctx: req.ctx).enroll(principal: try req.consumer, businessId: id, request: body)
            return try req.jsonResponse(result.account, status: result.created ? .created : .ok)
        }
        routes.api(APIRoutes.rewardClaim) { req in
            let id: RewardID = try req.uuidParameter("rewardId")
            return try req.jsonResponse(try await RewardsService(db: req.db, ctx: req.ctx).claim(principal: try req.consumer, rewardId: id))
        }
        routes.api(APIRoutes.rewardRedeem) { req in
            let id: RewardID = try req.uuidParameter("rewardId")
            // The body is optional (a till code); an empty body means none.
            let body: RedeemRewardRequest = req.bodyBytes.isEmpty ? RedeemRewardRequest() : try req.decodeBody()
            return try req.jsonResponse(try await RewardsService(db: req.db, ctx: req.ctx).redeem(principal: try req.consumer, rewardId: id, request: body), status: .created)
        }
        routes.api(APIRoutes.acknowledgments) { req in
            try req.jsonResponse(try await AcknowledgmentService(db: req.db, ctx: req.ctx).list(consumer: try req.consumer.consumerId))
        }
    }
}

enum WalletRoutes {
    static let pkpassType = HTTPMediaType(type: "application", subType: "vnd.apple.pkpass")

    static func register(_ routes: any RoutesBuilder) {
        routes.api(APIRoutes.walletPasses) { req in
            try req.jsonResponse(try await WalletService(db: req.db, ctx: req.ctx).list(consumer: try req.consumer.consumerId))
        }
        routes.api(APIRoutes.walletPassIssue) { req in
            let body: WalletPassIssueRequest = try req.decodeBody()
            return try req.jsonResponse(try await WalletService(db: req.db, ctx: req.ctx).issue(consumer: try req.consumer.consumerId, request: body), status: .created)
        }
        routes.api(APIRoutes.walletPass) { req in
            let id: WalletPassID = try req.uuidParameter("passId")
            let result = try await WalletService(db: req.db, ctx: req.ctx).download(consumer: try req.consumer.consumerId, id: id)
            return pkpass(result.data, updatedAt: result.pass.updatedAt)
        }
        registerWebService(routes)
    }

    private static func pkpass(_ data: Data, updatedAt: Date) -> Response {
        let response = Response(status: .ok, body: .init(data: data))
        response.headers.contentType = pkpassType
        response.headers.replaceOrAdd(name: .lastModified, value: httpDate(updatedAt))
        return response
    }

    /// RFC 7231 IMF-fixdate, always UTC and English.
    static func httpDate(_ date: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "GMT")
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
        return formatter.string(from: date)
    }

    static func parseHTTPDate(_ text: String) -> Date? {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(identifier: "GMT")
        formatter.dateFormat = "EEE, dd MMM yyyy HH:mm:ss 'GMT'"
        return formatter.date(from: text)
    }

    /// Apple's PassKit web service (`webServiceURL` + `/v1/...`). Authentication is the per-pass `ApplePass` token, compared in
    /// constant time; the device list and log endpoints are unauthenticated by protocol and are rate-limited per client IP.
    private static func registerWebService(_ routes: any RoutesBuilder) {
        let limiter = IPRateLimitMiddleware(name: "wallet-ws") { $0.rateLimits.walletWebServicePerIP }
        let logLimiter = IPRateLimitMiddleware(name: "wallet-log") { $0.rateLimits.walletLogPerIP }
        let v1 = routes.grouped(limiter).grouped("wallet", "v1")

        @Sendable func clientKey(_ req: Request, _ serial: String) -> String {
            ClientIP.resolve(req, trustedProxies: req.ctx.config.trustedProxyCount) + "|" + String(serial.prefix(64))
        }
        @Sendable func authorized(_ req: Request) async throws -> WalletPassRecord {
            guard let type = req.parameters.get("passTypeIdentifier"), let serial = req.parameters.get("serialNumber") else { throw APIError.notFound }
            return try await WalletService(db: req.db, ctx: req.ctx).authenticated(
                passTypeIdentifier: type, serialNumber: serial, authorization: req.headers.first(name: .authorization), clientKey: clientKey(req, serial))
        }

        struct Registration: Content { var pushToken: String }
        v1.post("devices", ":deviceLibraryIdentifier", "registrations", ":passTypeIdentifier", ":serialNumber") { req async throws -> Response in
            let pass = try await authorized(req)
            guard let device = req.parameters.get("deviceLibraryIdentifier") else { throw APIError.notFound }
            let body = try req.content.decode(Registration.self)
            let created = try await WalletService(db: req.db, ctx: req.ctx).register(pass: pass, deviceLibraryIdentifier: device, pushToken: body.pushToken)
            return Response(status: created ? .created : .ok)
        }
        v1.delete("devices", ":deviceLibraryIdentifier", "registrations", ":passTypeIdentifier", ":serialNumber") { req async throws -> Response in
            let pass = try await authorized(req)
            guard let device = req.parameters.get("deviceLibraryIdentifier") else { throw APIError.notFound }
            try await WalletService(db: req.db, ctx: req.ctx).unregister(pass: pass, deviceLibraryIdentifier: device)
            return Response(status: .ok)
        }
        struct Serials: Content {
            var serialNumbers: [String]
            var lastUpdated: String
        }
        v1.get("devices", ":deviceLibraryIdentifier", "registrations", ":passTypeIdentifier") { req async throws -> Response in
            guard let device = req.parameters.get("deviceLibraryIdentifier"), let type = req.parameters.get("passTypeIdentifier") else { throw APIError.notFound }
            guard let result = try await WalletService(db: req.db, ctx: req.ctx).updatedSerials(
                deviceLibraryIdentifier: device, passTypeIdentifier: type, since: req.query[String.self, at: "passesUpdatedSince"]) else {
                return Response(status: .noContent)
            }
            return try req.jsonResponse(Serials(serialNumbers: result.serials, lastUpdated: result.tag))
        }
        v1.get("passes", ":passTypeIdentifier", ":serialNumber") { req async throws -> Response in
            let pass = try await authorized(req)
            let updated = Date(timeIntervalSince1970: floor(pass.updatedAt.timeIntervalSince1970))
            if let since = req.headers.first(name: .ifModifiedSince).flatMap(parseHTTPDate), since >= updated {
                return Response(status: .notModified)
            }
            // A voided pass is still served (with `voided: true`) so Wallet can show it as void.
            return pkpass(try await WalletService(db: req.db, ctx: req.ctx).pkpass(for: pass), updatedAt: pass.updatedAt)
        }
        struct LogBody: Content { var logs: [String] }
        routes.grouped(logLimiter).grouped("wallet", "v1").post("log") { req async throws -> Response in
            let body = try req.content.decode(LogBody.self)
            try await WalletService(db: req.db, ctx: req.ctx).record(logs: body.logs)
            return Response(status: .ok)
        }
    }
}

enum HouseholdRoutes {
    static func register(_ routes: any RoutesBuilder) {
        routes.api(APIRoutes.household) { req in
            try req.jsonResponse(try await HouseholdService(db: req.db, ctx: req.ctx).overview(consumer: try req.consumer.consumerId))
        }
        routes.api(APIRoutes.householdInvite) { req in
            let body: DelegationInvitationRequest = try req.decodeBody()
            return try req.jsonResponse(try await HouseholdService(db: req.db, ctx: req.ctx).createInvitation(principal: try req.consumer, request: body), status: .created)
        }
        routes.api(APIRoutes.householdInvitationPreview) { req in
            let body: DelegationInvitationRedeemRequest = try req.decodeBody()
            return try req.jsonResponse(try await HouseholdService(db: req.db, ctx: req.ctx).preview(principal: try req.consumer, code: body.code))
        }
        routes.api(APIRoutes.householdInvitationAccept) { req in
            let body: DelegationInvitationRedeemRequest = try req.decodeBody()
            return try req.jsonResponse(try await HouseholdService(db: req.db, ctx: req.ctx).accept(principal: try req.consumer, code: body.code))
        }
        routes.api(APIRoutes.householdAudit) { req in
            try req.jsonResponse(try await HouseholdService(db: req.db, ctx: req.ctx).audit(consumer: try req.consumer.consumerId))
        }
        routes.api(APIRoutes.delegationsList) { req in
            let overview = try await HouseholdService(db: req.db, ctx: req.ctx).overview(consumer: try req.consumer.consumerId)
            let active = (overview.given + overview.received).filter { $0.status == .active }.map(\.grant)
            return try req.jsonResponse(active)
        }
        routes.api(APIRoutes.delegationRevoke) { req in
            let id: DelegationID = try req.uuidParameter("delegationId")
            try await HouseholdService(db: req.db, ctx: req.ctx).revoke(principal: try req.consumer, id: id)
            return try req.emptyOK()
        }
        // Granting by someone's account id would hand over access without the delegate knowing it; invitations are the only way.
        routes.api(APIRoutes.delegationCreate) { _ in
            throw APIError.gone("Direct delegation is not supported. Use household invitations.")
        }
    }
}

enum BusinessRewardRoutes {
    typealias Scope = BusinessAPIKeys.Scope

    static func register(_ routes: any RoutesBuilder) {
        routes.api(APIRoutes.businessIssueReward, scope: Scope.rewardsWrite) { req in
            var body: IssueRewardRequest = try req.decodeBody()
            let principal = try req.business
            try await SubjectResolver(db: req.db, ctx: req.ctx).resolve(relationshipId: &body.relationshipId, subjectRef: &body.subjectRef, businessId: principal.businessId)
            let result = try await RewardsService(db: req.db, ctx: req.ctx).createReward(principal: principal, request: body, headerKey: req.idempotencyHeader)
            return try req.jsonResponse(result.reward, status: result.created ? .created : .ok)
        }
        routes.api(APIRoutes.businessRewardsList, scope: Scope.rewardsWrite) { req in
            try req.jsonResponse(try await RewardsService(db: req.db, ctx: req.ctx).listRewards(principal: try req.business))
        }
        routes.api(APIRoutes.businessRewardRevoke, scope: Scope.rewardsWrite) { req in
            let id: RewardID = try req.uuidParameter("rewardId")
            return try req.jsonResponse(try await RewardsService(db: req.db, ctx: req.ctx).revokeReward(principal: try req.business, id: id))
        }
        routes.api(APIRoutes.businessLoyaltyProgramGet, scope: Scope.rewardsWrite) { req in
            try req.jsonResponse(try await RewardsService(db: req.db, ctx: req.ctx).program(principal: try req.business))
        }
        routes.api(APIRoutes.businessLoyaltyProgramPut, scope: Scope.rewardsWrite) { req in
            let body: UpsertLoyaltyProgramRequest = try req.decodeBody()
            return try req.jsonResponse(try await RewardsService(db: req.db, ctx: req.ctx).upsertProgram(principal: try req.business, request: body))
        }
        routes.api(APIRoutes.businessAdjustPoints, scope: Scope.rewardsWrite) { req in
            var body: AdjustLoyaltyPointsRequest = try req.decodeBody()
            let principal = try req.business
            try await SubjectResolver(db: req.db, ctx: req.ctx).resolve(&body, businessId: principal.businessId)
            return try req.jsonResponse(try await RewardsService(db: req.db, ctx: req.ctx).adjustPoints(principal: principal, request: body, headerKey: req.idempotencyHeader))
        }
        routes.api(APIRoutes.businessConsumeRedemption, scope: Scope.rewardsWrite) { req in
            let body: ConsumeRedemptionRequest = try req.decodeBody()
            return try req.jsonResponse(try await RewardsService(db: req.db, ctx: req.ctx).consume(principal: try req.business, request: body))
        }
    }
}
