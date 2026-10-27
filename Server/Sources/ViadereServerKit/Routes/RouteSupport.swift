import Fluent
import Foundation
import Vapor
import ViadereCore

extension RoutesBuilder {
    /// Registers a route from the shared `APIRoutes` catalog and applies the middleware its
    /// `AuthRequirement` demands, so the server cannot drift from the contract.
    func api<Req, Res>(_ endpoint: Endpoint<Req, Res>, scope: String? = nil, limiter: IPRateLimitMiddleware? = nil,
                       use handler: @escaping @Sendable (Request) async throws -> Response) {
        var group: any RoutesBuilder = self
        if let limiter { group = group.grouped(limiter) }
        switch endpoint.auth {
        case .none, .providerSignature: break
        case .bearer: group = group.grouped(BearerAuthMiddleware())
        case .deviceSignedBearer: group = group.grouped(DeviceSignedBearerMiddleware())
        case .businessAPIKey: group = group.grouped(BusinessAPIKeyMiddleware(requiredScope: scope))
        case .deviceSigned: group = group.grouped(DeviceSignedBearerMiddleware())
        }
        let method = NIOHTTP1.HTTPMethod(rawValue: endpoint.method.rawValue)
        let path = endpoint.descriptor.vaporPathComponents.map { PathComponent(stringLiteral: $0) }
        group.on(method, path, body: .collect(maxSize: nil), use: handler)
    }
}

extension Request {
    var idempotencyHeader: String? { headers.first(name: ViadereHeader.idempotencyKey) }

    func queryInt(_ name: String, default fallback: Int, range: ClosedRange<Int>) -> Int {
        guard let raw = query[String.self, at: name], let value = Int(raw) else { return fallback }
        return min(max(value, range.lowerBound), range.upperBound)
    }

    func emptyOK() throws -> Response { try jsonResponse(EmptyBody()) }
}

/// Registers every route.
enum Routes {
    static func register(_ app: Application) throws {
        let ctx = app.ctx
        _ = ctx
        let root = app.routes
        WebRoutes.register(root)
        let api = root
        AuthRoutes.register(api)
        DeviceRoutes.register(api)
        DirectoryRoutes.register(api)
        RelationshipRoutes.register(api)
        InteractionRoutes.register(api)
        ConversationRoutes.register(api)
        BusinessRoutes.register(api)
        ProviderRoutes.register(api)
        DashboardRoutes.register(app)
        OperatorRoutes.register(app)
        ConnectButtonRoutes.register(app)
        RewardRoutes.register(api)
        WalletRoutes.register(api)
        HouseholdRoutes.register(api)
        BusinessRewardRoutes.register(api)
    }
}
