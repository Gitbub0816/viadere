import Foundation
import ViadereCore

/// The Organization calls (`/v1/alerts`, `/v1/benefits`, `/v1/businesses`, conversation state; WP-1.1). Separate from `ViadereAPI` so
/// extensions and the App Clip build without it. The business filter is only ever a filter: the server checks it against this account.
public protocol OrganizationAPI: Sendable {
    func alerts(_ query: AlertQuery) async throws -> AlertPage
    func markAlertsSeen(_ alertIds: [String]) async throws
    func benefits(filter: BenefitFilter?, business: BusinessID?) async throws -> RewardsOverview
    func businesses() async throws -> [ConnectedBusiness]
    func preferences(business: BusinessID) async throws -> BusinessPreferences
    func updatePreferences(business: BusinessID, _ update: BusinessPreferencesUpdate) async throws -> BusinessPreferences
    func surface(business: BusinessID) async throws -> BusinessSurfaceView
    func conversations(business: BusinessID?, includeArchived: Bool) async throws -> [ConversationSummary]
    func updateConversation(_ id: SessionID, _ update: ConversationStateUpdate) async throws -> ConversationStateView
}

/// `OrganizationAPI` over HTTP through the app's signed `APIClient`.
public struct LiveOrganizationAPI: OrganizationAPI {
    let client: APIClient
    public init(client: APIClient) { self.client = client }

    public func alerts(_ query: AlertQuery) async throws -> AlertPage { try await client.call(APIRoutes.alertsList, query: query.queryItems) }

    public func markAlertsSeen(_ alertIds: [String]) async throws {
        _ = try await client.call(APIRoutes.alertsSeen, body: AlertSeenRequest(alertIds: alertIds))
    }

    public func benefits(filter: BenefitFilter?, business: BusinessID?) async throws -> RewardsOverview {
        var query: [(String, String)] = []
        if let filter { query.append(("filter", filter.rawValue)) }
        if let business { query.append(("business_id", business.description)) }
        return try await client.call(APIRoutes.benefitsList, query: query)
    }

    public func businesses() async throws -> [ConnectedBusiness] { try await client.call(APIRoutes.businessesList) }

    public func preferences(business: BusinessID) async throws -> BusinessPreferences {
        try await client.call(APIRoutes.businessPreferencesGet, params: ["businessId": business.description])
    }

    public func updatePreferences(business: BusinessID, _ update: BusinessPreferencesUpdate) async throws -> BusinessPreferences {
        try await client.call(APIRoutes.businessPreferencesPut, params: ["businessId": business.description], body: update)
    }

    public func surface(business: BusinessID) async throws -> BusinessSurfaceView {
        try await client.call(APIRoutes.businessSurfaceGet, params: ["businessId": business.description])
    }

    public func conversations(business: BusinessID?, includeArchived: Bool) async throws -> [ConversationSummary] {
        var query: [(String, String)] = []
        if let business { query.append(("business_id", business.description)) }
        if includeArchived { query.append(("archived", "1")) }
        return try await client.call(APIRoutes.conversationsList, query: query)
    }

    public func updateConversation(_ id: SessionID, _ update: ConversationStateUpdate) async throws -> ConversationStateView {
        try await client.call(APIRoutes.conversationStatePut, params: ["sessionId": id.description], body: update)
    }
}

extension LiveOrganizationAPI {
    /// A client that shares the app's session, device keys and certificate pinning.
    public static func make(services: ViadereServices) -> LiveOrganizationAPI {
        let transport = URLSessionTransport(configuration: services.configuration)
        let signer = DeviceRequestSigner(records: services.records, keys: services.keys, clock: services.clock)
        let executor = RequestExecutor(baseURL: services.configuration.apiBaseURL, transport: transport, signer: signer)
        let revocation = services.revocation
        return LiveOrganizationAPI(client: APIClient(executor: executor, sessions: services.sessions, onDeviceRejected: { revocation.notify() }))
    }
}
