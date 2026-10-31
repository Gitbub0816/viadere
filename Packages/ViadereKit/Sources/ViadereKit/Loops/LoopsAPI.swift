import Foundation
import ViadereCore

/// The consumer Loop calls (`APIRoutes.loopEndpoints`; WP-3.3, WP-3.5; SECURITY.md §2.98). Every route is device-signed; the tenant is
/// always the signed-in account, and an instance or business id is only a lookup handle the server checks.
public protocol LoopsAPI: Sendable {
    func consentStatus() async throws -> LoopConsentStatus
    func enableLoops(_ request: LoopGlobalConsentRequest) async throws -> LoopConsentStatus
    func disableLoops() async throws -> LoopConsentStatus
    func authorizeBusiness(_ business: BusinessID, _ request: LoopBusinessConsentRequest) async throws -> LoopConsentStatus
    func revokeBusiness(_ business: BusinessID) async throws -> LoopConsentStatus
    func availableLoops(business: BusinessID?) async throws -> [LoopSummary]
    func startInstance(_ request: LoopInstanceCreateRequest) async throws -> LoopInstanceView
    func instance(_ id: LoopInstanceID) async throws -> LoopInstanceView
    func submitAction(_ id: LoopInstanceID, _ request: LoopActionRequest) async throws -> LoopActionResult
    func report(_ id: LoopInstanceID, _ request: LoopReportRequest) async throws
    func publicationKeys() async throws -> LoopPublicationKeySet
}

/// `LoopsAPI` over HTTP through the app's signed `APIClient`.
public struct LiveLoopsAPI: LoopsAPI {
    let client: APIClient
    public init(client: APIClient) { self.client = client }

    public func consentStatus() async throws -> LoopConsentStatus { try await client.call(APIRoutes.loopConsentGet) }

    public func enableLoops(_ request: LoopGlobalConsentRequest) async throws -> LoopConsentStatus {
        try await client.call(APIRoutes.loopConsentPut, body: request)
    }

    public func disableLoops() async throws -> LoopConsentStatus { try await client.call(APIRoutes.loopConsentDelete) }

    public func authorizeBusiness(_ business: BusinessID, _ request: LoopBusinessConsentRequest) async throws -> LoopConsentStatus {
        try await client.call(APIRoutes.loopBusinessConsentPut, params: ["businessId": business.description], body: request)
    }

    public func revokeBusiness(_ business: BusinessID) async throws -> LoopConsentStatus {
        try await client.call(APIRoutes.loopBusinessConsentDelete, params: ["businessId": business.description])
    }

    public func availableLoops(business: BusinessID?) async throws -> [LoopSummary] {
        try await client.call(APIRoutes.loopsAvailable, query: business.map { [("business_id", $0.description)] } ?? [])
    }

    public func startInstance(_ request: LoopInstanceCreateRequest) async throws -> LoopInstanceView {
        try await client.call(APIRoutes.loopInstanceCreate, body: request)
    }

    public func instance(_ id: LoopInstanceID) async throws -> LoopInstanceView {
        try await client.call(APIRoutes.loopInstanceGet, params: ["instanceId": id.description])
    }

    public func submitAction(_ id: LoopInstanceID, _ request: LoopActionRequest) async throws -> LoopActionResult {
        try await client.call(APIRoutes.loopInstanceAction, params: ["instanceId": id.description], body: request)
    }

    public func report(_ id: LoopInstanceID, _ request: LoopReportRequest) async throws {
        _ = try await client.call(APIRoutes.loopInstanceReport, params: ["instanceId": id.description], body: request)
    }

    public func publicationKeys() async throws -> LoopPublicationKeySet { try await client.call(APIRoutes.loopKeys) }
}

/// The verified publication keys the renderer uses: the build pins, narrowed by the server's current list once fetched
/// (`ManifestKeyPins.effectiveLoopKeys`). A fetch failure keeps the build pins; nothing fetched can add a key.
public final class LoopKeyRing: @unchecked Sendable {
    private let pinned: [PinnedManifestKey]
    private let api: (any LoopsAPI)?
    private let lock = NSLock()
    private var served: LoopPublicationKeySet?

    public init(pinned: [PinnedManifestKey], api: (any LoopsAPI)?) {
        self.pinned = pinned
        self.api = api
    }

    public var keys: [PinnedManifestKey] { lock.withLock { ManifestKeyPins.effectiveLoopKeys(pinned: pinned, served: served) } }

    public func refresh() async {
        guard let api, let set = try? await api.publicationKeys() else { return }
        lock.withLock { served = set }
    }
}
