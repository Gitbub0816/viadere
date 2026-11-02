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

    // Installable Loops (SECURITY.md §2.98 "Installed Loops").
    func directory(query: String?, category: LoopDirectoryCategory?, business: BusinessID?) async throws -> LoopDirectoryPage
    func directoryDetail(_ loop: LoopDefinitionID) async throws -> LoopDirectoryDetail
    func installedLoops() async throws -> [InstalledLoop]
    func install(_ loop: LoopDefinitionID, _ request: LoopInstallRequest) async throws -> LoopInstallResult
    func uninstall(_ loop: LoopDefinitionID) async throws -> [InstalledLoop]
    /// Allow or stop this installed Loop's own alerts in Alerts (owner decision F-4). Never subscribes to anything else from the business.
    func setLoopAlerts(_ loop: LoopDefinitionID, enabled: Bool) async throws -> InstalledLoop
}

/// Defaults for test doubles written before installable Loops: the server answers `404` (nothing installable).
extension LoopsAPI {
    public func directory(query: String?, category: LoopDirectoryCategory?, business: BusinessID?) async throws -> LoopDirectoryPage {
        LoopDirectoryPage(featured: [], entries: [], categories: [])
    }
    public func directoryDetail(_ loop: LoopDefinitionID) async throws -> LoopDirectoryDetail {
        throw APIError.server(status: 404, code: .notFound, message: "Not found.")
    }
    public func installedLoops() async throws -> [InstalledLoop] { [] }
    public func install(_ loop: LoopDefinitionID, _ request: LoopInstallRequest) async throws -> LoopInstallResult {
        throw APIError.server(status: 404, code: .notFound, message: "Not found.")
    }
    public func uninstall(_ loop: LoopDefinitionID) async throws -> [InstalledLoop] {
        throw APIError.server(status: 404, code: .notFound, message: "Not found.")
    }
    public func setLoopAlerts(_ loop: LoopDefinitionID, enabled: Bool) async throws -> InstalledLoop {
        throw APIError.server(status: 404, code: .notFound, message: "Not found.")
    }
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

    public func directory(query: String?, category: LoopDirectoryCategory?, business: BusinessID?) async throws -> LoopDirectoryPage {
        var items: [(String, String)] = []
        if let query, !query.isEmpty { items.append(("q", query)) }
        if let category { items.append(("category", category.rawValue)) }
        if let business { items.append(("business_id", business.description)) }
        return try await client.call(APIRoutes.loopDirectory, query: items)
    }

    public func directoryDetail(_ loop: LoopDefinitionID) async throws -> LoopDirectoryDetail {
        try await client.call(APIRoutes.loopDirectoryDetail, params: ["loopId": loop.description])
    }

    public func installedLoops() async throws -> [InstalledLoop] { try await client.call(APIRoutes.loopsInstalled) }

    public func install(_ loop: LoopDefinitionID, _ request: LoopInstallRequest) async throws -> LoopInstallResult {
        try await client.call(APIRoutes.loopInstall, params: ["loopId": loop.description], body: request)
    }

    public func setLoopAlerts(_ loop: LoopDefinitionID, enabled: Bool) async throws -> InstalledLoop {
        try await client.call(APIRoutes.loopInstalledAlerts, params: ["loopId": loop.description], body: LoopAlertsRequest(enabled: enabled))
    }

    public func uninstall(_ loop: LoopDefinitionID) async throws -> [InstalledLoop] {
        try await client.call(APIRoutes.loopUninstall, params: ["loopId": loop.description])
    }
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
