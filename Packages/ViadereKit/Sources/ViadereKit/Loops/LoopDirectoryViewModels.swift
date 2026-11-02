import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

// MARK: - Installable Loops on the device (SECURITY.md §2.98 "Installed Loops")
//
// * **Reviewed data only.** Names and descriptions shown are the reviewed definition's (sanitized again here as untrusted text), always under
//   "Built by {verified name}". The permission list is derived on the device from the definition **after** the device verified the signed
//   publication manifest with its pinned keys and checked that the definition's hash and business are the ones signed.
// * **The customer chooses.** "Install only" adds the Loop without a connection; "Install and connect" also connects. Nothing is installed
//   without the global education (Loops turned on) and an explicit tap; the server checks everything again.

/// The browsable, searchable Loop directory (`GET /v1/loops/directory`).
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class LoopDirectoryViewModel {
    public private(set) var page: LoopDirectoryPage?
    public private(set) var isLoading = false
    public var errorMessage: String?
    /// The search text as typed; trimmed and capped when sent.
    public var query = ""
    public private(set) var category: LoopDirectoryCategory?

    private let api: (any LoopsAPI)?
    private let consent: @MainActor () -> LoopConsentStatus?

    public init(api: (any LoopsAPI)?, consent: @escaping @MainActor () -> LoopConsentStatus?) {
        self.api = api
        self.consent = consent
    }

    /// The platform `loops` switch is on (browsing does not need the global enablement; installing does).
    public var isAvailable: Bool { api != nil && (consent()?.available ?? true) }

    /// The query as sent: trimmed, at most `maxQueryLength` characters.
    public static let maxQueryLength = 60
    public var sentQuery: String { String(query.trimmingCharacters(in: .whitespacesAndNewlines).prefix(Self.maxQueryLength)) }

    public var isFiltering: Bool { !sentQuery.isEmpty || category != nil }
    public var featured: [LoopDirectoryEntry] { isFiltering ? [] : page?.featured ?? [] }
    /// Entries not already shown as featured (when nothing is filtered).
    public var entries: [LoopDirectoryEntry] {
        let all = page?.entries ?? []
        guard !isFiltering else { return all }
        let featuredIds = Set(featured.map(\.loopId))
        return all.filter { !featuredIds.contains($0.loopId) }
    }
    public var categories: [LoopDirectoryCategory] { page?.categories ?? [] }
    public var isEmpty: Bool { page != nil && featured.isEmpty && entries.isEmpty }

    public func load() async {
        guard let api, isAvailable else {
            page = LoopDirectoryPage(featured: [], entries: [], categories: [])
            return
        }
        isLoading = true
        defer { isLoading = false }
        errorMessage = nil
        do {
            page = try await api.directory(query: sentQuery.isEmpty ? nil : sentQuery, category: category, business: nil)
        } catch {
            errorMessage = (error as? APIError)?.userMessage ?? "Couldn't load Loops."
        }
    }

    /// Selects a category (or all with `nil`) and reloads.
    public func select(_ category: LoopDirectoryCategory?) async {
        self.category = category
        await load()
    }

    public func clear() {
        page = nil
        query = ""
        category = nil
        errorMessage = nil
    }

    /// The reviewed title as untrusted text (shown under the verified attribution, never instead of it).
    public static func title(_ entry: LoopDirectoryEntry) -> String { UntrustedText.line(entry.title, max: LoopLimits.titleLength) }
    public static func summary(_ entry: LoopDirectoryEntry) -> String? {
        entry.summary.map { UntrustedText.line($0, max: LoopLimits.descriptionLength) }.flatMap { $0.isEmpty ? nil : $0 }
    }
    public static func attribution(_ business: BusinessSummary) -> String { "Built by \(business.safeName)" }
}

/// One Loop's page and install sheet: verified details, the permission list, the install choice, install and uninstall.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class LoopDetailViewModel {
    public enum Status: Sendable, Equatable {
        case loading
        case ready
        /// Not found, not in the rollout, paused, or it failed verification: one neutral message (no oracle, no business content).
        case unavailable
        case failed(String)
    }

    public enum InstallOutcome: Sendable, Equatable {
        case installed(InstalledLoop)
        /// Loops are not turned on yet: run the education first, then install again.
        case needsGlobalConsent
        case failed(String)
    }

    public let loopId: LoopDefinitionID
    public let source: LoopInstallSource
    public private(set) var status: Status = .loading
    public private(set) var entry: LoopDirectoryEntry?
    /// Set only after the manifest verified and the definition matched it.
    public private(set) var definition: LoopDefinition?
    public var mode: LoopInstallMode = .installOnly
    public private(set) var isSubmitting = false
    public var errorMessage: String?

    private let api: (any LoopsAPI)?
    private let keys: @Sendable () -> [PinnedManifestKey]
    private let consent: @MainActor () -> LoopConsentStatus?
    private let clock: @Sendable () -> Date
    private let library: LoopLibraryViewModel?
    private let onConsent: @MainActor (LoopConsentStatus) -> Void

    public init(loopId: LoopDefinitionID, source: LoopInstallSource, api: (any LoopsAPI)?, keys: @escaping @Sendable () -> [PinnedManifestKey],
                consent: @escaping @MainActor () -> LoopConsentStatus?, library: LoopLibraryViewModel? = nil,
                onConsent: @escaping @MainActor (LoopConsentStatus) -> Void = { _ in }, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.loopId = loopId
        self.source = source
        self.api = api
        self.keys = keys
        self.consent = consent
        self.library = library
        self.onConsent = onConsent
        self.clock = clock
    }

    public func load() async {
        guard let api else {
            status = .unavailable
            return
        }
        status = .loading
        do {
            let detail = try await api.directoryDetail(loopId)
            guard detail.entry.loopId == loopId, let definition = Self.verified(detail, keys: keys(), now: clock()) else {
                entry = nil
                self.definition = nil
                status = .unavailable
                return
            }
            entry = detail.entry
            self.definition = definition
            if detail.entry.connected { mode = .installOnly }
            status = .ready
        } catch let error as APIError {
            if case .server(404, _, _) = error { status = .unavailable } else { status = .failed(error.userMessage) }
        } catch {
            status = .failed("Couldn't load this Loop.")
        }
    }

    /// The definition, only if the signed manifest verifies with the pinned keys, is inside its validity window, names this business, and
    /// signs exactly this definition's hash; and the business is verified.
    public static func verified(_ detail: LoopDirectoryDetail, keys: [PinnedManifestKey], now: Date) -> LoopDefinition? {
        guard detail.entry.business.isVerified,
              let manifest = try? LoopPublicationManifest.verify(detail.manifest, keys: keys, now: now),
              manifest.publisherType == .business, manifest.publisherBusinessId == detail.entry.business.id,
              manifest.publishedDefinitionId == detail.entry.publicationId,
              let definition = LoopDefinition.parse(detail.definition).definition,
              let hash = try? definition.definitionHash(), hash == manifest.definitionHash else { return nil }
        return definition
    }

    public var isInstalled: Bool { library?.isInstalled(loopId) ?? entry?.installed ?? false }
    public var isConnected: Bool { entry?.connected ?? false }
    /// "Install and connect" is offered only when the customer is not already connected.
    public var offersConnect: Bool { !isConnected }

    /// The permission list for the current choice (connected now, or chosen to connect).
    public var permissions: [LoopPermissionItem] {
        guard let definition, let entry else { return [] }
        return LoopPermissions.derive(definition, business: entry.business.safeName, connected: isConnected || mode == .installAndConnect)
    }

    public var title: String { entry.map(LoopDirectoryViewModel.title) ?? "" }
    public var summary: String? { entry.flatMap(LoopDirectoryViewModel.summary) }

    /// Viadere's per-business authorization sentence with the verified name (the install records that authorization).
    public var authorizationSentence: String? {
        guard let text = consent()?.text, let entry else { return nil }
        return LoopConsentGate.businessAuthorizationText(text, business: entry.business)
    }

    public var needsGlobalConsent: Bool {
        guard let status = consent() else { return true }
        return LoopConsentGate.decision(status: status, business: entry?.business.id ?? BusinessID()) == .needsGlobalConsent
    }

    public var canInstall: Bool {
        status == .ready && definition != nil && !isSubmitting && (consent()?.available ?? false) && authorizationSentence != nil
    }

    /// Installs with the chosen mode. Refused locally without the global enablement (the server refuses too).
    public func install() async -> InstallOutcome {
        guard let api, canInstall, let text = consent()?.text else { return .failed("This isn't available right now.") }
        guard !needsGlobalConsent else { return .needsGlobalConsent }
        isSubmitting = true
        defer { isSubmitting = false }
        errorMessage = nil
        do {
            let result = try await api.install(loopId, LoopInstallRequest(mode: offersConnect ? mode : .installOnly, source: source,
                                                                          textVersion: text.version, textDigest: text.digest, agree: true))
            onConsent(result.consent)
            library?.adopt(result.installed)
            if var entry {
                entry.installed = true
                entry.connected = result.installed.connected
                self.entry = entry
            }
            return .installed(result.installed)
        } catch let error as APIError {
            if case .server(409, _, _) = error, needsGlobalConsent { return .needsGlobalConsent }
            let message = error.userMessage
            errorMessage = message
            return .failed(message)
        } catch {
            errorMessage = "Couldn't add this Loop."
            return .failed("Couldn't add this Loop.")
        }
    }

    public func uninstall() async -> Bool {
        guard let library else { return false }
        let ok = await library.uninstall(loopId)
        if ok, var entry {
            entry.installed = false
            self.entry = entry
        }
        return ok
    }
}

/// Your Loops (`GET /v1/loops/installed`): the installed Loops, starting and resuming them, and removing them. Also the verified business
/// records of install-only businesses for the renderer (`AppModel.loopRenderContext`).
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class LoopLibraryViewModel {
    public private(set) var loops: [InstalledLoop] = []
    public private(set) var isLoading = false
    public private(set) var hasLoaded = false
    public var errorMessage: String?

    private let api: (any LoopsAPI)?
    private let consent: @MainActor () -> LoopConsentStatus?

    public init(api: (any LoopsAPI)?, consent: @escaping @MainActor () -> LoopConsentStatus?) {
        self.api = api
        self.consent = consent
    }

    public func load() async {
        guard let api else { return }
        isLoading = true
        defer { isLoading = false }
        do {
            loops = try await api.installedLoops()
            hasLoaded = true
            errorMessage = nil
        } catch {
            errorMessage = (error as? APIError)?.userMessage ?? "Couldn't load your Loops."
        }
    }

    public func isInstalled(_ loop: LoopDefinitionID) -> Bool { loops.contains { $0.loopId == loop } }

    /// Records a just-installed Loop (from the install sheet) without a round trip.
    public func adopt(_ installed: InstalledLoop) {
        loops.removeAll { $0.loopId == installed.loopId }
        loops.append(installed)
        loops.sort { ($0.title, $0.loopId.description) < ($1.title, $1.loopId.description) }
    }

    /// Removes the Loop (the server cancels its open requests). Returns whether it was removed.
    @discardableResult
    public func uninstall(_ loop: LoopDefinitionID) async -> Bool {
        guard let api else { return false }
        do {
            loops = try await api.uninstall(loop)
            errorMessage = nil
            return true
        } catch let error as APIError {
            if case .server(404, _, _) = error {
                loops.removeAll { $0.loopId == loop }
                return true
            }
            errorMessage = error.userMessage
            return false
        } catch {
            errorMessage = "Couldn't remove this Loop."
            return false
        }
    }

    /// Starts an installed Loop (entry point `business_page`) with both consents current on the device; the server checks again.
    public func start(_ loop: InstalledLoop) async -> LoopCatalogViewModel.StartResult {
        guard let api, let publication = loop.publicationId, loop.entryPoints.contains(.businessPage) else { return .failed("This Loop is paused right now.") }
        let decision = LoopConsentGate.decision(status: consent(), business: loop.business.id)
        guard decision == .allowed else { return .needsConsent(decision) }
        do {
            return .started(try await api.startInstance(LoopInstanceCreateRequest(publicationId: publication, entryPoint: .businessPage)))
        } catch let error as APIError {
            if case .server(403, _, _) = error { return .needsConsent(.needsBusinessAuthorization) }
            return .failed(error.userMessage)
        } catch {
            return .failed("Couldn't start this.")
        }
    }

    /// The verified directory record of a business the customer has a Loop of (from the server's directory record, like the connected list).
    public func publisherRecord(for business: BusinessID) -> VerifiedBusinessRecord? {
        guard let loop = loops.first(where: { $0.business.id == business }), loop.business.isVerified else { return nil }
        return VerifiedBusinessRecord(id: loop.business.id, displayName: loop.business.displayName, verificationStatus: loop.business.verificationStatus,
                                      category: loop.businessCategory)
    }

    /// Records for every installed business, captured for a render context.
    public var publisherRecords: [BusinessID: VerifiedBusinessRecord] {
        var out: [BusinessID: VerifiedBusinessRecord] = [:]
        for loop in loops where out[loop.business.id] == nil {
            if let record = publisherRecord(for: loop.business.id) { out[loop.business.id] = record }
        }
        return out
    }

    public func clear() {
        loops = []
        hasLoaded = false
        errorMessage = nil
    }

    public static func title(_ loop: InstalledLoop) -> String { UntrustedText.line(loop.title, max: LoopLimits.titleLength) }

    /// "Added · not connected" style subtitle.
    public static func subtitle(_ loop: InstalledLoop) -> String {
        let attribution = "Built by \(loop.business.safeName)"
        if loop.publicationId == nil { return "\(attribution) · Paused" }
        if !loop.openInstances.isEmpty { return "\(attribution) · \(loop.openInstances.count == 1 ? "1 open request" : "\(loop.openInstances.count) open requests")" }
        return loop.connected ? attribution : "\(attribution) · Not connected"
    }
}
