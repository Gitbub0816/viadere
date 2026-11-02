import Crypto
import Foundation
import ViadereCore

/// An in-memory Loop server for previews, the demo world and tests, with the server's consent and step rules (SECURITY.md §2.98): no
/// instance is created, shown or acted on without a current global grant **and** a current authorization of that business (`403`); a
/// wrong comprehension answer, a stale text or `agree != true` is `422`; an idempotency key replays its stored result.
public actor MockLoopsAPI: LoopsAPI {
    /// The software `loop-publication` key of the mock world (never a real key).
    public static let signingKey = try! SoftwareP256SigningKey(rawRepresentation: Data(SHA256.hash(data: Data("viadere-mock-loop-publication".utf8))))
    public static var kid: String { (try? KeyIdentifier.make(p256X963: signingKey.publicKey.x963)) ?? "mock-loop-publication" }
    public static var pinnedKey: PinnedManifestKey { PinnedManifestKey(kid: kid, publicKey: signingKey.publicKey) }

    struct Publication {
        var summary: LoopSummary
        var definition: LoopDefinition
        var loopId: LoopDefinitionID
        var category: LoopDirectoryCategory?
        var listed: Bool
        var featured: Bool
    }

    struct Install {
        var mode: LoopInstallMode
        var source: LoopInstallSource
        var at: Date
    }

    struct Instance {
        var view: LoopInstanceView
        var definition: LoopDefinition
        var replies: [String: LoopActionResult] = [:]
        /// The request digest each idempotency key was first used with.
        var digests: [String: String] = [:]
    }

    private let clock: @Sendable () -> Date
    private var available = true
    private var global: LoopConsentGrantView?
    private var businessGrants: [BusinessID: LoopConsentGrantView] = [:]
    private var publications: [Publication] = []
    private var instances: [LoopInstanceID: Instance] = [:]
    private var connected: Set<BusinessID>
    private var installs: [LoopDefinitionID: Install] = [:]
    private let businesses: [BusinessID: BusinessSummary]
    public private(set) var installCalls = 0
    public private(set) var reports: [(LoopInstanceID, LoopReportReason)] = []
    public private(set) var actionCalls = 0
    public private(set) var startCalls = 0
    private var text: LoopConsentTextVersion

    public init(connected: [BusinessID] = PreviewData.allBusinesses.map(\.id), text: LoopConsentTextVersion = LoopConsentCatalog.current,
                businesses: [BusinessSummary] = PreviewData.allBusinesses, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.connected = Set(connected)
        self.businesses = Dictionary(businesses.map { ($0.id, $0) }, uniquingKeysWith: { a, _ in a })
        self.text = text
        self.clock = clock
    }

    // MARK: Test hooks

    public func setAvailable(_ value: Bool) { available = value }
    public func bumpTextVersion(_ next: LoopConsentTextVersion) { text = next }
    public func setConnected(_ businesses: [BusinessID]) { connected = Set(businesses) }

    /// Publishes `definition` for `business` (signed with the mock key) and returns its summary.
    /// `category` lists it in the directory (the operator listing on the real server).
    @discardableResult
    public func publish(_ definition: LoopDefinition, business: BusinessID, revision: Int64 = 1, category: LoopDirectoryCategory? = nil,
                        featured: Bool = false) -> LoopSummary {
        let loopId = LoopDefinitionID()
        let summary = LoopSummary(publicationId: LoopPublicationID(), businessId: business, revision: revision, title: definition.title,
                                  entryPoints: definition.entryPoints, authorized: false, loopId: loopId, installed: false)
        publications.append(Publication(summary: summary, definition: definition, loopId: loopId, category: category, listed: category != nil,
                                        featured: category != nil && featured))
        return summary
    }

    public func isInstalled(_ loop: LoopDefinitionID) -> Bool { installs[loop] != nil }

    private func installedBusinesses() -> Set<BusinessID> {
        Set(publications.filter { installs[$0.loopId] != nil }.map(\.summary.businessId))
    }

    /// Like the server: a connection opens every Loop of the business, an install only that Loop.
    private func mayStart(_ p: Publication) -> Bool { connected.contains(p.summary.businessId) || installs[p.loopId] != nil }

    /// Records an outcome for the latest delivering event of `instance` (the hosted inbox's accept/reject, or the timeout job).
    public func setOutcome(_ outcome: LoopActionOutcome, instance id: LoopInstanceID) {
        guard var instance = instances[id], let index = instance.view.events.lastIndex(where: { $0.outcome != nil }) else { return }
        instance.view.events[index].outcome = outcome
        instance.view.events[index].outcomeAt = clock()
        if outcome.isFinal { instance.view.state = .completed }
        instances[id] = instance
    }

    // MARK: Consent

    private func statusValue() -> LoopConsentStatus {
        let consentText = LoopConsentText(text)
        func current(_ g: LoopConsentGrantView) -> LoopConsentGrantView {
            var g = g
            g.current = g.textVersion == text.version && g.textDigest == text.digest
            return g
        }
        let g = global.map(current)
        return LoopConsentStatus(available: available, enabled: g?.current ?? false, text: consentText, global: g,
                                 businesses: businessGrants.values.map(current).sorted { $0.grantedAt < $1.grantedAt })
    }

    public func consentStatus() async throws -> LoopConsentStatus { statusValue() }

    public func enableLoops(_ request: LoopGlobalConsentRequest) async throws -> LoopConsentStatus {
        let allCorrect = text.checks.allSatisfy { request.answers[$0.id] == $0.correctOptionId } && request.answers.count == text.checks.count
        guard request.agree, request.textVersion == text.version, request.textDigest == text.digest, allCorrect else {
            throw APIError.server(status: 422, code: .validationFailed, message: "Consent refused.")
        }
        global = LoopConsentGrantView(businessId: nil, textVersion: text.version, textDigest: text.digest, grantedAt: clock(), current: true)
        return statusValue()
    }

    public func disableLoops() async throws -> LoopConsentStatus {
        global = nil
        businessGrants = [:]
        cancelInstances { _ in true }
        return statusValue()
    }

    public func authorizeBusiness(_ business: BusinessID, _ request: LoopBusinessConsentRequest) async throws -> LoopConsentStatus {
        guard connected.contains(business) || installedBusinesses().contains(business) else {
            throw APIError.server(status: 404, code: .notFound, message: "Not found.")
        }
        guard let g = statusValue().global, g.current else { throw APIError.server(status: 409, code: .conflict, message: "Turn on Loops first.") }
        guard request.agree, request.textVersion == text.version, request.textDigest == text.digest else {
            throw APIError.server(status: 422, code: .validationFailed, message: "Consent refused.")
        }
        businessGrants[business] = LoopConsentGrantView(businessId: business, textVersion: text.version, textDigest: text.digest, grantedAt: clock(), current: true)
        return statusValue()
    }

    public func revokeBusiness(_ business: BusinessID) async throws -> LoopConsentStatus {
        businessGrants[business] = nil
        cancelInstances { $0 == business }
        return statusValue()
    }

    private func cancelInstances(_ matching: (BusinessID) -> Bool) {
        for (id, var instance) in instances where matching(instance.view.businessId) && instance.view.state.isOpen {
            instance.view.state = .cancelled
            instances[id] = instance
        }
    }

    private func requireConsent(_ business: BusinessID) throws {
        guard available else { throw APIError.server(status: 409, code: .conflict, message: "Paused.") }
        guard LoopConsentGate.decision(status: statusValue(), business: business) == .allowed else {
            throw APIError.server(status: 403, code: .consentRequired, message: "Consent required.")
        }
    }

    // MARK: Loops

    public func availableLoops(business: BusinessID?) async throws -> [LoopSummary] {
        guard available, statusValue().enabled else { return [] }
        if let business, !connected.contains(business), !installedBusinesses().contains(business) {
            throw APIError.server(status: 404, code: .notFound, message: "Not found.")
        }
        return publications.filter { (business == nil || $0.summary.businessId == business) && mayStart($0) }.map { p in
            var s = p.summary
            s.authorized = LoopConsentGate.decision(status: statusValue(), business: s.businessId) == .allowed
            s.installed = installs[p.loopId] != nil
            return s
        }
    }

    public func startInstance(_ request: LoopInstanceCreateRequest) async throws -> LoopInstanceView {
        startCalls += 1
        guard let publication = publications.first(where: { $0.summary.publicationId == request.publicationId }),
              mayStart(publication) else { throw APIError.server(status: 404, code: .notFound, message: "Not found.") }
        try requireConsent(publication.summary.businessId)
        guard publication.definition.entryPoints.contains(request.entryPoint) else {
            throw APIError.server(status: 422, code: .validationFailed, message: "Entry point.")
        }
        let now = clock()
        let manifest = try await Self.manifest(for: publication.definition, publication: publication.summary.publicationId,
                                               business: publication.summary.businessId, revision: publication.summary.revision, now: now)
        let view = LoopInstanceView(id: LoopInstanceID(), businessId: publication.summary.businessId, publicationId: publication.summary.publicationId,
                                    revision: publication.summary.revision, state: .active, currentStepId: publication.definition.steps[0].id,
                                    entryPoint: request.entryPoint, expiresAt: now.addingTimeInterval(TimeInterval(publication.definition.limits.expiresInSeconds)),
                                    createdAt: now, updatedAt: now, publicationStatus: .active, paused: false, manifest: manifest,
                                    definition: publication.definition.jsonValue, events: [])
        instances[view.id] = Instance(view: view, definition: publication.definition)
        return view
    }

    public func instance(_ id: LoopInstanceID) async throws -> LoopInstanceView {
        guard let instance = instances[id] else { throw APIError.server(status: 404, code: .notFound, message: "Not found.") }
        if instance.view.state.isOpen { try requireConsent(instance.view.businessId) }
        return instance.view
    }

    public func submitAction(_ id: LoopInstanceID, _ request: LoopActionRequest) async throws -> LoopActionResult {
        actionCalls += 1
        guard var instance = instances[id] else { throw APIError.server(status: 404, code: .notFound, message: "Not found.") }
        try requireConsent(instance.view.businessId)
        let digest = try LoopActionSubmission(instanceId: id, stepId: request.stepId, actionId: request.actionId, inputs: request.inputs,
                                              idempotencyKey: request.idempotencyKey).requestDigest()
        if let stored = instance.replies[request.idempotencyKey] {
            guard instance.digests[request.idempotencyKey] == digest else {
                throw APIError.server(status: 409, code: .idempotencyConflict, message: "Conflict.")
            }
            var replay = stored
            replay.replayed = true
            replay.instance = instance.view
            return replay
        }
        guard instance.view.state == .active else { throw APIError.server(status: 410, code: .gone, message: "Ended.") }
        guard request.stepId == instance.view.currentStepId, let step = instance.definition.step(request.stepId),
              let binding = step.actions.first(where: { $0.id == request.actionId }) else {
            throw APIError.server(status: 409, code: .conflict, message: "Step.")
        }
        guard LoopInputValidator.issues(request.inputs, step: step).isEmpty else {
            throw APIError.server(status: 422, code: .validationFailed, message: "Inputs.")
        }
        let now = clock()
        let event = LoopActionEventView(id: LoopActionEventID(), stepId: step.id, actionId: binding.id, actionType: binding.action,
                                        outcome: binding.routing != nil ? .pending : nil, outcomeAt: nil, createdAt: now)
        instance.view.events.append(event)
        if let next = binding.next { instance.view.currentStepId = next }
        if let nextStep = instance.definition.step(instance.view.currentStepId), nextStep.type == .result || nextStep.type == .handoff {
            instance.view.state = instance.view.events.contains { $0.outcome != nil } ? .submitted : .completed
        }
        instance.view.updatedAt = now
        let result = LoopActionResult(event: event, instance: instance.view, replayed: false)
        instance.replies[request.idempotencyKey] = result
        instance.digests[request.idempotencyKey] = digest
        instances[id] = instance
        return result
    }

    public func report(_ id: LoopInstanceID, _ request: LoopReportRequest) async throws {
        guard instances[id] != nil else { throw APIError.server(status: 404, code: .notFound, message: "Not found.") }
        reports.append((id, request.reason))
    }

    public func publicationKeys() async throws -> LoopPublicationKeySet {
        LoopPublicationKeySet(keys: [.init(kid: Self.kid, publicKey: Base64URL.encode(Self.signingKey.publicKey.x963))])
    }

    // MARK: Directory and installs

    private func entry(_ p: Publication) -> LoopDirectoryEntry? {
        guard let business = businesses[p.summary.businessId] else { return nil }
        let kit: String? = if case .brandKit(let key) = p.definition.appearance { key } else { nil }
        return LoopDirectoryEntry(loopId: p.loopId, publicationId: p.summary.publicationId, revision: p.summary.revision, business: business,
                                  businessCategory: .retail, title: p.definition.title, summary: p.definition.description, category: p.category,
                                  featured: p.featured, entryPoints: p.definition.entryPoints, installed: installs[p.loopId] != nil,
                                  connected: connected.contains(p.summary.businessId), brandKitId: kit)
    }

    public func directory(query: String?, category: LoopDirectoryCategory?, business: BusinessID?) async throws -> LoopDirectoryPage {
        guard available else { return LoopDirectoryPage(featured: [], entries: [], categories: []) }
        let q = (query ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        let pool = publications.filter { business == nil ? $0.listed : $0.summary.businessId == business }
        let categories = LoopDirectoryCategory.known.filter { c in pool.contains { $0.listed && $0.category == c } }
        let entries = pool.filter { p in
            let text = "\(p.definition.title) \(p.definition.description ?? "") \(businesses[p.summary.businessId]?.displayName ?? "")".lowercased()
            return (category == nil || p.category == category) && (q.isEmpty || text.contains(q))
        }.compactMap(entry).sorted { $0.title < $1.title }
        let featured = q.isEmpty && category == nil && business == nil ? entries.filter(\.featured) : []
        return LoopDirectoryPage(featured: featured, entries: entries, categories: categories)
    }

    public func directoryDetail(_ loop: LoopDefinitionID) async throws -> LoopDirectoryDetail {
        guard available, let p = publications.first(where: { $0.loopId == loop }), let entry = entry(p) else {
            throw APIError.server(status: 404, code: .notFound, message: "Not found.")
        }
        let manifest = try await Self.manifest(for: p.definition, publication: p.summary.publicationId, business: p.summary.businessId,
                                               revision: p.summary.revision, now: clock())
        return LoopDirectoryDetail(entry: entry, manifest: manifest, definition: p.definition.jsonValue)
    }

    private func installedList() -> [InstalledLoop] {
        publications.compactMap { p -> InstalledLoop? in
            guard let install = installs[p.loopId], let business = businesses[p.summary.businessId] else { return nil }
            let open = instances.values.filter { $0.view.publicationId == p.summary.publicationId && $0.view.state.isOpen }
                .sorted { $0.view.createdAt > $1.view.createdAt }.map(\.view.id)
            return InstalledLoop(loopId: p.loopId, business: business, businessCategory: .retail, title: p.definition.title, mode: install.mode,
                                 source: install.source, installedAt: install.at, connected: connected.contains(p.summary.businessId),
                                 publicationId: available ? p.summary.publicationId : nil, entryPoints: p.definition.entryPoints, openInstances: open,
                                 brandKitId: nil)
        }.sorted { $0.title < $1.title }
    }

    public func installedLoops() async throws -> [InstalledLoop] { installedList() }

    public func install(_ loop: LoopDefinitionID, _ request: LoopInstallRequest) async throws -> LoopInstallResult {
        installCalls += 1
        guard available, let p = publications.first(where: { $0.loopId == loop }) else { throw APIError.server(status: 404, code: .notFound, message: "Not found.") }
        guard request.agree, request.textVersion == text.version, request.textDigest == text.digest else {
            throw APIError.server(status: 422, code: .validationFailed, message: "Consent refused.")
        }
        guard let g = statusValue().global, g.current else { throw APIError.server(status: 409, code: .conflict, message: "Turn on Loops first.") }
        if request.mode == .installAndConnect { connected.insert(p.summary.businessId) }
        installs[loop] = Install(mode: request.mode, source: request.source, at: installs[loop]?.at ?? clock())
        if businessGrants[p.summary.businessId]?.current != true {
            businessGrants[p.summary.businessId] = LoopConsentGrantView(businessId: p.summary.businessId, textVersion: text.version, textDigest: text.digest,
                                                                       grantedAt: clock(), current: true)
        }
        guard let view = installedList().first(where: { $0.loopId == loop }) else { throw APIError.server(status: 404, code: .notFound, message: "Not found.") }
        return LoopInstallResult(installed: view, consent: statusValue())
    }

    public func uninstall(_ loop: LoopDefinitionID) async throws -> [InstalledLoop] {
        guard installs[loop] != nil, let p = publications.first(where: { $0.loopId == loop }) else {
            throw APIError.server(status: 404, code: .notFound, message: "Not found.")
        }
        installs[loop] = nil
        for (id, var instance) in instances where instance.view.publicationId == p.summary.publicationId && instance.view.state.isOpen {
            instance.view.state = .cancelled
            instances[id] = instance
        }
        let business = p.summary.businessId
        if !connected.contains(business), !installedBusinesses().contains(business) { businessGrants[business] = nil }
        return installedList()
    }

    static func manifest(for definition: LoopDefinition, publication: LoopPublicationID, business: BusinessID, revision: Int64, now: Date) async throws -> String {
        let from = Int64(now.timeIntervalSince1970) - 60
        return try await LoopPublicationManifest(publisherType: .business, publisherBusinessId: business, publishedDefinitionId: publication,
                                                 revision: revision, definitionHash: try definition.definitionHash(), validFrom: from,
                                                 notAfter: from + 30 * 86400, kid: kid).sign(with: signingKey)
    }

    /// A pickup-time Loop for the demo world (non-health example).
    public static var pickupDefinition: LoopDefinition {
        LoopDefinition(key: "pickup-scheduling", title: "Schedule your pickup", entryPoints: [.businessPage, .message, .alert], appearance: .standard,
                       steps: [
                        LoopStep(id: "s1", type: .form, fields: [
                            LoopField(id: "slot", type: .singleChoice, label: "Pickup time", required: true,
                                      options: [LoopOption(id: "am", label: "Morning"), LoopOption(id: "pm", label: "Afternoon")]),
                        ], actions: [LoopActionBinding(id: "confirm", action: "select_option", label: "continue", next: "s2")]),
                        LoopStep(id: "s2", type: .summary, actions: [
                            LoopActionBinding(id: "submit", action: "acknowledge", label: "send_request", next: "done",
                                              routing: LoopRouting(mode: .hosted, queue: "pickups")),
                        ]),
                        LoopStep(id: "done", type: .result, showOutcome: true),
                       ], limits: LoopLimits(expiresInSeconds: 86400))
    }
}
