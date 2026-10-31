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
    public private(set) var reports: [(LoopInstanceID, LoopReportReason)] = []
    public private(set) var actionCalls = 0
    public private(set) var startCalls = 0
    private var text: LoopConsentTextVersion

    public init(connected: [BusinessID] = PreviewData.allBusinesses.map(\.id), text: LoopConsentTextVersion = LoopConsentCatalog.current,
                clock: @escaping @Sendable () -> Date = { Date() }) {
        self.connected = Set(connected)
        self.text = text
        self.clock = clock
    }

    // MARK: Test hooks

    public func setAvailable(_ value: Bool) { available = value }
    public func bumpTextVersion(_ next: LoopConsentTextVersion) { text = next }
    public func setConnected(_ businesses: [BusinessID]) { connected = Set(businesses) }

    /// Publishes `definition` for `business` (signed with the mock key) and returns its summary.
    @discardableResult
    public func publish(_ definition: LoopDefinition, business: BusinessID, revision: Int64 = 1) -> LoopSummary {
        let summary = LoopSummary(publicationId: LoopPublicationID(), businessId: business, revision: revision, title: definition.title,
                                  entryPoints: definition.entryPoints, authorized: false)
        publications.append(Publication(summary: summary, definition: definition))
        return summary
    }

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
        guard connected.contains(business) else { throw APIError.server(status: 404, code: .notFound, message: "Not found.") }
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
        if let business, !connected.contains(business) { throw APIError.server(status: 404, code: .notFound, message: "Not found.") }
        return publications.filter { business == nil || $0.summary.businessId == business }.map { p in
            var s = p.summary
            s.authorized = LoopConsentGate.decision(status: statusValue(), business: s.businessId) == .allowed
            return s
        }
    }

    public func startInstance(_ request: LoopInstanceCreateRequest) async throws -> LoopInstanceView {
        startCalls += 1
        guard let publication = publications.first(where: { $0.summary.publicationId == request.publicationId }),
              connected.contains(publication.summary.businessId) else { throw APIError.server(status: 404, code: .notFound, message: "Not found.") }
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
