import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

/// Everything a Loop screen needs from the rest of the app, injected so the renderer model is tested on Linux.
public struct LoopRenderContext: Sendable {
    /// The verified Loop publication keys (`LoopKeyRing.keys`).
    public var keys: @Sendable () -> [PinnedManifestKey]
    /// The device's verified directory record of a business (from the connected-business list), or `nil` when unknown.
    public var publisher: @Sendable (BusinessID) -> VerifiedBusinessRecord?
    /// Consent as last known on the device; actions are not sent unless the gate allows.
    public var consent: @Sendable (BusinessID) -> LoopStartDecision
    public var brand: BrandKitStore?
    public var clock: @Sendable () -> Date
    public var makeIdempotencyKey: @Sendable () -> String
    /// Signs a binding estimate approval (`LoopApprovalSigner.sign`) with the device-bound biometric key; `nil` on a device that can't, so an
    /// `approve_estimate` button is never sent without one (WP-4.4).
    public var signApproval: (@Sendable (Interaction, String) async throws -> SignedDecision)?
    /// The newest phase this build can render and re-validate on the device (Phase 4: connected routing and `approve_estimate`). The server
    /// enforces its own phase on every action; this only lets the device show what the server reviewed and signed.
    public var platformPhase: LoopPlatformPhase

    public init(keys: @escaping @Sendable () -> [PinnedManifestKey], publisher: @escaping @Sendable (BusinessID) -> VerifiedBusinessRecord?,
                consent: @escaping @Sendable (BusinessID) -> LoopStartDecision, brand: BrandKitStore? = nil,
                clock: @escaping @Sendable () -> Date = { Date() },
                makeIdempotencyKey: @escaping @Sendable () -> String = { "loop-" + UUID().uuidString.lowercased() },
                signApproval: (@Sendable (Interaction, String) async throws -> SignedDecision)? = nil, platformPhase: LoopPlatformPhase = .connected) {
        self.keys = keys
        self.publisher = publisher
        self.consent = consent
        self.brand = brand
        self.clock = clock
        self.makeIdempotencyKey = makeIdempotencyKey
        self.signApproval = signApproval
        self.platformPhase = platformPhase
    }
}

/// One Loop instance on screen (WP-3.6): verifies, builds and validates the presentation tree, keeps the customer's answers, and submits
/// actions with idempotency keys through the signed API client.
///
/// * The tree comes only from `PresentationBuilder` with the build-pinned keys and the device's own verified directory record of the
///   publisher; anything missing or invalid is the safe fallback (Close and Report only), then `PresentationRendering.validated`.
/// * Consequential actions go through the protected confirmation panel that names the responsible business before anything is sent.
/// * A retry of the same step, action and answers reuses its idempotency key (the server returns the stored result); different answers get
///   a new key.
/// * Nothing is sent unless the consent gate allows it on the device too.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class LoopInstanceViewModel {
    public enum Status: Sendable, Equatable { case loading, ready, failed(String) }

    public let instanceId: LoopInstanceID
    public private(set) var view: LoopInstanceView?
    public private(set) var tree: PresentationTree = PresentationBuilder.fallback(.manifestMissing)
    public private(set) var status: Status = .loading
    public private(set) var phase: PresentationPhase?
    public private(set) var values: [String: LoopFieldValue] = [:]
    public private(set) var invalidFields: Set<String> = []
    public private(set) var isSubmitting = false
    public private(set) var reportSent = false
    public var errorMessage: String?
    /// Set when the customer chose Close.
    public private(set) var isClosed = false
    /// Set when the customer chose Report (the sheet shows the reasons).
    public var isReporting = false

    private let api: any LoopsAPI
    private let context: LoopRenderContext
    private var definition: LoopDefinition?
    private var pendingKeys: [String: String] = [:]

    public init(instanceId: LoopInstanceID, api: any LoopsAPI, context: LoopRenderContext, initial: LoopInstanceView? = nil) {
        self.instanceId = instanceId
        self.api = api
        self.context = context
        if let initial { apply(initial) }
    }

    // MARK: Derived state

    /// A neutral, Viadere-worded line when the instance can no longer be acted on.
    public var endedNotice: String? {
        guard let view else { return nil }
        switch view.state {
        case .expired: return "This request has expired."
        case .cancelled: return "This request was cancelled. Nothing more will be sent."
        case .active, .submitted, .completed: break
        }
        switch context.consent(view.businessId) {
        case .allowed: return nil
        case .unavailable: return "Loops aren't available right now."
        case .needsGlobalConsent: return "Loops are turned off. Turn them on in Settings to continue."
        case .needsBusinessAuthorization: return "You haven't allowed Loops from this business. Allow it in Settings to continue."
        }
    }

    /// Business actions can be sent right now.
    public var isActionable: Bool {
        guard let view, view.state == .active, !view.paused, tree.origin != .unavailable, endedNotice == nil else { return false }
        return true
    }

    // MARK: Loading

    public func load() async {
        do {
            apply(try await api.instance(instanceId))
            status = .ready
        } catch {
            status = .failed((error as? APIError)?.userMessage ?? "Couldn't open this request.")
            tree = PresentationBuilder.fallback(.manifestMissing)
        }
    }

    private func apply(_ new: LoopInstanceView) {
        if new.currentStepId != view?.currentStepId { values = [:]; invalidFields = [] }
        view = new
        definition = LoopDefinition.parse(new.definition).definition
        if case .confirm(let stepId, _)? = phase, stepId != new.currentStepId { phase = nil }
        rebuild()
        status = .ready
    }

    /// Rebuilds the tree from the verified inputs (also on appearance or key changes).
    public func rebuild() {
        guard let view else { return }
        guard let definition else {
            tree = PresentationBuilder.fallback(.definitionRejected)
            return
        }
        var brand: BrandKitPresentation?
        if case .brandKit(let key) = definition.appearance { brand = context.brand?.loopBrand(for: view.businessId, kitKey: key) }
        let status: LoopPublicationStatus = view.paused ? .suspended : view.publicationStatus
        let presentation = LoopPresentationContext(manifest: view.manifest, pinnedKeys: context.keys(), definition: definition,
                                                   instanceBusinessId: view.businessId, publisher: context.publisher(view.businessId),
                                                   publicationStatus: status, brand: brand, now: context.clock(), phase: context.platformPhase)
        let phase = self.phase ?? .step(view.currentStepId, outcome: latestOutcome(view))
        tree = PresentationRendering.validated(PresentationBuilder.build(presentation, phase: phase))
    }

    func latestOutcome(_ view: LoopInstanceView) -> LoopActionOutcome? {
        view.events.filter { $0.outcome != nil }.max { $0.createdAt < $1.createdAt }?.outcome
    }

    // MARK: Answers

    public func value(for field: String) -> LoopFieldValue? { values[field] }

    public func set(_ value: LoopFieldValue?, for field: String) {
        guard let step = currentStep, step.fields.contains(where: { $0.id == field }) else { return }
        values[field] = value
        invalidFields.remove(field)
    }

    var currentStep: LoopStep? { view.flatMap { definition?.step($0.currentStepId) } }

    /// The request inputs of the current step (only its own fields, only answered ones).
    func inputs() -> [String: JSONValue] {
        guard let step = currentStep else { return [:] }
        var inputs: [String: JSONValue] = [:]
        for field in step.fields {
            guard let value = values[field.id] else { continue }
            if case .options(let ids) = value, ids.isEmpty { continue }
            if case .text(let s) = value, s.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { continue }
            inputs[field.id] = value.jsonValue
        }
        return inputs
    }

    // MARK: Actions

    /// The actions on screen now (every action bar of the current tree, in order).
    public var actions: [ActionNode] {
        tree.nodes.flatMap { node -> [ActionNode] in if case .actionBar(let bar) = node { bar.actions } else { [] } }
    }

    /// Handles a tap on the action with `actionId` **of the current tree** (anything not on screen is ignored).
    public func perform(actionId: String) async {
        guard let action = actions.first(where: { $0.id == actionId }) else { return }
        await perform(action)
    }

    /// Handles a tap on an action of the current tree.
    public func perform(_ action: ActionNode) async {
        guard actions.contains(action) else { return }
        errorMessage = nil
        if action.system {
            switch action.actionType {
            case "viadere.close": isClosed = true
            case "viadere.report": isReporting = true
            case "viadere.cancel":
                phase = nil
                rebuild()
            default: break
            }
            return
        }
        guard isActionable, let view, let step = currentStep, step.actions.contains(where: { $0.id == action.id }) else { return }
        let inputs = inputs()
        let issues = LoopInputValidator.issues(inputs, step: step)
        guard issues.isEmpty else {
            invalidFields = Set(issues.compactMap { $0.path.hasPrefix("inputs.") ? String($0.path.dropFirst("inputs.".count)) : nil })
            errorMessage = "Check the highlighted answers."
            return
        }
        if action.requiresConfirmation, phase == nil {
            phase = .confirm(stepId: step.id, actionId: action.id)
            rebuild()
            return
        }
        await submit(view: view, stepId: step.id, actionId: action.id, inputs: inputs)
    }

    private func submit(view: LoopInstanceView, stepId: String, actionId: String, inputs: [String: JSONValue]) async {
        let submission = LoopActionSubmission(instanceId: view.id, stepId: stepId, actionId: actionId, inputs: inputs, idempotencyKey: "")
        guard let digest = try? submission.requestDigest() else { return }
        let key = pendingKeys[digest] ?? context.makeIdempotencyKey()
        guard LoopActionSubmission.isValidIdempotencyKey(key) else { return }
        pendingKeys[digest] = key
        isSubmitting = true
        defer { isSubmitting = false }
        do {
            // WP-4.4: a binding estimate approval is signed only for the challenge that matches what this device rendered from its own verified
            // definition and directory record; anything else is never signed and never sent.
            var approval: LoopActionApproval?
            if let binding = definition?.step(stepId)?.actions.first(where: { $0.id == actionId }), binding.action == LoopEstimateApproval.actionType {
                guard let signer = context.signApproval, let record = context.publisher(view.businessId),
                      let name = LoopEstimateApproval.merchantName(record.displayName) else {
                    errorMessage = "This device can't approve estimates. Nothing was approved."
                    return
                }
                let challenge = try await api.startApproval(view.id, LoopApprovalStartRequest(stepId: stepId, actionId: actionId))
                guard LoopEstimateApproval.matches(challenge, instanceId: view.id, stepId: stepId, binding: binding, businessId: view.businessId,
                                                   businessName: name, now: context.clock()) else {
                    pendingKeys[digest] = nil
                    phase = nil
                    errorMessage = "This estimate changed. Nothing was approved."
                    await load()
                    return
                }
                do {
                    approval = LoopActionApproval(approvalId: challenge.approvalId, signedDecision: try await signer(challenge.interaction, name))
                } catch {
                    errorMessage = "Not approved. Nothing was sent."
                    return
                }
            }
            let result = try await api.submitAction(view.id, LoopActionRequest(stepId: stepId, actionId: actionId, inputs: inputs, idempotencyKey: key, approval: approval))
            pendingKeys[digest] = nil
            phase = nil
            apply(result.instance)
        } catch let error as APIError {
            switch error {
            case .server(409, _, _), .server(410, _, _), .server(403, _, _):
                // Step moved on, paused, ended or consent withdrawn: show the server's current state.
                pendingKeys[digest] = nil
                phase = nil
                errorMessage = error.userMessage
                await load()
            case .server(422, _, _):
                pendingKeys[digest] = nil
                errorMessage = "Check the highlighted answers."
            default:
                // Network or server trouble: keep the key so a retry cannot record the action twice.
                errorMessage = error.userMessage
            }
        } catch {
            errorMessage = "Couldn't send that. Try again."
        }
    }

    /// Viadere's own chrome around every Loop screen (not part of the tree, so a definition can never remove it): Close and Report.
    public func close() { isClosed = true }
    public func requestReport() { isReporting = true }

    /// Reports this Loop (one report per account and publication counts toward suspension).
    public func report(_ reason: LoopReportReason) async {
        do {
            try await api.report(instanceId, LoopReportRequest(reason: reason))
            reportSent = true
            isReporting = false
        } catch {
            errorMessage = (error as? APIError)?.userMessage ?? "Couldn't send the report."
        }
    }

    /// Human labels for the report reasons (Viadere's words).
    public static func label(for reason: LoopReportReason) -> String {
        switch reason {
        case .misleading: "It's misleading"
        case .unsafe: "It feels unsafe"
        case .spam: "It's spam"
        case .healthDataRequested: "It asked about my health"
        case .impersonation: "It's pretending to be someone else"
        case .other: "Something else"
        }
    }
}

/// The Loops a business offers on its page (entry point `business_page`), and starting one behind both consents (WP-3.5, WP-3.6).
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class LoopCatalogViewModel {
    public enum StartResult: Sendable, Equatable {
        case started(LoopInstanceView)
        case needsConsent(LoopStartDecision)
        case failed(String)
    }

    public let business: BusinessID
    public private(set) var loops: [LoopSummary] = []
    private let api: (any LoopsAPI)?
    private let consent: @MainActor () -> LoopConsentStatus?

    public init(business: BusinessID, api: (any LoopsAPI)?, consent: @escaping @MainActor () -> LoopConsentStatus?) {
        self.business = business
        self.api = api
        self.consent = consent
    }

    /// Nothing is listed while Loops are unavailable or off globally (entry points are hidden, WP-3.5 "disable semantics").
    public var isVisible: Bool {
        let decision = LoopConsentGate.decision(status: consent(), business: business)
        return decision != .unavailable && decision != .needsGlobalConsent && !loops.isEmpty
    }

    public func load() async {
        guard let api else { return }
        let decision = LoopConsentGate.decision(status: consent(), business: business)
        guard decision != .unavailable, decision != .needsGlobalConsent else {
            loops = []
            return
        }
        let all = (try? await api.availableLoops(business: business)) ?? []
        loops = all.filter { $0.businessId == business && $0.entryPoints.contains(.businessPage) }
    }

    /// Starts `summary` only with both consents current on the device (the server checks again).
    public func start(_ summary: LoopSummary) async -> StartResult {
        guard let api, summary.businessId == business else { return .failed("This isn't available.") }
        let decision = LoopConsentGate.decision(status: consent(), business: business)
        guard decision == .allowed else { return .needsConsent(decision) }
        do {
            return .started(try await api.startInstance(LoopInstanceCreateRequest(publicationId: summary.publicationId, entryPoint: .businessPage)))
        } catch let error as APIError {
            if case .server(403, _, _) = error { return .needsConsent(.needsBusinessAuthorization) }
            return .failed(error.userMessage)
        } catch {
            return .failed("Couldn't start this.")
        }
    }

    /// The business-supplied title, sanitized, always shown under the verified attribution (never instead of it).
    public static func title(_ summary: LoopSummary) -> String { UntrustedText.line(summary.title, max: LoopLimits.titleLength) }
}
