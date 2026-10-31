import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

/// Fixtures for the Loop tests (WP-3.5, WP-3.6; D3 "Consent bypass", A6a attribution). Non-health examples only.
enum LP {
    static let business = PreviewData.northfield
    static let text = LoopConsentCatalog.current
    static var answers: [String: String] { Dictionary(uniqueKeysWithValues: text.checks.map { ($0.id, $0.correctOptionId) }) }

    static var checkIn: LoopDefinition {
        LoopDefinition(key: "arrival", title: "Let us know you're here", entryPoints: [.businessPage, .alert], appearance: .standard,
                       steps: [
                        LoopStep(id: "arrive", type: .summary, body: "Tap when you're at the counter.", actions: [
                            LoopActionBinding(id: "here", action: "check_in", label: "i_have_arrived", next: "done", routing: LoopRouting(mode: .hosted)),
                        ]),
                        LoopStep(id: "done", type: .result, showOutcome: true),
                       ], limits: LoopLimits(expiresInSeconds: 3600))
    }

    static func branded(_ kit: String) -> LoopDefinition {
        var d = MockLoopsAPI.pickupDefinition
        d.key = "pickup-branded"
        d.appearance = .brandKit(kit)
        return d
    }

    /// Consent fully given (global and for `business`).
    static func consented(_ api: MockLoopsAPI, business: BusinessID = LP.business.id) async throws {
        _ = try await api.enableLoops(LoopGlobalConsentRequest(textVersion: text.version, textDigest: text.digest, answers: answers, agree: true))
        _ = try await api.authorizeBusiness(business, LoopBusinessConsentRequest(textVersion: text.version, textDigest: text.digest, agree: true))
    }

    static func directory(_ businesses: [BusinessSummary] = PreviewData.allBusinesses) -> @Sendable (BusinessID) -> VerifiedBusinessRecord? {
        let map = Dictionary(uniqueKeysWithValues: businesses.map { ($0.id, $0) })
        return { id in
            map[id].map { VerifiedBusinessRecord(id: $0.id, displayName: $0.displayName, verificationStatus: $0.verificationStatus, category: .retail) }
        }
    }

    final class Keys: @unchecked Sendable {
        private let lock = NSLock()
        private var counter = 0
        func next() -> String { lock.lock(); defer { lock.unlock() }; counter += 1; return "key-\(counter)" }
    }

    static func context(keys: [PinnedManifestKey] = [MockLoopsAPI.pinnedKey], directory: @escaping @Sendable (BusinessID) -> VerifiedBusinessRecord? = LP.directory(),
                        status: LoopConsentStatus?, brand: BrandKitStore? = nil, idempotency: Keys = Keys()) -> LoopRenderContext {
        LoopRenderContext(keys: { keys }, publisher: directory, consent: { LoopConsentGate.decision(status: status, business: $0) }, brand: brand,
                          makeIdempotencyKey: { idempotency.next() })
    }
}

/// Wraps the mock server and fails chosen action submissions after recording what was sent (lost responses).
actor FlakyLoopsAPI: LoopsAPI {
    let inner: MockLoopsAPI
    var failNextActions: Int
    private(set) var sentKeys: [String] = []

    init(_ inner: MockLoopsAPI, failNextActions: Int) {
        self.inner = inner
        self.failNextActions = failNextActions
    }

    func consentStatus() async throws -> LoopConsentStatus { try await inner.consentStatus() }
    func enableLoops(_ r: LoopGlobalConsentRequest) async throws -> LoopConsentStatus { try await inner.enableLoops(r) }
    func disableLoops() async throws -> LoopConsentStatus { try await inner.disableLoops() }
    func authorizeBusiness(_ b: BusinessID, _ r: LoopBusinessConsentRequest) async throws -> LoopConsentStatus { try await inner.authorizeBusiness(b, r) }
    func revokeBusiness(_ b: BusinessID) async throws -> LoopConsentStatus { try await inner.revokeBusiness(b) }
    func availableLoops(business: BusinessID?) async throws -> [LoopSummary] { try await inner.availableLoops(business: business) }
    func startInstance(_ r: LoopInstanceCreateRequest) async throws -> LoopInstanceView { try await inner.startInstance(r) }
    func instance(_ id: LoopInstanceID) async throws -> LoopInstanceView { try await inner.instance(id) }
    func submitAction(_ id: LoopInstanceID, _ r: LoopActionRequest) async throws -> LoopActionResult {
        sentKeys.append(r.idempotencyKey)
        let result = try await inner.submitAction(id, r)
        if failNextActions > 0 {
            failNextActions -= 1
            throw APIError.transport("connection lost")
        }
        return result
    }
    func report(_ id: LoopInstanceID, _ r: LoopReportRequest) async throws { try await inner.report(id, r) }
    func publicationKeys() async throws -> LoopPublicationKeySet { try await inner.publicationKeys() }
}

@Suite("Loop consent (WP-3.5)")
@MainActor
struct LoopConsentTests {
    @Test func gateNeedsBothCurrentGrants() async throws {
        let api = MockLoopsAPI()
        let business = LP.business.id
        #expect(LoopConsentGate.decision(status: nil, business: business) == .unavailable)
        #expect(LoopConsentGate.decision(status: try await api.consentStatus(), business: business) == .needsGlobalConsent)
        _ = try await api.enableLoops(LoopGlobalConsentRequest(textVersion: LP.text.version, textDigest: LP.text.digest, answers: LP.answers, agree: true))
        #expect(LoopConsentGate.decision(status: try await api.consentStatus(), business: business) == .needsBusinessAuthorization)
        _ = try await api.authorizeBusiness(business, LoopBusinessConsentRequest(textVersion: LP.text.version, textDigest: LP.text.digest, agree: true))
        #expect(LoopConsentGate.decision(status: try await api.consentStatus(), business: business) == .allowed)
        #expect(LoopConsentGate.decision(status: try await api.consentStatus(), business: PreviewData.harborBank.id) == .needsBusinessAuthorization)
        await api.setAvailable(false)
        #expect(LoopConsentGate.decision(status: try await api.consentStatus(), business: business) == .unavailable)
    }

    @Test func aNewTextVersionRequiresConsentAgain() async throws {
        let api = MockLoopsAPI()
        try await LP.consented(api)
        var next = LP.text
        next.version += 1
        next.paragraphs.append("A new paragraph counsel added.")
        await api.bumpTextVersion(next)
        let status = try await api.consentStatus()
        #expect(status.global?.current == false)
        #expect(LoopConsentGate.decision(status: status, business: LP.business.id) == .needsGlobalConsent)
    }

    @Test func educationCannotBeSkippedAndNeedsAnswersAndAgreement() async throws {
        let api = MockLoopsAPI()
        let model = LoopConsentViewModel(api: api)
        await model.load()
        #expect(model.paragraphCount == LP.text.paragraphs.count)
        #expect(!model.hasReadAll)
        for check in LP.text.checks { model.select(option: check.correctOptionId, for: check.id) }
        model.agreed = true
        #expect(!model.canEnable)
        #expect(await model.enable() == false)
        #expect(model.isEnabled == false)
        // One paragraph at a time, in order; going back never skips ahead.
        for expected in 1..<model.paragraphCount {
            model.advance()
            #expect(model.paragraphIndex == expected)
            #expect(model.currentParagraph == LP.text.paragraphs[expected])
        }
        // On the last paragraph the questions are not offered yet: Continue moves on to them.
        #expect(!model.hasReadAll)
        model.advance()
        #expect(model.hasReadAll)
        model.back()
        #expect(!model.hasReadAll)
        #expect(model.currentParagraph == LP.text.paragraphs.last)
        model.advance()
        #expect(model.hasReadAll)
        #expect(model.canEnable)
        model.agreed = false
        #expect(!model.canEnable)
        model.agreed = true
        #expect(await model.enable())
        #expect(model.isEnabled)
    }

    @Test func wrongAnswersAreRefusedByTheServerAndCleared() async throws {
        let api = MockLoopsAPI()
        let model = LoopConsentViewModel(api: api)
        await model.load()
        for _ in 0..<model.paragraphCount { model.advance() }
        for check in LP.text.checks {
            let wrong = check.options.first { $0.id != check.correctOptionId }!.id
            model.select(option: wrong, for: check.id)
        }
        model.agreed = true
        #expect(await model.enable() == false)
        #expect(model.answers.isEmpty)
        #expect(model.agreed == false)
        #expect(model.errorMessage != nil)
        #expect(model.isEnabled == false)
        // An option that is not offered is ignored.
        model.select(option: "made-up", for: LP.text.checks[0].id)
        #expect(model.answers.isEmpty)
    }

    @Test func businessAuthorizationNamesTheVerifiedBusinessAndRequiresLoopsOn() async throws {
        let api = MockLoopsAPI()
        let model = LoopConsentViewModel(api: api)
        await model.load()
        #expect(model.authorizationText(for: LP.business) == "Allow Northfield Market to send you requests it built. You can stop this at any time.")
        var unverified = LP.business
        unverified.verificationStatus = .pending
        #expect(model.authorizationText(for: unverified) == nil)
        #expect(await model.authorize(LP.business) == false)
        try await LP.consented(api, business: PreviewData.harborBank.id)
        await model.load()
        #expect(await model.authorize(LP.business))
        #expect(model.isAuthorized(LP.business.id))
        await model.revoke(LP.business.id)
        #expect(!model.isAuthorized(LP.business.id))
        await model.disable()
        #expect(!model.isEnabled)
        #expect(!model.isAuthorized(PreviewData.harborBank.id))
    }

    @Test func noInstanceStartsWithoutBothConsents() async throws {
        let api = MockLoopsAPI()
        let summary = await api.publish(MockLoopsAPI.pickupDefinition, business: LP.business.id)
        let consent = LoopConsentViewModel(api: api)
        await consent.load()
        let catalog = LoopCatalogViewModel(business: LP.business.id, api: api, consent: { consent.status })
        await catalog.load()
        #expect(!catalog.isVisible)
        #expect(await catalog.start(summary) == .needsConsent(.needsGlobalConsent))
        _ = try await api.enableLoops(LoopGlobalConsentRequest(textVersion: LP.text.version, textDigest: LP.text.digest, answers: LP.answers, agree: true))
        await consent.load()
        await catalog.load()
        #expect(catalog.isVisible)
        #expect(await catalog.start(summary) == .needsConsent(.needsBusinessAuthorization))
        #expect(await api.startCalls == 0)
        _ = try await api.authorizeBusiness(LP.business.id, LoopBusinessConsentRequest(textVersion: LP.text.version, textDigest: LP.text.digest, agree: true))
        await consent.load()
        guard case .started(let view) = await catalog.start(summary) else { Issue.record("not started"); return }
        #expect(view.businessId == LP.business.id)
        #expect(await api.startCalls == 1)
    }

    @Test func theServerRefusesWhatTheDeviceWouldNotSend() async throws {
        let api = MockLoopsAPI()
        let summary = await api.publish(MockLoopsAPI.pickupDefinition, business: LP.business.id)
        await #expect(throws: APIError.self) {
            _ = try await api.startInstance(LoopInstanceCreateRequest(publicationId: summary.publicationId, entryPoint: .businessPage))
        }
    }

    @Test func revokingCancelsOpenInstancesAndStopsActions() async throws {
        let api = MockLoopsAPI()
        let summary = await api.publish(MockLoopsAPI.pickupDefinition, business: LP.business.id)
        try await LP.consented(api)
        let view = try await api.startInstance(LoopInstanceCreateRequest(publicationId: summary.publicationId, entryPoint: .businessPage))
        _ = try await api.revokeBusiness(LP.business.id)
        let status = try await api.consentStatus()
        let model = LoopInstanceViewModel(instanceId: view.id, api: api, context: LP.context(status: status), initial: view)
        #expect(model.endedNotice != nil)
        #expect(!model.isActionable)
        model.set(.option("am"), for: "slot")
        await model.perform(actionId: "confirm")
        #expect(await api.actionCalls == 0)
    }
}

@Suite("Loop renderer model (WP-3.6)")
@MainActor
struct LoopRendererTests {
    func started(_ definition: LoopDefinition = MockLoopsAPI.pickupDefinition, api: MockLoopsAPI = MockLoopsAPI()) async throws -> (MockLoopsAPI, LoopInstanceView, LoopConsentStatus) {
        let summary = await api.publish(definition, business: LP.business.id)
        try await LP.consented(api)
        let view = try await api.startInstance(LoopInstanceCreateRequest(publicationId: summary.publicationId, entryPoint: .businessPage))
        return (api, view, try await api.consentStatus())
    }

    @Test func attributionIsFirstAndNamesTheVerifiedBusiness() async throws {
        let (api, view, status) = try await started()
        let model = LoopInstanceViewModel(instanceId: view.id, api: api, context: LP.context(status: status))
        await model.load()
        #expect(model.tree.origin == .business)
        guard case .screen(let screen) = model.tree.root, case .attributionBar(let bar)? = screen.children.first else {
            Issue.record("no attribution bar first"); return
        }
        #expect(bar.text == "Built by Northfield Market")
        #expect(PresentationRendering.accessibilityLabel(.attributionBar(bar)) == "Built by Northfield Market, a business on Viadere")
        #expect(bar.verified && bar.protected)
        #expect(model.tree.compactOrigin == "By Northfield Market")
        #expect(model.isActionable)
    }

    @Test func missingOrInvalidManifestShowsTheSafeFallback() async throws {
        let (api, view, status) = try await started()
        var missing = view
        missing.manifest = ""
        let a = LoopInstanceViewModel(instanceId: view.id, api: api, context: LP.context(status: status), initial: missing)
        #expect(a.tree.origin == .unavailable)
        #expect(a.tree.fallbackReason == "manifest_missing" || a.tree.fallbackReason == "manifest_invalid")

        // Signed by a key the build does not pin.
        let b = LoopInstanceViewModel(instanceId: view.id, api: api, context: LP.context(keys: [BK.keys[0]], status: status), initial: view)
        #expect(b.tree.origin == .unavailable)
        #expect(!b.isActionable)

        // No pinned keys at all.
        let c = LoopInstanceViewModel(instanceId: view.id, api: api, context: LP.context(keys: [], status: status), initial: view)
        #expect(c.tree.origin == .unavailable)

        // The device cannot resolve the publisher in its verified directory, or the record is not verified.
        let d = LoopInstanceViewModel(instanceId: view.id, api: api, context: LP.context(directory: { _ in nil }, status: status), initial: view)
        #expect(d.tree.fallbackReason == "publisher_unknown")
        var pending = LP.business
        pending.verificationStatus = .pending
        let e = LoopInstanceViewModel(instanceId: view.id, api: api, context: LP.context(directory: LP.directory([pending]), status: status), initial: view)
        #expect(e.tree.fallbackReason == "publisher_not_verified")

        // The fallback carries only Close and Report, no business text.
        let actions = a.tree.nodes.compactMap { node -> [ActionNode]? in if case .actionBar(let bar) = node { bar.actions } else { nil } }.flatMap { $0 }
        #expect(actions.map(\.actionType) == ["viadere.close", "viadere.report"])
        #expect(!a.tree.nodes.contains { if case .header = $0 { true } else { false } })
    }

    @Test func pausedInstanceShowsThePausedState() async throws {
        let (api, view, status) = try await started()
        var paused = view
        paused.paused = true
        let model = LoopInstanceViewModel(instanceId: view.id, api: api, context: LP.context(status: status), initial: paused)
        #expect(model.tree.fallbackReason == "publication_suspended")
        #expect(!model.isActionable)
    }

    @Test func hostileBrandTokensCannotRestyleProtectedNodes() async throws {
        let api = MockLoopsAPI()
        let brandAPI = try await BK.served(BK.manifest(tokens: BK.hostile))
        let brand = BK.store(api: brandAPI, assets: brandAPI)
        _ = await brand.refresh(LP.business.id)
        let (_, view, status) = try await started(LP.branded("everyday"), api: api)
        let model = LoopInstanceViewModel(instanceId: view.id, api: api, context: LP.context(status: status, brand: brand), initial: view)
        #expect(model.tree.style.source == .brandKit)
        for node in model.tree.nodes where node.isProtected {
            for appearance in BrandAppearance.allCases {
                #expect(PresentationRendering.palette(for: node, in: model.tree, appearance: appearance) == ProtectedPalette.palette(appearance))
                #expect(!PresentationRendering.allowsFrame(behind: node, in: model.tree))
            }
        }
        guard case .screen(let screen) = model.tree.root, case .attributionBar(let bar)? = screen.children.first else {
            Issue.record("attribution hidden"); return
        }
        #expect(bar.text == "Built by Northfield Market")
        // Every hostile role was clamped back to neutral.
        #expect(model.tree.style.palette.overriddenLight.contains(.primary))
    }

    @Test func aKitOfAnotherBusinessIsIgnored() async throws {
        let brandAPI = try await BK.served(BK.manifest(business: PreviewData.harborBank.id, tokens: BK.good))
        let brand = BK.store(api: brandAPI, assets: brandAPI)
        _ = await brand.refresh(PreviewData.harborBank.id)
        let (api, view, status) = try await started(LP.branded("everyday"))
        let model = LoopInstanceViewModel(instanceId: view.id, api: api, context: LP.context(status: status, brand: brand), initial: view)
        #expect(model.tree.style.source == .neutral)
    }

    @Test func actionsAdvanceAndOutcomesUseTheFiveStates() async throws {
        let (api, view, status) = try await started()
        let model = LoopInstanceViewModel(instanceId: view.id, api: api, context: LP.context(status: status), initial: view)
        // Required answer missing: nothing is sent.
        await model.perform(actionId: "confirm")
        #expect(model.invalidFields == ["slot"])
        #expect(await api.actionCalls == 0)
        model.set(.option("pm"), for: "slot")
        await model.perform(actionId: "confirm")
        #expect(model.view?.currentStepId == "s2")
        await model.perform(actionId: "submit")
        #expect(model.view?.currentStepId == "done")
        let outcome = model.tree.nodes.compactMap { node -> OutcomeStatusNode? in if case .outcomeStatus(let n) = node { n } else { nil } }.first
        #expect(outcome?.outcome == .pending)
        #expect(outcome?.text == "Sent to Northfield Market. Waiting for them to confirm.")
        #expect(outcome?.protected == true)

        await api.setOutcome(.accepted, instance: view.id)
        await model.load()
        let accepted = model.tree.nodes.compactMap { node -> OutcomeStatusNode? in if case .outcomeStatus(let n) = node { n } else { nil } }.first
        #expect(accepted?.text == "Northfield Market confirmed")
        #expect(Set(LoopActionOutcome.allCases.map(LoopOutcomeTone.init)).count == 5)
        #expect(Set(LoopOutcomeTone.allCases.map(\.symbol)).count == 5)
    }

    @Test func consequentialActionsConfirmNamingTheResponsibleBusiness() async throws {
        let (api, view, status) = try await started(LP.checkIn)
        let model = LoopInstanceViewModel(instanceId: view.id, api: api, context: LP.context(status: status), initial: view)
        guard case .actionBar(let bar)? = model.tree.nodes.first(where: { if case .actionBar = $0 { true } else { false } }) else {
            Issue.record("no actions"); return
        }
        let here = try #require(bar.actions.first)
        #expect(here.requiresConfirmation)
        await model.perform(here)
        #expect(await api.actionCalls == 0)
        let panel = model.tree.nodes.compactMap { node -> ConfirmationPanelNode? in if case .confirmationPanel(let n) = node { n } else { nil } }.first
        #expect(panel?.responsibleBusinessName == "Northfield Market")
        #expect(panel?.responsibleBusinessId == LP.business.id)
        #expect(panel?.title == "Check in with Northfield Market?")
        #expect(panel?.protected == true)
        #expect(panel.map { PresentationRendering.accessibilityLabel(.confirmationPanel($0)) ?? "" }?.contains("Responsible business: Northfield Market") == true)
        // Cancel returns to the step without sending.
        await model.perform(actionId: "cancel")
        #expect(!model.tree.nodes.contains { if case .confirmationPanel = $0 { true } else { false } })
        await model.perform(here)
        guard case .actionBar(let confirmBar)? = model.tree.nodes.last(where: { if case .actionBar = $0 { true } else { false } }) else { return }
        #expect(confirmBar.protected)
        await model.perform(try #require(confirmBar.actions.first))
        #expect(await api.actionCalls == 1)
        #expect(model.view?.currentStepId == "done")
    }

    @Test func aRetryAfterALostResponseReusesTheIdempotencyKey() async throws {
        let (inner, view, status) = try await started()
        let api = FlakyLoopsAPI(inner, failNextActions: 1)
        let model = LoopInstanceViewModel(instanceId: view.id, api: api, context: LP.context(status: status), initial: view)
        model.set(.option("am"), for: "slot")
        await model.perform(actionId: "confirm")
        #expect(model.errorMessage != nil)
        #expect(model.view?.currentStepId == "s1")
        await model.perform(actionId: "confirm")
        let keys = await api.sentKeys
        #expect(keys.count == 2)
        #expect(keys[0] == keys[1])
        #expect(model.view?.currentStepId == "s2")
        // The server recorded the action once (the retry was a replay).
        #expect(try await inner.instance(view.id).events.count == 1)
    }

    @Test func reportAndClose() async throws {
        let (api, view, status) = try await started()
        let model = LoopInstanceViewModel(instanceId: view.id, api: api, context: LP.context(status: status), initial: view)
        // A business tree has no Close/Report nodes of its own: Viadere's chrome provides them, so a definition cannot remove them.
        #expect(model.actions.allSatisfy { !$0.system })
        model.requestReport()
        #expect(model.isReporting)
        await model.report(.misleading)
        #expect(model.reportSent)
        #expect(await api.reports.count == 1)
        model.close()
        #expect(model.isClosed)

        // The fallback tree's own Close and Report actions work too.
        var broken = view
        broken.manifest = ""
        let fallback = LoopInstanceViewModel(instanceId: view.id, api: api, context: LP.context(status: status), initial: broken)
        await fallback.perform(actionId: "report")
        #expect(fallback.isReporting)
        await fallback.perform(actionId: "close")
        #expect(fallback.isClosed)
        #expect(LoopReportReason.allCases.allSatisfy { !LoopInstanceViewModel.label(for: $0).isEmpty })
    }
}

@Suite("Presentation rendering rules")
struct PresentationRenderingTests {
    @Test func aBusinessTreeWithoutItsAttributionIsRefused() async throws {
        let definition = MockLoopsAPI.pickupDefinition
        let manifest = try await MockLoopsAPI.manifest(for: definition, publication: LoopPublicationID(), business: LP.business.id, revision: 1, now: Date())
        let context = LoopPresentationContext(manifest: manifest, pinnedKeys: [MockLoopsAPI.pinnedKey], definition: definition,
                                              instanceBusinessId: LP.business.id, publisher: LP.directory()(LP.business.id), now: Date())
        var tree = PresentationBuilder.build(context, phase: .step("s1"))
        #expect(PresentationRendering.validated(tree) == tree)
        guard case .screen(var screen) = tree.root else { return }
        screen.children.removeFirst()
        tree.root = .screen(screen)
        #expect(PresentationRendering.validated(tree).origin == .unavailable)
    }

    @Test func unknownNodeKindsDecodeToTheFallback() throws {
        let tree = PresentationBuilder.fallback(.manifestMissing)
        let data = try JSONEncoder().encode(tree)
        #expect(PresentationRendering.decodeOrFallback(data) == tree)
        let hostile = String(decoding: data, as: UTF8.self).replacingOccurrences(of: "\"notice\"", with: "\"web_view\"")
        #expect(PresentationRendering.decodeOrFallback(Data(hostile.utf8)).fallbackReason == "manifest_invalid")
    }

    @Test func loopNotificationsRouteToTheInstanceOrAlerts() {
        let id = LoopInstanceID()
        #expect(LoopNotificationRoute.route(categoryIdentifier: "viadere.loop", userInfo: ["loopInstanceId": id.description]) == .instance(id))
        #expect(LoopNotificationRoute.route(categoryIdentifier: "viadere.loop", userInfo: [:]) == .alerts)
        #expect(LoopNotificationRoute.route(categoryIdentifier: "viadere.loop", userInfo: ["loopInstanceId": "../x"]) == .alerts)
        #expect(LoopNotificationRoute.route(categoryIdentifier: "viadere.confirm", userInfo: [:]) == nil)
    }

    @Test func fieldValuesEncodeAsTheServerExpects() {
        #expect(LoopFieldValue.option("am").jsonValue == .string("am"))
        #expect(LoopFieldValue.options(["a", "b"]).jsonValue == .array([.string("a"), .string("b")]))
        #expect(LoopFieldValue.text("  hi ").jsonValue == .string("hi"))
        #expect(LoopFieldValue.flag(true).jsonValue == .bool(true))
        let date = Date(timeIntervalSince1970: 1_794_744_000)
        #expect(LoopFieldValue.dateString(date, timeZone: TimeZone(identifier: "UTC")!) == "2026-11-15")
    }
}
