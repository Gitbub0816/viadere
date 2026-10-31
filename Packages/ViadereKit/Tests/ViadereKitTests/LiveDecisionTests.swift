import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

@Suite("Decision Live Activities")
struct LiveDecisionTests {
    private func neutral(_ envelope: InteractionEnvelope) -> DecisionActivityState {
        let kind: DecisionActivityState.Kind = envelope.interaction.kind == .confirm ? .confirm : .choose
        return DecisionActivityState(interactionId: envelope.id, kind: kind, expiresAt: envelope.interaction.expiresAt)
    }

    private func envelope(_ payload: InteractionPayload, sensitivity: Sensitivity = .low, purpose: InteractionPurpose = .transactional,
                          status: InteractionStatus = .pending, now: Date = Date(), ttl: TimeInterval = 3_600) -> InteractionEnvelope {
        let business = PreviewData.copperline
        let interaction = Interaction(businessId: business.id, scope: RelationshipScope(consumerId: ConsumerID(), relationshipId: RelationshipID()),
                                      purpose: purpose, payload: payload, sensitivity: sensitivity, createdAt: now,
                                      expiresAt: now.addingTimeInterval(ttl), idempotencyKey: UUID().uuidString)
        return InteractionEnvelope(interaction: interaction, business: business, status: status)
    }

    // MARK: Enrichment

    @Test func enrichesConfirmWithSanitizedBoundedText() {
        let now = Date()
        let long = String(repeating: "Pick up ", count: 30)
        let e = envelope(.confirm(ConfirmPayload(title: "\u{202E}Table\u{200B} for two\nat 7pm", details: long, reference: "R-1")), now: now)
        let state = LiveDecisionEnrichment.enriched(neutral(e), businessId: e.business.id.description, from: e, now: now)
        #expect(state.title == "Table for two at 7pm")
        #expect(state.detail.map { $0.count <= LiveDecisionEnrichment.detailMax } == true)
        #expect(state.detail?.hasSuffix("…") == true)
        #expect(state.options == nil)
        #expect(state.stage == .pending)
        #expect(state.isEnriched)
        // No control, bidi or zero-width characters survive.
        for text in [state.title, state.detail].compactMap({ $0 }) {
            #expect(!DisplayTextSanitizer.containsDisallowedScalars(text))
        }
    }

    @Test func enrichesChooseWithAtMostThreeTruncatedOptions() {
        let now = Date()
        let e = envelope(.choose(ChoosePayload(prompt: "Which window?", options: [
            ChoiceOption(id: "am", label: "Morning between eight and noon please"), ChoiceOption(id: "pm", label: "Afternoon"),
            ChoiceOption(id: "eve", label: "Eve\u{0007}ning")])), now: now)
        let state = LiveDecisionEnrichment.enriched(neutral(e), businessId: e.business.id.description, from: e, now: now)
        #expect(state.title == "Which window?")
        #expect(state.options?.map(\.id) == ["am", "pm", "eve"])
        #expect(state.options?.allSatisfy { $0.label.count <= LiveDecisionEnrichment.labelMax } == true)
        #expect(state.options?[0].label.hasSuffix("…") == true)
        #expect(state.options?[2].label == "Evening")
    }

    @Test func chooseThatDoesNotFitInlineGetsNoOptions() {
        let now = Date()
        let four = envelope(.choose(ChoosePayload(prompt: "Pick", options: (0..<4).map { ChoiceOption(id: "o\($0)", label: "O\($0)") })), now: now)
        // The server never starts one of these; even if it did, the app adds no buttons.
        let state = LiveDecisionEnrichment.enriched(neutral(four), businessId: four.business.id.description, from: four, now: now)
        #expect(state.options == nil)
        let presentation = LiveDecisionPresentation(state: state, businessName: "Copperline", now: now)
        #expect(presentation.buttons.isEmpty)
        #expect(presentation.showsOpen)
    }

    @Test func mismatchedOrSecureOrFinishedInteractionsStayNeutral() {
        let now = Date()
        let e = envelope(.confirm(ConfirmPayload(title: "Secret title")), now: now)
        // Another interaction's envelope, or another business's.
        let other = envelope(.confirm(ConfirmPayload(title: "Other")), now: now)
        #expect(!LiveDecisionEnrichment.enriched(neutral(e), businessId: e.business.id.description, from: other, now: now).isEnriched)
        #expect(!LiveDecisionEnrichment.enriched(neutral(e), businessId: BusinessID().description, from: e, now: now).isEnriched)
        // A rendering the renderer marks secure gets no text and no buttons.
        let secure = envelope(.confirm(ConfirmPayload(title: "Secret title")), sensitivity: .high, now: now)
        #expect(ChannelRenderer.requiresSecureFlow(secure.interaction))
        let secureState = LiveDecisionEnrichment.enriched(neutral(secure), businessId: secure.business.id.description, from: secure, now: now)
        #expect(!secureState.isEnriched)
        // Already answered, cancelled or expired: the stage, without text.
        let answered = envelope(.confirm(ConfirmPayload(title: "Secret title")), status: .confirmed, now: now)
        #expect(LiveDecisionEnrichment.enriched(neutral(answered), businessId: answered.business.id.description, from: answered, now: now).stage == .answered)
        let cancelled = envelope(.confirm(ConfirmPayload(title: "Secret title")), status: .cancelled, now: now)
        #expect(LiveDecisionEnrichment.enriched(neutral(cancelled), businessId: cancelled.business.id.description, from: cancelled, now: now).stage == .cancelled)
        let old = envelope(.confirm(ConfirmPayload(title: "Secret title")), now: now.addingTimeInterval(-7_200))
        let expired = LiveDecisionEnrichment.enriched(neutral(old), businessId: old.business.id.description, from: old, now: now)
        #expect(expired.stage == .expired && !expired.isEnriched)
    }

    // MARK: Presentation

    @Test func fallbackNeverOffersABlindConfirm() {
        let now = Date()
        let state = DecisionActivityState(interactionId: InteractionID(), kind: .confirm, expiresAt: now.addingTimeInterval(600))
        let p = LiveDecisionPresentation(state: state, businessName: "Copperline Kitchen", now: now)
        #expect(p.headline == "Copperline Kitchen needs a quick decision")
        #expect(p.buttons.map(\.actionIdentifier) == ["viadere.decline"])
        #expect(p.showsOpen)
        #expect(p.openURL?.absoluteString == "viadere://i/\(state.interactionId)")
        if let url = p.openURL { #expect(DeepLinkRouter.route(url) == .interaction(state.interactionId)) }
        let choose = LiveDecisionPresentation(state: DecisionActivityState(interactionId: InteractionID(), kind: .choose, expiresAt: now.addingTimeInterval(600)),
                                              businessName: "Copperline Kitchen", now: now)
        #expect(choose.buttons.isEmpty)
        #expect(choose.showsOpen)
    }

    @Test func enrichedPresentationOffersInlineAnswers() {
        let now = Date()
        var state = DecisionActivityState(interactionId: InteractionID(), kind: .confirm, expiresAt: now.addingTimeInterval(600), title: "Pick up at 4:30")
        var p = LiveDecisionPresentation(state: state, businessName: "Copperline", now: now)
        #expect(p.buttons.map(\.actionIdentifier) == ["viadere.confirm", "viadere.decline"])
        #expect(p.buttons.map(\.accessibilityLabel) == ["Confirm Pick up at 4:30", "Decline Pick up at 4:30"])
        #expect(p.buttons.map(\.isPrimary) == [true, false])
        #expect(p.buttons.map(\.isDestructive) == [false, true])
        #expect(!p.showsOpen)
        #expect(p.isPending)
        state = DecisionActivityState(interactionId: InteractionID(), kind: .choose, expiresAt: now.addingTimeInterval(600), title: "Which time?",
                                      options: [.init(id: "tue_9", label: "Tue 9:00"), .init(id: "wed_14", label: "Wed 2:30")])
        p = LiveDecisionPresentation(state: state, businessName: "Copperline", now: now)
        #expect(p.buttons.map(\.actionIdentifier) == ["viadere.option.tue_9", "viadere.option.wed_14"])
        #expect(p.buttons.allSatisfy { !$0.isPrimary && !$0.isDestructive }, "no choice is nudged over another")
        // An option id that could smuggle another action is dropped, and then no options are offered at all.
        state.options = [.init(id: "tue_9", label: "Tue"), .init(id: "x confirm", label: "Bad")]
        p = LiveDecisionPresentation(state: state, businessName: "Copperline", now: now)
        #expect(p.buttons.isEmpty && p.showsOpen)
        // Text in the content state is sanitized again at render time.
        state = DecisionActivityState(interactionId: InteractionID(), kind: .confirm, expiresAt: now.addingTimeInterval(600), title: "Hi\u{202E}there")
        #expect(LiveDecisionPresentation(state: state, businessName: "Copperline", now: now).headline == "Hithere")
    }

    @Test func finishedOrExpiredActivitiesHaveNoButtons() {
        let now = Date()
        for stage in [DecisionActivityState.Stage.answered, .expired, .cancelled] {
            let state = DecisionActivityState(interactionId: InteractionID(), kind: .confirm, expiresAt: now.addingTimeInterval(600), stage: stage, title: "T")
            let p = LiveDecisionPresentation(state: state, businessName: "Copperline", now: now)
            #expect(p.buttons.isEmpty && !p.showsOpen && !p.isPending)
            #expect(p.stageText != nil)
        }
        // Past its expiry, a pending state reads as expired even before any push arrives.
        let late = DecisionActivityState(interactionId: InteractionID(), kind: .confirm, expiresAt: now.addingTimeInterval(-1), title: "T")
        let p = LiveDecisionPresentation(state: late, businessName: "Copperline", now: now)
        #expect(p.stageText == "Expired" && p.buttons.isEmpty)
        // The generic status presentation uses only Viadere's wording.
        let generic = LiveActivityPresentation(status: .decision(late), businessName: "Copperline", now: now)
        #expect(generic.headline == "Decision needed")
    }

    @Test func actionIdentifiersAreTheNotificationOnesAndNothingElse() {
        #expect(LiveDecisionAction(actionIdentifier: "viadere.confirm") == .confirm)
        #expect(LiveDecisionAction(actionIdentifier: "viadere.decline") == .decline)
        #expect(LiveDecisionAction(actionIdentifier: "viadere.option.wed_14") == .select(optionId: "wed_14"))
        for refused in ["viadere.approve", "viadere.deny", "viadere.report", "viadere.reply", "viadere.acknowledge", "viadere.open",
                        "viadere.option.", "viadere.option.a b", "evil.confirm", ""] {
            #expect(LiveDecisionAction(actionIdentifier: refused) == nil, "\(refused)")
        }
    }

    // MARK: Performer

    private func performer(_ services: ViadereServices, api: MockViadereAPI, unlocked: Bool = true) -> LiveDecisionPerformer {
        LiveDecisionPerformer(api: api, handler: services.notificationHandler, isProtectedDataAvailable: { unlocked })
    }

    private func world() async -> (ViadereServices, MockViadereAPI) {
        let api = MockViadereAPI(seed: false)
        return (await ViadereServices.mock(api: api), api)
    }

    @Test func confirmAndChooseAreSignedLikeANotificationAction() async throws {
        let (services, api) = await world()
        let confirm = PreviewData.confirm()
        await api.add(confirm)
        #expect(await performer(services, api: api).perform(interactionId: confirm.id.description, actionIdentifier: "viadere.confirm") == .finished(.answered))
        let choose = PreviewData.choose()
        await api.add(choose)
        #expect(await performer(services, api: api).perform(interactionId: choose.id.description, actionIdentifier: "viadere.option.wed_14") == .finished(.answered))
        let log = await api.decisionLog
        #expect(log.map(\.1) == [.confirm, .select])
        // The request key, at the same (lowest) assurance as an inline notification action.
        #expect(log.allSatisfy { $0.2 == DecisionAssurance.none })
        // A second tap finds it answered.
        #expect(await performer(services, api: api).perform(interactionId: confirm.id.description, actionIdentifier: "viadere.decline") == .finished(.answered))
        #expect(await api.decisionLog.count == 2)
    }

    @Test func lockedDeviceNeverDecides() async throws {
        let (services, api) = await world()
        let confirm = PreviewData.confirm()
        await api.add(confirm)
        #expect(await performer(services, api: api, unlocked: false).perform(interactionId: confirm.id.description, actionIdentifier: "viadere.confirm") == .locked)
        #expect(await api.decisionLog.isEmpty)
        // Locked between the fetch and the signature: still nothing.
        let flag = LockFlag()
        let flipping = LiveDecisionPerformer(api: api, handler: services.notificationHandler, isProtectedDataAvailable: { await flag.next() })
        #expect(await flipping.perform(interactionId: confirm.id.description, actionIdentifier: "viadere.confirm") == .locked)
        #expect(await api.decisionLog.isEmpty)
    }

    @Test func ineligibleOrMismatchedActionsNeverDecide() async throws {
        let (services, api) = await world()
        let p = performer(services, api: api)
        // Sign-in and approval requests: never from a Live Activity button, not even a refusal.
        let authorize = PreviewData.authorize(sensitivity: .low)
        await api.add(authorize)
        #expect(await p.perform(interactionId: authorize.id.description, actionIdentifier: "viadere.approve") == .rejected)
        #expect(await p.perform(interactionId: authorize.id.description, actionIdentifier: "viadere.decline") == .openApp)
        // A confirm the renderer marks secure opens the app.
        let secure = envelope(.confirm(ConfirmPayload(title: "Big change")), sensitivity: .high)
        await api.add(secure)
        #expect(await p.perform(interactionId: secure.id.description, actionIdentifier: "viadere.confirm") == .openApp)
        // Marketing never.
        let marketing = envelope(.confirm(ConfirmPayload(title: "Join")), purpose: .marketing)
        await api.add(marketing)
        #expect(await p.perform(interactionId: marketing.id.description, actionIdentifier: "viadere.confirm") == .openApp)
        // Wrong action for the kind, or an option the interaction does not have.
        let choose = PreviewData.choose()
        await api.add(choose)
        #expect(await p.perform(interactionId: choose.id.description, actionIdentifier: "viadere.confirm") == .rejected)
        #expect(await p.perform(interactionId: choose.id.description, actionIdentifier: "viadere.option.sat_10") == .rejected)
        let confirm = PreviewData.confirm()
        await api.add(confirm)
        #expect(await p.perform(interactionId: confirm.id.description, actionIdentifier: "viadere.option.tue_9") == .rejected)
        #expect(await p.perform(interactionId: "not-an-id", actionIdentifier: "viadere.confirm") == .rejected)
        // Unknown interaction (fetch fails): open the app rather than guess.
        #expect(await p.perform(interactionId: InteractionID().description, actionIdentifier: "viadere.confirm") == .openApp)
        #expect(await api.decisionLog.isEmpty)
    }

    @Test func expiredOrWithdrawnFinishTheActivity() async throws {
        let (services, api) = await world()
        let p = performer(services, api: api)
        let old = envelope(.confirm(ConfirmPayload(title: "Old")), now: Date().addingTimeInterval(-7_200))
        await api.add(old)
        #expect(await p.perform(interactionId: old.id.description, actionIdentifier: "viadere.confirm") == .finished(.expired))
        let cancelled = envelope(.confirm(ConfirmPayload(title: "Gone")), status: .cancelled)
        await api.add(cancelled)
        #expect(await p.perform(interactionId: cancelled.id.description, actionIdentifier: "viadere.confirm") == .finished(.cancelled))
        #expect(await api.decisionLog.isEmpty)
    }
}

/// Unlocked for the first check, locked for the second.
private actor LockFlag {
    private var calls = 0
    func next() -> Bool {
        calls += 1
        return calls == 1
    }
}
