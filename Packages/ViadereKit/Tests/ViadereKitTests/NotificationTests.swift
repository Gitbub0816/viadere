import Testing
import Foundation
import ViadereCore
@testable import ViadereKit

@Suite("Notification actions")
struct NotificationActionTests {
    func response(_ action: String, _ envelope: InteractionEnvelope, text: String? = nil) -> NotificationResponseInfo {
        NotificationResponseInfo(actionIdentifier: action, categoryIdentifier: "x", userInfo: ["iid": envelope.id.description], userText: text)
    }

    func world() async -> (ViadereServices, MockViadereAPI) {
        let api = MockViadereAPI(seed: false)
        return (await ViadereServices.mock(api: api), api)
    }

    @Test func parsesActionIdentifiers() {
        #expect(NotificationActionParser.parse(actionIdentifier: "viadere.approve") == .decision(.approve, optionId: nil))
        #expect(NotificationActionParser.parse(actionIdentifier: "viadere.option.tue_9") == .decision(.select, optionId: "tue_9"))
        #expect(NotificationActionParser.parse(actionIdentifier: "viadere.reply") == .decision(.reply, optionId: nil))
        #expect(NotificationActionParser.parse(actionIdentifier: "viadere.open") == .open)
        #expect(NotificationActionParser.parse(actionIdentifier: NotificationActionID.systemDefaultTap) == .open)
        #expect(NotificationActionParser.parse(actionIdentifier: NotificationActionID.systemDismiss) == .dismiss)
        #expect(NotificationActionParser.parse(actionIdentifier: "viadere.option.") == .unknown)
        #expect(NotificationActionParser.parse(actionIdentifier: "evil.approve") == .unknown)
    }

    @Test func approveOnSensitiveKindsNeverRunsInline() async throws {
        let (services, api) = await world()
        for envelope in [PreviewData.authorize(sensitivity: .low), PreviewData.authorize(sensitivity: .high),
                         PreviewData.authenticate(sensitivity: .low), PreviewData.authenticate(sensitivity: .standard)] {
            await api.add(envelope)
            let outcome = await services.notificationHandler.handle(response("viadere.approve", envelope))
            #expect(outcome == .requiresApp(envelope.id))
        }
        #expect(await api.decisionLog.isEmpty)
    }

    @Test func inlineAssuranceRules() {
        #expect(NotificationActionHandler.inlineAssurance(for: PreviewData.authorize(sensitivity: .low).interaction, decision: .approve) == nil)
        #expect(NotificationActionHandler.inlineAssurance(for: PreviewData.authorize().interaction, decision: .deny) == DecisionAssurance.none)
        #expect(NotificationActionHandler.inlineAssurance(for: PreviewData.authorize().interaction, decision: .report) == DecisionAssurance.none)
        #expect(NotificationActionHandler.inlineAssurance(for: PreviewData.choose().interaction, decision: .select) == DecisionAssurance.none)
        #expect(NotificationActionHandler.inlineAssurance(for: PreviewData.confirm().interaction, decision: .confirm) == DecisionAssurance.none)
    }

    @Test func denyRunsInlineWhenServerAcceptsLowAssurance() async throws {
        let (services, api) = await world()
        // low-sensitivity sign-in: a device signature suffices, so a lock-screen "No" is accepted
        let envelope = PreviewData.authenticate(sensitivity: .low)
        await api.add(envelope)
        let outcome = await services.notificationHandler.handle(response("viadere.deny", envelope))
        #expect(outcome == .submitted(envelope.id, .denied))
        #expect(await api.decisionLog.first?.2 == DecisionAssurance.none)
    }

    /// ViadereCore (`AssurancePolicy.canSatisfy(decision:)`) now accepts any valid device signature for deny/report,
    /// so a lock-screen Deny on a high-assurance request is recorded instead of bouncing into the app.
    @Test func denyOnHighAssuranceRunsInlineBecauseDenyIsAlwaysSafe() async throws {
        let (services, api) = await world()
        let envelope = PreviewData.authorize(sensitivity: .high)
        await api.add(envelope)
        let outcome = await services.notificationHandler.handle(response("viadere.deny", envelope))
        #expect(outcome == .submitted(envelope.id, .denied))
        #expect(await api.decisionLog.count == 1)
    }

    @Test func chooseAndConfirmRunInline() async throws {
        let (services, api) = await world()
        let choose = PreviewData.choose()
        await api.add(choose)
        #expect(await services.notificationHandler.handle(response("viadere.option.wed_14", choose)) == .submitted(choose.id, .selected))
        let confirm = PreviewData.confirm()
        await api.add(confirm)
        #expect(await services.notificationHandler.handle(response("viadere.confirm", confirm)) == .submitted(confirm.id, .confirmed))
    }

    @Test func invalidOptionOpensApp() async throws {
        let (services, api) = await world()
        let choose = PreviewData.choose()
        await api.add(choose)
        #expect(await services.notificationHandler.handle(response("viadere.option.bogus", choose)) == .requiresApp(choose.id))
    }

    @Test func textReplyIsSubmitted() async throws {
        let (services, api) = await world()
        let now = Date()
        let interaction = Interaction(
            businessId: PreviewData.copperline.id,
            scope: RelationshipScope(consumerId: PreviewData.consumerId, relationshipId: RelationshipID()),
            purpose: .support, payload: .reply(ReplyPayload(prompt: "Anything we should know?", maxLength: 40)),
            sensitivity: .low, createdAt: now, expiresAt: now.addingTimeInterval(600), idempotencyKey: "r")
        let envelope = InteractionEnvelope(interaction: interaction, business: PreviewData.copperline, status: .pending)
        await api.add(envelope)
        #expect(await services.notificationHandler.handle(response("viadere.reply", envelope, text: "  Oat milk please  ")) == .submitted(envelope.id, .replied))
        // an empty reply is never submitted
        let second = InteractionEnvelope(interaction: Interaction(
            businessId: PreviewData.copperline.id,
            scope: RelationshipScope(consumerId: PreviewData.consumerId, relationshipId: RelationshipID()),
            purpose: .support, payload: .reply(ReplyPayload(prompt: "Again?", maxLength: 40)),
            sensitivity: .low, createdAt: now, expiresAt: now.addingTimeInterval(600), idempotencyKey: "r2"),
            business: PreviewData.copperline, status: .pending)
        await api.add(second)
        #expect(await services.notificationHandler.handle(response("viadere.reply", second, text: "   ")) == .requiresApp(second.id))
        #expect(await api.decisionLog.count == 1)
    }

    @Test func staleExpiredAndSystemActions() async throws {
        let (services, api) = await world()
        let confirm = PreviewData.confirm()
        await api.add(confirm)
        _ = await services.notificationHandler.handle(response("viadere.confirm", confirm))
        #expect(await services.notificationHandler.handle(response("viadere.confirm", confirm)) == .stale(confirm.id, .confirmed))

        let old = PreviewData.confirm(now: Date().addingTimeInterval(-7_200))
        await api.add(old)
        #expect(await services.notificationHandler.handle(response("viadere.confirm", old)) == .expired(old.id))

        #expect(await services.notificationHandler.handle(response(NotificationActionID.systemDefaultTap, confirm)) == .open(confirm.id))
        #expect(await services.notificationHandler.handle(response(NotificationActionID.systemDismiss, confirm)) == .ignored)
        #expect(await services.notificationHandler.handle(response("viadere.open", confirm)) == .open(confirm.id))
        let noId = NotificationResponseInfo(actionIdentifier: "viadere.deny", userInfo: [:])
        #expect(await services.notificationHandler.handle(noId) == .open(nil))
    }
}

@Suite("Notification enrichment")
struct EnrichmentTests {
    @Test func rendersActionableSecureCategory() async throws {
        let api = MockViadereAPI(seed: false)
        let envelope = PreviewData.authorize(sensitivity: .high)
        await api.add(envelope)
        let enricher = NotificationEnricher(api: api)
        let result = try #require(await enricher.enrich(userInfo: ["iid": envelope.id.description]))
        #expect(result.title == "Northfield Market")
        #expect(result.body.contains("$285.28"))
        #expect(result.category.identifier == "viadere.authorize.secure")
        #expect(result.requiresSecureFlow)
        #expect(result.interruptionLevel == .timeSensitive)
        #expect(result.threadIdentifier == "business.\(PreviewData.northfield.id)")
        // approve opens the app, deny doesn't
        #expect(result.category.actions.first { $0.identifier == "viadere.approve" }?.opensApp == true)
        #expect(result.category.actions.first { $0.identifier == "viadere.deny" }?.opensApp == false)
        #expect(!result.isFallback)
    }

    @Test func securityRequestsCarryACompactCard() async throws {
        let api = MockViadereAPI(seed: false)
        let envelope = PreviewData.authorize(sensitivity: .high)
        await api.add(envelope)
        let result = try #require(await NotificationEnricher(api: api).enrich(userInfo: ["iid": envelope.id.description]))
        let json = try #require(result.userInfo[NotificationCard.userInfoKey])
        let card = try #require(NotificationCard.decode(json: json))
        #expect(card.business == "Northfield Market")
        #expect(card.rows.contains { $0.label == "Amount" && $0.value == "$285.28 USD" })
        #expect(card.finishesInApp)
        #expect(card.verification == "Face ID or Touch ID required")
        #expect(card.risks == ["Far from your usual location"])
        // non-security kinds don't need one
        let choose = PreviewData.choose()
        await api.add(choose)
        let other = try #require(await NotificationEnricher(api: api).enrich(userInfo: ["iid": choose.id.description]))
        #expect(other.userInfo[NotificationCard.userInfoKey] == nil)
    }

    @Test func choosePerInteractionCategory() async throws {
        let api = MockViadereAPI(seed: false)
        let choose = PreviewData.choose()
        await api.add(choose)
        let result = try #require(await NotificationEnricher(api: api).enrich(userInfo: ["iid": choose.id.description]))
        #expect(result.category.identifier == "viadere.choose.\(choose.id)")
        #expect(result.category.actions.map(\.identifier) == ["viadere.option.tue_9", "viadere.option.wed_14", "viadere.option.fri_11"])
    }

    @Test func fallsBackWhenFetchFails() async throws {
        let api = MockViadereAPI(seed: false)
        let missing = InteractionID()
        let result = try #require(await NotificationEnricher(api: api).enrich(userInfo: ["iid": missing.description]))
        #expect(result.isFallback)
        #expect(result.category.identifier == "viadere.unknown")
        #expect(!result.body.contains("$"))
        #expect(await NotificationEnricher(api: api).enrich(userInfo: ["other": "x"]) == nil)
    }

    @Test func alreadyHandledIsQuiet() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api)
        let envelope = PreviewData.confirm()
        await api.add(envelope)
        _ = try await services.approvals.submit(envelope, decision: .confirm)
        let result = try #require(await NotificationEnricher(api: api).enrich(userInfo: ["iid": envelope.id.description]))
        #expect(result.interruptionLevel == .passive)
        #expect(result.category.actions.isEmpty)
    }

    @Test func staticCategoriesMatchRendererList() {
        let specs = NotificationEnricher.staticCategorySpecs()
        #expect(Set(specs.map(\.identifier)) == Set(ChannelRenderer.staticCategories))
        let secure = specs.first { $0.identifier == "viadere.authorize.secure" }
        #expect(secure?.actions.first { $0.identifier == "viadere.approve" }?.opensApp == true)
        let reply = specs.first { $0.identifier == "viadere.reply" }
        #expect(reply?.actions.first?.style == .textInput)
    }
}
