import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

/// A clock tests can move.
final class MovableClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value: Date
    init(_ start: Date) { value = start }
    var now: Date { lock.lock(); defer { lock.unlock() }; return value }
    func advance(_ seconds: TimeInterval) { lock.lock(); value = value.addingTimeInterval(seconds); lock.unlock() }
}

/// WP-1.2 (plan 5.4): context safety (C9.7), stale cache (D3.T7), offline, push dedupe (C5.4), 50-business search (C9.2), and the IA.
@Suite("Organization (Kit)")
@MainActor
struct OrganizationKitTests {
    let start = Date(timeIntervalSince1970: 1_800_000_000)

    func world() async -> (model: AppModel, api: MockViadereAPI, clock: MovableClock, services: ViadereServices) {
        let clock = MovableClock(start)
        let tick: @Sendable () -> Date = { clock.now }
        let api = MockViadereAPI(seed: true, clock: tick)
        let services = await ViadereServices.mock(api: api, clock: tick)
        let model = AppModel(services: services)
        await model.bootstrap()
        return (model, api, clock, services)
    }

    // MARK: IA

    @Test func theBarIsMessagesAlertsBenefitsBusinessesAndSettingsIsSecondary() async {
        #expect(AppTab.allCases == [.messages, .alerts, .benefits, .businesses])
        #expect(AppTab.allCases.map(\.destination) == OrganizationDestination.primary)
        let (model, _, _, _) = await world()
        #expect(model.selectedTab == .alerts)
        await model.handle(.settings)
        #expect(model.settingsPresented)
        #expect(model.selectedTab == .alerts)
    }

    @Test func bootstrapLoadsBusinessesAndTheAlertsReadModel() async {
        let (model, _, _, _) = await world()
        #expect(model.businesses.active.count == 4)
        #expect(model.organization.options.count == 5)
        #expect(model.organization.title == "All businesses")
        #expect(model.organization.accessibilityValue == "Showing all businesses")
        let needsYou = model.alerts.needsYou(context: .all)
        #expect(needsYou.count == 3)
        #expect(model.alerts.badgeCount() == 3)
        // Security first, deterministic.
        #expect(needsYou.first?.purpose == .security)
        // The flight status update is history, never "needs you".
        #expect(model.alerts.history(context: .all).contains { $0.business?.id == PreviewData.juniperAir.id && !$0.actionRequired })
    }

    @Test func selectingABusinessFiltersEveryListAndPersists() async {
        let (model, _, _, services) = await world()
        #expect(model.organization.select(.business(PreviewData.harborBank.id)) == .changed)
        #expect(model.organization.accessibilityValue == "Showing Harbor Bank")
        let context = model.organization.effective
        #expect(model.alerts.needsYou(context: context).allSatisfy { $0.business?.id == PreviewData.harborBank.id })
        #expect(model.messages.visible(context: context).allSatisfy { $0.business.id == PreviewData.harborBank.id })
        // The saved context survives a relaunch (filter only; the server still checks it).
        let relaunched = AppModel(services: services)
        #expect(relaunched.organization.saved == .business(PreviewData.harborBank.id))
        // The selector is one adjustable element: decrement goes back to All.
        #expect(model.organization.adjust(by: -10) == .changed)
        #expect(model.organization.saved == .all)
    }

    // MARK: C9.7 sensitive-flow context safety (WP-1.7 tests first)

    @Test func anApprovalForAnotherBusinessShowsItsIssuerAndNeverChangesTheSavedContext() async throws {
        let (model, api, _, _) = await world()
        model.organization.select(.business(PreviewData.northfield.id))
        let signIn = try #require(try await api.interactions(status: .pending, cursor: nil).items.first { $0.business.id == PreviewData.harborBank.id })
        await model.openInteraction(signIn.id)
        let approval = try #require(model.presentedApproval)
        #expect(approval.envelope.business.id == PreviewData.harborBank.id)       // the sheet names its own issuer
        #expect(model.organization.saved == .business(PreviewData.northfield.id)) // the saved context is untouched
        #expect(model.organization.effective == .business(PreviewData.harborBank.id))
        #expect(model.organization.state.showsTemporaryBanner)                    // "Showing Harbor Bank" with "Back to all"
        // Nothing switches the context while the decision is open.
        #expect(model.organization.select(.all) == .deferredSensitiveFlow)
        #expect(model.organization.returnToSaved() == .deferredSensitiveFlow)
        #expect(model.presentedApproval?.envelope.business.id == PreviewData.harborBank.id)
        // Closing the sheet releases the context; "Back to all" returns to the saved choice.
        model.presentedApproval = nil
        #expect(!model.organization.isSensitiveFlowOpen)
        #expect(model.organization.returnToSaved() == .changed)
        #expect(model.organization.effective == .business(PreviewData.northfield.id))
    }

    @Test func aDeepLinkOrPushCannotSelectABusinessTheCustomerIsNotConnectedTo() async throws {
        let (model, _, _, _) = await world()
        model.organization.select(.business(PreviewData.northfield.id))
        #expect(model.organization.select(.business(PreviewData.copperline.id)) == .notConnected)
        #expect(model.organization.open(itemFrom: PreviewData.copperline.id) == .notConnected)
        await model.handle(.business(try #require(PreviewData.copperline.handle)))
        #expect(model.organization.saved == .business(PreviewData.northfield.id))
        #expect(model.organization.effective == .business(PreviewData.northfield.id))
        #expect(model.selectedTab == .businesses)
    }

    // MARK: D3.T7 stale cache; offline

    @Test func aStaleCacheNeverShowsAnExpiredItemAsActionable() async throws {
        let (model, _, clock, _) = await world()
        let before = model.alerts.needsYou(context: .all)
        #expect(before.allSatisfy { model.alerts.canAct($0) })
        // No sync happens; only time passes beyond every expiry.
        clock.advance(2 * 86_400)
        #expect(model.alerts.needsYou(context: .all).isEmpty)
        #expect(model.alerts.badgeCount() == 0)
        for entry in before {
            #expect(!model.alerts.canAct(entry))
            #expect(model.alerts.displayStatus(entry) == .expired)
        }
        #expect(model.alerts.history(context: .all).filter { $0.actionRequired }.count == before.count)
    }

    @Test func offlineKeepsTheCachedListButDisablesEveryAction() async {
        let (model, api, _, _) = await world()
        let cached = model.alerts.needsYou(context: .all)
        await api.setOrganizationOffline(true)
        await model.alerts.refresh()
        #expect(model.alerts.isOffline)
        #expect(model.alerts.needsYou(context: .all).map(\.alertId) == cached.map(\.alertId))
        #expect(cached.allSatisfy { !model.alerts.canAct($0) })
        await api.setOrganizationOffline(false)
        await model.alerts.refresh()
        #expect(!model.alerts.isOffline)
        #expect(cached.allSatisfy { model.alerts.canAct($0) })
    }

    // MARK: C5.4 push dedupe

    @Test func repeatedPushesForOneEventArePresentedOnceAndFinishedItemsNotAtAll() async throws {
        let (model, _, _, _) = await world()
        let pending = try #require(model.alerts.needsYou(context: .all).first)
        #expect(model.alerts.shouldPresentPush(eventId: pending.eventId))
        #expect(!model.alerts.shouldPresentPush(eventId: pending.eventId))
        let other = try #require(model.alerts.needsYou(context: .all).dropFirst().first)
        model.alerts.markHandled(alertId: other.alertId)
        #expect(!model.alerts.shouldPresentPush(eventId: other.eventId))
        #expect(model.alerts.shouldPresentPush(eventId: "alr_0123456789abcdef0123456789abcdef"))
    }

    @Test func seenMarksClearUnreadAndTheUnreadFilterHonorsThem() async throws {
        let (model, _, _, _) = await world()
        let first = try #require(model.alerts.needsYou(context: .all).first)
        await model.alerts.markSeen([first])
        model.alerts.unreadOnly = true
        #expect(!model.alerts.needsYou(context: .all).contains { $0.alertId == first.alertId })
        await model.alerts.refresh()
        #expect(!model.alerts.needsYou(context: .all).contains { $0.alertId == first.alertId })
    }

    // MARK: C9.2 fifty businesses

    @Test func fiftyBusinessesAreSearchableWithinBudget() {
        var list: [ConnectedBusiness] = []
        for i in 0..<50 {
            let summary = BusinessSummary(id: BusinessID(), displayName: String(format: "Shop %02d", i), handle: try? BusinessHandle(String(format: "shop%02d", i)),
                                          code: BusinessCode.generate(), verificationStatus: .verified)
            list.append(ConnectedBusiness(business: summary, category: nil, relationshipId: RelationshipID(), status: .active, connectedAt: start,
                                          lastActivityAt: start.addingTimeInterval(Double(i)), preferences: BusinessPreferences(businessId: summary.id)))
        }
        let model = BusinessesViewModel(api: nil, initial: list)
        let clock = ContinuousClock()
        let elapsed = clock.measure {
            for _ in 0..<100 {
                model.query = "@shop33"
                _ = model.results
            }
        }
        model.query = "@shop33"
        #expect(model.results.map(\.business.displayName) == ["Shop 33"])
        #expect(elapsed < .milliseconds(500), "100 searches over 50 businesses took \(elapsed)")
        model.query = ""
        #expect(model.results.count == 50)
    }

    // MARK: WP-1.5 block, favorites

    @Test func blockingABusinessRemovesItFromTheSelectorAndFallsBackToAll() async {
        let (model, _, _, _) = await world()
        model.organization.select(.business(PreviewData.harborBank.id))
        let settings = BusinessPreferencesViewModel(business: PreviewData.harborBank, api: model.services.organizationAPI)
        settings.onSaved = { model.businesses.apply($0) }
        await settings.block()
        #expect(settings.preferences.blocked)
        #expect(model.organization.saved == .all)
        #expect(!model.organization.connected.contains(PreviewData.harborBank.id))
        #expect(!model.alerts.needsYou(context: .all).contains { $0.business?.id == PreviewData.harborBank.id })
    }

    @Test func favoritesComeFirstInTheSelectorAndDirectory() async {
        let (model, _, _, _) = await world()
        await model.businesses.setFavorite(PreviewData.lindenStudio.id, true)
        #expect(model.businesses.active.first?.business.id == PreviewData.lindenStudio.id)
        #expect(model.organization.options.dropFirst().first == .business(PreviewData.lindenStudio.id))
    }

    // MARK: Messages, business home

    @Test func messagesGroupByBusinessAndSearchOnDevice() async {
        let (model, _, _, _) = await world()
        await model.messages.load()
        #expect(model.messages.groups(context: .all).map(\.business.id) == [PreviewData.lindenStudio.id])
        model.messages.searchQuery = "linden"
        #expect(model.messages.visible(context: .all).count == 1)
        model.messages.searchQuery = "harbor"
        #expect(model.messages.visible(context: .all).isEmpty)
        model.messages.searchQuery = ""
        #expect(model.messages.visible(context: .business(PreviewData.harborBank.id)).isEmpty)
    }

    @Test func aBusinessHomeRendersNeutralDefaultsAtOnceAndOnlyRegistryModulesFromTheServer() async {
        let (model, api, _, _) = await world()
        let home = BusinessHomeViewModel(business: PreviewData.harborBank, api: model.services.organizationAPI)
        #expect(home.modules.first?.module == "profile")
        #expect(home.modules.map(\.module) == SurfaceLayout.defaultBusinessHome.modules.map(\.module))
        await api.setSurface([SurfaceModule(module: "offers", size: .regular), SurfaceModule(module: "nav_takeover", size: .regular),
                              SurfaceModule(module: "loops", size: .regular)], for: PreviewData.harborBank.id)
        await home.load()
        #expect(home.modules.map(\.module) == ["profile", "offers"])
    }

    @Test func benefitsFilterLocallyByContextAndFilter() async {
        let (services, _) = await p3World()
        let model = AppModel(services: services)
        await model.bootstrap()
        let all = model.benefits.rewards(context: .all)
        #expect(!all.isEmpty)
        let business = all[0].business.id
        #expect(model.benefits.rewards(context: .business(business)).allSatisfy { $0.business.id == business })
        model.benefits.filter = .redeemed
        #expect(model.benefits.rewards(context: .all).allSatisfy { $0.reward.status == .redeemed || $0.eligibility.state == .redeemed })
    }

    @Test func signOutForgetsTheContextAndTheCaches() async {
        let (model, _, _, services) = await world()
        model.organization.select(.business(PreviewData.harborBank.id))
        await model.signOut()
        #expect(model.organization.saved == .all)
        #expect(model.alerts.isEmpty)
        #expect(services.preferences.string(.organizationContext) == nil)
    }
}
