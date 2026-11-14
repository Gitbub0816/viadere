import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

private let t0 = Date(timeIntervalSince1970: 1_800_000_000)

@Suite("Home Screen widget (snapshot, timeline, writer)")
@MainActor
struct HomeWidgetTests {
    @Test func theSnapshotHoldsOnlyNumbersAndTimes() throws {
        let snapshot = WidgetSnapshot(waiting: [t0.addingTimeInterval(60), nil, t0.addingTimeInterval(-1)], benefitsAvailable: 3, now: t0)
        let object = try #require(try JSONSerialization.jsonObject(with: JSONEncoder().encode(snapshot)) as? [String: Any])
        #expect(Set(object.keys) == ["u", "o", "b", "t"], "no field could hold a name, an amount, a code or a message")
        #expect(snapshot.waitingUntil == [t0.addingTimeInterval(60)], "an already-expired request is dropped")
        #expect(snapshot.waitingOpenEnded == 1 && snapshot.benefitsAvailable == 3)
        let labels = Set(Mirror(reflecting: snapshot).children.compactMap(\.label))
        #expect(labels == ["waitingUntil", "waitingOpenEnded", "benefitsAvailable", "updatedAt"])
    }

    @Test func entriesSayHowManyWaitAndNothingElse() {
        let snapshot = WidgetSnapshot(waiting: [t0.addingTimeInterval(60), t0.addingTimeInterval(120)], benefitsAvailable: 1, now: t0)
        let now = WidgetEntryContent(date: t0, snapshot: snapshot)
        #expect(now.state == .waiting(2) && now.count == "2" && now.headline == "requests waiting")
        #expect(now.benefitsLine == "1 benefit available")
        #expect(now.accessibilityLabel == "Viadere. 2 requests waiting. 1 benefit available.")
        let later = WidgetEntryContent(date: t0.addingTimeInterval(61), snapshot: snapshot)
        #expect(later.state == .waiting(1) && later.headline == "request waiting")
        let clear = WidgetEntryContent(date: t0.addingTimeInterval(121), snapshot: snapshot)
        #expect(clear.state == .clear && clear.count == nil && clear.headline == "Nothing needs you")
        let many = WidgetEntryContent(date: t0, snapshot: WidgetSnapshot(waiting: Array(repeating: nil, count: 140), now: t0))
        #expect(many.count == "99+")
    }

    @Test func withoutATrustworthySnapshotTheWidgetIsNeutral() {
        #expect(WidgetEntryContent(date: t0, snapshot: nil).state == .neutral)
        #expect(WidgetEntryContent.placeholder(date: t0).count == nil && WidgetEntryContent.placeholder(date: t0).headline == "Open Viadere")
        let snapshot = WidgetSnapshot(waiting: [nil], now: t0)
        #expect(WidgetEntryContent(date: t0.addingTimeInterval(WidgetSnapshot.staleAfter), snapshot: snapshot).state == .neutral, "too old")
        #expect(WidgetEntryContent(date: t0.addingTimeInterval(-3_600), snapshot: snapshot).state == .neutral, "written in the future")
    }

    @Test func theTimelineDropsTheCountAsEachRequestExpiresThenGoesNeutral() {
        let snapshot = WidgetSnapshot(waiting: [t0.addingTimeInterval(60), t0.addingTimeInterval(60), t0.addingTimeInterval(300)], now: t0)
        let entries = WidgetTimelineModel.entries(snapshot: snapshot, now: t0)
        #expect(entries.map(\.date) == [t0, t0.addingTimeInterval(60), t0.addingTimeInterval(300), t0.addingTimeInterval(WidgetSnapshot.staleAfter)])
        #expect(entries.map(\.state) == [.waiting(3), .waiting(1), .clear, .neutral])
        #expect(WidgetTimelineModel.entries(snapshot: nil, now: t0).map(\.state) == [.neutral])
        let crowded = WidgetSnapshot(waiting: (1...80).map { t0.addingTimeInterval(TimeInterval($0)) }, now: t0)
        #expect(WidgetTimelineModel.entries(snapshot: crowded, now: t0).count <= WidgetTimelineModel.maxEntries)
    }

    @Test func theStoreRefusesWhatItCannotTrustAndWritesOnlyChanges() throws {
        let persistence = InMemoryWidgetSnapshotPersistence()
        let store = WidgetSnapshotStore(persistence: persistence)
        #expect(store.read() == nil)
        #expect(store.write(waiting: [nil], now: t0))
        #expect(!store.write(waiting: [nil], now: t0.addingTimeInterval(60)), "same content within the hour: no write, no reload")
        #expect(store.write(waiting: [nil], now: t0.addingTimeInterval(3_601)), "hourly rewrite keeps it fresh")
        #expect(store.write(waiting: [nil, nil], now: t0.addingTimeInterval(3_602)))
        #expect(store.read()?.waitingCount(at: t0.addingTimeInterval(3_602)) == 2)

        persistence.save(Data(#"{"u":[],"o":5000,"t":0}"#.utf8))
        #expect(store.read() == nil, "an out-of-range count is not shown")
        persistence.save(Data("not json".utf8))
        #expect(store.read() == nil)
        #expect(store.clear() && persistence.load() == nil && !store.clear())
    }

    @Test func theWriterMergesAlertsAndDeliveriesAndReloadsOnlyOnChange() async {
        let store = WidgetSnapshotStore(persistence: InMemoryWidgetSnapshotPersistence())
        var reloads = 0
        let writer = HomeWidgetWriter(store: store, clock: { t0 }, reload: { reloads += 1 })
        let alerts = AlertsViewModel(api: nil, clock: { t0 })
        let api = MockAuthDeliveryAPI()
        await api.add(AuthDeliveryItem(deliveryId: UUID(), kind: .code(.otp), businessId: BusinessID(), business: "Acme", createdAt: t0,
                                       expiresAt: t0.addingTimeInterval(300)))
        await api.add(AuthDeliveryItem(deliveryId: UUID(), kind: .notice, businessId: BusinessID(), business: "Acme", createdAt: t0,
                                       expiresAt: t0.addingTimeInterval(300)))
        let inbox = AuthDeliveryInboxViewModel(api: api, clock: { t0 })
        await inbox.refresh()

        writer.publish(alerts: alerts)
        #expect(reloads == 1 && store.read()?.waitingCount(at: t0) == 0)
        writer.publish(deliveries: inbox)
        #expect(reloads == 2 && store.read()?.waitingCount(at: t0) == 1, "the code counts; the notice asks for nothing")
        writer.publish(alerts: alerts)
        #expect(reloads == 2 && store.read()?.waitingCount(at: t0) == 1, "an alerts refresh keeps the deliveries' count")
        writer.clear()
        #expect(reloads == 3 && store.read() == nil)
        writer.clear()
        #expect(reloads == 3)
    }
}

@Suite("Live Activity details setting (F-09)")
@MainActor
struct LiveActivityDetailsSettingTests {
    @Test func theRowIsSearchableInsideNotificationsAndNotOnTheYouPage() {
        #expect(SettingsDestination.liveActivityDetails.group == .notifications)
        #expect(SettingsDestination.liveActivityDetails.screen == .notifications)
        #expect(!SettingsDestination.liveActivityDetails.isTopLevel)
        #expect(!SettingsCatalog.rows(in: .notifications).contains(.liveActivityDetails))
        #expect(SettingsCatalog.search("live activity").first == .liveActivityDetails)
        #expect(SettingsCatalog.search("dynamic island") == [.liveActivityDetails])
        #expect(SettingsCatalog.search("lock screen").contains(.liveActivityDetails))
        #expect(!SettingsDestination.liveActivityDetails.symbol.contains("shield"))
        #expect(LiveActivityDetailsSetting.label == SettingsDestination.liveActivityDetails.title)
        let sentence = LiveActivityDetailsSetting.explanation
        #expect(sentence.filter { $0 == "." }.count == 1 && sentence.hasSuffix("."), "one sentence")
    }

    @Test func offByDefaultEnablingNeedsAuthenticationAndTheLiveActivityFollows() async {
        var services = await ViadereServices.mock(api: MockViadereAPI(seed: false))
        let model = SecuritySettingsViewModel(services: services)
        #expect(!model.liveActivityDetailsEnabled && LiveActivityDisclosure(preferences: services.preferences) == .neutral)

        services.appLock = MockAppLockAuthenticator(succeeds: false)
        let denied = SecuritySettingsViewModel(services: services)
        await denied.setLiveActivityDetails(true)
        #expect(!denied.liveActivityDetailsEnabled && LiveActivityDisclosure(preferences: services.preferences) == .neutral)

        await model.setLiveActivityDetails(true)
        #expect(model.liveActivityDetailsEnabled && LiveActivityDisclosure(preferences: services.preferences) == .detailed)
        // Turning details off never needs authentication.
        let offModel = SecuritySettingsViewModel(services: services)
        await offModel.setLiveActivityDetails(false)
        #expect(!offModel.liveActivityDetailsEnabled && LiveActivityDisclosure(preferences: services.preferences) == .neutral)
    }
}
