import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

/// The account-wide notification level and quiet hours on the device (SECURITY.md §2.96), and the per-Loop alerts choice (§2.98, F-4).
@Suite("Notification settings (Kit)")
@MainActor
struct NotificationSettingsKitTests {
    nonisolated static let toronto = TimeZone(identifier: "America/Toronto")!
    let start = Date(timeIntervalSince1970: 1_800_000_000)

    func world() async -> (model: AppModel, api: MockViadereAPI) {
        let tick: @Sendable () -> Date = { Date(timeIntervalSince1970: 1_800_000_000) }
        let api = MockViadereAPI(seed: true, clock: tick)
        let services = await ViadereServices.mock(api: api, clock: tick)
        let model = AppModel(services: services)
        await model.bootstrap()
        return (model, api)
    }

    // MARK: Default level

    @Test func theDefaultStartsAtEverythingAndMapsToTheThreeLevels() async {
        let (model, _) = await world()
        #expect(model.notificationSettings.hasLoaded)
        #expect(model.notificationSettings.preset == .everything)
        #expect(!model.notificationSettings.quietHoursEnabled)
        #expect(model.notificationSettings.rowSummary == "Everything")
        for preset in InterruptionPreset.allCases {
            #expect(InterruptionPreset(preset.muteLevel) == preset)
        }
        #expect(InterruptionPreset.essentials.title == "Only what matters")
        #expect(NotificationSettingsViewModel.securityNote.contains("Sign-in approvals"))
    }

    @Test func choosingALevelSavesAndASecondDeviceSeesIt() async {
        let (model, api) = await world()
        await model.notificationSettings.setPreset(.essentials)
        #expect(model.notificationSettings.preset == .essentials)
        #expect(model.notificationSettings.errorMessage == nil)
        #expect(model.notificationSettings.rowSummary == "Only what matters")
        let other = NotificationSettingsViewModel(api: model.services.organizationAPI)
        await other.load()
        #expect(other.preset == .essentials)
        _ = api
    }

    @Test func aRefusedSaveRollsBackAndSays() async {
        let (model, api) = await world()
        await api.setOrganizationOffline(true)
        await model.notificationSettings.setPreset(.balanced)
        #expect(model.notificationSettings.preset == .everything, "rolled back")
        #expect(model.notificationSettings.errorMessage != nil)
        await api.setOrganizationOffline(false)
        await model.notificationSettings.setPreset(.balanced)
        #expect(model.notificationSettings.preset == .balanced)
        #expect(model.notificationSettings.errorMessage == nil)
    }

    // MARK: Quiet hours

    @Test func quietHoursStartAtTenToSevenInTheDeviceZoneAndAreEditable() async {
        let (model, _) = await world()
        let settings = NotificationSettingsViewModel(api: model.services.organizationAPI, timeZone: { Self.toronto })
        await settings.setQuietHours(enabled: true)
        #expect(settings.quietHoursEnabled)
        #expect(settings.settings.quietHours == QuietHours(startMinute: 22 * 60, endMinute: 7 * 60, timeZone: "America/Toronto"))
        #expect(settings.startMinute == 1_320 && settings.endMinute == 420)
        await settings.setQuietHours(startMinute: 23 * 60, endMinute: 6 * 60 + 30)
        #expect(settings.settings.quietHours?.startMinute == 1_380)
        #expect(settings.settings.quietHours?.endMinute == 390)
        // Start equal to end, or a time outside a day, is refused locally and changes nothing.
        await settings.setQuietHours(startMinute: 600, endMinute: 600)
        #expect(settings.settings.quietHours?.startMinute == 1_380)
        #expect(settings.errorMessage != nil)
        await settings.setQuietHours(startMinute: -1, endMinute: 600)
        #expect(settings.settings.quietHours?.startMinute == 1_380)
        // The level is kept while quiet hours change, and the row says both.
        await settings.setPreset(.balanced)
        #expect(settings.rowSummary.hasPrefix("Balanced · Quiet "))
        await settings.setQuietHours(enabled: false)
        #expect(settings.settings.quietHours == nil)
        #expect(settings.preset == .balanced)
        #expect(settings.quietHoursSummary == "Off")
        // Editing while off does nothing.
        await settings.setQuietHours(startMinute: 60, endMinute: 120)
        #expect(settings.settings.quietHours == nil)
    }

    @Test func theWindowFollowsTheDeviceToANewTimeZone() async {
        let (model, _) = await world()
        let zone = ZoneBox(Self.toronto)
        let settings = NotificationSettingsViewModel(api: model.services.organizationAPI, timeZone: { zone.value })
        await settings.setQuietHours(enabled: true)
        await settings.syncTimeZone()
        #expect(settings.settings.quietHours?.timeZone == "America/Toronto", "nothing to sync")
        zone.value = TimeZone(identifier: "Europe/Paris")!
        await settings.syncTimeZone()
        #expect(settings.settings.quietHours == QuietHours(startMinute: 1_320, endMinute: 420, timeZone: "Europe/Paris"))
        // Without quiet hours there is nothing to sync.
        await settings.setQuietHours(enabled: false)
        await settings.syncTimeZone()
        #expect(settings.settings.quietHours == nil)
    }

    @Test func quietHoursKnowWhenTheyApply() async {
        let (model, _) = await world()
        let settings = NotificationSettingsViewModel(api: model.services.organizationAPI, timeZone: { Self.toronto })
        #expect(!settings.isQuiet(at: start))
        await settings.setQuietHours(enabled: true)
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = Self.toronto
        let midnight = calendar.date(from: DateComponents(year: 2027, month: 1, day: 15, hour: 0, minute: 30))!
        let noon = calendar.date(from: DateComponents(year: 2027, month: 1, day: 15, hour: 12))!
        #expect(settings.isQuiet(at: midnight))
        #expect(!settings.isQuiet(at: noon))
    }

    @Test func timeConversionsRoundTripThroughDatePickers() {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = Self.toronto
        for minute in [0, 59, 60, 420, 1_320, 1_439] {
            let date = NotificationSettingsViewModel.date(minute: minute, calendar: calendar, reference: start)
            #expect(NotificationSettingsViewModel.minute(of: date, calendar: calendar) == minute)
        }
        #expect(NotificationSettingsViewModel.timeLabel(minute: 22 * 60, locale: Locale(identifier: "en_US")).contains("10:00"))
        #expect(NotificationSettingsViewModel.timeLabel(minute: 7 * 60, locale: Locale(identifier: "en_US")).contains("7:00"))
        #expect(!NotificationSettingsViewModel.timeLabel(minute: 99_999).isEmpty)
    }

    @Test func signOutForgetsTheSettings() async {
        let (model, _) = await world()
        await model.notificationSettings.setPreset(.essentials)
        await model.signOut()
        #expect(model.notificationSettings.preset == .everything)
        #expect(!model.notificationSettings.hasLoaded)
    }

    // MARK: Businesses inherit the default

    @Test func aBusinessFollowsTheDefaultUntilItHasItsOwnLevelAndCanFollowAgain() async {
        let (model, _) = await world()
        let id = PreviewData.harborBank.id
        let now = model.services.clock()
        let before = model.businesses.entry(id)?.preferences
        #expect(before?.hasOwnLevel == false)
        #expect(before?.effectiveLevel(accountDefault: .allNonEssential, at: now) == .allNonEssential)
        #expect(model.businesses.quietedCount(at: now) == 0)
        let everyone = model.businesses.active.count
        #expect(model.businesses.quietedCount(at: now, accountDefault: .promotional) == everyone, "every business inherits a quieter default")
        await model.businesses.setMute(id, MuteLevel.none)
        #expect(model.businesses.entry(id)?.preferences.hasOwnLevel == true)
        #expect(model.businesses.quietedCount(at: now, accountDefault: .promotional) == everyone - 1, "an explicit Everything keeps its own level")
        await model.businesses.followDefault(id)
        #expect(model.businesses.entry(id)?.preferences.hasOwnLevel == false)
        #expect(model.businesses.quietedCount(at: now, accountDefault: .promotional) == everyone)
        let single = BusinessPreferencesViewModel(business: PreviewData.harborBank, api: model.services.organizationAPI)
        await single.setMute(.promotional)
        #expect(single.preferences.hasOwnLevel)
        await single.followDefault()
        #expect(!single.preferences.hasOwnLevel)
        #expect(single.preferences.muteLevel == MuteLevel.none)
        #expect(InterruptionPreset.balanced.followingSummary() == "Following your default: Balanced")
    }

    // MARK: Alerts from an installed Loop (F-4)

    @Test func theInstallSheetOffersAlertsOffAndSendsTheChoice() async throws {
        let api = MockLoopsAPI(connected: [])
        let listed = await api.publish(MockLoopsAPI.pickupDefinition, business: PreviewData.northfield.id, category: .foodAndDrink, featured: true)
        let consent = LoopConsentViewModel(api: api)
        consent.adopt(try await api.enableLoops(LoopGlobalConsentRequest(textVersion: LP.text.version, textDigest: LP.text.digest, answers: LP.answers, agree: true)))
        let library = LoopLibraryViewModel(api: api, consent: { consent.status })
        let loopId = try #require(listed.loopId)
        let model = LoopDetailViewModel(loopId: loopId, source: .directory, api: api, keys: { [MockLoopsAPI.pinnedKey] }, consent: { consent.status },
                                        library: library, onConsent: { consent.adopt($0) })
        await model.load()
        #expect(!model.alertsEnabled, "off unless the customer chooses it")
        #expect(model.alertsTitle == "Alerts from this Loop")
        #expect(model.alertsDetail.contains("no offers") && model.alertsDetail.contains("no messages") && model.alertsDetail.contains(PreviewData.northfield.safeName))
        guard case .installed(let off) = await model.install() else { Issue.record("install failed"); return }
        #expect(!off.alertsEnabled)

        // Choosing it at install time.
        let chosen = LoopDetailViewModel(loopId: loopId, source: .directory, api: api, keys: { [MockLoopsAPI.pinnedKey] }, consent: { consent.status },
                                         library: library, onConsent: { consent.adopt($0) })
        await chosen.load()
        chosen.alertsEnabled = true
        guard case .installed(let on) = await chosen.install() else { Issue.record("install failed"); return }
        #expect(on.alertsEnabled)
        #expect(library.loops.first?.alertsEnabled == true)
    }

    @Test func yourLoopsTurnsAlertsOnAndOffAndRollsBackWhenRefused() async throws {
        let api = MockLoopsAPI(connected: [])
        let listed = await api.publish(MockLoopsAPI.pickupDefinition, business: PreviewData.northfield.id, category: .foodAndDrink, featured: true)
        let consent = LoopConsentViewModel(api: api)
        consent.adopt(try await api.enableLoops(LoopGlobalConsentRequest(textVersion: LP.text.version, textDigest: LP.text.digest, answers: LP.answers, agree: true)))
        let library = LoopLibraryViewModel(api: api, consent: { consent.status })
        let loopId = try #require(listed.loopId)
        _ = try await api.install(loopId, LoopInstallRequest(mode: .installOnly, source: .directory, textVersion: LP.text.version, textDigest: LP.text.digest, agree: true))
        await library.load()
        #expect(library.loops.first?.alertsEnabled == false)
        #expect(await library.setAlerts(loopId, enabled: true))
        #expect(library.loops.first?.alertsEnabled == true)
        #expect(await library.setAlerts(loopId, enabled: false))
        #expect(library.loops.first?.alertsEnabled == false)
        // A Loop that is no longer installed: the choice is rolled back and the reason shown.
        _ = try await api.uninstall(loopId)
        #expect(await library.setAlerts(loopId, enabled: true) == false)
        #expect(library.loops.first?.alertsEnabled == false)
        #expect(library.errorMessage != nil)
        // Unknown Loops are ignored locally.
        #expect(await library.setAlerts(LoopDefinitionID(), enabled: true) == false)
    }
}

/// A time zone the test can change.
final class ZoneBox: @unchecked Sendable {
    private let lock = NSLock()
    private var zone: TimeZone
    init(_ zone: TimeZone) { self.zone = zone }
    var value: TimeZone {
        get { lock.lock(); defer { lock.unlock() }; return zone }
        set { lock.lock(); zone = newValue; lock.unlock() }
    }
}
