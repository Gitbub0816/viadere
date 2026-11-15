import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

/// docs/APP-IA.md: the You tab's catalog and search, the security summary, interruption presets, permission summaries, and the
/// directory actions added with the reorganization (business-by-business quiet levels, unblock, reconnect).
@Suite("App IA (Kit)")
@MainActor
struct AppIATests {
    // MARK: Settings catalog

    @Test func everyDestinationBelongsToOneGroupAndTopLevelRowsFollowTheGroupOrder() {
        for group in SettingsGroup.allCases {
            let rows = SettingsCatalog.rows(in: group)
            #expect(!rows.isEmpty, "\(group) has rows")
            #expect(rows.allSatisfy { $0.group == group && $0.isTopLevel })
        }
        // Items inside the Notifications screen are not repeated on the You page, but search still finds them.
        #expect(!SettingsCatalog.rows(in: .notifications).contains(.lockScreenDetails))
        #expect(SettingsCatalog.search("lock screen").first == .lockScreenDetails)
        #expect(SettingsDestination.lockScreenDetails.screen == .notifications)
        #expect(SettingsDestination.appLock.screen == nil)
        #expect(SettingsDestination.devices.screen == .devices)
        // Appearance has its own place (the appearance picker is wired there).
        #expect(SettingsCatalog.rows(in: .appearance) == [.appearance])
    }

    @Test func searchMatchesTitlesFirstThenKeywordsAndIgnoresCaseAndAccents() {
        #expect(SettingsCatalog.search("").isEmpty)
        #expect(SettingsCatalog.search("   ").isEmpty)
        #expect(SettingsCatalog.search("Trusted").first == .devices)
        #expect(SettingsCatalog.search("face id").contains(.appLock))
        #expect(SettingsCatalog.search("FREEZE").first == .approvals)
        #expect(SettingsCatalog.search("dark mode") == [.appearance])
        #expect(SettingsCatalog.search("récovery").first == .recovery)
        // Every word must match somewhere.
        #expect(SettingsCatalog.search("recovery zebra").isEmpty)
        // A title match ranks above a keyword match ("passkeys" is a title word of nothing, a keyword of Authenticator and Recovery).
        let codes = SettingsCatalog.search("codes")
        #expect(codes.first == .recovery)
        #expect(codes.contains(.authenticator))
    }

    @Test func unavailableFeaturesAreHiddenFromRowsAndSearch() {
        let limited = SettingsAvailability(recovery: false, phones: false, sessions: true, household: false, acknowledgments: false, loops: false)
        #expect(!SettingsCatalog.rows(in: .security, available: limited).contains(.recovery))
        #expect(!SettingsCatalog.rows(in: .account, available: limited).contains(.household))
        #expect(!SettingsCatalog.search("recovery", available: limited).contains(.recovery))
        #expect(SettingsCatalog.search("built by", available: limited).isEmpty)
        #expect(SettingsCatalog.rows(in: .records, available: limited) == [.dataExport])
    }

    // MARK: Security summary

    @Test func theWeakestFactWinsTheSecurityHeadline() {
        let strong = SecurityPosture.summarize(assurance: .biometric, appLock: true, activeDevices: 2, recoveryRemaining: 8, approvalsFrozen: false)
        #expect(strong.level == .strong)
        #expect(strong.detail == "Face ID approvals · App lock on · 2 trusted devices")
        let good = SecurityPosture.summarize(assurance: .biometric, appLock: false, activeDevices: 1, recoveryRemaining: nil, approvalsFrozen: false)
        #expect(good.level == .good && good.detail.contains("1 trusted device"))
        let noCodes = SecurityPosture.summarize(assurance: .biometric, appLock: true, activeDevices: 1, recoveryRemaining: 0, approvalsFrozen: false)
        #expect(noCodes.level == .needsAttention && noCodes.headline == "Create recovery codes")
        let frozen = SecurityPosture.summarize(assurance: .biometric, appLock: true, activeDevices: 1, recoveryRemaining: 0, approvalsFrozen: true)
        #expect(frozen.headline == "Approvals are frozen")
        let basic = SecurityPosture.summarize(assurance: DecisionAssurance.none, appLock: false, activeDevices: 1, recoveryRemaining: 3, approvalsFrozen: false)
        #expect(basic.level == .needsAttention)
        let loading = SecurityPosture.summarize(assurance: nil, appLock: false, activeDevices: 0, recoveryRemaining: nil, approvalsFrozen: false)
        #expect(loading.detail == "App lock off · 0 trusted devices")
    }

    // MARK: Interruption presets

    @Test func presetsMapOneToOneOntoMuteLevels() {
        for level in MuteLevel.allCases { #expect(InterruptionPreset(level).muteLevel == level) }
        #expect(InterruptionPreset.allCases.map(\.intensity) == [3, 2, 1])
        #expect(InterruptionPreset.everything.summary(until: Date(), now: Date()) == "Everything")
        #expect(InterruptionPreset.balanced.summary(until: nil, now: Date()) == "Balanced")
        #expect(InterruptionPreset.essentials.explanation(business: "Harbor Bank").contains("security checks"))
    }

    @Test func theDurationStepperWalksShortestToLongestAndClamps() {
        typealias Duration = BusinessPreferencesViewModel.MuteDuration
        #expect(Duration.hour.stepped(by: -1) == .hour)
        #expect(Duration.hour.stepped(by: 1) == .day)
        #expect(Duration.week.stepped(by: 1) == .untilChanged)
        #expect(Duration.untilChanged.stepped(by: 1) == .untilChanged)
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        #expect(Duration.closest(to: nil, now: now) == .untilChanged)
        #expect(Duration.closest(to: now.addingTimeInterval(1_800), now: now) == .hour)
        #expect(Duration.closest(to: now.addingTimeInterval(20_000), now: now) == .day)
        #expect(Duration.closest(to: now.addingTimeInterval(500_000), now: now) == .week)
    }

    // MARK: Permission summary

    @Test func thePermissionSummaryNamesWhatIsOnBeyondTheEssentials() {
        let all = PermissionCopy.rows(supported: InteractionPurpose.allCases, granted: [.marketing: true, .rewards: true])
        #expect(PermissionCopy.summary(all) == "Orders, support, offers and rewards")
        let defaults = PermissionCopy.rows(supported: InteractionPurpose.allCases, granted: [:])
        #expect(PermissionCopy.summary(defaults).hasPrefix("Orders"))
        let none = PermissionCopy.rows(supported: InteractionPurpose.allCases,
                                       granted: [.transactional: false, .support: false, .marketing: false, .rewards: false])
        #expect(PermissionCopy.summary(none) == "Only security and account notices")
        // Orders are essential (always listed); switched off here, so offers are the only extra.
        let one = PermissionCopy.rows(supported: [.marketing], granted: [.marketing: true, .transactional: false])
        #expect(PermissionCopy.summary(one) == "Offers and essentials")
    }

    // MARK: Directory actions

    func world() async -> (AppModel, MockViadereAPI) {
        let api = MockViadereAPI(seed: true)
        let services = await ViadereServices.mock(api: api)
        let model = AppModel(services: services)
        await model.bootstrap()
        return (model, api)
    }

    @Test func quietingABusinessFromTheNotificationsScreenIsSavedAndCounted() async throws {
        let (model, _) = await world()
        let id = try #require(model.businesses.active.first?.business.id)
        #expect(model.businesses.quietedCount(at: Date()) == 0)
        await model.businesses.setMute(id, .promotional)
        #expect(model.businesses.entry(id)?.preferences.muteLevel == .promotional)
        #expect(model.businesses.quietedCount(at: Date()) == 1)
        await model.businesses.setMute(id, MuteLevel.none)
        #expect(model.businesses.quietedCount(at: Date()) == 0)
    }

    @Test func aFailedQuietLevelChangeRollsBack() async throws {
        let (model, api) = await world()
        let id = try #require(model.businesses.active.first?.business.id)
        await api.setOrganizationOffline(true)
        await model.businesses.setMute(id, .allNonEssential)
        #expect(model.businesses.entry(id)?.preferences.muteLevel == MuteLevel.none)
        #expect(model.businesses.errorMessage != nil)
    }

    @Test func aBlockedBusinessCanBeUnblockedAndThenReconnectedFromItsCode() async throws {
        let (model, _) = await world()
        let business = PreviewData.harborBank
        let settings = BusinessPreferencesViewModel(business: business, api: model.services.organizationAPI)
        settings.onSaved = { model.businesses.apply($0) }
        await settings.block()
        #expect(model.businesses.entry(business.id)?.preferences.blocked == true)
        #expect(model.businesses.entry(business.id)?.isActive == false)

        #expect(await model.businesses.unblock(business.id))
        #expect(model.businesses.entry(business.id)?.preferences.blocked == false)
        // Unblocking does not reconnect by itself: the connect review asks again.
        #expect(model.businesses.entry(business.id)?.isActive == false)
        model.reconnect(business)
        #expect(model.selectedTab == .businesses && model.addBusinessPresented)
        #expect(model.pendingConnect?.code == business.code)
    }

    @Test func archivedConversationsSurviveAReloadAndCanBeRestored() async throws {
        let (model, _) = await world()
        await model.messages.load()
        let thread = try #require(model.messages.visible(context: .all).first)
        await model.messages.setArchived(thread.id, true)
        await model.messages.load() // the server keeps the mark; the thread is hidden, not lost
        #expect(!model.messages.visible(context: .all).contains { $0.id == thread.id })
        #expect(model.messages.archived(context: .all).map(\.id) == [thread.id])
        #expect(model.messages.archived(context: .business(BusinessID())).isEmpty)
        await model.messages.setArchived(thread.id, false)
        await model.messages.load()
        #expect(model.messages.visible(context: .all).contains { $0.id == thread.id })
        #expect(model.messages.archived(context: .all).isEmpty)
    }

    @Test func aBusinessThatWasNeverConnectedCannotBeUnblocked() async {
        let (model, _) = await world()
        #expect(await model.businesses.unblock(BusinessID()) == false)
    }
}
