import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

private let t0 = Date(timeIntervalSince1970: 1_800_000_000)

private func delivery(_ kind: AuthDeliveryItem.Kind) -> AuthDeliveryItem {
    AuthDeliveryItem(deliveryId: UUID(), kind: kind, businessId: BusinessID(), business: "Acme", host: kind == .link ? "login.acme.com" : nil,
                     createdAt: t0.addingTimeInterval(-10), expiresAt: t0.addingTimeInterval(300))
}

/// "Show business names on the Lock Screen" (UX_COPY §0 rule 5): off by default, read by the notification service extension.
@Suite("Business names on the Lock Screen")
@MainActor
struct LockScreenBusinessNamesTests {
    @Test func theRowIsSearchableInsideNotificationsAndNotOnTheYouPage() {
        let row = SettingsDestination.lockScreenBusinessNames
        #expect(row.title == "Show business names on the Lock Screen")
        #expect(row.group == .notifications && row.screen == .notifications && !row.isTopLevel)
        #expect(!SettingsCatalog.rows(in: .notifications).contains(row))
        #expect(SettingsCatalog.search("business names").first == row)
        #expect(SettingsCatalog.search("hide names") == [row])
        #expect(SettingsCatalog.search("lock screen").contains(row))
        #expect(!row.symbol.contains("shield"))
        #expect(LockScreenBusinessNamesSetting.label == row.title)
        let sentence = LockScreenBusinessNamesSetting.explanation
        #expect(sentence.filter { $0 == "." }.count == 1 && sentence.hasSuffix("."), "one sentence")
    }

    @Test func offByDefaultTurningOnNeedsAuthenticationAndOffNeverDoes() async {
        var services = await ViadereServices.mock(api: MockViadereAPI(seed: false))
        #expect(!services.preferences.bool(.lockScreenBusinessNames))
        let model = SecuritySettingsViewModel(services: services)
        #expect(!model.lockScreenBusinessNamesEnabled)

        services.appLock = MockAppLockAuthenticator(succeeds: false)
        let denied = SecuritySettingsViewModel(services: services)
        await denied.setLockScreenBusinessNames(true)
        #expect(!denied.lockScreenBusinessNamesEnabled && !services.preferences.bool(.lockScreenBusinessNames))

        await model.setLockScreenBusinessNames(true)
        #expect(model.lockScreenBusinessNamesEnabled && services.preferences.bool(.lockScreenBusinessNames))
        // Turning names off never needs authentication.
        let off = SecuritySettingsViewModel(services: services)
        await off.setLockScreenBusinessNames(false)
        #expect(!off.lockScreenBusinessNamesEnabled && !services.preferences.bool(.lockScreenBusinessNames))
    }

    @Test func authDeliveryLinesNameNoBusinessWhenOff() {
        let cases: [(AuthDeliveryItem.Kind, String, String)] = [
            (.link, AuthNotificationCategory.link, AuthDeliveryCopy.n02BodyNameless),
            (.code(.otp), AuthNotificationCategory.code, AuthDeliveryCopy.n05BodyNameless),
            (.notice, AuthNotificationCategory.notice, AuthDeliveryCopy.n06BodyNameless),
        ]
        for (kind, category, body) in cases {
            let hidden = AuthDeliveryNotificationText.make(item: delivery(kind), category: category, now: t0, showsBusinessName: false)
            #expect(hidden == AuthDeliveryNotificationText(title: "Viadere", body: body))
            #expect(!hidden.title.contains("Acme") && !hidden.body.contains("Acme"))
            let shown = AuthDeliveryNotificationText.make(item: delivery(kind), category: category, now: t0, showsBusinessName: true)
            #expect(shown.title == "Acme")
        }
        // The other rules still hold without names: a category that does not match the method is the generic line.
        #expect(AuthDeliveryNotificationText.make(item: delivery(.link), category: AuthNotificationCategory.code, now: t0, showsBusinessName: false) == .generic)
    }

    @Test func theEnricherNamesNoBusinessAndAttachesNoLogoWhenOff() async throws {
        let api = MockViadereAPI(seed: false)
        let sensitive = PreviewData.authorize(sensitivity: .high)
        let confirm = PreviewData.confirm(business: PreviewData.northfield)
        await api.add(sensitive)
        await api.add(confirm)
        let name = "Northfield"

        // No store at all, and a store with the default: no name anywhere, no brand context for a logo.
        for enricher in [NotificationEnricher(api: api), NotificationEnricher(api: api, preferences: InMemoryPreferences())] {
            let security = await enricher.enrich(interactionId: sensitive.interaction.id)
            #expect(security.title == "Viadere")
            #expect(!security.title.contains(name) && !security.subtitle.contains(name) && !security.body.contains(name))
            #expect(security.body == NotificationEnricher.namelessBody(for: sensitive.interaction.kind, verified: true))
            let other = await enricher.enrich(interactionId: confirm.interaction.id)
            #expect(other.title == "Viadere" && other.brand == nil)
        }

        let names = InMemoryPreferences()
        names.setBool(true, for: .lockScreenBusinessNames)
        let shown = await NotificationEnricher(api: api, preferences: names).enrich(interactionId: sensitive.interaction.id)
        #expect(shown.title == "Northfield Market")
        #expect(shown.body.contains(name) && !shown.body.contains("$285.28"), "a name, still no amount without detailed previews")
        let shownOther = await NotificationEnricher(api: api, preferences: names).enrich(interactionId: confirm.interaction.id)
        #expect(shownOther.brand != nil)

        // Detailed previews ("Who, amount and place") name the business by definition.
        let rich = InMemoryPreferences()
        rich.setBool(true, for: .richNotificationPreviews)
        #expect(await NotificationEnricher(api: api, preferences: rich).enrich(interactionId: sensitive.interaction.id).title == "Northfield Market")
    }
}
