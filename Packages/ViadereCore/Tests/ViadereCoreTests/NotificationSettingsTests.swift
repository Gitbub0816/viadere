import Foundation
import Testing
@testable import ViadereCore

/// Account-wide default level, quiet hours and the Loop alerts choice (SECURITY.md §2.96 "Notification level and quiet hours", §2.98).
@Suite("Notification settings and policy")
struct NotificationSettingsTests {
    /// 2027-01-15 12:00:00 UTC = 07:00 in Toronto (EST), 04:00 in Los Angeles (PST), 21:00 in Tokyo.
    static let noon = Date(timeIntervalSince1970: 1_800_014_400)

    func at(hour: Int, minute: Int = 0, zone: String) -> Date {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: zone)!
        return calendar.date(from: DateComponents(year: 2027, month: 1, day: 15, hour: hour, minute: minute))!
    }

    // MARK: Quiet hours

    @Test func windowThatCrossesMidnight() {
        let night = QuietHours(startMinute: 22 * 60, endMinute: 7 * 60, timeZone: "America/Toronto")
        #expect(night.isValid)
        #expect(night.contains(at(hour: 22, zone: "America/Toronto")))
        #expect(night.contains(at(hour: 23, minute: 59, zone: "America/Toronto")))
        #expect(night.contains(at(hour: 0, zone: "America/Toronto")))
        #expect(night.contains(at(hour: 6, minute: 59, zone: "America/Toronto")))
        #expect(!night.contains(at(hour: 7, zone: "America/Toronto")))
        #expect(!night.contains(at(hour: 12, zone: "America/Toronto")))
        #expect(!night.contains(at(hour: 21, minute: 59, zone: "America/Toronto")))
    }

    @Test func sameDayWindowEndsExclusive() {
        let lunch = QuietHours(startMinute: 12 * 60, endMinute: 13 * 60, timeZone: "UTC")
        #expect(lunch.contains(at(hour: 12, zone: "UTC")))
        #expect(!lunch.contains(at(hour: 13, zone: "UTC")))
        #expect(!lunch.contains(at(hour: 11, minute: 59, zone: "UTC")))
    }

    @Test func windowFollowsItsOwnTimeZoneNotTheServers() {
        let night = QuietHours(startMinute: 22 * 60, endMinute: 7 * 60, timeZone: "America/Toronto")
        // 12:00 UTC is 07:00 in Toronto: just outside; 11:59 UTC is 06:59 there: inside.
        #expect(!night.contains(Self.noon))
        #expect(night.contains(Self.noon.addingTimeInterval(-60)))
        let tokyo = QuietHours(startMinute: 22 * 60, endMinute: 7 * 60, timeZone: "Asia/Tokyo")
        #expect(!tokyo.contains(Self.noon)) // 21:00 in Tokyo
        #expect(tokyo.contains(Self.noon.addingTimeInterval(3_600))) // 22:00 in Tokyo
    }

    @Test func validationRefusesBadWindows() {
        #expect(!QuietHours(startMinute: 0, endMinute: 0, timeZone: "UTC").isValid)
        #expect(!QuietHours(startMinute: -1, endMinute: 60, timeZone: "UTC").isValid)
        #expect(!QuietHours(startMinute: 0, endMinute: 1_440, timeZone: "UTC").isValid)
        #expect(!QuietHours(startMinute: 60, endMinute: 120, timeZone: "Mars/Olympus").isValid)
        #expect(!QuietHours(startMinute: 60, endMinute: 120, timeZone: "").isValid)
        #expect(!QuietHours(startMinute: 60, endMinute: 120, timeZone: String(repeating: "a", count: 65)).isValid)
        #expect(NotificationSettingsUpdate(defaultLevel: .none, quietHours: QuietHours(startMinute: 5, endMinute: 5, timeZone: "UTC")).invalidField == "quietHours")
        #expect(NotificationSettingsUpdate(defaultLevel: .none, quietHours: nil).invalidField == nil)
    }

    @Test func invalidWindowFailsOpen() {
        // An unknown zone is never "quiet": the customer is notified normally rather than silently missing a notification.
        #expect(!QuietHours(startMinute: 0, endMinute: 1_000, timeZone: "Nowhere/Land").contains(Self.noon))
    }

    // MARK: Policy

    @Test func securityCriticalItemsBreakThroughEveryLevelAndQuietWindow() {
        let allDay = QuietHours(startMinute: 0, endMinute: 1_439, timeZone: "UTC")
        let inside = at(hour: 3, zone: "UTC")
        #expect(allDay.contains(inside))
        for level in MuteLevel.allCases {
            for kind in [InteractionKind.authenticate, .authorize] {
                for purpose in InteractionPurpose.allCases {
                    #expect(NotificationPolicy.interruption(kind: kind, purpose: purpose, actionRequired: true, level: level, quietHours: allDay, at: inside) == .normal)
                }
            }
            #expect(NotificationPolicy.interruption(kind: .confirm, purpose: .security, actionRequired: true, level: level, quietHours: allDay, at: inside) == .normal)
            #expect(NotificationPolicy.interruption(kind: nil, purpose: .security, actionRequired: false, level: level, quietHours: allDay, at: inside) == .normal)
        }
    }

    @Test func marketingNeverBreaksThroughQuietHours() {
        let night = QuietHours(startMinute: 22 * 60, endMinute: 7 * 60, timeZone: "UTC")
        let inside = at(hour: 2, zone: "UTC")
        for purpose in [InteractionPurpose.marketing, .rewards, .support, .transactional, .accountService] {
            #expect(NotificationPolicy.interruption(kind: .message, purpose: purpose, actionRequired: false, level: .none, quietHours: night, at: inside) == .quiet)
        }
        // Even an item that needs an answer is quiet in quiet hours unless it is security-critical.
        #expect(NotificationPolicy.interruption(kind: .confirm, purpose: .transactional, actionRequired: true, level: .none, quietHours: night, at: inside) == .quiet)
        // Outside the window nothing changes.
        #expect(NotificationPolicy.interruption(kind: .message, purpose: .marketing, actionRequired: false, level: .none, quietHours: night, at: at(hour: 12, zone: "UTC")) == .normal)
    }

    @Test func levelStillQuietsOutsideQuietHours() {
        let noon = at(hour: 12, zone: "UTC")
        #expect(NotificationPolicy.interruption(kind: .message, purpose: .marketing, actionRequired: false, level: .promotional, quietHours: nil, at: noon) == .quiet)
        #expect(NotificationPolicy.interruption(kind: .status, purpose: .transactional, actionRequired: false, level: .promotional, quietHours: nil, at: noon) == .normal)
        #expect(NotificationPolicy.interruption(kind: .status, purpose: .transactional, actionRequired: false, level: .allNonEssential, quietHours: nil, at: noon) == .quiet)
        #expect(NotificationPolicy.interruption(kind: .confirm, purpose: .transactional, actionRequired: true, level: .allNonEssential, quietHours: nil, at: noon) == .normal)
    }

    @Test func businessWithoutItsOwnLevelInheritsTheAccountDefault() {
        let id = BusinessID()
        let inherits = BusinessPreferences(businessId: id)
        #expect(!inherits.hasOwnLevel)
        #expect(inherits.effectiveLevel(accountDefault: .allNonEssential, at: Self.noon) == .allNonEssential)
        // Its own level wins, including an explicit "Everything" over a quieter default.
        let own = BusinessPreferences(businessId: id, muteLevel: .none, hasOwnLevel: true)
        #expect(own.effectiveLevel(accountDefault: .allNonEssential, at: Self.noon) == .none)
        let quiet = BusinessPreferences(businessId: id, muteLevel: .promotional, hasOwnLevel: true)
        #expect(quiet.effectiveLevel(accountDefault: .none, at: Self.noon) == .promotional)
        // A timed level that ended falls back to the default.
        let ended = BusinessPreferences(businessId: id, muteLevel: .allNonEssential, muteUntil: Self.noon.addingTimeInterval(-1), hasOwnLevel: true)
        #expect(ended.effectiveLevel(accountDefault: .promotional, at: Self.noon) == .promotional)
        // No row at all behaves like inheriting.
        #expect(NotificationPolicy.effectiveLevel(business: nil, accountDefault: .promotional, at: Self.noon) == .promotional)
    }

    @Test func businessPreferencesDecodeFromAnOlderServer() throws {
        let id = BusinessID()
        let old = #"{"businessId":"\#(id.description)","favorite":false,"muteLevel":"promotional","blocked":false}"#
        let decoded = try JSONDecoder().decode(BusinessPreferences.self, from: Data(old.utf8))
        #expect(decoded.hasOwnLevel, "an older server has no account default, so its level is the business's own")
        let none = #"{"businessId":"\#(id.description)","favorite":false,"muteLevel":"none","blocked":false}"#
        #expect(try !JSONDecoder().decode(BusinessPreferences.self, from: Data(none.utf8)).hasOwnLevel)
        #expect(BusinessPreferencesUpdate().isEmpty)
        #expect(!BusinessPreferencesUpdate(followDefault: true).isEmpty)
    }

    @Test func settingsRoutesAreDeviceSignedAndCatalogued() {
        let catalog = Set(APIRoutes.all.map(\.name))
        for route in APIRoutes.notificationSettingsEndpoints {
            #expect(route.auth == .deviceSignedBearer)
            #expect(catalog.contains(route.name))
        }
        #expect(Set(APIRoutes.all.map { "\($0.method.rawValue) \($0.template)" }).count == APIRoutes.all.count)
    }

    // MARK: Loop alerts (F-4)

    @Test func installedLoopAlertsDefaultOffAndDecodeFromAnOlderServer() throws {
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()
        let business = BusinessSummary(id: BusinessID(), displayName: "Atlas", handle: nil, code: BusinessCode.generate(), verificationStatus: .verified)
        let loop = InstalledLoop(loopId: LoopDefinitionID(), business: business, businessCategory: .retail, title: "Order", mode: .installOnly,
                                 source: .directory, installedAt: Self.noon, connected: false, publicationId: nil, entryPoints: [], openInstances: [], brandKitId: nil)
        #expect(!loop.alertsEnabled)
        var json = try #require(try JSONSerialization.jsonObject(with: encoder.encode(loop)) as? [String: Any])
        json.removeValue(forKey: "alertsEnabled")
        let old = try decoder.decode(InstalledLoop.self, from: JSONSerialization.data(withJSONObject: json))
        #expect(!old.alertsEnabled)
        var on = loop
        on.alertsEnabled = true
        #expect(try decoder.decode(InstalledLoop.self, from: encoder.encode(on)).alertsEnabled)
        #expect(LoopInstallRequest(mode: .installOnly, source: .directory, textVersion: 1, textDigest: "x", agree: true).alertsEnabled == nil)
        #expect(APIRoutes.all.contains { $0.name == APIRoutes.loopInstalledAlerts.name })
    }

    @Test func alertsCopyNamesTheLimits() {
        let detail = LoopAlertsCopy.detail(business: "Atlas")
        #expect(detail.contains("Atlas") && detail.contains("no offers") && detail.contains("no messages"))
        #expect(LoopAlertsCopy.detail(business: "").contains("the business"))
        #expect(LoopAlertsCopy.state(enabled: true) != LoopAlertsCopy.state(enabled: false))
    }
}
