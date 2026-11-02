import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// The account-wide default level and quiet hours (SECURITY.md §2.96 "Notification level and quiet hours"): stored per account, inherited by
/// businesses without their own level, enforced where pushes are decided, and never able to silence a security push.
final class NotificationSettingsServerTests: XCTestCase {
    func put(_ h: TestHarness, _ consumer: TestConsumer, _ update: NotificationSettingsUpdate) async throws -> HTTPResult {
        try await h.signed(consumer, .PUT, "/v1/notifications/settings", body: try ViadereJSON.encode(update))
    }

    func registerToken(_ h: TestHarness, _ consumer: TestConsumer) async throws {
        let token = try await h.signedPost(consumer, "/v1/push/apns-token",
                                           APNsTokenRegistration(token: String(repeating: "ab", count: 32), environment: .sandbox, bundleId: "com.viadere.app"))
        XCTAssertTrue([.ok, .created, .noContent].contains(token.status), token.text)
    }

    /// A UTC quiet window of two hours around the harness clock.
    func windowAround(_ h: TestHarness) -> QuietHours {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC")!
        let parts = calendar.dateComponents([.hour, .minute], from: h.clock.now())
        let minute = (parts.hour ?? 0) * 60 + (parts.minute ?? 0)
        return QuietHours(startMinute: (minute + QuietHours.minutesPerDay - 60) % QuietHours.minutesPerDay,
                          endMinute: (minute + 60) % QuietHours.minutesPerDay, timeZone: "UTC")
    }

    func testSettingsAreStoredPerAccountValidatedAndAudited() async throws {
        try await withHarness { h in
            let alice = try await h.readyConsumer(name: "Alice")
            let bob = try await h.readyConsumer(name: "Bob")
            let initial = try await h.signed(alice, .GET, "/v1/notifications/settings").json(NotificationSettings.self)
            XCTAssertEqual(initial.defaultLevel, MuteLevel.none)
            XCTAssertNil(initial.quietHours)

            let quiet = QuietHours(startMinute: 22 * 60, endMinute: 7 * 60, timeZone: "America/Toronto")
            let saved = try await put(h, alice, NotificationSettingsUpdate(defaultLevel: .promotional, quietHours: quiet))
            XCTAssertEqual(saved.status, .ok, saved.text)
            let body = try saved.json(NotificationSettings.self)
            XCTAssertEqual(body.defaultLevel, .promotional)
            XCTAssertEqual(body.quietHours, quiet)
            // Same request twice: same result, one row.
            try await eq(try await put(h, alice, NotificationSettingsUpdate(defaultLevel: .promotional, quietHours: quiet)).status, .ok)
            try await eq(try await NotificationSettingsRecord.query(on: h.db).count(), 1)
            try await eq(try await h.signed(alice, .GET, "/v1/notifications/settings").json(NotificationSettings.self).quietHours, quiet)
            // Per account: Bob is untouched.
            try await eq(try await h.signed(bob, .GET, "/v1/notifications/settings").json(NotificationSettings.self).defaultLevel, MuteLevel.none)
            // Quiet hours off; the default level stays.
            let off = try await put(h, alice, NotificationSettingsUpdate(defaultLevel: .allNonEssential, quietHours: nil)).json(NotificationSettings.self)
            XCTAssertEqual(off.defaultLevel, .allNonEssential)
            XCTAssertNil(off.quietHours)
            // Audited without the window itself.
            let audits = try await AuditEventRecord.query(on: h.db).filter(\.$action == "notifications.settings_updated").all()
            XCTAssertEqual(audits.count, 3)
            XCTAssertFalse(audits.contains { ($0.metadataJSON).contains("Toronto") })

            // Invalid windows are refused and change nothing.
            for bad in [QuietHours(startMinute: 60, endMinute: 60, timeZone: "UTC"), QuietHours(startMinute: -5, endMinute: 60, timeZone: "UTC"),
                        QuietHours(startMinute: 0, endMinute: 1_440, timeZone: "UTC"), QuietHours(startMinute: 0, endMinute: 60, timeZone: "Mars/Base")] {
                let refused = try await put(h, alice, NotificationSettingsUpdate(defaultLevel: .none, quietHours: bad))
                XCTAssertEqual(refused.status, .unprocessableEntity, refused.text)
            }
            try await eq(try await h.signed(alice, .GET, "/v1/notifications/settings").json(NotificationSettings.self).defaultLevel, .allNonEssential)
            // An unknown level is not decodable.
            let unknown = try await h.signed(alice, .PUT, "/v1/notifications/settings", body: Data(#"{"defaultLevel":"silent"}"#.utf8))
            XCTAssertNotEqual(unknown.status, .ok)
            // Device-signed only.
            let anonymous = try await h.request(.GET, "/v1/notifications/settings")
            XCTAssertEqual(anonymous.status, .unauthorized)
        }
    }

    func testBusinessesWithoutTheirOwnLevelInheritTheAccountDefault() async throws {
        try await withHarness { h in
            let world = try await TenantWorld.build(h)
            try await registerToken(h, world.alice)
            let relShop = world.rel("alice", "shop")
            let relBank = world.rel("alice", "bank")

            // The directory says who follows the default.
            func ownLevel(_ business: TestBusiness) async throws -> Bool {
                try await h.signed(world.alice, .GET, "/v1/businesses/\(business.id)/preferences").json(BusinessPreferences.self).hasOwnLevel
            }
            try await isTrue(!(try await ownLevel(world.shop)))

            // Default "Only what matters": an informational update from a business with no level of its own arrives quietly.
            try await eq(try await put(h, world.alice, NotificationSettingsUpdate(defaultLevel: .allNonEssential, quietHours: nil)).status, .ok)
            var before = h.push.sent.count
            let inherited = try await world.issueStatus(world.shop, relShop, title: "Your order shipped")
            XCTAssertEqual(h.push.sent.dropFirst(before).first { $0.interactionId == inherited.description }?.interruptionLevel, "passive")

            // A business with its own level keeps it: an explicit "Everything" beats the quieter default.
            let own = try await h.signed(world.alice, .PUT, "/v1/businesses/\(world.bank.id)/preferences",
                                         body: try ViadereJSON.encode(BusinessPreferencesUpdate(muteLevel: MuteLevel.none)))
            XCTAssertTrue(try own.json(BusinessPreferences.self).hasOwnLevel)
            before = h.push.sent.count
            let kept = try await world.issueStatus(world.bank, relBank, title: "Statement ready")
            XCTAssertNotEqual(h.push.sent.dropFirst(before).first { $0.interactionId == kept.description }?.interruptionLevel, "passive")

            // Following the default again returns it to the quiet default; a level and "follow default" together is refused.
            let both = try await h.signed(world.alice, .PUT, "/v1/businesses/\(world.bank.id)/preferences",
                                          body: try ViadereJSON.encode(BusinessPreferencesUpdate(muteLevel: .promotional, followDefault: true)))
            XCTAssertEqual(both.status, .unprocessableEntity)
            let follow = try await h.signed(world.alice, .PUT, "/v1/businesses/\(world.bank.id)/preferences",
                                            body: try ViadereJSON.encode(BusinessPreferencesUpdate(followDefault: true)))
            XCTAssertEqual(follow.status, .ok, follow.text)
            XCTAssertFalse(try follow.json(BusinessPreferences.self).hasOwnLevel)
            before = h.push.sent.count
            let followed = try await world.issueStatus(world.bank, relBank, title: "Another statement")
            XCTAssertEqual(h.push.sent.dropFirst(before).first { $0.interactionId == followed.description }?.interruptionLevel, "passive")

            // Security is never quieted by the default, however quiet it is, and everything stays in Alerts.
            before = h.push.sent.count
            let signIn = try await world.issueSignIn(world.shop, relShop)
            XCTAssertNotEqual(h.push.sent.dropFirst(before).first { $0.interactionId == signIn.description }?.interruptionLevel, "passive")
            let page = try await h.signed(world.alice, .GET, "/v1/alerts").json(AlertPage.self)
            for id in [inherited, kept, followed, signIn] {
                XCTAssertTrue(page.items.contains { $0.alertId == AlertIdentifier.make(.interaction, id.uuid) })
            }
            // Bob's account is unaffected by Alice's default.
            try await registerToken(h, world.bob)
            before = h.push.sent.count
            let bobs = try await world.issueStatus(world.bank, world.rel("bob", "bank"), title: "Hello Bob")
            XCTAssertNotEqual(h.push.sent.dropFirst(before).first { $0.interactionId == bobs.description }?.interruptionLevel, "passive")
        }
    }

    func testQuietHoursQuietEverythingExceptSecurityAndEndWithTheWindow() async throws {
        try await withHarness { h in
            let world = try await TenantWorld.build(h)
            try await registerToken(h, world.alice)
            let relShop = world.rel("alice", "shop")
            try await eq(try await put(h, world.alice, NotificationSettingsUpdate(defaultLevel: .none, quietHours: windowAround(h))).status, .ok)

            var before = h.push.sent.count
            let status = try await world.issueStatus(world.shop, relShop, title: "Your order shipped")
            let confirm = try await world.issueConfirm(world.shop, relShop, title: "Pick up at 5?")
            let signIn = try await world.issueSignIn(world.shop, relShop)
            var pushes = h.push.sent.dropFirst(before)
            XCTAssertEqual(pushes.first { $0.interactionId == status.description }?.interruptionLevel, "passive", "informational update during quiet hours")
            XCTAssertEqual(pushes.first { $0.interactionId == status.description }?.highPriority, false)
            XCTAssertEqual(pushes.first { $0.interactionId == confirm.description }?.interruptionLevel, "passive",
                           "a request that is not security-critical is quiet even though it needs an answer")
            let securityPush = try XCTUnwrap(pushes.first { $0.interactionId == signIn.description })
            XCTAssertNotEqual(securityPush.interruptionLevel, "passive", "a sign-in approval breaks through quiet hours")
            XCTAssertTrue(securityPush.highPriority)

            // Quiet is not absent: all three are in Alerts.
            let page = try await h.signed(world.alice, .GET, "/v1/alerts").json(AlertPage.self)
            for id in [status, confirm, signIn] { XCTAssertTrue(page.items.contains { $0.alertId == AlertIdentifier.make(.interaction, id.uuid) }) }

            // Outside the window the same update arrives normally.
            h.clock.advance(by: 3 * 3_600)
            let later = try await h.login(world.alice)
            before = h.push.sent.count
            let after = try await world.issueStatus(world.shop, relShop, title: "Order delivered")
            pushes = h.push.sent.dropFirst(before)
            XCTAssertNotEqual(pushes.first { $0.interactionId == after.description }?.interruptionLevel, "passive")
            // Turning quiet hours off while inside a window restores normal delivery.
            try await eq(try await put(h, later, NotificationSettingsUpdate(defaultLevel: .none, quietHours: windowAround(h))).status, .ok)
            try await eq(try await put(h, later, NotificationSettingsUpdate(defaultLevel: .none, quietHours: nil)).status, .ok)
            before = h.push.sent.count
            let reopened = try await world.issueStatus(world.shop, relShop, title: "Order reviewed")
            XCTAssertNotEqual(h.push.sent.dropFirst(before).first { $0.interactionId == reopened.description }?.interruptionLevel, "passive")
        }
    }

    func testTheMostRestrictiveSettingsStillNeverSilenceSecurity() async throws {
        try await withHarness { h in
            let world = try await TenantWorld.build(h)
            try await registerToken(h, world.alice)
            // Quietest default, an all-day quiet window, the business muted at the quietest level.
            let allDay = QuietHours(startMinute: 0, endMinute: 1_439, timeZone: "UTC")
            try await eq(try await put(h, world.alice, NotificationSettingsUpdate(defaultLevel: .allNonEssential, quietHours: allDay)).status, .ok)
            _ = try await h.signed(world.alice, .PUT, "/v1/businesses/\(world.shop.id)/preferences",
                                   body: try ViadereJSON.encode(BusinessPreferencesUpdate(muteLevel: .allNonEssential)))
            let before = h.push.sent.count
            let signIn = try await world.issueSignIn(world.shop, world.rel("alice", "shop"))
            let securityPush = try XCTUnwrap(h.push.sent.dropFirst(before).first { $0.interactionId == signIn.description })
            XCTAssertNotEqual(securityPush.interruptionLevel, "passive")
            XCTAssertTrue(securityPush.highPriority)
        }
    }
}
