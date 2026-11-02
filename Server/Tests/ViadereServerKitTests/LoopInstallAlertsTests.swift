import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Alerts for Loops installed without connecting (owner decision F-4; SECURITY.md §2.98 "Alerts from an installed Loop"): an install-only
/// customer sees **only that Loop's own** requests in Alerts, and only after allowing it; never the business's other Loops, offers, messages or
/// interactions; and turning it off, uninstalling or blocking stops it.
final class LoopInstallAlertsTests: XCTestCase {
    func enableLoops(_ h: TestHarness, _ consumer: TestConsumer) async throws {
        let text = LoopConsentCatalog.current
        var answers: [String: String] = [:]
        for check in text.checks { answers[check.id] = check.correctOptionId }
        let response = try await h.signed(consumer, .PUT, "/v1/loops/consent",
                                          body: try ViadereJSON.encode(LoopGlobalConsentRequest(textVersion: text.version, textDigest: text.digest, answers: answers, agree: true)))
        XCTAssertEqual(response.status, .ok, response.text)
    }

    func install(_ h: TestHarness, _ consumer: TestConsumer, _ loop: UUID, alerts: Bool? = nil) async throws -> HTTPResult {
        let text = LoopConsentCatalog.current
        return try await h.signed(consumer, .PUT, "/v1/loops/installed/\(loop.uuidString.lowercased())", body: try ViadereJSON.encode(
            LoopInstallRequest(mode: .installOnly, source: .directory, textVersion: text.version, textDigest: text.digest, agree: true, alertsEnabled: alerts)))
    }

    func setAlerts(_ h: TestHarness, _ consumer: TestConsumer, _ loop: UUID, _ enabled: Bool) async throws -> HTTPResult {
        try await h.signed(consumer, .PUT, "/v1/loops/installed/\(loop.uuidString.lowercased())/alerts", body: try ViadereJSON.encode(LoopAlertsRequest(enabled: enabled)))
    }

    func alerts(_ h: TestHarness, _ consumer: TestConsumer, _ query: String = "") async throws -> [AlertEntry] {
        let response = try await h.signed(consumer, .GET, "/v1/alerts\(query)")
        XCTAssertEqual(response.status, .ok, response.text)
        return try response.json(AlertPage.self).items
    }

    func testAnInstallOnlyCustomerGetsThisLoopsAlertAndNothingElseAndOnlyIfAllowed() async throws {
        try await withHarness { h in
            let world = try await LoopWorld.build(h)
            let pickup = try await world.publish()
            let cake = try await world.publish(LoopFixtures.pickup(title: "Order a cake", key: "cake"))
            let carol = try await h.readyConsumer(name: "Carol")
            try await enableLoops(h, carol)

            // Installing without choosing alerts leaves them off; both Loops installed install-only.
            let first = try await install(h, carol, pickup.definitionId)
            XCTAssertEqual(first.status, .ok, first.text)
            XCTAssertFalse(try first.json(LoopInstallResult.self).installed.alertsEnabled, "an install never turns alerts on by itself")
            _ = try await install(h, carol, cake.definitionId)
            try await eq(try await RelationshipRecord.query(on: h.db).filter(\.$consumerId == carol.id.uuid).count(), 0)
            let pickupInstance = try await world.instance(carol, pickup)
            let cakeInstance = try await world.instance(carol, cake)

            // Off: nothing in Alerts (the request is still reachable from Your Loops).
            try await eq(try await alerts(h, carol).count, 0)
            let mine = try await h.signed(carol, .GET, "/v1/loops/installed").json([InstalledLoop].self)
            XCTAssertEqual(Set(mine.flatMap(\.openInstances)), [pickupInstance.id, cakeInstance.id])

            // Allow alerts from the pickup Loop only.
            let allowed = try await setAlerts(h, carol, pickup.definitionId, true)
            XCTAssertEqual(allowed.status, .ok, allowed.text)
            XCTAssertTrue(try allowed.json(InstalledLoop.self).alertsEnabled)
            let items = try await alerts(h, carol)
            XCTAssertEqual(items.map(\.source), [.loopTask], "this Loop's alert and nothing else from the business")
            let item = try XCTUnwrap(items.first)
            XCTAssertEqual(item.target, AlertTarget(kind: .loopInstance, id: pickupInstance.id.uuid.uuidString.lowercased()))
            XCTAssertEqual(item.business?.id, world.business.id)
            XCTAssertTrue(item.actionRequired && item.actionable)
            XCTAssertEqual(item.title, "Schedule your pickup")
            XCTAssertFalse(items.contains { $0.target?.id == cakeInstance.id.uuid.uuidString.lowercased() }, "the business's other installed Loop stays out")
            // The business filter works for the installed Loop's business only; the same filter shows the same single item.
            try await eq(try await alerts(h, carol, "?business_id=\(world.business.id)").count, 1)
            let stranger = try await h.makeBusiness(name: "Elsewhere", handle: "elsewhere")
            let foreign = try await h.signed(carol, .GET, "/v1/alerts?business_id=\(stranger.id)")
            XCTAssertEqual(foreign.status, .notFound)
            // Status filters apply as for any other Loop task.
            try await eq(try await alerts(h, carol, "?status=pending").count, 1)
            try await eq(try await alerts(h, carol, "?status=completed").count, 0)

            // Another install-only customer who allowed alerts but has no request sees nothing, and never Carol's.
            let dave = try await h.readyConsumer(name: "Dave")
            try await enableLoops(h, dave)
            _ = try await install(h, dave, pickup.definitionId, alerts: true)
            try await eq(try await alerts(h, dave).count, 0)
            // A connected customer is unaffected by Carol's settings.
            try await eq(try await alerts(h, world.alice).count, 0)

            // Turning it off stops it at once, and back on restores it (the request is still open).
            let off = try await setAlerts(h, carol, pickup.definitionId, false)
            XCTAssertFalse(try off.json(InstalledLoop.self).alertsEnabled)
            try await eq(try await alerts(h, carol).count, 0)
            let filtered = try await h.signed(carol, .GET, "/v1/alerts?business_id=\(world.business.id)")
            XCTAssertEqual(filtered.status, .notFound, "with alerts off the business is not in scope at all")
            _ = try await setAlerts(h, carol, pickup.definitionId, true)
            try await eq(try await alerts(h, carol).count, 1)
            let audit = try await AuditEventRecord.query(on: h.db).filter(\.$action == "loop.alerts_changed").all()
            XCTAssertEqual(audit.count, 3)

            // Marking seen and the answer path still work for the allowed Loop.
            let seen = try await h.signed(carol, .POST, "/v1/alerts/seen", body: try ViadereJSON.encode(AlertSeenRequest(alertIds: [item.alertId])))
            XCTAssertEqual(seen.status, .ok, seen.text)
            try await eq(try await alerts(h, carol, "?unread=1").count, 0)
            _ = try await world.submitPickup(carol, pickupInstance.id)
            let submitted = try await XCTUnwrapAsync(try await alerts(h, carol).first)
            XCTAssertFalse(submitted.actionRequired, "waiting for the business")
        }
    }

    func testChoosingAlertsAtInstallAndEndingTheInstallClearsTheChoice() async throws {
        try await withHarness { h in
            let world = try await LoopWorld.build(h)
            let pickup = try await world.publish()
            let carol = try await h.readyConsumer(name: "Carol")
            try await enableLoops(h, carol)

            let chosen = try await install(h, carol, pickup.definitionId, alerts: true)
            XCTAssertTrue(try chosen.json(LoopInstallResult.self).installed.alertsEnabled)
            _ = try await world.instance(carol, pickup)
            try await eq(try await alerts(h, carol).count, 1)
            // Installing again without a choice keeps it; with a choice changes it.
            try await isTrue(try await install(h, carol, pickup.definitionId).json(LoopInstallResult.self).installed.alertsEnabled)
            try await isTrue(!(try await install(h, carol, pickup.definitionId, alerts: false).json(LoopInstallResult.self).installed.alertsEnabled))
            try await eq(try await alerts(h, carol).count, 0)
            _ = try await setAlerts(h, carol, pickup.definitionId, true)

            // Uninstall cancels the request and clears the choice; a re-install starts with alerts off.
            let removed = try await h.signed(carol, .DELETE, "/v1/loops/installed/\(pickup.definitionId.uuidString.lowercased())")
            XCTAssertEqual(removed.status, .ok, removed.text)
            try await eq(try await LoopInstallRecord.query(on: h.db).first()?.alertsEnabled, false)
            let again = try await install(h, carol, pickup.definitionId)
            XCTAssertFalse(try again.json(LoopInstallResult.self).installed.alertsEnabled)
            _ = try await world.instance(carol, pickup)
            try await eq(try await alerts(h, carol).filter { $0.status == .pending }.count, 0, "no stale permission carries over")
            // Not installed: the alerts route is a plain 404, never an oracle for other Loops.
            let missing = try await setAlerts(h, carol, UUID(), true)
            XCTAssertEqual(missing.status, .notFound)
            _ = try await h.signed(carol, .DELETE, "/v1/loops/installed/\(pickup.definitionId.uuidString.lowercased())")
            try await eq(try await setAlerts(h, carol, pickup.definitionId, true).status, .notFound)
        }
    }

    func testAnotherCustomerCannotChangeMyAlertsPermission() async throws {
        try await withHarness { h in
            let world = try await LoopWorld.build(h)
            let pickup = try await world.publish()
            let carol = try await h.readyConsumer(name: "Carol")
            try await enableLoops(h, carol)
            _ = try await install(h, carol, pickup.definitionId)
            let mallory = try await h.readyConsumer(name: "Mallory")
            try await eq(try await setAlerts(h, mallory, pickup.definitionId, true).status, .notFound)
            try await eq(try await LoopInstallRecord.query(on: h.db).first()?.alertsEnabled, false)
        }
    }
}
