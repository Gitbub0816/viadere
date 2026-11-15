import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// G21: the daily analytics rollup and the per-business history in the consumer export.
final class AnalyticsRollupTests: XCTestCase {
    struct World {
        var a: TestBusiness
        var b: TestBusiness
        var alice: TestConsumer
        var aliceA: Relationship
        var aliceB: Relationship
        var bob: TestConsumer
        var bobA: Relationship
    }

    static func world(_ h: TestHarness) async throws -> World {
        let a = try await h.makeBusiness(name: "Acme Roasters", handle: "acmeroasters")
        let b = try await h.makeBusiness(name: "Birch Bakery", handle: "birchbakery")
        let alice = try await h.readyConsumer(name: "Alice")
        let bob = try await h.readyConsumer(name: "Bob")
        return World(a: a, b: b, alice: alice, aliceA: try await h.connect(alice, to: a), aliceB: try await h.connect(alice, to: b),
                     bob: bob, bobA: try await h.connect(bob, to: a))
    }

    @discardableResult
    static func issue(_ h: TestHarness, _ business: TestBusiness, _ relationship: Relationship, count: Int, decided: Int = 0) async throws -> [UUID] {
        var ids: [UUID] = []
        for i in 0..<count {
            let response = try await h.issue(business, relationship: relationship, payload: .confirm(ConfirmPayload(title: "Confirm order \(i)")), purpose: .transactional)
            XCTAssertEqual(response.status, .created, response.text)
            ids.append(try response.json(Interaction.self).id.uuid)
        }
        for id in ids.prefix(decided) {
            try await InteractionRecord.query(on: h.db).filter(\.$id == id).set(\.$decidedAt, to: h.clock.now().addingTimeInterval(30)).update()
        }
        return ids
    }

    static func assertSame(_ rolled: DashboardAnalytics.Overview, _ raw: DashboardAnalytics.Overview, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(rolled.totalIssued, raw.totalIssued, "issued", file: file, line: line)
        XCTAssertEqual(rolled.totalDecided, raw.totalDecided, "decided", file: file, line: line)
        XCTAssertEqual(rolled.issuedByKind.map { "\($0.kind)=\($0.count)" }, raw.issuedByKind.map { "\($0.kind)=\($0.count)" }, file: file, line: line)
        XCTAssertEqual(rolled.decidedByKind.map { "\($0.kind)=\($0.count)" }, raw.decidedByKind.map { "\($0.kind)=\($0.count)" }, file: file, line: line)
        XCTAssertEqual(rolled.daily.map(\.count), raw.daily.map(\.count), "daily", file: file, line: line)
        XCTAssertEqual(rolled.daily.map(\.day), raw.daily.map(\.day), file: file, line: line)
        XCTAssertEqual(rolled.webhookSucceeded, raw.webhookSucceeded, file: file, line: line)
        XCTAssertEqual(rolled.webhookDead, raw.webhookDead, file: file, line: line)
        XCTAssertEqual(rolled.channelDelivered, raw.channelDelivered, file: file, line: line)
        XCTAssertEqual(rolled.channelFailed, raw.channelFailed, file: file, line: line)
        XCTAssertEqual(rolled.disconnects, raw.disconnects, file: file, line: line)
    }

    func snapshot(_ h: TestHarness) async throws -> [String] {
        try await BusinessDailyStatRecord.query(on: h.db).all().map { "\($0.businessId)|\($0.day.timeIntervalSince1970)|\($0.metric)|\($0.count)" }.sorted()
    }

    func testTheRollupEqualsTheRawCountsIsIdempotentAndTenantScoped() async throws {
        try await withHarness { h in
            let w = try await Self.world(h)
            let day0 = AnalyticsRollup.startOfDay(h.clock.now())
            try await Self.issue(h, w.a, w.aliceA, count: 3, decided: 1)
            try await Self.issue(h, w.a, w.bobA, count: 1)
            try await Self.issue(h, w.b, w.aliceB, count: 2, decided: 2)
            h.clock.advance(by: 86_400)
            try await Self.issue(h, w.a, w.aliceA, count: 2)
            h.clock.advance(by: 86_400)
            try await Self.issue(h, w.a, w.aliceA, count: 1)   // today: the live delta
            let rollup = AnalyticsRollup(db: h.db, ctx: h.ctx)
            let written = try await rollup.run()
            XCTAssertGreaterThanOrEqual(written, 2)
            // The rows of a closed day are exactly the raw counts, per tenant.
            let rows = try await BusinessDailyStatRecord.query(on: h.db).filter(\.$day == day0).all()
            let aRows = Dictionary(rows.filter { $0.businessId == w.a.record.id! }.map { ($0.metric, $0.count) }, uniquingKeysWith: +)
            let bRows = Dictionary(rows.filter { $0.businessId == w.b.record.id! }.map { ($0.metric, $0.count) }, uniquingKeysWith: +)
            XCTAssertEqual(aRows["issued.confirm"], 4)
            XCTAssertEqual(aRows["decided.confirm"], 1)
            XCTAssertEqual(bRows["issued.confirm"], 2)
            XCTAssertEqual(bRows["decided.confirm"], 2)
            // Rollups hold no customer-level data: only the fixed metric vocabulary per business and day.
            let allowed = Set(InteractionKind.known.flatMap { [AnalyticsRollup.Metric.issued($0.rawValue), AnalyticsRollup.Metric.decided($0.rawValue)] }
                + [AnalyticsRollup.Metric.webhookSucceeded, AnalyticsRollup.Metric.webhookDead, AnalyticsRollup.Metric.channelDelivered,
                   AnalyticsRollup.Metric.channelFailed, AnalyticsRollup.Metric.disconnects])
            let everyRow = try await BusinessDailyStatRecord.query(on: h.db).all()
            XCTAssertTrue(everyRow.allSatisfy { allowed.contains($0.metric) })
            // The overview from the rollup plus today's live rows equals the raw overview, for each tenant and each period.
            let analytics = DashboardAnalytics(db: h.db, ctx: h.ctx)
            for days in [7, 30, 90] {
                let rolledA = try await analytics.overview(businessId: w.a.record.id!, days: days)
                Self.assertSame(rolledA, try await analytics.overview(businessId: w.a.record.id!, days: days, source: .raw))
                XCTAssertEqual(rolledA.totalIssued, 7)
                XCTAssertEqual(rolledA.daily.suffix(3).map(\.count), [4, 2, 1])
                let rolledB = try await analytics.overview(businessId: w.b.record.id!, days: days)
                Self.assertSame(rolledB, try await analytics.overview(businessId: w.b.record.id!, days: days, source: .raw))
                XCTAssertEqual(rolledB.totalIssued, 2, "B never sees A's counts")
            }
            // A re-run changes nothing.
            let before = try await snapshot(h)
            let markers = try await AnalyticsRollupDayRecord.query(on: h.db).count()
            _ = try await rollup.run()
            _ = try await rollup.run()
            try await eq(try await snapshot(h), before)
            try await eq(try await AnalyticsRollupDayRecord.query(on: h.db).count(), markers)
            // A decision that lands after midnight is picked up within the settle window.
            let late = try await InteractionRecord.query(on: h.db).filter(\.$businessId == w.a.record.id!).filter(\.$decidedAt == nil).first()!
            try await InteractionRecord.query(on: h.db).filter(\.$id == late.id!).set(\.$decidedAt, to: h.clock.now()).update()
            _ = try await rollup.run()
            Self.assertSame(try await analytics.overview(businessId: w.a.record.id!, days: 7), try await analytics.overview(businessId: w.a.record.id!, days: 7, source: .raw))
            // Tenant deletion removes the tenant's rollups.
            let bCount = try await BusinessDailyStatRecord.query(on: h.db).filter(\.$businessId == w.b.record.id!).count()
            XCTAssertGreaterThan(bCount, 0)
            // The job runs in the hourly group.
            try await h.runJobs()
        }
    }

    func testTheJobToleratesAMissingDay() async throws {
        try await withHarness { h in
            let w = try await Self.world(h)
            let day0 = AnalyticsRollup.startOfDay(h.clock.now())
            try await Self.issue(h, w.a, w.aliceA, count: 2)
            h.clock.advance(by: 86_400)
            try await Self.issue(h, w.a, w.aliceA, count: 3)
            // The job did not run for ten days.
            h.clock.advance(by: 10 * 86_400)
            let analytics = DashboardAnalytics(db: h.db, ctx: h.ctx)
            // Before any run: closed days without a marker are read raw, so nothing shows as zero.
            Self.assertSame(try await analytics.overview(businessId: w.a.record.id!, days: 30), try await analytics.overview(businessId: w.a.record.id!, days: 30, source: .raw))
            try await eq(try await analytics.overview(businessId: w.a.record.id!, days: 30).totalIssued, 5)
            let rollup = AnalyticsRollup(db: h.db, ctx: h.ctx)
            let first = try await rollup.run()
            XCTAssertEqual(first, AnalyticsRollup.backfillDays, "the first run backfills every missing day")
            // A day lost later (its rows and marker gone, outside the settle window) is read raw and rebuilt by the next run.
            try await BusinessDailyStatRecord.query(on: h.db).filter(\.$day == day0).delete()
            try await AnalyticsRollupDayRecord.query(on: h.db).filter(\.$day == day0).delete()
            Self.assertSame(try await analytics.overview(businessId: w.a.record.id!, days: 30), try await analytics.overview(businessId: w.a.record.id!, days: 30, source: .raw))
            try await eq(try await analytics.overview(businessId: w.a.record.id!, days: 30).totalIssued, 5)
            let second = try await rollup.run()
            XCTAssertEqual(second, AnalyticsRollup.settleDays + 1)
            try await eq(try await BusinessDailyStatRecord.query(on: h.db).filter(\.$day == day0).filter(\.$businessId == w.a.record.id!).first()?.count, 2)
            // A second holder of the lease skips (another instance's run is in progress).
            let taken = try await JobLease.acquire(AnalyticsRollup.lease, holder: UUID(), ttl: 600, on: h.db, now: h.clock.now())
            XCTAssertTrue(taken)
            let skipped = try await rollup.run()
            XCTAssertEqual(skipped, 0)
        }
    }

    func testTheConsumerExportCarriesTheHistoryPerBusiness() async throws {
        try await withHarness { h in
            let w = try await Self.world(h)
            try await Self.issue(h, w.a, w.aliceA, count: 3, decided: 1)
            try await Self.issue(h, w.b, w.aliceB, count: 1)
            try await Self.issue(h, w.a, w.bobA, count: 4)   // another person's history never appears
            let document = try await ConsumerExports(db: h.db, ctx: h.ctx).document(for: w.alice.id.uuid)
            let history = try XCTUnwrap(document["historyByBusiness"] as? [[String: Any]])
            XCTAssertEqual(history.count, 2)
            let byBusiness = Dictionary(history.map { ($0["businessId"] as! String, $0) }, uniquingKeysWith: { a, _ in a })
            let a = try XCTUnwrap(byBusiness[w.a.record.id!.uuidString.lowercased()])
            XCTAssertEqual(a["business"] as? String, "Acme Roasters")
            XCTAssertEqual(a["interactionCount"] as? Int, 3)
            XCTAssertEqual((a["interactions"] as? [[String: Any]])?.count, 3)
            XCTAssertEqual(a["truncated"] as? Bool, false)
            XCTAssertEqual(a["relationshipStatus"] as? String, "active")
            XCTAssertEqual((a["byKind"] as? [String: Int])?["confirm"], 3)
            let b = try XCTUnwrap(byBusiness[w.b.record.id!.uuidString.lowercased()])
            XCTAssertEqual(b["interactionCount"] as? Int, 1)
            // Every listed interaction is Alice's.
            let aliceIds = Set(try await InteractionRecord.query(on: h.db).filter(\.$consumerId == w.alice.id.uuid).all().compactMap { $0.id?.uuidString.lowercased() })
            for entry in history { for row in entry["interactions"] as? [[String: Any]] ?? [] { XCTAssertTrue(aliceIds.contains(row["id"] as? String ?? "")) } }
            // The document still serializes (it is encrypted to the device as JSON).
            XCTAssertNoThrow(try JSONSerialization.data(withJSONObject: document, options: [.sortedKeys]))
            // Content erased by retention says so (the history keeps only metadata either way).
            try await InteractionRecord.query(on: h.db).filter(\.$consumerId == w.alice.id.uuid).filter(\.$businessId == w.b.record.id!).set(\.$contentErased, to: true).update()
            let after = try await ConsumerExports(db: h.db, ctx: h.ctx).document(for: w.alice.id.uuid)
            let bAfter = (after["historyByBusiness"] as? [[String: Any]])?.first { ($0["businessId"] as? String) == w.b.record.id!.uuidString.lowercased() }
            XCTAssertEqual((bAfter?["interactions"] as? [[String: Any]])?.first?["contentErased"] as? Bool, true)
            XCTAssertNil((bAfter?["interactions"] as? [[String: Any]])?.first?["content"], "the history never repeats content")
        }
    }
}
