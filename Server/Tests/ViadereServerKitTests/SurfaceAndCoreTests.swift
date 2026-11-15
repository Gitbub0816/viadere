import Fluent
import FluentSQL
import Foundation
import SQLKit
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// WP-1.6 neutral business surfaces and WP-0.5 "core without extensions" (INV-1, C9.3, C9.4).
final class SurfaceAndCoreTests: XCTestCase {
    // MARK: WP-1.6

    func testABusinessHomeDefaultsToViaderesStandardLayoutWithoutLoopsOrShop() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Corner Shop", handle: "cornershop")
            let c = try await h.readyConsumer()
            try await h.connect(c, to: b)
            let view = try await h.signed(c, .GET, "/v1/businesses/\(b.id)/surface").json(BusinessSurfaceView.self)
            XCTAssertEqual(view.version, 0)
            XCTAssertEqual(view.modules.first?.module, "profile")
            XCTAssertEqual(view.modules.map(\.module), SurfaceLayout.defaultBusinessHome.modules.map(\.module))
            XCTAssertFalse(view.modules.contains { ["loops", "shop"].contains($0.module) })
            XCTAssertEqual(view.business.id, b.id)
        }
    }

    func testTheConsolePublishesOnlyValidLayoutsAndTheBusinessCannotRemoveTheProfileOrAddNavigation() async throws {
        try await withHarness { h in
            let (owner, _, businessId) = try await h.verifiedOwner()
            let b = try await h.testBusiness(businessId)
            let c = try await h.readyConsumer()
            try await h.connect(c, to: b)
            let page = try await h.page(ConsoleSurface.path, owner)
            XCTAssertEqual(page.status, .ok, page.text)
            XCTAssertFalse(page.text.contains("show_loops"), "Loops are not offered in this release")
            XCTAssertFalse(page.text.contains("show_shop"))
            XCTAssertFalse(page.text.contains("show_profile"), "the profile cannot be removed")
            let published = try await h.formPost(ConsoleSurface.path, owner, [("show_offers", "1"), ("order_offers", "1"), ("show_message", "1"), ("order_message", "2"),
                                                                             ("show_loops", "1"), ("show_profile", "0"), ("tabs", "evil"), ("show_casino", "1")])
            XCTAssertEqual(published.status, .seeOther, published.text)
            let view = try await h.signed(c, .GET, "/v1/businesses/\(b.id)/surface").json(BusinessSurfaceView.self)
            XCTAssertEqual(view.modules.map(\.module), ["profile", "offers", "message"])
            XCTAssertEqual(view.version, 1)
            let bad = try await h.formPost(ConsoleSurface.path, owner, [("show_offers", "1"), ("order_offers", "99")])
            XCTAssertNotEqual(bad.status, .seeOther)
            // A stored row that no longer validates is never served (the default is, instead).
            let row = BusinessSurfaceRecord()
            row.id = UUID()
            row.businessId = businessId
            row.version = 9
            row.status = SurfaceService.published
            row.layoutJSON = #"{"v":1,"template":"business_home","modules":[{"module":"casino","size":"regular"}]}"#
            row.createdAt = h.clock.now()
            try await row.create(on: h.db)
            let fallback = try await h.signed(c, .GET, "/v1/businesses/\(b.id)/surface").json(BusinessSurfaceView.self)
            XCTAssertEqual(fallback.version, 1)
        }
    }

    func testOnlyOwnersAndAdminsCanPublishAndAnAuditorCannot() async throws {
        try await withHarness { h in
            let (owner, _, _) = try await h.verifiedOwner()
            let (auditor, _) = try await h.addMember(owner: owner, role: .auditor, email: "audit@example.com")
            let attempt = try await h.formPost(ConsoleSurface.path, auditor, [("show_offers", "1")])
            XCTAssertNotEqual(attempt.status, .seeOther, attempt.text)
            let rows = try await BusinessSurfaceRecord.query(on: h.db).count()
            XCTAssertEqual(rows, 0)
        }
    }

    // MARK: WP-0.5 core without extensions (INV-1)

    func testCoreFeaturesWorkWithNoLoopNoBrandKitAndNoSurfaceRows() async throws {
        try await withHarness { h in
            // Loop and Brand Kit tables exist but hold nothing: core features must not need a row in them.
            if let sql = h.db as? any SQLDatabase {
                let tables: [String]
                if DB.isPostgres(h.db) {
                    tables = try await sql.raw("SELECT table_name AS name FROM information_schema.tables WHERE table_schema = 'public'").all().map { try $0.decode(column: "name", as: String.self) }
                } else {
                    tables = try await sql.raw("SELECT name FROM sqlite_master WHERE type = 'table'").all().map { try $0.decode(column: "name", as: String.self) }
                }
                // Hosted Loops (WP-3.2) and Brand Kits (Phase 2) ship their tables, but nothing core needs a row in them: every Loop and Brand Kit table stays empty below.
                for table in tables where table.hasPrefix("loop_") || table.hasPrefix("inbox_") || table.hasPrefix("brand_") {
                    let rows = try await sql.raw(SQLQueryString("SELECT COUNT(*) AS n FROM \(unsafeRaw: table)")).first()?.decode(column: "n", as: Int.self)
                    XCTAssertEqual(rows, 0, table)
                }
                XCTAssertTrue(tables.contains("business_surfaces"))
            }
            let world = try await TenantWorld.build(h)
            let surfaces = try await BusinessSurfaceRecord.query(on: h.db).count()
            XCTAssertEqual(surfaces, 0)
            let brandRows = try await BrandKitRecord.query(on: h.db).count() + (try await BrandAssetRecord.query(on: h.db).count())
                + (try await BrandManifestRecord.query(on: h.db).count())
            XCTAssertEqual(brandRows, 0)
            // Approvals (signed decision), messaging, rewards and connection all work on a business with nothing configured.
            let id = world.interactions["alice/shop/confirm"]!
            let interaction = try await h.consumerInteraction(world.alice, id: id)
            let decided = try await h.decide(world.alice, id: id, signed: try await h.decision(world.alice, interaction: interaction, decision: .confirm))
            XCTAssertEqual(decided.status, .ok, decided.text)
            let started = try await h.signedPost(world.alice, APIRoutes.conversationStart.template, StartConversationRequest(businessId: world.shop.id))
            XCTAssertEqual(started.status, .ok, started.text)
            let session = try started.json(ConversationSummary.self)
            let sent = try await h.signedPost(world.alice, "/v1/conversations/\(session.id)/messages", SendMessageRequest(body: "Is my order ready?", clientMessageId: UUID().uuidString.lowercased()))
            XCTAssertEqual(sent.status, .created, sent.text)
            let reward = try await h.businessPost(world.shop, APIRoutes.businessIssueReward.template, IssueRewardRequest(title: "Free coffee", kind: .coupon, idempotencyKey: "core-1"))
            XCTAssertEqual(reward.status, .created, reward.text)
            let benefits = try await h.signed(world.alice, .GET, "/v1/benefits?filter=available").json(RewardsOverview.self)
            XCTAssertEqual(benefits.rewards.map(\.reward.title), ["Free coffee"])
            let home = try await h.signed(world.alice, .GET, "/v1/businesses/\(world.shop.id)/surface")
            XCTAssertEqual(home.status, .ok, home.text)
            let newcomer = try await h.readyConsumer()
            let connected = try await h.signedPost(newcomer, APIRoutes.relationshipConnect.template, ConnectRequest(businessId: world.cafe.id, source: .code))
            XCTAssertEqual(connected.status, .created, connected.text)
        }
    }

    // MARK: WP-1.8 (partial): load of GET /v1/alerts at 50 businesses x 500 items

    func testAlertListStaysFastAtFiftyBusinessesTimesFiveHundredItems() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            let first = try await h.makeBusiness(name: "Load 0", handle: "load0")
            let rel = try await h.connect(consumer, to: first)
            let issued = try await h.issue(first, relationship: rel, payload: .confirm(ConfirmPayload(title: "Load")), purpose: .transactional, ttl: 86_400)
            XCTAssertEqual(issued.status, .created, issued.text)
            let json = try await XCTUnwrapAsync(await InteractionRecord.query(on: h.db).first()).interactionJSON
            let now = h.clock.now()
            var targets: [(business: UUID, relationship: UUID)] = [(first.record.id!, rel.id.uuid)]
            for i in 1..<50 {
                let b = try await BusinessRegistry(db: h.db, ctx: h.ctx).register(displayName: "Load \(i)", handle: nil, category: .retail, status: .verified)
                let relationship = RelationshipRecord(consumerId: consumer.id.uuid, businessId: b.id!, source: .code, now: now)
                try await relationship.create(on: h.db)
                targets.append((b.id!, relationship.id!))
            }
            // 25,000 interactions (500 per business), written in batches straight to the table: this measures the read path.
            for (b, target) in targets.enumerated() {
                var batch: [InteractionRecord] = []
                for i in 0..<500 {
                    let row = InteractionRecord()
                    row.id = UUID()
                    row.businessId = target.business
                    row.consumerId = consumer.id.uuid
                    row.relationshipId = target.relationship
                    row.kind = "confirm"
                    row.purpose = "transactional"
                    row.status = i % 3 == 0 ? InteractionStatus.confirmed.rawValue : InteractionStatus.pending.rawValue
                    row.priority = "normal"
                    row.sensitivity = "standard"
                    row.livemode = true
                    row.interactionJSON = json
                    row.idempotencyKey = "load-\(b)-\(i)"
                    row.requestHash = "load"
                    row.createdAt = now.addingTimeInterval(-Double(b * 500 + i) - 10)
                    row.expiresAt = now.addingTimeInterval(86_400)
                    row.decidedAt = i % 3 == 0 ? now.addingTimeInterval(-5) : nil
                    row.expiryNotified = false
                    row.contentErased = false
                    batch.append(row)
                }
                try await batch.create(on: h.db)
            }
            func timed(_ path: String) async throws -> (AlertPage, TimeInterval) {
                let start = Date()
                let response = try await h.signed(consumer, .GET, path)
                let elapsed = Date().timeIntervalSince(start)
                XCTAssertEqual(response.status, .ok, response.text)
                return (try response.json(AlertPage.self), elapsed)
            }
            var timings: [String: TimeInterval] = [:]
            var (page, elapsed) = try await timed("/v1/alerts")
            timings["all, first page"] = elapsed
            XCTAssertEqual(page.items.count, AlertQuery.defaultLimit)
            var seen = Set(page.items.map(\.alertId))
            for n in 2...5 {
                let cursor = try XCTUnwrap(page.nextCursor)
                (page, elapsed) = try await timed("/v1/alerts?cursor=\(cursor)")
                timings["all, page \(n)"] = elapsed
                for item in page.items { XCTAssertTrue(seen.insert(item.alertId).inserted) }
            }
            (page, elapsed) = try await timed("/v1/alerts?status=pending&limit=50")
            timings["pending, 50"] = elapsed
            XCTAssertTrue(page.items.allSatisfy { $0.status == .pending && $0.actionable })
            (page, elapsed) = try await timed("/v1/alerts?business_id=\(BusinessID(targets[37].business))")
            timings["one business"] = elapsed
            XCTAssertTrue(page.items.allSatisfy { $0.business?.id.uuid == targets[37].business })
            (page, elapsed) = try await timed("/v1/alerts?since=\(SyncToken.encode(now.addingTimeInterval(-6)))&limit=50")
            timings["since"] = elapsed
            XCTAssertEqual(page.items.count, 50)
            let report = timings.sorted { $0.key < $1.key }.map { "\($0.key): \(Int($0.value * 1000)) ms" }.joined(separator: ", ")
            print("GET /v1/alerts load (50 businesses x 500 items, \(DB.isPostgres(h.db) ? "PostgreSQL" : "SQLite")): \(report)")
            // Budget for a debug build on a shared CI runner; the production budget is set in WP-1.8 on release builds.
            for (name, value) in timings { XCTAssertLessThan(value, 3.0, name) }
        }
    }
}
