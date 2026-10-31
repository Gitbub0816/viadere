import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// WP-3.4 security tests (plan 5.4 "Staff privilege escalation", D3.T9): tenant isolation of the hosted inbox, viewer vs manager, immediate
/// role downgrade, export scoped to the tenant.
final class LoopInboxTests: XCTestCase {
    /// Two organizations from the console, each with a published Loop and one delivered request.
    private struct Tenants {
        var world: LoopWorld
        var owner: DashSession
        var businessId: UUID
        var item: UUID
        var otherItem: UUID
        var otherBusiness: UUID
    }

    private func tenants(_ h: TestHarness) async throws -> Tenants {
        let (owner, _, businessId) = try await h.verifiedOwner()
        let world = try await LoopWorld.build(h, business: try await h.testBusiness(businessId), tag: "acme")
        let instance = try await world.instance(world.alice, try await world.publish())
        _ = try await world.submitPickup(world.alice, instance.id)
        let (_, _, otherBusiness) = try await h.verifiedOwner(email: "other@example.com", org: "Other Shop", handle: "othershop")
        let other = try await LoopWorld.build(h, business: try await h.testBusiness(otherBusiness), tag: "other")
        let otherInstance = try await other.instance(other.alice, try await other.publish())
        _ = try await other.submitPickup(other.alice, otherInstance.id)
        try await world.drain(.loopDelivery)
        let item = try await InboxItemRecord.query(on: h.db).filter(\.$businessId == businessId).first()!.id!
        let otherItem = try await InboxItemRecord.query(on: h.db).filter(\.$businessId == otherBusiness).first()!.id!
        return Tenants(world: world, owner: owner, businessId: businessId, item: item, otherItem: otherItem, otherBusiness: otherBusiness)
    }

    func testStaffCannotReadOrActOnAnotherTenantsItems() async throws {
        try await withHarness { h in
            let t = try await tenants(h)
            let list = try await h.page("/dashboard/inbox", t.owner)
            XCTAssertEqual(list.status, .ok, list.text)
            XCTAssertTrue(list.text.contains("/dashboard/inbox/\(t.item.uuidString.lowercased())"))
            XCTAssertFalse(list.text.contains(t.otherItem.uuidString.lowercased()))
            let own = try await h.page("/dashboard/inbox/\(t.item.uuidString.lowercased())", t.owner)
            XCTAssertEqual(own.status, .ok, own.text)
            XCTAssertTrue(own.text.contains("Morning"), "the answer the customer chose")
            // Another tenant's item id: not found, for reading and for every action.
            try await eq(try await h.page("/dashboard/inbox/\(t.otherItem.uuidString.lowercased())", t.owner).status, .notFound)
            for (path, form) in [("decide", [("decision", "accept")]), ("note", [("note", "hi")]), ("assign", [("assignee", "none")])] {
                let response = try await h.formPost("/dashboard/inbox/\(t.otherItem.uuidString.lowercased())/\(path)", t.owner, form)
                XCTAssertEqual(response.status, .notFound, "\(path): \(response.text)")
            }
            try await eq(try await LoopRuntimeService(db: h.db, ctx: h.ctx).currentOutcome(eventId: try await InboxItemRecord.find(t.otherItem, on: h.db)!.eventId)?.outcomeValue, .pending)
            // Read receipts and the accept flow on the own item.
            let accept = try await h.formPost("/dashboard/inbox/\(t.item.uuidString.lowercased())/decide", t.owner, [("decision", "accept")])
            XCTAssertEqual(accept.status, .seeOther, accept.text)
            try await eq(try await InboxReadRecord.query(on: h.db).filter(\.$itemId == t.item).count(), 1)
            try await isTrue(try await AuditEventRecord.query(on: h.db).filter(\.$action == "inbox.decision").count() == 1)
        }
    }

    func testAViewerCannotActAndARoleDowngradeTakesEffectImmediately() async throws {
        try await withHarness { h in
            let t = try await tenants(h)
            let auditor = try await h.addMember(owner: t.owner, role: .auditor, email: "auditor@example.com")
            let operatorMember = try await h.addMember(owner: t.owner, role: .messagingOperator, email: "ops@example.com")
            let itemPath = "/dashboard/inbox/\(t.item.uuidString.lowercased())"
            // The viewer reads but cannot act.
            try await eq(try await h.page(itemPath, auditor.session).status, .ok)
            for (path, form) in [("decide", [("decision", "accept")]), ("note", [("note", "hi")]), ("assign", [("assignee", "none")])] {
                try await eq(try await h.formPost("\(itemPath)/\(path)", auditor.session, form).status, .forbidden)
            }
            try await eq(try await h.formPost("/dashboard/inbox/hours", auditor.session, [("queue", "default"), ("timezone", "UTC")]).status, .forbidden)
            // The messaging operator can act...
            let note = try await h.formPost("\(itemPath)/note", operatorMember.session, [("note", "Calling them back.")])
            XCTAssertEqual(note.status, .seeOther, note.text)
            // ...until downgraded: the next request is refused, with no new sign-in needed.
            try await OrgMembershipRecord.query(on: h.db).filter(\.$businessId == t.businessId).filter(\.$userId == operatorMember.account.userId)
                .set(\.$role, to: OrgRole.analyst.rawValue).update()
            try await eq(try await h.formPost("\(itemPath)/note", operatorMember.session, [("note", "Again.")]).status, .forbidden)
            try await eq(try await h.page(itemPath, operatorMember.session).status, .forbidden)
            try await eq(try await InboxNoteRecord.query(on: h.db).count(), 1)
            // An inbox item can only be assigned to a member of this organization who can see the inbox.
            let assign = try await h.formPost("\(itemPath)/assign", t.owner, [("assignee", operatorMember.account.userId.uuidString)])
            XCTAssertEqual(assign.status, .unprocessableEntity, assign.text)
        }
    }

    func testTheTenantExportContainsOnlyThisTenantsLoopsAndInbox() async throws {
        try await withHarness { h in
            let t = try await tenants(h)
            let document = try await TenantDataRequests(db: h.db, ctx: h.ctx).document(businessId: t.businessId)
            let data = try JSONSerialization.data(withJSONObject: document)
            let text = String(decoding: data, as: UTF8.self)
            let inbox = document["inbox"] as? [[String: Any]]
            XCTAssertEqual(inbox?.count, 1)
            XCTAssertEqual(inbox?.first?["item"] as? String, t.item.uuidString.lowercased())
            XCTAssertFalse(text.contains(t.otherItem.uuidString.lowercased()))
            XCTAssertFalse(text.contains(t.otherBusiness.uuidString.lowercased()))
            XCTAssertFalse(text.contains(t.world.alice.id.uuid.uuidString.lowercased()), "customers appear only as instance ids")
            XCTAssertEqual((document["loops"] as? [[String: Any]])?.count, 1)
            // Tenant deletion removes this tenant's Loop and inbox rows (append-only events included) and nothing of the other tenant.
            try await LoopTenantData.delete(businessId: t.businessId, on: h.db)
            for count in [try await InboxItemRecord.query(on: h.db).filter(\.$businessId == t.businessId).count(),
                          try await LoopActionEventRecord.query(on: h.db).filter(\.$businessId == t.businessId).count(),
                          try await LoopRevisionRecord.query(on: h.db).filter(\.$businessId == t.businessId).count()] { XCTAssertEqual(count, 0) }
            try await eq(try await InboxItemRecord.query(on: h.db).filter(\.$businessId == t.otherBusiness).count(), 1)
            try await eq(try await LoopActionEventRecord.query(on: h.db).filter(\.$businessId == t.otherBusiness).count(), 2)
        }
    }

    func testOperatingHoursAndConsolePagesAreAccessible() async throws {
        try await withHarness { h in
            let t = try await tenants(h)
            let saved = try await h.formPost("/dashboard/inbox/hours", t.owner, [("queue", "pickups"), ("hours", "1-5 09:00-17:00"), ("timezone", "America/Phoenix")])
            XCTAssertEqual(saved.status, .seeOther, saved.text)
            let bad = try await h.formPost("/dashboard/inbox/hours", t.owner, [("queue", "pickups"), ("hours", "always"), ("timezone", "UTC")])
            XCTAssertEqual(bad.status, .unprocessableEntity, bad.text)
            let page = try await h.page("/dashboard/inbox", t.owner)
            XCTAssertTrue(page.text.contains("aria-live=\"polite\""))
            XCTAssertTrue(page.text.contains("<caption"))
            XCTAssertFalse(page.text.contains("<script"), "no script: new items appear on reload")
            let hours = try XCTUnwrap(OperatingHours.parse("1-5 09:00-17:00; 6 10:00-14:00"))
            let zone = TimeZone(identifier: "UTC")!
            // 2027-01-15 is a Friday.
            let friday = ISO8601DateFormatter().date(from: "2027-01-15T10:00:00Z")!
            XCTAssertTrue(hours.isOpen(at: friday, timezone: zone))
            XCTAssertFalse(hours.isOpen(at: friday.addingTimeInterval(8 * 3600), timezone: zone))
            XCTAssertFalse(hours.isOpen(at: friday.addingTimeInterval(2 * 86_400), timezone: zone), "Sunday")
            let loops = try await h.page("/dashboard/loops", t.owner)
            XCTAssertEqual(loops.status, .ok, loops.text)
            XCTAssertTrue(loops.text.contains("only Viadere publishes"))
        }
    }
}
