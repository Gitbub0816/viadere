@preconcurrency import Crypto
import Fluent
import Foundation
import XCTest
import ViadereCore
@testable import ViadereServerKit

/// ADR-0020 revisions 3 and 3.1: grouping of one person's open requests (match tags, `session_handle`, group pressure).
final class AuthGroupingTests: AuthDeliveryTestBase {

    func tag(_ code: String) -> String { Base64URL.encode(Data(SHA256.hash(data: Data("t\(code)".utf8)))) }
    func members(_ code: String) -> AuthMatchTagMembers { AuthMatchTagMembers(matchTag: tag(code), matchPrefixTag: code.count == 3 ? tag(String(code.prefix(2))) : nil) }

    func reserve(_ h: TestHarness, _ s: (b: UUID, c: UUID), _ code: String, ref: UUID = UUID()) async throws -> APIError? {
        do {
            let m = members(code)
            try await h.db.transaction { tx in try await AuthMatchGroups(db: tx, ctx: h.ctx).reserve(businessId: s.b, consumerId: s.c, refId: ref, members: m) }
            return nil
        } catch let error as APIError { return error }
    }

    func group(_ h: TestHarness, handle: String = "northwind") async throws -> (b: UUID, c: UUID) {
        let b = try await h.makeBusiness(name: handle, handle: handle)
        let consumer = try await h.readyConsumer()
        return (b.id.uuid, consumer.id.uuid)
    }

    func testCodesAreCollisionFreeAndPrefixFreeWithinAGroupAndIndependentAcrossGroups() async throws {
        try await harness { h in
            let g = try await group(h)
            let other = try await group(h, handle: "contoso")
            let first = try await reserve(h, g, "42"); XCTAssertNil(first)
            let a = try await reserve(h, g, "42"); XCTAssertEqual(a?.code, .matchCodeInUse); XCTAssertEqual(a?.status, .conflict)
            let b = try await reserve(h, g, "421"); XCTAssertEqual(b?.code, .matchCodeInUse)
            let c = try await reserve(h, g, "517"); XCTAssertNil(c)
            let d = try await reserve(h, g, "51"); XCTAssertEqual(d?.code, .matchCodeInUse)
            let e = try await reserve(h, g, "518"); XCTAssertNil(e)
            let f = try await reserve(h, other, "42"); XCTAssertNil(f, "another person's group is independent")
            // Nothing was created by the refusals.
            let rows = try await AuthMatchTagRecord.query(on: h.db).filter(\.$consumerId == g.c).count()
            XCTAssertEqual(rows, 3)
        }
    }

    func testThreeDigitsAreRequiredFromThirtyOpenRequests() async throws {
        try await harness { h in
            let g = try await group(h)
            for i in 10..<39 { let r = try await reserve(h, g, String(i)); XCTAssertNil(r, "\(i)") }
            let ok = try await reserve(h, g, "90"); XCTAssertNil(ok)                     // the 30th
            let need = try await reserve(h, g, "91")
            XCTAssertEqual(need?.code, .matchDigitsRequired); XCTAssertEqual(need?.details?["digits"], "3")
            let three = try await reserve(h, g, "912"); XCTAssertNil(three)
        }
    }

    func testExhaustionIsA409AndAlertsAndTagsAreReleasedAtTheTerminalState() async throws {
        try await harness { h in
            let g = try await group(h)
            // Fill the 3-digit space directly (900 distinct, prefix-free codes).
            for code in 100...999 {
                let row = AuthMatchTagRecord()
                row.id = UUID(); row.businessId = g.b; row.consumerId = g.c; row.refId = UUID(); row.tag = tag(String(code)); row.prefixTag = tag(String(code / 10)); row.createdAt = h.clock.now()
                try await row.create(on: h.db)
            }
            var r: APIError?
            do { try await AuthMatchGroups(db: h.db, ctx: h.ctx).check(businessId: g.b, consumerId: g.c, members: members("555")) } catch let error as APIError { r = error }
            XCTAssertEqual(r?.code, .matchCodeSpaceExhausted); XCTAssertEqual(r?.status, .conflict)
            let viaReserve = try await reserve(h, g, "555")
            XCTAssertEqual(viaReserve?.code, .matchCodeSpaceExhausted)
            let audits = try await AuditEventRecord.query(on: h.db).filter(\.$action == "auth_delivery.match_code_space_exhausted").count()
            XCTAssertEqual(audits, 1)
            // Releasing one request frees its code.
            let firstTag = try await AuthMatchTagRecord.query(on: h.db).first()
            let victimRef = try XCTUnwrap(firstTag?.refId)
            try await AuthMatchGroups(db: h.db, ctx: h.ctx).release(refId: victimRef)
            let again = try await AuthMatchTagRecord.query(on: h.db).filter(\.$refId == victimRef).count()
            XCTAssertEqual(again, 0)
        }
    }

    func testTerminalDeliveriesReleaseTheirTags() async throws {
        try await harness { h in
            let s = try await scene(h)
            let id = try await created(h, s).id
            let m = members("77")
            try await h.db.transaction { tx in
                try await AuthMatchGroups(db: tx, ctx: h.ctx).reserve(businessId: s.b.id.uuid, consumerId: s.consumer.id.uuid, refId: id.uuid, members: m)
            }
            let before = try await AuthMatchTagRecord.query(on: h.db).count()
            XCTAssertEqual(before, 1)
            _ = try await h.business(s.b, .POST, "/v1/business/auth-deliveries/\(id)/cancel", idempotencyKey: "c")
            let after = try await AuthMatchTagRecord.query(on: h.db).count()
            XCTAssertEqual(after, 0)
        }
    }

    /// Revision 3.1: a handle seen on more than 3 distinct request ids within 10 minutes stops superseding (and is audited); nothing is cancelled or refused.
    func testASessionHandleOnManyRequestsStopsSuperseding() async throws {
        try await harness { h in
            let s = try await scene(h)
            let t = self
            var ids: [AuthDeliveryView] = []
            for i in 0..<4 { ids.append(try await t.created(h, s, id: "w-\(i)", extra: ["session_handle": "sess_x"])) }
            // The 1st..3rd supersede each other as usual; the 4th arrives with 3 distinct earlier ids, so its handle is ignored.
            let statuses = try await ids.asyncMap { try await t.get(h, s, $0.id).status }
            XCTAssertEqual(statuses.last, .queued)
            XCTAssertEqual(statuses.filter { $0 == .queued }.count, 2, "the 3rd (still open) and the 4th")
            let abuse = try await AuditEventRecord.query(on: h.db).filter(\.$action == "auth_delivery.session_handle_abuse").count()
            XCTAssertEqual(abuse, 1)
            // A later request with the same handle never cancels the earlier open ones.
            let fifth = try await t.created(h, s, id: "w-5", extra: ["session_handle": "sess_x"])
            let open = try await ids.asyncMap { try await t.get(h, s, $0.id).status }
            XCTAssertEqual(open.filter { $0 == .queued }.count, 2)
            let f = try await t.get(h, s, fifth.id)
            XCTAssertEqual(f.status, .queued)
        }
    }

    func testGroupPressureIsAuditedAboveTenOpenRequestsAtMostOncePerHour() async throws {
        try await harness { h in
            let s = try await scene(h)
            let t = self
            for i in 0..<10 { _ = try await t.created(h, s, id: "p-\(i)") }
            var count = try await AuditEventRecord.query(on: h.db).filter(\.$action == "auth_delivery.group_pressure").count()
            XCTAssertEqual(count, 0, "10 open requests are not pressure")
            for i in 10..<14 { _ = try await t.created(h, s, id: "p-\(i)") }
            count = try await AuditEventRecord.query(on: h.db).filter(\.$action == "auth_delivery.group_pressure").count()
            XCTAssertEqual(count, 1, "at most once per group per hour")
            let event = try await AuditEventRecord.query(on: h.db).filter(\.$action == "auth_delivery.group_pressure").first()
            XCTAssertFalse(event?.metadataJSON.contains("482913") ?? true)
            // Nothing was refused because of the per-person count.
            let all = try await AuthDeliveryRecord.query(on: h.db).count()
            XCTAssertEqual(all, 14)
        }
    }
}

extension Array {
    func asyncMap<T>(_ transform: (Element) async throws -> T) async rethrows -> [T] {
        var out: [T] = []
        for element in self { out.append(try await transform(element)) }
        return out
    }
}

