import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Platform gate (Phase 0/1): legal holds (L2), the metrics listener (L3), webhook ownership (L4) and operator notice delivery (L5).
final class PlatformGateOpsTests: XCTestCase {
    private func days(_ n: Int) -> TimeInterval { Double(n) * 86_400 }

    // MARK: L2

    func testAnyLegalHoldKeepsTheAuditChainFromBeingPurged() async throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent("heads-" + UUID().uuidString).path
        defer { try? FileManager.default.removeItem(atPath: directory) }
        try await withHarness({ config in
            config.operations.auditExport = AuditHeadExportSettings(kind: .directory, target: directory, prefix: "audit-heads/", endpoint: nil, interval: 3_600, kmsKey: nil)
        }) { h in
            let business = try await h.makeBusiness(name: "Held Co", handle: "heldco")
            for index in 0..<4 { _ = try await AuditService(db: h.db, ctx: h.ctx).record("seed.\(index)", actor: AuditActor(kind: .system)) }
            _ = try await AuditHeadExporter(db: h.db, ctx: h.ctx).runIfDue()
            h.clock.advance(by: days(2_600))
            _ = try await AuditService(db: h.db, ctx: h.ctx).record("fresh.head", actor: AuditActor(kind: .system))
            let before = try await AuditEventRecord.query(on: h.db).count()
            // A hold on ONE business: the audit chain cannot be purged selectively, so nothing is purged while any hold exists.
            let hold = try await RetentionPolicy(db: h.db, ctx: h.ctx).placeHold(scopeKind: "business", scopeId: business.record.id!.uuidString, reason: "Litigation hold LH-2027-9", operatorId: UUID())
            var report = await RetentionPurger(db: h.db, ctx: h.ctx).run()
            XCTAssertEqual(report.skipped[RetentionClass.auditEvents.rawValue], "legal_hold", "\(report.skipped)")
            let held = try await AuditEventRecord.query(on: h.db).count()
            XCTAssertGreaterThanOrEqual(held, before, "no audit event was deleted while a hold was active")
            try await RetentionPolicy(db: h.db, ctx: h.ctx).releaseHold(id: hold.id!, operatorId: UUID())
            report = await RetentionPurger(db: h.db, ctx: h.ctx).run()
            XCTAssertGreaterThan(report.counts[RetentionClass.auditEvents.rawValue] ?? 0, 0, "\(report)")
        }
    }

    func testATenantDeletionCannotCompleteWhileAHoldCoversTheBusinessOrEverything() async throws {
        try await withHarness { h in
            let business = try await h.makeBusiness(name: "Doomed Co", handle: "doomedco")
            let businessId = business.record.id!
            let request = DataRequestRecord()
            request.id = UUID()
            request.businessId = businessId
            request.kind = "delete"
            request.status = "requested"
            request.requestedBy = UUID()
            request.createdAt = h.clock.now()
            try await request.create(on: h.db)
            let requests = TenantDataRequests(db: h.db, ctx: h.ctx)
            let policy = RetentionPolicy(db: h.db, ctx: h.ctx)
            let businessHold = try await policy.placeHold(scopeKind: "business", scopeId: businessId.uuidString, reason: "Litigation hold LH-2027-10", operatorId: UUID())
            do { try await requests.complete(id: request.id!, operatorId: UUID()); XCTFail("a business hold must block deletion") } catch let error as APIError { XCTAssertEqual(error.status, .conflict) }
            var still = try await XCTUnwrapAsync(await BusinessRecord.find(businessId, on: h.db))
            XCTAssertEqual(still.displayName, "Doomed Co")
            try await policy.releaseHold(id: businessHold.id!, operatorId: UUID())
            let global = try await policy.placeHold(scopeKind: "global", scopeId: nil, reason: "Regulator request REG-10", operatorId: UUID())
            do { try await requests.complete(id: request.id!, operatorId: UUID()); XCTFail("a global hold must block deletion") } catch let error as APIError { XCTAssertEqual(error.status, .conflict) }
            try await policy.releaseHold(id: global.id!, operatorId: UUID())
            // A hold on someone else's business does not stop this deletion.
            _ = try await policy.placeHold(scopeKind: "business", scopeId: UUID().uuidString, reason: "Litigation hold LH-2027-11", operatorId: UUID())
            try await requests.complete(id: request.id!, operatorId: UUID())
            still = try await XCTUnwrapAsync(await BusinessRecord.find(businessId, on: h.db))
            XCTAssertEqual(still.displayName, "Deleted business")
        }
    }
}
