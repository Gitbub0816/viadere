@preconcurrency import Crypto
import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Phase 3 gate: what a business can see of the audit log (AGE-005 oracle, cross-tenant linkage).
extension VerifyFlowTests {
    /// The tenant export as a string, exactly as a business would receive it.
    func exportText(_ h: TestHarness, _ business: TestBusiness) async throws -> (text: String, events: [[String: Any]]) {
        let document = try await TenantDataRequests(db: h.db, ctx: h.ctx).document(businessId: business.id.uuid)
        let data = try JSONSerialization.data(withJSONObject: document, options: [.sortedKeys, .withoutEscapingSlashes])
        return (String(decoding: data, as: UTF8.self), document["auditEvents"] as? [[String: Any]] ?? [])
    }

    /// F1 (AGE-005): under the threshold, declined and expired leave the business byte-identical audit rows.
    func testTheBusinessAuditTrailAndExportAreIdenticalForUnderageDeclinedAndExpired() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let a = try await createdID(r), b = try await createdID(r), c = try await createdID(r)
            try await consent(r, a)
            for _ in 0..<3 { _ = try await wallet(r, a, elements: ageOver(21, false)) }
            try await eq(try await h.signedPost(r.consumer, "/v1/verifications/\(b)/decline", EmptyBody()).status, .ok)
            h.clock.advance(by: 301)
            try await h.runJobs()
            for id in [a, b, c] { let ref = try await unwrap(try await resource(r, id).resultRef); _ = try await result(r, ref) }

            let export = try await exportText(h, r.b)
            // The rows of one request, with the request id and time masked: the same bytes for every non-positive end.
            func shape(_ id: VerificationRequestID) -> String {
                export.events.filter { ($0["subject"] as? String) == id.description }
                    .map { "\($0["action"] ?? "")|\($0["outcome"] ?? "")|\($0["actor"] ?? "")" }.sorted().joined(separator: "\n")
            }
            XCTAssertEqual(shape(a), shape(b))
            XCTAssertEqual(shape(b), shape(c))
            XCTAssertEqual(Set(export.events.filter { ($0["subject"] as? String) == a.description }.compactMap { $0["action"] as? String }),
                           ["verification.requested", "verification.completed", "verification.result_retrieved"])
            for word in ["attempts_exhausted", "declined", "expired", "wallet_", "reason", "estimate_only", "document_", "attempt_", "disclosure", "method"] {
                XCTAssertFalse(export.text.contains(word), "the export must not carry \(word)")
            }
            // The same events through the dashboard projection (what the audit page renders) are identical too.
            let rows = try await AuditEventRecord.query(on: h.db).filter(\.$businessId == r.b.id.uuid).sort(\.$seq, .ascending).all()
            let projected = BusinessAuditProjection(ctx: h.ctx).project(rows)
            for id in [a, b, c] {
                let mine = projected.filter { $0.subjectId == id.description }
                XCTAssertEqual(mine.map(\.action).sorted(), ["verification.completed", "verification.requested", "verification.result_retrieved"].sorted())
                XCTAssertEqual(mine.first { $0.action == "verification.completed" }?.metadata, ["capability": "age.minimum", "outcome": "not_verified"])
                XCTAssertEqual(mine.first { $0.action == "verification.completed" }?.outcome, "failure")
            }
            // The detail still exists, in the platform-only trail (no business id).
            let platform = try await AuditEventRecord.query(on: h.db).filter(\.$businessId == nil).filter(\.$action ~~ ["verification.concluded", "verification.wallet_verified", "verification.attempt_started", "consent.disclosure_granted"]).all()
            XCTAssertTrue(platform.contains { $0.action == "verification.concluded" && $0.metadataJSON.contains("attempts_exhausted") })
            XCTAssertTrue(platform.contains { $0.action == "verification.wallet_verified" }, "an under-age answer is a verified presentment: platform trail only")
            XCTAssertTrue(platform.contains { $0.action == "consent.disclosure_granted" })
            for event in try await AuditEventRecord.query(on: h.db).filter(\.$businessId == r.b.id.uuid).all() where event.action.hasPrefix("verification.") {
                XCTAssertTrue(BusinessAuditProjection.businessVisibleVerifyActions.contains(event.action), "business-scoped Verify event \(event.action)")
            }
        }
    }

    /// F1: rows written before the platform-only split are hidden from, or reduced in, every business view.
    func testDetailedVerifyRowsWrittenBeforeTheSplitNeverReachABusinessView() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let audit = AuditService(db: h.db, ctx: h.ctx)
            let consumer = r.consumer.id
            for (action, outcome) in [("verification.wallet_verified", AuditEvent.Outcome.success), ("verification.document_rejected", .failure), ("consent.disclosure_granted", .success)] {
                _ = try await audit.record(action, outcome: outcome, actor: AuditActor(kind: .consumer, id: consumer.description), consumerId: consumer,
                                           businessId: r.b.id, subjectType: "verification_request", subjectId: UUID().uuidString.lowercased(), metadata: ["reason": "age_under"])
            }
            _ = try await audit.record("verification.completed", outcome: .failure, actor: AuditActor(kind: .system, id: "verify"), consumerId: consumer, businessId: r.b.id,
                                       subjectType: "verification_request", subjectId: UUID().uuidString.lowercased(),
                                       metadata: ["capability": "age.minimum", "outcome": "not_verified", "reason": "attempts_exhausted", "status": "not_verified", "method": "wallet"])
            let export = try await exportText(h, r.b)
            for word in ["wallet_verified", "document_rejected", "disclosure", "attempts_exhausted", "age_under", "method"] { XCTAssertFalse(export.text.contains(word), word) }
            XCTAssertTrue(export.text.contains("verification.completed"))
        }
    }

    /// F2: no global consumer identifier in any business-facing audit view or export; the consumer is that business's `subject_ref`.
    func testNoGlobalConsumerIdentifierReachesAnyBusinessAuditView() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let other = try await h.makeBusiness(name: "Rival Co", handle: "rivalco", capabilities: Capability.operational + Self.verifyCapabilities)
            let theirRelationship = try await h.connect(r.consumer, to: other)
            let theirRef = try await subjectRef(h, theirRelationship)
            // Verify consent plus every other event that names the person (connect, disconnect).
            let id = try await createdID(r)
            try await consent(r, id)
            _ = try await wallet(r, id, elements: ageOver(21))
            _ = try await h.signed(r.consumer, .DELETE, "/v1/relationships/\(theirRelationship.id)")
            // Events from other paths that carry the consumer id in the actor, the subject or the metadata.
            let audit = AuditService(db: h.db, ctx: h.ctx)
            let consumerId = r.consumer.id.description
            for target in [r.b, other] {
                _ = try await audit.record("future.event", actor: AuditActor(kind: .consumer, id: consumerId), consumerId: r.consumer.id, businessId: target.id,
                                           subjectType: "consumer", subjectId: consumerId, metadata: ["consumer_id": consumerId, "note": "for \(consumerId)"])
                _ = try await audit.record("future.device_event", actor: AuditActor(kind: .device, id: UUID().uuidString.lowercased()), consumerId: r.consumer.id, businessId: target.id)
            }
            let a = try await exportText(h, r.b), b = try await exportText(h, other)
            XCTAssertFalse(a.text.contains(consumerId), "business A's export")
            XCTAssertFalse(b.text.contains(consumerId), "business B's export")
            let aActors = Set(a.events.compactMap { $0["actor"] as? String })
            let bActors = Set(b.events.compactMap { $0["actor"] as? String })
            XCTAssertTrue(aActors.contains(r.ref.rawValue), "business A sees its own subject_ref")
            XCTAssertTrue(bActors.contains(theirRef.rawValue))
            XCTAssertFalse(aActors.contains(theirRef.rawValue))
            // No UUID-shaped identifier is common to the two exports other than none: the person is a different reference in each.
            let uuids = { (text: String) in Set(text.split { !$0.isLetter && !$0.isNumber && $0 != "-" }.map(String.init).filter { $0.count == 36 && UUID(uuidString: $0) != nil }) }
            XCTAssertTrue(uuids(a.text).isDisjoint(with: uuids(b.text)), "shared identifiers")
            XCTAssertNotEqual(r.ref, theirRef)
        }
    }
}
