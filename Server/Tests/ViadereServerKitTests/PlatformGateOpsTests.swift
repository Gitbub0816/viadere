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

    // MARK: L3

    func testTheInternalMetricsListenerBindsPrivatelyAndAlwaysNeedsTheToken() async throws {
        let token = SecureToken.generate()
        var env = ["ENVIRONMENT": "development", "METRICS_PORT": "9091", "METRICS_TOKEN": token]
        // Without a private address the listener is loopback only; with the machine's 6PN address it binds there; never the public HTTP host.
        XCTAssertEqual(try ServerConfig.fromEnvironment(env).operations.metricsHost, "127.0.0.1")
        env["FLY_PRIVATE_IP"] = "fdaa:0:1234:a7b:1:2:3:2"
        XCTAssertEqual(try ServerConfig.fromEnvironment(env).operations.metricsHost, "fdaa:0:1234:a7b:1:2:3:2")
        for bad in ["0.0.0.0", "::", "not-an-ip", "10.0.0.1/8"] {
            env["FLY_PRIVATE_IP"] = bad
            XCTAssertThrowsError(try ServerConfig.fromEnvironment(env), bad)
        }
        // A port without a token would serve metrics to anything on the private network: the server does not start.
        var noToken = ["ENVIRONMENT": "development", "METRICS_PORT": "9091"]
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(noToken))
        noToken["METRICS_PORT"] = nil
        XCTAssertNil(try ServerConfig.fromEnvironment(noToken).operations.metricsPort)

        // The listener's answers: the token is required on the private port too.
        let secret = Data(token.utf8)
        let render: @Sendable () async -> String = { "viadere_up 1\n" }
        let none = await InternalMetricsResponder.respond(method: .GET, uri: "/metrics", authorization: nil, token: secret, render: render)
        XCTAssertEqual(none.0, .unauthorized)
        let wrong = await InternalMetricsResponder.respond(method: .GET, uri: "/metrics", authorization: "Bearer " + SecureToken.generate(), token: secret, render: render)
        XCTAssertEqual(wrong.0, .unauthorized)
        let ok = await InternalMetricsResponder.respond(method: .GET, uri: "/metrics?x=1", authorization: "Bearer " + token, token: secret, render: render)
        XCTAssertEqual(ok.0, .ok)
        XCTAssertEqual(ok.1, "viadere_up 1\n")
        let post = await InternalMetricsResponder.respond(method: .POST, uri: "/metrics", authorization: "Bearer " + token, token: secret, render: render)
        XCTAssertEqual(post.0, .notFound)
        let noneConfigured = await InternalMetricsResponder.respond(method: .GET, uri: "/metrics", authorization: "Bearer anything", token: nil, render: render)
        XCTAssertEqual(noneConfigured.0, .notFound, "no token configured: nothing is served")
    }

    // MARK: L5

    /// Platform gate L5: every instance ran `deliverDue` each tick with no claim, so two runners both read the same open notice and both mailed it.
    func testTwoRunnersDeliverAnOperatorNoticeOnce() async throws {
        try await withHarness { h in
            let (op, _) = try await h.makeOperator()
            _ = try await h.verifiedOwner()
            let created = try await h.formPost("/operator/notices", op, [("scope", "all_businesses"), ("severity", "important"), ("title", "Rotate your API keys"),
                                                                       ("body", "A third-party leak may affect keys created before Monday. Rotate them in the console.")])
            XCTAssertEqual(created.status, .seeOther, created.text)
            let before = h.emails.sent.count
            let db = h.db, ctx = h.ctx
            _ = try await withThrowingTaskGroup(of: Int.self) { group in
                for _ in 0..<4 { group.addTask { try await OperatorNotices(db: db, ctx: ctx).deliverDue() } }
                var total = 0
                for try await n in group { total += n }
                return total
            }
            let mails = h.emails.sent.dropFirst(before).filter { $0.to == "owner@example.com" && $0.subject == "Rotate your API keys" }
            XCTAssertEqual(mails.count, 1, "four concurrent runners must produce one delivery")
            let notice = try await XCTUnwrapAsync(await OperatorNoticeRecord.query(on: h.db).first())
            XCTAssertEqual(notice.status, "done")
            XCTAssertEqual(notice.delivered, 1)
            XCTAssertNil(notice.claimToken, "the claim is released when the batch is done")
        }
    }

    func testAHeldClaimBlocksOtherRunnersUntilItsLeaseExpires() async throws {
        try await withHarness { h in
            let (op, _) = try await h.makeOperator()
            _ = try await h.verifiedOwner()
            _ = try await h.formPost("/operator/notices", op, [("scope", "all_businesses"), ("severity", "info"), ("title", "Planned maintenance"),
                                                             ("body", "We will be read-only for ten minutes on Sunday at 03:00 UTC.")])
            let notice = try await XCTUnwrapAsync(await OperatorNoticeRecord.query(on: h.db).first())
            // Another runner holds the claim (as if it is mid-batch).
            notice.claimToken = "other-runner"
            notice.claimExpiresAt = Int(h.clock.now().timeIntervalSince1970) + 120
            try await notice.update(on: h.db)
            let before = h.emails.sent.count
            let blocked = try await OperatorNotices(db: h.db, ctx: h.ctx).deliverDue()
            XCTAssertEqual(blocked, 0)
            XCTAssertEqual(h.emails.sent.count, before)
            // The holder died: after the lease the batch is picked up exactly once.
            h.clock.advance(by: 180)
            let reclaimed = try await OperatorNotices(db: h.db, ctx: h.ctx).deliverDue()
            XCTAssertEqual(reclaimed, 1)
            let again = try await OperatorNotices(db: h.db, ctx: h.ctx).deliverDue()
            XCTAssertEqual(again, 0)
        }
    }

    // MARK: L6

    /// Platform gate L6: the household/reward code patterns (`XXXX-XXXX`) are case-sensitive over an alphabet that includes every digit and A-F, so
    /// any UUID whose adjacent middle groups were digit-only (lowercase) or any uppercase UUID had its groups masked: an audit decision then no
    /// longer named its receipt (a flake in PolicyWP2Tests, about one run in fourteen).
    func testTheRedactorNeverAltersAUUIDOrAnOpaqueIdentifier() {
        let fixed = ["12345678-1234-5678-1234-567812345678", "00000000-0000-4000-8000-000000000001", "0A1B2C3D-4E5F-6789-ABCD-EF0123456789"]
        for id in fixed {
            XCTAssertEqual(LogRedactor.redact(id), id)
            XCTAssertEqual(LogRedactor.redact(id.lowercased()), id.lowercased())
            XCTAssertEqual(LogRedactor.redact("receipt \(id) used"), "receipt \(id) used")
            XCTAssertEqual(AuditRedactor.redact(["receiptId": id]), ["receiptId": id])
        }
        for _ in 0..<3_000 {
            let id = UUID().uuidString
            XCTAssertEqual(LogRedactor.redact(id), id)
            XCTAssertEqual(LogRedactor.redact(id.lowercased()), id.lowercased())
        }
        for opaque in ["ten_0123456789abcdef0123456789abcdef", "req_8f14e45fceea167a5a36dedd4bea2543", "evt_00000000-0000-4000-8000-0000000000e1"] {
            XCTAssertEqual(LogRedactor.redact(opaque), opaque)
        }
        // What must still be masked, including next to an identifier.
        XCTAssertEqual(LogRedactor.redact("call +14155550123 now"), "call [phone] now")
        XCTAssertEqual(LogRedactor.redact("code: 482913"), "code=[redacted]")
        XCTAssertEqual(LogRedactor.redact("otp=482913 for 12345678-1234-5678-1234-567812345678"), "otp=[redacted] for 12345678-1234-5678-1234-567812345678")
        XCTAssertEqual(LogRedactor.redact("redeemed K7M2Q-9XPT4 ok"), "redeemed [redacted-code] ok")
        XCTAssertEqual(LogRedactor.redact("invite K7M2-9QXP now"), "invite [redacted-code] now")
        XCTAssertEqual(LogRedactor.redact("token=12345678-1234-5678-1234-567812345678"), "token=[redacted]")
    }
}
