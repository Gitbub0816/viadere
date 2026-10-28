@preconcurrency import Crypto
import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Phase 3 gate F3: the Didit purge never gives up silently, backs off in time, raises an alert signal, and survives the new-sessions switch.
extension VerifyFlowTests {
    /// A document attempt whose Didit session is finished and whose deletion keeps failing.
    func failingPurge(_ r: Rig, _ fake: FakeDidit) async throws -> (attempt: VerificationAttemptRecord, session: String) {
        let id = try await createdID(r)
        try await consent(r, id)
        let (start, session) = try await beginDocument(r, id)
        fake.setDecision(session, FakeDidit.decision(session: session, vendorData: start.attemptId.uuidString.lowercased()))
        fake.failDelete(100_000)
        try await eq(try await signedWebhook(r, session: session).status, .ok)
        let attempt = try unwrap(try await VerificationAttemptRecord.query(on: r.h.db).first())
        XCTAssertEqual(attempt.purgeStatus, "failed")
        return (attempt, session)
    }

    func gauge(_ h: TestHarness, _ name: String) async -> Double? {
        await MetricsService(db: h.db, ctx: h.ctx).gauges().first { $0.name == name }?.value
    }

    /// Exploit: a ~150 s provider outage abandoned the purge forever (30 tries at the 5 s job tick), leaving the images at Didit.
    func testAProviderOutageOfAnyLengthNeverAbandonsThePurge() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let (_, session) = try await failingPurge(r, fake)
            // 20 minutes of outage at the 5 s job tick: far beyond the old 30-try cap.
            let callsBefore = fake.deleteCalls
            for _ in 0..<240 {
                h.clock.advance(by: 5)
                try await h.runJobs()
            }
            var attempt = try unwrap(try await VerificationAttemptRecord.query(on: h.db).first())
            XCTAssertEqual(attempt.purgeStatus, "failed", "still pending, never abandoned")
            XCTAssertTrue(fake.deleted.isEmpty)
            // Exponential backoff in time, not one try per tick: 30 s, 1 m, 2 m, 4 m, 8 m ... is about 6 tries in 20 minutes.
            XCTAssertLessThanOrEqual(fake.deleteCalls - callsBefore, 8, "retries are spaced")
            XCTAssertGreaterThanOrEqual(fake.deleteCalls - callsBefore, 4)
            XCTAssertEqual(VerifyService.purgeBackoff(afterFailures: 1), 30)
            XCTAssertEqual(VerifyService.purgeBackoff(afterFailures: 2), 60)
            XCTAssertEqual(VerifyService.purgeBackoff(afterFailures: 40), VerifyService.purgeBackoffCap)
            XCTAssertNotNil(attempt.purgeNextAt)
            // Days of failures: the count is irrelevant; the purge happens when Didit comes back.
            attempt.purgeAttempts = 500
            attempt.purgeNextAt = h.clock.now().addingTimeInterval(86_400)
            try await attempt.update(on: h.db)
            fake.failDelete(0)
            try await h.runJobs()
            XCTAssertTrue(fake.deleted.isEmpty, "not before the backoff elapses")
            h.clock.advance(by: 86_401)
            try await h.runJobs()
            XCTAssertEqual(fake.deleted.map(\.session), [session])
            attempt = try unwrap(try await VerificationAttemptRecord.query(on: h.db).first())
            XCTAssertEqual(attempt.purgeStatus, "done")
        }
    }

    /// The silent failure becomes a signal: a counter, and gauges that go above 0 once a purge is overdue.
    func testAFailingPurgeRaisesTheMetricAndTheOverdueAlertSignal() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            _ = try await failingPurge(r, fake)
            XCTAssertGreaterThanOrEqual(h.ctx.metrics.value(.verifyPurgeFailed), 1)
            let pending = await gauge(h, "viadere_verify_provider_purge_pending")
            let early = await gauge(h, "viadere_verify_provider_purge_overdue")
            XCTAssertEqual(pending, 1)
            XCTAssertEqual(early, 0, "a fresh failure is not yet an alert")
            h.clock.advance(by: VerifyService.purgeAlertAfter + 60)
            let late = await gauge(h, "viadere_verify_provider_purge_overdue")
            let age = await gauge(h, "viadere_verify_provider_purge_oldest_seconds")
            XCTAssertEqual(late, 1, "older than the threshold and still not deleted")
            XCTAssertGreaterThan(try XCTUnwrap(age), VerifyService.purgeAlertAfter)
            let text = await MetricsService(db: h.db, ctx: h.ctx).render()
            XCTAssertTrue(text.contains("viadere_verify_provider_purge_overdue 1"))
            XCTAssertTrue(text.contains("viadere_security_events_total{event=\"verify_purge_failed\"}"))
            // Once Didit answers, the signal clears.
            fake.failDelete(0)
            try await h.runJobs()
            let after = await gauge(h, "viadere_verify_provider_purge_overdue")
            XCTAssertEqual(after, 0)
        }
    }

    /// Exploit: the only way to stop Didit was removing the API key, which also stopped every purge. The new-sessions switch stops starting
    /// sessions while leaving the purge client in place; the client needs only the API key.
    func testTheNewSessionsSwitchStopsNewSessionsButNotThePurge() async throws {
        try await withVerify { h, fake in
            let r = try await rig(h, fake)
            let (_, session) = try await failingPurge(r, fake)
            var config = h.ctx.config
            config.verify.diditNewSessionsEnabled = false
            XCTAssertFalse(h.app.verify.documentAvailable(settings: config.verify), "no new session")
            XCTAssertTrue(h.app.verify.documentAvailable(settings: h.ctx.config.verify))
            // The purge client exists with only the API key (no workflow, no webhook secret) and with the switch off.
            let purgeOnly = try await Application.make(.testing)
            config.verify.diditWorkflowIdentity = nil
            config.verify.diditWebhookSecrets = []
            VerifyRegistration.configure(purgeOnly, config: config)
            XCTAssertNotNil(purgeOnly.verify.didit, "credentials exist, so the purge client exists")
            XCTAssertFalse(purgeOnly.verify.documentAvailable(settings: config.verify))
            try await purgeOnly.asyncShutdown()
            // And a leftover session is still deleted while the switch is off.
            fake.failDelete(0)
            h.clock.advance(by: 120)
            try await h.runJobs()
            XCTAssertEqual(fake.deleted.map(\.session), [session])
        }
    }

    func testTheNewSessionsSwitchRefusesNewDocumentSessions() async throws {
        try await withHarness({ config in
            config.verify.enabled = true
            config.verify.diditAPIKey = "test-api-key"
            config.verify.diditWorkflowIdentity = "workflow-identity"
            config.verify.diditWebhookSecrets = [DiditWebhookTests.secret]
            config.verify.diditNewSessionsEnabled = false
        }) { h in
            let fake = FakeDidit()
            h.app.verify.didit = fake
            let r = try await rig(h, fake)
            let id = try await createdID(r)
            try await consent(r, id)
            let methods = try await prompt(r, id).methods
            XCTAssertEqual(methods.first { $0.kind == .document }?.available, false)
            let response = try await r.h.signedPost(r.consumer, "/v1/verifications/\(id)/document/begin", EmptyBody())
            XCTAssertEqual(response.status, .serviceUnavailable)
            XCTAssertTrue(fake.created.isEmpty)
        }
    }
}
