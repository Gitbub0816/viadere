import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// WP-3.2 security tests (plan 5.4 "Review bypass", "Prohibited category or health field", "Revoked businesses", "Staff privilege
/// escalation"): every Loop and every revision is reviewed by Viadere before it can be signed or served.
final class LoopReviewPipelineTests: XCTestCase {
    func testAnUnreviewedRevisionCannotBeSignedEvenIfItsStateIsForced() async throws {
        try await withHarness { h in
            let world = try await LoopWorld.build(h)
            let revision = try await world.submit()
            XCTAssertEqual(revision.stateValue, .inReview)
            // Publishing straight from review is refused.
            do { try await world.publications.publish(revisionId: revision.id!); XCTFail("published without review") } catch let error as APIError {
                XCTAssertEqual(error.status, .conflict)
            }
            // Even with the state flipped behind the service's back, the gate recomputed from stored reviews refuses to sign.
            try await LoopRevisionRecord.query(on: h.db).filter(\.$id == revision.id!).set(\.$state, to: "approved").update()
            do { try await world.publications.publish(revisionId: revision.id!); XCTFail("signed an unreviewed revision") } catch let error as APIError {
                XCTAssertEqual(error.status, .forbidden)
            }
            try await eq(try await LoopPublicationRecord.query(on: h.db).count(), 0)
            try await isTrue(try await AuditEventRecord.query(on: h.db).filter(\.$action == "loop.publish_refused").count() == 1)
        }
    }

    func testASingleReviewerCannotApproveAHighRiskRevision() async throws {
        try await withHarness { h in
            let world = try await LoopWorld.build(h)
            let revision = try await world.submit(LoopFixtures.estimate)
            XCTAssertEqual(revision.riskClass, "high")
            XCTAssertEqual(revision.requiredReview, LoopReviewLevel.twoPerson.rawValue)
            let first = try await world.publications.review(revisionId: revision.id!, reviewerId: world.reviewer1, decision: .approve, reason: "Looks right.")
            XCTAssertEqual(first.stateValue, .inReview, "one approval is not enough for high risk")
            try await eq(try await LoopPublicationRecord.query(on: h.db).count(), 0)
            // The same reviewer cannot be the second person.
            do { _ = try await world.publications.review(revisionId: revision.id!, reviewerId: world.reviewer1, decision: .approve, reason: "Again."); XCTFail() } catch let error as APIError {
                XCTAssertEqual(error.status, .forbidden)
            }
            let second = try await world.publications.review(revisionId: revision.id!, reviewerId: world.reviewer2, decision: .approve, reason: "Second check.")
            XCTAssertEqual(second.stateValue, .published)
            let publication = try await LoopPublicationRecord.query(on: h.db).filter(\.$revisionId == revision.id!).first()
            XCTAssertEqual(publication?.definitionHash, revision.definitionHash, "signed over exactly the reviewed hash")
            // The manifest verifies against the served key set and binds the business, revision and hash.
            let keys = try world.publications.keySet().keys.compactMap(\.pinned)
            let manifest = try LoopPublicationManifest.verify(publication?.manifestJWS, keys: keys, now: h.clock.now())
            XCTAssertEqual(manifest.publisherBusinessId, world.business.id)
            XCTAssertEqual(manifest.definitionHash, revision.definitionHash)
            XCTAssertEqual(manifest.revision, 1)
        }
    }

    func testAnAuthorCannotReviewTheirOwnRevisionAndReviewersNeedThePermission() async throws {
        try await withHarness { h in
            let world = try await LoopWorld.build(h)
            let revision = try await world.submit(author: world.reviewer1)
            do { _ = try await world.publications.review(revisionId: revision.id!, reviewerId: world.reviewer1, decision: .approve, reason: "Mine."); XCTFail() } catch let error as APIError {
                XCTAssertEqual(error.status, .forbidden)
            }
            let outsider = try await LoopWorld.operatorId(h, "outsider@viadere.test")
            do { _ = try await world.publications.review(revisionId: revision.id!, reviewerId: outsider, decision: .approve, reason: "No permission."); XCTFail() } catch let error as APIError {
                XCTAssertEqual(error.status, .forbidden)
            }
            // A revoked permission stops working at once.
            try await OperatorPermissions(db: h.db, ctx: h.ctx).set(userId: world.reviewer2, permission: .loopReviewer, granted: false)
            do { _ = try await world.publications.review(revisionId: revision.id!, reviewerId: world.reviewer2, decision: .approve, reason: "Revoked."); XCTFail() } catch let error as APIError {
                XCTAssertEqual(error.status, .forbidden)
            }
            // A decision needs a reason.
            try await OperatorPermissions(db: h.db, ctx: h.ctx).set(userId: world.reviewer2, permission: .loopReviewer, granted: true)
            do { _ = try await world.publications.review(revisionId: revision.id!, reviewerId: world.reviewer2, decision: .approve, reason: "  "); XCTFail() } catch let error as APIError {
                XCTAssertEqual(error.status, .unprocessableEntity)
            }
            try await eq(try await LoopRevisionRecord.find(revision.id!, on: h.db)?.stateValue, .inReview)
            try await isTrue(try await AuditEventRecord.query(on: h.db).filter(\.$action == "loop.review_denied").count() >= 2)
        }
    }

    func testANewRevisionIsNotServedUntilItPassesAndTheOldOneKeepsServing() async throws {
        try await withHarness { h in
            let world = try await LoopWorld.build(h)
            let v1 = try await world.publish()
            let live = try await world.instance(world.alice, v1)
            func available() async throws -> [LoopSummary] {
                let response = try await h.signed(world.alice, .GET, "/v1/loops/available")
                XCTAssertEqual(response.status, .ok, response.text)
                return try response.json([LoopSummary].self)
            }
            try await eq(try await available().map(\.publicationId.uuid), [v1.id!])
            // Revision 2 waits for review: customers still get revision 1.
            let r2 = try await world.submit(LoopFixtures.pickup(title: "Choose your pickup time"))
            XCTAssertEqual(r2.revision, 2)
            try await eq(try await available().map(\.revision), [1])
            // A change request does not touch what is served.
            _ = try await world.publications.review(revisionId: r2.id!, reviewerId: world.reviewer1, decision: .requestChanges, reason: "Shorter title please.")
            try await eq(try await available().map(\.revision), [1])
            // Revision 3 passes: it replaces revision 1 (same audience), revision 1 is retired.
            let r3 = try await world.submit(LoopFixtures.pickup(title: "Pickup time"))
            _ = try await world.publications.review(revisionId: r3.id!, reviewerId: world.reviewer1, decision: .approve, reason: "Fine.")
            let served = try await available()
            XCTAssertEqual(served.map(\.revision), [3])
            try await eq(try await LoopPublicationRecord.find(v1.id!, on: h.db)?.statusValue, .retired)
            // An instance pinned to the retired revision may still finish; a new one cannot start on it.
            let finish = try await world.submitPickup(world.alice, live.id)
            XCTAssertEqual(finish.event.outcome, .pending)
            let refused = try await world.start(world.alice, v1)
            XCTAssertEqual(refused.status, .conflict, refused.text)
        }
    }

    func testAReviewedRevisionCannotBeEditedInPlaceAndEventsAreAppendOnly() async throws {
        try await withHarness { h in
            let world = try await LoopWorld.build(h)
            let publication = try await world.publish()
            let revisionId = publication.revisionId
            do {
                try await LoopRevisionRecord.query(on: h.db).filter(\.$id == revisionId).set(\.$definitionJSON, to: "{}").update()
                XCTFail("edited the definition of a reviewed revision")
            } catch {}
            do {
                try await LoopRevisionRecord.query(on: h.db).filter(\.$id == revisionId).set(\.$definitionHash, to: "sha256:00").update()
                XCTFail("edited the hash of a reviewed revision")
            } catch {}
            // The state can still move (the pipeline), only content is frozen.
            try await LoopRevisionRecord.query(on: h.db).filter(\.$id == revisionId).set(\.$state, to: "published").update()
            let stored = try await LoopRevisionRecord.find(publication.revisionId, on: h.db)
            XCTAssertEqual(stored?.definitionHash, publication.definitionHash)
            let instance = try await world.instance(world.alice, publication)
            _ = try await world.submitPickup(world.alice, instance.id)
            for table in ["loop_action_events", "loop_action_outcomes", "loop_reviews"] {
                do { try await world.raw("UPDATE \(table) SET business_id = business_id"); XCTFail("updated \(table)") } catch {}
            }
            // Only the field-encrypted inputs may be rewritten (data-key rotation re-seals the same plaintext).
            let event = try await LoopActionEventRecord.query(on: h.db).first()!
            try await LoopActionEventRecord.query(on: h.db).filter(\.$id == event.id!).set(\.$inputsSealed, to: event.inputsSealed).update()
            let rotation = try await DataKeyRotator(db: h.db, ctx: h.ctx).run(rewrite: true)
            XCTAssertEqual(rotation.failed, 0)
            do {
                try await LoopActionEventRecord.query(on: h.db).filter(\.$id == event.id!).set(\.$stepId, to: "s2").update()
                XCTFail("rewrote an event")
            } catch {}
            // An edit is a new revision that starts the pipeline again.
            let next = try await world.submit(LoopFixtures.pickup(title: "Pickup slot"))
            XCTAssertEqual(next.revision, 2)
            XCTAssertEqual(next.stateValue, .inReview)
        }
    }

    func testBusinessRolesHaveNoPublishPath() async throws {
        try await withHarness { h in
            let (owner, account, businessId) = try await h.verifiedOwner()
            _ = account
            let submit = try await h.formPost("/dashboard/loops", owner, [("definition", String(decoding: LoopFixtures.pickup(), as: UTF8.self))])
            XCTAssertEqual(submit.status, .seeOther, submit.text)
            let revision = try await XCTUnwrapAsync(try await LoopRevisionRecord.query(on: h.db).filter(\.$businessId == businessId).first())
            XCTAssertEqual(revision.stateValue, .inReview)
            // The operator review route refuses a business session (separate realm).
            let decide = try await h.formPost("/operator/loops/revisions/\(revision.id!.uuidString.lowercased())/decide", owner, [("decision", "approve"), ("reason", "self")])
            XCTAssertFalse((200..<300).contains(Int(decide.status.code)), decide.text)
            XCTAssertFalse(decide.headers.first(name: .location)?.contains("lm=") ?? false, "redirected to the operator sign-in, nothing decided")
            // The service refuses a business member as reviewer, and no business permission publishes.
            do { _ = try await LoopPublicationService(db: h.db, ctx: h.ctx).review(revisionId: revision.id!, reviewerId: account.userId, decision: .approve, reason: "x"); XCTFail() } catch let error as APIError {
                XCTAssertEqual(error.status, .forbidden)
            }
            XCTAssertFalse(DashboardPermission.allCases.contains { $0.rawValue.lowercased().contains("publish") || $0.rawValue.lowercased().contains("review") })
            try await eq(try await LoopRevisionRecord.find(revision.id!, on: h.db)?.stateValue, .inReview)
            try await eq(try await LoopPublicationRecord.query(on: h.db).count(), 0)
            // A role without submitLoops cannot even submit.
            let analyst = try await h.addMember(owner: owner, role: .analyst, email: "analyst@example.com")
            let denied = try await h.formPost("/dashboard/loops", analyst.session, [("definition", "{}")])
            XCTAssertEqual(denied.status, .forbidden, denied.text)
        }
    }

    func testOperatorReviewThroughTheConsoleNeedsAFreshPasskey() async throws {
        try await withHarness { h in
            let world = try await LoopWorld.build(h)
            var (session, account) = try await h.makeOperator(email: "console-reviewer@viadere.test")
            let auth = DashboardAuthService(db: h.db, ctx: h.ctx)
            account.userId = try await DashboardUserRecord.query(on: h.db).filter(\.$emailHash == auth.emailHash("console-reviewer@viadere.test")).first()!.id!
            try await OperatorPermissions(db: h.db, ctx: h.ctx).set(userId: account.userId, permission: .loopReviewer, granted: true)
            let revision = try await world.submit()
            let page = try await h.page("/operator/loops/revisions/\(revision.id!.uuidString.lowercased())", session)
            XCTAssertEqual(page.status, .ok, page.text)
            XCTAssertTrue(page.text.contains("Built by Corner Bakery"), "the reviewer sees the customer tree")
            let path = "/operator/loops/revisions/\(revision.id!.uuidString.lowercased())/decide"
            // The sign-in assertion counts as fresh for the re-authentication window only.
            h.clock.advance(by: h.ctx.config.dashboard.reauthWindow + 60)
            let stale = try await h.formPost(path, session, [("decision", "approve"), ("reason", "ok")])
            XCTAssertNotEqual(stale.headers.first(name: .location).map { $0.contains("lm=published") }, true, "no decision without a fresh passkey")
            try await eq(try await LoopRevisionRecord.find(revision.id!, on: h.db)?.stateValue, .inReview)
            let reauth = try await h.dashReauth(session, account)
            XCTAssertEqual(reauth.status, .ok, reauth.text)
            let fresh = try await h.formPost(path, session, [("decision", "approve"), ("reason", "Wording checked.")])
            XCTAssertEqual(fresh.status, .seeOther, fresh.text)
            try await eq(try await LoopRevisionRecord.find(revision.id!, on: h.db)?.stateValue, .published)
            let queue = try await h.page("/operator/loops", session)
            XCTAssertEqual(queue.status, .ok, queue.text)
        }
    }

    func testRevokedOrSuspendedPublicationsAndRevokedBusinessesRefuseNewInstancesAndActions() async throws {
        try await withHarness { h in
            let world = try await LoopWorld.build(h)
            let publication = try await world.publish()
            let instance = try await world.instance(world.alice, publication)
            // Suspended: shown paused, nothing actionable, no new instance.
            try await world.publications.setStatus(publicationId: publication.id!, to: .suspended, operatorId: world.reviewer1, reason: "Investigating a report.")
            let paused = try await h.signed(world.alice, .GET, "/v1/loops/instances/\(instance.id)")
            XCTAssertEqual(paused.status, .ok, paused.text)
            XCTAssertEqual(try paused.json(LoopInstanceView.self).paused, true)
            try await eq(try await world.act(world.alice, instance.id, step: "s1", action: "next", inputs: ["slot": .string("am")]).status, .conflict)
            try await eq(try await world.start(world.alice, publication).status, .conflict)
            // Resumed, then revoked: open instances are cancelled.
            try await world.publications.setStatus(publicationId: publication.id!, to: .active, operatorId: world.reviewer1, reason: "Cleared.")
            try await world.publications.setStatus(publicationId: publication.id!, to: .revoked, operatorId: world.reviewer1, reason: "Misleading wording.")
            try await eq(try await LoopInstanceRecord.find(instance.id.uuid, on: h.db)?.stateValue, .cancelled)
            try await eq(try await world.act(world.alice, instance.id, step: "s1", action: "next", inputs: ["slot": .string("am")]).status, .conflict)
            try await eq(try await world.start(world.alice, publication).status, .conflict)
            // A revoked (suspended) business: everything is refused even with a live publication.
            let other = try await world.publish(LoopFixtures.pickup(title: "Order pickup", key: "pickup2"))
            let fresh = try await world.instance(world.alice, other)
            try await BusinessRecord.query(on: h.db).filter(\.$id == world.business.id.uuid).set(\.$verificationStatus, to: VerificationStatus.suspended.rawValue).update()
            try await eq(try await world.act(world.alice, fresh.id, step: "s1", action: "next", inputs: ["slot": .string("am")]).status, .notFound)
            try await eq(try await world.start(world.alice, other).status, .notFound)
            try await isTrue(try await world.refusals("business_not_verified") >= 2)
            try await eq(try await world.events(), 0)
        }
    }

    func testAHealthcareBusinessCannotSubmitAndHardGateFailuresCannotBeOverridden() async throws {
        try await withHarness { h in
            let world = try await LoopWorld.build(h)
            let clinic = try await h.makeBusiness(name: "Downtown Clinic", handle: "downtownclinic")
            try await BusinessRecord.query(on: h.db).filter(\.$id == clinic.id.uuid).set(\.$category, to: "healthcare").update()
            do { _ = try await world.submit(business: clinic.id.uuid); XCTFail("healthcare submitted") } catch let error as APIError {
                XCTAssertEqual(error.status, .forbidden)
            }
            try await eq(try await LoopRevisionRecord.query(on: h.db).filter(\.$businessId == clinic.id.uuid).count(), 0)
            try await isTrue(try await AuditEventRecord.query(on: h.db).filter(\.$action == "loop.submit_refused").count() == 1)
            // Health content fails the hard gate; no human decision can move it.
            let failed = try await world.submit(LoopFixtures.health)
            XCTAssertEqual(failed.stateValue, .validationFailed)
            XCTAssertTrue(failed.ruleHitsJSON.contains("health_content"))
            for reviewer in [world.reviewer1, world.reviewer2] {
                do { _ = try await world.publications.review(revisionId: failed.id!, reviewerId: reviewer, decision: .approve, reason: "Override."); XCTFail() } catch let error as APIError {
                    XCTAssertEqual(error.status, .conflict)
                }
            }
            try await LoopRevisionRecord.query(on: h.db).filter(\.$id == failed.id!).set(\.$state, to: "approved").update()
            do { try await world.publications.publish(revisionId: failed.id!); XCTFail("published a hard-gate failure") } catch let error as APIError {
                XCTAssertEqual(error.status, .forbidden)
            }
            try await eq(try await LoopPublicationRecord.query(on: h.db).count(), 0)
            // A prohibited field type never even parses into a reviewable revision.
            let card = Data(String(decoding: LoopFixtures.pickup(), as: UTF8.self).replacingOccurrences(of: "\"single_choice\"", with: "\"card_number\"").utf8)
            let rejected = try await world.submit(card)
            XCTAssertEqual(rejected.stateValue, .validationFailed)
            XCTAssertTrue(rejected.ruleHitsJSON.contains("prohibited_field_type"))
        }
    }

    func testCustomerReportsAutoSuspendAndKillSwitchesPauseEverything() async throws {
        try await withHarness { h in
            let world = try await LoopWorld.build(h)
            let publication = try await world.publish()
            var reporters: [TestConsumer] = [world.alice]
            for i in 0..<4 {
                let c = try await h.readyConsumer(name: "Reporter \(i)")
                try await h.connect(c, to: world.business)
                try await world.consent(c)
                reporters.append(c)
            }
            for (i, consumer) in reporters.enumerated() {
                let instance = try await world.instance(consumer, publication)
                let report = try await h.signed(consumer, .POST, "/v1/loops/instances/\(instance.id)/report", body: try ViadereJSON.encode(LoopReportRequest(reason: .misleading)))
                XCTAssertEqual(report.status, .ok, report.text)
                // Reporting twice counts once.
                _ = try await h.signed(consumer, .POST, "/v1/loops/instances/\(instance.id)/report", body: try ViadereJSON.encode(LoopReportRequest(reason: .spam)))
                let status = try await LoopPublicationRecord.find(publication.id!, on: h.db)?.statusValue
                XCTAssertEqual(status, i < 2 ? .active : .suspended, "after \(i + 1) reporters out of \(i + 1) customers")
                if status == .suspended { break }
            }
            XCTAssertEqual(h.ctx.metrics.value(.loopAutoSuspended), 1)

            // Per-business switch.
            let other = try await world.publish(LoopFixtures.pickup(title: "Order pickup", key: "pickup2"))
            try await world.publications.setBusinessSwitch(businessId: world.business.id.uuid, on: true, operatorId: world.reviewer1, reason: "Pause during review.")
            try await eq(try await world.start(world.alice, other).status, .conflict)
            try await world.publications.setBusinessSwitch(businessId: world.business.id.uuid, on: false, operatorId: world.reviewer1, reason: "Resume.")
            let instance = try await world.instance(world.alice, other)
            // Platform switch `loops`: no new instances, existing ones paused, nothing actionable.
            try await PlatformFlags(db: h.db, ctx: h.ctx).set(.loops, value: "on", reason: "Test: Loops kill switch.", actor: .system("test"))
            try await eq(try await world.start(world.alice, other).status, .conflict)
            let view = try await h.signed(world.alice, .GET, "/v1/loops/instances/\(instance.id)")
            XCTAssertEqual(try view.json(LoopInstanceView.self).paused, true)
            try await eq(try await world.act(world.alice, instance.id, step: "s1", action: "next", inputs: ["slot": .string("am")]).status, .conflict)
            let available = try await h.signed(world.alice, .GET, "/v1/loops/available")
            XCTAssertEqual(try available.json([LoopSummary].self), [])
        }
    }
}
