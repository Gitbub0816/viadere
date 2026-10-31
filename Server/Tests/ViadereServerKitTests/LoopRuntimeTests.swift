import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// WP-3.3 / WP-3.5 / WP-3.9 security tests (plan 5.4 "Forged Loop actions", "Consent bypass"): every refusal is audited, nothing is recorded.
final class LoopRuntimeTests: XCTestCase {
    func testForgedActionsFromAnotherConsumerDeviceOrBusinessAreRefusedAndAudited() async throws {
        try await withHarness { h in
            let world = try await LoopWorld.build(h)
            let publication = try await world.publish()
            let instance = try await world.instance(world.alice, publication)
            // Another customer (connected and consenting to the same business) cannot act on Alice's instance or even see it.
            let bob = try await h.readyConsumer(name: "Bob")
            try await h.connect(bob, to: world.business)
            try await world.consent(bob)
            try await eq(try await world.act(bob, instance.id, step: "s1", action: "next", inputs: ["slot": .string("am")]).status, .notFound)
            try await eq(try await h.signed(bob, .GET, "/v1/loops/instances/\(instance.id)").status, .notFound)
            // Alice's bearer with a signature from a key that is not her enrolled device key is refused before any handler runs.
            let body = try ViadereJSON.encode(LoopActionRequest(stepId: "s1", actionId: "next", inputs: ["slot": .string("am")], idempotencyKey: "forged"))
            let forged = try await h.signed(world.alice, .POST, "/v1/loops/instances/\(instance.id)/actions", body: body, signWithKey: SoftwareP256SigningKey())
            XCTAssertEqual(forged.status, .unauthorized, forged.text)
            // A signature over a different body (tampered inputs) is refused too.
            let tampered = try await h.signedHeaders(world.alice, .POST, "/v1/loops/instances/\(instance.id)/actions", body: body)
            let other = try ViadereJSON.encode(LoopActionRequest(stepId: "s1", actionId: "next", inputs: ["slot": .string("pm")], idempotencyKey: "forged"))
            try await eq(try await h.request(.POST, "/v1/loops/instances/\(instance.id)/actions", headers: tampered, body: other).status, .unauthorized)
            // A cross-business instance id: an instance of another business's Loop that belongs to someone else.
            let gym = try await LoopWorld.build(h, name: "Iron Gym", handle: "irongym")
            let gymPublication = try await gym.publish()
            let gymInstance = try await gym.instance(gym.alice, gymPublication)
            try await eq(try await world.act(world.alice, gymInstance.id, step: "s1", action: "next", inputs: ["slot": .string("am")]).status, .notFound)
            try await eq(try await world.events(), 0)
            try await isTrue(try await world.refusals("not_found") >= 3)
            try await isTrue(h.ctx.metrics.value(.loopActionRefused) >= 3)
        }
    }

    func testAReplayedIdempotencyKeyReturnsTheSameResultWithOneEvent() async throws {
        try await withHarness { h in
            let world = try await LoopWorld.build(h)
            let instance = try await world.instance(world.alice, try await world.publish())
            let first = try await world.act(world.alice, instance.id, step: "s1", action: "next", inputs: ["slot": .string("am")], key: "k-1")
            XCTAssertEqual(first.status, .created, first.text)
            let replay = try await world.act(world.alice, instance.id, step: "s1", action: "next", inputs: ["slot": .string("am")], key: "k-1")
            XCTAssertEqual(replay.status, .ok, replay.text)
            let a = try first.json(LoopActionResult.self), b = try replay.json(LoopActionResult.self)
            XCTAssertEqual(a.event.id, b.event.id)
            XCTAssertTrue(b.replayed)
            try await eq(try await world.events(), 1)
            // The same key with different content is a conflict, audited, and records nothing.
            let conflict = try await world.act(world.alice, instance.id, step: "s1", action: "next", inputs: ["slot": .string("pm")], key: "k-1")
            XCTAssertEqual(conflict.status, .conflict, conflict.text)
            try await eq(try await world.events(), 1)
            try await isTrue(try await world.refusals("idempotency_conflict") == 1)
            // A malformed key is refused.
            try await eq(try await world.act(world.alice, instance.id, step: "s2", action: "send", key: "has spaces").status, .unprocessableEntity)
        }
    }

    func testActionsOnARetiredStepAfterExpiryOrWithBadInputsAreRefused() async throws {
        try await withHarness { h in
            let world = try await LoopWorld.build(h)
            let publication = try await world.publish()
            let instance = try await world.instance(world.alice, publication)
            // Inputs must match the step: unknown fields, wrong option ids, missing required fields.
            for inputs: [String: JSONValue] in [["slot": .string("night")], ["slot": .string("am"), "extra": .string("x")], [:]] {
                try await eq(try await world.act(world.alice, instance.id, step: "s1", action: "next", inputs: inputs).status, .unprocessableEntity)
            }
            // An action that is not on the current step.
            try await eq(try await world.act(world.alice, instance.id, step: "s2", action: "send").status, .conflict)
            try await eq(try await world.act(world.alice, instance.id, step: "s1", action: "send").status, .unprocessableEntity)
            try await eq(try await world.act(world.alice, instance.id, step: "s1", action: "next", inputs: ["slot": .string("am")]).status, .created)
            // The step the customer left is retired.
            let retired = try await world.act(world.alice, instance.id, step: "s1", action: "next", inputs: ["slot": .string("pm")])
            XCTAssertEqual(retired.status, .conflict, retired.text)
            try await isTrue(try await world.refusals("step_mismatch") >= 2)
            // After expiry nothing is accepted and the instance reads as expired.
            h.clock.advance(by: 86_401)
            let alice = try await h.login(world.alice)
            try await eq(try await world.act(alice, instance.id, step: "s2", action: "send").status, .gone)
            let view = try await h.signed(alice, .GET, "/v1/loops/instances/\(instance.id)")
            XCTAssertEqual(try view.json(LoopInstanceView.self).state, .expired)
            try await eq(try await world.events(), 1)
        }
    }

    func testNoInstanceIsCreatedResumedOrActedOnWithoutBothConsents() async throws {
        try await withHarness { h in
            let world = try await LoopWorld.build(h)
            let publication = try await world.publish()
            // A connected customer with no consent at all; then global only; then both.
            let carol = try await h.readyConsumer(name: "Carol")
            try await h.connect(carol, to: world.business)
            let none = try await world.start(carol, publication)
            XCTAssertEqual(none.status, .forbidden, none.text)
            let text = LoopConsentCatalog.current
            var answers: [String: String] = [:]
            for check in text.checks { answers[check.id] = check.correctOptionId }
            // Business authorization before the global grant is refused.
            let early = try await h.signed(carol, .PUT, "/v1/loops/consent/businesses/\(world.business.id)",
                                           body: try ViadereJSON.encode(LoopBusinessConsentRequest(textVersion: text.version, textDigest: text.digest, agree: true)))
            XCTAssertEqual(early.status, .conflict, early.text)
            // Wrong comprehension answers, a stale digest or no agreement record nothing.
            var wrong = answers
            wrong[text.checks[0].id] = "viadere"
            for request in [LoopGlobalConsentRequest(textVersion: text.version, textDigest: text.digest, answers: wrong, agree: true),
                            LoopGlobalConsentRequest(textVersion: text.version, textDigest: "sha256:00", answers: answers, agree: true),
                            LoopGlobalConsentRequest(textVersion: text.version, textDigest: text.digest, answers: answers, agree: false)] {
                try await eq(try await h.signed(carol, .PUT, "/v1/loops/consent", body: try ViadereJSON.encode(request)).status, .unprocessableEntity)
            }
            try await eq(try await LoopConsentRecord.query(on: h.db).filter(\.$consumerId == carol.id.uuid).count(), 0)
            let global = try await h.signed(carol, .PUT, "/v1/loops/consent", body: try ViadereJSON.encode(LoopGlobalConsentRequest(textVersion: text.version, textDigest: text.digest, answers: answers, agree: true)))
            XCTAssertEqual(try global.json(LoopConsentStatus.self).enabled, true)
            let globalOnly = try await world.start(carol, publication)
            XCTAssertEqual(globalOnly.status, .forbidden, globalOnly.text)
            // A business the customer is not connected to cannot be authorized (no existence oracle).
            try await eq(try await h.signed(carol, .PUT, "/v1/loops/consent/businesses/\(BusinessID())",
                                            body: try ViadereJSON.encode(LoopBusinessConsentRequest(textVersion: text.version, textDigest: text.digest, agree: true))).status, .notFound)
            try await world.consent(carol)
            let instance = try await world.instance(carol, publication)
            // A consent recorded for an older text version authorizes nothing (re-consent on a version bump).
            try await LoopConsentRecord.query(on: h.db).filter(\.$consumerId == carol.id.uuid).set(\.$textVersion, to: 0).update()
            try await eq(try await world.act(carol, instance.id, step: "s1", action: "next", inputs: ["slot": .string("am")]).status, .forbidden)
            try await eq(try await h.signed(carol, .GET, "/v1/loops/instances/\(instance.id)").status, .forbidden)
            try await eq(try await world.start(carol, publication).status, .forbidden)
            try await isTrue(try await world.refusals("consent_outdated") == 3)
            try await isTrue(try await world.refusals("global_consent_missing") == 1)
            try await isTrue(try await world.refusals("business_consent_missing") == 1)
            try await eq(try await world.events(), 0)
        }
    }

    func testRevokingConsentCancelsPendingInstancesAndCoreMessagingWorksWithLoopsOff() async throws {
        try await withHarness { h in
            let world = try await LoopWorld.build(h)
            let publication = try await world.publish()
            let open = try await world.instance(world.alice, publication)
            let submitted = try await world.instance(world.alice, publication)
            _ = try await world.submitPickup(world.alice, submitted.id)
            let revoke = try await h.signed(world.alice, .DELETE, "/v1/loops/consent/businesses/\(world.business.id)")
            XCTAssertEqual(revoke.status, .ok, revoke.text)
            try await eq(try await LoopInstanceRecord.find(open.id.uuid, on: h.db)?.stateValue, .cancelled)
            try await eq(try await LoopInstanceRecord.find(submitted.id.uuid, on: h.db)?.stateValue, .cancelled)
            try await eq(try await world.act(world.alice, open.id, step: "s1", action: "next", inputs: ["slot": .string("am")]).status, .forbidden)
            // History is kept.
            try await eq(try await world.events(), 2)
            // Turning Loops off globally revokes everything.
            try await world.consent(world.alice)
            let off = try await h.signed(world.alice, .DELETE, "/v1/loops/consent")
            XCTAssertEqual(try off.json(LoopConsentStatus.self).enabled, false)
            XCTAssertEqual(try off.json(LoopConsentStatus.self).businesses, [])

            // Core messaging is unaffected with Loops switched off platform-wide and no consent.
            try await PlatformFlags(db: h.db, ctx: h.ctx).set(.loops, value: "on", reason: "Test: Loops kill switch.", actor: .system("test"))
            let relationship = try await h.connect(world.alice, to: world.business)
            let issued = try await h.issue(world.business, relationship: relationship, payload: .confirm(ConfirmPayload(title: "Pickup ready")), purpose: .transactional)
            XCTAssertEqual(issued.status, .created, issued.text)
            let interaction = try issued.json(Interaction.self)
            let fetched = try await h.consumerInteraction(world.alice, id: interaction.id)
            let decided = try await h.decide(world.alice, id: interaction.id, signed: try await h.decision(world.alice, interaction: fetched, decision: .confirm))
            XCTAssertEqual(decided.status, .ok, decided.text)
            let status = try await h.signed(world.alice, .GET, "/v1/loops/consent")
            XCTAssertEqual(try status.json(LoopConsentStatus.self).available, false)
        }
    }

    func testDeliveryCreatesOneInboxItemDuplicatesAreHarmlessAndOutcomesPushOpaquely() async throws {
        try await withHarness { h in
            let world = try await LoopWorld.build(h)
            let instance = try await world.instance(world.alice, try await world.publish())
            let registered = try await h.signedPost(world.alice, "/v1/push/apns-token", APNsTokenRegistration(token: String(repeating: "ab", count: 32), environment: .sandbox, bundleId: "com.viadere.app"))
            XCTAssertTrue([.ok, .created, .noContent].contains(registered.status), registered.text)
            let result = try await world.submitPickup(world.alice, instance.id)
            XCTAssertEqual(result.event.outcome, .pending)
            XCTAssertEqual(result.instance.state, .submitted)
            // The same delivery twice (the broker redelivers; a second outbox row for the same event) yields one item.
            let transport = h.ctx.queue.transport!
            try await OutboxPublisher(db: h.db, ctx: h.ctx, transport: transport).publishDue()
            let message = try await XCTUnwrapAsync(await transport.receive(queue: .loopDelivery, wait: 0))
            let consumer = QueueConsumer(db: h.db, ctx: h.ctx, transport: transport)
            try await eq(await consumer.process(message), .completed)
            try await eq(await consumer.process(message), .duplicate)
            try await Outbox.enqueue(LoopQueue.deliver, ref: result.event.id.uuid, tenant: world.business.id.uuid, on: h.db, ctx: h.ctx)
            try await world.drain(.loopDelivery)
            try await eq(try await InboxItemRecord.query(on: h.db).count(), 1)
            // The staff alert carries no customer content.
            let mails = h.emails.sent.filter { $0.kind == "loop-inbox" }
            XCTAssertTrue(mails.allSatisfy { !$0.text.contains("Morning") && !$0.subject.contains("Morning") })
            // A forged envelope for another tenant is dead-lettered and changes nothing.
            try await Outbox.enqueue(LoopQueue.deliver, ref: result.event.id.uuid, tenant: UUID(), on: h.db, ctx: h.ctx)
            let outcomes = try await world.drain(.loopDelivery)
            XCTAssertEqual(outcomes, [.deadLettered("tenant_mismatch")])
            try await eq(try await LoopRuntimeService(db: h.db, ctx: h.ctx).currentOutcome(eventId: result.event.id.uuid)?.outcomeValue, .pending)
            // Staff accepts: outcome accepted, instance completed, one opaque push with no business name or content.
            let item = try await InboxItemRecord.query(on: h.db).first()!
            try await LoopInbox(db: h.db, ctx: h.ctx).decide(itemId: item.id!, businessId: world.business.id.uuid, staffId: UUID(), decision: "accept", note: nil)
            let before = h.push.sent.count
            try await world.drain(.push)
            let pushes = Array(h.push.sent.dropFirst(before))
            XCTAssertEqual(pushes.count, 1)
            XCTAssertEqual(pushes.first?.body, LoopRuntimeService.pushBody)
            XCTAssertNil(pushes.first?.interactionId)
            // The instance id rides as the opaque top-level `loopInstanceId` (SECURITY.md §2.98) so the app opens this instance.
            XCTAssertEqual(pushes.first?.loopInstanceId, instance.id.uuid.uuidString.lowercased())
            XCTAssertEqual(pushes.first?.category, "viadere.loop")
            XCTAssertFalse(pushes.contains { $0.title.contains("Corner") || $0.body.contains("Corner") || $0.threadID.contains("Corner") })
            let view = try await h.signed(world.alice, .GET, "/v1/loops/instances/\(instance.id)")
            let loaded = try view.json(LoopInstanceView.self)
            XCTAssertEqual(loaded.state, .completed)
            XCTAssertEqual(loaded.events.last?.outcome, .accepted)
            // A final outcome cannot change.
            do { try await LoopInbox(db: h.db, ctx: h.ctx).decide(itemId: item.id!, businessId: world.business.id.uuid, staffId: UUID(), decision: "reject", note: nil); XCTFail() } catch {}
        }
    }

    func testADeadLetteredDeliveryMarksTheEventUnknownAndDeadlinesTimeOut() async throws {
        try await withHarness { h in
            let world = try await LoopWorld.build(h)
            let publication = try await world.publish()
            let result = try await world.submitPickup(world.alice, try await world.instance(world.alice, publication).id)
            struct Boom: Error {}
            let failing = QueueMessageType(name: LoopQueue.deliver.name, version: 1, queue: .loopDelivery, timeToLive: 60, requiresTenant: true,
                                           claim: { _, _, _ in throw Boom() }, onDeadLetter: LoopQueue.deliver.onDeadLetter)
            let transport = h.ctx.queue.transport!
            var consumer = QueueConsumer(db: h.db, ctx: h.ctx, transport: transport)
            consumer.registry = QueueRegistry([failing])
            try await OutboxPublisher(db: h.db, ctx: h.ctx, transport: transport).publishDue()
            var outcomes: [QueueConsumer.Outcome] = []
            for _ in 0..<QueueName.loopDelivery.maxDeliveries { outcomes += try await consumer.drain(.loopDelivery, limit: 1) }
            XCTAssertEqual(outcomes.last, .deadLettered("max_deliveries"))
            let runtime = LoopRuntimeService(db: h.db, ctx: h.ctx)
            try await eq(try await runtime.currentOutcome(eventId: result.event.id.uuid)?.outcomeValue, .unknown)
            XCTAssertEqual(h.ctx.metrics.value(.loopOutcomeUnknown), 1)
            try await eq(try await InboxItemRecord.query(on: h.db).count(), 0)
            // A late business answer is still honest (unknown -> accepted is allowed).
            try await isTrue(try await runtime.recordOutcome(eventId: result.event.id.uuid, businessId: world.business.id.uuid, outcome: .accepted, source: .staff, actor: UUID(), reason: nil))

            // Deadlines: an unanswered delivery times out through the scheduled message (and the sweep is a no-op afterwards).
            let second = try await world.submitPickup(world.alice, try await world.instance(world.alice, publication).id)
            h.clock.advance(by: 86_401)
            try await world.drain(.loopTimeout)
            try await eq(try await runtime.currentOutcome(eventId: second.event.id.uuid)?.outcomeValue, .timedOut)
            try await h.runJobs()
            try await eq(try await LoopActionOutcomeRecord.query(on: h.db).filter(\.$eventId == second.event.id.uuid).count(), 2)
        }
    }

    func testLoopTasksAppearInAlertsWithUrgencyAndExpiry() async throws {
        try await withHarness { h in
            let world = try await LoopWorld.build(h)
            let publication = try await world.publish()
            let instance = try await world.instance(world.alice, publication)
            var alice = world.alice
            func alert() async throws -> AlertEntry? {
                let page = try await h.signed(alice, .GET, "/v1/alerts")
                XCTAssertEqual(page.status, .ok, page.text)
                return try page.json(AlertPage.self).items.first { $0.source == .loopTask }
            }
            let waiting = try await XCTUnwrapAsync(try await alert())
            XCTAssertEqual(waiting.target, AlertTarget(kind: .loopInstance, id: instance.id.uuid.uuidString.lowercased()))
            XCTAssertTrue(waiting.actionRequired && waiting.actionable)
            XCTAssertEqual(waiting.expiresAt, instance.expiresAt)
            XCTAssertEqual(waiting.title, "Schedule your pickup")
            h.clock.advance(by: 80_000)
            alice = try await h.login(world.alice)
            try await eq(try await alert()?.urgency, .timeSensitive)
            _ = try await world.submitPickup(alice, instance.id)
            let submitted = try await XCTUnwrapAsync(try await alert())
            XCTAssertEqual(submitted.status, .pending)
            XCTAssertFalse(submitted.actionRequired, "waiting for the business, not the customer")
            // Another customer never sees it.
            let bob = try await h.readyConsumer(name: "Bob")
            try await h.connect(bob, to: world.business)
            let bobs = try await h.signed(bob, .GET, "/v1/alerts")
            XCTAssertFalse(try bobs.json(AlertPage.self).items.contains { $0.source == .loopTask })
        }
    }
}
