import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Loops Phase 4 (WP-4.1 connected mode, WP-4.4 binding `approve_estimate`, WP-4.7 advanced Studio; SECURITY.md §2.115). Written as the
/// exploit paths: forged, replayed and cross-tenant callbacks; an endpoint pause or a lost delivery shown as confirmed; an approval that is
/// missing, replayed, weaker than biometric, over another amount or for another instance; schema editing that slips a prohibited action,
/// field, kit or routing past the form; Phase 4 behaviour leaking while the switch is off.
final class LoopPhase4Tests: XCTestCase {
    static func on(_ config: inout ServerConfig) { config.loops.connectedEnabled = true }

    static func connectedPickup(key: String = "pickup") -> Data {
        Data(String(decoding: LoopFixtures.pickup(key: key), as: UTF8.self)
            .replacingOccurrences(of: #""routing":{"mode":"hosted","queue":"pickups"}"#, with: #""routing":{"mode":"connected","queue":"pickups"}"#).utf8)
    }

    static func estimateApproval(routing: String = "hosted") -> Data {
        Data("""
        {"schema_version":1,"key":"estimate-approval","title":"Approve your repair estimate","entry_points":["business_page","message"],"appearance":{"mode":"standard"},
         "steps":[{"id":"s1","type":"summary","body":"Brake pads and rotors","actions":[{"id":"approve","action":"approve_estimate","label":"approve_estimate",
           "routing":{"mode":"\(routing)"},"params":{"amount":{"value":"285.28","currency":"USD"},"terms":"Parts and labor, valid for 7 days","reference":"EST-1042"},"next":"done"}]},
          {"id":"done","type":"result","show_outcome":true}],"limits":{"expires_in_seconds":86400}}
        """.utf8)
    }

    /// A verified v2 endpoint of the world's business subscribed to the Loop events, bound to the Loop of `publication`.
    @discardableResult
    static func bind(_ world: LoopWorld, _ publication: LoopPublicationRecord, events: [WebhookEventType] = WebhookEventType.loopEvents) async throws -> UUID {
        let h = world.h
        let created = try await h.businessPost(world.business, "/v1/business/webhooks",
                                               CreateWebhookRequest(url: URL(string: "https://hooks.example.com/loops")!, events: events, envelopeVersion: WebhookEnvelopeV2.version))
        XCTAssertEqual(created.status, .created, created.text)
        let id = try created.json(WebhookSecretResponse.self).subscription.id.uuid
        try await WebhookSubscriptionRecord.query(on: h.db).filter(\.$id == id).set(\.$verifiedAt, to: h.clock.now()).update()
        try await LoopConnectedService(db: h.db, ctx: h.ctx).bind(businessId: world.business.id.uuid, definitionId: publication.definitionId, subscriptionId: id, by: world.author)
        return id
    }

    static func ref(_ result: LoopActionResult) -> String { LoopBusinessRef.event(result.event.id) }

    static func outcome(_ world: LoopWorld, _ ref: String, _ outcome: String, key: String, apiKey: String? = nil) async throws -> HTTPResult {
        try await world.h.business(world.business, .POST, "/v1/business/loops/events/\(ref)/outcome",
                                   body: Data(#"{"outcome":"\#(outcome)","idempotency_key":"\#(key)"}"#.utf8), key: apiKey)
    }

    static func current(_ world: LoopWorld, _ result: LoopActionResult) async throws -> LoopActionOutcome? {
        try await LoopRuntimeService(db: world.h.db, ctx: world.h.ctx).currentOutcome(eventId: result.event.id.uuid)?.outcomeValue
    }

    // MARK: WP-4.1 connected mode

    func testAConnectedActionReachesOnlyTheBoundEndpointAsAnOpaqueEventAndTheAnswerReachesTheCustomer() async throws {
        try await withHarness(Self.on) { h in
            let world = try await LoopWorld.build(h)
            let publication = try await world.publish(Self.connectedPickup())
            try await Self.bind(world, publication)
            // A second endpoint of the same business that is not bound gets nothing.
            _ = try await h.businessPost(world.business, "/v1/business/webhooks", CreateWebhookRequest(url: URL(string: "https://other.example.com/hook")!,
                                         events: [.loopActionSubmitted], envelopeVersion: WebhookEnvelopeV2.version))
            let instance = try await world.instance(world.alice, publication)
            let submitted = try await world.submitPickup(world.alice, instance.id)
            XCTAssertEqual(submitted.event.outcome, .pending)
            try await world.drain(.loopDelivery)
            try await world.drain(.webhookDelivery)
            // No hosted inbox item: connected events never land in the Viadere inbox.
            try await eq(try await InboxItemRecord.query(on: h.db).count(), 0)
            let sent = h.webhooks.received.filter { $0.headers[ViadereHeader.eventType] == WebhookEventType.loopActionSubmitted.rawValue }
            XCTAssertEqual(sent.count, 1)
            XCTAssertEqual(sent.first?.url.host, "hooks.example.com")
            let body = try XCTUnwrap(sent.first?.body)
            let envelope = try ViadereJSON.decode(WebhookEnvelopeV2.self, from: body)
            XCTAssertEqual(envelope.resultRef, Self.ref(submitted))
            // Ids only: no answers, no customer, no business name, no Loop title.
            let text = String(decoding: body, as: UTF8.self)
            for leak in ["am", "Morning", "slot", world.alice.id.description, "Corner Bakery", "pickup", instance.id.description] {
                XCTAssertFalse(text.contains("\"\(leak)\"") || text.contains(leak) && leak.count > 4, "leaked \(leak): \(text)")
            }
            // The business fetches with loops:read and sees the answers with the reviewed labels, no identity.
            let fetched = try await h.business(world.business, .GET, "/v1/business/loops/events/\(Self.ref(submitted))")
            XCTAssertEqual(fetched.status, .ok, fetched.text)
            XCTAssertEqual(fetched.headers.first(name: .cacheControl), "no-store")
            let view = try fetched.json(LoopBusinessEvent.self)
            XCTAssertEqual(view.answers.map(\.value), [.string("am")])
            XCTAssertEqual(view.queue, "pickups")
            XCTAssertNil(view.approval)
            XCTAssertFalse(fetched.text.contains(world.alice.id.description))
            XCTAssertFalse(fetched.text.contains("subject_ref"))
            // The answer: accepted reaches the customer and closes the instance.
            let answered = try await Self.outcome(world, Self.ref(submitted), "accepted", key: "ans-1")
            XCTAssertEqual(answered.status, .created, answered.text)
            let resumed = try await h.signed(world.alice, .GET, "/v1/loops/instances/\(instance.id)").json(LoopInstanceView.self)
            XCTAssertEqual(resumed.events.last?.outcome, .accepted)
            XCTAssertEqual(resumed.state, .completed)
        }
    }

    func testForgedReplayedAndCrossTenantCallbacksAreRefused() async throws {
        try await withHarness(Self.on) { h in
            let world = try await LoopWorld.build(h)
            let publication = try await world.publish(Self.connectedPickup())
            try await Self.bind(world, publication)
            let submitted = try await world.submitPickup(world.alice, try await world.instance(world.alice, publication).id)
            let ref = Self.ref(submitted)
            // Wrong key: no key, a key of another business, a key without the scope, a test key.
            try await eq(try await h.request(.POST, "/v1/business/loops/events/\(ref)/outcome", body: Data(#"{"outcome":"accepted","idempotency_key":"k"}"#.utf8)).status, .unauthorized)
            let other = try await h.makeBusiness(name: "Iron Gym", handle: "irongym")
            try await eq(try await h.business(other, .GET, "/v1/business/loops/events/\(ref)").status, .notFound)
            try await eq(try await h.business(other, .POST, "/v1/business/loops/events/\(ref)/outcome", body: Data(#"{"outcome":"accepted","idempotency_key":"x"}"#.utf8)).status, .notFound)
            let readOnly = try await BusinessAPIKeys.issue(businessId: world.business.id.uuid, name: "read", live: true, scopes: [BusinessAPIKeys.Scope.loopsRead], now: h.clock.now(), on: h.db)
            try await eq(try await Self.outcome(world, ref, "accepted", key: "k0", apiKey: readOnly.key).status, .forbidden)
            let noScope = try await BusinessAPIKeys.issue(businessId: world.business.id.uuid, name: "none", live: true, scopes: [BusinessAPIKeys.Scope.messagesWrite], now: h.clock.now(), on: h.db)
            try await eq(try await h.business(world.business, .GET, "/v1/business/loops/events/\(ref)", key: noScope.key).status, .forbidden)
            let test = try await BusinessAPIKeys.issue(businessId: world.business.id.uuid, name: "test", live: false, scopes: BusinessAPIKeys.Scope.all, now: h.clock.now(), on: h.db)
            try await eq(try await h.business(world.business, .GET, "/v1/business/loops/events/\(ref)", key: test.key).status, .notFound)
            // References of the wrong kind or malformed.
            for bad in [LoopBusinessRef.instance(submitted.instance.id), submitted.event.id.description, ref.uppercased(), "lev_nope"] {
                try await eq(try await h.business(world.business, .GET, "/v1/business/loops/events/\(bad)").status, .notFound)
            }
            // Malformed bodies record nothing.
            for body in [#"{"outcome":"accepted"}"#, #"{"outcome":"timed_out","idempotency_key":"k"}"#, #"{"outcome":"accepted","idempotency_key":"k","extra":1}"#] {
                try await eq(try await h.business(world.business, .POST, "/v1/business/loops/events/\(ref)/outcome", body: Data(body.utf8)).status, .unprocessableEntity)
            }
            try await eq(try await Self.current(world, submitted), .pending)
            // Idempotent: the same key and answer replays (one outcome row); the same key with another answer is a conflict.
            try await eq(try await Self.outcome(world, ref, "rejected", key: "ans-1").status, .created)
            let replay = try await Self.outcome(world, ref, "rejected", key: "ans-1")
            XCTAssertEqual(replay.status, .ok, replay.text)
            XCTAssertTrue(try replay.json(LoopOutcomeCallbackResult.self).replayed)
            try await eq(try await Self.outcome(world, ref, "accepted", key: "ans-1").status, .conflict)
            // A final answer can't be changed with a new key either.
            try await eq(try await Self.outcome(world, ref, "accepted", key: "ans-2").status, .conflict)
            try await eq(try await LoopActionOutcomeRecord.query(on: h.db).filter(\.$eventId == submitted.event.id.uuid).count(), 2)
            try await eq(try await Self.current(world, submitted), .rejected)
            try await isTrue(try await AuditEventRecord.query(on: h.db).filter(\.$action == "loop.connected_refused").count() >= 8)
        }
    }

    func testHostedEventsCannotBeFetchedOrAnsweredThroughTheAPI() async throws {
        try await withHarness(Self.on) { h in
            let world = try await LoopWorld.build(h)
            let submitted = try await world.submitPickup(world.alice, try await world.instance(world.alice, try await world.publish()).id)
            let ref = Self.ref(submitted)
            try await eq(try await h.business(world.business, .GET, "/v1/business/loops/events/\(ref)").status, .notFound)
            try await eq(try await Self.outcome(world, ref, "accepted", key: "k").status, .notFound)
            try await eq(try await Self.current(world, submitted), .pending)
        }
    }

    func testAPausedUnboundOrDeadEndpointShowsUnknownNeverAccepted() async throws {
        try await withHarness(Self.on) { h in
            let world = try await LoopWorld.build(h)
            // 1. No endpoint bound: unknown at delivery.
            let unbound = try await world.publish(Self.connectedPickup())
            let lost = try await world.submitPickup(world.alice, try await world.instance(world.alice, unbound).id)
            try await world.drain(.loopDelivery)
            try await eq(try await Self.current(world, lost), .unknown)
            // 2. Bound but paused at delivery: unknown, and the delivery waits for the resume.
            let endpoint = try await Self.bind(world, unbound)
            try await WebhookService(db: h.db, ctx: h.ctx).setPaused(businessId: world.business.id, id: WebhookSubscriptionID(endpoint), paused: true, reason: "maintenance",
                                                                              actor: AuditActor(kind: .business, id: "test"))
            let paused = try await world.submitPickup(world.alice, try await world.instance(world.alice, unbound).id)
            try await world.drain(.loopDelivery)
            try await eq(try await Self.current(world, paused), .unknown)
            try await world.drain(.webhookDelivery)
            XCTAssertTrue(h.webhooks.received.filter { $0.headers[ViadereHeader.eventType] == WebhookEventType.loopActionSubmitted.rawValue }.isEmpty)
            // A late confirmation from the business is honest and taken: unknown → pending → accepted.
            try await eq(try await Self.outcome(world, Self.ref(paused), "pending", key: "late-1").status, .created)
            try await eq(try await Self.outcome(world, Self.ref(paused), "accepted", key: "late-2").status, .created)
            try await eq(try await Self.current(world, paused), .accepted)
            // 3. Pausing an endpoint with a queued event marks it unknown at once.
            try await WebhookService(db: h.db, ctx: h.ctx).setPaused(businessId: world.business.id, id: WebhookSubscriptionID(endpoint), paused: false, reason: "",
                                                                              actor: AuditActor(kind: .business, id: "test"))
            let queued = try await world.submitPickup(world.alice, try await world.instance(world.alice, unbound).id)
            try await world.drain(.loopDelivery)
            try await eq(try await Self.current(world, queued), .pending)
            try await WebhookService(db: h.db, ctx: h.ctx).setPaused(businessId: world.business.id, id: WebhookSubscriptionID(endpoint), paused: true, reason: "incident",
                                                                              actor: AuditActor(kind: .business, id: "test"))
            try await eq(try await Self.current(world, queued), .unknown)
            // 4. A delivery that dead-letters (the endpoint keeps failing) marks the event unknown.
            try await WebhookService(db: h.db, ctx: h.ctx).setPaused(businessId: world.business.id, id: WebhookSubscriptionID(endpoint), paused: false, reason: "",
                                                                              actor: AuditActor(kind: .business, id: "test"))
            h.webhooks.respond(with: [], then: 500)
            let dead = try await world.submitPickup(world.alice, try await world.instance(world.alice, unbound).id)
            try await world.drain(.loopDelivery)
            for _ in 0..<(WebhookService.maxAttempts + 1) {
                for delivery in try await WebhookDeliveryRecord.query(on: h.db).filter(\.$status ~~ ["pending", "sending"]).all() {
                    delivery.nextAttemptAt = h.clock.now()
                    try await delivery.update(on: h.db)
                }
                try await WebhookService(db: h.db, ctx: h.ctx).deliverDue()
            }
            try await eq(try await Self.current(world, dead), .unknown)
            // Nothing ever became accepted without the business saying so.
            try await eq(try await LoopActionOutcomeRecord.query(on: h.db).filter(\.$outcome == "accepted").filter(\.$source != "webhook").count(), 0)
        }
    }

    func testAnEndpointMustBeTheTenantsOwnOpaqueSubscribedAndProven() async throws {
        try await withHarness({ Self.on(&$0); $0.operations.webhookOwnershipVerification = true }) { h in
            let world = try await LoopWorld.build(h)
            let publication = try await world.publish(Self.connectedPickup())
            let service = LoopConnectedService(db: h.db, ctx: h.ctx)
            func create(_ b: TestBusiness, events: [WebhookEventType], version: String?) async throws -> UUID {
                let r = try await h.businessPost(b, "/v1/business/webhooks", CreateWebhookRequest(url: URL(string: "https://hooks.example.com/\(UUID())")!, events: events, envelopeVersion: version))
                XCTAssertEqual(r.status, .created, r.text)
                return try r.json(WebhookSecretResponse.self).subscription.id.uuid
            }
            // loop.* events can never be asked for on a v1 subscription.
            let v1 = try await h.businessPost(world.business, "/v1/business/webhooks", CreateWebhookRequest(url: URL(string: "https://hooks.example.com/v1")!, events: [.loopActionSubmitted]))
            XCTAssertEqual(v1.status, .unprocessableEntity, v1.text)
            let unproven = try await create(world.business, events: [.loopActionSubmitted], version: WebhookEnvelopeV2.version)
            let notSubscribed = try await create(world.business, events: [.interactionDecided], version: WebhookEnvelopeV2.version)
            try await WebhookSubscriptionRecord.query(on: h.db).filter(\.$id == notSubscribed).set(\.$verifiedAt, to: h.clock.now()).update()
            let gym = try await h.makeBusiness(name: "Iron Gym", handle: "irongym")
            let foreign = try await create(gym, events: [.loopActionSubmitted], version: WebhookEnvelopeV2.version)
            try await WebhookSubscriptionRecord.query(on: h.db).filter(\.$id == foreign).set(\.$verifiedAt, to: h.clock.now()).update()
            for (id, status) in [(unproven, HTTPStatus.unprocessableEntity), (notSubscribed, .unprocessableEntity), (foreign, .notFound)] {
                do {
                    try await service.bind(businessId: world.business.id.uuid, definitionId: publication.definitionId, subscriptionId: id, by: world.author)
                    XCTFail("bound \(id)")
                } catch let error as APIError { XCTAssertEqual(error.status, status) }
            }
            // Another business cannot bind this business's Loop to its own endpoint.
            do {
                try await service.bind(businessId: gym.id.uuid, definitionId: publication.definitionId, subscriptionId: foreign, by: world.author)
                XCTFail("cross-tenant bind")
            } catch let error as APIError { XCTAssertEqual(error.status, .notFound) }
            try await eq(try await LoopEndpointBindingRecord.query(on: h.db).count(), 0)
            try await isTrue(try await AuditEventRecord.query(on: h.db).filter(\.$action == "loop.endpoint_bind_refused").count() >= 2)
        }
    }

    func testTheConsoleBindingNeedsBothPermissionsAndAFreshPasskey() async throws {
        try await withHarness(Self.on) { h in
            let (owner, account, businessId) = try await h.verifiedOwner()
            let world = try await LoopWorld.build(h, business: try await h.testBusiness(businessId), tag: "console")
            let publication = try await world.publish(Self.connectedPickup())
            let created = try await h.businessPost(world.business, "/v1/business/webhooks",
                                                   CreateWebhookRequest(url: URL(string: "https://hooks.example.com/loops")!, events: [.loopActionSubmitted], envelopeVersion: WebhookEnvelopeV2.version))
            let endpoint = try created.json(WebhookSecretResponse.self).subscription.id.uuid
            try await WebhookSubscriptionRecord.query(on: h.db).filter(\.$id == endpoint).set(\.$verifiedAt, to: h.clock.now()).update()
            let target = "/dashboard/loops/\(publication.definitionId.uuidString.lowercased())/endpoint"
            // A Messaging Operator has neither submitLoops nor manageWebhooks.
            let operatorMember = try await h.addMember(owner: owner, role: .messagingOperator, email: "ops@example.com")
            try await eq(try await h.formPost(target, operatorMember.session, [("webhook", endpoint.uuidString.lowercased())]).status, .forbidden)
            // The owner without a fresh passkey is asked to confirm first; nothing is bound.
            try await DashboardSessionRecord.query(on: h.db).set(\.$reauthAt, to: h.clock.now().addingTimeInterval(-86_400)).update()
            let stale = try await h.formPost(target, owner, [("webhook", endpoint.uuidString.lowercased())])
            XCTAssertEqual(stale.status, .forbidden, stale.text)
            try await eq(try await LoopEndpointBindingRecord.query(on: h.db).count(), 0)
            aeq(try await h.dashReauth(owner, account).status, .ok)
            let bound = try await h.formPost(target, owner, [("webhook", endpoint.uuidString.lowercased())])
            XCTAssertEqual(bound.status, .seeOther, bound.text)
            try await eq(try await LoopEndpointBindingRecord.query(on: h.db).first()?.subscriptionId, endpoint)
            let page = try await h.page("/dashboard/loops", owner)
            XCTAssertTrue(page.text.contains("Connected endpoints"), page.text)
        }
    }

    func testAnExpiredConnectedInstanceTellsTheEndpointOnce() async throws {
        try await withHarness(Self.on) { h in
            let world = try await LoopWorld.build(h)
            let publication = try await world.publish(Self.connectedPickup())
            try await Self.bind(world, publication)
            let instance = try await world.instance(world.alice, publication)
            _ = try await world.act(world.alice, instance.id, step: "s1", action: "next", inputs: ["slot": .string("am")])
            // An instance without connected events is never announced.
            h.clock.advance(by: 86_401)
            try await world.drain(.loopTimeout)
            try await world.drain(.webhookDelivery)
            XCTAssertTrue(h.webhooks.received.filter { $0.headers[ViadereHeader.eventType] == WebhookEventType.loopInstanceExpired.rawValue }.isEmpty)
            // One with a connected event is, exactly once.
            let alice = try await h.login(world.alice)
            let second = try await world.instance(alice, publication)
            let submitted = try await world.submitPickup(alice, second.id)
            XCTAssertEqual(submitted.instance.state, .submitted)
            try await LoopInstanceRecord.query(on: h.db).filter(\.$id == second.id.uuid).set(\.$state, to: LoopInstanceState.active.rawValue).update()
            h.clock.advance(by: 86_401)
            try await world.drain(.loopTimeout)
            let record = try await LoopInstanceRecord.find(second.id.uuid, on: h.db)!
            try await LoopRuntimeService(db: h.db, ctx: h.ctx).expireIfDue(record)
            try await world.drain(.webhookDelivery)
            let expired = h.webhooks.received.filter { $0.headers[ViadereHeader.eventType] == WebhookEventType.loopInstanceExpired.rawValue }
            XCTAssertEqual(expired.count, 1)
            let envelope = try ViadereJSON.decode(WebhookEnvelopeV2.self, from: expired[0].body)
            XCTAssertEqual(envelope.requestId, LoopBusinessRef.instance(second.id))
            let fetched = try await h.business(world.business, .GET, "/v1/business/loops/instances/\(envelope.requestId)")
            XCTAssertEqual(fetched.status, .ok, fetched.text)
            XCTAssertEqual(try fetched.json(LoopBusinessInstance.self).state, .expired)
            // The first (never connected) instance is not readable through the business API.
            try await eq(try await h.business(world.business, .GET, "/v1/business/loops/instances/\(LoopBusinessRef.instance(instance.id))").status, .notFound)
        }
    }

    func testWithPhase4OffConnectedRoutingApprovalsAndTheBusinessRoutesDoNotExist() async throws {
        try await withHarness { h in
            let world = try await LoopWorld.build(h)
            for data in [Self.connectedPickup(), Self.estimateApproval()] {
                let revision = try await world.submit(data)
                XCTAssertEqual(revision.stateValue, .validationFailed, revision.ruleHitsJSON)
            }
            let ref = LoopBusinessRef.event(LoopActionEventID())
            try await eq(try await h.business(world.business, .GET, "/v1/business/loops/events/\(ref)").status, .notFound)
            try await eq(try await Self.outcome(world, ref, "accepted", key: "k").status, .notFound)
        }
    }

    // MARK: WP-4.4 binding approve_estimate

    func challenge(_ world: LoopWorld, _ consumer: TestConsumer, _ instance: LoopInstanceID, step: String = "s1", action: String = "approve") async throws -> HTTPResult {
        try await world.h.signedPost(consumer, "/v1/loops/instances/\(instance)/approvals", LoopApprovalStartRequest(stepId: step, actionId: action))
    }

    func approve(_ world: LoopWorld, _ consumer: TestConsumer, _ instance: LoopInstanceID, approval: LoopActionApproval?, key: String = UUID().uuidString) async throws -> HTTPResult {
        try await world.h.signed(consumer, .POST, "/v1/loops/instances/\(instance)/actions",
                                 body: try ViadereJSON.encode(LoopActionRequest(stepId: "s1", actionId: "approve", idempotencyKey: key, approval: approval)))
    }

    func testAnEstimateApprovalNeedsAFreshSingleUseBiometricDecisionOverTheReviewedAmount() async throws {
        try await withHarness({ Self.on(&$0); $0.loops.approvalRate = .perMinute(60, burst: 30) }) { h in
            let world = try await LoopWorld.build(h)
            let publication = try await world.publish(Self.estimateApproval())
            let instance = try await world.instance(world.alice, publication)
            // No approval: refused, audited, nothing recorded.
            try await eq(try await approve(world, world.alice, instance.id, approval: nil).status, .forbidden)
            try await eq(try await world.events(), 0)
            try await isTrue(try await world.refusals("approval_required") == 1)
            let issued = try await challenge(world, world.alice, instance.id)
            XCTAssertEqual(issued.status, .created, issued.text)
            let challenge = try issued.json(LoopApprovalChallenge.self)
            guard case .authorize(let payload) = challenge.interaction.payload else { return XCTFail("not authorize") }
            XCTAssertEqual(payload.amount?.decimalString, "285.28")
            XCTAssertEqual(payload.merchant, "Corner Bakery")
            XCTAssertEqual(payload.effectOfApproval, "This approves the estimate. It does not charge you.")
            XCTAssertEqual(challenge.interaction.sensitivity, .high)
            // A passcode-level signature is below what a high-risk approval needs.
            let weak = try await h.decision(world.alice, interaction: challenge.interaction, assurance: .devicePasscode)
            try await eq(try await approve(world, world.alice, instance.id, approval: LoopActionApproval(approvalId: challenge.approvalId, signedDecision: weak)).status, .forbidden)
            // A fresh challenge for the rest (the weak attempt spent the first one's nonce).
            let second = try await self.challenge(world, world.alice, instance.id).json(LoopApprovalChallenge.self)
            // Signed over a smaller amount than the server's: refused.
            var tampered = second.interaction
            if case .authorize(var p) = tampered.payload { p.amount = try MoneyAmount(string: "28.52", currency: .usd); tampered.payload = .authorize(p) }
            let cheaper = try await h.decision(world.alice, interaction: tampered)
            try await eq(try await approve(world, world.alice, instance.id, approval: LoopActionApproval(approvalId: second.approvalId, signedDecision: cheaper)).status, .forbidden)
            // Another key than the device's biometric key.
            let third = try await self.challenge(world, world.alice, instance.id).json(LoopApprovalChallenge.self)
            let forged = try await h.decision(world.alice, interaction: third.interaction, signWith: SoftwareP256SigningKey())
            try await eq(try await approve(world, world.alice, instance.id, approval: LoopActionApproval(approvalId: third.approvalId, signedDecision: forged)).status, .forbidden)
            // A deny decision is not an approval.
            let fourth = try await self.challenge(world, world.alice, instance.id).json(LoopApprovalChallenge.self)
            let deny = try await h.decision(world.alice, interaction: fourth.interaction, decision: .deny)
            try await eq(try await approve(world, world.alice, instance.id, approval: LoopActionApproval(approvalId: fourth.approvalId, signedDecision: deny)).status, .forbidden)
            try await eq(try await world.events(), 0)
            // The genuine approval records the event once and is consumed.
            let good = try await self.challenge(world, world.alice, instance.id).json(LoopApprovalChallenge.self)
            let signed = try await h.decision(world.alice, interaction: good.interaction)
            let accepted = try await approve(world, world.alice, instance.id, approval: LoopActionApproval(approvalId: good.approvalId, signedDecision: signed), key: "approve-1")
            XCTAssertEqual(accepted.status, .created, accepted.text)
            let row = try await LoopApprovalRecord.find(UUID(uuidString: good.approvalId)!, on: h.db)!
            XCTAssertNotNil(row.consumedAt)
            XCTAssertEqual(row.contextDigest, good.interaction.displayContextDigest())
            XCTAssertEqual(row.assurance, "biometric")
            // The same idempotency key replays without a new approval; reusing the approval with a new key is refused.
            try await eq(try await approve(world, world.alice, instance.id, approval: nil, key: "approve-1").status, .ok)
            try await eq(try await world.events(), 1)
            // An approval belongs to its instance: Alice's challenge on another instance can't approve this one.
            let other = try await world.instance(world.alice, publication)
            let foreign = try await self.challenge(world, world.alice, other.id).json(LoopApprovalChallenge.self)
            let foreignSigned = try await h.decision(world.alice, interaction: foreign.interaction)
            let crossed = try await h.signed(world.alice, .POST, "/v1/loops/instances/\(instance.id)/actions",
                body: try ViadereJSON.encode(LoopActionRequest(stepId: "s1", actionId: "approve", idempotencyKey: "x", approval: LoopActionApproval(approvalId: foreign.approvalId, signedDecision: foreignSigned))))
            XCTAssertNotEqual(crossed.status, .created)
            // The approval never creates an interaction, never charges and never reaches a checkout.
            try await eq(try await InteractionRecord.query(on: h.db).count(), 0)
            try await isTrue(try await world.refusals("approval_invalid") >= 3)
            try await isTrue(try await world.refusals("approval_insufficient_assurance") == 1)
        }
    }

    func testApprovalChallengesOnlyForTheCallersCurrentApproveEstimateStep() async throws {
        try await withHarness(Self.on) { h in
            let world = try await LoopWorld.build(h)
            let pickup = try await world.publish()
            let pickupInstance = try await world.instance(world.alice, pickup)
            // Not an approve_estimate action.
            try await eq(try await challenge(world, world.alice, pickupInstance.id, step: "s1", action: "next").status, .unprocessableEntity)
            let estimate = try await world.publish(Self.estimateApproval())
            let instance = try await world.instance(world.alice, estimate)
            // Another customer, a step that isn't current.
            let bob = try await h.readyConsumer(name: "Bob")
            try await h.connect(bob, to: world.business)
            try await world.consent(bob)
            try await eq(try await challenge(world, bob, instance.id).status, .notFound)
            try await eq(try await challenge(world, world.alice, instance.id, step: "done").status, .conflict)
            try await eq(try await LoopApprovalRecord.query(on: h.db).count(), 0)
        }
    }

    func testAConnectedEstimateApprovalCarriesTheApprovalToTheBusiness() async throws {
        try await withHarness(Self.on) { h in
            let world = try await LoopWorld.build(h)
            let publication = try await world.publish(Self.estimateApproval(routing: "connected"))
            try await Self.bind(world, publication)
            let instance = try await world.instance(world.alice, publication)
            let good = try await challenge(world, world.alice, instance.id).json(LoopApprovalChallenge.self)
            let signed = try await h.decision(world.alice, interaction: good.interaction)
            let accepted = try await approve(world, world.alice, instance.id, approval: LoopActionApproval(approvalId: good.approvalId, signedDecision: signed))
            XCTAssertEqual(accepted.status, .created, accepted.text)
            let event = try accepted.json(LoopActionResult.self)
            try await world.drain(.loopDelivery)
            let view = try await h.business(world.business, .GET, "/v1/business/loops/events/\(Self.ref(event))").json(LoopBusinessEvent.self)
            let approval = try XCTUnwrap(view.approval)
            XCTAssertEqual(approval.amount.decimalString, "285.28")
            XCTAssertEqual(approval.reference, "EST-1042")
            XCTAssertEqual(approval.assurance, .biometric)
            XCTAssertEqual(approval.contextDigest, good.interaction.displayContextDigest())
            // The device-signed decision itself never reaches the business (it names the device).
            let raw = try await h.business(world.business, .GET, "/v1/business/loops/events/\(Self.ref(event))").text
            XCTAssertFalse(raw.contains(signed.signature))
            XCTAssertFalse(raw.contains(world.alice.device!.id.description))
        }
    }

    func testTenantDeletionRemovesBindingsApprovalsMarkersAndCallbacks() async throws {
        try await withHarness(Self.on) { h in
            let world = try await LoopWorld.build(h)
            let pickup = try await world.publish(Self.connectedPickup())
            try await Self.bind(world, pickup)
            let submitted = try await world.submitPickup(world.alice, try await world.instance(world.alice, pickup).id)
            try await eq(try await Self.outcome(world, Self.ref(submitted), "accepted", key: "ans-1").status, .created)
            let estimate = try await world.instance(world.alice, try await world.publish(Self.estimateApproval()))
            _ = try await challenge(world, world.alice, estimate.id)
            let request = DataRequestRecord()
            request.id = UUID()
            request.businessId = world.business.id.uuid
            request.kind = "delete"
            request.status = "requested"
            request.requestedBy = UUID()
            request.createdAt = h.clock.now()
            try await request.create(on: h.db)
            try await TenantDataRequests(db: h.db, ctx: h.ctx).complete(id: request.id!, operatorId: UUID())
            try await eq(try await LoopEndpointBindingRecord.query(on: h.db).count(), 0)
            try await eq(try await LoopConnectedEventRecord.query(on: h.db).count(), 0)
            try await eq(try await LoopApprovalRecord.query(on: h.db).count(), 0)
            try await eq(try await LoopOutcomeCallbackRecord.query(on: h.db).count(), 0)
        }
    }

    func testTheHostedInboxShowsTheApprovedEstimateAndSaysNothingWasCharged() async throws {
        try await withHarness(Self.on) { h in
            let (owner, _, businessId) = try await h.verifiedOwner()
            let world = try await LoopWorld.build(h, business: try await h.testBusiness(businessId), tag: "inbox")
            let instance = try await world.instance(world.alice, try await world.publish(Self.estimateApproval()))
            let good = try await challenge(world, world.alice, instance.id).json(LoopApprovalChallenge.self)
            let signed = try await h.decision(world.alice, interaction: good.interaction)
            try await eq(try await approve(world, world.alice, instance.id, approval: LoopActionApproval(approvalId: good.approvalId, signedDecision: signed)).status, .created)
            try await world.drain(.loopDelivery)
            let item = try await XCTUnwrapAsync(try await InboxItemRecord.query(on: h.db).first())
            let page = try await h.page("/dashboard/inbox/\(item.id!.uuidString.lowercased())", owner)
            XCTAssertEqual(page.status, .ok, page.text)
            XCTAssertTrue(page.text.contains("Approved estimate"), page.text)
            XCTAssertTrue(page.text.contains("$285.28") && page.text.contains("nothing was charged"))
        }
    }

    // MARK: WP-4.7 advanced Studio mode

    func testTheSchemaEditorHoldsJSONToTheSameClosedSchemaAndNeverPublishes() async throws {
        try await withHarness(Self.on) { h in
            let (owner, _, businessId) = try await h.verifiedOwner()
            let id = try await LoopStudioTests.createDraft(h, owner)
            let draft = "\(LoopStudioTests.path)/drafts/\(id.uuidString.lowercased())"
            let (record, base) = try await LoopStudioTests.stored(h, id)
            var json = String(decoding: try base.canonicalJSON(), as: UTF8.self)
            func post(_ text: String) async throws -> HTTPResult {
                try await h.formPost("\(draft)/schema", owner, [("version", try await LoopStudioTests.version(h, id)), ("schema", text)])
            }
            // Unknown members, a reserved or unregistered action, a prohibited field type, another business's kit, a foreign next step,
            // routing on a non-delivering action, an unregistered parameter, a handoff step: all refused before anything is stored.
            let hostile = [
                json.replacingOccurrences(of: #""schema_version":1"#, with: #""schema_version":1,"script":"x""#),
                json.replacingOccurrences(of: #""action":"acknowledge""#, with: #""action":"payment.capture""#),
                json.replacingOccurrences(of: #""action":"acknowledge""#, with: #""action":"wire_money""#),
                json.replacingOccurrences(of: #""type":"time_slot""#, with: #""type":"password""#),
                json.replacingOccurrences(of: #"{"mode":"standard"}"#, with: #"{"kit":"someone-else","mode":"brand_kit"}"#),
                json.replacingOccurrences(of: #""next":"done""#, with: #""next":"elsewhere""#),
                json.replacingOccurrences(of: #""label":"choose_time""#, with: #""label":"choose_time","routing":{"mode":"hosted"}"#),
                json.replacingOccurrences(of: #""label":"send_request""#, with: #""label":"send_request","params":{"callback_url":"x"}"#),
                "not json", String(repeating: " ", count: LoopSchemaEditor.maxBytes + 1),
            ]
            for (index, text) in hostile.enumerated() {
                XCTAssertNotEqual(text, json, "case \(index) changed nothing")
                let refused = try await post(text)
                // The oversize text is refused by the body limit before it is read.
                XCTAssertTrue([.unprocessableEntity, .payloadTooLarge].contains(refused.status), "case \(index): \(refused.status) \(refused.text.prefix(300))")
            }
            try await eq(try await LoopStudioTests.stored(h, id).0.version, record.version)
            // A viewer can't save JSON.
            let auditor = try await h.addMember(owner: owner, role: .auditor, email: "auditor@example.com")
            try await eq(try await h.formPost("\(draft)/schema", auditor.session, [("version", String(record.version)), ("schema", json)]).status, .forbidden)
            // Valid JSON is stored canonically under the draft's own key, whatever the text says, and the editor offers connected routing.
            json = json.replacingOccurrences(of: #""title":"Choose a pickup time""#, with: #""title":"Pick up your order""#)
                .replacingOccurrences(of: #""key":"\#(record.loopKey)""#, with: #""key":"hijacked""#)
                .replacingOccurrences(of: #""mode":"hosted""#, with: #""mode":"connected""#)
            let saved = try await post(json)
            XCTAssertEqual(saved.status, .seeOther, saved.text)
            let (after, definition) = try await LoopStudioTests.stored(h, id)
            XCTAssertEqual(definition.title, "Pick up your order")
            XCTAssertEqual(definition.key, record.loopKey)
            XCTAssertEqual(after.version, record.version + 1)
            XCTAssertTrue(definition.steps.flatMap(\.actions).contains { $0.routing?.mode == .connected })
            try await isTrue(try await AuditEventRecord.query(on: h.db).filter(\.$action == "loop.studio_draft_saved").all().contains { $0.metadataJSON.contains("\"schema\"") })
            let page = try await h.page(draft, owner)
            XCTAssertTrue(page.text.contains("Advanced: edit as JSON"))
            XCTAssertTrue(page.text.contains("Your own system"), "connected routing is offered in Phase 4")
            // Submitting goes through the pipeline: in review, not published.
            let submitted = try await h.formPost("\(draft)/submit", owner, [("version", String(after.version))])
            XCTAssertEqual(submitted.status, .seeOther, submitted.text)
            let revision = try await LoopRevisionRecord.query(on: h.db).filter(\.$businessId == businessId).first()
            XCTAssertEqual(revision?.stateValue, .inReview)
            try await eq(try await LoopPublicationRecord.query(on: h.db).count(), 0)
        }
    }

    func testWithPhase4OffTheSchemaEditorRefusesConnectedRoutingAndApprovals() async throws {
        try await withHarness { h in
            let (owner, _, _) = try await h.verifiedOwner()
            let id = try await LoopStudioTests.createDraft(h, owner)
            let draft = "\(LoopStudioTests.path)/drafts/\(id.uuidString.lowercased())"
            let json = String(decoding: try await LoopStudioTests.stored(h, id).1.canonicalJSON(), as: UTF8.self)
            let connected = try await h.formPost("\(draft)/schema", owner, [("version", try await LoopStudioTests.version(h, id)),
                                                                           ("schema", json.replacingOccurrences(of: #""mode":"hosted""#, with: #""mode":"connected""#))])
            XCTAssertEqual(connected.status, .unprocessableEntity, connected.text)
            let page = try await h.page(draft, owner)
            XCTAssertFalse(page.text.contains("Your own system"))
        }
    }
}
