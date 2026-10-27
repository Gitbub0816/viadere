import Fluent
import Foundation
import ViadereCore
import struct ViadereCore.Page
import XCTest
@testable import ViadereServerKit

final class DecisionTests: XCTestCase {
    struct Scene {
        var business: TestBusiness
        var consumer: TestConsumer
        var relationship: Relationship
    }

    func scene(_ h: TestHarness) async throws -> Scene {
        let business = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
        let consumer = try await h.readyConsumer()
        let relationship = try await h.connect(consumer, to: business)
        return Scene(business: business, consumer: consumer, relationship: relationship)
    }

    func issueAuthorize(_ h: TestHarness, _ s: Scene, sensitivity: Sensitivity = .standard, ttl: Int = 300, key: String = UUID().uuidString) async throws -> Interaction {
        let response = try await h.issue(s.business, relationship: s.relationship, payload: .authorize(.sample()), sensitivity: sensitivity, key: key, ttl: ttl)
        XCTAssertEqual(response.status, .created, response.text)
        return try response.json(Interaction.self)
    }

    // MARK: Happy path, push and webhook

    func testApproveFlowPushPayloadAndSignedWebhook() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            // Register an APNs token for the consumer's device (device-signed).
            let token = String(repeating: "ab", count: 32)
            let registered = try await h.signedPost(s.consumer, "/v1/push/apns-token", APNsTokenRegistration(token: token, environment: .sandbox, bundleId: "com.viadere.app"))
            XCTAssertEqual(registered.status, .ok, registered.text)
            // Business subscribes to decisions.
            let created = try await h.businessPost(s.business, "/v1/business/webhooks", CreateWebhookRequest(url: URL(string: "https://hooks.example.com/viadere")!, events: [.interactionDecided]))
            XCTAssertEqual(created.status, .created, created.text)
            let secret = try created.json(WebhookSecretResponse.self).secret

            let businessView = try await issueAuthorize(h, s, sensitivity: .high)
            // The business sees a per-business pseudonym, not the consumer's id, and not the device challenge.
            XCTAssertNotEqual(businessView.scope.consumerId, s.consumer.id)
            let real = try await h.consumerInteraction(s.consumer, id: businessView.id)
            XCTAssertEqual(real.scope.consumerId, s.consumer.id)
            XCTAssertNotEqual(businessView.challenge, real.challenge)
            XCTAssertEqual(businessView.priority, .normal)

            // Push: opaque id only, never the amount, merchant, or place.
            XCTAssertEqual(h.push.sent.count, 1)
            let push = h.push.sent[0]
            XCTAssertEqual(push.interactionId, businessView.id.description)
            XCTAssertEqual(push.deviceToken, token)
            XCTAssertTrue(push.mutableContent)
            XCTAssertEqual(push.category, "viadere.authorize.secure")
            XCTAssertEqual(push.threadID, "business.\(s.business.id)")
            for text in [push.title, push.body, push.category, push.threadID, push.interactionId ?? ""] {
                for secretWord in ["285", "Walmart", "Mesa", "Northwind", "Arizona"] { XCTAssertFalse(text.contains(secretWord), "push leaked \(secretWord)") }
            }

            // The consumer lists pending interactions and decides with a biometric-gated key.
            let list = try await h.signed(s.consumer, .GET, "/v1/interactions")
            XCTAssertEqual(try list.json(Page<InteractionEnvelope>.self).items.count, 1)
            let signedDecision = try await h.decision(s.consumer, interaction: real)
            let decided = try await h.decide(s.consumer, id: real.id, signed: signedDecision)
            XCTAssertEqual(decided.status, .ok, decided.text)
            let outcome = try decided.json(InteractionOutcome.self)
            XCTAssertEqual(outcome.status, .approved)
            XCTAssertEqual(outcome.assurance, .biometric)

            // The business reads the outcome (with the device-signed decision for its audit trail).
            let fetched = try await h.business(s.business, .GET, "/v1/business/interactions/\(real.id)")
            let businessOutcome = try fetched.json(InteractionOutcome.self)
            XCTAssertEqual(businessOutcome.status, .approved)
            XCTAssertEqual(businessOutcome.signedDecision, signedDecision)
            // No longer pending for the consumer.
            let after = try await h.signed(s.consumer, .GET, "/v1/interactions")
            XCTAssertEqual(try after.json(Page<InteractionEnvelope>.self).items.count, 0)

            // Webhook delivery is signed and verifiable with the subscription secret.
            try await h.runJobs()
            let deliveries = h.webhooks.received
            XCTAssertEqual(deliveries.count, 1)
            let delivery = deliveries[0]
            XCTAssertEqual(delivery.headers[ViadereHeader.eventType], "interaction.decided")
            XCTAssertNoThrow(try WebhookSignature.verify(header: delivery.headers[ViadereHeader.signature]!, body: delivery.body, secrets: [secret], now: h.clock.now()))
            XCTAssertThrowsError(try WebhookSignature.verify(header: delivery.headers[ViadereHeader.signature]!, body: delivery.body, secrets: ["whsec_wrong"], now: h.clock.now()))
            let event = try ViadereJSON.decode(WebhookEvent.self, from: delivery.body)
            XCTAssertEqual(event.type, .interactionDecided)
            XCTAssertEqual(event.businessId, s.business.id)
            XCTAssertEqual(try event.decodeData(InteractionOutcome.self).status, .approved)
            XCTAssertEqual(delivery.headers[ViadereHeader.eventId], event.id.description)
            // The consumer's real identifier never appears in what the business receives.
            XCTAssertFalse(String(decoding: delivery.body, as: UTF8.self).contains(s.consumer.id.description))
        }
    }

    // MARK: Replay, staleness, binding

    func testReplayedDecisionIsRejected() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            let interaction = try await h.consumerInteraction(s.consumer, id: try await issueAuthorize(h, s).id)
            let signedDecision = try await h.decision(s.consumer, interaction: interaction)
            let first = try await h.decide(s.consumer, id: interaction.id, signed: signedDecision)
            XCTAssertEqual(first.status, .ok)
            let replay = try await h.decide(s.consumer, id: interaction.id, signed: signedDecision)
            XCTAssertEqual(replay.status, .conflict)
            // Even a freshly signed decision (different signedAt) cannot flip the outcome afterwards.
            let flip = try await h.decision(s.consumer, interaction: interaction, decision: .deny)
            let second = try await h.decide(s.consumer, id: interaction.id, signed: flip)
            XCTAssertEqual(second.status, .conflict)
            let status = try await InteractionRecord.find(interaction.id.uuid, on: h.db)?.status
            XCTAssertEqual(status, InteractionStatus.approved.rawValue)
        }
    }

    func testStaleDecisionIsRejectedAndDoesNotBurnTheChallenge() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            let interaction = try await h.consumerInteraction(s.consumer, id: try await issueAuthorize(h, s).id)
            h.clock.advance(by: 120)
            let stale = try await h.decision(s.consumer, interaction: interaction, signedAt: h.clock.now().addingTimeInterval(-310))
            let rejected = try await h.decide(s.consumer, id: interaction.id, signed: stale)
            XCTAssertEqual(rejected.status, .gone)
            let future = try await h.decision(s.consumer, interaction: interaction, signedAt: h.clock.now().addingTimeInterval(120))
            try await eq(try await h.decide(s.consumer, id: interaction.id, signed: future).status, .unauthorized)
            // A fresh, correct decision still works afterwards.
            let fresh = try await h.decision(s.consumer, interaction: interaction)
            try await eq(try await h.decide(s.consumer, id: interaction.id, signed: fresh).status, .ok)
        }
    }

    func testExpiredInteractionCannotBeDecidedAndBusinessIsNotified() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            _ = try await h.businessPost(s.business, "/v1/business/webhooks", CreateWebhookRequest(url: URL(string: "https://hooks.example.com/v")!, events: [.interactionExpired]))
            let interaction = try await h.consumerInteraction(s.consumer, id: try await issueAuthorize(h, s, ttl: 60).id)
            h.clock.advance(by: 61)
            let signedDecision = try await h.decision(s.consumer, interaction: interaction, signedAt: h.clock.now())
            let response = try await h.decide(s.consumer, id: interaction.id, signed: signedDecision)
            XCTAssertEqual(response.status, .gone)
            let outcome = try await h.business(s.business, .GET, "/v1/business/interactions/\(interaction.id)").json(InteractionOutcome.self)
            XCTAssertEqual(outcome.status, .expired)
            try await h.runJobs()
            XCTAssertEqual(h.webhooks.received.count, 1)
            XCTAssertEqual(h.webhooks.received[0].headers[ViadereHeader.eventType], "interaction.expired")
            // Expired interactions are no longer listed as pending.
            let list = try await h.signed(s.consumer, .GET, "/v1/interactions")
            XCTAssertEqual(try list.json(Page<InteractionEnvelope>.self).items.count, 0)
        }
    }

    func testWrongKeyPurposeIsRejected() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            let interaction = try await h.consumerInteraction(s.consumer, id: try await issueAuthorize(h, s).id)
            let device = s.consumer.device!
            // Claims biometric assurance but is signed by the passcode (userPresence) key.
            let passcodeForBiometric = try await h.decision(s.consumer, interaction: interaction, assurance: .biometric, signWith: device.passcodeKey)
            try await eq(try await h.decide(s.consumer, id: interaction.id, signed: passcodeForBiometric).status, .unauthorized)
            // The plain request key cannot sign a decision that claims higher assurance.
            let requestKey = try await h.decision(s.consumer, interaction: interaction, assurance: .devicePasscode, signWith: device.requestKey)
            try await eq(try await h.decide(s.consumer, id: interaction.id, signed: requestKey).status, .unauthorized)
            // A key from a different device (same consumer) is not accepted for this device.
            let other = SoftwareP256SigningKey()
            let foreign = try await h.decision(s.consumer, interaction: interaction, assurance: .biometric, signWith: other)
            try await eq(try await h.decide(s.consumer, id: interaction.id, signed: foreign).status, .unauthorized)
            // The honest decision still works: failures did not consume the challenge.
            let honest = try await h.decision(s.consumer, interaction: interaction, assurance: .biometric)
            try await eq(try await h.decide(s.consumer, id: interaction.id, signed: honest).status, .ok)
        }
    }

    func testDeviceWithoutApprovalKeysCannotClaimHigherAssurance() async throws {
        try await withHarness { h in
            let business = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
            let consumer = try await h.enrollDevice(try await h.registerConsumer(), purposes: [.request])
            let relationship = try await h.connect(consumer, to: business)
            let response = try await h.issue(business, relationship: relationship, payload: .authorize(.sample()), sensitivity: .standard)
            let interaction = try await h.consumerInteraction(consumer, id: try response.json(Interaction.self).id)
            let key = consumer.device!.requestKey
            let claimed = try await h.decision(consumer, interaction: interaction, assurance: .biometric, signWith: key)
            let rejected = try await h.decide(consumer, id: interaction.id, signed: claimed)
            XCTAssertEqual(rejected.status, .forbidden)
            XCTAssertEqual(rejected.errorCode, .insufficientAssurance)
            // A request-key-only decision (assurance .none) is below what authorize needs at standard sensitivity.
            let weak = try await h.decision(consumer, interaction: interaction, assurance: .none)
            let weakResult = try await h.decide(consumer, id: interaction.id, signed: weak)
            XCTAssertEqual(weakResult.errorCode, .insufficientAssurance)
        }
    }

    func testAssurancePolicyIsEnforcedServerSide() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            // High-sensitivity authorize needs a biometric-gated key; a passcode-gated signature is not enough.
            let interaction = try await h.consumerInteraction(s.consumer, id: try await issueAuthorize(h, s, sensitivity: .high).id)
            let passcode = try await h.decision(s.consumer, interaction: interaction, assurance: .devicePasscode)
            let rejected = try await h.decide(s.consumer, id: interaction.id, signed: passcode)
            XCTAssertEqual(rejected.status, .forbidden)
            XCTAssertEqual(rejected.errorCode, .insufficientAssurance)
            let biometric = try await h.decision(s.consumer, interaction: interaction, assurance: .biometric)
            try await eq(try await h.decide(s.consumer, id: interaction.id, signed: biometric).status, .ok)
        }
    }

    func testSMSChannelCanNeverSatisfyAuthorize() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            // The business even lists SMS as an allowed channel; it still cannot carry the decision.
            let response = try await h.issue(s.business, relationship: s.relationship, payload: .authorize(.sample()), channels: [.nativePush, .sms])
            let interaction = try await h.consumerInteraction(s.consumer, id: try response.json(Interaction.self).id)
            for channel: DeliveryChannel in [.sms, .rcs, .appleMessagesForBusiness] {
                let signedDecision = try await h.decision(s.consumer, interaction: interaction)
                let rejected = try await h.decide(s.consumer, id: interaction.id, signed: signedDecision, channel: channel)
                XCTAssertEqual(rejected.status, .forbidden, "\(channel)")
                XCTAssertEqual(rejected.errorCode, .insufficientAssurance)
            }
            let status = try await InteractionRecord.find(interaction.id.uuid, on: h.db)?.status
            XCTAssertEqual(status, InteractionStatus.pending.rawValue)
        }
    }

    func testBindingMismatchesAreRejected() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            let interaction = try await h.consumerInteraction(s.consumer, id: try await issueAuthorize(h, s).id)
            let other = try await h.consumerInteraction(s.consumer, id: try await issueAuthorize(h, s).id)
            // Decision for another interaction submitted to this one.
            let wrongInteraction = try await h.decision(s.consumer, interaction: other)
            try await eq(try await h.decide(s.consumer, id: interaction.id, signed: wrongInteraction).status, .forbidden)
            // Wrong challenge.
            let wrongChallenge = try await h.decision(s.consumer, interaction: interaction, challenge: ChallengeNonce.generate())
            try await eq(try await h.decide(s.consumer, id: interaction.id, signed: wrongChallenge).status, .forbidden)
            // The challenge the *business* sees is not usable (it is a one-way reference).
            let businessChallenge = ChallengeNonce(SecureToken.hash(interaction.challenge.value))!
            let viaBusiness = try await h.decision(s.consumer, interaction: interaction, challenge: businessChallenge)
            try await eq(try await h.decide(s.consumer, id: interaction.id, signed: viaBusiness).status, .forbidden)
            // Decision kind not allowed for authorize.
            let confirm = try await h.decision(s.consumer, interaction: interaction, decision: .confirm)
            try await eq(try await h.decide(s.consumer, id: interaction.id, signed: confirm).status, .unprocessableEntity)
            // Garbage signed decision.
            let garbage = try await h.decide(s.consumer, id: interaction.id, signed: SignedDecision(payload: "AAAA", signature: "BBBB"))
            XCTAssertEqual(garbage.status, .badRequest)
        }
    }

    func testAnotherConsumerCannotSeeOrDecide() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            let interaction = try await h.consumerInteraction(s.consumer, id: try await issueAuthorize(h, s).id)
            let mallory = try await h.readyConsumer(name: "Mallory")
            try await eq(try await h.signed(mallory, .GET, "/v1/interactions/\(interaction.id)").status, .notFound)
            let signedDecision = try await h.decision(mallory, interaction: interaction)
            try await eq(try await h.decide(mallory, id: interaction.id, signed: signedDecision).status, .notFound)
            try await eq(try await h.signed(mallory, .GET, "/v1/interactions").json(Page<InteractionEnvelope>.self).items.count, 0)
        }
    }

    func testChoiceSelectionIsValidated() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            let payload = InteractionPayload.choose(ChoosePayload(prompt: "Pick a seat", options: [ChoiceOption(id: "a", label: "Aisle"), ChoiceOption(id: "w", label: "Window")]))
            let response = try await h.issue(s.business, relationship: s.relationship, payload: payload, purpose: .transactional)
            let interaction = try await h.consumerInteraction(s.consumer, id: try response.json(Interaction.self).id)
            let invalid = try await h.decision(s.consumer, interaction: interaction, decision: .select, assurance: .none, selected: ["zzz"])
            try await eq(try await h.decide(s.consumer, id: interaction.id, signed: invalid).status, .unprocessableEntity)
            let valid = try await h.decision(s.consumer, interaction: interaction, decision: .select, assurance: .none, selected: ["w"])
            let ok = try await h.decide(s.consumer, id: interaction.id, signed: valid)
            XCTAssertEqual(ok.status, .ok, ok.text)
            let outcome = try ok.json(InteractionOutcome.self)
            XCTAssertEqual(outcome.status, .selected)
            XCTAssertEqual(outcome.selectedOptionIds, ["w"])
        }
    }

    func testReportedDecisionIsAuditedAsSuspicious() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            let interaction = try await h.consumerInteraction(s.consumer, id: try await issueAuthorize(h, s).id)
            let report = try await h.decision(s.consumer, interaction: interaction, decision: .report)
            try await eq(try await h.decide(s.consumer, id: interaction.id, signed: report).json(InteractionOutcome.self).status, .reported)
            let flagged = try await AuditEventRecord.query(on: h.db).filter(\.$action == "interaction.reported_suspicious").count()
            XCTAssertEqual(flagged, 1)
        }
    }

    func testRejectedDecisionsAreAudited() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            let interaction = try await h.consumerInteraction(s.consumer, id: try await issueAuthorize(h, s).id)
            let signedDecision = try await h.decision(s.consumer, interaction: interaction)
            _ = try await h.decide(s.consumer, id: interaction.id, signed: signedDecision, channel: .sms)
            let denied = try await AuditEventRecord.query(on: h.db).filter(\.$action == "interaction.decision_rejected").all()
            XCTAssertEqual(denied.count, 1)
            XCTAssertEqual(denied[0].outcome, "denied")
            XCTAssertFalse(denied[0].metadataJSON.contains(signedDecision.signature))
        }
    }
}
