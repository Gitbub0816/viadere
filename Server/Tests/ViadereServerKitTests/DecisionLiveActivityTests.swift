import Fluent
import Foundation
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Decision Live Activities (docs/SECURITY.md §2.16): a neutral push-to-start for an eligible confirm/choose, and an end push when it is
/// answered, withdrawn or expires. No business text ever enters the pushed content.
final class DecisionLiveActivityTests: XCTestCase {
    private let startToken = String(repeating: "5a", count: 32)
    private let updateToken = String(repeating: "7c", count: 32)

    /// Every business-authored string used below; none may appear in a Live Activity push.
    private let secrets = ["Pick up at 4:30", "Order 1042 two items", "REF-77", "Which window works", "Morning slot", "Evening slot", "Secret"]

    private struct Scene {
        var business: TestBusiness
        var consumer: TestConsumer
        var relationship: Relationship
    }

    private func scene(_ h: TestHarness, live: Bool = true, startToken register: Bool = true, name: String = "Copperline Kitchen",
                       handle: String = "copperline") async throws -> Scene {
        let business = try await h.makeBusiness(name: name, handle: handle, live: live)
        let consumer = try await h.readyConsumer()
        let relationship = try await h.connect(consumer, to: business)
        _ = try await h.signedPost(consumer, "/v1/push/apns-token", APNsTokenRegistration(token: String(repeating: "ab", count: 32), environment: .sandbox, bundleId: "com.viadere.app"))
        if register {
            try await eq(try await h.signedPost(consumer, "/v1/live-activities/tokens", LiveActivityTokenRegistration(kind: .pushToStart, pushToken: startToken)).status, .ok)
        }
        return Scene(business: business, consumer: consumer, relationship: relationship)
    }

    private var confirm: InteractionPayload { .confirm(ConfirmPayload(title: "Pick up at 4:30", details: "Order 1042 two items", reference: "REF-77")) }
    private var choose: InteractionPayload {
        .choose(ChoosePayload(prompt: "Which window works", options: [ChoiceOption(id: "am", label: "Morning slot"), ChoiceOption(id: "eve", label: "Evening slot")]))
    }

    private func issue(_ h: TestHarness, _ s: Scene, _ payload: InteractionPayload, purpose: InteractionPurpose = .transactional,
                       sensitivity: Sensitivity = .low, ttl: Int = 600, channels: [DeliveryChannel] = [.nativePush, .inApp]) async throws -> HTTPResult {
        try await h.issue(s.business, relationship: s.relationship, payload: payload, purpose: purpose, sensitivity: sensitivity, ttl: ttl, channels: channels)
    }

    private func registerUpdate(_ h: TestHarness, _ s: Scene, _ interaction: Interaction, token: String? = nil) async throws {
        let body = LiveActivityTokenRegistration(kind: .update, activityId: "act-\(interaction.id)", businessId: s.business.id,
                                                 interactionId: interaction.id, pushToken: token ?? updateToken)
        try await eq(try await h.signedPost(s.consumer, "/v1/live-activities/tokens", body).status, .ok)
    }

    /// The exact content-state JSON APNs receives (the sender encodes with a default `JSONEncoder`).
    private func contentJSON(_ push: LiveActivityPush) throws -> String {
        String(decoding: try JSONEncoder().encode(push.content), as: UTF8.self)
    }

    private func assertNoBusinessText(_ push: LiveActivityPush, file: StaticString = #filePath, line: UInt = #line) throws {
        let json = try contentJSON(push)
        for secret in secrets { XCTAssertFalse(json.contains(secret), "content leaked \(secret): \(json)", file: file, line: line) }
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(json.utf8)) as? [String: Any], file: file, line: line)
        let decision = try XCTUnwrap(object["decision"] as? [String: Any], file: file, line: line)
        XCTAssertEqual(Set(decision.keys), ["interactionId", "kind", "expiresAt", "stage"], file: file, line: line)
        XCTAssertNotEqual(push.alertBody.map { b in secrets.contains { b.contains($0) } }, true, file: file, line: line)
    }

    func testEligibleConfirmAndChooseStartANeutralDecisionActivity() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            let issued = try await issue(h, s, confirm).json(Interaction.self)
            var pushes = h.push.liveActivities
            XCTAssertEqual(pushes.count, 1)
            let start = try XCTUnwrap(pushes.first)
            XCTAssertEqual(start.event, .start)
            XCTAssertEqual(start.deviceToken, startToken)
            XCTAssertEqual(start.environment, .sandbox)
            XCTAssertEqual(start.topic, "com.viadere.app.push-type.liveactivity")
            XCTAssertEqual(start.attributes, LiveActivityPush.Attributes(businessName: "Copperline Kitchen", businessId: s.business.id.description, interactionId: issued.id.description))
            XCTAssertEqual(start.alertTitle, "Viadere")
            XCTAssertEqual(start.alertBody, "You have a new request.", "the start alert is neutral")
            XCTAssertEqual(start.staleDate, Int(issued.expiresAt.timeIntervalSince1970))
            XCTAssertEqual(start.content, .decision(DecisionActivityState(interactionId: issued.id, kind: .confirm, expiresAt: issued.expiresAt, stage: .pending)))
            try assertNoBusinessText(start)

            let chosen = try await issue(h, s, choose).json(Interaction.self)
            pushes = h.push.liveActivities
            XCTAssertEqual(pushes.count, 2)
            XCTAssertEqual(pushes[1].content, .decision(DecisionActivityState(interactionId: chosen.id, kind: .choose, expiresAt: chosen.expiresAt, stage: .pending)))
            try assertNoBusinessText(pushes[1])
            // Support and account-service decisions qualify too.
            _ = try await issue(h, s, confirm, purpose: .support)
            _ = try await issue(h, s, confirm, purpose: .accountService)
            XCTAssertEqual(h.push.liveActivities.count, 4)
            // The ordinary notification push still went out, generic as ever.
            XCTAssertFalse(h.push.sent.isEmpty)
            XCTAssertFalse(h.push.sent.contains { m in secrets.contains { m.body.contains($0) || m.title.contains($0) } })
        }
    }

    func testIneligibleInteractionsNeverStartOne() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            let optIn = ConsentUpdateRequest(changes: [ConsentChange(purpose: .marketing, granted: true), ConsentChange(purpose: .rewards, granted: true)], policyVersion: "2026-10")
            let consent = try await h.request(.PUT, "/v1/relationships/\(s.relationship.id)/consents",
                                              headers: try await h.signedHeaders(s.consumer, .PUT, "/v1/relationships/\(s.relationship.id)/consents", body: try ViadereJSON.encode(optIn)),
                                              body: try ViadereJSON.encode(optIn))
            XCTAssertEqual(consent.status, .ok, consent.text)
            // Sign-in and approval requests, whatever their purpose.
            try await eq(try await issue(h, s, .authorize(.sample()), purpose: .security).status, .created)
            try await eq(try await issue(h, s, .authenticate(AuthenticatePayload(service: "Online", device: "Chrome", attemptedAt: h.clock.now())), purpose: .security).status, .created)
            // Marketing, rewards and security purposes.
            for purpose in [InteractionPurpose.marketing, .rewards, .security] {
                let result = try await issue(h, s, confirm, purpose: purpose)
                XCTAssertTrue([.created, .unprocessableEntity].contains(result.status), "\(purpose): \(result.text)")
            }
            // A rendering the notification renderer marks secure (step-up needed).
            let secure = try await issue(h, s, confirm, sensitivity: .high).json(Interaction.self)
            XCTAssertTrue(ChannelRenderer.requiresSecureFlow(secure))
            // A choose that does not fit the Lock Screen.
            let four = ChoosePayload(prompt: "Secret", options: (0..<4).map { ChoiceOption(id: "o\($0)", label: "Option \($0)") })
            try await eq(try await issue(h, s, .choose(four)).status, .created)
            let multi = ChoosePayload(prompt: "Secret", options: [ChoiceOption(id: "a", label: "A"), ChoiceOption(id: "b", label: "B")], allowsMultiple: true)
            try await eq(try await issue(h, s, .choose(multi)).status, .created)
            // Native push not allowed for it.
            try await eq(try await issue(h, s, confirm, channels: [.inApp]).status, .created)
            // Other kinds.
            try await eq(try await issue(h, s, .acknowledge(AcknowledgePayload(title: "Secret", body: "Terms"))).status, .created)
            XCTAssertEqual(h.push.liveActivities.count, 0, "none of these may start a decision activity")
            // A business status can never smuggle a decision activity in.
            let smuggled = LiveActivityStatus.decision(DecisionActivityState(interactionId: secure.id, kind: .confirm, expiresAt: h.clock.now().addingTimeInterval(600),
                                                                             title: "Secret", options: [.init(id: "x", label: "Secret")]))
            let status = try await h.businessPost(s.business, "/v1/business/statuses", BusinessStatusUpdateRequest(
                relationshipId: s.relationship.id, purpose: .transactional, status: StatusPayload(title: "Order", liveActivity: smuggled),
                activityKey: "smuggle", idempotencyKey: "smuggle-1"))
            XCTAssertEqual(status.status, .unprocessableEntity, status.text)
            XCTAssertEqual(h.push.liveActivities.count, 0)
        }
    }

    func testTestKeysRestrictedPushAndUnregisteredDevicesGetNothing() async throws {
        try await withHarness { h in
            // Test-mode keys reach sandbox consumers only, and never start an activity.
            let test = try await scene(h, live: false, name: "Copperline Test", handle: "copperlinetest")
            let sandbox = try await h.sandboxRelationship(test.business)
            let testIssued = try await h.issue(test.business, relationship: sandbox, payload: confirm, purpose: .transactional, sensitivity: .low, ttl: 600)
            XCTAssertEqual(testIssued.status, .created, testIssued.text)
            XCTAssertEqual(h.push.liveActivities.count, 0, "test keys never reach real devices")
            // No push-to-start token registered: nothing to start.
            let quiet = try await scene(h, startToken: false, name: "Quiet Kitchen", handle: "quietkitchen")
            _ = try await issue(h, quiet, confirm)
            XCTAssertEqual(h.push.liveActivities.count, 0)
            // An emergency push restriction on the business (G-6) blocks the activity exactly like the notification.
            let s = try await scene(h)
            try await PlatformFlags(db: h.db, ctx: h.ctx).set(.messagingRestrict, businessId: s.business.record.id!, value: #"{"mode":"block","channels":["push"]}"#,
                                                              reason: "Complaint wave", actor: EntitlementActor.system("test"))
            let pushesBefore = h.push.sent.count
            try await eq(try await issue(h, s, confirm).status, .created)
            XCTAssertEqual(h.push.sent.count, pushesBefore, "the notification is restricted")
            XCTAssertEqual(h.push.liveActivities.count, 0, "and so is the activity")
        }
    }

    func testDecisionEndsTheActivityWithoutBusinessText() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            let issued = try await issue(h, s, confirm).json(Interaction.self)
            try await registerUpdate(h, s, issued)
            // A second activity's token for another interaction must not be touched.
            let other = try await issue(h, s, choose).json(Interaction.self)
            try await registerUpdate(h, s, other, token: String(repeating: "3d", count: 32))
            let before = h.push.liveActivities.count
            h.clock.advance(by: 5)
            let shown = try await h.consumerInteraction(s.consumer, id: issued.id)
            let signed = try await h.decision(s.consumer, interaction: shown, decision: .confirm, assurance: .none)
            let decided = try await h.decide(s.consumer, id: issued.id, signed: signed)
            XCTAssertEqual(decided.status, .ok, decided.text)
            let after = Array(h.push.liveActivities.dropFirst(before))
            XCTAssertEqual(after.count, 1)
            let end = try XCTUnwrap(after.first)
            XCTAssertEqual(end.event, .end)
            XCTAssertEqual(end.deviceToken, updateToken)
            XCTAssertNil(end.attributes)
            XCTAssertEqual(end.content, .decision(DecisionActivityState(interactionId: issued.id, kind: .confirm, expiresAt: issued.expiresAt, stage: .answered)))
            XCTAssertEqual(end.dismissalDate, end.timestamp + LiveActivityService.decisionDismissalDelay)
            try assertNoBusinessText(end)
            // The token is used once: ending again sends nothing.
            await InteractionService(db: h.db, ctx: h.ctx).endDecisionActivity(issued.id.uuid)
            XCTAssertEqual(h.push.liveActivities.count, before + 1)
            let remaining = try await LiveActivityTokenRecord.query(on: h.db).filter(\.$kind == "update").all()
            XCTAssertEqual(remaining.map(\.interactionId), [other.id.uuid])
            // A pending interaction is never "ended".
            await InteractionService(db: h.db, ctx: h.ctx).endDecisionActivity(other.id.uuid)
            XCTAssertEqual(h.push.liveActivities.count, before + 1)
        }
    }

    func testCancelAndDisconnectEndTheActivity() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            let issued = try await issue(h, s, confirm).json(Interaction.self)
            try await registerUpdate(h, s, issued)
            let before = h.push.liveActivities.count
            let cancel = try await h.business(s.business, .POST, "/v1/business/interactions/\(issued.id)/cancel", body: Data("{}".utf8), idempotencyKey: "cancel-1")
            XCTAssertEqual(cancel.status, .ok, cancel.text)
            var after = Array(h.push.liveActivities.dropFirst(before))
            XCTAssertEqual(after.map(\.event), [.end])
            XCTAssertEqual(after.first?.content, .decision(DecisionActivityState(interactionId: issued.id, kind: .confirm, expiresAt: issued.expiresAt, stage: .cancelled)))
            try assertNoBusinessText(try XCTUnwrap(after.first))
            // Replaying the cancel sends nothing more.
            _ = try await h.business(s.business, .POST, "/v1/business/interactions/\(issued.id)/cancel", body: Data("{}".utf8), idempotencyKey: "cancel-1")
            XCTAssertEqual(h.push.liveActivities.count, before + 1)

            // Disconnecting withdraws pending requests: their activities end too.
            let second = try await issue(h, s, choose).json(Interaction.self)
            try await registerUpdate(h, s, second, token: String(repeating: "4e", count: 32))
            let beforeDisconnect = h.push.liveActivities.count
            try await eq(try await h.signed(s.consumer, .DELETE, "/v1/relationships/\(s.relationship.id)").status, .ok)
            after = Array(h.push.liveActivities.dropFirst(beforeDisconnect))
            XCTAssertEqual(after.map(\.event), [.end])
            XCTAssertEqual(after.first?.content, .decision(DecisionActivityState(interactionId: second.id, kind: .choose, expiresAt: second.expiresAt, stage: .cancelled)))
        }
    }

    func testExpiryEndsTheActivityAfterCommit() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            // Through the scheduled expiry message.
            let issued = try await issue(h, s, confirm, ttl: 120).json(Interaction.self)
            try await registerUpdate(h, s, issued)
            let before = h.push.liveActivities.count
            await QueuePump(app: h.app).runOnce()
            XCTAssertEqual(h.push.liveActivities.count, before, "nothing before expires_at")
            h.clock.advance(by: 121)
            await QueuePump(app: h.app).runOnce()
            try await eq(try await InteractionRecord.find(issued.id.uuid, on: h.db)?.status, InteractionStatus.expired.rawValue)
            var after = Array(h.push.liveActivities.dropFirst(before))
            XCTAssertEqual(after.map(\.event), [.end])
            XCTAssertEqual(after.first?.content, .decision(DecisionActivityState(interactionId: issued.id, kind: .confirm, expiresAt: issued.expiresAt, stage: .expired)))
            try assertNoBusinessText(try XCTUnwrap(after.first))

            // Through a business reading the outcome after the expiry (lazy expiry outside a transaction).
            let second = try await issue(h, s, choose, ttl: 120).json(Interaction.self)
            try await registerUpdate(h, s, second, token: String(repeating: "6f", count: 32))
            let beforeLazy = h.push.liveActivities.count
            h.clock.advance(by: 121)
            let outcome = try await h.business(s.business, .GET, "/v1/business/interactions/\(second.id)").json(InteractionOutcome.self)
            XCTAssertEqual(outcome.status, .expired)
            after = Array(h.push.liveActivities.dropFirst(beforeLazy))
            XCTAssertEqual(after.map(\.event), [.end])
            XCTAssertEqual(after.first?.content, .decision(DecisionActivityState(interactionId: second.id, kind: .choose, expiresAt: second.expiresAt, stage: .expired)))
        }
    }

    func testEndPushesSkipRevokedDevicesAndOtherConsumersTokens() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            let issued = try await issue(h, s, confirm).json(Interaction.self)
            try await registerUpdate(h, s, issued)
            // Someone else, connected to the same business, registers a token naming this interaction: it is never used.
            let mallory = try await h.readyConsumer(name: "Mallory")
            _ = try await h.connect(mallory, to: s.business)
            try await eq(try await h.signedPost(mallory, "/v1/live-activities/tokens", LiveActivityTokenRegistration(
                kind: .update, activityId: "m", businessId: s.business.id, interactionId: issued.id, pushToken: String(repeating: "99", count: 32))).status, .ok)
            let before = h.push.liveActivities.count
            let shown = try await h.consumerInteraction(s.consumer, id: issued.id)
            let decided = try await h.decide(s.consumer, id: issued.id, signed: try await h.decision(s.consumer, interaction: shown, decision: .decline, assurance: .none))
            XCTAssertEqual(decided.status, .ok, decided.text)
            let after = Array(h.push.liveActivities.dropFirst(before))
            XCTAssertEqual(after.map(\.deviceToken), [updateToken], "only the interaction's own consumer's tokens")
        }
    }

    func testNoEndPushFromInsideATransaction() async throws {
        try await withHarness { h in
            let s = try await scene(h)
            let issued = try await issue(h, s, confirm).json(Interaction.self)
            try await registerUpdate(h, s, issued)
            try await InteractionRecord.query(on: h.db).filter(\.$id == issued.id.uuid).set(\.$status, to: InteractionStatus.cancelled.rawValue).update()
            let before = h.push.liveActivities.count
            let ctx = h.ctx
            try await h.db.transaction { tx in
                await InteractionService(db: tx, ctx: ctx).endDecisionActivity(issued.id.uuid)
            }
            XCTAssertEqual(h.push.liveActivities.count, before, "a change that could still roll back is never announced")
            await InteractionService(db: h.db, ctx: h.ctx).endDecisionActivity(issued.id.uuid)
            XCTAssertEqual(h.push.liveActivities.count, before + 1)
        }
    }

    func testContentStateCodingMatchesActivityKit() throws {
        let state = LiveActivityStatus.decision(DecisionActivityState(interactionId: InteractionID(), kind: .choose, expiresAt: Date(timeIntervalSince1970: 1_800_000_000)))
        let data = try JSONEncoder().encode(state)
        XCTAssertEqual(try JSONDecoder().decode(LiveActivityStatus.self, from: data), state)
        let push = LiveActivityPush(deviceToken: startToken, environment: .production, bundleId: "com.viadere.app", event: .end, content: state, timestamp: 1, dismissalDate: 9)
        XCTAssertEqual(push.dismissalDate, 9)
        XCTAssertNil(push.staleDate)
    }
}
