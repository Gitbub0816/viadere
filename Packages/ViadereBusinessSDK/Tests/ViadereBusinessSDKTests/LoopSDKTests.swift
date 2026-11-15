import Foundation
import Testing
import ViadereCore
@testable import ViadereBusinessSDK

@Suite("Connected Loops")
struct LoopSDKTests {
    @Test func eventFetchAndAnswerUseTheCatalogPathsAndAStrictBody() async throws {
        let transport = MockTransport()
        let client = try Fixtures.client(transport)
        let ref = LoopBusinessRef.event(LoopActionEventID())
        let event = LoopBusinessEvent(ref: ref, instanceRef: LoopBusinessRef.instance(LoopInstanceID()), loopKey: "pickup", revision: 1, stepId: "s2", actionId: "send",
                                      actionType: "acknowledge", queue: "pickups", answers: [LoopBusinessAnswer(stepId: "s1", fieldId: "slot", label: "Time", value: .string("am"))],
                                      approval: nil, outcome: .pending, createdAt: Fixtures.now, respondBy: nil)
        try transport.enqueue(status: 200, json: event)
        let fetched = try await client.loopEvent(ref: ref)
        #expect(fetched.answers.first?.value == .string("am"))
        #expect(transport.requests[0].method == "GET" && transport.requests[0].url.path == "/v1/business/loops/events/\(ref)")
        try transport.enqueue(status: 201, json: LoopOutcomeCallbackResult(ref: ref, outcome: .accepted, replayed: false))
        let answered = try await client.answerLoopEvent(ref: ref, outcome: .accepted, idempotencyKey: "ans-1")
        #expect(answered.outcome == .accepted && !answered.replayed)
        #expect(transport.requests[1].method == "POST" && transport.requests[1].url.path == "/v1/business/loops/events/\(ref)/outcome")
        // The server accepts exactly these two members.
        let body = try #require(transport.requests[1].body)
        #expect(LoopOutcomeCallbackRequest.decodeStrict(body) == LoopOutcomeCallbackRequest(outcome: .accepted, idempotencyKey: "ans-1"))
        let instanceRef = LoopBusinessRef.instance(LoopInstanceID())
        try transport.enqueue(status: 200, json: LoopBusinessInstance(ref: instanceRef, loopKey: "pickup", revision: 1, state: .expired, expiresAt: Fixtures.now, eventRefs: [ref]))
        #expect(try await client.loopInstance(ref: instanceRef).state == .expired)
        #expect(transport.requests[2].url.path == "/v1/business/loops/instances/\(instanceRef)")
    }

    @Test func connectedLoopEventsArriveOnlyAsOpaqueEnvelopes() {
        for event in WebhookEventType.loopEvents { #expect(WebhookEventType.opaqueEvents.contains(event)) }
    }
}
