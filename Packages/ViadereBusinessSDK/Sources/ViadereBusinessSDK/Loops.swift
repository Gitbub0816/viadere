import Foundation
import ViadereCore

/// Connected Loops (feature expansion v4 Phase 4, WP-4.1; SECURITY.md §2.115). A Loop button routed to your own system reaches you as an
/// opaque `loop.action.submitted` webhook (ids only; `result_ref` is the event reference `lev_…`) on the endpoint you bound to that Loop in the
/// console. Fetch the request with a key holding `loops:read`, then answer it with a key holding `loops:write`. Customers are identified
/// only by the instance reference: there is no account id, `subject_ref` or name.
///
/// Until you answer, the customer sees "Sent to {you}. Waiting for them to confirm." If your endpoint is paused, unbound or the delivery
/// dead-letters, they see "We couldn't confirm that {you} received this." (`unknown`); answering later still works (`pending` confirms receipt,
/// `accepted` and `rejected` are final).
extension ViadereBusinessClient {
    /// `GET /v1/business/loops/events/{eventRef}`: the answers, the binding estimate approval (for `approve_estimate`) and the current outcome.
    public func loopEvent(ref: String) async throws -> LoopBusinessEvent {
        try decode(LoopBusinessEvent.self, try await perform(APIRoutes.businessLoopEventGet.descriptor, parameters: ["eventRef": ref]))
    }

    /// `POST /v1/business/loops/events/{eventRef}/outcome`. Safe to retry with the same `idempotencyKey`: the stored answer comes back with
    /// `replayed: true` (the key travels in the body, so the client retries it). The same key with another outcome, or a change after a
    /// final outcome, is `409`.
    public func answerLoopEvent(ref: String, outcome: LoopConnectedOutcome, idempotencyKey: String = IdempotencyKey.generate(prefix: "loop")) async throws -> LoopOutcomeCallbackResult {
        try decode(LoopOutcomeCallbackResult.self, try await perform(APIRoutes.businessLoopEventOutcome.descriptor, parameters: ["eventRef": ref],
                                                                     body: LoopOutcomeCallbackRequest(outcome: outcome, idempotencyKey: idempotencyKey),
                                                                     naturallyIdempotent: true))
    }

    /// `GET /v1/business/loops/instances/{instanceRef}` (after `loop.instance.expired`, whose `request_id` is the instance reference `lin_…`).
    public func loopInstance(ref: String) async throws -> LoopBusinessInstance {
        try decode(LoopBusinessInstance.self, try await perform(APIRoutes.businessLoopInstanceGet.descriptor, parameters: ["instanceRef": ref]))
    }
}
