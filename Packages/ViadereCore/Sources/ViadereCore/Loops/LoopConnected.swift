import Foundation

// MARK: - Connected mode (feature expansion v4 Phase 4, WP-4.1; plan section 4.5; SECURITY.md §2.115)
//
// A business that runs its own systems binds a published Loop to one of its webhook endpoints (an endpoint that proved ownership, uses the
// opaque v2 envelope and subscribes to the Loop events). Actions routed `connected` then reach the business as **opaque** events: ids
// only, never answers, amounts or customer data. The business fetches the event with its API key (scope `loops:read`) and answers with an
// outcome (scope `loops:write`, idempotent). Business-facing members are snake_case like the rest of the business API.

/// Webhook events of connected Loops. Opaque only (`WebhookEnvelopeV2`): a v1 subscription can never receive them.
public extension WebhookEventType {
    /// A customer submitted a delivering action of a connected Loop. `request_id` and `result_ref` are the event reference (`lev_…`):
    /// fetch `GET /v1/business/loops/events/{ref}`.
    static let loopActionSubmitted = WebhookEventType(rawValue: "loop.action.submitted")
    /// An instance of a connected Loop expired. `request_id` is the instance reference (`lin_…`): fetch `GET /v1/business/loops/instances/{ref}`.
    static let loopInstanceExpired = WebhookEventType(rawValue: "loop.instance.expired")

    /// The connected-Loop events (both opaque-only).
    static let loopEvents: [WebhookEventType] = [.loopActionSubmitted, .loopInstanceExpired]
}

/// Opaque references handed to a business: a fixed prefix and the lowercase UUID. The prefix keeps an event reference from being used
/// where an instance reference is expected (and the reverse); the server still checks the tenant of every lookup.
public enum LoopBusinessRef {
    public static let eventPrefix = "lev_"
    public static let instancePrefix = "lin_"

    public static func event(_ id: LoopActionEventID) -> String { eventPrefix + id.description }
    public static func instance(_ id: LoopInstanceID) -> String { instancePrefix + id.description }

    /// Strict parse: the prefix, then exactly a lowercase canonical UUID.
    public static func parseEvent(_ ref: String) -> LoopActionEventID? { parse(ref, prefix: eventPrefix).map(LoopActionEventID.init) }
    public static func parseInstance(_ ref: String) -> LoopInstanceID? { parse(ref, prefix: instancePrefix).map(LoopInstanceID.init) }

    static func parse(_ ref: String, prefix: String) -> UUID? {
        guard ref.hasPrefix(prefix) else { return nil }
        let rest = String(ref.dropFirst(prefix.count))
        guard rest.utf8.count == 36, rest == rest.lowercased(), let id = UUID(uuidString: rest), id.uuidString.lowercased() == rest else { return nil }
        return id
    }
}

/// The binding approval of an `approve_estimate` event, as the business reads it. The customer approved exactly this amount and these terms
/// with a device-bound biometric signature over Viadere's authorization context (§2.115 "Binding estimate approvals"). It never charges
/// anything and Viadere moves no money.
public struct LoopBusinessApproval: Codable, Sendable, Hashable {
    public var approvalId: String
    public var amount: MoneyAmount
    public var terms: String
    public var reference: String
    /// `Interaction.displayContextDigest()` of the authorization context the customer signed (lowercase hex).
    public var contextDigest: String
    /// `biometric` (device-bound user verification).
    public var assurance: DecisionAssurance
    public var approvedAt: Date

    public init(approvalId: String, amount: MoneyAmount, terms: String, reference: String, contextDigest: String, assurance: DecisionAssurance, approvedAt: Date) {
        self.approvalId = approvalId
        self.amount = amount
        self.terms = terms
        self.reference = reference
        self.contextDigest = contextDigest
        self.assurance = assurance
        self.approvedAt = approvedAt
    }

    enum CodingKeys: String, CodingKey {
        case approvalId = "approval_id", amount, terms, reference, contextDigest = "context_digest", assurance, approvedAt = "approved_at"
    }
}

/// One answer the customer gave, by field id (values as the customer submitted them: option ids, booleans, dates or short text).
/// `label` is the reviewed field label.
public struct LoopBusinessAnswer: Codable, Sendable, Hashable {
    public var stepId: String
    public var fieldId: String
    public var label: String
    public var value: JSONValue

    public init(stepId: String, fieldId: String, label: String, value: JSONValue) {
        self.stepId = stepId
        self.fieldId = fieldId
        self.label = label
        self.value = value
    }

    enum CodingKeys: String, CodingKey { case stepId = "step_id", fieldId = "field_id", label, value }
}

/// `GET /v1/business/loops/events/{eventRef}` (scope `loops:read`): a connected action event of this business. The customer is identified
/// only by the instance reference: no account id, `subject_ref`, name or device.
public struct LoopBusinessEvent: Codable, Sendable, Hashable {
    public var ref: String
    public var instanceRef: String
    /// The Loop key (`loop_definitions.key`) and the revision the instance is pinned to.
    public var loopKey: String
    public var revision: Int64
    public var stepId: String
    public var actionId: String
    public var actionType: String
    /// The routing queue the definition names (`routing.queue`), or `default`.
    public var queue: String
    /// The answers of every step of the instance up to this event, in step order.
    public var answers: [LoopBusinessAnswer]
    /// Present exactly for `approve_estimate`.
    public var approval: LoopBusinessApproval?
    public var outcome: LoopActionOutcome
    public var createdAt: Date
    public var respondBy: Date?

    public init(ref: String, instanceRef: String, loopKey: String, revision: Int64, stepId: String, actionId: String, actionType: String, queue: String,
                answers: [LoopBusinessAnswer], approval: LoopBusinessApproval?, outcome: LoopActionOutcome, createdAt: Date, respondBy: Date?) {
        self.ref = ref
        self.instanceRef = instanceRef
        self.loopKey = loopKey
        self.revision = revision
        self.stepId = stepId
        self.actionId = actionId
        self.actionType = actionType
        self.queue = queue
        self.answers = answers
        self.approval = approval
        self.outcome = outcome
        self.createdAt = createdAt
        self.respondBy = respondBy
    }

    enum CodingKeys: String, CodingKey {
        case ref, instanceRef = "instance_ref", loopKey = "loop_key", revision, stepId = "step_id", actionId = "action_id", actionType = "action_type",
             queue, answers, approval, outcome, createdAt = "created_at", respondBy = "respond_by"
    }
}

/// `GET /v1/business/loops/instances/{instanceRef}` (scope `loops:read`): the state of an instance that has at least one connected event.
public struct LoopBusinessInstance: Codable, Sendable, Hashable {
    public var ref: String
    public var loopKey: String
    public var revision: Int64
    public var state: LoopInstanceState
    public var expiresAt: Date
    /// References of the instance's connected events, oldest first.
    public var eventRefs: [String]

    public init(ref: String, loopKey: String, revision: Int64, state: LoopInstanceState, expiresAt: Date, eventRefs: [String]) {
        self.ref = ref
        self.loopKey = loopKey
        self.revision = revision
        self.state = state
        self.expiresAt = expiresAt
        self.eventRefs = eventRefs
    }

    enum CodingKeys: String, CodingKey { case ref, loopKey = "loop_key", revision, state, expiresAt = "expires_at", eventRefs = "event_refs" }
}

/// The answers a connected business may give. `pending` only confirms receipt after Viadere marked the event `unknown` (a late delivery).
public enum LoopConnectedOutcome: String, Codable, Sendable, CaseIterable, Hashable {
    case accepted, rejected, pending

    public var outcome: LoopActionOutcome {
        switch self {
        case .accepted: .accepted
        case .rejected: .rejected
        case .pending: .pending
        }
    }
}

/// `POST /v1/business/loops/events/{eventRef}/outcome` (scope `loops:write`). `idempotency_key` (`[A-Za-z0-9_.:-]`, 1 to 128) makes the
/// call safe to retry: the same key with the same outcome returns the stored answer; the same key with another outcome is `409`.
public struct LoopOutcomeCallbackRequest: Codable, Sendable, Hashable {
    public var outcome: LoopConnectedOutcome
    public var idempotencyKey: String

    public init(outcome: LoopConnectedOutcome, idempotencyKey: String) {
        self.outcome = outcome
        self.idempotencyKey = idempotencyKey
    }

    enum CodingKeys: String, CodingKey { case outcome, idempotencyKey = "idempotency_key" }

    /// Strict decoding: exactly the two members.
    public static func decodeStrict(_ data: Data) -> LoopOutcomeCallbackRequest? {
        guard let value = try? JSONDecoder().decode(JSONValue.self, from: data), case .object(let o) = value, Set(o.keys) == ["outcome", "idempotency_key"],
              let raw = o["outcome"]?.stringValue, let outcome = LoopConnectedOutcome(rawValue: raw), let key = o["idempotency_key"]?.stringValue,
              LoopActionSubmission.isValidIdempotencyKey(key) else { return nil }
        return LoopOutcomeCallbackRequest(outcome: outcome, idempotencyKey: key)
    }

    /// `"sha256:"` + hex SHA-256 of the canonical JSON `{"event_ref","outcome","v":1}`: what one idempotency key is bound to.
    public func digest(eventRef: String) throws -> String {
        try ContractHash.sha256(.object(["v": .integer(1), "event_ref": .string(eventRef), "outcome": .string(outcome.rawValue)]))
    }
}

public struct LoopOutcomeCallbackResult: Codable, Sendable, Hashable {
    public var ref: String
    /// The event's outcome after this call.
    public var outcome: LoopActionOutcome
    /// A repeated idempotency key: nothing new was recorded.
    public var replayed: Bool

    public init(ref: String, outcome: LoopActionOutcome, replayed: Bool) {
        self.ref = ref
        self.outcome = outcome
        self.replayed = replayed
    }
}

extension APIRoutes {
    /// A connected action event of the caller's business (scope `loops:read`). Another tenant's reference, a hosted event and a malformed
    /// reference are all `404`.
    public static let businessLoopEventGet = Endpoint<EmptyBody, LoopBusinessEvent>(
        "business.loops.events.get", .GET, "/v1/business/loops/events/{eventRef}", auth: .businessAPIKey)
    /// The business's answer to a connected event (scope `loops:write`). `409` for an outcome the state machine refuses (already final) or a
    /// reused key with another outcome; `422` for a malformed body.
    public static let businessLoopEventOutcome = Endpoint<LoopOutcomeCallbackRequest, LoopOutcomeCallbackResult>(
        "business.loops.events.outcome", .POST, "/v1/business/loops/events/{eventRef}/outcome", auth: .businessAPIKey)
    /// A connected instance of the caller's business (scope `loops:read`), e.g. after `loop.instance.expired`.
    public static let businessLoopInstanceGet = Endpoint<EmptyBody, LoopBusinessInstance>(
        "business.loops.instances.get", .GET, "/v1/business/loops/instances/{instanceRef}", auth: .businessAPIKey)

    /// Appended to `APIRoutes.all`.
    public static let loopConnectedEndpoints: [AnyEndpoint] = [
        businessLoopEventGet.descriptor, businessLoopEventOutcome.descriptor, businessLoopInstanceGet.descriptor,
    ]
}
