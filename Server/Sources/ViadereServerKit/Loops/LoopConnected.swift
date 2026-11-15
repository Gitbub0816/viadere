import Fluent
import FluentSQL
import Foundation
import SQLKit
import ViadereCore

// MARK: - Models (migration `LoopsPhase4.v1`; SECURITY.md §2.115)

/// The one webhook endpoint a published Loop delivers its connected actions to (WP-4.1 "console endpoint binding per Loop"). At most one per
/// Loop (`definition_id` unique, across revisions); always the same tenant as the Loop. Set from the console with a fresh passkey.
final class LoopEndpointBindingRecord: Model, @unchecked Sendable {
    static let schema = "loop_endpoint_bindings"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "definition_id") var definitionId: UUID
    @Field(key: "subscription_id") var subscriptionId: UUID
    @Field(key: "bound_by") var boundBy: UUID
    @Field(key: "bound_at") var boundAt: Date
    init() {}
}

/// Marks an action event as routed `connected` (written in the action's own transaction). Only events with this row can be fetched or
/// answered through the business API; hosted events never can. `subscription_id` is set once the opaque event was queued to it.
final class LoopConnectedEventRecord: Model, @unchecked Sendable {
    static let schema = "loop_connected_events"
    @ID(key: .id) var id: UUID?
    @Field(key: "event_id") var eventId: UUID
    @Field(key: "instance_id") var instanceId: UUID
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "definition_id") var definitionId: UUID
    @OptionalField(key: "subscription_id") var subscriptionId: UUID?
    @Field(key: "created_at") var createdAt: Date
    init() {}
}

/// One single-use approval challenge of an `approve_estimate` action (WP-4.4). Amount, terms and reference are copied from the reviewed
/// definition when the challenge is issued and compared again when it is used; `consumed_at` moves from NULL exactly once (compare-and-swap)
/// and names the event it produced. The signed decision itself is not kept (it names the device); its context digest and assurance are.
final class LoopApprovalRecord: Model, @unchecked Sendable {
    static let schema = "loop_approvals"
    @ID(key: .id) var id: UUID?
    @Field(key: "instance_id") var instanceId: UUID
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "step_id") var stepId: String
    @Field(key: "action_id") var actionId: String
    @Field(key: "amount_value") var amountValue: String
    @Field(key: "currency") var currency: String
    @Field(key: "terms") var terms: String
    @Field(key: "reference") var reference: String
    @Field(key: "business_name") var businessName: String
    @Field(key: "challenge") var challenge: String
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "consumed_at") var consumedAt: Date?
    @OptionalField(key: "event_id") var eventId: UUID?
    @OptionalField(key: "context_digest") var contextDigest: String?
    @OptionalField(key: "assurance") var assurance: String?
    init() {}

    var estimateTerms: LoopEstimateTerms? {
        guard let code = CurrencyCode(currency), let amount = try? MoneyAmount(string: amountValue, currency: code) else { return nil }
        return LoopEstimateTerms(amount: amount, terms: terms, reference: reference)
    }

    func interaction(relationshipId: UUID?) -> Interaction? {
        guard let id, let terms = estimateTerms, let nonce = ChallengeNonce(challenge) else { return nil }
        return LoopEstimateApproval.interaction(approvalId: InteractionID(id), consumerId: ConsumerID(consumerId),
                                                relationshipId: relationshipId.flatMap { $0 == LoopInstanceRecord.noRelationship ? nil : RelationshipID($0) },
                                                businessId: BusinessID(businessId), businessName: businessName, terms: terms, challenge: nonce,
                                                createdAt: createdAt, expiresAt: expiresAt)
    }
}

/// An answered outcome callback (idempotency per business and key, bound to the event and outcome by `request_digest`).
final class LoopOutcomeCallbackRecord: Model, @unchecked Sendable {
    static let schema = "loop_outcome_callbacks"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "event_id") var eventId: UUID
    @Field(key: "idempotency_key") var idempotencyKey: String
    @Field(key: "request_digest") var requestDigest: String
    @Field(key: "outcome") var outcome: String
    @Field(key: "created_at") var createdAt: Date
    init() {}
}

/// `LoopsPhase4.v1` (additive, forward-only): endpoint bindings, connected-event markers, estimate approvals and outcome callbacks.
struct CreateLoopsPhase4Schema: AsyncMigration {
    var name: String { "LoopsPhase4.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema(LoopEndpointBindingRecord.schema).id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("definition_id", .uuid, .required, .references(LoopDefinitionRecord.schema, "id"))
            .field("subscription_id", .uuid, .required, .references("webhook_subscriptions", "id"))
            .field("bound_by", .uuid, .required)
            .field("bound_at", .datetime, .required)
            .unique(on: "definition_id").create()
        try await db.schema(LoopConnectedEventRecord.schema).id()
            .field("event_id", .uuid, .required, .references(LoopActionEventRecord.schema, "id"))
            .field("instance_id", .uuid, .required, .references(LoopInstanceRecord.schema, "id"))
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("definition_id", .uuid, .required)
            .field("subscription_id", .uuid)
            .field("created_at", .datetime, .required)
            .unique(on: "event_id").create()
        try await db.schema(LoopApprovalRecord.schema).id()
            .field("instance_id", .uuid, .required, .references(LoopInstanceRecord.schema, "id"))
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("consumer_id", .uuid, .required)
            .field("step_id", .string, .required)
            .field("action_id", .string, .required)
            .field("amount_value", .string, .required)
            .field("currency", .string, .required)
            .field("terms", .string, .required)
            .field("reference", .string, .required)
            .field("business_name", .string, .required)
            .field("challenge", .string, .required)
            .field("created_at", .datetime, .required)
            .field("expires_at", .datetime, .required)
            .field("consumed_at", .datetime)
            .field("event_id", .uuid)
            .field("context_digest", .string)
            .field("assurance", .string)
            .unique(on: "challenge").create()
        try await db.schema(LoopOutcomeCallbackRecord.schema).id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("event_id", .uuid, .required, .references(LoopActionEventRecord.schema, "id"))
            .field("idempotency_key", .string, .required)
            .field("request_digest", .string, .required)
            .field("outcome", .string, .required)
            .field("created_at", .datetime, .required)
            .unique(on: "business_id", "idempotency_key").create()
        guard let sql = db as? any SQLDatabase else { return }
        // Compile-time constant statements.
        try await sql.raw("CREATE INDEX IF NOT EXISTS idx_loop_connected_instance ON loop_connected_events (instance_id)").run()
        try await sql.raw("CREATE INDEX IF NOT EXISTS idx_loop_approvals_instance ON loop_approvals (instance_id, step_id, action_id)").run()
        try await sql.raw("CREATE INDEX IF NOT EXISTS idx_loop_approvals_event ON loop_approvals (event_id)").run()
    }

    func revert(on db: any Database) async throws {
        try await db.schema(LoopOutcomeCallbackRecord.schema).delete()
        try await db.schema(LoopApprovalRecord.schema).delete()
        try await db.schema(LoopConnectedEventRecord.schema).delete()
        try await db.schema(LoopEndpointBindingRecord.schema).delete()
    }
}

// MARK: - Connected mode (WP-4.1)

/// Connected Loops: the per-Loop endpoint binding, the opaque `loop.*` events, the business's event fetch and outcome callbacks.
///
/// * Deliveries go only to the Loop's bound endpoint, through the ordinary webhook path (signature, delivery id, key id, retries, DNS
///   pinning to public addresses, pause) as the opaque v2 envelope: ids only.
/// * Delivery to the business is never assumed: an unbound or ineligible endpoint, a paused endpoint and a dead-lettered delivery all mark
///   the event `unknown` ("We couldn't confirm that {Business} received this."), never `accepted`. A late answer is still taken.
/// * The business reads and answers only its own connected events (another tenant's reference, a hosted event, a test key: `404`).
struct LoopConnectedService {
    let db: any Database
    let ctx: ServerContext

    static let reasonUnbound = "endpoint_unbound"
    static let reasonPaused = "endpoint_paused"
    static let reasonDead = "delivery_dead_lettered"

    // MARK: Binding

    /// Why an endpoint cannot carry a Loop's events, or `nil` when it can: same tenant, active, the opaque v2 envelope, subscribed to
    /// `loop.action.submitted`, and its ownership proven (§2.73; in staging and production the proof cannot be switched off).
    static func ineligibility(_ subscription: WebhookSubscriptionRecord, businessId: UUID, ctx: ServerContext) -> String? {
        guard subscription.businessId == businessId, subscription.active else { return "not_found" }
        guard subscription.envelopeVersion == WebhookEnvelopeV2.version else { return "envelope_v2_required" }
        let events = subscription.events.split(separator: ",").map(String.init)
        guard events.contains(WebhookEventType.loopActionSubmitted.rawValue) else { return "not_subscribed" }
        if ctx.config.operations.webhookOwnershipVerification, subscription.verifiedAt == nil { return "ownership_unproven" }
        return nil
    }

    func binding(definitionId: UUID) async throws -> LoopEndpointBindingRecord? {
        try await LoopEndpointBindingRecord.query(on: db).filter(\.$definitionId == definitionId).first()
    }

    /// Binds a published Loop of the business to one of its own eligible endpoints (replacing an earlier binding). Callers check the console
    /// permissions and the fresh passkey; this re-checks the tenant of both the Loop and the endpoint.
    func bind(businessId: UUID, definitionId: UUID, subscriptionId: UUID, by userId: UUID) async throws {
        guard ctx.config.loops.connectedEnabled else { throw APIError.notFound }
        guard try await LoopDefinitionRecord.query(on: db).filter(\.$id == definitionId).filter(\.$businessId == businessId).first() != nil else { throw APIError.notFound }
        guard let subscription = try await WebhookSubscriptionRecord.query(on: db).filter(\.$id == subscriptionId).filter(\.$businessId == businessId).first() else {
            throw APIError.notFound
        }
        if let reason = Self.ineligibility(subscription, businessId: businessId, ctx: ctx) {
            _ = try? await AuditService(db: db, ctx: ctx).record("loop.endpoint_bind_refused", outcome: .denied, actor: LoopPublicationService.businessActor(userId),
                businessId: BusinessID(businessId), subjectType: "loop_definition", subjectId: definitionId.uuidString.lowercased(), metadata: ["reason": reason])
            throw APIError.validation(Self.message(reason), details: ["endpoint": reason])
        }
        let ctx = self.ctx
        try await db.transaction { tx in
            try await LoopEndpointBindingRecord.query(on: tx).filter(\.$definitionId == definitionId).delete()
            let row = LoopEndpointBindingRecord()
            row.id = UUID()
            row.businessId = businessId
            row.definitionId = definitionId
            row.subscriptionId = subscriptionId
            row.boundBy = userId
            row.boundAt = ctx.now
            try await row.create(on: tx)
            _ = try await AuditService(db: tx, ctx: ctx).record("loop.endpoint_bound", actor: LoopPublicationService.businessActor(userId), businessId: BusinessID(businessId),
                subjectType: "loop_definition", subjectId: definitionId.uuidString.lowercased(), metadata: ["webhook_id": subscriptionId.uuidString.lowercased()])
        }
    }

    func unbind(businessId: UUID, definitionId: UUID, by userId: UUID) async throws {
        guard try await LoopEndpointBindingRecord.query(on: db).filter(\.$definitionId == definitionId).filter(\.$businessId == businessId).first() != nil else { return }
        try await LoopEndpointBindingRecord.query(on: db).filter(\.$definitionId == definitionId).filter(\.$businessId == businessId).delete()
        _ = try await AuditService(db: db, ctx: ctx).record("loop.endpoint_unbound", actor: LoopPublicationService.businessActor(userId), businessId: BusinessID(businessId),
            subjectType: "loop_definition", subjectId: definitionId.uuidString.lowercased())
    }

    static func message(_ reason: String) -> String {
        switch reason {
        case "envelope_v2_required": "Choose an endpoint that uses the opaque envelope (envelope version 2026-10-27)."
        case "not_subscribed": "Choose an endpoint subscribed to loop.action.submitted."
        case "ownership_unproven": "Verify the endpoint first: it must prove it controls its URL."
        default: "Choose one of your endpoints."
        }
    }

    // MARK: Delivery (queue `loop-delivery`)

    /// Queues the opaque `loop.action.submitted` event to the Loop's bound endpoint, inside the queue consumer's transaction. Returns the
    /// reason the event must be marked `unknown`, or `nil` when the event went out on an endpoint that is not paused.
    func deliver(_ event: LoopActionEventRecord, marker: LoopConnectedEventRecord) async throws -> String? {
        guard marker.subscriptionId == nil else { return nil }
        guard ctx.config.loops.connectedEnabled, let binding = try await binding(definitionId: marker.definitionId), binding.businessId == event.businessId,
              let subscription = try await WebhookSubscriptionRecord.find(binding.subscriptionId, on: db),
              Self.ineligibility(subscription, businessId: event.businessId, ctx: ctx) == nil else { return Self.reasonUnbound }
        let ref = LoopBusinessRef.event(LoopActionEventID(event.id!))
        try await WebhookService(db: db, ctx: ctx).enqueue(.loopActionSubmitted, businessId: BusinessID(event.businessId), payload: EmptyBody(),
                                                         onlySubscription: subscription.id, opaque: OpaqueWebhookEvent(requestId: ref, resultRef: ref))
        marker.subscriptionId = subscription.id
        try await marker.update(on: db)
        // A paused endpoint keeps the delivery queued (it goes out after a resume), but nothing tells the customer it arrived.
        let pauses = try await PlatformFlagRecord.query(on: db).filter(\.$flag == PlatformFlag.webhooksPause.rawValue).all()
        let paused = subscription.pausedAt != nil || pauses.contains { $0.scope == PlatformFlags.globalScope || UUID(uuidString: $0.scope) == event.businessId }
        return paused ? Self.reasonPaused : nil
    }

    /// `loop.instance.expired` to the bound endpoint, for an instance that has at least one connected event.
    func instanceExpired(_ instance: LoopInstanceRecord) async throws {
        guard ctx.config.loops.connectedEnabled, let id = instance.id,
              let marker = try await LoopConnectedEventRecord.query(on: db).filter(\.$instanceId == id).first(),
              let binding = try await binding(definitionId: marker.definitionId), binding.businessId == instance.businessId,
              let subscription = try await WebhookSubscriptionRecord.find(binding.subscriptionId, on: db),
              Self.ineligibility(subscription, businessId: instance.businessId, ctx: ctx) == nil,
              subscription.events.split(separator: ",").contains(Substring(WebhookEventType.loopInstanceExpired.rawValue)) else { return }
        let ref = LoopBusinessRef.instance(LoopInstanceID(id))
        try await WebhookService(db: db, ctx: ctx).enqueue(.loopInstanceExpired, businessId: BusinessID(instance.businessId), payload: EmptyBody(),
                                                         onlySubscription: subscription.id, opaque: OpaqueWebhookEvent(requestId: ref, resultRef: ref))
    }

    /// A Loop delivery that reached the dead-letter state (retries exhausted, blocked destination, endpoint removed): the event's outcome
    /// becomes `unknown` (only from `pending`; a business answer that already arrived stands).
    func deliveryDead(_ delivery: WebhookDeliveryRecord) async {
        guard delivery.eventType == WebhookEventType.loopActionSubmitted.rawValue else { return }
        await markUnknown(delivery, reason: Self.reasonDead)
    }

    /// An endpoint was paused: every Loop event still queued to it becomes `unknown` for the customer.
    func endpointPaused(subscriptionId: UUID) async throws {
        let queued = try await WebhookDeliveryRecord.query(on: db).filter(\.$subscriptionId == subscriptionId)
            .filter(\.$eventType == WebhookEventType.loopActionSubmitted.rawValue).filter(\.$status ~~ ["pending", "sending"]).all()
        for delivery in queued { await markUnknown(delivery, reason: Self.reasonPaused) }
    }

    private func markUnknown(_ delivery: WebhookDeliveryRecord, reason: String) async {
        guard let body = WebhookService(db: db, ctx: ctx).storedBody(delivery), let envelope = try? ViadereJSON.decode(WebhookEnvelopeV2.self, from: body),
              let ref = envelope.resultRef, let eventId = LoopBusinessRef.parseEvent(ref) else { return }
        _ = try? await LoopRuntimeService(db: db, ctx: ctx).recordOutcome(eventId: eventId.uuid, businessId: delivery.businessId, outcome: .unknown,
                                                                         source: .system, actor: nil, reason: reason)
    }

    // MARK: Business API

    /// The business's own connected event; anything else (another tenant, a hosted event, a test key, Phase 4 off) is `404`.
    func ownEvent(principal: BusinessPrincipal, ref: String) async throws -> (LoopActionEventRecord, LoopConnectedEventRecord) {
        guard ctx.config.loops.connectedEnabled, principal.livemode, let id = LoopBusinessRef.parseEvent(ref),
              let marker = try await LoopConnectedEventRecord.query(on: db).filter(\.$eventId == id.uuid).filter(\.$businessId == principal.businessId.uuid).first(),
              let event = try await LoopActionEventRecord.query(on: db).filter(\.$id == id.uuid).filter(\.$businessId == principal.businessId.uuid).first() else {
            await refuseBusiness(principal, ref: ref, reason: "not_found")
            throw APIError.notFound
        }
        return (event, marker)
    }

    func event(principal: BusinessPrincipal, ref: String) async throws -> LoopBusinessEvent {
        let (event, _) = try await ownEvent(principal: principal, ref: ref)
        guard let instance = try await LoopInstanceRecord.find(event.instanceId, on: db), let revision = try await LoopRevisionRecord.find(instance.revisionId, on: db),
              let definitionRow = try await LoopDefinitionRecord.find(revision.definitionId, on: db) else { throw APIError.notFound }
        let definition = LoopDefinition.parse(Data(revision.definitionJSON.utf8)).definition
        let runtime = LoopRuntimeService(db: db, ctx: ctx)
        // Answers of the instance's events up to and including this one, with the reviewed labels. No customer identity of any kind.
        let events = try await LoopActionEventRecord.query(on: db).filter(\.$instanceId == event.instanceId).sort(\.$createdAt, .ascending).all()
            .filter { $0.createdAt <= event.createdAt }
        var answers: [LoopBusinessAnswer] = []
        for e in events {
            let inputs = runtime.inputs(of: e)
            for field in definition?.step(e.stepId)?.fields ?? [] {
                guard let value = inputs[field.id] else { continue }
                answers.append(LoopBusinessAnswer(stepId: e.stepId, fieldId: field.id, label: DisplayTextSanitizer.sanitize(field.label, maxCharacters: LoopLimits.fieldLabelLength), value: value))
            }
        }
        var approval: LoopBusinessApproval?
        if let row = try await LoopApprovalRecord.query(on: db).filter(\.$eventId == event.id!).filter(\.$businessId == event.businessId).first(),
           let terms = row.estimateTerms, let consumed = row.consumedAt, let digest = row.contextDigest,
           let assurance = row.assurance.flatMap(DecisionAssurance.init(rawValue:)) {
            approval = LoopBusinessApproval(approvalId: row.id!.uuidString.lowercased(), amount: terms.amount, terms: terms.terms, reference: terms.reference,
                                            contextDigest: digest, assurance: assurance, approvedAt: consumed)
        }
        let queue = definition?.step(event.stepId)?.actions.first { $0.id == event.actionId }?.routing?.queue ?? LoopPublicationService.defaultQueue
        let outcome = try await runtime.currentOutcome(eventId: event.id!)?.outcomeValue ?? .pending
        _ = try? await AuditService(db: db, ctx: ctx).record("loop.connected_event_read", actor: principal.auditActor, businessId: principal.businessId,
            subjectType: "loop_action_event", subjectId: event.id!.uuidString.lowercased())
        return LoopBusinessEvent(ref: LoopBusinessRef.event(LoopActionEventID(event.id!)), instanceRef: LoopBusinessRef.instance(LoopInstanceID(event.instanceId)),
                                 loopKey: definitionRow.key, revision: Int64(revision.revision), stepId: event.stepId, actionId: event.actionId,
                                 actionType: event.actionType, queue: queue, answers: answers, approval: approval, outcome: outcome,
                                 createdAt: event.createdAt, respondBy: event.responseDueAt)
    }

    func instance(principal: BusinessPrincipal, ref: String) async throws -> LoopBusinessInstance {
        guard ctx.config.loops.connectedEnabled, principal.livemode, let id = LoopBusinessRef.parseInstance(ref),
              let instance = try await LoopInstanceRecord.query(on: db).filter(\.$id == id.uuid).filter(\.$businessId == principal.businessId.uuid).first() else {
            await refuseBusiness(principal, ref: ref, reason: "not_found")
            throw APIError.notFound
        }
        let markers = try await LoopConnectedEventRecord.query(on: db).filter(\.$instanceId == id.uuid).filter(\.$businessId == principal.businessId.uuid)
            .sort(\.$createdAt, .ascending).all()
        guard !markers.isEmpty, let revision = try await LoopRevisionRecord.find(instance.revisionId, on: db),
              let definitionRow = try await LoopDefinitionRecord.find(revision.definitionId, on: db) else {
            await refuseBusiness(principal, ref: ref, reason: "not_found")
            throw APIError.notFound
        }
        try await LoopRuntimeService(db: db, ctx: ctx).expireIfDue(instance)
        let state = try await LoopInstanceRecord.find(id.uuid, on: db)?.stateValue ?? instance.stateValue
        return LoopBusinessInstance(ref: ref, loopKey: definitionRow.key, revision: Int64(revision.revision), state: state, expiresAt: instance.expiresAt,
                                    eventRefs: markers.map { LoopBusinessRef.event(LoopActionEventID($0.eventId)) })
    }

    /// `POST /v1/business/loops/events/{ref}/outcome`: idempotent per (business, key); the outcome machine decides what is legal.
    func answer(principal: BusinessPrincipal, ref: String, body: Data) async throws -> (LoopOutcomeCallbackResult, created: Bool) {
        guard await ctx.limiter.allow("loop-callback", key: principal.businessId.description, rule: ctx.config.loops.callbackRate) else {
            throw APIError.rateLimited(retryAfter: 30)
        }
        let (event, _) = try await ownEvent(principal: principal, ref: ref)
        guard let request = LoopOutcomeCallbackRequest.decodeStrict(body) else {
            await refuseBusiness(principal, ref: ref, reason: "invalid_body")
            throw APIError.validation("Send exactly outcome (accepted, rejected or pending) and idempotency_key.", details: ["reason": "invalid_body"])
        }
        let digest = try request.digest(eventRef: ref)
        let runtime = LoopRuntimeService(db: db, ctx: ctx)
        func replay(_ stored: LoopOutcomeCallbackRecord) async throws -> (LoopOutcomeCallbackResult, created: Bool) {
            guard stored.eventId == event.id, ConstantTime.equals(stored.requestDigest, digest) else {
                await refuseBusiness(principal, ref: ref, reason: "idempotency_conflict")
                throw APIError(.conflict, .conflict, "This idempotency key was used for a different answer.", details: ["reason": "idempotency_conflict"])
            }
            let current = try await runtime.currentOutcome(eventId: event.id!)?.outcomeValue ?? .pending
            return (LoopOutcomeCallbackResult(ref: ref, outcome: current, replayed: true), false)
        }
        if let stored = try await LoopOutcomeCallbackRecord.query(on: db).filter(\.$businessId == principal.businessId.uuid)
            .filter(\.$idempotencyKey == request.idempotencyKey).first() {
            return try await replay(stored)
        }
        // Claim the key first (a concurrent call with the same key loses on the unique constraint and replays).
        let row = LoopOutcomeCallbackRecord()
        row.id = UUID()
        row.businessId = principal.businessId.uuid
        row.eventId = event.id!
        row.idempotencyKey = request.idempotencyKey
        row.requestDigest = digest
        row.outcome = request.outcome.rawValue
        row.createdAt = ctx.now
        do { try await row.create(on: db) } catch let error where error.isConstraintViolation {
            guard let stored = try await LoopOutcomeCallbackRecord.query(on: db).filter(\.$businessId == principal.businessId.uuid)
                .filter(\.$idempotencyKey == request.idempotencyKey).first() else { throw error }
            return try await replay(stored)
        }
        guard try await runtime.recordOutcome(eventId: event.id!, businessId: event.businessId, outcome: request.outcome.outcome, source: .webhook,
                                              actor: nil, reason: "connected_callback") else {
            try await row.delete(on: db)
            await refuseBusiness(principal, ref: ref, reason: "outcome_refused")
            let current = try await runtime.currentOutcome(eventId: event.id!)?.outcomeValue
            throw APIError(.conflict, .conflict, "This answer isn't possible now.", details: ["reason": "outcome_refused", "outcome": current?.rawValue ?? "none"])
        }
        _ = try? await AuditService(db: db, ctx: ctx).record("loop.connected_outcome", actor: principal.auditActor, businessId: principal.businessId,
            subjectType: "loop_action_event", subjectId: event.id!.uuidString.lowercased(), metadata: ["outcome": request.outcome.rawValue])
        return (LoopOutcomeCallbackResult(ref: ref, outcome: request.outcome.outcome, replayed: false), true)
    }

    private func refuseBusiness(_ principal: BusinessPrincipal, ref: String, reason: String) async {
        ctx.metrics.count(.loopActionRefused)
        _ = try? await AuditService(db: db, ctx: ctx).record("loop.connected_refused", outcome: .denied, actor: principal.auditActor, businessId: principal.businessId,
            subjectType: "loop_connected", subjectId: String(ref.prefix(48)), metadata: ["reason": reason])
    }
}

// MARK: - Binding estimate approvals (WP-4.4)

/// Issues and verifies the single-use approvals of `approve_estimate`, with the interaction decision machinery (`DecisionVerifier`,
/// `AssurancePolicy`, `ReplayGuard`, context digest) over an `authorize` context the server rebuilds from its own row.
struct LoopApprovalService {
    let db: any Database
    let ctx: ServerContext

    struct Refusal: Error { let reason: String }

    /// The binding of `actionId` on `stepId` if it is an available `approve_estimate` with complete terms.
    static func approvalBinding(_ definition: LoopDefinition, stepId: String, actionId: String, phase: LoopPlatformPhase) -> (LoopActionBinding, LoopEstimateTerms)? {
        guard let binding = definition.step(stepId)?.actions.first(where: { $0.id == actionId }), binding.action == LoopEstimateApproval.actionType,
              case .registered(let action) = LoopActionRegistry.v1.resolve(binding.action), action.bindsApproval, action.isAvailable(in: phase),
              let terms = LoopEstimateTerms(binding) else { return nil }
        return (binding, terms)
    }

    func start(principal: ConsumerPrincipal, instanceId: UUID, request: LoopApprovalStartRequest) async throws -> LoopApprovalChallenge {
        let consumer = principal.consumerId.uuid
        let runtime = LoopRuntimeService(db: db, ctx: ctx)
        guard let instance = try await LoopInstanceRecord.query(on: db).filter(\.$id == instanceId).filter(\.$consumerId == consumer).first(),
              let publication = try await LoopPublicationRecord.find(instance.publicationId, on: db), publication.businessId == instance.businessId else {
            throw await runtime.refuse("not_found", principal: principal, business: nil, subject: instanceId, operation: "approval")
        }
        guard await ctx.limiter.allow("loop-approval", key: consumer.uuidString.lowercased(), rule: ctx.config.loops.approvalRate) else {
            throw APIError.rateLimited(retryAfter: 30)
        }
        let facts = try await runtime.access(.act, consumer: consumer, publication: publication, instance: instance)
        if case .denied(let denial) = facts.decision {
            throw await runtime.refuse(denial.rawValue, principal: principal, business: instance.businessId, subject: instanceId, operation: "approval")
        }
        guard instance.stateValue == .active else {
            throw await runtime.refuse("instance_closed", principal: principal, business: instance.businessId, subject: instanceId, operation: "approval")
        }
        guard request.stepId == instance.currentStepId else {
            throw await runtime.refuse("step_mismatch", principal: principal, business: instance.businessId, subject: instanceId, operation: "approval")
        }
        guard let revision = try await LoopRevisionRecord.find(instance.revisionId, on: db),
              let definition = LoopDefinition.parse(Data(revision.definitionJSON.utf8)).definition,
              let (_, terms) = Self.approvalBinding(definition, stepId: request.stepId, actionId: request.actionId, phase: ctx.config.loops.platformPhase) else {
            throw await runtime.refuse("invalid_action", principal: principal, business: instance.businessId, subject: instanceId, operation: "approval")
        }
        guard let business = try await DirectoryService(db: db).verified(id: instance.businessId),
              let name = LoopEstimateApproval.merchantName(business.displayName) else {
            throw await runtime.refuse("not_found", principal: principal, business: instance.businessId, subject: instanceId, operation: "approval")
        }
        let now = ViadereDate.truncatedToMilliseconds(ctx.now)
        let row = LoopApprovalRecord()
        row.id = UUID()
        row.instanceId = instanceId
        row.businessId = instance.businessId
        row.consumerId = consumer
        row.stepId = request.stepId
        row.actionId = request.actionId
        row.amountValue = terms.amount.decimalString
        row.currency = terms.amount.currency.value
        row.terms = terms.terms
        row.reference = terms.reference
        row.businessName = name
        row.challenge = ChallengeNonce.generate().value
        row.createdAt = now
        row.expiresAt = ViadereDate.truncatedToMilliseconds(min(now.addingTimeInterval(LoopEstimateApproval.lifetime), instance.expiresAt))
        try await row.create(on: db)
        guard let interaction = row.interaction(relationshipId: instance.relationshipId) else { throw APIError.internalError }
        _ = try await AuditService(db: db, ctx: ctx).record("loop.approval_issued", principal: principal, businessId: BusinessID(instance.businessId),
            subjectType: "loop_approval", subjectId: row.id!.uuidString.lowercased(), metadata: ["instance_id": instanceId.uuidString.lowercased(), "step_id": request.stepId])
        return LoopApprovalChallenge(approvalId: row.id!.uuidString.lowercased(), instanceId: LoopInstanceID(instanceId), stepId: request.stepId,
                                     actionId: request.actionId, interaction: interaction, expiresAt: row.expiresAt)
    }

    /// Verifies the approval carried by an `approve_estimate` action and returns the row to consume plus what was signed. Every failure is a
    /// `Refusal` with a reason code; nothing is consumed here except the decision's challenge in the replay guard (single use: a refused
    /// attempt after that point needs a new challenge).
    func verify(principal: ConsumerPrincipal, instance: LoopInstanceRecord, stepId: String, binding: LoopActionBinding,
                approval: LoopActionApproval?) async throws -> (LoopApprovalRecord, DecisionPayload) {
        guard let approval else { throw Refusal(reason: "approval_required") }
        guard let approvalId = UUID(uuidString: approval.approvalId), approvalId.uuidString.lowercased() == approval.approvalId,
              let row = try await LoopApprovalRecord.query(on: db).filter(\.$id == approvalId).filter(\.$instanceId == instance.id!)
                  .filter(\.$consumerId == principal.consumerId.uuid).filter(\.$businessId == instance.businessId).first(),
              row.stepId == stepId, row.actionId == binding.id, row.consumedAt == nil else { throw Refusal(reason: "approval_invalid") }
        // The terms the customer saw are still the reviewed terms of the pinned revision.
        guard let terms = LoopEstimateTerms(binding), let stored = row.estimateTerms, stored == terms else { throw Refusal(reason: "approval_invalid") }
        guard let interaction = row.interaction(relationshipId: instance.relationshipId) else { throw Refusal(reason: "approval_invalid") }
        guard let deviceId = principal.deviceId, let device = try await DeviceRecord.find(deviceId.uuid, on: db), device.consumerId == principal.consumerId.uuid,
              device.kind == .app else { throw Refusal(reason: "approval_invalid") }
        // High-risk approvals need a D1 device (§2.5a), exactly as for interactions.
        guard DeviceTrust.isTrusted(device, at: ctx.now) else { throw Refusal(reason: "device_not_trusted") }
        let verifier = DecisionVerifier()
        guard let claimed = try? verifier.decodeUnverified(approval.signedDecision), claimed.deviceId == deviceId, claimed.decision == .approve,
              let keyRecord = try await DeviceKeyRecord.query(on: db).filter(\.$deviceId == deviceId.uuid)
                  .filter(\.$purpose == DeviceKeyPurpose.required(for: claimed.assurance).rawValue).first(),
              let publicKey = try? DevicePublicKey(base64URL: keyRecord.publicKey) else { throw Refusal(reason: "approval_invalid") }
        do {
            let payload = try await verifier.verify(approval.signedDecision, for: interaction, deviceId: deviceId, publicKey: publicKey, channel: .inApp,
                                                    now: ctx.now, replayGuard: DatabaseReplayGuard(db: db))
            return (row, payload)
        } catch let error as DecisionVerificationError {
            throw Refusal(reason: error == .insufficientAssurance ? "approval_insufficient_assurance" : (error == .expired ? "approval_expired" : "approval_invalid"))
        }
    }
}
