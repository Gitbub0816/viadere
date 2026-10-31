import Fluent
import Foundation
import ViadereCore

/// Customer Loop consent, instances, action events and outcomes (WP-3.3, WP-3.5; plan section 4.5; SECURITY.md §2.94, §2.98).
///
/// Every check takes the account from the authenticated principal; ids in a request are lookup handles only. Every refusal is audited
/// (`loop.access_refused`, with the reason code) and counted (`loop_action_refused`).
struct LoopRuntimeService {
    let db: any Database
    let ctx: ServerContext

    static let inputsContext = "loop_action_events.inputs"
    static let pushBody = "There's an update to your request."

    // MARK: Consent (WP-3.5)

    func consentStatus(consumer: UUID) async throws -> LoopConsentStatus {
        let current = LoopConsentCatalog.current
        let rows = try await LoopConsentRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$revokedAt == nil).sort(\.$grantedAt, .descending).all()
        func view(_ row: LoopConsentRecord) -> LoopConsentGrantView {
            LoopConsentGrantView(businessId: row.businessId.map(BusinessID.init), textVersion: row.textVersion, textDigest: row.textDigest, grantedAt: row.grantedAt,
                                 current: row.textVersion >= current.version)
        }
        let global = rows.first { $0.businessId == nil }.map(view)
        var seen = Set<UUID>()
        let businesses = rows.filter { row in row.businessId.map { seen.insert($0).inserted } ?? false }.map(view)
        let available = !(await PlatformFlags(db: db, ctx: ctx).isStopped(.loops))
        return LoopConsentStatus(available: available, enabled: global?.current == true, text: LoopConsentText(current), global: global, businesses: businesses)
    }

    func grantGlobal(principal: ConsumerPrincipal, request: LoopGlobalConsentRequest) async throws -> LoopConsentStatus {
        let current = LoopConsentCatalog.current
        guard request.agree else { throw APIError.validation("Agree to turn this on.", details: ["agree": "required"]) }
        guard request.textVersion == current.version, request.textDigest == current.digest else {
            throw APIError.validation("The text changed. Read the current version first.", details: ["textVersion": "stale"])
        }
        guard current.passes(request.answers) else { throw APIError.validation("Check your answers.", details: ["answers": "incorrect"]) }
        let consumer = principal.consumerId.uuid
        let now = ctx.now
        try await db.transaction { tx in
            try await LoopConsentRecord.query(on: tx).filter(\.$consumerId == consumer).filter(\.$businessId == nil).filter(\.$revokedAt == nil)
                .set(\.$revokedAt, to: now).update()
            let row = LoopConsentRecord()
            row.consumerId = consumer
            row.businessId = nil
            row.textVersion = current.version
            row.textDigest = current.digest
            row.comprehensionPassedAt = now
            row.grantedAt = now
            try await row.create(on: tx)
            _ = try await AuditService(db: tx, ctx: ctx).record("loop.consent_granted", principal: principal, metadata: ["scope": "global", "version": String(current.version)])
        }
        return try await consentStatus(consumer: consumer)
    }

    func grantBusiness(principal: ConsumerPrincipal, business: BusinessID, request: LoopBusinessConsentRequest) async throws -> LoopConsentStatus {
        let current = LoopConsentCatalog.current
        let consumer = principal.consumerId.uuid
        guard try await activeRelationship(consumer: consumer, business: business.uuid) != nil else { throw APIError.notFound }
        guard request.agree else { throw APIError.validation("Agree to allow this business.", details: ["agree": "required"]) }
        guard request.textVersion == current.version, request.textDigest == current.digest else {
            throw APIError.validation("The text changed. Read the current version first.", details: ["textVersion": "stale"])
        }
        let global = try await LoopConsentRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$businessId == nil).filter(\.$revokedAt == nil).first()
        guard let global, global.textVersion >= current.version else { throw APIError.conflict("Turn on requests built by businesses first.") }
        let now = ctx.now
        try await db.transaction { tx in
            try await LoopConsentRecord.query(on: tx).filter(\.$consumerId == consumer).filter(\.$businessId == business.uuid).filter(\.$revokedAt == nil)
                .set(\.$revokedAt, to: now).update()
            let row = LoopConsentRecord()
            row.consumerId = consumer
            row.businessId = business.uuid
            row.textVersion = current.version
            row.textDigest = current.digest
            row.grantedAt = now
            try await row.create(on: tx)
            _ = try await AuditService(db: tx, ctx: ctx).record("loop.consent_granted", principal: principal, businessId: business,
                                                               metadata: ["scope": "business", "version": String(current.version)])
        }
        return try await consentStatus(consumer: consumer)
    }

    /// Revokes the global grant (and with it every business authorization) or one business's authorization, and cancels the affected open
    /// instances. History (events, outcomes, inbox items) is kept.
    func revoke(principal: ConsumerPrincipal, business: BusinessID?) async throws -> LoopConsentStatus {
        let consumer = principal.consumerId.uuid
        let now = ctx.now
        try await db.transaction { tx in
            var query = LoopConsentRecord.query(on: tx).filter(\.$consumerId == consumer).filter(\.$revokedAt == nil)
            if let business { query = query.filter(\.$businessId == business.uuid) }
            try await query.set(\.$revokedAt, to: now).update()
            try await LoopRuntimeService(db: tx, ctx: ctx).cancelOpenInstances(consumer: consumer, business: business?.uuid, reason: "consent_revoked")
            _ = try await AuditService(db: tx, ctx: ctx).record("loop.consent_revoked", principal: principal, businessId: business,
                                                               metadata: ["scope": business == nil ? "global" : "business"])
        }
        return try await consentStatus(consumer: consumer)
    }

    func consentState(consumer: UUID, business: UUID) async throws -> LoopConsentState {
        let rows = try await LoopConsentRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$revokedAt == nil).all()
        let global = rows.filter { $0.businessId == nil }.map(\.textVersion).max()
        let own = rows.filter { $0.businessId == business }.map(\.textVersion).max()
        return LoopConsentState(globalTextVersion: global, businessTextVersion: own)
    }

    // MARK: Access (plan 4.5 step 2)

    struct AccessFacts {
        var decision: LoopAccessDecision
        var relationship: RelationshipRecord?
    }

    func access(_ operation: LoopAccessOperation, consumer: UUID, publication: LoopPublicationRecord, instance: LoopInstanceRecord?) async throws -> AccessFacts {
        let business = try await BusinessRecord.find(publication.businessId, on: db)
        let relationship = try await activeRelationship(consumer: consumer, business: publication.businessId)
        var status = publication.statusValue
        // A retired (superseded) publication starts nothing new, but instances already pinned to it may finish.
        if operation != .createInstance, status == .retired { status = .active }
        let input = LoopAccessInput(
            consent: try await consentState(consumer: consumer, business: publication.businessId),
            currentConsentTextVersion: LoopConsentCatalog.current.version, relationshipActive: relationship != nil,
            businessStatus: business?.status ?? .suspended, businessCategory: BusinessCategory(rawValue: business?.category ?? "healthcare"),
            publicationStatus: status, businessLoopsSwitchedOff: try await LoopPublicationService.businessSwitchedOff(publication.businessId, on: db),
            platformLoopsOff: await PlatformFlags(db: db, ctx: ctx).isStopped(.loops),
            instanceExpired: instance.map { $0.expiresAt <= ctx.now } ?? false,
            instanceOwnedByCaller: instance.map { $0.consumerId == consumer && $0.businessId == publication.businessId } ?? true)
        return AccessFacts(decision: LoopAccessPolicy.evaluate(operation, input), relationship: relationship)
    }

    /// Audits and maps a denial to the HTTP answer. Not-found classes never reveal that the object exists.
    func refuse(_ denial: String, principal: ConsumerPrincipal, business: UUID?, subject: UUID?, operation: String) async -> APIError {
        ctx.metrics.count(.loopActionRefused)
        _ = try? await AuditService(db: db, ctx: ctx).record("loop.access_refused", outcome: .denied, principal: principal, businessId: business.map(BusinessID.init),
            subjectType: "loop_instance", subjectId: subject?.uuidString.lowercased(), metadata: ["reason": denial, "operation": operation])
        switch denial {
        case LoopAccessDenial.platformOff.rawValue, LoopAccessDenial.businessSwitchedOff.rawValue, LoopAccessDenial.publicationNotActive.rawValue:
            return APIError(.conflict, .conflict, "This request is paused.", details: ["reason": denial])
        case LoopAccessDenial.globalConsentMissing.rawValue, LoopAccessDenial.businessConsentMissing.rawValue, LoopAccessDenial.consentOutdated.rawValue:
            return APIError(.forbidden, .forbidden, "Turn on requests from this business first.", details: ["reason": denial])
        case LoopAccessDenial.expired.rawValue, "instance_closed":
            return APIError.gone("This request has ended.")
        case "idempotency_conflict", "step_mismatch":
            return APIError(.conflict, .conflict, denial == "step_mismatch" ? "This step is no longer current." : "This key was used for a different request.",
                            details: ["reason": denial])
        case "invalid_action", "invalid_inputs", "invalid_key", "entry_point":
            return APIError.validation("Check the request.", details: ["reason": denial])
        default:
            return APIError.notFound
        }
    }

    // MARK: Available Loops

    func available(principal: ConsumerPrincipal, business filter: BusinessID?) async throws -> [LoopSummary] {
        let consumer = principal.consumerId.uuid
        if await PlatformFlags(db: db, ctx: ctx).isStopped(.loops) { return [] }
        let relationships = try await RelationshipRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$status == "active").all()
        var businesses = Set(relationships.map(\.businessId))
        if let filter {
            guard businesses.contains(filter.uuid) else { throw APIError.notFound }
            businesses = [filter.uuid]
        }
        guard !businesses.isEmpty else { return [] }
        let publications = try await LoopPublicationRecord.query(on: db).filter(\.$businessId ~~ Array(businesses))
            .filter(\.$status == LoopPublicationStatus.active.rawValue).all()
        let allowed = Set(try await LoopRolloutAllowRecord.query(on: db).filter(\.$consumerId == consumer).all().map(\.publicationId))
        let consents = try await LoopConsentRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$revokedAt == nil).all()
        let current = LoopConsentCatalog.current.version
        var out: [LoopSummary] = []
        for publication in publications {
            guard let id = publication.id,
                  LoopRollout.isEligible(consumerId: consumer, publicationId: id, percent: publication.rolloutPercent, allowListed: allowed.contains(id)),
                  try await !LoopPublicationService.businessSwitchedOff(publication.businessId, on: db),
                  let business = try await BusinessRecord.find(publication.businessId, on: db), business.status == .verified,
                  case .eligible = LoopCategoryPolicy.loops(BusinessCategory(rawValue: business.category)),
                  let revision = try await LoopRevisionRecord.find(publication.revisionId, on: db),
                  let definition = LoopDefinition.parse(Data(revision.definitionJSON.utf8)).definition else { continue }
            let authorized = consents.contains { $0.businessId == publication.businessId && $0.textVersion >= current }
            out.append(LoopSummary(publicationId: LoopPublicationID(id), businessId: BusinessID(publication.businessId), revision: Int64(publication.revision),
                                   title: DisplayTextSanitizer.sanitize(definition.title, maxCharacters: LoopLimits.titleLength), entryPoints: definition.entryPoints,
                                   authorized: authorized))
        }
        return out.sorted { $0.title < $1.title }
    }

    // MARK: Instances

    func createInstance(principal: ConsumerPrincipal, request: LoopInstanceCreateRequest) async throws -> LoopInstanceView {
        let consumer = principal.consumerId.uuid
        guard await ctx.limiter.allow("loop-instance", key: consumer.uuidString.lowercased(), rule: ctx.config.loops.instanceRate) else {
            throw APIError.rateLimited(retryAfter: 60)
        }
        guard let publication = try await LoopPublicationRecord.find(request.publicationId.uuid, on: db) else {
            throw await refuse("not_found", principal: principal, business: nil, subject: nil, operation: "create")
        }
        let facts = try await access(.createInstance, consumer: consumer, publication: publication, instance: nil)
        if case .denied(let denial) = facts.decision {
            throw await refuse(denial.rawValue, principal: principal, business: publication.businessId, subject: nil, operation: "create")
        }
        let allowListed = try await LoopRolloutAllowRecord.query(on: db).filter(\.$publicationId == publication.id!).filter(\.$consumerId == consumer).first() != nil
        guard LoopRollout.isEligible(consumerId: consumer, publicationId: publication.id!, percent: publication.rolloutPercent, allowListed: allowListed),
              let relationship = facts.relationship,
              let revision = try await LoopRevisionRecord.find(publication.revisionId, on: db),
              let definition = LoopDefinition.parse(Data(revision.definitionJSON.utf8)).definition, let entry = definition.steps.first else {
            throw await refuse("not_found", principal: principal, business: publication.businessId, subject: nil, operation: "create")
        }
        guard definition.entryPoints.contains(request.entryPoint) else {
            throw await refuse("entry_point", principal: principal, business: publication.businessId, subject: nil, operation: "create")
        }
        let now = ctx.now
        let instance = LoopInstanceRecord()
        instance.id = UUID()
        instance.publicationId = publication.id!
        instance.revisionId = revision.id!
        instance.businessId = publication.businessId
        instance.consumerId = consumer
        instance.relationshipId = relationship.id!
        instance.entryPoint = request.entryPoint.rawValue
        instance.state = LoopInstanceState.active.rawValue
        instance.currentStepId = entry.id
        instance.expiresAt = now.addingTimeInterval(Double(definition.limits.expiresInSeconds))
        instance.createdAt = now
        instance.updatedAt = now
        let ctx = self.ctx
        try await db.transaction { tx in
            try await instance.create(on: tx)
            try await Outbox.enqueue(LoopQueue.timeout, ref: instance.id!, tenant: instance.businessId, notBefore: instance.expiresAt, on: tx, ctx: ctx)
            _ = try await AuditService(db: tx, ctx: ctx).record("loop.instance_created", principal: principal, businessId: BusinessID(instance.businessId),
                subjectType: "loop_instance", subjectId: instance.id!.uuidString.lowercased(), metadata: ["publication_id": publication.id!.uuidString.lowercased()])
        }
        return try await view(instance)
    }

    func getInstance(principal: ConsumerPrincipal, id: UUID) async throws -> LoopInstanceView {
        let consumer = principal.consumerId.uuid
        guard let instance = try await LoopInstanceRecord.query(on: db).filter(\.$id == id).filter(\.$consumerId == consumer).first(),
              let publication = try await LoopPublicationRecord.find(instance.publicationId, on: db) else {
            throw await refuse("not_found", principal: principal, business: nil, subject: id, operation: "resume")
        }
        let facts = try await access(.resume, consumer: consumer, publication: publication, instance: instance)
        if case .denied(let denial) = facts.decision {
            // Paused, revoked and expired states are shown (neutral paused / ended); everything else is refused.
            let shown: Set<LoopAccessDenial> = [.platformOff, .businessSwitchedOff, .publicationNotActive, .expired]
            if !shown.contains(denial) { throw await refuse(denial.rawValue, principal: principal, business: instance.businessId, subject: id, operation: "resume") }
        }
        try await expireIfDue(instance)
        return try await view(try await LoopInstanceRecord.find(id, on: db) ?? instance)
    }

    // MARK: Actions (plan 4.5 steps 1 to 3)

    func act(principal: ConsumerPrincipal, instanceId: UUID, request: LoopActionRequest) async throws -> LoopActionResult {
        let consumer = principal.consumerId.uuid
        // 1. The instance belongs to the caller (another account's or another business's id is "not found", and audited).
        guard let instance = try await LoopInstanceRecord.query(on: db).filter(\.$id == instanceId).filter(\.$consumerId == consumer).first(),
              let publication = try await LoopPublicationRecord.find(instance.publicationId, on: db), publication.businessId == instance.businessId else {
            throw await refuse("not_found", principal: principal, business: nil, subject: instanceId, operation: "act")
        }
        guard await ctx.limiter.allow("loop-action", key: consumer.uuidString.lowercased(), rule: ctx.config.loops.actionRate) else {
            throw APIError.rateLimited(retryAfter: 30)
        }
        // 2. Platform and business switches, relationship, verification, category, both consents at the current version, publication, expiry.
        let facts = try await access(.act, consumer: consumer, publication: publication, instance: instance)
        if case .denied(let denial) = facts.decision {
            throw await refuse(denial.rawValue, principal: principal, business: instance.businessId, subject: instanceId, operation: "act")
        }
        guard LoopActionSubmission.isValidIdempotencyKey(request.idempotencyKey) else {
            throw await refuse("invalid_key", principal: principal, business: instance.businessId, subject: instanceId, operation: "act")
        }
        let submission = LoopActionSubmission(instanceId: LoopInstanceID(instanceId), stepId: request.stepId, actionId: request.actionId,
                                              inputs: request.inputs, idempotencyKey: request.idempotencyKey)
        let digest = try submission.requestDigest()
        // 3. Idempotency: the same key and content returns the stored result and records nothing.
        if let stored = try await LoopActionEventRecord.query(on: db).filter(\.$instanceId == instanceId).filter(\.$idempotencyKey == request.idempotencyKey).first() {
            switch try LoopIdempotency.decide(storedEvent: LoopActionEventID(stored.id!), storedDigest: stored.requestDigest, submission: submission) {
            case .replay: return LoopActionResult(event: try await eventView(stored), instance: try await view(instance), replayed: true)
            case .conflict, .insert: throw await refuse("idempotency_conflict", principal: principal, business: instance.businessId, subject: instanceId, operation: "act")
            }
        }
        guard instance.stateValue == .active else {
            throw await refuse("instance_closed", principal: principal, business: instance.businessId, subject: instanceId, operation: "act")
        }
        // 4. The action belongs to the current step; inputs match the registered fields; the action type is registered and available.
        guard let revision = try await LoopRevisionRecord.find(instance.revisionId, on: db),
              let definition = LoopDefinition.parse(Data(revision.definitionJSON.utf8)).definition else { throw APIError.internalError }
        guard request.stepId == instance.currentStepId, let step = definition.step(request.stepId) else {
            throw await refuse("step_mismatch", principal: principal, business: instance.businessId, subject: instanceId, operation: "act")
        }
        guard let binding = step.actions.first(where: { $0.id == request.actionId }), let next = binding.next, let nextStep = definition.step(next),
              case .registered(let action) = LoopActionRegistry.v1.resolve(binding.action), action.isAvailable(in: .hosted) else {
            throw await refuse("invalid_action", principal: principal, business: instance.businessId, subject: instanceId, operation: "act")
        }
        guard LoopInputValidator.issues(request.inputs, step: step).isEmpty else {
            throw await refuse("invalid_inputs", principal: principal, business: instance.businessId, subject: instanceId, operation: "act")
        }
        let now = ctx.now
        let delivers = action.deliversToBusiness && binding.routing?.mode == .hosted
        let terminal = nextStep.type == .result || nextStep.type == .handoff
        let previouslyDelivered = try await LoopActionEventRecord.query(on: db).filter(\.$instanceId == instanceId).filter(\.$delivers == true).count() > 0
        let newState: LoopInstanceState = terminal ? ((delivers || previouslyDelivered) ? .submitted : .completed) : .active
        let event = LoopActionEventRecord()
        event.id = UUID()
        event.instanceId = instanceId
        event.businessId = instance.businessId
        event.consumerId = consumer
        event.deviceId = principal.deviceId?.uuid ?? UUID()
        event.stepId = request.stepId
        event.actionId = request.actionId
        event.actionType = action.actionType
        event.actionSchemaVersion = LoopActionRegistry.v1.version
        event.delivers = delivers
        event.inputsSealed = try ctx.cipher.seal(try CanonicalJSON.serialize(.object(request.inputs)), context: Self.inputsContext, rowId: event.id!)
        event.requestDigest = digest
        event.idempotencyKey = request.idempotencyKey
        event.correlationId = UUID().uuidString.lowercased()
        event.responseDueAt = delivers ? min(now.addingTimeInterval(Double(action.timeoutSeconds)), now.addingTimeInterval(Double(definition.limits.expiresInSeconds))) : nil
        event.createdAt = now
        let ctx = self.ctx
        do {
            try await db.transaction { tx in
                try await event.create(on: tx)
                // The instance advances by compare-and-swap on (step, state): two racing actions on one step cannot both apply.
                guard try await DB.swap(tx, table: LoopInstanceRecord.schema, id: instanceId, column: "current_step_id", expected: request.stepId, newValue: next,
                                        extra: [("state", newState.rawValue), ("updated_at", now)]) else { throw StepRace() }
                if delivers {
                    try await Self.appendOutcome(tx, event: event, outcome: LoopOutcomeMachine.initial, source: .system, actor: nil, reason: nil, seq: 1, ctx: ctx)
                    try await Outbox.enqueue(LoopQueue.deliver, ref: event.id!, tenant: event.businessId, on: tx, ctx: ctx)
                    if let due = event.responseDueAt { try await Outbox.enqueue(LoopQueue.timeout, ref: event.id!, tenant: event.businessId, notBefore: due, on: tx, ctx: ctx) }
                }
                _ = try await AuditService(db: tx, ctx: ctx).record("loop.action_recorded", principal: principal, businessId: BusinessID(event.businessId),
                    subjectType: "loop_action_event", subjectId: event.id!.uuidString.lowercased(),
                    metadata: ["instance_id": instanceId.uuidString.lowercased(), "action_type": action.actionType, "step_id": request.stepId])
            }
        } catch is StepRace {
            throw await refuse("step_mismatch", principal: principal, business: instance.businessId, subject: instanceId, operation: "act")
        } catch let error where error.isConstraintViolation {
            // A concurrent request with the same key won: answer with its result.
            if let stored = try await LoopActionEventRecord.query(on: db).filter(\.$instanceId == instanceId).filter(\.$idempotencyKey == request.idempotencyKey).first(),
               stored.requestDigest == digest {
                return LoopActionResult(event: try await eventView(stored), instance: try await view(instance), replayed: true)
            }
            throw await refuse("idempotency_conflict", principal: principal, business: instance.businessId, subject: instanceId, operation: "act")
        }
        if delivers { ctx.metrics.count(.loopOutcomePending) }
        let updated = try await LoopInstanceRecord.find(instanceId, on: db) ?? instance
        return LoopActionResult(event: try await eventView(event), instance: try await view(updated), replayed: false)
    }

    private struct StepRace: Error {}

    func report(principal: ConsumerPrincipal, instanceId: UUID, reason: LoopReportReason) async throws {
        let consumer = principal.consumerId.uuid
        guard await ctx.limiter.allow("loop-report", key: consumer.uuidString.lowercased(), rule: ctx.config.loops.reportRate) else { throw APIError.rateLimited(retryAfter: 60) }
        guard let instance = try await LoopInstanceRecord.query(on: db).filter(\.$id == instanceId).filter(\.$consumerId == consumer).first(),
              let publication = try await LoopPublicationRecord.find(instance.publicationId, on: db) else {
            throw await refuse("not_found", principal: principal, business: nil, subject: instanceId, operation: "report")
        }
        // Reporting never needs consent: a customer can always report what they were shown.
        try await LoopPublicationService(db: db, ctx: ctx).report(publication: publication, instance: instance, consumerId: consumer, reason: reason)
    }

    // MARK: Outcomes

    /// The current outcome of a delivering event (the last appended row).
    func currentOutcome(eventId: UUID) async throws -> LoopActionOutcomeRecord? {
        try await LoopActionOutcomeRecord.query(on: db).filter(\.$eventId == eventId).sort(\.$seq, .descending).first()
    }

    /// Appends an outcome if `LoopOutcomeMachine` allows it. Returns false when the move is refused (the caller decides whether that is an
    /// error). Final outcomes complete the instance; every change queues an opaque push to the customer.
    @discardableResult
    func recordOutcome(eventId: UUID, businessId: UUID, outcome: LoopActionOutcome, source: LoopOutcomeSource, actor: UUID?, reason: String?) async throws -> Bool {
        guard let event = try await LoopActionEventRecord.query(on: db).filter(\.$id == eventId).filter(\.$businessId == businessId).first(), event.delivers else { return false }
        guard let current = try await currentOutcome(eventId: eventId) else { return false }
        do { _ = try LoopOutcomeMachine.transition(from: current.outcomeValue, to: outcome, source: source) } catch { return false }
        let ctx = self.ctx
        do {
            try await db.transaction { tx in
                try await Self.appendOutcome(tx, event: event, outcome: outcome, source: source, actor: actor, reason: reason, seq: current.seq + 1, ctx: ctx)
                if outcome.isFinal {
                    try await LoopInstanceRecord.query(on: tx).filter(\.$id == event.instanceId).filter(\.$state ~~ [LoopInstanceState.active.rawValue, LoopInstanceState.submitted.rawValue])
                        .set(\.$state, to: LoopInstanceState.completed.rawValue).set(\.$updatedAt, to: ctx.now).update()
                }
                try await Outbox.enqueue(LoopQueue.notify, ref: event.id!, tenant: event.businessId, on: tx, ctx: ctx)
                _ = try await AuditService(db: tx, ctx: ctx).record("loop.outcome_recorded",
                    actor: actor.map { AuditActor(kind: source == .staff ? .business : .system, id: $0.uuidString.lowercased()) } ?? AuditActor(kind: .system, id: "loop-runtime"),
                    consumerId: ConsumerID(event.consumerId), businessId: BusinessID(event.businessId), subjectType: "loop_action_event",
                    subjectId: eventId.uuidString.lowercased(), metadata: ["outcome": outcome.rawValue, "source": source.rawValue])
            }
        } catch let error where error.isConstraintViolation {
            return false
        }
        switch outcome {
        case .accepted: ctx.metrics.count(.loopOutcomeAccepted)
        case .rejected: ctx.metrics.count(.loopOutcomeRejected)
        case .pending: ctx.metrics.count(.loopOutcomePending)
        case .timedOut: ctx.metrics.count(.loopOutcomeTimedOut)
        case .unknown: ctx.metrics.count(.loopOutcomeUnknown)
        }
        return true
    }

    static func appendOutcome(_ db: any Database, event: LoopActionEventRecord, outcome: LoopActionOutcome, source: LoopOutcomeSource, actor: UUID?,
                              reason: String?, seq: Int, ctx: ServerContext) async throws {
        let row = LoopActionOutcomeRecord()
        row.eventId = event.id!
        row.businessId = event.businessId
        row.seq = seq
        row.outcome = outcome.rawValue
        row.source = source.rawValue
        row.actorId = actor
        row.reason = reason
        row.at = ctx.now
        try await row.create(on: db)
    }

    // MARK: Ending instances

    func cancelOpenInstances(consumer: UUID? = nil, business: UUID? = nil, publicationId: UUID? = nil, reason: String) async throws {
        var query = LoopInstanceRecord.query(on: db).filter(\.$state ~~ [LoopInstanceState.active.rawValue, LoopInstanceState.submitted.rawValue])
        if let consumer { query = query.filter(\.$consumerId == consumer) }
        if let business { query = query.filter(\.$businessId == business) }
        if let publicationId { query = query.filter(\.$publicationId == publicationId) }
        try await query.set(\.$state, to: LoopInstanceState.cancelled.rawValue).set(\.$updatedAt, to: ctx.now).update()
    }

    func expireIfDue(_ instance: LoopInstanceRecord) async throws {
        guard instance.stateValue == .active, instance.expiresAt <= ctx.now, let id = instance.id else { return }
        _ = try await DB.swap(db, table: LoopInstanceRecord.schema, id: id, column: "state", expected: LoopInstanceState.active.rawValue,
                              newValue: LoopInstanceState.expired.rawValue, extra: [("updated_at", ctx.now)])
    }

    // MARK: Views

    func view(_ instance: LoopInstanceRecord) async throws -> LoopInstanceView {
        guard let publication = try await LoopPublicationRecord.find(instance.publicationId, on: db),
              let revision = try await LoopRevisionRecord.find(instance.revisionId, on: db),
              let definition = LoopIDs.json(Data(revision.definitionJSON.utf8)) else { throw APIError.internalError }
        let events = try await LoopActionEventRecord.query(on: db).filter(\.$instanceId == instance.id!).sort(\.$createdAt, .ascending).all()
        var views: [LoopActionEventView] = []
        for event in events { views.append(try await eventView(event)) }
        let platformOff = await PlatformFlags(db: db, ctx: ctx).isStopped(.loops)
        let businessOff = try await LoopPublicationService.businessSwitchedOff(instance.businessId, on: db)
        let paused = platformOff || businessOff || publication.statusValue == .suspended
        let manifest = try await LoopPublicationService(db: db, ctx: ctx).currentManifest(publication)
        return LoopInstanceView(id: LoopInstanceID(instance.id!), businessId: BusinessID(instance.businessId), publicationId: LoopPublicationID(publication.id!),
                                revision: Int64(publication.revision), state: instance.stateValue, currentStepId: instance.currentStepId,
                                entryPoint: LoopEntryPoint(rawValue: instance.entryPoint) ?? .businessPage, expiresAt: instance.expiresAt,
                                createdAt: instance.createdAt, updatedAt: instance.updatedAt, publicationStatus: publication.statusValue, paused: paused,
                                manifest: manifest, definition: definition, events: views)
    }

    func eventView(_ event: LoopActionEventRecord) async throws -> LoopActionEventView {
        let outcome = event.delivers ? try await currentOutcome(eventId: event.id!) : nil
        return LoopActionEventView(id: LoopActionEventID(event.id!), stepId: event.stepId, actionId: event.actionId, actionType: event.actionType,
                                   outcome: outcome?.outcomeValue, outcomeAt: outcome?.at, createdAt: event.createdAt)
    }

    func inputs(of event: LoopActionEventRecord) -> [String: JSONValue] {
        guard let data = try? ctx.cipher.open(event.inputsSealed, context: Self.inputsContext, rowId: event.id!),
              case .object(let object)? = LoopIDs.json(data) else { return [:] }
        return object
    }

    func activeRelationship(consumer: UUID, business: UUID) async throws -> RelationshipRecord? {
        try await RelationshipRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$businessId == business).filter(\.$status == "active").first()
    }

    /// The opaque outcome push: no business name, no content. It carries the instance id as the top-level `loopInstanceId` (an opaque
    /// UUID, like `iid` for interactions) so the app opens that instance and fetches it over the authenticated API.
    func pushOutcome(consumer: UUID, instanceId: UUID) async {
        let now = ctx.now
        let id = instanceId.uuidString.lowercased()
        do {
            let devices = try await DeviceRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$revokedAt == nil).all().filter { $0.kind == .app && !$0.isExpired(at: now) }
            let tokens = try await APNsTokenRecord.query(on: db).filter(\.$deviceId ~~ devices.compactMap(\.id)).filter(\.$invalidatedAt == nil).all()
            for token in tokens {
                let message = PushMessage(deviceToken: token.record.token, environment: token.record.environment,
                                          topic: token.record.bundleId.isEmpty ? ctx.config.appBundleID : token.record.bundleId,
                                          title: PushPayloadBuilder.genericTitle, body: Self.pushBody, category: "viadere.loop", threadID: "viadere.loop",
                                          interruptionLevel: "active", mutableContent: true, interactionId: nil, highPriority: true,
                                          collapseID: "loop.\(id)", loopInstanceId: id)
                if await ctx.apns.send(message) == .tokenInvalid {
                    try await APNsTokenRecord.query(on: db).filter(\.$id == token.id!).set(\.$invalidatedAt, to: now).update()
                }
            }
        } catch {
            // Best effort: the outcome is visible through the authenticated API and Alerts.
        }
    }
}
