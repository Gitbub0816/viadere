import Fluent
import Foundation
import ViadereCore
import struct ViadereCore.Page

/// The Trust Engine's server-side policy. Priority is derived from what the interaction *is*, never from
/// what the business asks for or pays for.
enum TrustEngine {
    /// `Interaction.effectivePriority` (marketing/rewards ≤ normal, non-security purposes ≤ high) plus:
    /// `urgent` is reserved for security-purpose authenticate/authorize requests.
    static func clampPriority(requested: InteractionPriority, kind: InteractionKind, purpose: InteractionPurpose) -> InteractionPriority {
        var priority: InteractionPriority
        switch purpose {
        case .marketing, .rewards: priority = min(requested, .normal)
        case .security: priority = requested
        default: priority = min(requested, .high)
        }
        if priority == .urgent && !(kind.isSecuritySensitive && purpose == .security) { priority = .high }
        return priority
    }
}

/// Issuing, delivering, deciding and expiring interactions.
struct InteractionService {
    let db: any Database
    let ctx: ServerContext

    // MARK: Business-facing views

    /// What the business sees: a per-business pseudonym instead of the consumer id, and a one-way
    /// reference instead of the device challenge.
    func businessView(_ record: InteractionRecord) throws -> Interaction {
        var interaction = try record.interaction()
        interaction.scope.consumerId = ctx.hasher.consumerReference(businessId: interaction.businessId, consumerId: interaction.scope.consumerId)
        if let reference = ChallengeNonce(SecureToken.hash(interaction.challenge.value)) { interaction.challenge = reference }
        return interaction
    }

    func outcome(_ record: InteractionRecord) throws -> InteractionOutcome {
        if let json = record.outcomeJSON { return try ViadereJSON.decode(InteractionOutcome.self, from: Data(json.utf8)) }
        var status = record.statusValue
        if status == .pending && record.expiresAt <= ctx.now { status = .expired }
        return InteractionOutcome(interactionId: InteractionID(record.id!), businessId: BusinessID(record.businessId), status: status,
                                  correlationId: record.correlationId)
    }

    // MARK: Issue

    struct IssueResult {
        var interaction: Interaction
        var created: Bool
    }

    func issue(principal: BusinessPrincipal, request: IssueInteractionRequest, headerKey: String?) async throws -> IssueResult {
        if let headerKey, headerKey != request.idempotencyKey {
            throw APIError.badRequest("Idempotency-Key header does not match the request body.")
        }
        let hash = SecureToken.sha256Hex(try ViadereJSON.encode(request))
        return try await issueInternal(principal: principal, request: request, requestHash: hash, activityKey: nil)
    }

    private func issueInternal(principal: BusinessPrincipal, request: IssueInteractionRequest, requestHash: String,
                               activityKey: String?) async throws -> IssueResult {
        // Idempotency: same key + same body → the original; same key + different body → 409.
        if let existing = try await existing(businessId: principal.businessId, key: request.idempotencyKey) {
            return try replay(existing, requestHash: requestHash)
        }
        // Defence in depth behind the API-key middleware: only a verified business may issue.
        guard let business = try await BusinessRecord.find(principal.businessId.uuid, on: db), business.isVerified else {
            throw APIError(.forbidden, .forbidden, "This business is not currently active.")
        }
        let controls = try await BusinessControls.load(principal.businessId.uuid, on: db)
        // Tenant isolation: the relationship must belong to *this* business; anything else is a plain 404.
        guard let relationship = try await RelationshipRecord.query(on: db).filter(\.$id == request.relationshipId.uuid)
            .filter(\.$businessId == principal.businessId.uuid).first() else { throw APIError.notFound }
        guard relationship.isActive else { throw APIError.conflict("The consumer is not connected to your business.") }
        let now = ctx.now
        var interaction = request.makeInteraction(businessId: principal.businessId, consumerId: ConsumerID(relationship.consumerId), now: now)
        interaction.priority = TrustEngine.clampPriority(requested: request.priority, kind: interaction.kind, purpose: interaction.purpose)
        // Operator controls can only lower the ceiling; a billing tier is never consulted.
        interaction.priority = BusinessControls.applyCeiling(interaction.priority, controls: controls)
        interaction.sensitivity = interaction.effectiveSensitivity
        let issues = InteractionValidation.issues(in: interaction, now: now)
        if !issues.isEmpty {
            var details: [String: String] = [:]
            for issue in issues.prefix(8) { details[issue.field] = issue.code.rawValue }
            throw APIError.validation("The interaction is invalid.", details: details)
        }
        guard try await ConsentService(db: db, ctx: ctx).permits(purpose: request.purpose, relationshipId: relationship.id!) else {
            throw APIError(.forbidden, .consentRequired, "The consumer has not consented to this kind of message.",
                           details: ["purpose": request.purpose.rawValue])
        }
        // Quota (live traffic only). A paid tier raises the quota; it never changes priority.
        if principal.livemode { try await enforceQuota(principal: principal, business: business, controls: controls, now: now) }
        let issued = interaction
        let record = try InteractionRecord(interaction: issued, consumerId: relationship.consumerId, livemode: principal.livemode,
                                           requestHash: requestHash, activityKey: activityKey)
        do {
            try await db.transaction { tx in
                try await record.create(on: tx)
                try await InteractionChallengeRecord(interaction: issued).create(on: tx)
                if let activityKey {
                    // A newer status for the same ongoing event replaces the earlier ones.
                    try await InteractionRecord.query(on: tx).filter(\.$businessId == principal.businessId.uuid)
                        .filter(\.$activityKey == activityKey).filter(\.$status == InteractionStatus.pending.rawValue)
                        .filter(\.$id != issued.id.uuid).set(\.$status, to: InteractionStatus.delivered.rawValue).update()
                }
                relationship.lastActivityAt = now
                try await relationship.update(on: tx)
                try await UsageMeter.record(.interaction, businessId: principal.businessId.uuid, livemode: principal.livemode,
                                            ref: issued.id.uuid.uuidString.lowercased(), at: now, on: tx)
                try await ChannelRouter(db: tx, ctx: ctx).enqueue(record: record, interaction: issued, on: tx)
                _ = try await AuditService(db: tx, ctx: ctx).record("interaction.issued", actor: AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased()),
                    consumerId: ConsumerID(relationship.consumerId), businessId: principal.businessId, subjectType: "interaction",
                    subjectId: issued.id.description, correlationId: issued.correlationId,
                    metadata: ["kind": issued.kind.rawValue, "purpose": issued.purpose.rawValue,
                               "priority": issued.priority.rawValue, "live": principal.livemode ? "true" : "false"])
            }
        } catch {
            // A concurrent request with the same key won the race: treat it as a replay.
            if error.isConstraintViolation, let existing = try await existing(businessId: principal.businessId, key: request.idempotencyKey) {
                return try replay(existing, requestHash: requestHash)
            }
            throw error
        }
        if principal.livemode { await push(record: record, interaction: issued) }
        return IssueResult(interaction: try businessView(record), created: true)
    }

    private func existing(businessId: BusinessID, key: String) async throws -> InteractionRecord? {
        try await InteractionRecord.query(on: db).filter(\.$businessId == businessId.uuid).filter(\.$idempotencyKey == key).first()
    }

    private func replay(_ existing: InteractionRecord, requestHash: String) throws -> IssueResult {
        guard ConstantTime.equals(existing.requestHash, requestHash) else {
            throw APIError(.conflict, .idempotencyConflict, "This Idempotency-Key was already used with a different request.")
        }
        guard let view = try? businessView(existing) else { throw APIError.gone("The consumer's data has been erased.") }
        return IssueResult(interaction: view, created: false)
    }

    private func enforceQuota(principal: BusinessPrincipal, business: BusinessRecord, controls: BusinessControlRecord?, now: Date) async throws {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC") ?? .current
        let dayStart = calendar.startOfDay(for: now)
        let used = try await InteractionRecord.query(on: db).filter(\.$businessId == principal.businessId.uuid)
            .filter(\.$livemode == true).filter(\.$createdAt >= dayStart).count()
        // A throttled business (abuse thresholds or operator) gets a fraction of its quota; the tier only sets the base.
        let quota = Int((Double(business.dailyQuota) * BusinessControls.throttleFactor(controls, settings: ctx.config.abuse)).rounded(.down))
        if used >= quota {
            let retry = Int(dayStart.addingTimeInterval(86_400).timeIntervalSince(now))
            throw APIError(.tooManyRequests, .rateLimited, "Daily interaction quota exceeded.",
                           headers: ["Retry-After": String(max(1, retry))])
        }
    }

    // MARK: Status updates

    func updateStatus(principal: BusinessPrincipal, request: BusinessStatusUpdateRequest, headerKey: String?) async throws -> IssueResult {
        if let headerKey, headerKey != request.idempotencyKey { throw APIError.badRequest("Idempotency-Key header does not match the request body.") }
        let hash = SecureToken.sha256Hex(try ViadereJSON.encode(request))
        let synthetic = IssueInteractionRequest(
            relationshipId: request.relationshipId, purpose: request.purpose, payload: .status(request.status),
            requestedActions: [], priority: .normal, sensitivity: .low, allowedChannels: [.nativePush, .inApp],
            ttlSeconds: 24 * 3600, idempotencyKey: request.idempotencyKey, correlationId: nil, accountReference: nil)
        guard request.activityKey.count <= 64, !request.activityKey.isEmpty else {
            throw APIError.validation("activityKey is required (max 64 characters).", details: ["activityKey": "invalid"])
        }
        return try await issueInternal(principal: principal, request: synthetic, requestHash: hash, activityKey: request.activityKey)
    }

    // MARK: Business outcome / cancel

    func record(id: InteractionID, businessId: BusinessID) async throws -> InteractionRecord {
        guard let record = try await InteractionRecord.query(on: db).filter(\.$id == id.uuid)
            .filter(\.$businessId == businessId.uuid).first() else { throw APIError.notFound }
        return record
    }

    func cancel(principal: BusinessPrincipal, id: InteractionID) async throws -> InteractionOutcome {
        let record = try await record(id: id, businessId: principal.businessId)
        if record.statusValue != .pending { return try outcome(record) }
        if record.expiresAt <= ctx.now { _ = try await expireIfNeeded(record); return try outcome(record) }
        try await db.transaction { tx in
            _ = try await InteractionService(db: tx, ctx: ctx).cancelPending(record, notify: true)
        }
        return try outcome(record)
    }

    /// pending → cancelled with a webhook. Returns false if another request already finalized it.
    @discardableResult
    func cancelPending(_ record: InteractionRecord, notify: Bool) async throws -> Bool {
        let swapped = try await DB.swap(db, table: InteractionRecord.schema, id: record.id!, column: "status",
                                        expected: InteractionStatus.pending.rawValue, newValue: InteractionStatus.cancelled.rawValue)
        guard swapped else { return false }
        let outcome = InteractionOutcome(interactionId: InteractionID(record.id!), businessId: BusinessID(record.businessId),
                                         status: .cancelled, decidedAt: ctx.now, correlationId: record.correlationId)
        record.status = InteractionStatus.cancelled.rawValue
        record.outcomeJSON = String(decoding: try ViadereJSON.encode(outcome), as: UTF8.self)
        try await InteractionRecord.query(on: db).filter(\.$id == record.id!).set(\.$outcomeJSON, to: record.outcomeJSON).update()
        if notify { try await WebhookService(db: db, ctx: ctx).enqueue(.interactionCancelled, businessId: outcome.businessId, payload: outcome) }
        _ = try await AuditService(db: db, ctx: ctx).record("interaction.cancelled", actor: AuditActor(kind: .system),
            consumerId: ConsumerID(record.consumerId), businessId: outcome.businessId, subjectType: "interaction",
            subjectId: outcome.interactionId.description)
        return true
    }

    /// Marks an overdue pending interaction as expired and notifies the business exactly once.
    @discardableResult
    func expireIfNeeded(_ record: InteractionRecord) async throws -> Bool {
        guard record.statusValue == .pending, record.expiresAt <= ctx.now else { return false }
        let swapped = try await DB.swap(db, table: InteractionRecord.schema, id: record.id!, column: "status",
                                        expected: InteractionStatus.pending.rawValue, newValue: InteractionStatus.expired.rawValue)
        guard swapped else { return false }
        let outcome = InteractionOutcome(interactionId: InteractionID(record.id!), businessId: BusinessID(record.businessId),
                                         status: .expired, decidedAt: record.expiresAt, correlationId: record.correlationId)
        record.status = InteractionStatus.expired.rawValue
        record.outcomeJSON = String(decoding: try ViadereJSON.encode(outcome), as: UTF8.self)
        record.expiryNotified = true
        try await InteractionRecord.query(on: db).filter(\.$id == record.id!).set(\.$outcomeJSON, to: record.outcomeJSON)
            .set(\.$expiryNotified, to: true).update()
        try await WebhookService(db: db, ctx: ctx).enqueue(.interactionExpired, businessId: outcome.businessId, payload: outcome)
        return true
    }

    /// Maintenance: expire everything overdue.
    @discardableResult
    func expireDue(limit: Int = 200) async throws -> Int {
        let overdue = try await InteractionRecord.query(on: db).filter(\.$status == InteractionStatus.pending.rawValue)
            .filter(\.$expiresAt <= ctx.now).limit(limit).all()
        var count = 0
        for record in overdue where try await expireIfNeeded(record) { count += 1 }
        return count
    }

    // MARK: Consumer-facing

    func envelopes(_ records: [InteractionRecord]) async throws -> [InteractionEnvelope] {
        let businesses = try await BusinessRecord.query(on: db).filter(\.$id ~~ Array(Set(records.map(\.businessId)))).all()
        let summaries = try await DirectoryService(db: db).summaries(for: businesses)
        let byId = Dictionary(summaries.map { ($0.id.uuid, $0) }, uniquingKeysWith: { first, _ in first })
        let now = ctx.now
        return try records.compactMap { record in
            guard let summary = byId[record.businessId] else { return nil }
            var status = record.statusValue
            if status == .pending && record.expiresAt <= now { status = .expired }
            return InteractionEnvelope(interaction: try record.interaction(), business: summary, status: status)
        }
    }

    func list(consumer: ConsumerID, status: String?, cursor: String?, limit: Int) async throws -> Page<InteractionEnvelope> {
        let limit = min(max(limit, 1), 50)
        let offset = cursor.flatMap { Int($0) }.map { max(0, $0) } ?? 0
        var query = InteractionRecord.query(on: db).filter(\.$consumerId == consumer.uuid)
        let wanted = status.flatMap { InteractionStatus(rawValue: $0) } ?? .pending
        if status != nil, InteractionStatus(rawValue: status!) == nil { throw APIError.validation("Unknown status.", details: ["status": "invalid"]) }
        query = query.filter(\.$status == wanted.rawValue)
        if wanted == .pending { query = query.filter(\.$expiresAt > ctx.now) }
        let records = try await query.sort(\.$createdAt, .descending).sort(\.$id, .ascending).offset(offset).limit(limit + 1).all()
        let page = Array(records.prefix(limit))
        return Page(items: try await envelopes(page), nextCursor: records.count > limit ? String(offset + limit) : nil)
    }

    func get(consumer: ConsumerID, id: InteractionID) async throws -> InteractionEnvelope {
        guard let record = try await InteractionRecord.query(on: db).filter(\.$id == id.uuid)
            .filter(\.$consumerId == consumer.uuid).first(), let envelope = try await envelopes([record]).first else {
            throw APIError.notFound
        }
        return envelope
    }

    // MARK: Decide

    func decide(principal: ConsumerPrincipal, id: InteractionID, request: DecideInteractionRequest) async throws -> InteractionOutcome {
        guard let deviceId = principal.deviceId else { throw APIError.signatureInvalid }
        guard let record = try await InteractionRecord.query(on: db).filter(\.$id == id.uuid)
            .filter(\.$consumerId == principal.consumerId.uuid).first() else { throw APIError.notFound }
        let now = ctx.now
        let audit = AuditService(db: db, ctx: ctx)
        func deny(_ code: String, error: APIError) async throws -> Never {
            _ = try? await audit.record("interaction.decision_rejected", outcome: .denied, principal: principal,
                businessId: BusinessID(record.businessId), subjectType: "interaction", subjectId: id.description, metadata: ["reason": code])
            throw error
        }
        guard record.statusValue == .pending else {
            try await deny("not_pending", error: .conflict("This request has already been resolved."))
        }
        guard try await DirectoryService(db: db).verified(id: record.businessId) != nil else {
            try await deny("business_unavailable", error: .gone("This request is no longer available."))
        }
        if record.expiresAt <= now {
            _ = try await expireIfNeeded(record)
            try await deny("expired", error: .gone("This request has expired."))
        }
        let interaction = try record.interaction()
        let verifier = DecisionVerifier()
        // 1. Claimed device and assurance → which registered key must have signed.
        let claimed: DecisionPayload
        do { claimed = try verifier.decodeUnverified(request.signedDecision) } catch {
            try await deny("malformed", error: .badRequest("The decision could not be read."))
        }
        guard claimed.deviceId == deviceId else { try await deny("device_mismatch", error: .forbidden) }
        guard let keyRecord = try await DeviceKeyRecord.query(on: db).filter(\.$deviceId == deviceId.uuid)
            .filter(\.$purpose == DeviceKeyPurpose.required(for: claimed.assurance).rawValue).first(),
              let publicKey = try? DevicePublicKey(base64URL: keyRecord.publicKey) else {
            try await deny("no_key_for_assurance", error: APIError(.forbidden, .insufficientAssurance,
                                                                   "This device cannot produce the required assurance."))
        }
        // 2. Full verification, including single-use challenge consumption.
        let payload: DecisionPayload
        do {
            payload = try await verifier.verify(request.signedDecision, for: interaction, deviceId: deviceId, publicKey: publicKey,
                                                channel: request.channel, now: now, replayGuard: DatabaseReplayGuard(db: db))
        } catch let error as DecisionVerificationError {
            switch error {
            case .malformedPayload, .nonCanonicalPayload, .malformedSignature:
                try await deny("malformed", error: .badRequest("The decision could not be read."))
            case .badSignature: try await deny("bad_signature", error: .signatureInvalid)
            case .interactionMismatch, .businessMismatch, .deviceMismatch, .challengeMismatch:
                try await deny("binding_mismatch", error: .forbidden)
            case .expired: try await deny("expired", error: .gone("This request has expired."))
            case .signedInFuture: try await deny("signed_in_future", error: APIError(.unauthorized, .clockSkew, "The decision timestamp is invalid."))
            case .stale: try await deny("stale", error: APIError(.gone, .expired, "This decision is too old. Please try again."))
            case .insufficientAssurance:
                try await deny("insufficient_assurance", error: APIError(.forbidden, .insufficientAssurance,
                    "This request needs stronger verification than the channel or device provided."))
            case .invalidSelection, .invalidDecision:
                try await deny("invalid_decision", error: .validation("The decision is not valid for this request."))
            case .replayed: try await deny("replayed", error: APIError(.conflict, .replayDetected, "This request was already decided."))
            }
        }
        // 3. Record the outcome atomically; the status swap makes the decision single-use even across instances.
        let outcome = InteractionOutcome(
            interactionId: id, businessId: BusinessID(record.businessId), status: InteractionStatus(decision: payload.decision),
            decision: payload.decision, selectedOptionIds: payload.selectedOptionIds, reply: payload.reply, assurance: payload.assurance,
            channel: request.channel, decidedAt: now, correlationId: record.correlationId, signedDecision: request.signedDecision)
        let outcomeJSON = String(decoding: try ViadereJSON.encode(outcome), as: UTF8.self)
        try await db.transaction { tx in
            let swapped = try await DB.swap(tx, table: InteractionRecord.schema, id: id.uuid, column: "status",
                                            expected: InteractionStatus.pending.rawValue, newValue: outcome.status.rawValue)
            guard swapped else { throw APIError(.conflict, .replayDetected, "This request was already decided.") }
            try await InteractionRecord.query(on: tx).filter(\.$id == id.uuid).set(\.$decidedAt, to: now)
                .set(\.$outcomeJSON, to: outcomeJSON).update()
            let decision = DecisionRecord()
            decision.id = UUID()
            decision.interactionId = id.uuid
            decision.businessId = record.businessId
            decision.consumerId = record.consumerId
            decision.deviceId = deviceId.uuid
            decision.decision = payload.decision.rawValue
            decision.assurance = payload.assurance.rawValue
            decision.channel = request.channel.rawValue
            decision.signedPayload = request.signedDecision.payload
            decision.signature = request.signedDecision.signature
            decision.decidedAt = now
            try await decision.create(on: tx)
            try await InteractionChallengeRecord.query(on: tx).filter(\.$interactionId == id.uuid)
                .set(\.$consumedAt, to: now).set(\.$consumedByDevice, to: deviceId.uuid).update()
            try await WebhookService(db: tx, ctx: ctx).enqueue(.interactionDecided, businessId: outcome.businessId, payload: outcome)
            let auditService = AuditService(db: tx, ctx: ctx)
            _ = try await auditService.record("interaction.decided", principal: principal, businessId: outcome.businessId,
                subjectType: "interaction", subjectId: id.description,
                metadata: ["decision": payload.decision.rawValue, "assurance": payload.assurance.rawValue, "channel": request.channel.rawValue])
            if payload.decision == .report {
                _ = try await auditService.record("interaction.reported_suspicious", principal: principal, businessId: outcome.businessId,
                    subjectType: "interaction", subjectId: id.description)
            }
        }
        return outcome
    }

    // MARK: Push

    /// Best-effort push to the consumer's devices. The payload carries only an opaque interaction id.
    func push(record: InteractionRecord, interaction: Interaction) async {
        guard interaction.allowedChannels.contains(.nativePush) else { return }
        do {
            guard let business = try await BusinessRecord.find(record.businessId, on: db),
                  let summary = try await DirectoryService(db: db).summary(for: business) else { return }
            let devices = try await DeviceRecord.query(on: db).filter(\.$consumerId == record.consumerId).filter(\.$revokedAt == nil).all()
            let tokens = try await APNsTokenRecord.query(on: db).filter(\.$deviceId ~~ devices.compactMap(\.id))
                .filter(\.$invalidatedAt == nil).all()
            let topic = ctx.config.appBundleID
            for token in tokens {
                let message = PushPayloadBuilder.message(for: interaction, business: summary, token: token.record, topic: topic)
                if await ctx.apns.send(message) == .tokenInvalid {
                    try await APNsTokenRecord.query(on: db).filter(\.$id == token.id!).set(\.$invalidatedAt, to: ctx.now).update()
                }
            }
        } catch {
            // Push is best effort; the interaction remains available through the authenticated API.
        }
    }
}
