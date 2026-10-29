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
        // Both business-facing references: the pairwise `subject_ref` (canonical) and the legacy per-business pseudonym (kept for compatibility).
        interaction.scope.subjectRef = ctx.subjects.subjectRef(businessId: interaction.businessId, consumerId: interaction.scope.consumerId)
        interaction.scope.consumerId = ctx.hasher.consumerReference(businessId: interaction.businessId, consumerId: interaction.scope.consumerId)
        if let reference = ChallengeNonce(SecureToken.hash(interaction.challenge.value)) { interaction.challenge = reference }
        return interaction
    }

    func outcome(_ record: InteractionRecord) throws -> InteractionOutcome {
        if var stored = record.outcomeJSON.flatMap({ try? ViadereJSON.decode(InteractionOutcome.self, from: Data($0.utf8)) }) {
            // Rows written before pseudonymous outcomes still carry the raw signed decision; a business never sees it.
            stored.signedDecision = nil
            return stored
        }
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
        // Policy first (SEC-API-003): the capability this kind exercises must be in the key's scope **and** in the business's current
        // entitlements, before anything about the customer is read and before an idempotent replay can return an earlier result.
        let policy = PolicyService(db: db, ctx: ctx)
        let capability = Capability.required(forInteractionKind: request.kind)
        try await policy.enforce(PolicyInput(capability), principal: principal, auditAllowed: false)
        // Gate finding F2: an approval decided on relay status alone needs the explicit, expiring legacy entitlement while Approve v2 exists.
        try await LegacyApproval.require(kind: request.kind, sensitivity: request.sensitivity, principal: principal, ctx: ctx, db: db)
        // Idempotency: same key + same body → the original; same key + different body → 409.
        if let existing = try await existing(businessId: principal.businessId, key: request.idempotencyKey) {
            return try replay(existing, requestHash: requestHash)
        }
        // Defence in depth behind the API-key middleware: a verified business may issue (live traffic needs approved go-live), and a business
        // still being onboarded may issue sandbox traffic once its domain control is verified.
        guard let business = try await BusinessRecord.find(principal.businessId.uuid, on: db),
              try await OnboardingGate.allows(business: business, livemode: principal.livemode, on: db) else {
            throw APIError(.forbidden, .forbidden, "This business is not currently active.")
        }
        let controls = try await BusinessControls.load(principal.businessId.uuid, on: db)
        // Tenant isolation: the relationship must belong to *this* business; anything else is a plain 404.
        guard let relationship = try await RelationshipRecord.query(on: db).filter(\.$id == request.relationshipId.uuid)
            .filter(\.$businessId == principal.businessId.uuid).first() else { throw APIError.notFound }
        guard relationship.isActive else { throw APIError.conflict("The consumer is not connected to your business.") }
        // Test-mode keys reach sandbox consumers only, and live keys never reach them: test traffic cannot land on a real person,
        // bypass quota or abuse accounting, or be decided by a real device.
        try await Sandbox(db: db).requireMatching(relationship: relationship, livemode: principal.livemode)
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
        // Customer consent, authenticator evidence and law/policy: the policy engine decides (same `consent_required` answer as before).
        let subject = try await policy.subjectFacts(relationship: relationship, capability: capability, interactionPurpose: request.purpose)
        try await policy.enforce(PolicyInput(capability, subjectRef: SubjectResolver(db: db, ctx: ctx).ref(for: relationship), purpose: request.purpose.rawValue),
                                 principal: principal, stage: .full, subject: subject)
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
                    // A newer status for the same ongoing event replaces the earlier ones: of the same relationship and the same mode only,
                    // so one activity key cannot supersede another person's (or a live) status.
                    try await InteractionRecord.query(on: tx).filter(\.$businessId == principal.businessId.uuid)
                        .filter(\.$relationshipId == relationship.id!).filter(\.$livemode == principal.livemode)
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
        if principal.livemode {
            await push(record: record, interaction: issued)
            // Ongoing statuses can also drive a Live Activity (only when `LiveActivityPolicy` allows; never marketing).
            await LiveActivityService(db: db, ctx: ctx).push(record: record, interaction: issued)
        }
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
        let quota = Int((Double(business.dailyQuota) * BusinessControls.throttleFactor(controls, settings: await AbuseService(db: db, ctx: ctx).thresholds())).rounded(.down))
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
            ttlSeconds: 24 * 3600, idempotencyKey: request.idempotencyKey, correlationId: request.correlationId, accountReference: nil)
        guard request.activityKey.count <= 64, !request.activityKey.isEmpty else {
            throw APIError.validation("activityKey is required (max 64 characters).", details: ["activityKey": "invalid"])
        }
        return try await issueInternal(principal: principal, request: synthetic, requestHash: hash, activityKey: request.activityKey)
    }

    // MARK: Business outcome / cancel

    /// The business's own interaction. A test-mode key sees only test interactions and a live key only live ones (`livemode`), so a
    /// leaked test key cannot read or cancel real traffic, and a live key cannot touch the sandbox.
    func record(id: InteractionID, businessId: BusinessID, livemode: Bool) async throws -> InteractionRecord {
        guard let record = try await InteractionRecord.query(on: db).filter(\.$id == id.uuid)
            .filter(\.$businessId == businessId.uuid).filter(\.$livemode == livemode).first() else { throw APIError.notFound }
        return record
    }

    func cancel(principal: BusinessPrincipal, id: InteractionID) async throws -> InteractionOutcome {
        let record = try await record(id: id, businessId: principal.businessId, livemode: principal.livemode)
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
        if notify { try await WebhookService(db: db, ctx: ctx).enqueue(.interactionCancelled, businessId: outcome.businessId, payload: outcome,
                                                                                     opaque: OpaqueWebhookEvent(requestId: outcome.interactionId.description, resultRef: nil)) }
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
        try await WebhookService(db: db, ctx: ctx).enqueue(.interactionExpired, businessId: outcome.businessId, payload: outcome,
                                                           opaque: OpaqueWebhookEvent(requestId: outcome.interactionId.description, resultRef: nil))
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

    /// The consumer's own interactions plus those of anyone who delegated to them, limited to each grant's purposes and businesses.
    /// A delegate never sees an interaction outside every active grant's scope.
    private func accessible(_ consumer: ConsumerID, grants: [DelegationGrantRecord], on query: QueryBuilder<InteractionRecord>) -> QueryBuilder<InteractionRecord> {
        guard !grants.isEmpty else { return query.filter(\.$consumerId == consumer.uuid) }
        return query.group(.or) { or in
            or.filter(\.$consumerId == consumer.uuid)
            for grant in grants {
                or.group(.and) { and in
                    and.filter(\.$consumerId == grant.grantorId)
                    and.filter(\.$purpose ~~ grant.purposeSet.map(\.rawValue))
                    and.filter(\.$businessId ~~ grant.businessIdSet)
                }
            }
        }
    }

    func list(consumer: ConsumerID, status: String?, cursor: String?, limit: Int) async throws -> Page<InteractionEnvelope> {
        let limit = min(max(limit, 1), 50)
        let offset = cursor.flatMap { Int($0) }.map { max(0, $0) } ?? 0
        let grants = try await HouseholdService(db: db, ctx: ctx).activeReceivedGrants(delegate: consumer)
        var query = accessible(consumer, grants: grants, on: InteractionRecord.query(on: db)).filter(\.$livemode == true)
        let wanted = status.flatMap { InteractionStatus(rawValue: $0) } ?? .pending
        if status != nil, InteractionStatus(rawValue: status!) == nil { throw APIError.validation("Unknown status.", details: ["status": "invalid"]) }
        query = query.filter(\.$status == wanted.rawValue)
        if wanted == .pending { query = query.filter(\.$expiresAt > ctx.now) }
        let records = try await query.sort(\.$createdAt, .descending).sort(\.$id, .ascending).offset(offset).limit(limit + 1).all()
        let page = Array(records.prefix(limit))
        return Page(items: try await envelopes(page), nextCursor: records.count > limit ? String(offset + limit) : nil)
    }

    func get(consumer: ConsumerID, id: InteractionID) async throws -> InteractionEnvelope {
        let grants = try await HouseholdService(db: db, ctx: ctx).activeReceivedGrants(delegate: consumer)
        guard let record = try await accessible(consumer, grants: grants, on: InteractionRecord.query(on: db).filter(\.$id == id.uuid).filter(\.$livemode == true)).first(),
              let envelope = try await envelopes([record]).first else {
            throw APIError.notFound
        }
        return envelope
    }

    // MARK: Decide

    func decide(principal: ConsumerPrincipal, id: InteractionID, request: DecideInteractionRequest) async throws -> InteractionOutcome {
        guard let deviceId = principal.deviceId else { throw APIError.signatureInvalid }
        guard let record = try await InteractionRecord.find(id.uuid, on: db), record.livemode else { throw APIError.notFound }
        let now = ctx.now
        // Someone else's interaction is reachable only through an active grant that covers its purpose and business.
        // Out of scope is a plain 404: a delegate learns nothing about what lies outside their grant.
        var matchedGrant: DelegationGrantRecord?
        if record.consumerId != principal.consumerId.uuid {
            guard let purpose = InteractionPurpose(rawValue: record.purpose) else { throw APIError.notFound }
            matchedGrant = try await HouseholdService(db: db, ctx: ctx).activeReceivedGrants(delegate: principal.consumerId).first {
                $0.grantorId == record.consumerId && $0.permits(purpose: purpose, businessId: record.businessId, now: now)
            }
            guard matchedGrant != nil else { throw APIError.notFound }
        }
        let delegation = matchedGrant
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
        // App Clip devices can request but never decide; a device in its new-device cool-down cannot approve high or critical
        // requests (deny/report/decline stay available: they are the safe directions).
        guard let device = try await DeviceRecord.find(deviceId.uuid, on: db) else { throw APIError.signatureInvalid }
        guard device.kind == .app else {
            try await deny("clip_device", error: APIError(.forbidden, .forbidden, "This device can't respond to requests."))
        }
        let verifier = DecisionVerifier()
        // 1. Claimed device and assurance → which registered key must have signed.
        let claimed: DecisionPayload
        do { claimed = try verifier.decodeUnverified(request.signedDecision) } catch {
            try await deny("malformed", error: .badRequest("The decision could not be read."))
        }
        guard claimed.deviceId == deviceId else { try await deny("device_mismatch", error: .forbidden) }
        // High and critical approvals need a D1 device (§2.5a); a device that is not approved yet never becomes one by waiting.
        if !DeviceTrust.isTrusted(device, at: now), interaction.effectiveSensitivity >= .high,
           ![Decision.deny, .report, .decline].contains(claimed.decision) {
            try await deny("device_not_trusted", error: APIError(.forbidden, .deviceCoolDown,
                "This device hasn't been approved yet. Approve it from a device you already trust before approving this request."))
        }
        // A delegate can never approve authenticate/authorize, and only a manager may confirm, decline or choose. Server-enforced.
        if let delegation {
            guard DelegationScopePolicy.delegateMayDecide(role: delegation.roleValue, kind: interaction.kind, decision: claimed.decision) else {
                _ = try? await audit.record("delegation.denied", outcome: .denied, actor: AuditActor(kind: .consumer, id: principal.consumerId.description),
                    consumerId: ConsumerID(record.consumerId), businessId: BusinessID(record.businessId), subjectType: "delegation",
                    subjectId: delegation.id!.uuidString.lowercased(),
                    metadata: ["delegateId": principal.consumerId.description, "grantorId": ConsumerID(record.consumerId).description,
                               "reason": interaction.kind.isSecuritySensitive ? "kind_not_delegable" : "role_or_decision"])
                throw APIError(.forbidden, .forbidden, "You can't respond to this request on someone else's behalf.")
            }
        }
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
            case .contextDigestRequired:
                try await deny("context_digest_required", error: APIError(.badRequest, .contextDigestRequired,
                    "Update Viadere to respond to this request: the decision must be signed over what was shown."))
            case .contextMismatch:
                try await deny("context_mismatch", error: APIError(.conflict, .contextMismatch, "This request changed. Review it again."))
            }
        }
        // 3. Record the outcome atomically; the status swap makes the decision single-use even across instances.
        let decisionId = UUID()
        // What the business gets: a per-business device pseudonym and the server's attestation, never the signed decision.
        let businessOutcome = InteractionOutcome(
            interactionId: id, businessId: BusinessID(record.businessId), status: InteractionStatus(decision: payload.decision),
            decision: payload.decision, selectedOptionIds: payload.selectedOptionIds, reply: payload.reply, assurance: payload.assurance,
            channel: request.channel, decidedAt: now, correlationId: record.correlationId, signedDecision: nil,
            deviceRef: ctx.hasher.deviceReference(businessId: BusinessID(record.businessId), deviceId: deviceId),
            verification: DecisionVerification(keyPurpose: DeviceKeyPurpose.required(for: payload.assurance),
                                               contextBound: payload.contextDigest != nil, verifiedAt: now,
                                               evidenceRef: ctx.hasher.evidenceReference(decisionId: decisionId)))
        let outcome: InteractionOutcome = {
            var own = businessOutcome
            own.signedDecision = request.signedDecision   // the consumer's own response keeps it
            return own
        }()
        let outcomeJSON = String(decoding: try ViadereJSON.encode(businessOutcome), as: UTF8.self)
        try await db.transaction { tx in
            let swapped = try await DB.swap(tx, table: InteractionRecord.schema, id: id.uuid, column: "status",
                                            expected: InteractionStatus.pending.rawValue, newValue: outcome.status.rawValue)
            guard swapped else { throw APIError(.conflict, .replayDetected, "This request was already decided.") }
            try await InteractionRecord.query(on: tx).filter(\.$id == id.uuid).set(\.$decidedAt, to: now)
                .set(\.$outcomeJSON, to: outcomeJSON).update()
            let decision = DecisionRecord()
            decision.id = decisionId
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
            try await WebhookService(db: tx, ctx: ctx).enqueue(.interactionDecided, businessId: outcome.businessId, payload: businessOutcome,
                                                                opaque: OpaqueWebhookEvent(requestId: outcome.interactionId.description, resultRef: businessOutcome.verification?.evidenceRef))
            let auditService = AuditService(db: tx, ctx: ctx)
            _ = try await auditService.record("interaction.decided", principal: principal, businessId: outcome.businessId,
                subjectType: "interaction", subjectId: id.description,
                metadata: ["decision": payload.decision.rawValue, "assurance": payload.assurance.rawValue, "channel": request.channel.rawValue])
            if let delegation {
                _ = try await auditService.record("delegation.used", actor: AuditActor(kind: .consumer, id: principal.consumerId.description),
                    consumerId: ConsumerID(record.consumerId), businessId: outcome.businessId, subjectType: "delegation",
                    subjectId: delegation.id!.uuidString.lowercased(),
                    metadata: ["delegateId": principal.consumerId.description, "grantorId": ConsumerID(record.consumerId).description,
                               "decision": payload.decision.rawValue])
            }
            if payload.decision == .report {
                _ = try await auditService.record("interaction.reported_suspicious", principal: principal, businessId: outcome.businessId,
                    subjectType: "interaction", subjectId: id.description)
            }
        }
        return outcome
    }

    // MARK: Push

    /// Best-effort push to the consumer's devices, and to the devices of every delegate whose active grant covers this interaction's
    /// purpose **and** business. The payload is the same generic one (opaque interaction id only, no business data); a delegate
    /// fetches the details through the scoped API, which applies the same grant check again. An interaction outside every grant's
    /// scope (other purpose, other business, expired or revoked grant, deleted delegate) is never pushed to the delegate.
    func push(record: InteractionRecord, interaction: Interaction) async {
        guard interaction.allowedChannels.contains(.nativePush) else { return }
        // Emergency messaging restriction (G-6): a restricted push is skipped; the interaction stays available in the app.
        guard await MessagingGate(db: db, ctx: ctx).decide(businessId: record.businessId, channel: .push, purpose: record.purpose, kind: InteractionKind(rawValue: record.kind)) == .allow else { return }
        do {
            guard let business = try await BusinessRecord.find(record.businessId, on: db),
                  let summary = try await DirectoryService(db: db).summary(for: business) else { return }
            var recipients: [UUID] = [record.consumerId]
            if let purpose = InteractionPurpose(rawValue: record.purpose) {
                let now = ctx.now
                let grants = try await DelegationGrantRecord.query(on: db).filter(\.$grantorId == record.consumerId).filter(\.$revokedAt == nil)
                    .filter(\.$expiresAt > now).all()
                for grant in grants where grant.permits(purpose: purpose, businessId: record.businessId, now: now) && !recipients.contains(grant.delegateId) {
                    if let delegate = try await ConsumerRecord.find(grant.delegateId, on: db), delegate.status == "active" { recipients.append(grant.delegateId) }
                }
            }
            let devices = try await DeviceRecord.query(on: db).filter(\.$consumerId ~~ recipients).filter(\.$revokedAt == nil).all()
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
