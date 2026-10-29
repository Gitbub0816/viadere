import Fluent
import Foundation
import ViadereCore

/// Approval requests (`auth.challenge` and `transaction.approve`, spec 14.2): creation by the business, delivery to the customer's enrolled
/// devices, and the **signed, audience-bound result** coming back.
///
/// The relay is a courier. It verifies what it can (defense in depth) but it **cannot** authorize anything on a business's behalf: the
/// business fetches the signed result and verifies it itself against its own transaction record (APP-005, acceptance 5).
struct ApproveRequestService {
    let db: any Database
    let ctx: ServerContext

    /// What the relay keeps of a server-visible request's displayed details (end-to-end requests keep nothing).
    struct StoredDetails: Codable {
        var transaction: TransactionDetails?
        var authentication: AuthenticationDetails?
        var subject: ApprovalSubject? {
            if let transaction { return .transaction(transaction) }
            if let authentication { return .authentication(authentication) }
            return nil
        }
    }

    static let sealContext = "approve_requests.details"
    static let defaultLifetime = 120
    static let envelopeMaxFuture: TimeInterval = 900

    // MARK: Business: create

    func create(principal: BusinessPrincipal, body: CreateApprovalRequest) async throws -> (view: ApprovalRequestView, created: Bool) {
        let settings = ctx.config.approve
        guard body.capability == .authChallenge || body.capability == .transactionApprove else {
            throw APIError.validation("capability must be auth.challenge or transaction.approve.", details: ["capability": "invalid"])
        }
        guard ApproveIdentifiers.isValidRequestId(body.requestId) else { throw APIError.validation("request_id is invalid.", details: ["request_id": "invalid"]) }
        let lifetime = body.expiresInSeconds ?? Self.defaultLifetime
        guard (30...600).contains(lifetime) else { throw APIError.validation("expires_in_seconds must be between 30 and 600.", details: ["expires_in_seconds": "invalid"]) }

        // The shape: exactly one way to carry the details.
        let endToEnd = body.envelopes != nil
        var details: ApprovalSubject?
        if endToEnd {
            guard body.transaction == nil, body.authentication == nil, body.challenge == nil, let envelopes = body.envelopes, (1...8).contains(envelopes.count) else {
                throw APIError.validation("An end-to-end request carries only encrypted envelopes (1 to 8).", details: ["envelopes": "invalid"])
            }
        } else {
            switch body.capability {
            case .transactionApprove:
                guard let transaction = body.transaction, body.authentication == nil else { throw APIError.validation("transaction is required.", details: ["transaction": "required"]) }
                details = .transaction(transaction)
            default:
                guard let authentication = body.authentication, body.transaction == nil else { throw APIError.validation("authentication is required.", details: ["authentication": "required"]) }
                details = .authentication(authentication)
            }
            guard let challenge = body.challenge, ChallengeNonce(challenge) != nil else {
                throw APIError.validation("challenge must be a base64url nonce of 22 to 128 characters.", details: ["challenge": "invalid"])
            }
            do { try details?.validate() } catch let error as ApprovalTransactionError {
                if case .invalid(let field) = error { throw APIError.validation("A displayed parameter is invalid.", details: [field: "invalid"]) }
                throw APIError.validation("A displayed parameter is invalid.")
            }
        }

        // Policy first: key scope, entitlement, tier, kill switches, typed parameters (server-visible requests).
        let policy = PolicyService(db: db, ctx: ctx)
        var parameters: [String: JSONValue]?
        if case .transaction(let t)? = details {
            parameters = ["currency": .string(t.currency), "amount_minor": .integer(t.amountMinor), "payee_display": .string(t.payeeDisplay),
                          "transaction_reference": .string(t.transactionReference), "challenge": .string(body.challenge ?? "")]
        }
        try await policy.enforce(PolicyInput(body.capability, parameters: parameters), principal: principal, auditAllowed: false)
        try await ctx.limiter.enforce("approve-request", key: principal.businessId.description, rule: settings.requestRate)

        // Idempotency on the business's request id.
        let hash = SecureToken.sha256Hex(try ViadereJSON.encode(body))
        if let existing = try await ApproveRequestRecord.query(on: db).filter(\.$businessId == principal.businessId.uuid).filter(\.$requestId == body.requestId).first() {
            guard ConstantTime.equals(existing.requestHash, hash) else {
                throw APIError(.conflict, .idempotencyConflict, "This request_id was already used with a different request.")
            }
            return (try view(existing), false)
        }

        let relationship = try await SubjectResolver(db: db, ctx: ctx).relationship(businessId: principal.businessId, subjectRef: body.subjectRef)
        guard relationship.isActive else { throw APIError.conflict("The customer is not connected to your business.") }
        try await Sandbox(db: db).requireMatching(relationship: relationship, livemode: principal.livemode)
        let subjectFacts = try await policy.subjectFacts(relationship: relationship, capability: body.capability, interactionPurpose: .security)
        try await policy.enforce(PolicyInput(body.capability, subjectRef: body.subjectRef, parameters: parameters, purpose: InteractionPurpose.security.rawValue, requestId: body.requestId),
                                 principal: principal, stage: .full, subject: subjectFacts)
        try await ApproveFreezeService(db: db, ctx: ctx).requireNotFrozen(consumerId: relationship.consumerId, relationshipId: relationship.id!)

        let keyService = ApproveKeyService(db: db, ctx: ctx)
        let active = try await keyService.activeKeys(relationshipId: relationship.id!)
        guard !active.isEmpty else {
            throw APIError(.conflict, .conflict, "The customer has no active approval key for your business. Enroll one first.", details: ["reason": "no_active_key"])
        }

        // Prompt-fatigue protection (SEC-DEV-008), before anything is stored or pushed. This early look only avoids work: the authoritative check runs
        // again inside the transaction that inserts the request, under a per-relationship lock (gate finding F5), so concurrent requests cannot all
        // pass a count that none of them has yet changed.
        let now = ctx.now
        let early = try await promptVerdict(relationshipId: relationship.id!, now: now)
        if case .rateLimited(let retry) = early { throw Self.rateLimited(retry) }

        // Targets.
        var deliveries: [(key: ApproveKeyRecord, device: DeviceRecord, envelope: E2EEEnvelope?)] = []
        if let envelopes = body.envelopes {
            var seen = Set<String>()
            for delivery in envelopes {
                guard seen.insert(delivery.kid).inserted, let target = active.first(where: { $0.key.kid == delivery.kid }) else {
                    throw APIError.validation("An envelope names a key that is not an active approval key of this customer.", details: ["envelopes": "invalid_key"])
                }
                let ctxe = delivery.envelope.context
                guard delivery.envelope.kid == target.key.hpkeKid, ctxe.purpose == "approve.request", ctxe.requestId == body.requestId,
                      ctxe.sender == ApproveIdentifiers.sender(principal.businessId), ctxe.recipient == ApproveIdentifiers.recipient(kid: target.key.kid),
                      ctxe.expiresAt > now, ctxe.expiresAt <= now.addingTimeInterval(Self.envelopeMaxFuture) else {
                    throw APIError.validation("An envelope is not bound to this request, business and key.", details: ["envelopes": "invalid_binding"])
                }
                deliveries.append((target.key, target.device, delivery.envelope))
            }
        } else {
            deliveries = active.map { ($0.key, $0.device, nil) }
        }

        let record = ApproveRequestRecord()
        record.id = UUID()
        record.businessId = principal.businessId.uuid
        record.requestId = body.requestId
        record.relationshipId = relationship.id!
        record.consumerId = relationship.consumerId
        record.subjectRef = body.subjectRef.rawValue
        record.capability = body.capability.rawValue
        record.protection = (endToEnd ? ApprovalProtection.endToEnd : .serverVisible).rawValue
        record.requestHash = hash
        record.challenge = endToEnd ? nil : body.challenge
        if let details {
            let stored = StoredDetails(transaction: body.transaction, authentication: body.authentication)
            _ = details
            record.detailsSealed = try ctx.cipher.seal(try ViadereJSON.encode(stored), context: Self.sealContext, rowId: record.id!)
        }
        record.createdAt = now
        record.expiresAt = now.addingTimeInterval(TimeInterval(lifetime))
        let actor = AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased())
        let targets = deliveries
        let service = self
        do {
            try await DB.retryingTransient { try await db.transaction { tx in
                // Serialize requests per relationship (`SELECT ... FOR UPDATE` on PostgreSQL; SQLite serializes writers), then decide on the history
                // as it is now, including every request that committed while this one waited.
                try await DB.lockForUpdate(tx, table: RelationshipRecord.schema, id: relationship.id!)
                let verdict = try await ApproveRequestService(db: tx, ctx: service.ctx).promptVerdict(relationshipId: relationship.id!, now: now)
                var denied = false
                switch verdict {
                case .rateLimited(let retry): throw Self.rateLimited(retry)
                case .autoDeny: denied = true
                case .allow: break
                }
                record.status = denied ? ApprovalRequestStatus.denied.rawValue : ApprovalRequestStatus.pending.rawValue
                record.reason = denied ? "auto_denied" : nil
                record.delivered = denied ? 0 : targets.count
                if denied { record.decidedAt = now }
                let isAutoDenied = denied
                try await record.create(on: tx)
                if !isAutoDenied {
                    for target in targets {
                        let row = ApproveDeliveryRecord()
                        row.id = UUID()
                        row.requestId = record.id!
                        row.kid = target.key.kid
                        row.deviceId = target.device.id!
                        row.consumerId = relationship.consumerId
                        row.envelope = try target.envelope.map { String(decoding: try $0.serialized(), as: UTF8.self) }
                        row.createdAt = now
                        try await row.create(on: tx)
                    }
                }
                // The audit record names the request and the protection mode. Never the amount, the payee or an envelope.
                _ = try await AuditService(db: tx, ctx: ctx).record(isAutoDenied ? "approve.request_auto_denied" : "approve.request_created", actor: actor,
                    consumerId: ConsumerID(relationship.consumerId), businessId: principal.businessId, subjectType: "approve_request", subjectId: record.id?.uuidString.lowercased(),
                    correlationId: body.requestId, metadata: ["capability": body.capability.rawValue, "protection": record.protection, "devices": String(record.delivered)])
            } }
        } catch {
            // A concurrent request with the same id won the race: replay it.
            if error.isConstraintViolation, let existing = try await ApproveRequestRecord.query(on: db).filter(\.$businessId == principal.businessId.uuid)
                .filter(\.$requestId == body.requestId).first(), ConstantTime.equals(existing.requestHash, hash) {
                return (try view(existing), false)
            }
            throw error
        }
        if record.reason == "auto_denied" {
            await pauseNotice(relationship: relationship)
        } else {
            await ApproveNotifier(db: db, ctx: ctx).pushRequest(to: Array(Set(deliveries.compactMap(\.device.id))))
        }
        return (try view(record), true)
    }

    // MARK: Prompt fatigue

    static func rateLimited(_ retry: TimeInterval) -> APIError {
        APIError(.tooManyRequests, .rateLimited, "Too many approval requests for this customer.", headers: ["Retry-After": String(Int(retry.rounded(.up)))])
    }

    func promptVerdict(relationshipId: UUID, now: Date) async throws -> ApprovalPromptPolicy.Verdict {
        let policy = ctx.config.approve.prompt
        let since = now.addingTimeInterval(-max(policy.window, policy.pauseDuration))
        let rows = try await ApproveRequestRecord.query(on: db).filter(\.$relationshipId == relationshipId).filter(\.$createdAt > since).all()
        let records = rows.map { row -> ApprovalPromptPolicy.Record in
            // An auto-denied request is not a decision of the customer: it must not extend the pause.
            let decision = row.reason == "auto_denied" ? nil : row.decision.flatMap(ApprovalDecision.init(rawValue:))
            return ApprovalPromptPolicy.Record(createdAt: row.createdAt, decision: decision, isOpen: row.statusValue == .pending && row.expiresAt > now)
        }
        return policy.evaluate(history: records, now: now)
    }

    private func pauseNotice(relationship: RelationshipRecord) async {
        // Once per pause, not once per refused request.
        guard await ctx.limiter.allow("approve-pause-notice", key: relationship.id!.uuidString, rule: .perHour(1, burst: 1)) else { return }
        await ApproveNotifier(db: db, ctx: ctx).notice(.approvalRequestsPaused, consumerId: relationship.consumerId, subjectId: relationship.id?.uuidString.lowercased())
    }

    // MARK: Business: read, cancel, result

    func record(requestId: String, principal: BusinessPrincipal) async throws -> ApproveRequestRecord {
        guard let record = try await ApproveRequestRecord.query(on: db).filter(\.$businessId == principal.businessId.uuid).filter(\.$requestId == requestId).first(),
              try await Sandbox(db: db).matches(consumerId: record.consumerId, livemode: principal.livemode) else { throw APIError.notFound }
        return record
    }

    func view(_ record: ApproveRequestRecord) throws -> ApprovalRequestView {
        guard let subject = SubjectRef(record.subjectRef) else { throw APIError.internalError }
        var status = record.statusValue
        if status == .pending, record.expiresAt <= ctx.now { status = .expired }
        return ApprovalRequestView(requestId: record.requestId, subjectRef: subject, capability: Capability(rawValue: record.capability), status: status,
                                   protection: record.protectionValue, expiresAt: record.expiresAt, createdAt: record.createdAt, decidedAt: record.decidedAt,
                                   resultRef: record.resultRef, reason: record.reason, deliveredTo: record.delivered)
    }

    func cancel(principal: BusinessPrincipal, requestId: String) async throws -> ApproveRequestRecord {
        let record = try await record(requestId: requestId, principal: principal)
        if record.statusValue == .pending, record.expiresAt > ctx.now { _ = try await finish(record, status: .cancelled, reason: "cancelled_by_business", notify: false) }
        else if record.statusValue == .pending { _ = try await finish(record, status: .expired, reason: nil, notify: true) }
        return try await self.record(requestId: requestId, principal: principal)
    }

    /// The signed result, to the business it is addressed to only. A reference of another business is a plain 404.
    func result(principal: BusinessPrincipal, resultRef: String) async throws -> ApprovalResultResponse {
        guard ApproveIdentifiers.isValidResultRef(resultRef),
              let record = try await ApproveRequestRecord.query(on: db).filter(\.$resultRef == resultRef).filter(\.$businessId == principal.businessId.uuid).first(),
              try await Sandbox(db: db).matches(consumerId: record.consumerId, livemode: principal.livemode),
              let jws = record.resultJWS, let kid = record.decidedKid, let decidedAt = record.decidedAt else { throw APIError.notFound }
        return ApprovalResultResponse(resultRef: resultRef, requestId: record.requestId, result: jws, kid: kid, decidedAt: decidedAt)
    }

    // MARK: Finishing

    /// pending -> `status` (cancelled / expired) exactly once, with the opaque event when asked.
    @discardableResult
    func finish(_ record: ApproveRequestRecord, status: ApprovalRequestStatus, reason: String?, notify: Bool) async throws -> Bool {
        let swapped = try await DB.swap(db, table: ApproveRequestRecord.schema, id: record.id!, column: "status", expected: ApprovalRequestStatus.pending.rawValue,
                                        newValue: status.rawValue)
        guard swapped else { return false }
        if let reason { try await ApproveRequestRecord.query(on: db).filter(\.$id == record.id!).set(\.$reason, to: reason).update() }
        // The relay keeps nothing it does not need: the displayed details and the nonce go as soon as the request is over.
        try await ApproveRequestRecord.query(on: db).filter(\.$id == record.id!).set(\.$detailsSealed, to: nil).set(\.$challenge, to: nil).update()
        record.status = status.rawValue
        record.reason = reason
        _ = try await AuditService(db: db, ctx: ctx).record("approve.request_\(status.rawValue)", actor: AuditActor(kind: .system), consumerId: ConsumerID(record.consumerId),
            businessId: BusinessID(record.businessId), subjectType: "approve_request", subjectId: record.id?.uuidString.lowercased(), metadata: ["reason": reason ?? ""])
        if notify { try await ApproveWebhooks(db: db, ctx: ctx).requestExpired(record) }
        return true
    }

    /// Maintenance: expire everything overdue (the business gets one opaque event per request).
    @discardableResult
    func expireDue(limit: Int = 200) async throws -> Int {
        let now = ctx.now
        let overdue = try await ApproveRequestRecord.query(on: db).filter(\.$status == ApprovalRequestStatus.pending.rawValue).filter(\.$expiresAt <= now).limit(limit).all()
        var count = 0
        for record in overdue where try await finish(record, status: .expired, reason: nil, notify: true) { count += 1 }
        // Requests are kept for the capability's maximum result retention (400 days), then purged with their deliveries.
        let cutoff = now.addingTimeInterval(-400 * 86_400)
        if try await ApproveRequestRecord.query(on: db).filter(\.$createdAt < cutoff).filter(\.$status != ApprovalRequestStatus.pending.rawValue).count() > 0 {
            try await ApproveRequestRecord.query(on: db).filter(\.$createdAt < cutoff).filter(\.$status != ApprovalRequestStatus.pending.rawValue).delete()
        }
        // Enrollments the customer never completed.
        // Read first so an idle tick takes no write lock.
        if try await ApproveEnrollmentRecord.query(on: db).filter(\.$status == ApprovalEnrollmentStatus.pending.rawValue).filter(\.$expiresAt <= now).count() > 0 {
            try await ApproveEnrollmentRecord.query(on: db).filter(\.$status == ApprovalEnrollmentStatus.pending.rawValue).filter(\.$expiresAt <= now)
                .set(\.$status, to: ApprovalEnrollmentStatus.expired.rawValue).update()
        }
        try await ApproveEnrollmentService(db: db, ctx: ctx).expireUnconfirmed()
        if try await ApproveFreezeEventRecord.query(on: db).filter(\.$createdAt < cutoff).count() > 0 {
            try await ApproveFreezeEventRecord.query(on: db).filter(\.$createdAt < cutoff).delete()
        }
        return count
    }

    // MARK: Device: list and read

    func deviceRequest(delivery: ApproveDeliveryRecord, request: ApproveRequestRecord, key: ApproveKeyRecord, business: BusinessSummary,
                       verdict: ApprovalPromptPolicy.Verdict?) throws -> ApproveDeviceRequest {
        guard let subject = SubjectRef(request.subjectRef) else { throw APIError.internalError }
        var envelope: E2EEEnvelope?
        if let raw = delivery.envelope { envelope = try E2EEEnvelope.parse(Data(raw.utf8)) }
        var stored: StoredDetails?
        if let sealed = request.detailsSealed, request.protectionValue == .serverVisible {
            stored = try ViadereJSON.decode(StoredDetails.self, from: try ctx.cipher.open(sealed, context: Self.sealContext, rowId: request.id!))
        }
        var requests = 1
        var warn = false
        if case .allow(let count, let showWarning)? = verdict { requests = count; warn = showWarning }
        return ApproveDeviceRequest(id: delivery.id!, requestId: request.requestId, business: business, subjectRef: subject, capability: Capability(rawValue: request.capability),
                                    kid: key.kid, protection: request.protectionValue, status: request.statusValue, createdAt: request.createdAt, expiresAt: request.expiresAt,
                                    envelope: envelope, challenge: request.challenge, transaction: stored?.transaction, authentication: stored?.authentication,
                                    requestsInWindow: requests, showFatigueWarning: warn)
    }

    /// Pending requests for the calling device's active keys.
    func pending(principal: ConsumerPrincipal) async throws -> [ApproveDeviceRequest] {
        guard let deviceId = principal.deviceId else { throw APIError.signatureInvalid }
        let now = ctx.now
        let deliveries = try await ApproveDeliveryRecord.query(on: db).filter(\.$deviceId == deviceId.uuid).filter(\.$consumerId == principal.consumerId.uuid)
            .sort(\.$createdAt, .descending).limit(100).all()
        var out: [ApproveDeviceRequest] = []
        var summaries: [UUID: BusinessSummary] = [:]
        let freezes = ApproveFreezeService(db: db, ctx: ctx)
        for delivery in deliveries {
            guard let request = try await ApproveRequestRecord.find(delivery.requestId, on: db), request.statusValue == .pending, request.expiresAt > now,
                  let key = try await ApproveKeyRecord.query(on: db).filter(\.$kid == delivery.kid).first(), key.isActive else { continue }
            // While approvals are frozen the customer is not shown requests at all.
            if try await freezes.frozenBy(consumerId: request.consumerId, relationshipId: request.relationshipId) != nil { continue }
            if summaries[request.businessId] == nil { summaries[request.businessId] = try? await ApproveKeyService(db: db, ctx: ctx).businessSummary(request.businessId) }
            guard let summary = summaries[request.businessId] else { continue }
            let verdict = try await promptVerdictForDisplay(relationshipId: request.relationshipId, now: now)
            out.append(try deviceRequest(delivery: delivery, request: request, key: key, business: summary, verdict: verdict))
        }
        return out
    }

    /// The count and warning shown with a request: the same policy, evaluated over the history **including** this request.
    private func promptVerdictForDisplay(relationshipId: UUID, now: Date) async throws -> ApprovalPromptPolicy.Verdict {
        let policy = ctx.config.approve.prompt
        let rows = try await ApproveRequestRecord.query(on: db).filter(\.$relationshipId == relationshipId)
            .filter(\.$createdAt > now.addingTimeInterval(-policy.window)).all().filter { $0.reason != "auto_denied" }
        let count = rows.count
        return .allow(requestsInWindow: count, showWarning: count >= policy.warnAtRequests)
    }

    func get(principal: ConsumerPrincipal, deliveryId: UUID) async throws -> ApproveDeviceRequest {
        guard let deviceId = principal.deviceId,
              let delivery = try await ApproveDeliveryRecord.find(deliveryId, on: db), delivery.deviceId == deviceId.uuid, delivery.consumerId == principal.consumerId.uuid,
              let request = try await ApproveRequestRecord.find(delivery.requestId, on: db),
              let key = try await ApproveKeyRecord.query(on: db).filter(\.$kid == delivery.kid).first(), key.isActive else { throw APIError.notFound }
        let summary = try await ApproveKeyService(db: db, ctx: ctx).businessSummary(request.businessId)
        return try deviceRequest(delivery: delivery, request: request, key: key, business: summary,
                                 verdict: try await promptVerdictForDisplay(relationshipId: request.relationshipId, now: ctx.now))
    }

    // MARK: Device: the signed result

    func submit(principal: ConsumerPrincipal, deliveryId: UUID, body: SubmitApprovalResultRequest) async throws -> SubmitApprovalResultResponse {
        guard let deviceId = principal.deviceId else { throw APIError.signatureInvalid }
        let now = ctx.now
        guard let delivery = try await ApproveDeliveryRecord.find(deliveryId, on: db), delivery.deviceId == deviceId.uuid, delivery.consumerId == principal.consumerId.uuid,
              let request = try await ApproveRequestRecord.find(delivery.requestId, on: db) else { throw APIError.notFound }
        let audit = AuditService(db: db, ctx: ctx)
        func reject(_ reason: String, _ error: APIError) async throws -> Never {
            _ = try? await audit.record("approve.decision_rejected", outcome: .denied, principal: principal, businessId: BusinessID(request.businessId), subjectType: "approve_request",
                                        subjectId: request.id?.uuidString.lowercased(), metadata: ["reason": reason])
            throw error
        }
        guard request.statusValue == .pending else { try await reject("not_pending", .conflict("This request has already been resolved.")) }
        if request.expiresAt <= now {
            _ = try await finish(request, status: .expired, reason: nil, notify: true)
            try await reject("expired", .gone("This request has expired."))
        }
        guard let key = try await ApproveKeyRecord.query(on: db).filter(\.$kid == delivery.kid).first(), key.isActive, key.deviceId == deviceId.uuid,
              key.consumerId == principal.consumerId.uuid, key.relationshipId == request.relationshipId else {
            try await reject("key_not_active", APIError(.forbidden, .forbidden, "This approval key is not active."))
        }
        guard let device = try await DeviceRecord.find(deviceId.uuid, on: db), device.kind == .app, device.revokedAt == nil else {
            try await reject("device", APIError(.forbidden, .forbidden, "This device can't respond to requests."))
        }
        guard try await DirectoryService(db: db).verified(id: request.businessId) != nil else { try await reject("business_unavailable", .gone("This request is no longer available.")) }

        let parts: ApprovalResultJWS.Parts
        do { parts = try ApprovalResultJWS.parse(body.result) } catch { try await reject("malformed", .badRequest("The result could not be read.")) }
        guard parts.kid == key.kid else { try await reject("kid_mismatch", .forbidden) }
        guard let subject = SubjectRef(request.subjectRef), let publicKey = try? DevicePublicKey(base64URL: key.publicKey) else { throw APIError.internalError }
        var details: ApprovalSubject?
        if let sealed = request.detailsSealed, request.protectionValue == .serverVisible {
            details = try ViadereJSON.decode(StoredDetails.self, from: try ctx.cipher.open(sealed, context: Self.sealContext, rowId: request.id!)).subject
        }
        let capability = Capability(rawValue: request.capability)
        let required = ApprovalAMR.required(for: capability.definition?.sensitivity ?? .critical)
        let expectation = ApprovalExpectation(relayAudience: BusinessID(request.businessId), subject: subject, requestId: request.requestId, capability: capability,
                                              challenge: request.challenge, subjectDetails: details, requestExpiresAt: request.expiresAt, minimumAMR: required)
        let verified: VerifiedApproval
        do {
            verified = try ApprovalResultVerifier.verify(body.result, expecting: expectation,
                                                         keys: [EnrolledApprovalKey(kid: key.kid, publicKey: publicKey, subject: subject, assurance: key.assuranceValue)], now: now)
        } catch let error as ApprovalVerificationError {
            switch error {
            case .malformed, .unsupportedVersion, .unsupportedType, .unsupportedAlgorithm, .unknownCriticalHeader, .lifetimeTooLong:
                try await reject("malformed", .badRequest("The result could not be read."))
            case .badSignature, .unknownKey, .keyRevoked: try await reject("bad_signature", .signatureInvalid)
            case .expired: try await reject("result_expired", .gone("This result has expired."))
            case .issuedInFuture: try await reject("signed_in_future", APIError(.unauthorized, .clockSkew, "The result timestamp is invalid."))
            case .challengeMismatch, .transactionMismatch: try await reject("context_mismatch", APIError(.conflict, .contextMismatch, "This request changed. Review it again."))
            case .insufficientAuthentication, .amrExceedsKey:
                try await reject("insufficient_assurance", APIError(.forbidden, .insufficientAssurance, "This request needs stronger verification."))
            default: try await reject("binding_mismatch", .forbidden)
            }
        }
        let decision = verified.decision
        // A frozen relationship or account accepts only refusals; a device in its new-device cool-down may not approve high-risk requests.
        if decision == .approve {
            if let by = try await ApproveFreezeService(db: db, ctx: ctx).frozenBy(consumerId: request.consumerId, relationshipId: request.relationshipId) {
                try await reject("frozen", APIError(.conflict, .approvalsFrozen, "Approvals are frozen.", details: ["frozen_by": by]))
            }
            // High-risk approval needs a D1 device, or a key the business itself enrolled for this (D0) device after it existed (business
            // re-enrollment, `DeviceTrust.mayCompleteBusinessEnrollment`). Never time.
            if (capability.definition?.sensitivity ?? .critical) >= .high, !DeviceTrust.isTrusted(device, at: now) {
                let enrollment = try await ApproveEnrollmentRecord.find(key.enrollmentId, on: db)
                let businessEnrolled = enrollment.map { $0.statusValue == .confirmed && $0.createdAt >= device.createdAt } ?? false
                if !businessEnrolled {
                    try await reject("device_not_trusted", APIError(.forbidden, .deviceCoolDown,
                        "This device hasn't been approved yet. Approve it from a device you already trust, or ask the business to set it up again."))
                }
            }
        }
        let resultRef = ApproveIdentifiers.newResultRef()
        let status: ApprovalRequestStatus = decision == .approve ? .approved : (decision == .deny ? .denied : .reported)
        try await db.transaction { tx in
            let swapped = try await DB.swap(tx, table: ApproveRequestRecord.schema, id: request.id!, column: "status", expected: ApprovalRequestStatus.pending.rawValue,
                                            newValue: status.rawValue, extra: [("decided_at", now), ("decided_kid", key.kid), ("decision", decision.rawValue),
                                                                               ("amr", verified.claims.amr.rawValue), ("result_ref", resultRef), ("result_jws", body.result)])
            guard swapped else { throw APIError(.conflict, .replayDetected, "This request was already decided.") }
            try await ApproveRequestRecord.query(on: tx).filter(\.$id == request.id!).set(\.$detailsSealed, to: nil).set(\.$challenge, to: nil).update()
            guard let decided = try await ApproveRequestRecord.find(request.id!, on: tx) else { throw APIError.internalError }
            try await ApproveWebhooks(db: tx, ctx: ctx).requestDecided(decided)
            let auditService = AuditService(db: tx, ctx: ctx)
            _ = try await auditService.record("approve.request_decided", principal: principal, businessId: BusinessID(request.businessId), subjectType: "approve_request",
                                              subjectId: request.id?.uuidString.lowercased(), metadata: ["decision": decision.rawValue, "amr": verified.claims.amr.rawValue])
            if decision == .report {
                _ = try await auditService.record("approve.reported_suspicious", principal: principal, businessId: BusinessID(request.businessId), subjectType: "approve_request",
                                                  subjectId: request.id?.uuidString.lowercased())
            }
        }
        return SubmitApprovalResultResponse(id: deliveryId, status: status)
    }
}
