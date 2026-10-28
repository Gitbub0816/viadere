@preconcurrency import Crypto
import Fluent
import Foundation
import Vapor
import ViadereCore

/// Verify (WP3): verification requests from businesses, the person's consent, the Wallet and document methods, and the one-time,
/// recipient-bound result.
///
/// What it guarantees (each has a test):
/// - **Policy first.** Creating a request and exercising the disclosure both go through `PolicyService` (entitlement ∩ key scope ∩
///   consent ∩ evidence ∩ law/policy). A messaging key cannot reach any of it (acceptance 1).
/// - **Granular consent.** The person sees the verified business, the purpose, exactly what is disclosed and the expiry, and consents to
///   a digest of precisely that; the receipt is bound to this business, subject, capability, purpose and request, and is consumed by the
///   disclosure (one receipt, one disclosure).
/// - **Minimization.** Evidence lives in memory while one claim is derived; nothing but the capability's output fields leaves
///   (`CapabilityDefinition.project/violations`, acceptance 6), sealed per row until the business retrieves it once.
/// - **No oracle for the business.** Every non-positive end (under the threshold, declined, abandoned, expired, unsupported document,
///   provider outage, revoked consent) is the same `not_verified` (AGE-005).
struct VerifyService {
    let db: any Database
    let ctx: ServerContext
    let runtime: VerifyRuntime

    var settings: VerifySettings { ctx.config.verify }

    static let supportedCapabilities: [Capability] = [.ageMinimum, .identityName, .identityAddress, .identityVerified]
    /// Open requests one business may have for one customer (prompt-fatigue and spam bound).
    static let maxOpenPerSubject = 3
    /// Rows older than this (closed requests, their attempts and results) are deleted. Audit and consent receipts follow their own rules.
    static let recordRetention: TimeInterval = 400 * 86_400
    static let providerEventRetention: TimeInterval = 7 * 86_400
    /// Provider purge retries back off exponentially (30 s, 1 min, 2 min, ... capped at a day) and **never stop**: an outage of any length must
    /// not leave a document, selfie or face template at the provider. A purge that is still failing after `purgeAlertAfter` raises the
    /// `viadere_verify_provider_purge_overdue` gauge (alert: page when it is above 0 for 10 minutes).
    static let purgeBackoffBase: TimeInterval = 30
    static let purgeBackoffCap: TimeInterval = 86_400
    static let purgeAlertAfter: TimeInterval = 3_600
    static func purgeBackoff(afterFailures failures: Int) -> TimeInterval {
        min(purgeBackoffCap, purgeBackoffBase * Double(1 << min(max(0, failures - 1), 20)))
    }
    /// The chosen verification method cannot run right now (not configured, provider outage). The person can choose another.
    static var methodUnavailable: APIError { APIError(.serviceUnavailable, .unavailable, "This way of verifying is not available right now. Try another.") }

    /// The release gate: while `VERIFY_ENABLED` is off every Verify route answers `404`.
    static func requireEnabled(_ ctx: ServerContext) throws {
        guard ctx.config.verify.enabled else { throw APIError.notFound }
    }

    func limit(_ name: String, key: String, rule: RateRule) async throws {
        guard await ctx.limiter.allow(name, key: key, rule: rule) else { throw APIError.rateLimited(retryAfter: 30) }
    }

    // MARK: Business: create

    func canonicalParameters(_ parameters: [String: JSONValue]) -> String {
        String(decoding: (try? CanonicalJSON.serialize(.object(parameters))) ?? Data("{}".utf8), as: UTF8.self)
    }

    /// The jurisdictions of the business side of a request: the legal-entity jurisdiction from its approved onboarding review. Empty when
    /// the business has none on record (a block rule on a high-sensitivity capability then fails closed).
    func businessJurisdictions(_ businessId: UUID) async throws -> [String] {
        guard let row = try await BusinessOnboardingRecord.query(on: db).filter(\.$businessId == businessId).first(),
              row.legalStatus == OnboardingReview.approved.rawValue, let region = row.legalJurisdiction, PolicyAdmin.isRegion(region) else { return [] }
        return [region]
    }

    func create(principal: BusinessPrincipal, body: CreateVerificationRequest, idempotencyKey: String) async throws -> (resource: VerificationRequestResource, created: Bool) {
        let capability = body.capability
        guard Self.supportedCapabilities.contains(capability) else {
            // Everything else has its own endpoint; a bad capability here must not look like a policy answer about the customer.
            throw APIError.validation("This capability is not available through verification requests.", details: ["capability": "invalid"])
        }
        let parameters = body.parameters ?? [:]
        // 1. Policy at the business level first: key scope, entitlement ceiling, tier, kill switches, typed parameters, purpose, law/policy.
        //    A key without the capability learns nothing about the customer (acceptance 1).
        try await PolicyService(db: db, ctx: ctx).enforce(
            PolicyInput(capability, subjectRef: body.subjectRef, parameters: parameters, purpose: body.purposeCode,
                        additionalJurisdictions: try await businessJurisdictions(principal.businessId.uuid)), principal: principal, auditAllowed: false)
        try await limit("verify-create", key: principal.businessId.description, rule: settings.createRate)

        // 2. Envelope validation.
        let lifetime = body.expiresInSeconds ?? 300
        guard (VerifyPolicy.minRequestLifetime...VerifyPolicy.maxRequestLifetime).contains(lifetime) else {
            throw APIError.validation("expires_in_seconds must be between \(VerifyPolicy.minRequestLifetime) and \(VerifyPolicy.maxRequestLifetime).",
                                      details: ["expires_in_seconds": "invalid"])
        }
        let callbackId = try await resolveCallback(body.callbackId, principal: principal)
        if settings.requireEncryptedIdentity, !(capability.definition?.output.personalDataFields.isEmpty ?? true),
           try await encryptionKey(for: principal.businessId.uuid) == nil {
            throw APIError.validation("Publish an hpke-encryption key in the key directory to receive identity attributes.", details: ["encryption_key": "required"])
        }

        // 3. Idempotency (the same key and body return the same request; the same key with another body is a conflict).
        let idemHash = ctx.hasher.hmacHex("verify-idempotency", "\(principal.businessId)\n\(idempotencyKey)")
        let requestHash = SecureToken.sha256Hex(Data(("\(capability.rawValue)\n\(body.subjectRef.rawValue)\n\(canonicalParameters(parameters))\n\(body.purposeCode)\n\(callbackId?.uuidString ?? "")\n\(lifetime)").utf8))
        if let existing = try await VerificationRequestRecord.query(on: db).filter(\.$businessId == principal.businessId.uuid)
            .filter(\.$idempotencyHash == idemHash).first() {
            guard existing.requestHash == requestHash else { throw APIError.conflict("This Idempotency-Key was used with a different request.") }
            return (try resource(existing), false)
        }

        // 4. The customer: the business's own relationship (a foreign or unknown subject_ref is a plain 404), in the key's environment.
        let relationship = try await SubjectResolver(db: db, ctx: ctx).relationship(businessId: principal.businessId, subjectRef: body.subjectRef)
        guard relationship.isActive, let consumer = try await ConsumerRecord.find(relationship.consumerId, on: db), (consumer.status == "active" || consumer.isSandbox),
              consumer.isSandbox == !principal.livemode else { throw APIError.notFound }
        guard let business = try await BusinessRecord.find(principal.businessId.uuid, on: db) else { throw APIError.notFound }
        let now = ctx.now
        let open = try await VerificationRequestRecord.query(on: db).filter(\.$businessId == principal.businessId.uuid)
            .filter(\.$relationshipId == relationship.id!).filter(\.$status ~~ [ConsumerVerificationStatus.pendingConsent.rawValue,
                                                                                ConsumerVerificationStatus.consented.rawValue])
            .filter(\.$expiresAt > now).count()
        guard open < Self.maxOpenPerSubject else {
            throw APIError(.tooManyRequests, .rateLimited, "This customer already has open verification requests.", headers: ["Retry-After": "60"])
        }

        let record = VerificationRequestRecord(
            id: UUID(), businessId: principal.businessId.uuid, keyId: principal.keyId, livemode: principal.livemode, relationshipId: relationship.id!,
            consumerId: relationship.consumerId, subjectRef: body.subjectRef.rawValue, capability: capability, parameters: canonicalParameters(parameters),
            purpose: body.purposeCode, callbackId: callbackId, recipientName: business.displayName, idempotencyHash: idemHash, requestHash: requestHash,
            now: now, expiresAt: now.addingTimeInterval(TimeInterval(lifetime)))
        do {
            try await db.transaction { tx in
                try await record.create(on: tx)
                _ = try await AuditService(db: tx, ctx: ctx).record("verification.requested", actor: AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased()),
                    businessId: principal.businessId, subjectType: "verification_request", subjectId: record.requestID.description,
                    metadata: ["capability": capability.rawValue, "purpose": body.purposeCode, "subject_ref": body.subjectRef.rawValue, "expires_in": String(lifetime)])
            }
        } catch {
            if error.isConstraintViolation,
               let existing = try await VerificationRequestRecord.query(on: db).filter(\.$businessId == principal.businessId.uuid)
                .filter(\.$idempotencyHash == idemHash).first(), existing.requestHash == requestHash {
                return (try resource(existing), false)
            }
            throw error
        }
        if !principal.livemode { try await completeSandbox(record, relationship: relationship) } else { await pushRequest(record) }
        let fresh = try await VerificationRequestRecord.find(record.id, on: db) ?? record
        return (try resource(fresh), true)
    }

    /// `callback_id` is an identifier of a webhook endpoint the business registered and verified, never a URL.
    private func resolveCallback(_ raw: String?, principal: BusinessPrincipal) async throws -> UUID? {
        guard let raw else { return nil }
        guard let id = UUID(uuidString: raw), raw.count == 36,
              let subscription = try await WebhookSubscriptionRecord.query(on: db).filter(\.$id == id).filter(\.$businessId == principal.businessId.uuid)
                .filter(\.$active == true).first(),
              subscription.events.split(separator: ",").contains(where: { String($0) == WebhookEventType.verificationCompleted.rawValue }) else {
            throw APIError.validation("callback_id must name a registered webhook endpoint that subscribes to verification.completed.", details: ["callback_id": "invalid"])
        }
        return id
    }

    /// The business's current `hpke-encryption` key from the authenticated key directory, if it has published one.
    func encryptionKey(for businessId: UUID) async throws -> E2EEPublicKey? {
        let state = try await KeyLogService(db: db, ctx: ctx).state(for: businessId)
        return state.validKeys(for: .hpkeEncryption, at: ctx.now).first?.encryptionKey
    }

    func resource(_ record: VerificationRequestRecord) throws -> VerificationRequestResource {
        guard let ref = SubjectRef(record.subjectRef) else { throw APIError.internalError }
        let done = record.resultId != nil && !record.consumerStatus.isOpen
        return VerificationRequestResource(
            requestId: record.requestID, capability: record.capabilityValue, subjectRef: ref, purposeCode: record.purpose, status: done ? .completed : .pending,
            createdAt: record.createdAt, expiresAt: record.expiresAt, resultRef: done ? resultRef(for: record.requestID) : nil)
    }

    /// The result reference of a request: derived, so it can be shown again in the request resource, and unguessable without the
    /// server's key. It retrieves nothing on its own (retrieval is bound to the owning business's credential).
    func resultRef(for id: VerificationRequestID) -> VerificationResultRef {
        let bytes = Hex.decode(ctx.hasher.hmacHex("verify-result-ref", id.description)) ?? Data()
        return VerificationResultRef(VerificationResultRef.prefix + Base64URL.encode(bytes))
            ?? VerificationResultRef.generate()
    }

    // MARK: Business: read

    func request(principal: BusinessPrincipal, id: VerificationRequestID) async throws -> VerificationRequestResource {
        guard let record = try await VerificationRequestRecord.query(on: db).filter(\.$id == id.uuid)
            .filter(\.$businessId == principal.businessId.uuid).filter(\.$livemode == principal.livemode).first() else { throw APIError.notFound }
        try await PolicyService(db: db, ctx: ctx).enforce(PolicyInput(record.capabilityValue, parameters: record.parameterValues, purpose: record.purpose,
                                                                      additionalJurisdictions: try await businessJurisdictions(principal.businessId.uuid)), principal: principal, auditAllowed: false)
        // A request past its expiry that nobody finished is finished now, so the business never waits on the sweeper.
        if record.consumerStatus.isOpen, ctx.now >= record.expiresAt { try await close(record, status: .expired, reason: "expired") }
        let fresh = try await VerificationRequestRecord.find(record.id, on: db) ?? record
        return try resource(fresh)
    }

    // MARK: Business: retrieve (single use, recipient-bound)

    func retrieve(principal: BusinessPrincipal, ref: VerificationResultRef) async throws -> VerificationResult {
        let hash = SecureToken.sha256Hex(Data(ref.rawValue.utf8))
        // Tenant-scoped: another business's result is a plain 404 even with the right reference (acceptance 2).
        guard let row = try await VerificationResultRecord.query(on: db).filter(\.$refHash == hash).filter(\.$businessId == principal.businessId.uuid).first(),
              let request = try await VerificationRequestRecord.find(row.requestId, on: db), request.livemode == principal.livemode else { throw APIError.notFound }
        let capability = request.capabilityValue
        try await PolicyService(db: db, ctx: ctx).enforce(PolicyInput(capability, parameters: request.parameterValues, purpose: request.purpose,
                                                                      additionalJurisdictions: try await businessJurisdictions(principal.businessId.uuid)), principal: principal, auditAllowed: false)
        try await limit("verify-result", key: principal.businessId.description, rule: .perMinute(120, burst: 60))
        let now = ctx.now
        guard row.retrievedAt == nil, now < row.expiresAt else { throw APIError.gone("This result was already retrieved or has expired.") }
        guard let subjectRef = SubjectRef(request.subjectRef), let outcome = VerificationOutcome(rawValue: row.outcome), let definition = capability.definition else {
            throw APIError.internalError
        }
        var values: [String: JSONValue] = [:]
        if outcome == .verified {
            guard let sealed = row.payload, let data = try? ctx.cipher.open(sealed, context: "verification_results.payload", rowId: row.id!),
                  case .object(let object)? = try? JSONDecoder().decode(JSONValue.self, from: data) else { throw APIError.internalError }
            values = object
        }
        // Acceptance 6: only the capability's own output fields ever leave. A producer bug is a refusal, not a leak.
        guard definition.violations(in: values).isEmpty else {
            ctx.logger.error("verification result violated its output schema")
            throw APIError.internalError
        }
        // Single use: whoever flips `retrieved_at` first gets the payload; the payload is erased right after.
        guard try await DB.swapFromNull(db, table: VerificationResultRecord.schema, id: row.id!, column: "retrieved_at", newValue: now) else {
            throw APIError.gone("This result was already retrieved or has expired.")
        }
        row.payload = nil
        row.retrievedAt = now
        try await row.update(on: db)
        _ = try? await AuditService(db: db, ctx: ctx).record("verification.result_retrieved", actor: AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased()),
            businessId: principal.businessId, subjectType: "verification_request", subjectId: request.requestID.description,
            metadata: ["capability": capability.rawValue, "outcome": outcome.rawValue])
        let encrypted = row.encryptedPayload
        let encryptedKid = row.encryptedKid
        row.encryptedPayload = nil
        row.encryptedKid = nil
        try await row.update(on: db)
        return VerificationResult(resultRef: ref, requestId: request.requestID, capability: capability, subjectRef: subjectRef, parameters: request.parameterValues,
                                  createdAt: row.createdAt, outcome: outcome, result: values, encryptedResult: encrypted, encryptedResultKid: encryptedKid)
    }

    // MARK: Consumer: read

    func ownRequest(_ consumer: ConsumerID, _ id: VerificationRequestID) async throws -> VerificationRequestRecord {
        guard let record = try await VerificationRequestRecord.query(on: db).filter(\.$id == id.uuid).filter(\.$consumerId == consumer.uuid).first() else {
            throw APIError.notFound
        }
        return record
    }

    func prompt(for record: VerificationRequestRecord) async throws -> VerificationPrompt {
        guard let business = try await BusinessRecord.find(record.businessId, on: db), let definition = record.capabilityValue.definition else { throw APIError.notFound }
        let handle = try await DirectoryService(db: db).summary(for: business)?.handle
        let parameters = record.parameterValues
        let fields = definition.disclosedClaimFields
        let digest = VerificationPrompt.displayDigest(requestId: record.requestID, businessId: BusinessID(record.businessId), recipientName: record.recipientName,
                                                      capability: record.capabilityValue, parameters: parameters, purposeCode: record.purpose, fields: fields,
                                                      expiresAt: record.expiresAt)
        var status = record.consumerStatus
        if status.isOpen, ctx.now >= record.expiresAt { status = .expired }
        return VerificationPrompt(
            id: record.requestID, status: status, businessId: BusinessID(record.businessId), recipientName: record.recipientName, recipientHandle: handle.map { "@\($0)" },
            recipientVerified: business.isVerified, capability: record.capabilityValue, parameters: parameters, purposeCode: record.purpose,
            disclosure: VerificationPromptContent.disclosure(for: record.capabilityValue, parameters: parameters),
            notDisclosed: VerificationPromptContent.notDisclosed(for: record.capabilityValue), includedMetadata: VerificationPromptContent.metadata,
            methods: methods(for: record), createdAt: record.createdAt, expiresAt: record.expiresAt, displayDigest: digest, receiptId: record.receiptId)
    }

    func methods(for record: VerificationRequestRecord) -> [VerificationMethodOption] {
        [VerificationMethodOption(kind: .wallet, available: record.livemode && runtime.walletAvailable(settings: settings, now: ctx.now)),
         VerificationMethodOption(kind: .document, available: record.livemode && runtime.documentAvailable(settings: settings))]
    }

    func list(consumer: ConsumerID) async throws -> VerificationListResponse {
        let now = ctx.now
        let open = [ConsumerVerificationStatus.pendingConsent.rawValue, ConsumerVerificationStatus.consented.rawValue]
        let pending = try await VerificationRequestRecord.query(on: db).filter(\.$consumerId == consumer.uuid).filter(\.$livemode == true)
            .filter(\.$status ~~ open).filter(\.$expiresAt > now).sort(\.$createdAt, .descending).limit(20).all()
        var prompts: [VerificationPrompt] = []
        for record in pending { prompts.append(try await prompt(for: record)) }
        let past = try await VerificationRequestRecord.query(on: db).filter(\.$consumerId == consumer.uuid).filter(\.$livemode == true)
            .sort(\.$createdAt, .descending).limit(50).all().filter { !($0.consumerStatus.isOpen && $0.expiresAt > now) }
        return VerificationListResponse(pending: prompts, history: past.map { historyItem($0) })
    }

    func historyItem(_ record: VerificationRequestRecord) -> VerificationHistoryItem {
        var status = record.consumerStatus
        if status.isOpen, ctx.now >= record.expiresAt { status = .expired }
        return VerificationHistoryItem(
            id: record.requestID, recipientName: record.recipientName, capability: record.capabilityValue, purposeCode: record.purpose, status: status,
            requestedAt: record.createdAt, decidedAt: record.decidedAt, receiptId: record.receiptId,
            revocable: status == .consented && record.receiptId != nil,
            disclosedFields: record.disclosedFields.map { $0.split(separator: ",").map(String.init) } ?? [],
            label: record.label.flatMap(VerificationLabel.init(rawValue:)))
    }

    // MARK: Consumer: consent, decline, revoke

    func consent(consumer: ConsumerID, id: VerificationRequestID, digest: String) async throws -> VerificationPrompt {
        try await limit("verify-consent", key: consumer.description, rule: settings.attemptRate)
        let record = try await ownRequest(consumer, id)
        guard record.consumerStatus == .pendingConsent else { throw APIError.conflict("This request was already answered.") }
        guard ctx.now < record.expiresAt else { throw APIError.gone("This request has expired.") }
        let shown = try await prompt(for: record)
        // What the person saw must be exactly what will be released.
        guard ConstantTime.equals(Data(shown.displayDigest.utf8), Data(digest.utf8)) else {
            throw APIError.conflict("This request changed. Review it again.")
        }
        let receipts = DisclosureReceiptService(db: db, ctx: ctx)
        let lifetime = max(1, record.expiresAt.timeIntervalSince(ctx.now))
        let receipt: DisclosureReceipt
        do {
            receipt = try await receipts.grant(consumer: consumer, relationshipId: RelationshipID(record.relationshipId), capability: record.capabilityValue,
                                               purpose: record.purpose, requestId: id.description, lifetime: lifetime)
        } catch let error as APIError where error.status == .conflict {
            throw error
        }
        guard try await DB.swap(db, table: VerificationRequestRecord.schema, id: record.id!, column: "status", expected: ConsumerVerificationStatus.pendingConsent.rawValue,
                                newValue: ConsumerVerificationStatus.consented.rawValue, extra: [("receipt_id", receipt.id)]) else {
            try? await receipts.revoke(consumer: consumer, receiptId: receipt.id)
            throw APIError.conflict("This request was already answered.")
        }
        return try await prompt(for: try await ownRequest(consumer, id))
    }

    func decline(consumer: ConsumerID, id: VerificationRequestID) async throws {
        let record = try await ownRequest(consumer, id)
        guard record.consumerStatus.isOpen else { return }
        if let receipt = record.receiptId { try? await DisclosureReceiptService(db: db, ctx: ctx).revoke(consumer: consumer, receiptId: receipt) }
        try await close(record, status: .declined, reason: "declined")
    }

    func revoke(consumer: ConsumerID, id: VerificationRequestID) async throws -> VerificationHistoryItem {
        let record = try await ownRequest(consumer, id)
        guard let receipt = record.receiptId else { throw APIError.conflict("There is nothing to withdraw.") }
        if record.consumerStatus == .released { throw APIError.conflict("This disclosure was already made.") }
        // Throws a conflict when the receipt was already used; otherwise the receipt can no longer authorize a disclosure.
        try await DisclosureReceiptService(db: db, ctx: ctx).revoke(consumer: consumer, receiptId: receipt)
        if record.consumerStatus.isOpen { try await close(record, status: .revoked, reason: "revoked") }
        return historyItem(try await ownRequest(consumer, id))
    }

    // MARK: Concluding a request

    /// The person-facing outcome after an attempt that did not conclude the request.
    func outcome(_ record: VerificationRequestRecord, retry: Bool = false) -> VerificationAttemptOutcome {
        VerificationAttemptOutcome(status: record.consumerStatus, label: record.label.flatMap(VerificationLabel.init(rawValue:)), receiptId: record.receiptId,
                                   canRetry: retry && record.consumerStatus == .consented && record.attemptCount < VerifyPolicy.maxAttemptsPerRequest && ctx.now < record.expiresAt)
    }

    /// Claims the right to conclude (compare-and-swap on `result_id`): exactly one caller wins. The winner must persist a result.
    private func claim(_ record: VerificationRequestRecord) async throws -> UUID? {
        let resultId = UUID()
        guard try await DB.swapFromNull(db, table: VerificationRequestRecord.schema, id: record.id!, column: "result_id", newValue: resultId) else { return nil }
        return resultId
    }

    /// Ends the request with a `not_verified` result (declined, expired, revoked, exhausted, denied by policy). The business learns only
    /// `not_verified` (AGE-005); the person's own history keeps the reason.
    func close(_ record: VerificationRequestRecord, status: ConsumerVerificationStatus, reason: String) async throws {
        guard let resultId = try await claim(record) else { return }
        try await persist(record, resultId: resultId, outcome: .notVerified, status: status, built: nil, reason: reason)
    }

    /// Persists the result row, the final request state and the webhook, in one transaction.
    private func persist(_ record: VerificationRequestRecord, resultId: UUID, outcome: VerificationOutcome, status: ConsumerVerificationStatus,
                         built: ClaimsBuilder.Built?, reason: String) async throws {
        let now = ctx.now
        let ref = resultRef(for: record.requestID)
        let validity = outcome == .verified ? (built.map { $0.provenance.expiresAt } ?? now.addingTimeInterval(VerifyPolicy.resultValidity))
                                            : now.addingTimeInterval(VerifyPolicy.resultValidity)
        let row = VerificationResultRecord(id: resultId, requestId: record.id!, businessId: record.businessId, refHash: SecureToken.sha256Hex(Data(ref.rawValue.utf8)),
                                           outcome: outcome, now: now, expiresAt: validity)
        if let built {
            var clear = built.values
            // Identity attributes are sealed to the business's published HPKE key when it has one: the database then holds ciphertext that
            // Viadere cannot open (the relay-compromise property of acceptance 4). The non-personal fields stay readable.
            let personal = Set(record.capabilityValue.definition?.output.personalDataFields ?? [])
            if !personal.isEmpty, let key = try await encryptionKey(for: record.businessId) {
                var sensitive: [String: JSONValue] = [:]
                for name in personal { sensitive[name] = clear.removeValue(forKey: name) }
                let context = E2EEContext(purpose: VerificationResult.e2eePurpose, requestId: record.requestID.description, sender: VerificationResult.e2eeSender,
                                          recipient: VerificationResult.e2eeRecipient(BusinessID(record.businessId)), expiresAt: validity)
                let envelope = try E2EE.seal(try CanonicalJSON.serialize(.object(sensitive)), to: key, context: context)
                row.encryptedPayload = Base64URL.encode(try envelope.serialized())
                row.encryptedKid = key.kid
            }
            row.payload = try ctx.cipher.seal(try CanonicalJSON.serialize(.object(clear)), context: "verification_results.payload", rowId: resultId)
            row.provenance = String(decoding: try ViadereJSON.encode(built.provenance), as: UTF8.self)
        }
        try await db.transaction { tx in
            try await row.create(on: tx)
            record.status = status.rawValue
            record.decidedAt = now
            record.label = built?.label.rawValue
            record.disclosedFields = built.map { Array($0.values.keys.filter { !(["assurance", "issued_at", "expires_at", "audience"].contains($0)) }).sorted().joined(separator: ",") }
            try await record.update(on: tx)
            // AGE-005: the business-scoped event is the same for every end of the same polarity (no reason, status, label or method);
            // the detail goes to the platform-only trail, which has no business id and is never rendered to a business.
            _ = try await AuditService(db: tx, ctx: ctx).record("verification.completed", outcome: outcome == .verified ? .success : .failure,
                actor: AuditActor(kind: .system, id: "verify"), consumerId: ConsumerID(record.consumerId), businessId: BusinessID(record.businessId),
                subjectType: "verification_request", subjectId: record.requestID.description,
                metadata: ["capability": record.capability, "outcome": outcome.rawValue])
            _ = try await AuditService(db: tx, ctx: ctx).record("verification.concluded", outcome: outcome == .verified ? .success : .failure,
                actor: AuditActor(kind: .system, id: "verify"), consumerId: ConsumerID(record.consumerId),
                subjectType: "verification_request", subjectId: record.requestID.description,
                metadata: ["capability": record.capability, "outcome": outcome.rawValue, "status": status.rawValue, "reason": reason,
                           "label": built?.label.rawValue ?? "none", "method": built?.provenance.method.rawValue ?? "none",
                           "policy_version": VerifyPolicy.version])
            if let callback = record.callbackId {
                try await WebhookService(db: tx, ctx: ctx).enqueue(.verificationCompleted, businessId: BusinessID(record.businessId),
                    payload: VerificationCompletedEventData(requestId: record.requestID, resultRef: ref), onlySubscription: callback,
                    opaque: OpaqueWebhookEvent(requestId: record.requestID.description, resultRef: ref.rawValue))
            }
        }
    }

    /// Concludes a request whose evidence was verified: `built == nil` means the evidence did not support the claim (under the threshold,
    /// missing attribute). Releases the disclosure only through `PolicyService.authorizeDisclosure`, which consumes the receipt.
    func conclude(_ record: VerificationRequestRecord, claims: EvidenceClaims?, source: String) async throws -> VerificationAttemptOutcome {
        let now = ctx.now
        // The release gate is also a kill switch: with Verify switched off nothing is disclosed, even for a request already in flight.
        guard settings.enabled else {
            if record.consumerStatus.isOpen { try await close(record, status: .notVerified, reason: "verify_disabled") }
            return outcome(try await VerificationRequestRecord.find(record.id, on: db) ?? record)
        }
        guard record.consumerStatus == .consented, now < record.expiresAt else {
            if record.consumerStatus.isOpen { try await close(record, status: .expired, reason: "expired") }
            return outcome(try await VerificationRequestRecord.find(record.id, on: db) ?? record)
        }
        let capability = record.capabilityValue
        let audience = BusinessID(record.businessId)
        // A simulated (sandbox) result can never conclude a live request.
        let usable = claims.flatMap { $0.method == .sandbox && record.livemode ? nil : $0 }
        guard let claims = usable, let built = ClaimsBuilder.build(capability: capability, parameters: record.parameterValues, claims: claims, audience: audience, now: now) else {
            // The evidence does not support the claim. Nothing is disclosed, the receipt stays unused, and the person may try another
            // method while attempts remain. Out of attempts: the request ends as not_verified.
            let fresh = try await VerificationRequestRecord.find(record.id, on: db) ?? record
            if fresh.attemptCount >= VerifyPolicy.maxAttemptsPerRequest {
                try await close(fresh, status: .notVerified, reason: "attempts_exhausted")
                return outcome(try await VerificationRequestRecord.find(record.id, on: db) ?? fresh)
            }
            return outcome(fresh, retry: true)
        }
        // Claim the conclusion before any disclosure: one winner per request.
        guard let resultId = try await claim(record) else { return outcome(try await VerificationRequestRecord.find(record.id, on: db) ?? record) }
        guard let principal = try await principal(for: record), let relationship = try await RelationshipRecord.find(record.relationshipId, on: db),
              let holding = built.provenance.evidenceHolding(), let subjectRef = SubjectRef(record.subjectRef) else {
            try await persist(record, resultId: resultId, outcome: .notVerified, status: .notVerified, built: nil, reason: "key_unavailable")
            return outcome(try await VerificationRequestRecord.find(record.id, on: db) ?? record)
        }
        // Jurisdiction (F4): evaluated again here, now that the document's issuing country is known. Both the business's legal-entity
        // jurisdiction and the issuer's country count; an issuer that cannot be established fails block rules closed (live requests).
        let issuer = claims.issuerCountry
        let input = PolicyInput(capability, subjectRef: subjectRef, parameters: record.parameterValues, purpose: record.purpose,
                                additionalJurisdictions: try await businessJurisdictions(record.businessId) + [issuer].compactMap { $0 },
                                jurisdictionIncomplete: record.livemode && issuer == nil, requestId: record.requestID.description)
        let decision = try await PolicyService(db: db, ctx: ctx, platformOnlyDenials: true).authorizeDisclosure(input, principal: principal, relationship: relationship, evidence: [holding])
        guard decision.allowed else {
            // Revoked receipt, withdrawn entitlement, switched-off capability, ...: the same `not_verified` for the business.
            try await persist(record, resultId: resultId, outcome: .notVerified, status: .notVerified, built: nil, reason: "policy_" + (decision.primaryReason?.rawValue ?? "denied"))
            return outcome(try await VerificationRequestRecord.find(record.id, on: db) ?? record)
        }
        try await persist(record, resultId: resultId, outcome: .verified, status: .released, built: built, reason: source)
        return outcome(try await VerificationRequestRecord.find(record.id, on: db) ?? record)
    }

    /// The business principal the disclosure is evaluated for: the creating key, **if it is still valid**. A revoked or expired key
    /// cannot release a disclosure that was requested before.
    func principal(for record: VerificationRequestRecord) async throws -> BusinessPrincipal? {
        guard let key = try await BusinessAPIKeyRecord.find(record.keyId, on: db), key.businessId == record.businessId, key.revokedAt == nil,
              (key.expiresAt ?? .distantFuture) > ctx.now, key.livemode == record.livemode,
              let business = try await BusinessRecord.find(record.businessId, on: db) else { return nil }
        return BusinessPrincipal(businessId: BusinessID(record.businessId), keyId: record.keyId, livemode: key.livemode, scopes: key.scopeSet,
                                 businessName: business.displayName, capabilities: key.capabilitySet)
    }

    // MARK: Platform-only trail

    /// Detailed Verify events (attempts, reasons, methods, consent, provider purge) go to the platform-only trail: **no business id**, so
    /// no business-facing view or export can ever contain them (AGE-005: a business must not tell "under the threshold" from "declined"
    /// or "expired"). The request id in `subject_id` lets the platform correlate; the consumer id is platform-internal.
    @discardableResult
    func platformAudit(_ action: String, _ record: VerificationRequestRecord, metadata: [String: String] = [:], outcome: AuditEvent.Outcome = .success,
                       on database: (any Database)? = nil) async -> Bool {
        (try? await AuditService(db: database ?? db, ctx: ctx).record(action, outcome: outcome, actor: AuditActor(kind: .consumer, id: record.consumerId.uuidString.lowercased()),
            consumerId: ConsumerID(record.consumerId), subjectType: "verification_request", subjectId: record.requestID.description, metadata: metadata)) != nil
    }

    // MARK: Push

    /// Best-effort generic push: no business data, no request details (the app fetches them over the authenticated API).
    func pushRequest(_ record: VerificationRequestRecord) async {
        do {
            let devices = try await DeviceRecord.query(on: db).filter(\.$consumerId == record.consumerId).filter(\.$revokedAt == nil).all()
            let tokens = try await APNsTokenRecord.query(on: db).filter(\.$deviceId ~~ devices.compactMap(\.id)).filter(\.$invalidatedAt == nil).all()
            for token in tokens {
                let message = PushMessage(deviceToken: token.record.token, environment: token.record.environment,
                                          topic: token.record.bundleId.isEmpty ? ctx.config.appBundleID : token.record.bundleId, title: PushPayloadBuilder.genericTitle,
                                          body: "A verified business sent a request. Open to review it.", category: "viadere.verification.request",
                                          threadID: "viadere.verification", interruptionLevel: "active", mutableContent: true,
                                          interactionId: record.requestID.description, highPriority: true)
                if await ctx.apns.send(message) == .tokenInvalid {
                    try await APNsTokenRecord.query(on: db).filter(\.$id == token.id!).set(\.$invalidatedAt, to: ctx.now).update()
                }
            }
        } catch {
            // Push is best effort; the request stays available in the app.
        }
    }
}
