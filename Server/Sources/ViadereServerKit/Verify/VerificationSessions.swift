import Fluent
import Foundation
import Vapor
import ViadereCore

/// One verification session ("Verify with Viadere", `docs/SECURITY.md` §2.60). The code is stored only as a keyed hash.
final class VerificationSessionRecord: Model, @unchecked Sendable {
    static let schema = "verification_sessions"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    /// The key that created it: the disclosure is evaluated again with this key when the app accepts (a revoked key opens nothing).
    @Field(key: "api_key_id") var apiKeyId: UUID
    @Field(key: "livemode") var livemode: Bool
    @Field(key: "code_hash") var codeHash: String
    @Field(key: "capability") var capability: String
    /// Canonical JSON of the capability parameters.
    @Field(key: "parameters") var parameters: String
    @Field(key: "purpose") var purpose: String
    /// Canonical origin (`https://shop.example`), inside `business_domain`.
    @Field(key: "origin") var origin: String
    /// The business's verified domain the origin was matched against when the session was created (the descriptor names it).
    @Field(key: "business_domain") var businessDomain: String
    @OptionalField(key: "return_url") var returnURL: String?
    @OptionalField(key: "callback_id") var callbackId: UUID?
    @Field(key: "status") var status: String
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "consumer_id") var consumerId: UUID?
    @OptionalField(key: "device_id") var deviceId: UUID?
    @OptionalField(key: "subject_ref") var subjectRef: String?
    @OptionalField(key: "relationship_id") var relationshipId: UUID?
    @OptionalField(key: "request_id") var requestId: UUID?
    @OptionalField(key: "accepted_at") var acceptedAt: Date?
    /// JSON of Viadere's signed `VerificationSessionResult` (`ViadereSignedStatement`).
    @OptionalField(key: "result") var result: String?
    @OptionalField(key: "completed_at") var completedAt: Date?
    @OptionalField(key: "cancelled_at") var cancelledAt: Date?
    /// Why a session ended without a result: `cancelled`, `accept_failed`.
    @OptionalField(key: "ended_reason") var endedReason: String?

    init() {}

    var statusValue: VerificationSessionStatus { VerificationSessionStatus(rawValue: status) ?? .unknown }
    var capabilityValue: Capability { Capability(rawValue: capability) }
    var parameterValues: [String: JSONValue] { (try? ViadereJSON.decode(JSONValue.self, from: Data(parameters.utf8)))?.objectValue ?? [:] }
    var signedResult: ViadereSignedStatement? { result.flatMap { try? ViadereJSON.decode(ViadereSignedStatement.self, from: Data($0.utf8)) } }
}

/// Verification sessions: the server side of the "Verify with Viadere" button (`docs/VERIFY-BUTTON.md`, `docs/SECURITY.md` §2.60).
///
/// 1. The business's **server** creates a ≤ 5 min, single-use session for one Verify capability it is entitled to, on one web origin inside one
///    of its **verified domains** (live keys only).
/// 2. The app looks the code up (rationed per account and globally, every failure the same `404`) and receives a descriptor **signed by Viadere's
///    `link-descriptor` key** naming the verified business, its verified domain, the origin, the capability, the purpose and the account's pairwise
///    reference. The app shows the business and the origin and asks the person.
/// 3. The app accepts by quoting the digest of the descriptor it showed. The session is consumed by compare-and-swap; the policy is evaluated again
///    with the creating key; the account is connected to the business (the app said so before) and an **ordinary verification request** is
///    opened. Consent (display digest), the disclosure receipt, the evidence and the release then run exactly as for any verification request.
/// 4. When that request ends (released, not verified, declined, expired, revoked), Viadere signs a `VerificationSessionResult` (outcome only,
///    no personal data) that the business fetches with its key and verifies against the keys it pinned. The browser is never trusted.
struct VerificationSessionService {
    let db: any Database
    let ctx: ServerContext
    let runtime: VerifyRuntime

    static let codeContext = "verification-session-code"
    var verify: VerifyService { VerifyService(db: db, ctx: ctx, runtime: runtime) }
    var settings: VerifySettings { ctx.config.verify }

    func codeHash(_ canonical: String) -> String { ctx.hasher.hmacHex(Self.codeContext, canonical) }

    /// A parameter the descriptor can carry: a lower-case snake_case name and a string, integer or boolean value.
    static func isFlatParameter(name: String, value: JSONValue) -> Bool {
        guard (1...32).contains(name.utf8.count), name.utf8.first.map({ $0 >= 0x61 && $0 <= 0x7A }) == true,
              name.utf8.allSatisfy({ ($0 >= 0x61 && $0 <= 0x7A) || ($0 >= 0x30 && $0 <= 0x39) || $0 == 0x5F }) else { return false }
        switch value {
        case .string, .integer, .bool: return true
        default: return false
        }
    }

    // MARK: Business: create

    func create(principal: BusinessPrincipal, request: CreateVerificationSessionRequest) async throws -> VerificationSessionTicket {
        try Sandbox.requireLive(principal, "create verification sessions")
        let capability = request.capability
        guard VerifyService.supportedCapabilities.contains(capability) else {
            throw APIError.validation("This capability is not available through verification sessions.", details: ["capability": "invalid"])
        }
        guard VerificationPurposeCode.isValid(request.purposeCode) else {
            throw APIError.validation("purpose_code must be a snake_case identifier.", details: ["purpose_code": "invalid"])
        }
        let parameters = request.parameters ?? [:]
        guard parameters.count <= VerificationSessionLimits.maxParameters, parameters.allSatisfy({ Self.isFlatParameter(name: $0.key, value: $0.value) }) else {
            throw APIError.validation("parameters must be a flat object of the capability's typed parameters.", details: ["parameters": "invalid"])
        }
        guard let origin = VerificationSessionOrigin.canonical(request.origin) else {
            throw APIError.validation("origin must be an https origin such as https://shop.example (no path, no port).", details: ["origin": "invalid"])
        }
        var returnURL: String?
        if let raw = request.returnURL {
            guard let valid = VerificationSessionOrigin.validReturnURL(raw, origin: origin) else {
                throw APIError.validation("return_url must be an https URL on the session's origin.", details: ["return_url": "invalid"])
            }
            returnURL = valid
        }
        let lifetime = request.expiresInSeconds ?? VerificationSessionLimits.defaultLifetime
        guard (VerificationSessionLimits.minLifetime...VerificationSessionLimits.maxLifetime).contains(lifetime) else {
            throw APIError.validation("expires_in_seconds must be between 60 and 300.", details: ["expires_in_seconds": "invalid"])
        }
        // Policy at the business level first (key capability, entitlement ceiling, tier, kill switches, typed parameters, purpose, law/policy):
        // a key without the capability learns nothing.
        try await PolicyService(db: db, ctx: ctx).enforce(
            PolicyInput(capability, parameters: parameters, purpose: request.purposeCode,
                        additionalJurisdictions: try await verify.businessJurisdictions(principal.businessId.uuid)), principal: principal, auditAllowed: false)
        try await verify.limit("verify-session-create", key: principal.businessId.description, rule: settings.createRate)
        guard try await DirectoryService(db: db).verified(id: principal.businessId.uuid) != nil else { throw APIError.forbidden }
        // Origin binding: the button may only be shown on the business's own verified domain (or a subdomain). The app shows the origin and the
        // signed result names it, so a session made for one site is never presented as another's.
        let domains = try await BusinessDomainRecord.query(on: db).filter(\.$businessId == principal.businessId.uuid).filter(\.$status == "verified").all()
        guard let domain = domains.compactMap({ ($0.verifiedDomain ?? $0.domain).lowercased() }).sorted().first(where: { VerificationSessionOrigin.isWithin(origin, domain: $0) }) else {
            throw APIError.validation("origin must be one of your verified domains or a subdomain of one.", details: ["origin": "not_verified_domain"])
        }
        let callbackId = try await verify.resolveCallback(request.callbackId, principal: principal)
        if settings.requireEncryptedIdentity, !(capability.definition?.output.personalDataFields.isEmpty ?? true),
           try await verify.encryptionKey(for: principal.businessId.uuid) == nil {
            throw APIError.validation("Publish an hpke-encryption key in the key directory to receive identity attributes.", details: ["encryption_key": "required"])
        }

        let now = ctx.now
        var created: VerificationSessionRecord?
        var code = ""
        for _ in 0..<5 {
            code = VerificationSessionCode.generate()
            let record = VerificationSessionRecord()
            record.id = UUID()
            record.businessId = principal.businessId.uuid
            record.apiKeyId = principal.keyId
            record.livemode = principal.livemode
            record.codeHash = codeHash(code)
            record.capability = capability.rawValue
            record.parameters = verify.canonicalParameters(parameters)
            record.purpose = request.purposeCode
            record.origin = origin
            record.businessDomain = domain
            record.returnURL = returnURL
            record.callbackId = callbackId
            record.status = VerificationSessionStatus.open.rawValue
            record.createdAt = now
            record.expiresAt = now.addingTimeInterval(TimeInterval(lifetime))
            do {
                try await record.create(on: db)
                created = record
                break
            } catch where error.isConstraintViolation { continue }
        }
        guard let session = created, let id = session.id else { throw APIError.internalError }
        _ = try await AuditService(db: db, ctx: ctx).record("verification_session.created", actor: AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased()),
            businessId: principal.businessId, subjectType: "verification_session", subjectId: id.uuidString.lowercased(),
            metadata: ["capability": capability.rawValue, "purpose": request.purposeCode, "origin": origin, "lifetime": String(lifetime)])
        return VerificationSessionTicket(sessionId: id, code: code, link: VerificationSessionLink.build(code: code, domain: ctx.config.linkDomain), expiresAt: session.expiresAt)
    }

    // MARK: Business: read, cancel

    /// The calling business's own session; anything else (another tenant's id, another environment) is the same `404`.
    func record(id: UUID, principal: BusinessPrincipal) async throws -> VerificationSessionRecord {
        guard let record = try await VerificationSessionRecord.query(on: db).filter(\.$id == id).filter(\.$businessId == principal.businessId.uuid).first(),
              record.livemode == principal.livemode else { throw APIError.notFound }
        return record
    }

    func businessView(_ stored: VerificationSessionRecord) async throws -> VerificationSessionView {
        var record = stored
        // A request that ended while the signature could not be made (a KMS hiccup) is completed here, on read.
        if record.statusValue == .accepted, let id = record.id {
            try await completeIfConcluded(record)
            record = try await VerificationSessionRecord.find(id, on: db) ?? record
        }
        var status = record.statusValue
        if status == .open, record.expiresAt <= ctx.now { status = .expired }
        let requestId = record.requestId.map(VerificationRequestID.init)
        let completed = status == .completed
        return VerificationSessionView(sessionId: record.id!, status: status, capability: record.capabilityValue, purposeCode: record.purpose, origin: record.origin,
                                       createdAt: record.createdAt, expiresAt: record.expiresAt, requestId: requestId,
                                       subjectRef: record.subjectRef.flatMap { SubjectRef($0) },
                                       resultRef: completed ? requestId.map { verify.resultRef(for: $0) } : nil,
                                       result: completed ? record.signedResult : nil, completedAt: record.completedAt)
    }

    /// Ends an open session. An accepted one is the person's verification now and runs to its result.
    func cancel(principal: BusinessPrincipal, id: UUID) async throws -> VerificationSessionRecord {
        let record = try await record(id: id, principal: principal)
        if record.statusValue == .open,
           try await DB.swap(db, table: VerificationSessionRecord.schema, id: id, column: "status", expected: VerificationSessionStatus.open.rawValue,
                             newValue: VerificationSessionStatus.cancelled.rawValue, extra: [("cancelled_at", ctx.now), ("ended_reason", "cancelled")]) {
            _ = try await AuditService(db: db, ctx: ctx).record("verification_session.cancelled", actor: AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased()),
                businessId: principal.businessId, subjectType: "verification_session", subjectId: id.uuidString.lowercased())
        }
        return try await self.record(id: id, principal: principal)
    }

    // MARK: Device: lookup

    /// The signed descriptor of one session, for the account that asks. Wrong codes are rationed per account and globally, and every failure is
    /// the same `404` (no oracle on whether a code exists, expired, was used or belongs to a business that is no longer verified).
    func lookup(principal: ConsumerPrincipal, code: String) async throws -> VerificationSessionOffer {
        try await verify.limit("verify-session-lookup", key: principal.consumerId.description, rule: settings.sessionLookupRate)
        try await verify.limit("verify-session-lookup-global", key: "all", rule: settings.sessionLookupRateGlobal)
        return try await DB.retryingTransient { try await lookupAttempt(principal: principal, code: code) }
    }

    private func lookupAttempt(principal: ConsumerPrincipal, code: String) async throws -> VerificationSessionOffer {
        let now = ctx.now
        guard principal.deviceId != nil, let canonical = VerificationSessionCode.canonical(code),
              let record = try await VerificationSessionRecord.query(on: db).filter(\.$codeHash == codeHash(canonical)).first(),
              record.statusValue == .open, record.expiresAt > now, record.livemode,
              try await Sandbox(db: db).matches(consumerId: principal.consumerId.uuid, livemode: true),
              let business = try await DirectoryService(db: db).verified(id: record.businessId),
              let summary = try await DirectoryService(db: db).summary(for: business) else {
            _ = try? await AuditService(db: db, ctx: ctx).record("verification_session.lookup_failed", outcome: .denied, principal: principal)
            throw APIError.notFound
        }
        let subject = ctx.subjects.subjectRef(businessId: summary.id, consumerId: principal.consumerId)
        let signer = KMSStatementSigner(key: ctx.config.approve.linkDescriptorKey)
        let payload = try descriptor(record, business: summary, subject: subject).payload(signerKid: try signer.kid())
        let signed = try await signer.sign(payload: payload, domain: VerificationSessionDomainSeparator.descriptor)
        let relationship = try await RelationshipRecord.query(on: db).filter(\.$consumerId == principal.consumerId.uuid).filter(\.$businessId == record.businessId).first()
        _ = try await AuditService(db: db, ctx: ctx).record("verification_session.looked_up", principal: principal, businessId: summary.id,
                                                           subjectType: "verification_session", subjectId: record.id?.uuidString.lowercased())
        return VerificationSessionOffer(sessionId: record.id!, descriptor: signed, business: summary, subjectRef: subject,
                                        alreadyConnected: relationship?.isActive ?? false, expiresAt: record.expiresAt)
    }

    /// Deterministic per account (issued at creation), so the server can recompute the digest the app quotes; only the signature varies.
    func descriptor(_ record: VerificationSessionRecord, business: BusinessSummary, subject: SubjectRef) -> VerificationSessionDescriptor {
        VerificationSessionDescriptor(sessionId: record.id!, businessId: business.id, businessName: business.displayName, businessDomain: record.businessDomain,
                                      origin: record.origin, capability: record.capabilityValue, parameters: record.parameterValues, purposeCode: record.purpose,
                                      subject: subject, issuedAt: record.createdAt, expiresAt: record.expiresAt)
    }

    // MARK: Device: accept

    func accept(principal: ConsumerPrincipal, sessionId: UUID, request: VerificationSessionAcceptRequest) async throws -> VerificationSessionAccepted {
        try await verify.limit("verify-session-accept", key: principal.consumerId.description, rule: settings.attemptRate)
        let now = ctx.now
        let audit = AuditService(db: db, ctx: ctx)
        func reject(_ reason: String, _ error: APIError) async throws -> Never {
            _ = try? await audit.record("verification_session.accept_rejected", outcome: .denied, principal: principal, subjectType: "verification_session",
                                        subjectId: sessionId.uuidString.lowercased(), metadata: ["reason": reason])
            throw error
        }
        guard let deviceId = principal.deviceId, let device = try await DeviceRecord.find(deviceId.uuid, on: db), device.consumerId == principal.consumerId.uuid else {
            throw APIError.signatureInvalid
        }
        guard let record = try await VerificationSessionRecord.find(sessionId, on: db), record.livemode,
              try await Sandbox(db: db).matches(consumerId: principal.consumerId.uuid, livemode: true) else { throw APIError.notFound }
        guard device.kind == .app, device.revokedAt == nil, !device.isExpired(at: now) else {
            try await reject("device", APIError(.forbidden, .forbidden, "Verify from the Viadere app."))
        }
        // One session, one account: a second accept (whoever makes it) is a conflict; the code is spent.
        guard record.statusValue == .open else { try await reject("not_open", .conflict("This code was already used.")) }
        guard record.expiresAt > now else { try await reject("expired", .gone("This code has expired. Ask the business for a new one.")) }
        guard let business = try await DirectoryService(db: db).verified(id: record.businessId), let summary = try await DirectoryService(db: db).summary(for: business) else {
            try await reject("business_unavailable", .gone("This business is no longer available."))
        }
        let subject = ctx.subjects.subjectRef(businessId: summary.id, consumerId: principal.consumerId)
        // The app accepts exactly the descriptor it verified and showed: this session, this business and name, this origin, capability and purpose,
        // and this account's pairwise reference.
        let signerKid = try KMSStatementSigner(key: ctx.config.approve.linkDescriptorKey).kid()
        let expected = SecureToken.sha256Hex(Data(Base64URL.encode(try descriptor(record, business: summary, subject: subject).payload(signerKid: signerKid)).utf8))
        guard request.descriptorDigest.utf8.count == 64, ConstantTime.equals(expected, request.descriptorDigest) else {
            try await reject("descriptor_mismatch", .conflict("This request changed. Review it again."))
        }
        // A business the customer blocked cannot ask (WP-1.5): refused before anything is written.
        if try await PreferenceService(db: db, ctx: ctx).isBlocked(consumer: principal.consumerId.uuid, business: record.businessId) {
            try await reject("blocked", .conflict(PreferenceService.blockedMessage))
        }
        // The creating key must still be valid, and the policy is evaluated again for this customer with it.
        guard let businessPrincipal = try await creatingPrincipal(for: record) else { try await reject("key_unavailable", .gone("This request is no longer available.")) }
        try await PolicyService(db: db, ctx: ctx).enforce(
            PolicyInput(record.capabilityValue, subjectRef: subject, parameters: record.parameterValues, purpose: record.purpose,
                        additionalJurisdictions: try await verify.businessJurisdictions(record.businessId)), principal: businessPrincipal, auditAllowed: false)

        // Compare-and-swap: one session is accepted once, whoever races (a second device, a replay, a QR photographed by someone else).
        guard try await DB.swap(db, table: VerificationSessionRecord.schema, id: sessionId, column: "status", expected: VerificationSessionStatus.open.rawValue,
                                newValue: VerificationSessionStatus.accepted.rawValue,
                                extra: [("consumer_id", principal.consumerId.uuid), ("device_id", device.id!), ("subject_ref", subject.rawValue), ("accepted_at", now)]) else {
            try await reject("not_open", .conflict("This code was already used."))
        }
        do {
            // The app told the person, before they accepted, that verifying connects them to this business (unless already connected).
            let (relationship, _) = try await RelationshipService(db: db, ctx: ctx).connect(consumer: principal.consumerId,
                                                                                            request: ConnectRequest(businessId: summary.id, source: .button), source: .button)
            let opened = try await verify.openSessionRequest(sessionId: sessionId, principal: businessPrincipal, relationshipId: relationship.id.uuid,
                                                             consumerId: principal.consumerId.uuid, subject: subject, capability: record.capabilityValue,
                                                             parameters: record.parameterValues, purpose: record.purpose, callbackId: record.callbackId,
                                                             recipientName: summary.displayName)
            try await VerificationSessionRecord.query(on: db).filter(\.$id == sessionId)
                .set(\.$relationshipId, to: relationship.id.uuid).set(\.$requestId, to: opened.id!).update()
            _ = try await audit.record("verification_session.accepted", principal: principal, businessId: summary.id, subjectType: "verification_session",
                                       subjectId: sessionId.uuidString.lowercased(), metadata: ["capability": record.capability, "request_id": opened.requestID.description])
            return VerificationSessionAccepted(sessionId: sessionId, prompt: try await verify.prompt(for: opened), returnURL: record.returnURL)
        } catch {
            _ = try? await DB.swap(db, table: VerificationSessionRecord.schema, id: sessionId, column: "status", expected: VerificationSessionStatus.accepted.rawValue,
                                   newValue: VerificationSessionStatus.cancelled.rawValue, extra: [("cancelled_at", ctx.now), ("ended_reason", "accept_failed")])
            _ = try? await audit.record("verification_session.accept_rejected", outcome: .denied, principal: principal, subjectType: "verification_session",
                                        subjectId: sessionId.uuidString.lowercased(), metadata: ["reason": "accept_failed"])
            throw error
        }
    }

    /// The business principal the session is evaluated for: the creating key, **if it is still valid**.
    func creatingPrincipal(for record: VerificationSessionRecord) async throws -> BusinessPrincipal? {
        guard let key = try await BusinessAPIKeyRecord.find(record.apiKeyId, on: db), key.businessId == record.businessId, key.revokedAt == nil,
              (key.expiresAt ?? .distantFuture) > ctx.now, key.livemode == record.livemode,
              let business = try await BusinessRecord.find(record.businessId, on: db) else { return nil }
        return BusinessPrincipal(businessId: BusinessID(record.businessId), keyId: record.apiKeyId, livemode: key.livemode, scopes: key.scopeSet,
                                 businessName: business.displayName, capabilities: key.capabilitySet)
    }

    // MARK: Completion

    /// Called after a verification request ended (`VerifyService.persist`): completes the session that opened it, if any.
    func requestConcluded(requestId: UUID) async {
        guard let record = try? await VerificationSessionRecord.query(on: db).filter(\.$requestId == requestId).first() else { return }
        try? await completeIfConcluded(record)
    }

    /// Signs Viadere's `VerificationSessionResult` once the session's request has a result, and completes the session (compare-and-swap).
    func completeIfConcluded(_ record: VerificationSessionRecord) async throws {
        guard record.statusValue == .accepted, let id = record.id, let requestId = record.requestId, let subjectText = record.subjectRef,
              let subject = SubjectRef(subjectText),
              let row = try await VerificationResultRecord.query(on: db).filter(\.$requestId == requestId).first(),
              let outcome = VerificationOutcome(rawValue: row.outcome) else { return }
        let request = VerificationRequestID(requestId)
        let now = ctx.now
        let result = VerificationSessionResult(sessionId: id, businessId: BusinessID(record.businessId), requestId: request, subject: subject,
                                               capability: record.capabilityValue, parameters: record.parameterValues, purposeCode: record.purpose,
                                               origin: record.origin, outcome: outcome, resultRef: verify.resultRef(for: request), completedAt: now)
        let signer = KMSStatementSigner(key: ctx.config.approve.linkDescriptorKey)
        let signed = try await signer.sign(payload: try result.payload(signerKid: try signer.kid()), domain: VerificationSessionDomainSeparator.result)
        let json = String(decoding: try ViadereJSON.encode(signed), as: UTF8.self)
        guard try await DB.swap(db, table: VerificationSessionRecord.schema, id: id, column: "status", expected: VerificationSessionStatus.accepted.rawValue,
                                newValue: VerificationSessionStatus.completed.rawValue, extra: [("result", json), ("completed_at", now)]) else { return }
        _ = try await AuditService(db: db, ctx: ctx).record("verification_session.completed", outcome: outcome == .verified ? .success : .failure,
            actor: AuditActor(kind: .system, id: "verify"), consumerId: record.consumerId.map(ConsumerID.init), businessId: BusinessID(record.businessId),
            subjectType: "verification_session", subjectId: id.uuidString.lowercased(), metadata: ["capability": record.capability, "outcome": outcome.rawValue])
    }
}

extension VerifyService {
    /// Opens the verification request of an accepted session for the account that accepted it: the same record, envelope rules, open-request bound
    /// and audit as `create`, with the session as its idempotency key. The person is in the app already, so there is no push.
    func openSessionRequest(sessionId: UUID, principal: BusinessPrincipal, relationshipId: UUID, consumerId: UUID, subject: SubjectRef, capability: Capability,
                            parameters: [String: JSONValue], purpose: String, callbackId: UUID?, recipientName: String) async throws -> VerificationRequestRecord {
        let now = ctx.now
        let open = try await VerificationRequestRecord.query(on: db).filter(\.$businessId == principal.businessId.uuid)
            .filter(\.$relationshipId == relationshipId).filter(\.$status ~~ [ConsumerVerificationStatus.pendingConsent.rawValue, ConsumerVerificationStatus.consented.rawValue])
            .filter(\.$expiresAt > now).count()
        guard open < Self.maxOpenPerSubject else {
            throw APIError(.tooManyRequests, .rateLimited, "This business already has open verification requests for you.", headers: ["Retry-After": "60"])
        }
        let lifetime = VerificationSessionLimits.requestLifetime
        let idemHash = ctx.hasher.hmacHex("verify-idempotency", "\(principal.businessId)\nsession:\(sessionId.uuidString.lowercased())")
        let requestHash = SecureToken.sha256Hex(Data(("\(capability.rawValue)\n\(subject.rawValue)\n\(canonicalParameters(parameters))\n\(purpose)\n\(callbackId?.uuidString ?? "")\n\(lifetime)").utf8))
        let record = VerificationRequestRecord(
            id: UUID(), businessId: principal.businessId.uuid, keyId: principal.keyId, livemode: principal.livemode, relationshipId: relationshipId,
            consumerId: consumerId, subjectRef: subject.rawValue, capability: capability, parameters: canonicalParameters(parameters), purpose: purpose,
            callbackId: callbackId, recipientName: recipientName, idempotencyHash: idemHash, requestHash: requestHash, now: now,
            expiresAt: now.addingTimeInterval(TimeInterval(lifetime)))
        try await db.transaction { tx in
            try await record.create(on: tx)
            _ = try await AuditService(db: tx, ctx: ctx).record("verification.requested", actor: AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased()),
                businessId: principal.businessId, subjectType: "verification_request", subjectId: record.requestID.description,
                metadata: ["capability": capability.rawValue, "purpose": purpose, "subject_ref": subject.rawValue, "expires_in": String(lifetime),
                           "via": "verification_session"])
        }
        return record
    }
}

/// `/v1/business/verification-sessions/...` (the business's server; capability-gated like every Verify route) and `/v1/verification-sessions/...`
/// (the customer's app). Behind the Verify release gate.
enum VerificationSessionRoutes {
    @Sendable static func service(_ req: Request) throws -> VerificationSessionService {
        try VerifyService.requireEnabled(req.ctx)
        return VerificationSessionService(db: req.db, ctx: req.ctx, runtime: req.verify)
    }

    static func register(_ routes: any RoutesBuilder) {
        // MARK: Business (tenant = the API key's business, never a parameter)
        routes.api(APIRoutes.businessVerificationSessionCreate) { req in
            let svc = try service(req)
            let body: CreateVerificationSessionRequest = try req.decodeBody()
            return try req.jsonResponse(try await svc.create(principal: try req.business, request: body), status: .created)
        }
        routes.api(APIRoutes.businessVerificationSessionGet) { req in
            let svc = try service(req)
            let response = try req.jsonResponse(try await svc.businessView(try await svc.record(id: try req.uuidPath("sessionId"), principal: try req.business)))
            response.headers.replaceOrAdd(name: .cacheControl, value: "no-store")
            return response
        }
        routes.api(APIRoutes.businessVerificationSessionCancel) { req in
            let svc = try service(req)
            return try req.jsonResponse(try await svc.businessView(try await svc.cancel(principal: try req.business, id: try req.uuidPath("sessionId"))))
        }

        // MARK: Devices
        routes.api(APIRoutes.verificationSessionLookup) { req in
            let svc = try service(req)
            let body: VerificationSessionLookupRequest = try req.decodeBody()
            return try req.jsonResponse(try await svc.lookup(principal: try req.consumer, code: body.code))
        }
        routes.api(APIRoutes.verificationSessionAccept) { req in
            let svc = try service(req)
            let body: VerificationSessionAcceptRequest = try req.decodeBody()
            return try req.jsonResponse(try await svc.accept(principal: try req.consumer, sessionId: try req.uuidPath("sessionId"), request: body), status: .created)
        }
    }
}
