import Fluent
import Foundation
import ViadereCore

/// Business link sessions (WP-C1, spec §5, `docs/SECURITY.md` §2.59): a business that has just authenticated its customer links that customer's
/// Viadere app to its own customer record, without the customer typing anything that identifies them and without the business learning anything
/// but a pairwise `subject_ref`.
///
/// 1. The business creates a short-lived (≤ 5 min), single-use session for capabilities it is entitled to (registered, linkable actions only).
/// 2. The app looks the code up and receives a **descriptor signed by Viadere's `link-descriptor` KMS key**, cross-checked on the device against
///    the business's key directory; the person confirms.
/// 3. The app signs a `VIADERE-LINK-V1` statement (and, for approval capabilities, an ordinary approval-key enrollment statement) and completes;
///    the relay consumes the session by compare-and-swap. The connection exists from now on but is `pending_link`: nothing can be sent or asked.
/// 4. The business fetches the statement and Viadere's signed result, authenticates the statement with its session secret (binding tag) and
///    the SAS the person compares or types **in the business's own signed-in session**, then confirms with its directory key. Only then is the
///    connection active (and the approval key with it). A session the business never confirms is ended and reported.
///
/// What the relay cannot do: create a statement the business accepts (binding tag and SAS need `es`), confirm on the business's behalf (directory
/// key), or show the app a business that did not create the session (descriptor key + directory cross-check). What it cannot prevent alone: a
/// person who scans a QR an attacker photographed; that is what the SAS comparison in the business's session and the business's out-of-band
/// notice are for (residual risk: real-time relay phishing, §2.59).
struct LinkSessionService {
    let db: any Database
    let ctx: ServerContext

    static let codeContext = "link-session-code"
    static let customerContext = "link-session-customer"

    func codeHash(_ canonical: String) -> String { ctx.hasher.hmacHex(Self.codeContext, canonical) }
    func customerHash(businessId: BusinessID, customerRef: String) -> String { ctx.hasher.hmacHex(Self.customerContext, businessId.description + "\n" + customerRef) }

    static func isValidCustomerRef(_ value: String) -> Bool {
        (1...LinkSessionLimits.customerRefLength).contains(value.utf8.count) && E2EEContext.validIdentifier(value)
    }

    /// Non-sensitive display text: the display-text rules, at most 40 characters, and no run of more than four digits (an account or card
    /// number never belongs here; "Account ending 4821" does).
    static func isValidDisplayHint(_ value: String) -> Bool {
        guard DisplayTextSanitizer.violation(of: value, maxCharacters: LinkSessionLimits.displayHintLength) == nil else { return false }
        var run = 0
        for scalar in value.unicodeScalars {
            run = scalar.properties.numericType != nil ? run + 1 : 0
            if run > 4 { return false }
        }
        return true
    }

    // MARK: Business: create

    func create(principal: BusinessPrincipal, request: CreateLinkSessionRequest) async throws -> LinkSessionTicket {
        try Sandbox.requireLive(principal, "create link sessions")
        guard Self.isValidCustomerRef(request.customerRef) else {
            throw APIError.validation("customer_ref must be 1 to 128 of A-Z a-z 0-9 . _ : -.", details: ["customer_ref": "invalid"])
        }
        let capabilities = LinkCapabilities.canonical(request.capabilities)
        guard (1...LinkSessionLimits.maxCapabilities).contains(capabilities.count), capabilities.count == request.capabilities.count else {
            throw APIError.validation("Name 1 to 8 different capabilities.", details: ["capabilities": "invalid"])
        }
        // Registered, live, linkable actions only (spec v4 A4): never an arbitrary operation string.
        for capability in capabilities {
            guard let grant = ActionRegistry.grant(capability), grant.isLive, grant.linkable else {
                throw APIError.validation("\(capability.rawValue) cannot be granted by a link session.", details: ["capabilities": "not_linkable"])
            }
        }
        let lifetime = request.expiresInSeconds ?? ActionRegistry.linkConnect.defaultTimeout
        guard ActionRegistry.linkConnect.timeout.contains(lifetime) else {
            throw APIError.validation("expires_in_seconds must be between 60 and 300.", details: ["expires_in_seconds": "invalid"])
        }
        if let hint = request.displayHint, !Self.isValidDisplayHint(hint) {
            throw APIError.validation("display_hint must be short, plain and non-sensitive.", details: ["display_hint": "invalid"])
        }
        // The business must be entitled, now, to everything it asks the customer to grant (key scope, entitlement, tier, switches).
        let policy = PolicyService(db: db, ctx: ctx)
        for capability in capabilities { try await policy.enforce(PolicyInput(capability), principal: principal, auditAllowed: false) }
        guard try await DirectoryService(db: db).verified(id: principal.businessId.uuid) != nil else { throw APIError.forbidden }
        // The directory is part of the protocol: the app cross-checks the business against it and the business confirms with a published key.
        let state = try await KeyLogService(db: db, ctx: ctx).state(for: principal.businessId.uuid)
        guard let root = state.currentRoot, !state.validKeys(for: .approvalEnrollmentConfirmation, at: ctx.now).isEmpty else {
            throw APIError(.conflict, .conflict, "Register your business root key and publish an approval-enrollment-confirmation key first.",
                           details: ["reason": "key_directory_required"])
        }
        let customerHash = customerHash(businessId: principal.businessId, customerRef: request.customerRef)
        let settings = ctx.config.approve
        try await ctx.limiter.enforce("link-session-create", key: principal.businessId.description, rule: settings.linkCreateRate)
        try await ctx.limiter.enforce("link-session-customer", key: principal.businessId.description + ":" + customerHash, rule: settings.linkPerCustomerRate)

        let now = ctx.now
        var created: LinkSessionRecord?
        var code = ""
        for _ in 0..<5 {
            code = LinkSessionCode.generate()
            let record = LinkSessionRecord()
            record.id = UUID()
            record.businessId = principal.businessId.uuid
            record.apiKeyId = principal.keyId
            record.livemode = principal.livemode
            record.codeHash = codeHash(code)
            record.customerRefHash = customerHash
            record.capabilities = capabilities.map(\.rawValue).joined(separator: ",")
            record.displayHint = request.displayHint
            record.rootKid = root.kid
            record.status = LinkSessionStatus.open.rawValue
            record.createdAt = now
            record.expiresAt = now.addingTimeInterval(TimeInterval(lifetime))
            record.relationshipCreated = false
            do {
                // The session's two deadlines are scheduled messages (the maintenance sweep remains the safety net): `expires_at` for an open
                // session, and `expires_at` + the confirmation grace for a completed one the business never confirmed. `approve.expire` runs the
                // Approve v2 expiry sweep, which ends both (`expireDue`), so the message is a doorbell and carries only the session id.
                let grace = settings.unconfirmedGrace
                try await db.transaction { [ctx] tx in
                    try await record.create(on: tx)
                    try await Outbox.enqueue(QueueHandlers.approveExpire, ref: record.id!, notBefore: record.expiresAt, on: tx, ctx: ctx)
                    try await Outbox.enqueue(QueueHandlers.approveExpire, ref: record.id!, notBefore: record.expiresAt.addingTimeInterval(grace), on: tx, ctx: ctx)
                }
                created = record
                break
            } catch where error.isConstraintViolation { continue }
        }
        guard let session = created, let id = session.id else { throw APIError.internalError }
        _ = try await AuditService(db: db, ctx: ctx).record("link.session_created", actor: AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased()),
            businessId: principal.businessId, subjectType: "link_session", subjectId: id.uuidString.lowercased(),
            metadata: ["capabilities": session.capabilities, "lifetime": String(lifetime)])
        return LinkSessionTicket(sessionId: id, code: code, link: LinkSessionLink.build(code: code, secret: nil, domain: ctx.config.linkDomain),
                                 rootKid: root.kid, expiresAt: session.expiresAt)
    }

    // MARK: Business: read, cancel

    /// The calling business's own session; anything else (another tenant's id, a malformed id) is the same `404`.
    func record(id: UUID, principal: BusinessPrincipal) async throws -> LinkSessionRecord {
        guard let record = try await LinkSessionRecord.query(on: db).filter(\.$id == id).filter(\.$businessId == principal.businessId.uuid).first(),
              record.livemode == principal.livemode else { throw APIError.notFound }
        return record
    }

    func businessView(_ record: LinkSessionRecord) -> LinkSessionView {
        var status = record.statusValue
        if status == .open, record.expiresAt <= ctx.now { status = .expired }
        return LinkSessionView(sessionId: record.id!, status: status, capabilities: record.capabilityList, createdAt: record.createdAt, expiresAt: record.expiresAt,
                               subjectRef: record.subjectRef.flatMap { SubjectRef($0) }, statement: record.statement, bindingTag: record.bindingTag,
                               approvalStatement: record.approvalStatement, result: record.signedResult, completedAt: record.completedAt,
                               confirmedAt: record.confirmedAt)
    }

    func cancel(principal: BusinessPrincipal, id: UUID) async throws -> LinkSessionRecord {
        let record = try await record(id: id, principal: principal)
        if record.statusValue == .open || record.statusValue == .deviceCompleted {
            try await end(record, as: .cancelled, reason: "cancelled", actor: AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased()))
        }
        return try await self.record(id: id, principal: principal)
    }

    // MARK: Device: lookup

    /// The descriptor of one session, for the account that asks. Wrong codes are rationed per account and globally, and every failure is the same
    /// `404` (no oracle on whether a code exists, expired or was used).
    func lookup(principal: ConsumerPrincipal, code: String) async throws -> LinkSessionOffer {
        let settings = ctx.config.approve
        try await ctx.limiter.enforce("link-lookup", key: principal.consumerId.description, rule: settings.linkLookupRate)
        try await ctx.limiter.enforce("link-lookup-global", key: "all", rule: settings.linkLookupRateGlobal)
        // Read-only apart from the audit row at the end, so a transient database failure is retried as a whole.
        return try await DB.retryingTransient { try await lookupAttempt(principal: principal, code: code) }
    }

    private func lookupAttempt(principal: ConsumerPrincipal, code: String) async throws -> LinkSessionOffer {
        let now = ctx.now
        guard principal.deviceId != nil, let canonical = LinkSessionCode.canonical(code),
              let record = try await LinkSessionRecord.query(on: db).filter(\.$codeHash == codeHash(canonical)).first(),
              record.statusValue == .open, record.expiresAt > now, record.livemode,
              try await Sandbox(db: db).matches(consumerId: principal.consumerId.uuid, livemode: true),
              let business = try await DirectoryService(db: db).verified(id: record.businessId),
              let summary = try await DirectoryService(db: db).summary(for: business) else {
            _ = try? await AuditService(db: db, ctx: ctx).record("link.lookup_failed", outcome: .denied, principal: principal)
            throw APIError.notFound
        }
        let subject = ctx.subjects.subjectRef(businessId: summary.id, consumerId: principal.consumerId)
        let descriptor = try await signedDescriptor(record, business: summary, subject: subject)
        let relationship = try await RelationshipRecord.query(on: db).filter(\.$consumerId == principal.consumerId.uuid).filter(\.$businessId == record.businessId).first()
        _ = try await AuditService(db: db, ctx: ctx).record("link.session_looked_up", principal: principal, businessId: summary.id, subjectType: "link_session",
                                                           subjectId: record.id?.uuidString.lowercased())
        return LinkSessionOffer(sessionId: record.id!, descriptor: descriptor, business: summary, subjectRef: subject, capabilities: record.capabilityList,
                                requiredAssurance: LinkCapabilities.requiredAssurance(record.capabilityList), expiresAt: record.expiresAt,
                                alreadyConnected: relationship?.isActive ?? false)
    }

    /// The descriptor for one account is deterministic (issued at the session's creation), so the server can recompute the digest the device's
    /// statement commits to; only the signature differs between lookups.
    func descriptor(_ record: LinkSessionRecord, business: BusinessSummary, subject: SubjectRef) async throws -> LinkSessionDescriptor {
        let domain = try await BusinessDomainRecord.query(on: db).filter(\.$businessId == record.businessId).filter(\.$status == "verified").sort(\.$verifiedAt).first()
        return LinkSessionDescriptor(sessionId: record.id!, businessId: business.id, businessName: business.displayName,
                                     businessDomain: domain?.verifiedDomain ?? domain?.domain ?? "", rootKid: record.rootKid, capabilities: record.capabilityList,
                                     displayHint: record.displayHint ?? "", subject: subject, issuedAt: record.createdAt, expiresAt: record.expiresAt)
    }

    func signedDescriptor(_ record: LinkSessionRecord, business: BusinessSummary, subject: SubjectRef) async throws -> ViadereSignedStatement {
        let signer = KMSStatementSigner(key: ctx.config.approve.linkDescriptorKey)
        let payload = try await descriptor(record, business: business, subject: subject).payload(signerKid: try signer.kid())
        return try await signer.sign(payload: payload, domain: LinkDomainSeparator.descriptor)
    }

    // MARK: Device: complete

    func complete(principal: ConsumerPrincipal, sessionId: UUID, request: CompleteLinkSessionRequest) async throws -> LinkSessionDeviceView {
        try await ctx.limiter.enforce("link-complete", key: principal.consumerId.description, rule: ctx.config.approve.linkCompleteRate)
        // Checking and consuming are retried as a whole on a transient database failure (SQLite serializes writers; PostgreSQL may abort a
        // contended statement): every attempt re-reads the session, and the compare-and-swap inside decides who wins. Work after the commit is
        // retried on its own, so a committed completion is never attempted twice.
        let (record, summary, hasApproval) = try await DB.retryingTransient { try await completeAttempt(principal: principal, sessionId: sessionId, request: request) }
        try await DB.retryingTransient {
            _ = try await AuditService(db: db, ctx: ctx).record("link.session_device_completed", principal: principal, businessId: summary.id, subjectType: "link_session",
                                                               subjectId: sessionId.uuidString.lowercased(),
                                                               metadata: ["capabilities": record.capabilities, "approval_key": hasApproval ? "pending" : "none",
                                                                          "binding_tag": request.bindingTag == nil ? "absent" : "present"])
        }
        try await DB.retryingTransient { try await LinkWebhooks(db: db, ctx: ctx).completed(businessId: record.businessId, sessionId: sessionId) }
        guard let completed = try await DB.retryingTransient({ try await LinkSessionRecord.find(sessionId, on: db) }) else { throw APIError.internalError }
        return try await deviceView(completed, business: summary)
    }

    private func completeAttempt(principal: ConsumerPrincipal, sessionId: UUID, request: CompleteLinkSessionRequest) async throws
        -> (LinkSessionRecord, BusinessSummary, Bool) {
        let now = ctx.now
        guard let deviceId = principal.deviceId, let device = try await DeviceRecord.find(deviceId.uuid, on: db), device.consumerId == principal.consumerId.uuid else {
            throw APIError.signatureInvalid
        }
        let audit = AuditService(db: db, ctx: ctx)
        func reject(_ reason: String, _ error: APIError) async throws -> Never {
            _ = try? await audit.record("link.complete_rejected", outcome: .denied, principal: principal, subjectType: "link_session",
                                        subjectId: sessionId.uuidString.lowercased(), metadata: ["reason": reason])
            throw error
        }
        guard let record = try await LinkSessionRecord.find(sessionId, on: db), record.livemode,
              try await Sandbox(db: db).matches(consumerId: principal.consumerId.uuid, livemode: true) else { throw APIError.notFound }
        guard device.kind == .app, device.revokedAt == nil, !device.isExpired(at: now) else {
            try await reject("device", APIError(.forbidden, .forbidden, "Link a business from the Viadere app."))
        }
        // One session, one account: a second completion (whoever makes it) is a conflict; the code is spent.
        guard record.statusValue == .open else { try await reject("not_open", .conflict("This code was already used.")) }
        guard record.expiresAt > now else {
            try? await end(record, as: .expired, reason: "not_completed", actor: AuditActor(kind: .system, id: "link-sweep"))
            try await reject("expired", .gone("This code has expired. Ask for a new one."))
        }
        // An approval key may be bound only by a D1 device, or by a D0 device of an account without one when the business created the session
        // after the device existed (the business's own customer authentication vouches; §2.5a). Messaging-only links are fine for D0.
        if record.needsApprovalKey, try await !DeviceTrust.mayCompleteBusinessEnrollment(device, enrollmentCreatedAt: record.createdAt, db: db, now: now) {
            try await reject("device_not_trusted", DeviceTrust.notTrustedError(device, at: now))
        }
        try await AppAttestAssertionPolicy(db: db, ctx: ctx).check(device: device, assertion: request.appAttestAssertion,
                                                                   clientData: LinkAppAttest.clientData(sessionId: sessionId, statement: request.statement),
                                                                   purpose: "link_complete", principal: principal)
        guard let business = try await DirectoryService(db: db).verified(id: record.businessId), let summary = try await DirectoryService(db: db).summary(for: business) else {
            try await reject("business_unavailable", .gone("This business is no longer available."))
        }
        let subject = ctx.subjects.subjectRef(businessId: summary.id, consumerId: principal.consumerId)
        let statement: LinkStatement
        let approval: ApprovalEnrollmentStatement?
        do {
            statement = try LinkStatement.verify(request.statement)
            let expected = try await descriptor(record, business: summary, subject: subject)
            let descriptorDigest = SecureToken.sha256Hex(Data(Base64URL.encode(try expected.payload(signerKid: try KMSStatementSigner(key: ctx.config.approve.linkDescriptorKey).kid())).utf8))
            // Bound to this session, this business, **this account's** pairwise reference, the exact capabilities and the descriptor shown.
            try statement.checkBinding(sessionId: sessionId, businessId: summary.id, subject: subject, capabilities: record.capabilityList, descriptorDigest: descriptorDigest)
            approval = try statement.checkApprovalStatement(request.approvalStatement)
        } catch let error as LinkSessionError {
            try await reject("statement_\(error)", .validation("The link statement is not valid.", details: ["statement": "invalid"]))
        } catch {
            try await reject("statement_invalid", .validation("The link statement is not valid.", details: ["statement": "invalid"]))
        }
        guard abs(now.timeIntervalSince(Date(timeIntervalSince1970: TimeInterval(statement.createdAt)))) <= 600 else {
            try await reject("statement_stale", .validation("The link statement is stale.", details: ["statement": "stale"]))
        }
        if let tag = request.bindingTag, !Base64URL.isValid(tag, minLength: 43, maxLength: 43) {
            try await reject("binding_tag_invalid", .validation("The binding tag is not valid.", details: ["binding_tag": "invalid"]))
        }
        let existing = try await RelationshipRecord.query(on: db).filter(\.$consumerId == principal.consumerId.uuid).filter(\.$businessId == record.businessId).first()
        if let existing, existing.isPendingLink { try await reject("link_in_progress", .conflict("Another link with this business is waiting for its confirmation.")) }
        if approval != nil, let existing {
            try await ApproveFreezeService(db: db, ctx: ctx).requireNotFrozen(consumerId: principal.consumerId.uuid, relationshipId: existing.id!)
            let keys = try await ApproveKeyRecord.query(on: db).filter(\.$relationshipId == existing.id!).filter(\.$status != ApprovalKeyStatus.revoked.rawValue).count()
            guard keys < ctx.config.approve.maxKeysPerRelationship else { try await reject("too_many_keys", .conflict("Too many approval keys for this business.")) }
        }

        // Viadere's signed account of the completion, for the business (made before the transaction: the KMS is a remote call).
        let statementDigest = LinkStatement.digest(of: request.statement)
        let signer = KMSStatementSigner(key: ctx.config.approve.linkDescriptorKey)
        let result = LinkResult(sessionId: sessionId, businessId: summary.id, subject: subject, statementDigest: statementDigest,
                                approvalStatementDigest: request.approvalStatement.map(ApprovalEnrollmentStatement.digest(of:)), completedAt: now)
        let signedResult = try await signer.sign(payload: try result.payload(signerKid: try signer.kid()), domain: LinkDomainSeparator.result)
        let resultJSON = String(decoding: try ViadereJSON.encode(signedResult), as: UTF8.self)

        do {
            // SQLite serializes writers and PostgreSQL may abort a contended transaction: transient failures are retried; the CAS decides.
            try await DB.retryingTransient { try await db.transaction { tx in
                var relationship: RelationshipRecord
                var created = false
                var prior: String?
                if let existing {
                    relationship = existing
                    if !existing.isActive {
                        // A disconnected connection is reactivated only when the business confirms.
                        prior = existing.status
                        relationship.status = RelationshipRecord.pendingLink
                        try await relationship.update(on: tx)
                    }
                } else {
                    relationship = RelationshipRecord(consumerId: principal.consumerId.uuid, businessId: record.businessId, source: .qr, now: now)
                    relationship.status = RelationshipRecord.pendingLink
                    relationship.connectionMethod = ConnectionMethod.linkSession.rawValue
                    try await relationship.create(on: tx)
                    created = true
                }
                var extra: [(String, any Encodable & Sendable)] = [
                    ("claimed_consumer_id", principal.consumerId.uuid), ("claimed_device_id", device.id!), ("relationship_id", relationship.id!),
                    ("relationship_created", created), ("subject_ref", subject.rawValue), ("statement_payload", request.statement.payload),
                    ("statement_signature", request.statement.signature), ("statement_digest", statementDigest), ("connection_kid", statement.kid),
                    ("result", resultJSON), ("completed_at", now)]
                if let prior { extra.append(("relationship_prior_status", prior)) }
                if let tag = request.bindingTag { extra.append(("binding_tag", tag)) }
                if let signed = request.approvalStatement, let approval {
                    extra.append(("approval_statement_payload", signed.payload))
                    extra.append(("approval_statement_signature", signed.signature))
                    extra.append(("approval_kid", approval.kid))
                }
                // Compare-and-swap: one session completes once, whoever races (a second device, a replayed request, a QR thief second in line).
                guard try await DB.swap(tx, table: LinkSessionRecord.schema, id: sessionId, column: "status", expected: LinkSessionStatus.open.rawValue,
                                        newValue: LinkSessionStatus.deviceCompleted.rawValue, extra: extra) else {
                    throw APIError.conflict("This code was already used.")
                }
                if let signed = request.approvalStatement, let approval {
                    let key = ApproveKeyRecord()
                    key.id = UUID()
                    key.kid = approval.kid
                    key.enrollmentId = sessionId
                    key.businessId = record.businessId
                    key.relationshipId = relationship.id!
                    key.consumerId = principal.consumerId.uuid
                    key.deviceId = device.id!
                    key.subjectRef = subject.rawValue
                    key.publicKey = approval.publicKey.base64URL
                    key.hpkeKid = approval.hpkePublicKey.kid
                    key.hpkePublicKey = approval.hpkePublicKey.base64URL
                    key.assurance = approval.assurance.rawValue
                    key.status = ApprovalKeyStatus.pending.rawValue
                    key.statementPayload = signed.payload
                    key.statementSignature = signed.signature
                    key.createdAt = now
                    try await key.create(on: tx)
                }
            } }
        } catch {
            if error.isConstraintViolation { try await reject("key_reused", .conflict("This key was already used.")) }
            if let api = error as? APIError, api.status == .conflict { try await reject("not_open", api) }
            throw error
        }
        return (record, summary, approval != nil)
    }

    // MARK: Business: confirm

    /// The business's signed confirmation activates the connection (and the approval key). Both confirmations must be signed by keys the directory
    /// publishes for this business now, and must cover exactly the statements the device made.
    func confirm(principal: BusinessPrincipal, id: UUID, request: ConfirmLinkSessionRequest) async throws -> LinkSessionRecord {
        let record = try await record(id: id, principal: principal)
        let actor = AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased())
        let audit = AuditService(db: db, ctx: ctx)
        func reject(_ reason: String, _ error: APIError) async throws -> Never {
            _ = try? await audit.record("link.confirm_rejected", outcome: .denied, actor: actor, businessId: principal.businessId, subjectType: "link_session",
                                        subjectId: id.uuidString.lowercased(), metadata: ["reason": reason])
            throw error
        }
        let now = ctx.now
        guard record.expiresAt.addingTimeInterval(ctx.config.approve.unconfirmedGrace) > now else {
            try await reject("confirmation_too_late", .gone("This link session has expired. Start a new one."))
        }
        guard record.statusValue == .deviceCompleted, let signed = record.statement, let relationshipId = record.relationshipId,
              let subjectText = record.subjectRef, SubjectRef(subjectText) != nil else {
            throw APIError.conflict("This link session is not waiting for confirmation.")
        }
        let state = try await KeyLogService(db: db, ctx: ctx).state(for: principal.businessId.uuid)
        guard let published = state.validKey(kid: request.confirmation.kid, purpose: .approvalEnrollmentConfirmation, at: now), let key = published.signingKey else {
            try await reject("confirmation_key_not_published", APIError(.forbidden, .forbidden, "The confirmation key is not published in your key directory.",
                                                                        details: ["reason": "key_not_published"]))
        }
        let confirmation: LinkConfirmation
        do {
            confirmation = try LinkConfirmation.verify(request.confirmation, confirmationKey: key)
            try confirmation.checkMatches(try LinkStatement.verify(signed), signed: signed)
        } catch {
            try await reject("confirmation_invalid", .validation("The confirmation does not match the link session.", details: ["confirmation": "invalid"]))
        }
        // A business can confirm only its own session: the confirmation names the business, and so does the session (tenant confusion).
        guard confirmation.businessId == principal.businessId, confirmation.sessionId == id else {
            try await reject("confirmation_wrong_tenant", .validation("The confirmation does not match the link session.", details: ["confirmation": "invalid"]))
        }
        var approvalJSON: String?
        if let approvalSigned = record.approvalStatement {
            guard let approvalConfirmation = request.approvalConfirmation,
                  let approvalKey = state.validKey(kid: approvalConfirmation.kid, purpose: .approvalEnrollmentConfirmation, at: now)?.signingKey else {
                try await reject("approval_confirmation_missing", .validation("Confirm the approval key as well.", details: ["approval_confirmation": "required"]))
            }
            do {
                let parsed = try ApprovalEnrollmentConfirmation.verify(approvalConfirmation, confirmationKey: approvalKey)
                try parsed.checkMatches(try ApprovalEnrollmentStatement.verify(approvalSigned), signed: approvalSigned)
            } catch {
                try await reject("approval_confirmation_invalid", .validation("The approval confirmation does not match.", details: ["approval_confirmation": "invalid"]))
            }
            approvalJSON = String(decoding: try ViadereJSON.encode(approvalConfirmation), as: UTF8.self)
        } else if request.approvalConfirmation != nil {
            try await reject("approval_confirmation_unexpected", .validation("This link session has no approval key.", details: ["approval_confirmation": "unexpected"]))
        }
        let confirmationJSON = String(decoding: try ViadereJSON.encode(request.confirmation), as: UTF8.self)
        let policy = try await ApproveKeyService(db: db, ctx: ctx).devicePolicy(businessId: record.businessId)
        let approvalConfirmationJSON = approvalJSON
        let becameActive = try await db.transaction { tx -> Bool in
            var activated = false
            guard try await DB.swap(tx, table: LinkSessionRecord.schema, id: id, column: "status", expected: LinkSessionStatus.deviceCompleted.rawValue,
                                    newValue: LinkSessionStatus.confirmed.rawValue,
                                    extra: [("confirmation", confirmationJSON), ("verification", confirmation.verification.rawValue), ("confirmed_at", now)]) else {
                throw APIError.conflict("This link session is no longer waiting for confirmation.")
            }
            guard let relationship = try await RelationshipRecord.find(relationshipId, on: tx) else { throw APIError.conflict("The connection no longer exists.") }
            if relationship.isPendingLink {
                relationship.status = "active"
                relationship.disconnectedAt = nil
                relationship.connectedAt = now
                activated = true
                try await ConsentService(db: tx, ctx: ctx).initialize(relationship: relationship, optIn: [], source: .app, channels: [.nativePush, .inApp])
            }
            guard relationship.isActive else { throw APIError.conflict("The connection is no longer available.") }
            relationship.lastActivityAt = now
            relationship.linkSessionId = id
            relationship.evidenceDigest = record.statementDigest
            relationship.linkedAt = now
            relationship.scopes = LinkCapabilities.canonical(relationship.scopeList + record.capabilityList).map(\.rawValue).joined(separator: ",")
            if record.relationshipCreated { relationship.connectionMethod = ConnectionMethod.linkSession.rawValue }
            try await relationship.update(on: tx)
            if let kid = record.approvalKid, let approvalConfirmationJSON {
                try await ApproveKeyRecord.query(on: tx).filter(\.$kid == kid).filter(\.$enrollmentId == id).filter(\.$status == ApprovalKeyStatus.pending.rawValue)
                    .set(\.$status, to: ApprovalKeyStatus.active.rawValue).set(\.$activatedAt, to: now).set(\.$confirmation, to: approvalConfirmationJSON)
                    .set(\.$devicePolicy, to: policy.rawValue).update()
            }
            return activated
        }
        _ = try await audit.record("link.session_confirmed", actor: actor, consumerId: record.claimedConsumerId.map(ConsumerID.init), businessId: principal.businessId,
                                   subjectType: "link_session", subjectId: id.uuidString.lowercased(),
                                   metadata: ["verification": confirmation.verification.rawValue, "capabilities": record.capabilities])
        if let kid = record.approvalKid, let activated = try await ApproveKeyRecord.query(on: db).filter(\.$kid == kid).first(), activated.isActive {
            _ = try await audit.record("approve.key_activated", actor: actor, consumerId: ConsumerID(activated.consumerId), businessId: principal.businessId,
                                       subjectType: "approve_key", subjectId: kid, metadata: ["assurance": activated.assurance, "via": "link_session"])
            try await ApproveKeyService(db: db, ctx: ctx).applyDevicePolicy(activated: activated, policy: policy)
        }
        if becameActive, let consumer = record.claimedConsumerId {
            try await WebhookService(db: db, ctx: ctx).enqueue(.relationshipConnected, businessId: principal.businessId,
                payload: RelationshipEventPayload(relationshipId: RelationshipID(relationshipId), subjectRef: ctx.subjects.subjectRef(businessId: principal.businessId, consumerId: ConsumerID(consumer)),
                                                  source: .qr, occurredAt: now))
        }
        // The customer's other devices are told (their out-of-band channel is the business's own notice).
        if let consumer = record.claimedConsumerId {
            await ApproveNotifier(db: db, ctx: ctx).notice(.businessLinked, consumerId: consumer, except: record.claimedDeviceId, subjectId: relationshipId.uuidString.lowercased())
        }
        return try await self.record(id: id, principal: principal)
    }

    // MARK: Ending

    /// Ends a session that is open or waiting for confirmation: the pending connection is removed (or restored to what it was) and a pending approval
    /// key is revoked. Never touches a connection that became active some other way in the meantime.
    func end(_ record: LinkSessionRecord, as status: LinkSessionStatus, reason: String, actor: AuditActor) async throws {
        let now = ctx.now
        let expected = record.status
        guard expected == LinkSessionStatus.open.rawValue || expected == LinkSessionStatus.deviceCompleted.rawValue, let id = record.id else { return }
        var fields: [(String, any Encodable & Sendable)] = [("ended_reason", reason)]
        if status == .cancelled { fields.append(("cancelled_at", now)) }
        let extra = fields
        let (swapped, revokedKey) = try await db.transaction { tx -> (Bool, ApproveKeyRecord?) in
            guard try await DB.swap(tx, table: LinkSessionRecord.schema, id: id, column: "status", expected: expected, newValue: status.rawValue, extra: extra) else { return (false, nil) }
            guard expected == LinkSessionStatus.deviceCompleted.rawValue else { return (true, nil) }
            var revoked: ApproveKeyRecord?
            if let relationshipId = record.relationshipId, let relationship = try await RelationshipRecord.find(relationshipId, on: tx), relationship.isPendingLink {
                if record.relationshipCreated {
                    try await relationship.delete(on: tx)
                } else {
                    relationship.status = record.relationshipPriorStatus ?? "disconnected"
                    try await relationship.update(on: tx)
                }
            }
            if let kid = record.approvalKid {
                try await ApproveKeyRecord.query(on: tx).filter(\.$kid == kid).filter(\.$enrollmentId == id).filter(\.$status == ApprovalKeyStatus.pending.rawValue)
                    .set(\.$status, to: ApprovalKeyStatus.revoked.rawValue).set(\.$revokedAt, to: now).set(\.$revokedBy, to: "system")
                    .set(\.$revokeReason, to: "link_\(reason)").update()
                revoked = try await ApproveKeyRecord.query(on: tx).filter(\.$kid == kid).first()
            }
            return (true, revoked)
        }
        guard swapped else { return }
        let wasCompleted = expected == LinkSessionStatus.deviceCompleted.rawValue
        _ = try await AuditService(db: db, ctx: ctx).record(wasCompleted && reason == "unconfirmed" ? "link.session_unconfirmed" : "link.session_\(status.rawValue)",
            outcome: wasCompleted ? .denied : .success, actor: actor, consumerId: record.claimedConsumerId.map(ConsumerID.init), businessId: BusinessID(record.businessId),
            subjectType: "link_session", subjectId: id.uuidString.lowercased(), metadata: ["reason": reason])
        if wasCompleted {
            try await LinkWebhooks(db: db, ctx: ctx).expired(businessId: record.businessId, sessionId: id)
            if let revokedKey { try await ApproveWebhooks(db: db, ctx: ctx).keyRevoked(revokedKey) }
            if let consumer = record.claimedConsumerId {
                await ApproveNotifier(db: db, ctx: ctx).notice(.businessLinkUnconfirmed, consumerId: consumer, subjectId: id.uuidString.lowercased())
            }
        }
    }

    /// Maintenance: open sessions past their expiry, and completed sessions the business never confirmed within the expiry plus the grace (reported).
    @discardableResult
    func expireDue(limit: Int = 100) async throws -> Int {
        let now = ctx.now
        let actor = AuditActor(kind: .system, id: "link-sweep")
        var count = 0
        // Read first so an idle tick takes no write lock.
        for record in try await LinkSessionRecord.query(on: db).filter(\.$status == LinkSessionStatus.open.rawValue).filter(\.$expiresAt <= now).limit(limit).all() {
            try await end(record, as: .expired, reason: "not_completed", actor: actor)
            count += 1
        }
        let cutoff = now.addingTimeInterval(-ctx.config.approve.unconfirmedGrace)
        for record in try await LinkSessionRecord.query(on: db).filter(\.$status == LinkSessionStatus.deviceCompleted.rawValue).filter(\.$expiresAt <= cutoff).limit(limit).all() {
            try await end(record, as: .expired, reason: "unconfirmed", actor: actor)
            count += 1
        }
        return count
    }

    // MARK: Device: read

    /// The account's own session (the account that completed it); anything else is `404`.
    func deviceRecord(principal: ConsumerPrincipal, id: UUID) async throws -> LinkSessionRecord {
        guard let record = try await LinkSessionRecord.find(id, on: db), record.claimedConsumerId == principal.consumerId.uuid else { throw APIError.notFound }
        return record
    }

    func deviceView(_ record: LinkSessionRecord, business: BusinessSummary? = nil) async throws -> LinkSessionDeviceView {
        let summary: BusinessSummary
        if let business { summary = business } else { summary = try await ApproveKeyService(db: db, ctx: ctx).businessSummary(record.businessId) }
        guard let subject = record.subjectRef.flatMap({ SubjectRef($0) }), let id = record.id else { throw APIError.notFound }
        let now = ctx.now
        let confirmBy = record.expiresAt.addingTimeInterval(ctx.config.approve.unconfirmedGrace)
        var connection: CustomerBusinessConnection?
        if let relationshipId = record.relationshipId, let relationship = try await RelationshipRecord.find(relationshipId, on: db) {
            connection = try await ConnectionViews(db: db, ctx: ctx).view(relationship)
        }
        let alertStatus: AlertStatus
        switch record.statusValue {
        case .deviceCompleted: alertStatus = confirmBy > now ? .pending : .expired
        case .confirmed: alertStatus = .completed
        case .expired: alertStatus = .expired
        case .cancelled: alertStatus = .cancelled
        case .open, .unknown: alertStatus = .pending
        }
        let alert = AlertDescriptor(eventId: AlertDescriptor.eventId(kind: "link_session", id: id), category: .linkConfirmation, businessId: summary.id,
                                    urgency: AlertUrgency(risk: record.needsApprovalKey ? .high : .medium), status: alertStatus, expiresAt: confirmBy,
                                    action: ActionRegistry.linkConnect.id, now: now)
        return LinkSessionDeviceView(sessionId: id, status: record.statusValue, business: summary, subjectRef: subject, capabilities: record.capabilityList,
                                     expiresAt: record.expiresAt, confirmBy: confirmBy, confirmation: record.signedConfirmation, connection: connection, alert: alert)
    }
}

/// The customer-facing connection view (spec v4 D2): today's relationship with its scopes and preferences.
struct ConnectionViews {
    let db: any Database
    let ctx: ServerContext

    func view(_ relationship: RelationshipRecord) async throws -> CustomerBusinessConnection {
        let status: ConnectionStatus = relationship.isActive ? .active : (relationship.isPendingLink ? .pending : .disconnected)
        let marketing = try await ConsentService(db: db, ctx: ctx).permits(purpose: .marketing, relationshipId: relationship.id!)
        let method = relationship.connectionMethod.flatMap { ConnectionMethod(rawValue: $0) }
            ?? ConnectionMethod(source: ConnectSource(rawValue: relationship.source) ?? .link)
        return CustomerBusinessConnection(relationshipId: RelationshipID(relationship.id!), businessId: BusinessID(relationship.businessId), status: status,
                                          method: method, scopes: relationship.scopeList,
                                          preferences: ConnectionPreferences(marketing: marketing, muted: relationship.prefMuted, favorite: relationship.prefFavorite),
                                          createdAt: relationship.connectedAt, linkedAt: relationship.linkedAt)
    }
}

/// Opaque link-session events (the v2 envelope carries the session id in `request_id`; the business fetches the session with its own key).
struct LinkWebhooks {
    let db: any Database
    let ctx: ServerContext

    struct Payload: Codable, Sendable {
        var sessionId: String
        enum CodingKeys: String, CodingKey { case sessionId = "session_id" }
    }

    func completed(businessId: UUID, sessionId: UUID) async throws {
        try await WebhookService(db: db, ctx: ctx).enqueue(.linkCompleted, businessId: BusinessID(businessId), payload: Payload(sessionId: sessionId.uuidString.lowercased()),
                                                           opaque: OpaqueWebhookEvent(requestId: sessionId.uuidString.lowercased(), resultRef: nil))
    }

    func expired(businessId: UUID, sessionId: UUID) async throws {
        try await WebhookService(db: db, ctx: ctx).enqueue(.linkExpired, businessId: BusinessID(businessId), payload: Payload(sessionId: sessionId.uuidString.lowercased()),
                                                           opaque: OpaqueWebhookEvent(requestId: sessionId.uuidString.lowercased(), resultRef: nil))
    }
}
