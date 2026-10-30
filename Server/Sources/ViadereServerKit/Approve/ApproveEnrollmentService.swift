import Fluent
import Foundation
import ViadereCore

/// Business-authorized enrollment of pairwise approval keys (APP-001, APP-002, ADR-06).
///
/// 1. The business starts an enrollment for an **existing relationship** (`subject_ref`, never a phone number) and shows the customer the
///    short code or QR in its own logged-in session.
/// 2. The customer's app looks the code up (only the relationship's own customer can), shows the verified business, creates a **pairwise
///    Secure Enclave key** and signs an enrollment statement with it (biometric for high and critical capabilities).
/// 3. The business verifies the statement itself and confirms it with a signature from its directory-published confirmation key.
///    The key becomes active only then, and the device checks that the confirmation covers **its** key.
///
/// **What the relay cannot do (gate finding F1).** The relay creates the code, stores the statement and forwards it, so it could make a key
/// of its own, sign a perfectly valid statement and hand it to the business. The server therefore *cannot* be the authority on whether a
/// statement came from the customer's device; the **business SDK is**, using a secret (`es`) that only the business and the customer's app
/// hold (the link/QR fragment, or the check code of the typed path). The device's `binding_tag` and the SAS typed into the business's own
/// session are verified there, before the SDK confirms. The server stores and forwards the tag and ends enrollments the business never
/// confirmed (`expireUnconfirmed`).
struct ApproveEnrollmentService {
    let db: any Database
    let ctx: ServerContext

    static let codeContext = "approve-enrollment-code"

    func codeHash(_ canonicalCode: String) -> String { ctx.hasher.hmacHex(Self.codeContext, canonicalCode) }

    // MARK: Business: create

    func create(principal: BusinessPrincipal, request: CreateApprovalEnrollmentRequest) async throws -> ApprovalEnrollmentTicket {
        guard request.capability == .authChallenge || request.capability == .transactionApprove else {
            throw APIError.validation("Approval enrollment is for auth.challenge or transaction.approve.", details: ["capability": "invalid"])
        }
        let lifetime = request.expiresInSeconds ?? Int(ctx.config.approve.enrollmentLifetime)
        guard (60...900).contains(lifetime) else { throw APIError.validation("expires_in_seconds must be between 60 and 900.", details: ["expires_in_seconds": "invalid"]) }
        let policy = PolicyService(db: db, ctx: ctx)
        try await policy.enforce(PolicyInput(request.capability), principal: principal, auditAllowed: false)
        let relationship = try await SubjectResolver(db: db, ctx: ctx).relationship(businessId: principal.businessId, subjectRef: request.subjectRef)
        guard relationship.isActive else { throw APIError.conflict("The customer is not connected to your business.") }
        try await Sandbox(db: db).requireMatching(relationship: relationship, livemode: principal.livemode)
        let subject = try await policy.subjectFacts(relationship: relationship, capability: request.capability, interactionPurpose: .security)
        try await policy.enforce(PolicyInput(request.capability, subjectRef: request.subjectRef, purpose: InteractionPurpose.security.rawValue), principal: principal,
                                 stage: .full, subject: subject)
        try await ApproveFreezeService(db: db, ctx: ctx).requireNotFrozen(consumerId: relationship.consumerId, relationshipId: relationship.id!)
        // The directory is part of the protocol: without a registered root and a published confirmation key the business could not confirm
        // the enrollment, and a device could not verify anything about it.
        let state = try await KeyLogService(db: db, ctx: ctx).state(for: principal.businessId.uuid)
        guard let root = state.currentRoot, !state.validKeys(for: .approvalEnrollmentConfirmation, at: ctx.now).isEmpty else {
            throw APIError(.conflict, .conflict, "Register your business root key and publish an approval-enrollment-confirmation key first.",
                           details: ["reason": "key_directory_required"])
        }
        try await ctx.limiter.enforce("approve-enrollment", key: principal.businessId.description, rule: ctx.config.approve.requestRate)
        let open = try await ApproveEnrollmentRecord.query(on: db).filter(\.$relationshipId == relationship.id!).filter(\.$status == ApprovalEnrollmentStatus.pending.rawValue)
            .filter(\.$expiresAt > ctx.now).count()
        guard open < ctx.config.approve.maxOpenEnrollmentsPerRelationship else { throw APIError(.tooManyRequests, .rateLimited, "Too many open enrollments for this customer.", headers: ["Retry-After": "60"]) }
        let activeKeys = try await ApproveKeyRecord.query(on: db).filter(\.$relationshipId == relationship.id!).filter(\.$status != ApprovalKeyStatus.revoked.rawValue).count()
        guard activeKeys < ctx.config.approve.maxKeysPerRelationship else { throw APIError.conflict("This customer already has the maximum number of approval keys. Revoke one first.") }

        let assurance = ApprovalAMR.required(for: request.capability.definition?.sensitivity ?? .critical)
        let now = ctx.now
        var created: ApproveEnrollmentRecord?
        var code = ""
        for _ in 0..<5 {
            code = ApprovalEnrollmentCode.generate()
            let record = ApproveEnrollmentRecord()
            record.id = UUID()
            record.businessId = principal.businessId.uuid
            record.relationshipId = relationship.id!
            record.consumerId = relationship.consumerId
            record.subjectRef = request.subjectRef.rawValue
            record.capability = request.capability.rawValue
            record.requiredAssurance = assurance.rawValue
            record.codeHash = codeHash(code)
            record.status = ApprovalEnrollmentStatus.pending.rawValue
            record.createdAt = now
            record.expiresAt = now.addingTimeInterval(TimeInterval(lifetime))
            do {
                try await record.create(on: db)
                created = record
                break
            } catch where error.isConstraintViolation { continue }   // a (vanishingly rare) code collision: draw another
        }
        guard let enrollment = created else { throw APIError.internalError }
        _ = try await AuditService(db: db, ctx: ctx).record("approve.enrollment_created", actor: AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased()),
            consumerId: ConsumerID(relationship.consumerId), businessId: principal.businessId, subjectType: "approve_enrollment", subjectId: enrollment.id?.uuidString.lowercased(),
            metadata: ["capability": request.capability.rawValue, "assurance": assurance.rawValue])
        return ApprovalEnrollmentTicket(enrollmentId: enrollment.id!, code: code, deepLink: ApprovalEnrollmentCode.deepLink(code: code, rootKid: root.kid, domain: ctx.config.linkDomain), expiresAt: enrollment.expiresAt)
    }

    // MARK: Business: read, cancel

    /// The business's own enrollment. A record of another business, or one on the other side of the test/live line, is a plain 404.
    func record(id: UUID, principal: BusinessPrincipal) async throws -> ApproveEnrollmentRecord {
        guard let record = try await ApproveEnrollmentRecord.query(on: db).filter(\.$id == id).filter(\.$businessId == principal.businessId.uuid).first(),
              try await Sandbox(db: db).matches(consumerId: record.consumerId, livemode: principal.livemode) else { throw APIError.notFound }
        return record
    }

    func businessView(_ record: ApproveEnrollmentRecord) throws -> ApprovalEnrollmentView {
        guard let subject = SubjectRef(record.subjectRef) else { throw APIError.internalError }
        var status = record.statusValue
        if status == .pending, record.expiresAt <= ctx.now { status = .expired }
        let confirmation = record.confirmation.flatMap { try? ViadereJSON.decode(BusinessSignedStatement.self, from: Data($0.utf8)) }
        return ApprovalEnrollmentView(enrollmentId: record.id!, subjectRef: subject, capability: Capability(rawValue: record.capability), status: status, expiresAt: record.expiresAt,
                                      createdAt: record.createdAt, deviceStatement: record.deviceStatement, kid: record.kid, confirmation: confirmation,
                                      bindingTag: record.bindingTag)
    }

    func cancel(principal: BusinessPrincipal, id: UUID) async throws -> ApproveEnrollmentRecord {
        let record = try await record(id: id, principal: principal)
        guard record.statusValue == .pending || record.statusValue == .deviceCompleted else { return record }
        let swapped = try await DB.swap(db, table: ApproveEnrollmentRecord.schema, id: id, column: "status", expected: record.status,
                                        newValue: ApprovalEnrollmentStatus.cancelled.rawValue, extra: [("cancelled_at", ctx.now)])
        if swapped, let kid = record.kid {
            try await ApproveKeyRecord.query(on: db).filter(\.$kid == kid).filter(\.$status == ApprovalKeyStatus.pending.rawValue)
                .set(\.$status, to: ApprovalKeyStatus.revoked.rawValue).set(\.$revokedAt, to: ctx.now).set(\.$revokedBy, to: "business").update()
        }
        _ = try await AuditService(db: db, ctx: ctx).record("approve.enrollment_cancelled", actor: AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased()),
            businessId: principal.businessId, subjectType: "approve_enrollment", subjectId: id.uuidString.lowercased())
        return try await self.record(id: id, principal: principal)
    }

    // MARK: Device: lookup

    /// Redeems nothing yet: shows what the code is for. Only the customer the enrollment was created for can see it, and wrong codes are
    /// rationed per customer and globally (the code space is 40 bits; the lifetime is minutes).
    func lookup(principal: ConsumerPrincipal, code: String) async throws -> ApproveEnrollmentPreview {
        let settings = ctx.config.approve
        try await ctx.limiter.enforce("approve-lookup", key: principal.consumerId.description, rule: settings.lookupRate)
        try await ctx.limiter.enforce("approve-lookup-global", key: "all", rule: settings.lookupRateGlobal)
        guard let canonical = ApprovalEnrollmentCode.canonical(code),
              let record = try await ApproveEnrollmentRecord.query(on: db).filter(\.$codeHash == codeHash(canonical)).first(),
              record.consumerId == principal.consumerId.uuid, record.statusValue == .pending, record.expiresAt > ctx.now,
              let deviceId = principal.deviceId else {
            _ = try? await AuditService(db: db, ctx: ctx).record("approve.enrollment_lookup_failed", outcome: .denied, principal: principal)
            throw APIError.notFound
        }
        guard let business = try await DirectoryService(db: db).verified(id: record.businessId), let summary = try await DirectoryService(db: db).summary(for: business),
              let subject = SubjectRef(record.subjectRef),
              let relationship = try await RelationshipRecord.find(record.relationshipId, on: db), relationship.isActive else { throw APIError.notFound }
        try await ApproveFreezeService(db: db, ctx: ctx).requireNotFrozen(consumerId: record.consumerId, relationshipId: record.relationshipId)
        try await ApproveEnrollmentRecord.query(on: db).filter(\.$id == record.id!).set(\.$claimedDeviceId, to: deviceId.uuid).update()
        return ApproveEnrollmentPreview(enrollmentId: record.id!, business: summary, relationshipId: RelationshipID(record.relationshipId), subjectRef: subject,
                                        capability: Capability(rawValue: record.capability), requiredAssurance: ApprovalAMR(rawValue: record.requiredAssurance) ?? .biometric,
                                        expiresAt: record.expiresAt)
    }

    // MARK: Device: complete

    func complete(principal: ConsumerPrincipal, enrollmentId: UUID, request: CompleteApproveEnrollmentRequest) async throws -> ApproveKey {
        let now = ctx.now
        guard let deviceId = principal.deviceId, let device = try await DeviceRecord.find(deviceId.uuid, on: db),
              device.consumerId == principal.consumerId.uuid else { throw APIError.signatureInvalid }
        let audit = AuditService(db: db, ctx: ctx)
        func reject(_ reason: String, _ error: APIError) async throws -> Never {
            _ = try? await audit.record("approve.enrollment_rejected", outcome: .denied, principal: principal, subjectType: "approve_enrollment",
                                        subjectId: enrollmentId.uuidString.lowercased(), metadata: ["reason": reason])
            throw error
        }
        guard let record = try await ApproveEnrollmentRecord.find(enrollmentId, on: db), record.consumerId == principal.consumerId.uuid,
              record.claimedDeviceId == device.id else { throw APIError.notFound }
        // Only a D1 device binds a key, or the business re-enrolls a D0 device of an account with no D1 device (a recovered account) with
        // an enrollment it opened after the device existed. A device nobody approved, on an account that has a trusted phone, cannot.
        guard try await DeviceTrust.mayCompleteBusinessEnrollment(device, enrollmentCreatedAt: record.createdAt, db: db, now: now) else {
            try await reject("device_not_trusted", DeviceTrust.notTrustedError(device, at: now))
        }
        guard record.statusValue == .pending else { try await reject("not_pending", .conflict("This enrollment is no longer open.")) }
        guard record.expiresAt > now else { try await reject("expired", .gone("This enrollment has expired.")) }
        try await ApproveFreezeService(db: db, ctx: ctx).requireNotFrozen(consumerId: record.consumerId, relationshipId: record.relationshipId)
        guard let business = try await DirectoryService(db: db).verified(id: record.businessId) else { throw APIError.gone("This business is no longer available.") }
        guard let subject = SubjectRef(record.subjectRef) else { throw APIError.internalError }
        let statement: ApprovalEnrollmentStatement
        do {
            statement = try ApprovalEnrollmentStatement.verify(request.statement)
            try statement.checkBinding(businessId: BusinessID(record.businessId), subject: subject, enrollmentId: enrollmentId)
        } catch {
            try await reject("statement_invalid", .validation("The enrollment statement is not valid.", details: ["statement": "invalid"]))
        }
        // The key must be at least as strong as the capability requires (biometric for high and critical).
        let required = ApprovalAMR(rawValue: record.requiredAssurance) ?? .biometric
        guard statement.assurance.satisfies(required) else {
            try await reject("assurance_too_low", APIError(.forbidden, .insufficientAssurance, "This business needs an approval key protected by Face ID or Touch ID."))
        }
        // The statement is bounded in time (a stale statement cannot be replayed into a later enrollment: the enrollment id binds it anyway).
        guard abs(now.timeIntervalSince(Date(timeIntervalSince1970: TimeInterval(statement.createdAt)))) <= 600 else {
            try await reject("statement_stale", .validation("The enrollment statement is stale.", details: ["statement": "stale"]))
        }
        let active = try await ApproveKeyRecord.query(on: db).filter(\.$relationshipId == record.relationshipId).filter(\.$status != ApprovalKeyStatus.revoked.rawValue).count()
        guard active < ctx.config.approve.maxKeysPerRelationship else { try await reject("too_many_keys", .conflict("Too many approval keys for this business.")) }

        // The binding tag is opaque to the relay (it does not hold the secret); only its shape is checked.
        if let tag = request.bindingTag, !Base64URL.isValid(tag, minLength: 43, maxLength: 43) {
            try await reject("binding_tag_invalid", .validation("The binding tag is not valid.", details: ["binding_tag": "invalid"]))
        }
        let key = ApproveKeyRecord()
        key.id = UUID()
        key.kid = statement.kid
        key.enrollmentId = enrollmentId
        key.businessId = record.businessId
        key.relationshipId = record.relationshipId
        key.consumerId = record.consumerId
        key.deviceId = device.id!
        key.subjectRef = record.subjectRef
        key.publicKey = statement.publicKey.base64URL
        key.hpkeKid = statement.hpkePublicKey.kid
        key.hpkePublicKey = statement.hpkePublicKey.base64URL
        key.assurance = statement.assurance.rawValue
        key.status = ApprovalKeyStatus.pending.rawValue
        key.statementPayload = request.statement.payload
        key.statementSignature = request.statement.signature
        key.createdAt = now
        do {
            try await db.transaction { tx in
                // Compare-and-swap: one enrollment completes once, whoever races.
                var extra: [(String, any Encodable & Sendable)] = [("statement_payload", request.statement.payload), ("statement_signature", request.statement.signature),
                                                                   ("kid", statement.kid), ("device_completed_at", now)]
                if let tag = request.bindingTag { extra.append(("binding_tag", tag)) }
                let swapped = try await DB.swap(tx, table: ApproveEnrollmentRecord.schema, id: enrollmentId, column: "status", expected: ApprovalEnrollmentStatus.pending.rawValue,
                                                newValue: ApprovalEnrollmentStatus.deviceCompleted.rawValue, extra: extra)
                guard swapped else { throw APIError.conflict("This enrollment is no longer open.") }
                try await key.create(on: tx)
            }
        } catch {
            // A key (or HPKE key) that already exists is a reused key: pairwise means one key, one relationship.
            if error.isConstraintViolation { try await reject("key_reused", .conflict("This key was already used.")) }
            throw error
        }
        _ = try await audit.record("approve.enrollment_device_completed", principal: principal, businessId: BusinessID(record.businessId), subjectType: "approve_enrollment",
                                   subjectId: enrollmentId.uuidString.lowercased(), metadata: ["assurance": statement.assurance.rawValue])
        guard let completed = try await ApproveEnrollmentRecord.find(enrollmentId, on: db) else { throw APIError.internalError }
        try await ApproveWebhooks(db: db, ctx: ctx).enrollmentDeviceCompleted(completed)
        let keys = ApproveKeyService(db: db, ctx: ctx)
        _ = business
        return try keys.deviceView(key, business: try await keys.businessSummary(record.businessId))
    }

    // MARK: Business: confirm

    /// The business's signed confirmation activates the key. The confirming key must be one the **directory** currently publishes for this
    /// business (so the relay cannot confirm on the business's behalf), and the confirmation must cover exactly the statement the device made.
    func confirm(principal: BusinessPrincipal, id: UUID, request: ConfirmApprovalEnrollmentRequest) async throws -> ApproveKeyRecord {
        let record = try await record(id: id, principal: principal)
        let audit = AuditService(db: db, ctx: ctx)
        let actor = AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased())
        func reject(_ reason: String, _ error: APIError) async throws -> Never {
            _ = try? await audit.record("approve.enrollment_confirm_rejected", outcome: .denied, actor: actor, businessId: principal.businessId, subjectType: "approve_enrollment",
                                        subjectId: id.uuidString.lowercased(), metadata: ["reason": reason])
            throw error
        }
        // A key the business does not confirm within the enrollment's lifetime (plus a short grace) is ended, not left pending for a relay to use later.
        guard record.expiresAt.addingTimeInterval(ctx.config.approve.unconfirmedGrace) > ctx.now else {
            try await reject("confirmation_too_late", .gone("This enrollment has expired. Start a new one."))
        }
        guard record.statusValue == .deviceCompleted, let statement = record.deviceStatement, let kid = record.kid,
              let key = try await ApproveKeyRecord.query(on: db).filter(\.$kid == kid).first() else { throw APIError.conflict("This enrollment is not waiting for confirmation.") }
        let state = try await KeyLogService(db: db, ctx: ctx).state(for: principal.businessId.uuid)
        guard let published = state.validKey(kid: request.confirmation.kid, purpose: .approvalEnrollmentConfirmation, at: ctx.now), let signing = published.signingKey else {
            try await reject("confirmation_key_not_published", APIError(.forbidden, .forbidden, "The confirmation key is not published in your key directory.", details: ["reason": "key_not_published"]))
        }
        do {
            let confirmation = try ApprovalEnrollmentConfirmation.verify(request.confirmation, confirmationKey: signing)
            let parsed = try ApprovalEnrollmentStatement.verify(statement)
            try confirmation.checkMatches(parsed, signed: statement)
        } catch {
            try await reject("confirmation_invalid", .validation("The confirmation does not match the enrollment.", details: ["confirmation": "invalid"]))
        }
        let now = ctx.now
        let confirmationJSON = String(decoding: try ViadereJSON.encode(request.confirmation), as: UTF8.self)
        try await db.transaction { tx in
            let swapped = try await DB.swap(tx, table: ApproveEnrollmentRecord.schema, id: id, column: "status", expected: ApprovalEnrollmentStatus.deviceCompleted.rawValue,
                                            newValue: ApprovalEnrollmentStatus.confirmed.rawValue, extra: [("confirmation", confirmationJSON), ("confirmed_at", now)])
            guard swapped else { throw APIError.conflict("This enrollment is no longer waiting for confirmation.") }
            try await ApproveKeyRecord.query(on: tx).filter(\.$id == key.id!).filter(\.$status == ApprovalKeyStatus.pending.rawValue)
                .set(\.$status, to: ApprovalKeyStatus.active.rawValue).set(\.$activatedAt, to: now).set(\.$confirmation, to: confirmationJSON).update()
        }
        _ = try await audit.record("approve.key_activated", actor: actor, consumerId: ConsumerID(record.consumerId), businessId: principal.businessId,
                                   subjectType: "approve_key", subjectId: kid, metadata: ["assurance": key.assurance])
        if let confirmed = try await ApproveEnrollmentRecord.find(id, on: db) { try await ApproveWebhooks(db: db, ctx: ctx).enrollmentConfirmed(confirmed) }
        await ApproveNotifier(db: db, ctx: ctx).notice(.approvalKeyEnrolled, consumerId: record.consumerId, subjectId: kid)
        guard let active = try await ApproveKeyRecord.find(key.id!, on: db) else { throw APIError.internalError }
        return active
    }

    // MARK: Unconfirmed keys

    /// Ends every enrollment the device completed but the business never confirmed (gate finding F1): the pending key is revoked, the
    /// customer gets a notice, and the business gets `approve.key.revoked` and an audit record. A key that stays unconfirmed is either a
    /// business that lost the flow or a relay holding a key back to confirm later, and neither is allowed to linger.
    @discardableResult
    func expireUnconfirmed(limit: Int = 100) async throws -> Int {
        let cutoff = ctx.now.addingTimeInterval(-ctx.config.approve.unconfirmedGrace)
        let overdue = try await ApproveEnrollmentRecord.query(on: db).filter(\.$status == ApprovalEnrollmentStatus.deviceCompleted.rawValue)
            .filter(\.$expiresAt <= cutoff).limit(limit).all()
        var count = 0
        for record in overdue {
            guard try await DB.swap(db, table: ApproveEnrollmentRecord.schema, id: record.id!, column: "status", expected: ApprovalEnrollmentStatus.deviceCompleted.rawValue,
                                    newValue: ApprovalEnrollmentStatus.expired.rawValue) else { continue }
            count += 1
            var revoked: ApproveKeyRecord?
            if let kid = record.kid {
                try await ApproveKeyRecord.query(on: db).filter(\.$kid == kid).filter(\.$status == ApprovalKeyStatus.pending.rawValue)
                    .set(\.$status, to: ApprovalKeyStatus.revoked.rawValue).set(\.$revokedAt, to: ctx.now).set(\.$revokedBy, to: "system").update()
                revoked = try await ApproveKeyRecord.query(on: db).filter(\.$kid == kid).first()
            }
            _ = try await AuditService(db: db, ctx: ctx).record("approve.enrollment_unconfirmed", outcome: .denied, actor: AuditActor(kind: .system, id: "approve-sweep"),
                consumerId: ConsumerID(record.consumerId), businessId: BusinessID(record.businessId), subjectType: "approve_enrollment",
                subjectId: record.id?.uuidString.lowercased(), metadata: ["kid": record.kid ?? ""])
            if let revoked { try await ApproveWebhooks(db: db, ctx: ctx).keyRevoked(revoked) }
            await ApproveNotifier(db: db, ctx: ctx).notice(.approvalKeyUnconfirmed, consumerId: record.consumerId, subjectId: record.kid)
        }
        return count
    }

    // MARK: Device: the account's keys

    func deviceKeys(principal: ConsumerPrincipal) async throws -> [ApproveKey] {
        let rows = try await ApproveKeyRecord.query(on: db).filter(\.$consumerId == principal.consumerId.uuid).sort(\.$createdAt, .descending).all()
        let keys = ApproveKeyService(db: db, ctx: ctx)
        var out: [ApproveKey] = []
        var summaries: [UUID: BusinessSummary] = [:]
        for row in rows {
            if summaries[row.businessId] == nil { summaries[row.businessId] = try? await keys.businessSummary(row.businessId) }
            guard let summary = summaries[row.businessId] else { continue }
            out.append(try keys.deviceView(row, business: summary))
        }
        return out
    }
}
