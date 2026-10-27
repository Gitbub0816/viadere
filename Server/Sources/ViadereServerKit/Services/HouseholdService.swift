import Fluent
import Foundation
import ViadereCore

/// Household (delegated) access: invitations, grants, revocation and the audit feed.
///
/// * A grant exists only after the invitee accepts a single-use code in their own app, so nobody can be given access to
///   someone's data without knowing it, and nobody needs another person's account id.
/// * Codes are stored as keyed hashes, expire after 24 hours, and lookups are rate-limited per consumer and globally, with a
///   hard attempt cap per invitation.
/// * Sensitive scopes (security, account service) need a fresh biometric step-up verified against the device's
///   `approvalBiometric` key, are single-use, and are capped at 30 days.
/// * Delegates can never approve `authenticate` or `authorize`; that is enforced by `InteractionService`, not by the client.
struct HouseholdService {
    let db: any Database
    let ctx: ServerContext

    static let maxOpenInvitations = 10
    static let maxGivenGrants = 25
    static let maxAttemptsPerInvitation = 10
    /// The id placed in `DelegationGrant.delegateId` while an invitation is pending (nobody has accepted yet).
    static let pendingDelegate = ConsumerID(UUID(uuidString: "00000000-0000-0000-0000-000000000000")!)
    private static let alphabet = Array("0123456789ABCDEFGHJKMNPQRSTVWXYZ")

    // MARK: Codes

    /// 40 random bits as `XXXX-XXXX` (Crockford base32 without I, L, O, U).
    static func generateCode() -> String {
        let chars = SecureToken.randomBytes(8).map { alphabet[Int($0) & 31] }
        return String(chars[0..<4]) + "-" + String(chars[4..<8])
    }

    static func normalizeCode(_ raw: String) -> String? {
        let cleaned = raw.uppercased().filter { !$0.isWhitespace && $0 != "-" }
        guard cleaned.count == 8 else { return nil }
        let mapped = cleaned.map { ch -> Character in
            switch ch {
            case "I", "L": "1"
            case "O": "0"
            default: ch
            }
        }
        guard mapped.allSatisfy({ alphabet.contains($0) }) else { return nil }
        return String(mapped)
    }

    func codeHash(_ normalized: String) -> String { ctx.hasher.hmacHex("delegation-invite", normalized) }

    // MARK: Names

    private func name(of consumer: UUID) async throws -> String {
        guard let record = try await ConsumerRecord.find(consumer, on: db), record.status == "active" else { return "Deleted account" }
        return record.displayName
    }

    /// A grant has the id of the invitation it came from, so the label's ciphertext (bound to that id) is valid on both rows.
    private func label(_ ciphertext: String?, rowId: UUID?) -> String {
        guard let ciphertext, let rowId, let text = try? ctx.cipher.openString(ciphertext, context: "delegation.label", rowId: rowId) else { return "Someone" }
        return text
    }

    private func businessNames(_ ids: [UUID]) async throws -> [String: String] {
        guard !ids.isEmpty else { return [:] }
        let businesses = try await BusinessRecord.query(on: db).filter(\.$id ~~ ids).all()
        return Dictionary(businesses.compactMap { b in b.id.map { ($0.uuidString.lowercased(), b.displayName) } }, uniquingKeysWith: { a, _ in a })
    }

    // MARK: Overview

    private func status(grant: DelegationGrantRecord, now: Date) -> HouseholdGrant.Status {
        if grant.revokedAt != nil { return .revoked }
        return now >= grant.expiresAt ? .expired : .active
    }

    func overview(consumer: ConsumerID) async throws -> HouseholdOverview {
        let now = ctx.now
        let id = consumer.uuid
        let given = try await DelegationGrantRecord.query(on: db).filter(\.$grantorId == id).sort(\.$createdAt, .descending).limit(100).all()
        let received = try await DelegationGrantRecord.query(on: db).filter(\.$delegateId == id).sort(\.$createdAt, .descending).limit(100).all()
        let invitations = try await DelegationInvitationRecord.query(on: db).filter(\.$grantorId == id).filter(\.$state != "accepted")
            .sort(\.$createdAt, .descending).limit(100).all()
        let allBusinessIds = Set(given.flatMap(\.businessIdSet) + received.flatMap(\.businessIdSet)
            + invitations.flatMap { $0.businessIds.split(separator: ",").compactMap { UUID(uuidString: String($0)) } })
        let names = try await businessNames(Array(allBusinessIds))
        func businessLabels(_ ids: [UUID]) -> [String] { ids.compactMap { names[$0.uuidString.lowercased()] } }

        var givenOut: [HouseholdGrant] = []
        for grant in given {
            guard let dto = grant.dto else { continue }
            givenOut.append(HouseholdGrant(grant: dto, counterpartName: label(grant.labelCiphertext, rowId: grant.id), businessNames: businessLabels(grant.businessIdSet),
                                           status: status(grant: grant, now: now)))
        }
        for invite in invitations {
            let purposes = invite.purposes.split(separator: ",").compactMap { InteractionPurpose(rawValue: String($0)) }
            let businessIds = invite.businessIds.split(separator: ",").compactMap { UUID(uuidString: String($0)) }
            let dto = DelegationGrant(id: DelegationID(invite.id!), grantorId: consumer, delegateId: Self.pendingDelegate,
                                      role: DelegationGrant.Role(rawValue: invite.role) ?? .viewer, purposes: purposes,
                                      businessIds: businessIds.map { BusinessID($0) }, createdAt: invite.createdAt, expiresAt: invite.grantExpiresAt)
            let state: HouseholdGrant.Status
            switch invite.state {
            case "open": state = invite.inviteExpiresAt > now && invite.grantExpiresAt > now ? .pending : .expired
            case "revoked": state = .revoked
            default: state = .expired   // locked after too many attempts
            }
            givenOut.append(HouseholdGrant(grant: dto, counterpartName: label(invite.labelCiphertext, rowId: invite.id), businessNames: businessLabels(businessIds), status: state))
        }
        givenOut.sort { $0.grant.createdAt > $1.grant.createdAt }

        var receivedOut: [HouseholdGrant] = []
        for grant in received {
            guard let dto = grant.dto else { continue }
            receivedOut.append(HouseholdGrant(grant: dto, counterpartName: try await name(of: grant.grantorId),
                                              businessNames: businessLabels(grant.businessIdSet), status: status(grant: grant, now: now)))
        }
        return HouseholdOverview(given: givenOut, received: receivedOut)
    }

    // MARK: Create invitation

    func createInvitation(principal: ConsumerPrincipal, request: DelegationInvitationRequest) async throws -> DelegationInvitation {
        guard let deviceId = principal.deviceId else { throw APIError.signatureInvalid }
        try await DeviceTrust.require(principal, db: db, now: ctx.now)
        let consumer = principal.consumerId
        try await ctx.limiter.enforce("household-invite-create", key: consumer.description, rule: ctx.config.rateLimits.inviteCreatePerConsumer)
        let now = ctx.now
        let label = request.delegateLabel.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (1...40).contains(label.count), !label.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw APIError.validation("Give the person a name of up to 40 characters.", details: ["delegateLabel": "invalid"])
        }
        let purposes = Set(request.purposes)
        guard !purposes.isEmpty, purposes.count == request.purposes.count,
              purposes.isSubset(of: DelegationScopePolicy.delegablePurposes) else {
            throw APIError.validation("Choose at least one kind of access that can be shared.", details: ["purposes": "invalid"])
        }
        let businessIds = Set(request.businessIds)
        guard !businessIds.isEmpty, businessIds.count == request.businessIds.count, businessIds.count <= 10 else {
            throw APIError.validation("Choose between one and ten businesses.", details: ["businessIds": "invalid"])
        }
        // The server decides sensitivity from the purposes; the client's flag is not trusted.
        let sensitive = DelegationScopePolicy.includesSensitiveScope(purposes: purposes)
        let lifetime = request.expiresAt.timeIntervalSince(now)
        guard lifetime >= DelegationScopePolicy.minimumLifetime else {
            throw APIError.validation("Access must last at least an hour.", details: ["expiresAt": "tooSoon"])
        }
        guard lifetime <= DelegationScopePolicy.maximumLifetime(includesSensitive: sensitive) else {
            throw APIError.validation(sensitive ? "Sensitive access can last at most 30 days." : "Access can last at most a year.",
                                      details: ["expiresAt": "tooFar"])
        }
        // Only businesses the grantor is actually connected to can be shared.
        let connected = Set(try await RelationshipRecord.query(on: db).filter(\.$consumerId == consumer.uuid).filter(\.$status == "active")
            .filter(\.$businessId ~~ businessIds.map(\.uuid)).all().map(\.businessId))
        guard connected.count == businessIds.count else {
            throw APIError.validation("You can only share access for businesses you are connected to.", details: ["businessIds": "notConnected"])
        }
        if sensitive { try await verifyStepUp(principal: principal, deviceId: deviceId, request: request, now: now) }
        guard try await DelegationInvitationRecord.query(on: db).filter(\.$grantorId == consumer.uuid).filter(\.$state == "open")
            .filter(\.$inviteExpiresAt > now).count() < Self.maxOpenInvitations,
              try await DelegationGrantRecord.query(on: db).filter(\.$grantorId == consumer.uuid).filter(\.$revokedAt == nil)
                .filter(\.$expiresAt > now).count() < Self.maxGivenGrants else {
            throw APIError.conflict("You have too many open invitations or active grants. Revoke some first.")
        }
        for _ in 0..<4 {
            let code = Self.generateCode()
            let record = DelegationInvitationRecord()
            record.id = UUID()
            record.grantorId = consumer.uuid
            record.labelCiphertext = try ctx.cipher.seal(label, context: "delegation.label", rowId: record.id!)
            record.role = request.role.rawValue
            record.purposes = request.purposes.map(\.rawValue).sorted().joined(separator: ",")
            record.businessIds = request.businessIds.map { $0.uuid.uuidString.lowercased() }.sorted().joined(separator: ",")
            record.grantExpiresAt = request.expiresAt
            record.codeHash = codeHash(Self.normalizeCode(code)!)
            record.inviteExpiresAt = now.addingTimeInterval(DelegationScopePolicy.invitationLifetime)
            record.attempts = 0
            record.state = "open"
            record.createdAt = now
            do {
                try await db.transaction { tx in
                    try await record.create(on: tx)
                    _ = try await AuditService(db: tx, ctx: ctx).record("delegation.created", actor: AuditActor(kind: .consumer, id: consumer.description),
                        consumerId: consumer, subjectType: "delegation", subjectId: record.id!.uuidString.lowercased(),
                        metadata: ["role": request.role.rawValue, "sensitive": sensitive ? "true" : "false", "grantorId": consumer.description])
                }
            } catch {
                if error.isConstraintViolation { continue }   // astronomically unlikely code collision: draw again
                throw error
            }
            return DelegationInvitation(id: DelegationID(record.id!), code: code, inviteExpiresAt: record.inviteExpiresAt)
        }
        throw APIError.internalError
    }

    /// Verifies the biometric proof: from this device, bound to exactly this scope, fresh, made by the device's
    /// `approvalBiometric` key (a passcode-gated key is not accepted), and never used before.
    private func verifyStepUp(principal: ConsumerPrincipal, deviceId: DeviceID, request: DelegationInvitationRequest, now: Date) async throws {
        func reject(_ reason: String, _ error: APIError) async throws -> Never {
            _ = try? await AuditService(db: db, ctx: ctx).record("delegation.stepup_rejected", outcome: .denied, principal: principal,
                subjectType: "delegation", metadata: ["reason": reason])
            throw error
        }
        guard let keyRecord = try await DeviceKeyRecord.query(on: db).filter(\.$deviceId == deviceId.uuid)
            .filter(\.$purpose == DeviceKeyPurpose.approvalBiometric.rawValue).first(),
              let publicKey = try? DevicePublicKey(base64URL: keyRecord.publicKey) else {
            try await reject("no_biometric_key", APIError(.forbidden, .insufficientAssurance, "Sharing this access needs Face ID or Touch ID on this device."))
        }
        do {
            try await DelegationStepUpVerifier.verify(request.stepUp, for: request, deviceId: deviceId, publicKey: publicKey, now: now,
                                                      replayGuard: DatabaseReplayGuard(db: db))
        } catch let failure as DelegationStepUpVerifier.Failure {
            switch failure {
            case .missing:
                try await reject("missing", APIError(.forbidden, .insufficientAssurance, "Sharing this access needs Face ID or Touch ID."))
            case .deviceMismatch, .scopeMismatch:
                try await reject("binding", .forbidden)
            case .malformedSignature:
                try await reject("malformed", .badRequest("The verification could not be read."))
            case .badSignature:
                try await reject("bad_signature", .signatureInvalid)
            case .signedInFuture:
                try await reject("signed_in_future", APIError(.unauthorized, .clockSkew, "The verification timestamp is invalid."))
            case .tooOld:
                try await reject("stale", APIError(.gone, .expired, "That verification is too old. Please try again."))
            case .replayed:
                try await reject("replayed", APIError(.conflict, .replayDetected, "That verification was already used."))
            }
        }
    }

    // MARK: Preview / accept

    /// Looks an invitation code up under three budgets:
    /// * the platform-wide budget (`household-invite-global`) and the per-consumer budget (`household-invite-attempt`) are **spent only by failed
    ///   lookups**: a lookup that finds a live invitation is refunded, so any number of accounts doing valid previews can never exhaust the
    ///   budget that guards against distributed guessing (and so cannot lock everyone else out). A budget that is already empty refuses the
    ///   lookup before it touches the database, valid code or not;
    /// * previews additionally have their own per-consumer limit (`household-invite-preview`, every preview counts).
    /// The per-invitation cap of 10 lookups is unchanged and independent of the budgets.
    private func lookup(code: String, consumer: ConsumerID) async throws -> DelegationInvitationRecord {
        let limits = ctx.config.rateLimits
        // Reserve a token from each failure budget up front (so an empty budget refuses), and give it back when the lookup succeeds.
        try await ctx.limiter.enforce("household-invite-attempt", key: consumer.description, rule: limits.inviteAttemptPerConsumer)
        do {
            try await ctx.limiter.enforce("household-invite-global", key: "all", rule: limits.inviteAttemptGlobal)
        } catch {
            await ctx.limiter.refund("household-invite-attempt", key: consumer.description, rule: limits.inviteAttemptPerConsumer)
            throw error
        }
        // A failed lookup throws here and keeps its tokens spent.
        let invitation = try await find(code: code, consumer: consumer)
        await ctx.limiter.refund("household-invite-attempt", key: consumer.description, rule: limits.inviteAttemptPerConsumer)
        await ctx.limiter.refund("household-invite-global", key: "all", rule: limits.inviteAttemptGlobal)
        return invitation
    }

    private func find(code: String, consumer: ConsumerID) async throws -> DelegationInvitationRecord {
        guard let normalized = Self.normalizeCode(code),
              let invitation = try await DelegationInvitationRecord.query(on: db).filter(\.$codeHash == codeHash(normalized)).first(),
              let id = invitation.id else { throw APIError.notFound }
        // The hard cap per invitation: past it the invitation is dead and the grantor must start over.
        if invitation.state == "open" {
            if invitation.attempts >= Self.maxAttemptsPerInvitation {
                _ = try await DB.swap(db, table: DelegationInvitationRecord.schema, id: id, column: "state", expected: "open", newValue: "locked")
                throw APIError.gone("This invitation is no longer valid.")
            }
            _ = try await DB.swap(db, table: DelegationInvitationRecord.schema, id: id, column: "attempts", expected: invitation.attempts,
                                  newValue: invitation.attempts + 1)
        }
        let now = ctx.now
        guard invitation.state == "open", invitation.inviteExpiresAt > now, invitation.grantExpiresAt > now else {
            throw APIError.gone("This invitation is no longer valid.")
        }
        // A person cannot accept their own invitation, and the grantor's account must still exist.
        guard invitation.grantorId != consumer.uuid else { throw APIError.notFound }
        guard let grantor = try await ConsumerRecord.find(invitation.grantorId, on: db), grantor.status == "active" else {
            throw APIError.gone("This invitation is no longer valid.")
        }
        return invitation
    }

    func preview(principal: ConsumerPrincipal, code: String) async throws -> DelegationInvitationPreview {
        try await ctx.limiter.enforce("household-invite-preview", key: principal.consumerId.description, rule: ctx.config.rateLimits.invitePreviewPerConsumer)
        let invitation = try await lookup(code: code, consumer: principal.consumerId)
        let businessIds = invitation.businessIds.split(separator: ",").compactMap { UUID(uuidString: String($0)) }
        let names = try await businessNames(businessIds)
        return DelegationInvitationPreview(
            grantorName: try await name(of: invitation.grantorId), role: DelegationGrant.Role(rawValue: invitation.role) ?? .viewer,
            purposes: invitation.purposes.split(separator: ",").compactMap { InteractionPurpose(rawValue: String($0)) },
            businessNames: businessIds.compactMap { names[$0.uuidString.lowercased()] }, expiresAt: invitation.grantExpiresAt)
    }

    func accept(principal: ConsumerPrincipal, code: String) async throws -> HouseholdGrant {
        try await DeviceTrust.require(principal, db: db, now: ctx.now)
        let consumer = principal.consumerId
        let invitation = try await lookup(code: code, consumer: consumer)
        let now = ctx.now
        let grant = DelegationGrantRecord()
        grant.id = invitation.id
        grant.grantorId = invitation.grantorId
        grant.delegateId = consumer.uuid
        grant.role = invitation.role
        grant.purposes = invitation.purposes
        grant.businessIds = invitation.businessIds
        grant.createdAt = now
        grant.expiresAt = invitation.grantExpiresAt
        grant.labelCiphertext = invitation.labelCiphertext
        grant.expiryRecorded = false
        do {
            try await db.transaction { tx in
                // Single use: only one accept can flip open → accepted, even across instances.
                guard try await DB.swap(tx, table: DelegationInvitationRecord.schema, id: invitation.id!, column: "state", expected: "open",
                                        newValue: "accepted", extra: [("accepted_at", now)]) else { throw ConcurrencyConflict() }
                try await grant.create(on: tx)
                _ = try await AuditService(db: tx, ctx: ctx).record("delegation.accepted", actor: AuditActor(kind: .consumer, id: consumer.description),
                    consumerId: ConsumerID(invitation.grantorId), subjectType: "delegation", subjectId: invitation.id!.uuidString.lowercased(),
                    metadata: ["grantorId": ConsumerID(invitation.grantorId).description, "delegateId": consumer.description])
            }
        } catch is ConcurrencyConflict {
            throw APIError.gone("This invitation is no longer valid.")
        }
        guard let dto = grant.dto else { throw APIError.internalError }
        let names = try await businessNames(grant.businessIdSet)
        return HouseholdGrant(grant: dto, counterpartName: try await name(of: grant.grantorId),
                              businessNames: grant.businessIdSet.compactMap { names[$0.uuidString.lowercased()] }, status: .active)
    }

    // MARK: Revoke

    /// The grantor or the delegate ends a grant (or the grantor cancels a pending invitation). Idempotent.
    func revoke(principal: ConsumerPrincipal, id: DelegationID) async throws {
        let consumer = principal.consumerId
        let now = ctx.now
        try await DeviceTrust.require(principal, db: db, now: now)
        if let grant = try await DelegationGrantRecord.find(id.uuid, on: db), grant.grantorId == consumer.uuid || grant.delegateId == consumer.uuid {
            guard grant.revokedAt == nil else { return }
            try await db.transaction { tx in
                guard try await DB.swapFromNull(tx, table: DelegationGrantRecord.schema, id: id.uuid, column: "revoked_at", newValue: now) else { return }
                _ = try await AuditService(db: tx, ctx: ctx).record("delegation.revoked", actor: AuditActor(kind: .consumer, id: consumer.description),
                    consumerId: ConsumerID(grant.grantorId), subjectType: "delegation", subjectId: id.description,
                    metadata: ["grantorId": ConsumerID(grant.grantorId).description, "delegateId": ConsumerID(grant.delegateId).description])
            }
            return
        }
        if let invitation = try await DelegationInvitationRecord.find(id.uuid, on: db), invitation.grantorId == consumer.uuid {
            guard invitation.state == "open" else { return }
            try await db.transaction { tx in
                guard try await DB.swap(tx, table: DelegationInvitationRecord.schema, id: id.uuid, column: "state", expected: "open", newValue: "revoked") else { return }
                _ = try await AuditService(db: tx, ctx: ctx).record("delegation.revoked", actor: AuditActor(kind: .consumer, id: consumer.description),
                    consumerId: consumer, subjectType: "delegation", subjectId: id.description, metadata: ["grantorId": consumer.description])
            }
            return
        }
        // Someone else's grant is indistinguishable from one that does not exist.
        throw APIError.notFound
    }

    /// Account deletion: every grant given or received ends and open invitations are cancelled.
    func endAll(for consumer: ConsumerID) async throws {
        let now = ctx.now
        for grant in try await DelegationGrantRecord.query(on: db).filter(\.$revokedAt == nil).group(.or, { or in
            or.filter(\.$grantorId == consumer.uuid)
            or.filter(\.$delegateId == consumer.uuid)
        }).all() {
            if try await DB.swapFromNull(db, table: DelegationGrantRecord.schema, id: grant.id!, column: "revoked_at", newValue: now) {
                _ = try await AuditService(db: db, ctx: ctx).record("delegation.revoked", actor: AuditActor(kind: .consumer, id: consumer.description),
                    consumerId: ConsumerID(grant.grantorId), subjectType: "delegation", subjectId: grant.id!.uuidString.lowercased(),
                    metadata: ["grantorId": ConsumerID(grant.grantorId).description, "reason": "account_deleted"])
            }
        }
        try await DelegationInvitationRecord.query(on: db).filter(\.$grantorId == consumer.uuid).filter(\.$state == "open").set(\.$state, to: "revoked").update()
    }

    // MARK: Access checks used by interactions

    func activeReceivedGrants(delegate: ConsumerID) async throws -> [DelegationGrantRecord] {
        let now = ctx.now
        return try await DelegationGrantRecord.query(on: db).filter(\.$delegateId == delegate.uuid).filter(\.$revokedAt == nil)
            .filter(\.$expiresAt > now).all()
    }

    // MARK: Audit feed

    func audit(consumer: ConsumerID) async throws -> [HouseholdAuditEntry] {
        let me = consumer.uuid
        let myId = consumer.description
        let events = try await AuditEventRecord.query(on: db).filter(\.$subjectType == "delegation").group(.or, { or in
            or.filter(\.$consumerId == me)
            or.filter(\.$actorId == myId)
        }).sort(\.$seq, .descending).limit(100).all()
        // Resolve every name in a few queries.
        let grantIds = Set(events.compactMap { $0.subjectId.flatMap { UUID(uuidString: $0) } })
        let grants = try await DelegationGrantRecord.query(on: db).filter(\.$id ~~ Array(grantIds)).all()
        let grantById = Dictionary(grants.compactMap { g in g.id.map { ($0, g) } }, uniquingKeysWith: { a, _ in a })
        let consumerIds = Set(events.compactMap { $0.actorId.flatMap { UUID(uuidString: $0) } } + events.compactMap(\.consumerId))
        let consumers = try await ConsumerRecord.query(on: db).filter(\.$id ~~ Array(consumerIds)).all()
        let consumerNames = Dictionary(consumers.compactMap { c in c.id.map { ($0, c.status == "active" ? c.displayName : "Deleted account") } }, uniquingKeysWith: { a, _ in a })
        let businessIds = Array(Set(events.compactMap(\.businessId)))
        let businesses = businessIds.isEmpty ? [] : try await BusinessRecord.query(on: db).filter(\.$id ~~ businessIds).all()
        let businessNames = Dictionary(businesses.compactMap { b in b.id.map { ($0, b.displayName) } }, uniquingKeysWith: { a, _ in a })

        return events.compactMap { event in
            guard let eventId = event.id else { return nil }
            let grantId = event.subjectId.flatMap { UUID(uuidString: $0) }
            let grantor = event.consumerId
            let actor = event.actorId.flatMap { UUID(uuidString: $0) }
            func displayName(_ id: UUID?, delegateLabelFor grant: UUID?) -> String {
                guard let id else { return "Viadere" }
                if id == me { return "You" }
                // The grantor sees the delegate by the label they chose.
                if grantor == me, let grant {
                    if let record = grantById[grant], record.delegateId == id { return label(record.labelCiphertext, rowId: record.id) }
                }
                return consumerNames[id] ?? "Someone"
            }
            let onBehalf: String? = ["delegation.used", "delegation.denied"].contains(event.action)
                ? (grantor == me ? "you" : grantor.flatMap { consumerNames[$0] } ?? "someone")
                : nil
            return HouseholdAuditEntry(id: AuditEventID(eventId), occurredAt: event.occurredAt, action: event.action,
                                       actorName: displayName(actor, delegateLabelFor: grantId),
                                       businessName: event.businessId.flatMap { businessNames[$0] },
                                       outcome: event.outcome == AuditEvent.Outcome.success.rawValue ? .success : .denied, onBehalfOfName: onBehalf)
        }
    }

    // MARK: Maintenance

    /// Writes the `delegation.expired` audit event once per grant that ran out.
    @discardableResult
    func recordExpired(limit: Int = 100) async throws -> Int {
        let now = ctx.now
        let due = try await DelegationGrantRecord.query(on: db).filter(\.$expiresAt <= now).filter(\.$revokedAt == nil)
            .filter(\.$expiryRecorded == false).limit(limit).all()
        var count = 0
        for grant in due {
            guard try await DB.swap(db, table: DelegationGrantRecord.schema, id: grant.id!, column: "expiry_recorded", expected: false, newValue: true) else { continue }
            _ = try await AuditService(db: db, ctx: ctx).record("delegation.expired", actor: AuditActor(kind: .system),
                consumerId: ConsumerID(grant.grantorId), subjectType: "delegation", subjectId: grant.id!.uuidString.lowercased(),
                metadata: ["grantorId": ConsumerID(grant.grantorId).description, "delegateId": ConsumerID(grant.delegateId).description])
            count += 1
        }
        return count
    }
}
