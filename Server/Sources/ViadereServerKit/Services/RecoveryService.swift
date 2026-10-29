import Fluent
import FluentSQL
import Foundation
import SQLKit
import ViadereCore

/// Account recovery with single-use recovery codes (SECURITY.md §2.25).
///
/// * **Codes.** 10 codes `XXXXX-XXXXX` (50 bits each) and a recovery ID `XXXX-XXXX-XXXX` (60 bits) are issued at registration (and by
///   `regenerate`), shown once. Only peppered HMACs are stored; a new set replaces the old one **and** the recovery ID.
/// * **begin** spends one code (compare-and-swap `active → used`) and returns options for a NEW passkey. Every failure is the same
///   `401`, so it cannot be used to find accounts; per-IP and global budgets apply and an account locks for 24 h after 5 wrong codes
///   (the account's devices get a notice).
/// * **finish** registers the new passkey **without activating it** and starts the 72 h hold: every existing device gets an in-app
///   notice and a push ("Not you? Cancel"), and any trusted device can cancel.
/// * **activation** (after 72 h without cancellation): the new passkey becomes the account's only passkey, every device and session is
///   revoked, the remaining codes are invalidated, and the recovering client receives 10 new codes once (`complete`).
struct RecoveryService {
    let db: any Database
    let ctx: ServerContext

    static let maxFailedAttempts = 5
    static let lockDuration: TimeInterval = 24 * 3600

    // MARK: Hashing

    func codeHash(consumerId: UUID, normalized: String) -> String {
        ctx.hasher.hmacHex("recovery-code", "\(consumerId.uuidString.lowercased())\n\(normalized)")
    }

    func recoveryIdHash(normalized: String) -> String { ctx.hasher.hmacHex("recovery-id", normalized) }

    private func audit(_ action: String, outcome: AuditEvent.Outcome = .success, consumer: UUID?, subject: UUID? = nil, actor: AuditActor = AuditActor(kind: .system),
                       metadata: [String: String] = [:]) async {
        _ = try? await AuditService(db: db, ctx: ctx).record(action, outcome: outcome, actor: actor, consumerId: consumer.map { ConsumerID($0) },
                                                            subjectType: "recovery", subjectId: subject?.uuidString.lowercased(), metadata: metadata)
    }

    // MARK: Issuing

    /// Issues a fresh set: every active code dies, the recovery ID changes, the failure counter resets. Call inside the caller's
    /// transaction when the set must be committed together with something else (registration).
    @discardableResult
    func issueCodes(consumerId: UUID) async throws -> RecoveryCodeSet {
        let now = ctx.now
        let recoveryId = RecoveryCodeFormat.generateRecoveryID()
        guard let normalizedId = RecoveryCodeFormat.normalizeRecoveryID(recoveryId) else { throw APIError.internalError }
        var codes: [String] = []
        while codes.count < RecoveryPolicy.codeCount {
            let code = RecoveryCodeFormat.generateCode()
            if !codes.contains(code) { codes.append(code) }
        }
        try await RecoveryCodeRecord.query(on: db).filter(\.$consumerId == consumerId).filter(\.$state == "active").set(\.$state, to: "invalidated").update()
        if let profile = try await RecoveryProfileRecord.query(on: db).filter(\.$consumerId == consumerId).first() {
            profile.recoveryIdHash = recoveryIdHash(normalized: normalizedId)
            profile.failedAttempts = 0
            profile.lockedUntil = nil
            profile.issuedAt = now
            try await profile.update(on: db)
        } else {
            try await RecoveryProfileRecord(consumerId: consumerId, recoveryIdHash: recoveryIdHash(normalized: normalizedId), now: now).create(on: db)
        }
        for code in codes {
            guard let normalized = RecoveryCodeFormat.normalizeCode(code) else { throw APIError.internalError }
            try await RecoveryCodeRecord(consumerId: consumerId, codeHash: codeHash(consumerId: consumerId, normalized: normalized), now: now).create(on: db)
        }
        await audit("recovery.codes_issued", consumer: consumerId, metadata: ["count": String(codes.count)])
        return RecoveryCodeSet(recoveryId: recoveryId, codes: codes, issuedAt: now)
    }

    // MARK: Begin

    static let globalRule = RateRule.perHour(300, burst: 60)
    static let perIdRule = RateRule.perHour(20, burst: 10)

    func begin(_ request: RecoveryBeginRequest) async throws -> PasskeyRegistrationOptions {
        let failure = APIError(.unauthorized, .unauthorized, "Recovery could not be started. Check the recovery ID and the code.")
        // Both values are hashed whatever they are, so the work does not depend on whether the account exists.
        let normalizedId = RecoveryCodeFormat.normalizeRecoveryID(request.recoveryId)
        let normalizedCode = RecoveryCodeFormat.normalizeCode(request.code)
        let idHash = recoveryIdHash(normalized: normalizedId ?? "invalid")
        // Malformed input is rejected before any shared budget is touched (the per-IP middleware still counts it), so a flood of garbage
        // cannot use up what a real recovery needs.
        guard normalizedId != nil, let normalizedCode else { throw failure }
        // Per recovery ID: guessing codes for one account is bounded here, whatever the number of source addresses. Refunded on success.
        try await ctx.limiter.enforce("recovery-begin-id", key: idHash, rule: Self.perIdRule)
        guard let profile = try await RecoveryProfileRecord.query(on: db).filter(\.$recoveryIdHash == idHash).first(), let profileId = profile.id,
              let consumer = try await ConsumerRecord.find(profile.consumerId, on: db), consumer.status == "active" else {
            // An ID that names no account: this is what guessing the ID space looks like, so it is what the global budget bounds. The
            // known-ID path below never waits on it, so a flood of made-up IDs from many addresses cannot lock a real recovery out.
            try await ctx.limiter.enforce("recovery-begin-global", key: "all", rule: Self.globalRule)
            throw failure
        }
        let now = ctx.now
        let consumerId = profile.consumerId
        // From here every failure is charged to the global budget too (a success is not).
        func fail(_ reason: String? = nil) async -> APIError {
            _ = await ctx.limiter.allow("recovery-begin-global", key: "all", rule: Self.globalRule)
            if let reason { await audit("recovery.begin_denied", outcome: .denied, consumer: consumerId, metadata: ["reason": reason]) }
            return failure
        }
        if let locked = profile.lockedUntil, locked > now { throw await fail("locked") }
        // One recovery at a time: a competing begin does not burn a code. (The unique index on open recoveries is what makes this
        // hold under concurrency; this check only saves the code in the common case.)
        try await expireStale(consumerId: consumerId)
        if try await AccountRecoveryRecord.query(on: db).filter(\.$consumerId == consumerId).filter(\.$state ~~ ["awaiting_passkey", "holding"]).count() > 0 {
            throw await fail("in_progress")
        }
        let hash = codeHash(consumerId: consumerId, normalized: normalizedCode)
        guard let code = try await RecoveryCodeRecord.query(on: db).filter(\.$consumerId == consumerId).filter(\.$codeHash == hash)
            .filter(\.$state == "active").first(), let codeId = code.id else {
            try await recordFailure(profileId: profileId, consumerId: consumerId)
            throw await fail()
        }
        let challenge = Base64URL.encode(ctx.passkeys.makeChallenge())
        // A device-first account gets its WebAuthn user handle here if it never added a passkey.
        let userHandle = try await RecoveryCredentialService.ensureUserHandle(consumerId, db: db)
        let recovery = AccountRecoveryRecord(consumerId: consumerId, challenge: challenge, userHandle: userHandle, now: now)
        // Spending the code and opening the recovery are one transaction: losing the race for the single open-recovery slot (unique
        // index violation) rolls the code back, so a competing begin burns nothing.
        enum Outcome { case started, wrongCode, inProgress }
        let outcome: Outcome
        do {
            outcome = try await db.transaction { tx in
                guard try await DB.swap(tx, table: RecoveryCodeRecord.schema, id: codeId, column: "state", expected: "active", newValue: "used",
                                        extra: [("used_at", now)]) else { return .wrongCode }
                try await recovery.create(on: tx)
                return .started
            }
        } catch {
            guard error.isConstraintViolation else { throw error }
            outcome = .inProgress
        }
        switch outcome {
        case .wrongCode:
            try await recordFailure(profileId: profileId, consumerId: consumerId)
            throw await fail()
        case .inProgress:
            throw await fail("in_progress")
        case .started:
            break
        }
        try await RecoveryProfileRecord.query(on: db).filter(\.$id == profileId).set(\.$failedAttempts, to: 0).update()
        await ctx.limiter.refund("recovery-begin-id", key: idHash, rule: Self.perIdRule)
        await audit("recovery.code_accepted", consumer: consumerId, subject: recovery.id)
        return PasskeyRegistrationOptions(ceremonyId: CeremonyID(recovery.id!), challenge: challenge, relyingPartyId: ctx.config.relyingPartyID,
                                          relyingPartyName: ctx.config.relyingPartyName, userId: userHandle, userName: consumer.label,
                                          userDisplayName: consumer.label, timeoutMilliseconds: Int(RecoveryPolicy.passkeyWindow * 1000))
    }

    /// Counts a wrong code atomically; at the cap the account locks for a day and its devices are told.
    private func recordFailure(profileId: UUID, consumerId: UUID) async throws {
        guard let sql = db as? any SQLDatabase else { throw APIError.internalError }
        let row = try await sql.raw("UPDATE recovery_profiles SET failed_attempts = failed_attempts + 1 WHERE id = \(bind: profileId) RETURNING failed_attempts").first()
        let attempts = try row?.decode(column: "failed_attempts", as: Int.self) ?? 0
        await audit("recovery.begin_failed", outcome: .failure, consumer: consumerId, metadata: ["attempts": String(attempts)])
        if attempts >= Self.maxFailedAttempts {
            let until = ctx.now.addingTimeInterval(Self.lockDuration)
            try await RecoveryProfileRecord.query(on: db).filter(\.$id == profileId).set(\.$lockedUntil, to: until).set(\.$failedAttempts, to: 0).update()
            await audit("recovery.locked", outcome: .denied, consumer: consumerId, metadata: ["hours": String(Int(Self.lockDuration / 3600))])
            await SecurityNotices(db: db, ctx: ctx).notifyOtherDevices(of: consumerId, except: nil, notice: .recoveryAttemptsLocked)
        }
    }

    private func expireStale(consumerId: UUID) async throws {
        let now = ctx.now
        try await AccountRecoveryRecord.query(on: db).filter(\.$consumerId == consumerId).filter(\.$state == "awaiting_passkey")
            .filter(\.$passkeyExpiresAt <= now).set(\.$state, to: "expired").update()
    }

    // MARK: Finish

    func finish(_ request: RecoveryFinishRequest) async throws -> RecoveryStatus {
        let failure = APIError(.unauthorized, .unauthorized, "Recovery could not be completed. Start again.")
        let now = ctx.now
        guard let recovery = try await AccountRecoveryRecord.find(request.ceremonyId.uuid, on: db), recovery.state == "awaiting_passkey",
              recovery.passkeyExpiresAt > now, let challenge = Base64URL.decode(recovery.challenge), let recoveryId = recovery.id else { throw failure }
        let database = db
        let verified: VerifiedPasskeyRegistration
        do {
            verified = try await ctx.passkeys.verifyRegistration(request.credential, challenge: challenge) { credentialId in
                let used = try await PasskeyCredentialRecord.query(on: database).filter(\.$credentialId == credentialId).count() > 0
                let pending = try await AccountRecoveryRecord.query(on: database).filter(\.$newCredentialId == credentialId).count() > 0
                return used || pending
            }
        } catch {
            await audit("recovery.passkey_failed", outcome: .failure, consumer: recovery.consumerId, subject: recoveryId)
            throw failure
        }
        let token = SecureToken.generate()
        let holdUntil = now.addingTimeInterval(RecoveryPolicy.holdSeconds)
        // The "Recovery started" notice is stored in the same transaction as the hold: if it cannot be stored the recovery does not start
        // (an owner who is never told is exactly what the hold exists to prevent). The push afterwards is best effort.
        let consumerId = recovery.consumerId
        let started: Bool = try await db.transaction { tx in
            guard try await DB.swap(tx, table: AccountRecoveryRecord.schema, id: recoveryId, column: "state", expected: "awaiting_passkey",
                                    newValue: "holding", extra: [("new_credential_id", verified.credentialId),
                                                                 ("new_public_key", Base64URL.encode(verified.publicKey)),
                                                                 ("new_sign_count", Int(verified.signCount)),
                                                                 ("new_backup_eligible", verified.backupEligible),
                                                                 ("status_token_hash", SecureToken.hash(token)), ("hold_until", holdUntil)]) else { return false }
            try await SecurityNotices(db: tx, ctx: ctx).store(of: consumerId, except: nil, notice: .recoveryStarted, subjectId: RecoveryID(recoveryId).description)
            return true
        }
        guard started else { throw failure }
        await audit("recovery.started", consumer: consumerId, subject: recoveryId, metadata: ["activates_at": ViadereDate.format(holdUntil)])
        await SecurityNotices(db: db, ctx: ctx).push(to: consumerId, except: nil, notice: .recoveryStarted)
        return RecoveryStatus(id: RecoveryID(recoveryId), state: .holding, startedAt: recovery.createdAt, activatesAt: holdUntil, statusToken: token)
    }

    // MARK: Cancel

    /// "Not you? Cancel": any trusted device of the account. It also kills the account's remaining recovery codes (whoever started this
    /// held at least one), so the person must make new ones.
    func cancel(_ principal: ConsumerPrincipal, id: RecoveryID) async throws -> RecoveryStatus {
        try await ctx.limiter.enforce("recovery-cancel", key: principal.consumerId.description, rule: .perHour(30, burst: 10))
        let now = ctx.now
        let caller = try await DeviceTrust.require(principal, db: db, now: now)
        guard let recovery = try await AccountRecoveryRecord.find(id.uuid, on: db), recovery.consumerId == principal.consumerId.uuid else { throw APIError.notFound }
        switch recovery.state {
        case "cancelled": return status(recovery)
        case "holding", "awaiting_passkey": break
        default: throw APIError.conflict("This recovery can no longer be cancelled.")
        }
        let cancelled: Bool = try await db.transaction { tx in
            guard try await DB.swap(tx, table: AccountRecoveryRecord.schema, id: id.uuid, column: "state", expected: recovery.state, newValue: "cancelled",
                                    extra: [("cancelled_at", now)]) else { return false }
            // Every other open recovery of the account closes with it: cancelling one must never leave another able to activate.
            try await AccountRecoveryRecord.query(on: tx).filter(\.$consumerId == principal.consumerId.uuid).filter(\.$state ~~ ["awaiting_passkey", "holding"])
                .set(\.$state, to: "cancelled").set(\.$cancelledAt, to: now).update()
            try await RecoveryCodeRecord.query(on: tx).filter(\.$consumerId == principal.consumerId.uuid).filter(\.$state == "active")
                .set(\.$state, to: "invalidated").update()
            _ = try await AuditService(db: tx, ctx: ctx).record("recovery.cancelled", principal: principal, subjectType: "recovery", subjectId: id.description)
            return true
        }
        guard cancelled else { throw APIError.conflict("This recovery can no longer be cancelled.") }
        await SecurityNotices(db: db, ctx: ctx).notifyOtherDevices(of: principal.consumerId.uuid, except: caller.id, notice: .recoveryCancelled, subjectId: id.description)
        guard let fresh = try await AccountRecoveryRecord.find(id.uuid, on: db) else { throw APIError.notFound }
        return status(fresh)
    }

    // MARK: Complete (poll, activate, hand over the new codes once)

    func complete(_ request: RecoveryCompleteRequest) async throws -> RecoveryStatus {
        let failure = APIError(.unauthorized, .unauthorized, "This recovery could not be found.")
        try await ctx.limiter.enforce("recovery-complete", key: request.recoveryId.description, rule: .perHour(120, burst: 30))
        guard request.statusToken.count <= 128, var recovery = try await AccountRecoveryRecord.find(request.recoveryId.uuid, on: db),
              let hash = recovery.statusTokenHash, SecureToken.matches(request.statusToken, hash: hash) else { throw failure }
        let now = ctx.now
        if recovery.state == "holding", let hold = recovery.holdUntil, hold <= now {
            try await activate(recovery)
            guard let fresh = try await AccountRecoveryRecord.find(request.recoveryId.uuid, on: db) else { throw failure }
            recovery = fresh
        }
        var codes: RecoveryCodeSet?
        if recovery.state == "activated", recovery.codesIssuedAt == nil, let activated = recovery.activatedAt,
           now.timeIntervalSince(activated) <= RecoveryPolicy.completionWindow, let id = recovery.id {
            // Exactly one caller wins the right to see the new codes.
            let consumerId = recovery.consumerId
            codes = try await db.transaction { tx -> RecoveryCodeSet? in
                guard try await DB.swapFromNull(tx, table: AccountRecoveryRecord.schema, id: id, column: "codes_issued_at", newValue: now) else { return nil }
                return try await RecoveryService(db: tx, ctx: ctx).issueCodes(consumerId: consumerId)
            }
        }
        var result = status(recovery)
        result.recoveryCodes = codes
        return result
    }

    private func status(_ recovery: AccountRecoveryRecord) -> RecoveryStatus {
        let state: RecoveryState
        switch recovery.state {
        case "awaiting_passkey": state = .awaitingPasskey
        case "holding": state = .holding
        case "activated": state = .activated
        case "cancelled": state = .cancelled
        default: state = .expired
        }
        return RecoveryStatus(id: RecoveryID(recovery.id ?? UUID()), state: state, startedAt: recovery.createdAt, activatesAt: recovery.holdUntil)
    }

    // MARK: Activation

    /// The hold passed without cancellation: the new passkey becomes the account's passkey, every old device and session is revoked,
    /// the remaining codes die. Idempotent and safe to race (compare-and-swap on the state).
    func activate(_ recovery: AccountRecoveryRecord) async throws {
        let now = ctx.now
        guard recovery.state == "holding", let hold = recovery.holdUntil, hold <= now, let id = recovery.id,
              let credentialId = recovery.newCredentialId, let publicKey = recovery.newPublicKey else { return }
        let consumerId = recovery.consumerId
        var counterparts: [UUID] = []
        do {
            counterparts = try await db.transaction { tx -> [UUID] in
                guard try await DB.swap(tx, table: AccountRecoveryRecord.schema, id: id, column: "state", expected: "holding", newValue: "activated",
                                        extra: [("activated_at", now)]) else { throw ConcurrencyConflict() }
                let deviceIds = try await DeviceRecord.query(on: tx).filter(\.$consumerId == consumerId).filter(\.$revokedAt == nil).all().compactMap(\.id)
                try await DeviceLifecycle(db: tx, ctx: ctx).revoke(deviceIds: deviceIds, now: now)
                try await ConsumerTokenService(db: tx, ctx: ctx).revokeAll(consumerId: consumerId, now: now)
                try await PasskeyCredentialRecord.query(on: tx).filter(\.$consumerId == consumerId).delete()
                try await PasskeyCredentialRecord(consumerId: consumerId, credentialId: credentialId, publicKey: publicKey,
                                                  signCount: recovery.newSignCount ?? 0, backupEligible: recovery.newBackupEligible ?? false, now: now).create(on: tx)
                try await RecoveryCodeRecord.query(on: tx).filter(\.$consumerId == consumerId).filter(\.$state == "active").set(\.$state, to: "invalidated").update()
                // Recovery proves possession of a code, not that this is the person the household and the phone numbers were trusted
                // for: third-party trust does not carry over. Delegation grants (both directions) end and open invitations are cancelled;
                // every phone link goes back into cool-down (confirmable from a trusted device with Face ID).
                let ended = try await HouseholdService(db: tx, ctx: ctx).endAll(for: ConsumerID(consumerId), reason: "account_recovered")
                let phonesCooling = try await PhoneLinkService.coolDownAll(consumerId: consumerId, until: now.addingTimeInterval(RecoveryPolicy.holdSeconds), on: tx)
                let notices = SecurityNotices(db: tx, ctx: ctx)
                try await notices.store(of: consumerId, except: nil, notice: .recoveryCompleted, subjectId: id.uuidString.lowercased())
                for other in ended { try await notices.store(of: other, except: nil, notice: .delegationEnded, subjectId: id.uuidString.lowercased()) }
                _ = try await AuditService(db: tx, ctx: ctx).record("recovery.activated", actor: AuditActor(kind: .system), consumerId: ConsumerID(consumerId),
                    subjectType: "recovery", subjectId: id.uuidString.lowercased(),
                    metadata: ["devices_revoked": String(deviceIds.count), "delegations_ended": String(ended.count), "phones_cooling": String(phonesCooling)])
                return ended
            }
        } catch is ConcurrencyConflict {
            return
        }
        for other in counterparts { await SecurityNotices(db: db, ctx: ctx).push(to: other, except: nil, notice: .delegationEnded) }
    }

    // MARK: Maintenance

    func sweep() async throws {
        let now = ctx.now
        let due = try await AccountRecoveryRecord.query(on: db).filter(\.$state == "holding").filter(\.$holdUntil <= now).limit(100).all()
        for recovery in due { try await activate(recovery) }
        try await AccountRecoveryRecord.query(on: db).filter(\.$state == "awaiting_passkey").filter(\.$passkeyExpiresAt <= now)
            .set(\.$state, to: "expired").update()
        // A finished recovery's status token stops working after the completion window.
        let stale = now.addingTimeInterval(-RecoveryPolicy.completionWindow)
        try await AccountRecoveryRecord.query(on: db).filter(\.$state == "activated").filter(\.$activatedAt <= stale)
            .filter(\.$statusTokenHash != nil).set(\.$statusTokenHash, to: nil).update()
    }

    // MARK: Settings (trusted device)

    func info(_ principal: ConsumerPrincipal) async throws -> RecoveryInfo {
        let consumerId = principal.consumerId.uuid
        let remaining = try await RecoveryCodeRecord.query(on: db).filter(\.$consumerId == consumerId).filter(\.$state == "active").count()
        let profile = try await RecoveryProfileRecord.query(on: db).filter(\.$consumerId == consumerId).first()
        let holding = try await AccountRecoveryRecord.query(on: db).filter(\.$consumerId == consumerId).filter(\.$state == "holding")
            .sort(\.$createdAt, .ascending).all()
        let pending = holding.compactMap { row -> PendingRecovery? in
            guard let id = row.id, let until = row.holdUntil else { return nil }
            return PendingRecovery(id: RecoveryID(id), startedAt: row.createdAt, activatesAt: until)
        }
        let passkeys = try await PasskeyCredentialRecord.query(on: db).filter(\.$consumerId == consumerId).count()
        return RecoveryInfo(remainingCodes: remaining, issuedAt: profile?.issuedAt, pending: pending.first, pendingRecoveries: pending, passkeyCount: passkeys)
    }

    /// Step 1 of regeneration: a single-use ceremony (its id is what the device's `recoveryCredential` proof names) with passkey assertion
    /// options over its challenge for older apps. Needs a device that may manage the account.
    func regenerateBegin(_ principal: ConsumerPrincipal) async throws -> PasskeyAssertionOptions {
        try await ctx.limiter.enforce("recovery-regen", key: principal.consumerId.description, rule: .perHour(20, burst: 10))
        _ = try await DeviceTrust.require(principal, db: db, now: ctx.now)
        let challenge = Base64URL.encode(ctx.passkeys.makeChallenge())
        let ceremony = PasskeyCeremonyRecord(kind: "recovery_codes", challenge: challenge, consumerId: principal.consumerId.uuid, displayName: nil,
                                             userHandle: nil, now: ctx.now, ttl: AuthService.ceremonyTTL)
        try await ceremony.create(on: db)
        let credentialIds = try await PasskeyCredentialRecord.query(on: db).filter(\.$consumerId == principal.consumerId.uuid).all().map(\.credentialId)
        return PasskeyAssertionOptions(ceremonyId: CeremonyID(ceremony.id!), challenge: challenge, relyingPartyId: ctx.config.relyingPartyID,
                                       allowCredentialIds: credentialIds, timeoutMilliseconds: Int(AuthService.ceremonyTTL * 1000))
    }

    /// Step 2: a device that may manage the account **and** a user-verified proof from it over the step-1 ceremony id (or, from older apps, a
    /// fresh user-verified passkey assertion over its challenge). The old codes die; the new set is returned once.
    func regenerate(_ principal: ConsumerPrincipal, request: RecoveryCodesRegenerateRequest) async throws -> RecoveryCodeSet {
        try await ctx.limiter.enforce("recovery-regen", key: principal.consumerId.description, rule: .perHour(20, burst: 10))
        let now = ctx.now
        let device = try await DeviceTrust.require(principal, db: db, now: now)
        let required = APIError(.unauthorized, .passkeyAssertionRequired, "Confirm with Face ID, Touch ID or your passcode to make new recovery codes.")
        guard let ceremony = try await PasskeyCeremonyRecord.find(request.ceremonyId.uuid, on: db), ceremony.kind == "recovery_codes", ceremony.state == "open",
              ceremony.expiresAt > now, ceremony.consumerId == principal.consumerId.uuid, let challenge = Base64URL.decode(ceremony.challenge),
              let consumer = try await ConsumerRecord.find(principal.consumerId.uuid, on: db), consumer.status == "active" else { throw required }
        if let proof = request.proof {
            // This device's user-verified approval key over the ceremony id (§2.5a): no passkey needed.
            try await RecoveryCredentialService(db: db, ctx: ctx).verifyProof(proof, ceremonyId: request.ceremonyId.uuid, principal: principal, device: device)
            guard try await DB.swap(db, table: PasskeyCeremonyRecord.schema, id: request.ceremonyId.uuid, column: "state", expected: "open", newValue: "used") else { throw required }
        } else {
            // Older apps: a fresh user-verified passkey assertion over the ceremony's challenge.
            guard let assertion = request.assertion, assertion.id.count <= 1024,
                  let credential = try await PasskeyCredentialRecord.query(on: db).filter(\.$credentialId == assertion.id)
                      .filter(\.$consumerId == principal.consumerId.uuid).first(), let publicKey = Base64URL.decode(credential.publicKey) else { throw required }
            if let handle = assertion.userHandle, !ConstantTime.equals(handle, consumer.userHandle ?? "") { throw required }
            guard try await DB.swap(db, table: PasskeyCeremonyRecord.schema, id: request.ceremonyId.uuid, column: "state", expected: "open", newValue: "used") else { throw required }
            do {
                let result = try ctx.passkeys.verifyAssertion(assertion, challenge: challenge, publicKey: publicKey, signCount: UInt32(clamping: credential.signCount))
                credential.signCount = Int(result.newSignCount)
                credential.lastUsedAt = now
                try await credential.update(on: db)
            } catch {
                _ = try? await AuditService(db: db, ctx: ctx).record("recovery.codes_failed", outcome: .failure, principal: principal, subjectType: "recovery")
                throw required
            }
        }
        // Whoever started a recovery held a code of the old set. A trusted device that makes a new set closes every recovery still waiting
        // (the old codes die, and so must what they started).
        let (set, cancelled): (RecoveryCodeSet, [UUID]) = try await db.transaction { tx in
            let open = try await AccountRecoveryRecord.query(on: tx).filter(\.$consumerId == principal.consumerId.uuid)
                .filter(\.$state ~~ ["awaiting_passkey", "holding"]).all()
            if !open.isEmpty {
                try await AccountRecoveryRecord.query(on: tx).filter(\.$consumerId == principal.consumerId.uuid).filter(\.$state ~~ ["awaiting_passkey", "holding"])
                    .set(\.$state, to: "cancelled").set(\.$cancelledAt, to: now).update()
                for row in open {
                    _ = try await AuditService(db: tx, ctx: ctx).record("recovery.cancelled", principal: principal, subjectType: "recovery",
                                                                       subjectId: row.id?.uuidString.lowercased(), metadata: ["reason": "codes_regenerated"])
                }
            }
            let set = try await RecoveryService(db: tx, ctx: ctx).issueCodes(consumerId: principal.consumerId.uuid)
            _ = try await AuditService(db: tx, ctx: ctx).record("recovery.codes_regenerated", principal: principal, subjectType: "recovery")
            return (set, open.compactMap(\.id))
        }
        for id in cancelled {
            await SecurityNotices(db: db, ctx: ctx).notifyOtherDevices(of: principal.consumerId.uuid, except: principal.deviceId?.uuid, notice: .recoveryCancelled,
                                                                       subjectId: RecoveryID(id).description)
        }
        return set
    }
}
