@preconcurrency import Crypto
import Fluent
import Foundation
import SQLKit
import Vapor
import ViadereCore

// Authority-verified recovery with sealed, key-bound codes (ADR-0032 §3, ADR-0034 §1-§4, lean HPKE construction; residual R-23). Behind
// `AUTHORITY_RECOVERY_ENABLED` (refused in production, C-16). The api never receives a code or a value it could test a code against.

struct AuthorityRecoveryService {
    let ctx: AuthorityContext
    let db: any Database

    static let hold: TimeInterval = 72 * 3600
    static let maxFailuresPerAccount = 5
    static let maxFailuresPerRecoveryId = 20

    struct StoredKey: Sendable { let kid: String; let publicKey: String; let purpose: String }

    static func storedKeys(_ json: String) -> [StoredKey] {
        guard case .array(let items)? = try? JSONDecoder().decode(JSONValue.self, from: Data(json.utf8)) else { return [] }
        return items.compactMap { item in
            guard let o = item.objectValue, let kid = o["kid"]?.stringValue, let key = o["public_key"]?.stringValue, let purpose = o["key_purpose"]?.stringValue else { return nil }
            return StoredKey(kid: kid, publicKey: key, purpose: purpose)
        }
    }

    /// `HMAC-SHA256(RECOVERY_VERIFIER_KEY, "recovery-code-v2\n" ‖ account_ref ‖ "\n" ‖ set_id ‖ "\n" ‖ normalized_code)`, lowercase hex.
    func verifier(accountRef: String, setId: String, code: String) -> String {
        Hex.encode(HMAC<SHA256>.authenticationCode(for: Data("recovery-code-v2\n\(accountRef)\n\(setId)\n\(code)".utf8), using: ctx.config.recoveryVerifierKey))
    }

    func requireSeal() throws -> SealKeyHolder {
        guard ctx.config.recoveryEnabled else { throw Abort(.notFound) }
        // Fail closed: no app-pinned unwrapped seal key, or one past its lifetime (ADR-0034 §8.1), opens nothing.
        guard let seal = ctx.seal, seal.notAfter > ctx.now else { throw Abort(.serviceUnavailable, reason: "recovery_unavailable") }
        return seal
    }

    // MARK: Challenges

    func prepareChallenge(_ purpose: AuthorityPurpose, _ o: [String: JSONValue], accountRef: String, binding: AuthorityChallengeBinding) async throws -> JSONValue {
        _ = try requireSeal()
        switch purpose {
        case .recoveryCodesSet:
            // The device names its own set id before it asks (S3-A3-05 item 1).
            guard Set(o.keys) == ["purpose", "account_id", "set_id"], let setId = o["set_id"]?.stringValue, RecoverySeal.isSetId(setId) else {
                throw Abort(.unprocessableEntity, reason: "invalid_request")
            }
            binding.setId = setId
            return AuthorityDisplay.recoveryCodesSet(setId: setId, count: RecoverySeal.codeCount)
        case .recoveryCancel:
            guard Set(o.keys) == ["purpose", "account_id"],
                  let pending = try await AuthorityRecovery.query(on: db).filter(\.$accountRef == accountRef).filter(\.$state == "pending").first() else {
                throw Abort(.unprocessableEntity, reason: "no_pending_recovery")
            }
            binding.recoveryId = pending.id
            return AuthorityDisplay.recoveryCancel(startedAt: Int64(pending.startedAt.timeIntervalSince1970), activatesAt: Int64(pending.activatesAt.timeIntervalSince1970))
        case .recoveryStarted:
            // The account is the one the api resolved from the recovery id; the authority binds the challenge to it (ADR-0034 §4 step 3).
            guard Set(o.keys) == ["purpose", "account_id", "recovery_id"], let recoveryId = o["recovery_id"]?.stringValue,
                  RecoveryCodeFormat.normalizeRecoveryID(recoveryId) == recoveryId else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
            guard try await AuthorityRecovery.query(on: db).filter(\.$accountRef == accountRef).filter(\.$state == "pending").count() == 0 else {
                throw Abort(.conflict, reason: "recovery_pending")
            }
            try await requireAttemptBudget(accountRef: accountRef, recoveryId: recoveryId)
            binding.recoveryId = recoveryId
            return AuthorityDisplay.recoveryStarted()
        default:
            throw Abort(.unprocessableEntity, reason: "purpose_not_supported")
        }
    }

    func requireAttemptBudget(accountRef: String, recoveryId: String) async throws {
        let since = ctx.now.addingTimeInterval(-86_400)
        let perAccount = try await AuthorityRecoveryAttempt.query(on: db).filter(\.$accountRef == accountRef).filter(\.$at > since).count()
        let perId = try await AuthorityRecoveryAttempt.query(on: db).filter(\.$recoveryId == recoveryId).count()
        guard perAccount < Self.maxFailuresPerAccount, perId < Self.maxFailuresPerRecoveryId else {
            await AuthorityAudit.record(db, "authority.recovery", outcome: "denied", reason: "attempt_limit", accountRef: accountRef, at: ctx.now)
            throw Abort(.tooManyRequests, reason: "recovery_attempt_limit")
        }
    }

    func recordFailure(accountRef: String, recoveryId: String, reason: String) async {
        let row = AuthorityRecoveryAttempt()
        row.accountRef = accountRef
        row.recoveryId = recoveryId
        row.reason = reason
        row.at = ctx.now
        try? await row.create(on: db)
    }

    // MARK: Factor-JWS purposes

    func evidence(_ c: AuthorityKeyLogService.Checked, _ o: [String: JSONValue], refuse: (String, String?) async -> Abort,
                  swap: (String, String) async throws -> Bool) async throws -> [String: JSONValue] {
        let ref = c.key.accountRef
        let now = ctx.now
        switch c.parsed.claims.purpose {
        case .recoveryCodesSet:
            let seal = try requireSeal()
            // D1-equivalent (ADR-0032 §3.1, ST-REC-16): a grant-capable approvalBiometric key past its cool-down.
            guard c.key.keyPurpose == DeviceKeyPurpose.approvalBiometric.rawValue, c.key.grantCapable, c.key.usableFrom <= now,
                  c.parsed.claims.userVerification == .biometric else { throw await refuse("approver_not_eligible", ref) }
            guard let envelopeValue = o["envelope"], let envelope = try? RecoverySealEnvelope.parse(envelopeValue) else { throw await refuse("envelope_malformed", ref) }
            guard let committed = c.parsed.claims.envelopeDigest, ConstantTime.equals(committed, envelope.digest) else { throw await refuse("envelope_digest", ref) }
            guard ConstantTime.equals(envelope.kid, seal.kid) else { throw await refuse("seal_kid", ref) }
            let plaintext: [String: JSONValue]
            do {
                plaintext = try RecoverySeal.open(envelope, with: seal.privateKey, purpose: .codesSet, environment: ctx.environment,
                                                  challengeId: c.challenge.id!, nonce: c.challenge.nonce)
            } catch { throw await refuse("envelope_open_failed", ref) }
            guard let set = try? RecoverySeal.parseSet(plaintext) else { throw await refuse("envelope_plaintext", ref) }
            guard ConstantTime.equals(set.accountRef, ref) else { throw await refuse("envelope_account", ref) }
            guard let boundSet = c.binding.setId, ConstantTime.equals(set.setId, boundSet) else { throw await refuse("envelope_set_id", ref) }
            guard ConstantTime.equals(set.nonce, c.challenge.nonce) else { throw await refuse("envelope_nonce", ref) }
            guard try await swap(c.challenge.id!, "used") else { throw await refuse("challenge_not_pending", ref) }
            let verifiers = set.codes.map { verifier(accountRef: ref, setId: set.setId, code: $0) }
            try await db.transaction { tx in
                try await AuthorityRecoveryCode.query(on: tx).filter(\.$accountRef == ref).filter(\.$state == "active").set(\.$state, to: "superseded").update()
                for value in verifiers {
                    let row = AuthorityRecoveryCode()
                    row.accountRef = ref
                    row.setId = set.setId
                    row.sealKid = seal.kid
                    row.verifier = value
                    row.state = "active"
                    row.createdAt = now
                    try await row.create(on: tx)
                }
                try await AuthorityKeyLog.append(tx, accountRef: ref, type: "recovery_codes_set", kid: c.key.id!, publicKey: c.key.publicKey, keyPurpose: c.key.keyPurpose,
                                                 detail: ["set_id": .string(set.setId), "count": .integer(Int64(verifiers.count)), "seal_kid": .string(seal.kid)], now: now)
            }
            await AuthorityAudit.record(db, "authority.recovery_codes_set", outcome: "success", accountRef: ref, challengeId: c.challenge.id, kid: c.key.id, at: now)
            return ["ach": .string(c.challenge.id!), "decision": .string("approve"), "head": .string(try await AuthorityHeads(ctx: ctx, db: db).signed(accountRef: ref))]
        case .recoveryCancel:
            guard ctx.config.recoveryEnabled else { throw Abort(.notFound) }
            // Reduce-only: any logged, active key of the account (grant capability not required).
            guard let recoveryRow = c.binding.recoveryId else { throw await refuse("binding", ref) }
            guard try await swap(c.challenge.id!, "used") else { throw await refuse("challenge_not_pending", ref) }
            try await db.transaction { tx in
                guard let recovery = try await AuthorityRecovery.find(recoveryRow, on: tx), recovery.state == "pending", recovery.accountRef == ref else { return }
                recovery.state = "cancelled"
                try await recovery.update(on: tx)
                try await AuthorityKeyLog.append(tx, accountRef: ref, type: "recovery_cancel", kid: c.key.id!, publicKey: c.key.publicKey, keyPurpose: c.key.keyPurpose,
                                                 detail: ["recovery_id": .string(recovery.recoveryId)], now: now)
            }
            await AuthorityAudit.record(db, "authority.recovery_cancel", outcome: "success", accountRef: ref, challengeId: c.challenge.id, kid: c.key.id, at: now)
            return ["ach": .string(c.challenge.id!), "decision": .string("approve"), "head": .string(try await AuthorityHeads(ctx: ctx, db: db).signed(accountRef: ref))]
        default:
            throw await refuse("purpose_not_supported", ref)
        }
    }

    // MARK: Sealed start (ADR-0032 §3.2, ADR-0034 §4)

    /// `{ach, envelope, keys:[{public_key, key_purpose, pop}]}`. The account is the one bound to the challenge, never a request value.
    func start(_ o: [String: JSONValue], caller: AuthorityCaller?) async throws -> [String: JSONValue] {
        let seal = try requireSeal()
        _ = try ctx.requireKeys()
        guard ctx.config.keylogEnabled, Set(o.keys) == ["ach", "envelope", "keys"] else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
        let now = ctx.now
        let ach = try AuthorityBody.string(o, "ach", max: 64)
        guard let challenge = try await AuthorityChallenge.find(ach, on: db), challenge.purpose == AuthorityPurpose.recoveryStarted.rawValue, challenge.state == "pending",
              challenge.expiresAt > now, let binding = try await AuthorityChallengeBinding.find(ach, on: db), let recoveryId = binding.recoveryId else {
            await AuthorityAudit.record(db, "authority.recovery", outcome: "denied", reason: "challenge", challengeId: ach, caller: caller?.name, at: now)
            throw Abort.evidenceInvalid
        }
        let ref = binding.accountRef
        func refuse(_ reason: String, counts: Bool) async -> Abort {
            if counts { await recordFailure(accountRef: ref, recoveryId: recoveryId, reason: reason) }
            await AuthorityAudit.record(db, "authority.recovery", outcome: "denied", reason: reason, accountRef: ref, challengeId: ach, caller: caller?.name, at: now)
            return Abort.evidenceInvalid
        }
        try await requireAttemptBudget(accountRef: ref, recoveryId: recoveryId)
        let keys: [SubmittedKey]
        do { keys = try SubmittedKey.parseList(o["keys"]) } catch { throw await refuse("keys_malformed", counts: false) }
        guard let envelopeValue = o["envelope"], let envelope = try? RecoverySealEnvelope.parse(envelopeValue) else { throw await refuse("envelope_malformed", counts: true) }
        guard ConstantTime.equals(envelope.kid, seal.kid) else { throw await refuse("seal_kid", counts: true) }
        let plaintext: [String: JSONValue]
        do {
            plaintext = try RecoverySeal.open(envelope, with: seal.privateKey, purpose: .start, environment: ctx.environment, challengeId: ach, nonce: challenge.nonce)
        } catch { throw await refuse("envelope_open_failed", counts: true) }
        guard let start = try? RecoverySeal.parseStart(plaintext), ConstantTime.equals(start.nonce, challenge.nonce), start.recoveryId == recoveryId else {
            throw await refuse("envelope_plaintext", counts: true)
        }
        // The PoP keys equal `new_kids` exactly (no superset, no subset), and each PoP commits to the envelope digest (ST-REC-15).
        guard RecoverySeal.sortedKids(keys.map(\.kid)) == start.newKids else { throw await refuse("new_kids_mismatch", counts: true) }
        let keyLog = AuthorityKeyLogService(ctx: ctx, db: db)
        guard keyLog.verifyPoPs(keys, type: "recovery_started", nonce: challenge.nonce, extra: [envelope.digest]) else { throw await refuse("pop_invalid", counts: true) }
        do { try await keyLog.requireUnused(keys.map(\.kid)) } catch { throw await refuse("key_in_use", counts: false) }
        // The verifier uses the account's single active authority set (S3-A3-05 item 2); no active set: nothing to verify against.
        guard let active = try await AuthorityRecoveryCode.query(on: db).filter(\.$accountRef == ref).filter(\.$state == "active").first() else {
            throw await refuse("no_active_set", counts: true)
        }
        let value = verifier(accountRef: ref, setId: active.setId, code: start.code)
        guard let sql = db as? any SQLDatabase else { throw Abort.evidenceInvalid }
        // Lookup by value and active → used in one compare-and-swap.
        let used = try await sql.update(AuthorityRecoveryCode.schema).set("state", to: "used").where("account_ref", .equal, ref).where("verifier", .equal, value)
            .where("state", .equal, "active").where("set_id", .equal, active.setId).returning("id").all()
        guard used.count == 1 else { throw await refuse("code_mismatch", counts: true) }
        guard try await keyLog.swap(ach, to: "used") else { throw await refuse("challenge_not_pending", counts: false) }
        let recovery = AuthorityRecovery()
        recovery.id = "rec_" + Base64URL.encode(SecureToken.randomBytes(16))
        recovery.accountRef = ref
        recovery.recoveryId = recoveryId
        recovery.keys = String(decoding: try CanonicalJSON.serialize(.array(keys.map(\.stored))), as: UTF8.self)
        recovery.legacy = false
        recovery.state = "pending"
        recovery.startedAt = now
        recovery.activatesAt = now.addingTimeInterval(Self.hold)
        recovery.challengeId = ach
        try await db.transaction { tx in
            try await recovery.create(on: tx)
            try await AuthorityKeyLog.append(tx, accountRef: ref, type: "recovery_started", kid: start.newKids[0], publicKey: "", keyPurpose: "",
                                             detail: ["recovery_id": .string(recoveryId), "kids": .array(start.newKids.map { .string($0) }),
                                                      "activates_at": .integer(Int64(recovery.activatesAt.timeIntervalSince1970))], now: now)
        }
        await AuthorityAudit.record(db, "authority.recovery_started", outcome: "success", accountRef: ref, challengeId: ach, caller: caller?.name, at: now)
        return ["recovery": .string(recovery.id!), "activates_at": .integer(Int64(recovery.activatesAt.timeIntervalSince1970)),
                "head": .string(try await AuthorityHeads(ctx: ctx, db: db).signed(accountRef: ref))]
    }

    /// A start without a sealed, authority-verified code (the api verified a legacy code): recorded as `recovery_started_legacy`, refused for an
    /// account with an active authority set; its keys are **never** grant-capable (ADR-0032 §3.2, §3.3).
    func legacyStart(_ o: [String: JSONValue], caller: AuthorityCaller?) async throws -> [String: JSONValue] {
        guard ctx.config.recoveryEnabled, ctx.config.keylogEnabled else { throw Abort(.notFound) }
        _ = try ctx.requireKeys()
        guard Set(o.keys) == ["account_id", "recovery_id", "nonce_id", "keys"], let recoveryId = o["recovery_id"]?.stringValue,
              RecoveryCodeFormat.normalizeRecoveryID(recoveryId) == recoveryId else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
        let keyLog = AuthorityKeyLogService(ctx: ctx, db: db)
        let account = try await keyLog.account(try AuthorityBody.accountId(o), caller: caller)
        let ref = account.accountRef
        let now = ctx.now
        guard try await AuthorityRecoveryCode.query(on: db).filter(\.$accountRef == ref).filter(\.$state == "active").count() == 0 else {
            await AuthorityAudit.record(db, "authority.recovery", outcome: "denied", reason: "legacy_with_authority_set", accountRef: ref, caller: caller?.name, at: now)
            throw Abort(.conflict, reason: "authority_set_active")
        }
        guard try await AuthorityRecovery.query(on: db).filter(\.$accountRef == ref).filter(\.$state == "pending").count() == 0 else { throw Abort(.conflict, reason: "recovery_pending") }
        let keys = try SubmittedKey.parseList(o["keys"])
        let nonce = try await keyLog.consumeNonce(try AuthorityBody.string(o, "nonce_id", max: 64), entryType: "recovery_started_legacy")
        guard keyLog.verifyPoPs(keys, type: "recovery_started_legacy", nonce: nonce) else { throw Abort.evidenceInvalid }
        try await keyLog.requireUnused(keys.map(\.kid))
        let recovery = AuthorityRecovery()
        recovery.id = "rec_" + Base64URL.encode(SecureToken.randomBytes(16))
        recovery.accountRef = ref
        recovery.recoveryId = recoveryId
        recovery.keys = String(decoding: try CanonicalJSON.serialize(.array(keys.map(\.stored))), as: UTF8.self)
        recovery.legacy = true
        recovery.state = "pending"
        recovery.startedAt = now
        recovery.activatesAt = now.addingTimeInterval(Self.hold)
        try await db.transaction { tx in
            try await recovery.create(on: tx)
            try await AuthorityKeyLog.append(tx, accountRef: ref, type: "recovery_started_legacy", kid: keys[0].kid, publicKey: "", keyPurpose: "",
                                             detail: ["recovery_id": .string(recoveryId), "kids": .array(RecoverySeal.sortedKids(keys.map(\.kid)).map { .string($0) })], now: now)
        }
        await AuthorityAudit.record(db, "authority.recovery_started_legacy", outcome: "success", accountRef: ref, caller: caller?.name, at: now)
        return ["recovery": .string(recovery.id!), "activates_at": .integer(Int64(recovery.activatesAt.timeIntervalSince1970))]
    }

    // MARK: Activation (maintenance; the authority enforces the hold even if the api lies)

    /// After 72 h without a cancel: adds **exactly** the start's keys, revokes every earlier key. Authority-verified starts give grant-capable keys
    /// (`usable_from` = activation); legacy starts never do.
    @discardableResult
    func activateDue() async throws -> Int {
        let now = ctx.now
        var count = 0
        for recovery in try await AuthorityRecovery.query(on: db).filter(\.$state == "pending").filter(\.$activatesAt <= now).limit(100).all() {
            let keys = Self.storedKeys(recovery.keys)
            try await db.transaction { tx in
                guard let fresh = try await AuthorityRecovery.find(recovery.id!, on: tx), fresh.state == "pending" else { return }
                for key in try await AuthorityKey.query(on: tx).filter(\.$accountRef == recovery.accountRef).filter(\.$revokedAt == nil).all() {
                    try await AuthorityKeyLog.revokeKey(tx, key, reason: "recovery_activated", by: "authority", now: now)
                }
                try await AuthorityKeyLogService.addKeys(tx, keys.map { ($0.kid, $0.publicKey, $0.purpose) }, accountRef: recovery.accountRef, entryType: "recovery_activated",
                                                         group: recovery.id!, usableFrom: now, grantCapable: false,
                                                         detail: ["recovery_id": .string(recovery.recoveryId), "legacy": .bool(recovery.legacy)], now: now)
                if !recovery.legacy {
                    try await AuthorityKey.query(on: tx).filter(\.$id ~~ keys.map(\.kid)).filter(\.$keyPurpose != DeviceKeyPurpose.request.rawValue)
                        .set(\.$grantCapable, to: true).update()
                }
                fresh.state = "activated"
                try await fresh.update(on: tx)
            }
            await AuthorityAudit.record(db, "authority.recovery_activated", outcome: "success", reason: recovery.legacy ? "legacy" : nil, accountRef: recovery.accountRef,
                                        caller: "authority", at: now)
            count += 1
        }
        return count
    }
}
