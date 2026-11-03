@preconcurrency import Crypto
import Fluent
import Foundation
import SQLKit
import Vapor
import ViadereCore

// Key-log entries that need proof (ADR-0023 §4, ADR-0032 §1, ADR-0033 §1, §2, §4.1): genesis with authority-minted account ids, enrollment
// confirmation committing to the head, device add with the comparison code and the C-13 caps, and signed heads. Behind `AUTHORITY_KEYLOG_ENABLED`.
// The api relays; every decision is made here from the authority's own records.

/// One key submitted with its proof of possession.
struct SubmittedKey: Sendable {
    let publicKey: DevicePublicKey
    let signingKey: P256.Signing.PublicKey
    let kid: String
    let purpose: String
    let pop: String

    /// Keys an entry may add: the three app keys (ADR-0032 §3.2); approval keys only for genesis and device add.
    static let purposes: Set<String> = [DeviceKeyPurpose.request.rawValue, DeviceKeyPurpose.approvalUserPresence.rawValue, DeviceKeyPurpose.approvalBiometric.rawValue]

    /// Strict parse of `keys: [{public_key, key_purpose, pop}]` (1-4 keys, distinct, at least one approval key).
    static func parseList(_ value: JSONValue?) throws -> [SubmittedKey] {
        guard case .array(let items)? = value, (1...4).contains(items.count) else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
        var out: [SubmittedKey] = []
        for item in items {
            guard let o = item.objectValue, Set(o.keys) == ["public_key", "key_purpose", "pop"], let text = o["public_key"]?.stringValue,
                  let publicKey = try? DevicePublicKey(base64URL: text), let signing = try? publicKey.signingKey(), let purpose = o["key_purpose"]?.stringValue,
                  purposes.contains(purpose), let pop = o["pop"]?.stringValue else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
            out.append(SubmittedKey(publicKey: publicKey, signingKey: signing, kid: KeyIdentifier.make(signing), purpose: purpose, pop: pop))
        }
        guard Set(out.map(\.kid)).count == out.count, out.contains(where: { $0.purpose != DeviceKeyPurpose.request.rawValue }) else {
            throw Abort(.unprocessableEntity, reason: "invalid_request")
        }
        return out
    }

    var stored: JSONValue { .object(["kid": .string(kid), "public_key": .string(publicKey.base64URL), "key_purpose": .string(purpose)]) }
}

/// Body helpers: closed objects, nothing the authority would act on can be smuggled.
enum AuthorityBody {
    static func object(_ req: Request, allowed: Set<String>, required: Set<String> = []) throws -> [String: JSONValue] {
        guard req.headers.contentType == .json, let buffer = req.body.data,
              case .object(let o)? = try? JSONDecoder().decode(JSONValue.self, from: Data(buffer: buffer)),
              Set(o.keys).isSubset(of: allowed), required.isSubset(of: Set(o.keys)) else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
        return o
    }

    static func accountId(_ o: [String: JSONValue]) throws -> UUID {
        guard let id = o["account_id"]?.stringValue.flatMap(UUID.init(uuidString:)) else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
        return id
    }

    static func string(_ o: [String: JSONValue], _ key: String, max: Int = 512) throws -> String {
        guard let value = o[key]?.stringValue, !value.isEmpty, value.utf8.count <= max else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
        return value
    }
}

extension Abort {
    static var accountUnknown: Abort { Abort(.notFound, reason: "account_unknown") }
    static var keyInUse: Abort { Abort(.conflict, reason: "key_in_use") }
}

/// Signed key-log heads (ADR-0033 §2): computed from the log and the current-key view, cached, re-signed when the log changed or the cached statement
/// is older than 5 minutes when served (so `GET head` is not a Key Vault `sign` per request).
struct AuthorityHeads {
    let ctx: AuthorityContext
    let db: any Database
    static let resignAfter: TimeInterval = 300

    func compute(accountRef: String) async throws -> AuthorityKeyLogHead {
        let last = try await AuthorityKeylogEntry.query(on: db).filter(\.$accountRef == accountRef).sort(\.$seq, .descending).first()
        let keys = try await AuthorityKey.query(on: db).filter(\.$accountRef == accountRef).filter(\.$revokedAt == nil).all()
        var listed: [AuthorityKeyLogHead.Key] = []
        for key in keys.sorted(by: { $0.id! < $1.id! }) {
            let entry = try await AuthorityKeyEntry.find(key.id!, on: db)
            let type = entry?.entryType ?? "imported"
            listed.append(.init(kid: key.id!, purpose: key.keyPurpose, usableFrom: Int64(key.usableFrom.timeIntervalSince1970), entryType: type,
                                imported: type == "imported", grantCapable: key.grantCapable))
        }
        let pending = try await AuthorityRecovery.query(on: db).filter(\.$accountRef == accountRef).filter(\.$state == "pending").all().map { r in
            AuthorityKeyLogHead.PendingRecovery(recoveryId: r.recoveryId, startedAt: Int64(r.startedAt.timeIntervalSince1970), activatesAt: Int64(r.activatesAt.timeIntervalSince1970),
                                                legacy: r.legacy, kids: AuthorityRecoveryService.storedKeys(r.keys).map(\.kid))
        }
        return AuthorityKeyLogHead(environment: ctx.environment, accountRef: accountRef, seq: Int64(last?.seq ?? -1), headHash: last?.entryHash ?? AuthorityKeyLog.genesisHash,
                                   keys: listed, pendingRecoveries: pending, recoverySet: try await recoverySetState(accountRef),
                                   issuedAt: Int64(ctx.now.timeIntervalSince1970))
    }

    /// `active` while a set is usable; `refresh_suggested` when its seal key is no longer the active ready key; `invalidated` after an exposure.
    func recoverySetState(_ accountRef: String) async throws -> String {
        let rows = try await AuthorityRecoveryCode.query(on: db).filter(\.$accountRef == accountRef).filter(\.$state ~~ ["active", "invalidated"]).all()
        if let active = rows.first(where: { $0.state == "active" }) {
            let seal = try await AuthoritySealKey.find(active.sealKid, on: db)
            return seal?.state == "ready" && seal?.role == "active" ? "active" : "refresh_suggested"
        }
        return rows.isEmpty ? "none" : "invalidated"
    }

    /// The signed head for an account; re-signed when stale or when anything it states changed (keys, grant capability, pending recoveries,
    /// recovery-set state), not only when the chain grew. The cache key is the digest of the payload without `issued_at`.
    func signed(accountRef: String) async throws -> String {
        let keys = try ctx.requireKeys()
        let head = try await compute(accountRef: accountRef)
        var content = head.payload
        content["issued_at"] = nil
        let digest = SecureToken.sha256Hex(try CanonicalJSON.serialize(.object(content)))
        if let cached = try await AuthorityHeadCache.find(accountRef, on: db), cached.seq == Int(head.seq), cached.headHash == digest,
           ctx.now.timeIntervalSince(cached.signedAt) < Self.resignAfter {
            return cached.statement
        }
        let statement = try await StatementBuilder(kms: ctx.kms, keys: keys, environment: ctx.environment).sign(head: head)
        let cache = try await AuthorityHeadCache.find(accountRef, on: db) ?? AuthorityHeadCache()
        let isNew = cache.id == nil
        cache.id = accountRef
        cache.seq = Int(head.seq)
        cache.headHash = digest
        cache.statement = statement
        cache.signedAt = ctx.now
        if isNew { try await cache.create(on: db) } else { try await cache.update(on: db) }
        return statement
    }
}

struct AuthorityKeyLogService {
    let ctx: AuthorityContext
    let db: any Database

    static let nonceLifetime: TimeInterval = 600
    /// ADR-0033 §4.1 item 3 (C-13).
    static let deviceAddPerDay = 5
    static let deviceAddAlertFrom = 4
    /// SECURITY §2.5a cool-down for keys the authority cannot see attested (every key added through the relay).
    static let deviceAddCoolDown: TimeInterval = 72 * 3600
    static let unconfirmedAccountLifetime: TimeInterval = 24 * 3600

    func requireEnabled() throws -> AuthorityKeyRing {
        guard ctx.config.keylogEnabled else { throw Abort(.notFound) }
        return try ctx.requireKeys()
    }

    /// Resolves an api-named account id to an account the authority minted or imported (`404 account_unknown` otherwise, audited) that is not closed.
    func account(_ accountId: UUID, caller: AuthorityCaller?) async throws -> AuthorityAccount {
        let ref = OIDCProfile.accountRef(key: ctx.config.accountRefKey, accountId: accountId)
        guard let account = try await AuthorityAccount.find(accountId, on: db), ConstantTime.equals(account.accountRef, ref),
              try await AuthorityAccountState.find(ref, on: db)?.state != "closed" else {
            await AuthorityAudit.record(db, "authority.account_unknown", outcome: "denied", reason: "account_unknown", caller: caller?.name, at: ctx.now)
            throw Abort.accountUnknown
        }
        return account
    }

    /// `409 key_in_use` when any submitted kid is a non-revoked key of **any** account or sits in a pending device-add entry or recovery (S3-A2-4).
    func requireUnused(_ kids: [String]) async throws {
        for kid in kids {
            if let existing = try await AuthorityKey.find(kid, on: db), existing.revokedAt == nil { throw Abort.keyInUse }
        }
        for entry in try await AuthorityDeviceAddEntry.query(on: db).filter(\.$state == "pending").all() where AuthorityRecoveryService.storedKeys(entry.keys).contains(where: { kids.contains($0.kid) }) {
            throw Abort.keyInUse
        }
        for recovery in try await AuthorityRecovery.query(on: db).filter(\.$state == "pending").all() where AuthorityRecoveryService.storedKeys(recovery.keys).contains(where: { kids.contains($0.kid) }) {
            throw Abort.keyInUse
        }
    }

    // MARK: PoP nonces

    func issueNonce(entryType: String) async throws -> [String: JSONValue] {
        _ = try requireEnabled()
        guard ["genesis", "device_added", "recovery_started_legacy"].contains(entryType) else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
        let row = AuthorityKeylogNonce()
        row.id = "kln_" + Base64URL.encode(SecureToken.randomBytes(16))
        row.nonce = AuthorityNonce.generate()
        row.entryType = entryType
        row.expiresAt = ctx.now.addingTimeInterval(Self.nonceLifetime)
        try await row.create(on: db)
        return ["nonce_id": .string(row.id!), "nonce": .string(row.nonce), "expires_at": .integer(Int64(row.expiresAt.timeIntervalSince1970))]
    }

    /// Consumes a PoP nonce once (compare-and-swap), for its own entry type only, and returns its value.
    func consumeNonce(_ id: String, entryType: String) async throws -> String {
        guard let row = try await AuthorityKeylogNonce.find(id, on: db), row.entryType == entryType, row.usedAt == nil, row.expiresAt > ctx.now,
              let sql = db as? any SQLDatabase else { throw Abort.evidenceInvalid }
        let rows = try await sql.update(AuthorityKeylogNonce.schema).set("used_at", to: ctx.now).where("id", .equal, id).where("used_at", .is, SQLLiteral.null)
            .returning("id").all()
        guard rows.count == 1 else { throw Abort.evidenceInvalid }
        return row.nonce
    }

    func verifyPoPs(_ keys: [SubmittedKey], type: String, nonce: String, extra: [String] = []) -> Bool {
        keys.allSatisfy { key in
            AuthorityKeyLogFormat.verifyPoP(key.pop, key: key.signingKey, message: AuthorityKeyLogFormat.popMessage(environment: ctx.environment, type: type, kid: key.kid,
                                                                                                                  nonce: nonce, extra: extra))
        }
    }

    /// Inserts keys into the current view and appends one entry per key (inside the caller's transaction).
    static func addKeys(_ tx: any Database, _ keys: [(kid: String, publicKey: String, purpose: String)], accountRef: String, entryType: String, group: String,
                        usableFrom: Date, grantCapable: Bool, detail: [String: JSONValue], now: Date) async throws {
        for key in keys {
            let row = AuthorityKey()
            row.id = key.kid
            row.accountRef = accountRef
            row.publicKey = key.publicKey
            row.keyPurpose = key.purpose
            row.hardwareAttested = false
            row.grantCapable = grantCapable
            row.usableFrom = usableFrom
            try await row.create(on: tx)
            let meta = AuthorityKeyEntry()
            meta.id = key.kid
            meta.entryType = entryType
            meta.entryGroup = group
            try await meta.create(on: tx)
            try await AuthorityKeyLog.append(tx, accountRef: accountRef, type: entryType, kid: key.kid, publicKey: key.publicKey, keyPurpose: key.purpose,
                                             detail: detail.merging(["group": .string(group), "usable_from": .integer(Int64(usableFrom.timeIntervalSince1970))]) { $1 }, now: now)
        }
    }

    // MARK: Genesis (ADR-0032 §1.1-§1.3)

    /// No caller-chosen account id: the authority mints it. Keys are not grant-capable until `enrollment_confirmed`.
    func genesis(_ o: [String: JSONValue], caller: AuthorityCaller?) async throws -> [String: JSONValue] {
        _ = try requireEnabled()
        guard Set(o.keys) == ["nonce_id", "keys"] else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
        let keys = try SubmittedKey.parseList(o["keys"])
        let nonce = try await consumeNonce(try AuthorityBody.string(o, "nonce_id", max: 64), entryType: "genesis")
        guard verifyPoPs(keys, type: "genesis", nonce: nonce) else {
            await AuthorityAudit.record(db, "authority.genesis", outcome: "denied", reason: "pop_invalid", caller: caller?.name, at: ctx.now)
            throw Abort.evidenceInvalid
        }
        do { try await requireUnused(keys.map(\.kid)) } catch {
            await AuthorityAudit.record(db, "authority.genesis", outcome: "denied", reason: "key_in_use", caller: caller?.name, at: ctx.now)
            throw error
        }
        let accountId = UUID()
        let ref = OIDCProfile.accountRef(key: ctx.config.accountRefKey, accountId: accountId)
        let now = ctx.now
        try await db.transaction { tx in
            let account = AuthorityAccount()
            account.id = accountId
            account.accountRef = ref
            account.origin = "minted"
            account.frozen = false
            account.createdAt = now
            try await account.create(on: tx)
            let state = AuthorityAccountState()
            state.id = ref
            state.state = "unconfirmed"
            state.updatedAt = now
            try await state.create(on: tx)
            try await Self.addKeys(tx, keys.map { ($0.kid, $0.publicKey.base64URL, $0.purpose) }, accountRef: ref, entryType: "genesis", group: "gen_" + ref,
                                   usableFrom: now, grantCapable: false, detail: [:], now: now)
        }
        await AuthorityAudit.record(db, "authority.genesis", outcome: "success", accountRef: ref, caller: caller?.name, at: now)
        let head = try await AuthorityHeads(ctx: ctx, db: db).signed(accountRef: ref)
        return ["account_id": .string(accountId.uuidString.lowercased()), "account_ref": .string(ref), "head": .string(head)]
    }

    // MARK: Device add (ADR-0033 §4.1, C-13)

    /// Stores the entry with its keys (state `pending`) after every new key's PoP verified; only then may its one challenge be created.
    func submitDeviceAdd(_ o: [String: JSONValue], caller: AuthorityCaller?) async throws -> [String: JSONValue] {
        _ = try requireEnabled()
        guard Set(o.keys) == ["account_id", "nonce_id", "reported_name", "keys"] else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
        let account = try await account(try AuthorityBody.accountId(o), caller: caller)
        guard let name = o["reported_name"]?.stringValue.flatMap(AuthorityKeyLogFormat.reportedName) else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
        let keys = try SubmittedKey.parseList(o["keys"])
        let ref = account.accountRef
        let now = ctx.now
        // Cap: at most 5 entries per account per rolling 24 h, counted at submission whatever their outcome. Every refusal alerts.
        let recent = try await AuthorityDeviceAddEntry.query(on: db).filter(\.$accountRef == ref).filter(\.$createdAt > now.addingTimeInterval(-86_400)).count()
        guard recent < Self.deviceAddPerDay else {
            await AuthorityAudit.record(db, "authority.device_add_alert", outcome: "denied", reason: "device_add_limit", accountRef: ref, caller: caller?.name, at: now)
            throw Abort(.tooManyRequests, reason: "device_add_limit")
        }
        let nonce = try await consumeNonce(try AuthorityBody.string(o, "nonce_id", max: 64), entryType: "device_added")
        guard verifyPoPs(keys, type: "device_added", nonce: nonce) else {
            await AuthorityAudit.record(db, "authority.device_add", outcome: "denied", reason: "pop_invalid", accountRef: ref, caller: caller?.name, at: now)
            throw Abort.evidenceInvalid
        }
        do { try await requireUnused(keys.map(\.kid)) } catch {
            await AuthorityAudit.record(db, "authority.device_add", outcome: "denied", reason: "key_in_use", accountRef: ref, caller: caller?.name, at: now)
            throw error
        }
        let entry = AuthorityDeviceAddEntry()
        entry.id = "dae_" + Base64URL.encode(SecureToken.randomBytes(16))
        entry.accountRef = ref
        entry.keys = String(decoding: try CanonicalJSON.serialize(.array(keys.map(\.stored))), as: UTF8.self)
        entry.reportedName = name
        entry.state = "pending"
        entry.createdAt = now
        try await db.transaction { tx in
            // One pending entry per account: a new one cancels the previous entry and its challenge.
            for previous in try await AuthorityDeviceAddEntry.query(on: tx).filter(\.$accountRef == ref).filter(\.$state == "pending").all() {
                previous.state = "cancelled"
                try await previous.update(on: tx)
                if let ach = previous.challengeId {
                    try await AuthorityChallenge.query(on: tx).filter(\.$id == ach).filter(\.$state == "pending").set(\.$state, to: "cancelled").update()
                }
                await AuthorityAudit.record(tx, "authority.device_add", outcome: "cancelled", reason: "superseded", accountRef: ref, caller: caller?.name, at: now)
            }
            try await entry.create(on: tx)
        }
        if recent + 1 >= Self.deviceAddAlertFrom {
            await AuthorityAudit.record(db, "authority.device_add_alert", outcome: "success", reason: "entries_\(recent + 1)_in_24h", accountRef: ref, caller: caller?.name, at: now)
        }
        await AuthorityAudit.record(db, "authority.device_add", outcome: "pending", accountRef: ref, caller: caller?.name, detail: entry.id, at: now)
        return ["entry_id": .string(entry.id!)]
    }

    // MARK: Key-log challenges (ADR-0033 §1: references only; the authority builds the display)

    func createChallenge(_ o: [String: JSONValue], caller: AuthorityCaller?) async throws -> [String: JSONValue] {
        let keys = try requireEnabled()
        guard let purpose = o["purpose"]?.stringValue.flatMap(AuthorityPurpose.init(rawValue:)), purpose.isKeyLog else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
        let account = try await account(try AuthorityBody.accountId(o), caller: caller)
        let ref = account.accountRef
        let now = ctx.now
        guard await ctx.bulkhead.admit(tenant: "keylog:" + ref, now: now) else { throw Abort(.tooManyRequests, reason: "challenge_budget") }
        let challenge = AuthorityChallenge()
        challenge.id = AuthorityChallengeID.generate()
        challenge.purpose = purpose.rawValue
        challenge.state = "pending"
        challenge.matchFailures = 0
        challenge.tenantId = ""
        challenge.clientId = ""
        challenge.targetURL = ""
        challenge.createdAt = now
        challenge.expiresAt = now.addingTimeInterval(ctx.config.challengeLifetime)
        let binding = AuthorityChallengeBinding()
        binding.id = challenge.id
        binding.accountRef = ref
        var statementKids: [String]?
        let display: JSONValue
        switch purpose {
        case .enrollmentConfirmed:
            guard Set(o.keys) == ["purpose", "account_id", "kids"], case .array(let items)? = o["kids"] else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
            let kids = items.compactMap(\.stringValue)
            guard (1...4).contains(kids.count), kids.count == items.count, Set(kids).count == kids.count else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
            for kid in kids {
                guard let key = try await AuthorityKey.find(kid, on: db), key.revokedAt == nil, key.accountRef == ref else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
            }
            let head = try await AuthorityHeads(ctx: ctx, db: db).compute(accountRef: ref)
            challenge.nonce = AuthorityNonce.generate()
            statementKids = kids
            display = AuthorityDisplay.enrollmentConfirmed(accountRef: ref, kids: kids, headHash: head.headHash, seq: head.seq)
        case .keylogDeviceAdded:
            guard Set(o.keys) == ["purpose", "account_id", "entry_id"], let entryId = o["entry_id"]?.stringValue,
                  let entry = try await AuthorityDeviceAddEntry.find(entryId, on: db), entry.accountRef == ref else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
            guard entry.state == "pending" else { throw Abort(.conflict, reason: "entry_closed") }
            // One challenge per entry in its lifetime; the nonce is drawn now, after the entry's kids are fixed (C-13).
            guard entry.challengeId == nil else {
                await AuthorityAudit.record(db, "authority.device_add_alert", outcome: "denied", reason: "challenge_exists", accountRef: ref, caller: caller?.name, at: now)
                throw Abort(.conflict, reason: "challenge_exists")
            }
            let kids = AuthorityRecoveryService.storedKeys(entry.keys).map(\.kid)
            challenge.nonce = AuthorityNonce.generate()
            challenge.matchCode = AuthorityDeviceAddCode.code(environment: ctx.environment, nonce: challenge.nonce, kids: kids)
            binding.entryId = entryId
            statementKids = kids
            display = AuthorityDisplay.deviceAdded(reportedName: entry.reportedName, kids: kids)
            try await AuthorityDeviceAddEntry.query(on: db).filter(\.$id == entryId).filter(\.$challengeId == nil).filter(\.$state == "pending")
                .set(\.$challengeId, to: challenge.id).update()
            guard try await AuthorityDeviceAddEntry.find(entryId, on: db)?.challengeId == challenge.id else { throw Abort(.conflict, reason: "challenge_exists") }
        case .recoveryCodesSet, .recoveryCancel, .recoveryStarted:
            challenge.nonce = AuthorityNonce.generate()
            display = try await AuthorityRecoveryService(ctx: ctx, db: db).prepareChallenge(purpose, o, accountRef: ref, binding: binding)
        default:
            throw Abort(.unprocessableEntity, reason: "purpose_not_supported")
        }
        challenge.display = String(decoding: try CanonicalJSON.serialize(display), as: UTF8.self)
        challenge.displayDigest = try AuthorityDisplay.digest(display)
        try await db.transaction { tx in
            try await challenge.create(on: tx)
            try await binding.create(on: tx)
        }
        let statement = try await StatementBuilder(kms: ctx.kms, keys: keys, environment: ctx.environment).sign(challenge, accountRef: ref, kids: statementKids)
        await AuthorityAudit.record(db, "authority.challenge_created", outcome: "success", accountRef: ref, challengeId: challenge.id, caller: caller?.name,
                                    detail: challenge.purpose, at: now)
        return ["ach": .string(challenge.id!), "statement": .string(statement), "expires_at": .integer(Int64(challenge.expiresAt.timeIntervalSince1970))]
    }

    // MARK: Evidence for key-log purposes (ADR-0023 §3 order, then the purpose's own rules)

    struct Checked {
        let parsed: ParsedFactorAssertion
        let key: AuthorityKey
        let challenge: AuthorityChallenge
        let binding: AuthorityChallengeBinding
    }

    /// Steps 1-5 and 7 of ADR-0023 §3 for key-log purposes. Never consumes the challenge (the purpose handler does, after its own checks).
    func check(_ o: [String: JSONValue], caller: AuthorityCaller?, refuse: (String, String?) async -> Abort) async throws -> Checked {
        let parsed: ParsedFactorAssertion
        do { parsed = try FactorAssertion.parse(try AuthorityBody.string(o, "factor", max: 4096)) } catch { throw await refuse("malformed", nil) }
        let claims = parsed.claims
        guard claims.purpose.isKeyLog, claims.purpose != .recoveryStarted else { throw await refuse("purpose_not_supported", nil) }
        guard let key = try await AuthorityKey.find(parsed.kid, on: db), key.revokedAt == nil else { throw await refuse("unknown_key", nil) }
        guard let account = try await AuthorityAccount.query(on: db).filter(\.$accountRef == key.accountRef).first(), !account.frozen,
              try await AuthorityAccountState.find(key.accountRef, on: db)?.state != "closed" else { throw await refuse("account_unavailable", key.accountRef) }
        if claims.userVerification == .biometric, key.keyPurpose != DeviceKeyPurpose.approvalBiometric.rawValue { throw await refuse("uv_inconsistent", key.accountRef) }
        guard key.keyPurpose != DeviceKeyPurpose.request.rawValue else { throw await refuse("key_purpose", key.accountRef) }
        guard let publicKey = try? DevicePublicKey(base64URL: key.publicKey).signingKey() else { throw await refuse("unknown_key", key.accountRef) }
        do { try FactorAssertion.verifySignature(parsed, loggedKey: publicKey) } catch { throw await refuse("bad_signature", key.accountRef) }
        if o["account_id"] != nil {
            let named = try AuthorityBody.accountId(o)
            guard ConstantTime.equals(OIDCProfile.accountRef(key: ctx.config.accountRefKey, accountId: named), key.accountRef) else {
                throw await refuse("account_binding_mismatch", key.accountRef)
            }
        }
        guard claims.audience == ctx.environment.authorityURN else { throw await refuse("audience", key.accountRef) }
        guard let challenge = try await AuthorityChallenge.find(claims.challengeId, on: db), let binding = try await AuthorityChallengeBinding.find(claims.challengeId, on: db) else {
            throw await refuse("unknown_challenge", key.accountRef)
        }
        guard challenge.state == "pending" else { throw await refuse("challenge_not_pending", key.accountRef) }
        guard challenge.expiresAt > ctx.now else {
            _ = try? await swap(challenge.id!, to: "expired")
            throw await refuse("challenge_expired", key.accountRef)
        }
        guard ConstantTime.equals(claims.nonce, challenge.nonce), claims.purpose.rawValue == challenge.purpose else { throw await refuse("challenge_mismatch", key.accountRef) }
        // The approving key belongs to the account the challenge is about (S2-A2-11 item 4).
        guard ConstantTime.equals(binding.accountRef, key.accountRef) else { throw await refuse("account_binding_mismatch", key.accountRef) }
        guard ConstantTime.equals(claims.displayDigest, challenge.displayDigest) else { throw await refuse("display_mismatch", key.accountRef) }
        let t = Int64(ctx.now.timeIntervalSince1970)
        guard claims.issuedAt <= t + FactorAssertionClaims.skew, t <= claims.expiresAt + FactorAssertionClaims.skew else { throw await refuse("time_bounds", key.accountRef) }
        return Checked(parsed: parsed, key: key, challenge: challenge, binding: binding)
    }

    func evidence(_ o: [String: JSONValue], caller: AuthorityCaller?) async throws -> [String: JSONValue] {
        _ = try requireEnabled()
        guard Set(o.keys).isSubset(of: ["factor", "account_id", "pops", "envelope"]) else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
        let now = ctx.now
        var auditKid: String?
        var auditChallenge: String?
        func refuse(_ reason: String, _ accountRef: String?) async -> Abort {
            await AuthorityAudit.record(db, "authority.keylog_evidence", outcome: "denied", reason: reason, accountRef: accountRef, challengeId: auditChallenge,
                                        kid: auditKid, caller: caller?.name, at: now)
            return Abort.evidenceInvalid
        }
        if let raw = o["factor"]?.stringValue, let parsed = try? FactorAssertion.parse(raw) { auditKid = parsed.kid; auditChallenge = parsed.claims.challengeId }
        let checked = try await check(o, caller: caller, refuse: refuse)
        let claims = checked.parsed.claims
        if claims.decision != .approve {
            guard try await swap(checked.challenge.id!, to: "denied") else { throw await refuse("challenge_not_pending", checked.key.accountRef) }
            if claims.purpose == .keylogDeviceAdded, let entryId = checked.binding.entryId { try await closeEntry(entryId, state: "abandoned") }
            await AuthorityAudit.record(db, "authority.keylog_evidence", outcome: "denied_by_person", reason: claims.decision.rawValue, accountRef: checked.key.accountRef,
                                        challengeId: checked.challenge.id, kid: checked.key.id, caller: caller?.name, at: now)
            return ["ach": .string(checked.challenge.id!), "decision": .string(claims.decision.rawValue)]
        }
        switch claims.purpose {
        case .enrollmentConfirmed: return try await confirmEnrollment(checked, o, refuse: refuse)
        case .keylogDeviceAdded: return try await approveDeviceAdd(checked, refuse: refuse)
        case .recoveryCodesSet, .recoveryCancel:
            return try await AuthorityRecoveryService(ctx: ctx, db: db).evidence(checked, o, refuse: refuse, swap: swap)
        default: throw await refuse("purpose_not_supported", checked.key.accountRef)
        }
    }

    /// ADR-0032 §1.4: `head_hash`/`seq` equal the current head; a PoP by **every** key the challenge names over `head_hash`; keys become grant-capable
    /// only when every key of their entry confirmed the same head (imported keys: each key that confirmed).
    func confirmEnrollment(_ c: Checked, _ o: [String: JSONValue], refuse: (String, String?) async -> Abort) async throws -> [String: JSONValue] {
        let claims = c.parsed.claims
        let ref = c.key.accountRef
        let head = try await AuthorityHeads(ctx: ctx, db: db).compute(accountRef: ref)
        guard let headHash = claims.headHash, let seq = claims.seq, ConstantTime.equals(headHash, head.headHash), seq == head.seq else { throw await refuse("head_mismatch", ref) }
        guard case .object(let display)? = try? JSONDecoder().decode(JSONValue.self, from: Data(c.challenge.display.utf8)), case .array(let kidItems)? = display["kids"] else {
            throw await refuse("display", ref)
        }
        let kids = kidItems.compactMap(\.stringValue)
        guard kids.contains(c.key.id!), case .array(let popItems)? = o["pops"], popItems.count == kids.count else { throw await refuse("pop_missing", ref) }
        var pops: [String: String] = [:]
        for item in popItems {
            guard let p = item.objectValue, Set(p.keys) == ["kid", "pop"], let kid = p["kid"]?.stringValue, let pop = p["pop"]?.stringValue else { throw await refuse("pop_missing", ref) }
            pops[kid] = pop
        }
        guard Set(pops.keys) == Set(kids) else { throw await refuse("pop_missing", ref) }
        for kid in kids {
            guard let key = try await AuthorityKey.find(kid, on: db), key.revokedAt == nil, key.accountRef == ref,
                  let publicKey = try? DevicePublicKey(base64URL: key.publicKey).signingKey(),
                  AuthorityKeyLogFormat.verifyPoP(pops[kid]!, key: publicKey, message: AuthorityKeyLogFormat.popMessage(environment: ctx.environment, type: "enrollment_confirmed",
                                                                                                                    kid: kid, nonce: headHash)) else {
                throw await refuse("pop_invalid", ref)
            }
        }
        guard try await swap(c.challenge.id!, to: "used") else { throw await refuse("challenge_not_pending", ref) }
        let now = ctx.now
        let capable: [String] = try await db.transaction { tx in
            var capable: [String] = []
            for kid in kids {
                if let meta = try await AuthorityKeyEntry.find(kid, on: tx) {
                    meta.confirmedHead = headHash
                    try await meta.update(on: tx)
                } else {
                    let meta = AuthorityKeyEntry()
                    meta.id = kid
                    meta.entryType = "imported"
                    meta.entryGroup = "imp_" + ref
                    meta.confirmedHead = headHash
                    try await meta.create(on: tx)
                }
            }
            // Groups touched by this confirmation: every live key of the group must have confirmed this same head.
            var groups = Set<String>()
            for kid in kids { if let meta = try await AuthorityKeyEntry.find(kid, on: tx) { groups.insert(meta.entryType == "imported" ? "imp_" + kid : meta.entryGroup) } }
            for group in groups {
                let members: [AuthorityKey]
                if group.hasPrefix("imp_"), let key = try await AuthorityKey.find(String(group.dropFirst(4)), on: tx) {
                    members = [key]
                } else {
                    let kidsInGroup = try await AuthorityKeyEntry.query(on: tx).filter(\.$entryGroup == group).all().compactMap(\.id)
                    members = try await AuthorityKey.query(on: tx).filter(\.$id ~~ kidsInGroup).filter(\.$revokedAt == nil).all()
                }
                var allConfirmed = true
                for member in members {
                    guard try await AuthorityKeyEntry.find(member.id!, on: tx)?.confirmedHead == headHash else { allConfirmed = false; break }
                }
                guard allConfirmed else { continue }
                for member in members where !member.grantCapable && member.keyPurpose != DeviceKeyPurpose.request.rawValue {
                    member.grantCapable = true
                    try await member.update(on: tx)
                    capable.append(member.id!)
                }
            }
            try await AuthorityKeyLog.append(tx, accountRef: ref, type: "enrollment_confirmed", kid: c.key.id!, publicKey: c.key.publicKey, keyPurpose: c.key.keyPurpose,
                                             detail: ["head_hash": .string(headHash), "seq": .integer(seq), "kids": .array(kids.map { .string($0) }),
                                                      "grant_capable": .array(capable.sorted().map { .string($0) })], now: now)
            if let state = try await AuthorityAccountState.find(ref, on: tx), state.state == "unconfirmed", !capable.isEmpty {
                state.state = "active"
                state.updatedAt = now
                try await state.update(on: tx)
            }
            return capable
        }
        await AuthorityAudit.record(db, "authority.enrollment_confirmed", outcome: "success", accountRef: ref, challengeId: c.challenge.id, kid: c.key.id,
                                    detail: "grant_capable:\(capable.count)", at: now)
        return ["ach": .string(c.challenge.id!), "decision": .string("approve"), "grant_capable": .array(capable.sorted().map { .string($0) }),
                "head": .string(try await AuthorityHeads(ctx: ctx, db: db).signed(accountRef: ref))]
    }

    /// ADR-0023 §4 `device_added`: a logged, grant-capable `approvalBiometric` key past its cool-down, of the entry's account; `match` equals the
    /// comparison code computed from the stored entry's kids and the challenge nonce (constant time; three wrong numbers end the entry).
    func approveDeviceAdd(_ c: Checked, refuse: (String, String?) async -> Abort) async throws -> [String: JSONValue] {
        let ref = c.key.accountRef
        let now = ctx.now
        guard c.key.keyPurpose == DeviceKeyPurpose.approvalBiometric.rawValue, c.key.grantCapable, c.key.usableFrom <= now,
              c.parsed.claims.userVerification == .biometric else { throw await refuse("approver_not_eligible", ref) }
        guard let entryId = c.binding.entryId, let entry = try await AuthorityDeviceAddEntry.find(entryId, on: db), entry.state == "pending",
              entry.challengeId == c.challenge.id, entry.accountRef == ref else { throw await refuse("entry_mismatch", ref) }
        let kids = AuthorityRecoveryService.storedKeys(entry.keys)
        let expected = AuthorityDeviceAddCode.code(environment: ctx.environment, nonce: c.challenge.nonce, kids: kids.map(\.kid))
        guard let typed = c.parsed.claims.match, typed.count == 6, ConstantTime.equals(typed, expected) else {
            let failures = try await countMatchFailure(c.challenge)
            if failures >= EvidenceVerifier.maxFailures { try await closeEntry(entryId, state: "abandoned") }
            throw await refuse(failures >= EvidenceVerifier.maxFailures ? "match_failed_final" : "match_mismatch", ref)
        }
        // A key that became used elsewhere since the entry was stored is refused here too (one account per key).
        do { try await requireUnusedOutside(entryId: entryId, kids: kids.map(\.kid)) } catch { throw await refuse("key_in_use", ref) }
        guard try await swap(c.challenge.id!, to: "used") else { throw await refuse("challenge_not_pending", ref) }
        try await db.transaction { tx in
            try await Self.addKeys(tx, kids.map { ($0.kid, $0.publicKey, $0.purpose) }, accountRef: ref, entryType: "device_added", group: entryId,
                                   usableFrom: now.addingTimeInterval(Self.deviceAddCoolDown), grantCapable: false,
                                   detail: ["approved_by": .string(c.key.id!), "reported_name": .string(entry.reportedName)], now: now)
            entry.state = "added"
            try await entry.update(on: tx)
        }
        await AuthorityAudit.record(db, "authority.device_added", outcome: "success", accountRef: ref, challengeId: c.challenge.id, kid: c.key.id, detail: entryId, at: now)
        return ["ach": .string(c.challenge.id!), "decision": .string("approve"), "head": .string(try await AuthorityHeads(ctx: ctx, db: db).signed(accountRef: ref))]
    }

    func requireUnusedOutside(entryId: String, kids: [String]) async throws {
        for kid in kids { if let existing = try await AuthorityKey.find(kid, on: db), existing.revokedAt == nil { throw Abort.keyInUse } }
        for other in try await AuthorityDeviceAddEntry.query(on: db).filter(\.$state == "pending").filter(\.$id != entryId).all()
        where AuthorityRecoveryService.storedKeys(other.keys).contains(where: { kids.contains($0.kid) }) { throw Abort.keyInUse }
    }

    func closeEntry(_ entryId: String, state: String) async throws {
        try await AuthorityDeviceAddEntry.query(on: db).filter(\.$id == entryId).filter(\.$state == "pending").set(\.$state, to: state).update()
    }

    func headFor(_ o: [String: JSONValue], caller: AuthorityCaller?) async throws -> [String: JSONValue] {
        _ = try requireEnabled()
        guard Set(o.keys) == ["account_id"] else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
        let account = try await account(try AuthorityBody.accountId(o), caller: caller)
        return ["head": .string(try await AuthorityHeads(ctx: ctx, db: db).signed(accountRef: account.accountRef))]
    }

    /// pending → `state`, exactly once.
    func swap(_ id: String, to state: String) async throws -> Bool {
        guard let sql = db as? any SQLDatabase else { return false }
        let rows = try await sql.update(AuthorityChallenge.schema).set("state", to: state).set("used_at", to: ctx.now)
            .where("id", .equal, id).where("state", .equal, "pending").returning("id").all()
        return rows.count == 1
    }

    func countMatchFailure(_ challenge: AuthorityChallenge) async throws -> Int {
        guard let sql = db as? any SQLDatabase else { return EvidenceVerifier.maxFailures }
        try await sql.raw("UPDATE \(ident: AuthorityChallenge.schema) SET match_failures = match_failures + 1 WHERE id = \(bind: challenge.id!) AND state = 'pending'").run()
        let failures = try await AuthorityChallenge.find(challenge.id!, on: db)?.matchFailures ?? EvidenceVerifier.maxFailures
        if failures >= EvidenceVerifier.maxFailures { _ = try await swap(challenge.id!, to: "failed") }
        return failures
    }
}
