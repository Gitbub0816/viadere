@preconcurrency import Crypto
import Fluent
import Foundation
import SQLKit
import Vapor
import ViadereCore
import WebAuthn

// Passkeys in the key log (ADR-0023 §3a, §4; ADR-0032 §3.3): `passkey_added` (a factor JWS by the device that created the passkey, never a WebAuthn
// assertion) and the reduce-only passkey `recovery_cancel` (a UV WebAuthn assertion by a logged passkey of the same account, from the purpose's
// origin allow-list, over an authority nonce kept in `authority_passkey_challenges`, apart from every factor-JWS challenge). Also `Authority.v4`.

// MARK: Schema

/// `Authority.v4` (additive): the passkey-cancel binding, the passkey-added binding, the challenge of a `decrypt` record (ADR-0034 §9) and the App
/// Attest keys seen at genesis (one account per App Attest key, ADR-0032 §1.3).
struct CreateAuthorityKeyLogV4Schema: AsyncMigration {
    var name: String { "Authority.v4" }

    func prepare(on db: any Database) async throws {
        // One column per statement (SQLite adds one column per ALTER TABLE).
        try await db.schema(AuthorityPasskeyChallenge.schema).field("account_ref", .string).update()
        try await db.schema(AuthorityPasskeyChallenge.schema).field("recovery_ref", .string).update()
        try await db.schema(AuthorityChallengeBinding.schema).field("passkey_credential_id", .string).update()
        try await db.schema(AuthorityChallengeBinding.schema).field("passkey_public_key", .string).update()
        try await db.schema(AuthoritySignRecord.schema).field("challenge_id", .string).update()
        try await db.schema(AuthorityAppAttestKey.schema)
            .field("key_id", .string, .identifier(auto: false)).field("account_ref", .string, .required).field("environment", .string, .required)
            .field("created_at", .datetime, .required).create()
    }

    func revert(on db: any Database) async throws {
        try await db.schema(AuthorityAppAttestKey.schema).delete()
        try await db.schema(AuthoritySignRecord.schema).deleteField("challenge_id").update()
        try await db.schema(AuthorityChallengeBinding.schema).deleteField("passkey_public_key").update()
        try await db.schema(AuthorityChallengeBinding.schema).deleteField("passkey_credential_id").update()
        try await db.schema(AuthorityPasskeyChallenge.schema).deleteField("recovery_ref").update()
        try await db.schema(AuthorityPasskeyChallenge.schema).deleteField("account_ref").update()
    }
}

/// An App Attest key whose attestation vouched for a genesis: a key id is accepted once, so one genuine device cannot vouch for a stream of accounts.
final class AuthorityAppAttestKey: Model, @unchecked Sendable {
    static let schema = "authority_app_attest_keys"
    @ID(custom: "key_id", generatedBy: .user) var id: String?
    @Field(key: "account_ref") var accountRef: String
    @Field(key: "environment") var environment: String
    @Field(key: "created_at") var createdAt: Date
    init() {}
}

// MARK: WebAuthn (shared by the OIDC passkey method and the passkey cancel)

enum PasskeyWebAuthn {
    /// webauthn-swift's checks: type, challenge, origin, `rpIdHash`, user presence **and user verification**, signature with the logged COSE key,
    /// signature counter (a counter that did not grow is refused as a possible clone). Throws on any failure.
    static func finish(_ credential: PasskeyAssertionCredential, credentialId: String, origin: String, passkey: AuthorityPasskey, nonce: Data,
                       relyingPartyID: String) throws -> VerifiedAuthentication {
        let manager = WebAuthnManager(configuration: .init(relyingPartyID: relyingPartyID, relyingPartyName: "Viadere", relyingPartyOrigin: origin))
        guard let publicKey = Base64URL.decode(passkey.publicKey) else { throw Abort.evidenceInvalid }
        var response: [String: Any] = ["authenticatorData": credential.authenticatorData, "clientDataJSON": credential.clientDataJSON, "signature": credential.signature]
        if let handle = credential.userHandle { response["userHandle"] = handle }
        let json = try JSONSerialization.data(withJSONObject: ["id": credentialId, "rawId": credentialId, "type": "public-key", "response": response])
        let decoded = try JSONDecoder().decode(AuthenticationCredential.self, from: json)
        return try manager.finishAuthentication(credential: decoded, expectedChallenge: [UInt8](nonce), credentialPublicKey: [UInt8](publicKey),
                                                credentialCurrentSignCount: UInt32(clamping: passkey.signCount), requireUserVerification: true)
    }

    /// The counter moves forward exactly once (compare-and-swap on the value read).
    static func advanceCounter(_ db: any Database, credentialId: String, from: Int, to: UInt32) async throws -> Bool {
        guard to > 0 else { return true }
        guard let sql = db as? any SQLDatabase else { return false }
        return try await sql.update(AuthorityPasskey.schema).set("sign_count", to: Int(to)).where("credential_id", .equal, credentialId)
            .where("sign_count", .equal, from).returning("credential_id").all().count == 1
    }

    /// pending → used, exactly once.
    static func consume(_ db: any Database, challengeId: String, now: Date) async throws -> Bool {
        guard let sql = db as? any SQLDatabase else { return false }
        return try await sql.update(AuthorityPasskeyChallenge.schema).set("state", to: "used").set("used_at", to: now).where("id", .equal, challengeId)
            .where("state", .equal, "pending").returning("id").all().count == 1
    }

    /// The `kid` of a logged passkey (its COSE key as SPKI, ADR-0023 §2), or the `passkey:` reference of an imported one whose key is not canonical.
    static func kid(_ passkey: AuthorityPasskey) -> String {
        Base64URL.decode(passkey.publicKey).flatMap(AuthorityKeyLogFormat.passkeyKid(cose:)) ?? "passkey:" + passkey.id!
    }
}

// MARK: passkey_added (ADR-0023 §4)

extension AuthorityKeyLogService {
    /// The challenge: the credential the app just created, parsed strictly, logged nowhere yet (one account per credential and per key).
    func preparePasskeyAdded(_ o: [String: JSONValue], accountRef: String, binding: AuthorityChallengeBinding, caller: AuthorityCaller?) async throws -> (display: JSONValue, kids: [String]) {
        guard Set(o.keys) == ["purpose", "account_id", "credential_id", "public_key"], let credentialId = o["credential_id"]?.stringValue,
              let publicKey = o["public_key"]?.stringValue, let added = AuthorityPasskeyAdded.parse(credentialId: credentialId, publicKey: publicKey) else {
            throw Abort(.unprocessableEntity, reason: "invalid_request")
        }
        do { try await requirePasskeyUnused(added) } catch {
            await AuthorityAudit.record(db, "authority.passkey_added", outcome: "denied", reason: "key_in_use", accountRef: accountRef, caller: caller?.name, at: ctx.now)
            throw error
        }
        binding.passkeyCredentialId = added.credentialId
        binding.passkeyPublicKey = publicKey
        return (AuthorityDisplay.passkeyAdded(kid: added.kid), [added.kid])
    }

    func requirePasskeyUnused(_ added: AuthorityPasskeyAdded) async throws {
        if try await AuthorityPasskey.find(added.credentialId, on: db) != nil { throw Abort.keyInUse }
        if try await AuthorityKey.find(added.kid, on: db) != nil { throw Abort.keyInUse }
        // A credential whose COSE key is already logged under another id is the same key.
        let cose = Base64URL.encode(added.cose)
        if try await AuthorityPasskey.query(on: db).filter(\.$publicKey == cose).count() > 0 { throw Abort.keyInUse }
    }

    /// A logged, grant-capable `approvalBiometric` key of the account, past its cool-down, with `uv = biometric`, approving the display the authority
    /// built for exactly the stored credential. No WebAuthn assertion is accepted for this purpose (ADR-0023 §3a item 1).
    func approvePasskeyAdded(_ c: Checked, refuse: (String, String?) async -> Abort) async throws -> [String: JSONValue] {
        let ref = c.key.accountRef
        let now = ctx.now
        guard c.key.keyPurpose == DeviceKeyPurpose.approvalBiometric.rawValue, c.key.grantCapable, c.key.usableFrom <= now,
              c.parsed.claims.userVerification == .biometric else { throw await refuse("approver_not_eligible", ref) }
        guard let credentialId = c.binding.passkeyCredentialId, let publicKey = c.binding.passkeyPublicKey,
              let added = AuthorityPasskeyAdded.parse(credentialId: credentialId, publicKey: publicKey) else { throw await refuse("binding", ref) }
        do { try await requirePasskeyUnused(added) } catch { throw await refuse("key_in_use", ref) }
        guard try await swap(c.challenge.id!, to: "used") else { throw await refuse("challenge_not_pending", ref) }
        do {
            try await db.transaction { tx in
                let row = AuthorityPasskey()
                row.id = added.credentialId
                row.accountRef = ref
                row.publicKey = publicKey
                row.signCount = 0
                // No attestation is verified for an app-created passkey: `swk`, never an implied `hwk`.
                row.hardwareBound = false
                // Added by a grant-capable device key of the account over the authority's own display.
                row.grantCapable = true
                row.createdAt = now
                try await row.create(on: tx)
                try await AuthorityKeyLog.append(tx, accountRef: ref, type: "passkey_added", kid: added.kid, publicKey: publicKey, keyPurpose: "passkey",
                                                 detail: ["credential_id": .string(added.credentialId), "approved_by": .string(c.key.id!), "hardware_bound": .bool(false)], now: now)
            }
        } catch {
            // The primary key on `credential_id` lost a race with another addition of the same credential.
            throw await refuse("key_in_use", ref)
        }
        await AuthorityAudit.record(db, "authority.passkey_added", outcome: "success", accountRef: ref, challengeId: c.challenge.id, kid: added.kid, at: now)
        return ["ach": .string(c.challenge.id!), "decision": .string("approve"), "head": .string(try await AuthorityHeads(ctx: ctx, db: db).signed(accountRef: ref))]
    }
}

// MARK: Passkey recovery_cancel (ADR-0023 §3a item 1, §4)

struct PasskeyRecoveryCancel {
    let ctx: AuthorityContext
    let db: any Database

    func requireEnabled() throws {
        _ = try ctx.requireKeys()
        guard ctx.config.keylogEnabled, ctx.config.recoveryEnabled else { throw Abort(.notFound) }
    }

    /// `POST /v1/keylog/recovery/passkey-cancel/challenges {account_id}`: a WebAuthn nonce for the account's pending recovery. Nothing is signed. The
    /// cancel does not need the seal key (reduce-only: a missing seal key must never keep a person from stopping a recovery).
    func challenge(_ o: [String: JSONValue], caller: AuthorityCaller?) async throws -> [String: JSONValue] {
        try requireEnabled()
        guard Set(o.keys) == ["account_id"] else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
        let account = try await AuthorityKeyLogService(ctx: ctx, db: db).account(try AuthorityBody.accountId(o), caller: caller)
        let ref = account.accountRef
        let now = ctx.now
        guard let pending = try await AuthorityRecovery.query(on: db).filter(\.$accountRef == ref).filter(\.$state == "pending").first() else {
            throw Abort(.unprocessableEntity, reason: "no_pending_recovery")
        }
        guard await ctx.bulkhead.admit(tenant: "keylog:" + ref, now: now) else { throw Abort(.tooManyRequests, reason: "challenge_budget") }
        let challenge = AuthorityPasskeyChallenge()
        challenge.id = AuthorityChallengeID.generate()
        challenge.purpose = AuthorityPurpose.recoveryCancel.rawValue
        challenge.nonce = AuthorityNonce.generate()
        challenge.state = "pending"
        challenge.tenantId = ""
        challenge.clientId = ""
        challenge.redirectURI = ""
        challenge.codeChallenge = ""
        challenge.oidcNonce = ""
        challenge.accountRef = ref
        challenge.recoveryRef = pending.id
        challenge.createdAt = now
        challenge.expiresAt = now.addingTimeInterval(ctx.config.challengeLifetime)
        try await challenge.create(on: db)
        await AuthorityAudit.record(db, "authority.passkey_challenge_created", outcome: "success", accountRef: ref, challengeId: challenge.id, caller: caller?.name,
                                    detail: challenge.purpose, at: now)
        return ["ach": .string(challenge.id!), "challenge": .string(challenge.nonce), "rp_id": .string(ctx.config.webAuthnRelyingPartyID),
                "timeout_ms": .integer(Int64(PasskeyChallengeService.timeoutMilliseconds)), "expires_at": .integer(Int64(challenge.expiresAt.timeIntervalSince1970)),
                "display": AuthorityDisplay.recoveryCancel(startedAt: Int64(pending.startedAt.timeIntervalSince1970), activatesAt: Int64(pending.activatesAt.timeIntervalSince1970))]
    }

    /// `POST /v1/keylog/recovery/passkey-cancel {ach, credential}`. Every refusal is `401 evidence_invalid` with the reason audited; a refusal before
    /// the WebAuthn checks passed never touches the challenge.
    func submit(_ request: AuthorityPasskeyEvidenceRequest, caller: AuthorityCaller?) async throws -> [String: JSONValue] {
        try requireEnabled()
        let now = ctx.now
        var auditAccount: String?
        func refuse(_ reason: String) async -> Abort {
            await AuthorityAudit.record(db, "authority.passkey_cancel", outcome: "denied", reason: reason, accountRef: auditAccount,
                                        challengeId: AuthorityChallengeID.isValid(request.challengeId) ? request.challengeId : nil, caller: caller?.name, at: now)
            return Abort.evidenceInvalid
        }
        let credential = request.credential

        // 1. Shape.
        guard AuthorityChallengeID.isValid(request.challengeId) else { throw await refuse("malformed") }
        let credentialId = PasskeyCredentialIDs.canonical(credential.id)
        guard Base64URL.isValid(credentialId, minLength: 16, maxLength: 1366), let idBytes = Base64URL.decode(credentialId),
              Base64URL.decode(PasskeyCredentialIDs.canonical(credential.rawId)) == idBytes else { throw await refuse("malformed") }

        // 2. clientDataJSON: `webauthn.get`, an origin allowed for `recovery_cancel`, not cross-origin.
        guard let clientData = PasskeyClientData.parse(credential.clientDataJSON) else { throw await refuse("client_data") }
        guard clientData.type == "webauthn.get" else { throw await refuse("ceremony_type") }
        let origins = OIDCProfile.passkeyOrigins(for: .recoveryCancel, issuer: ctx.config.issuer, relyingPartyID: ctx.config.webAuthnRelyingPartyID)
        guard origins.contains(clientData.origin) else { throw await refuse("origin_not_allowed") }

        // 3. A logged, unrevoked passkey (grant capability is not needed for a reduce-only cancel) of an account that is not closed.
        guard let passkey = try await AuthorityPasskey.find(credentialId, on: db), passkey.revokedAt == nil else { throw await refuse("unknown_passkey") }
        auditAccount = passkey.accountRef
        guard try await AuthorityAccountState.find(passkey.accountRef, on: db)?.state != "closed" else { throw await refuse("account_unavailable") }

        // 4. A pending, unexpired passkey challenge created for `recovery_cancel` (never an `oidc_login` one), for this passkey's account.
        guard let challenge = try await AuthorityPasskeyChallenge.find(request.challengeId, on: db), challenge.purpose == AuthorityPurpose.recoveryCancel.rawValue,
              let boundAccount = challenge.accountRef, let recoveryRef = challenge.recoveryRef else { throw await refuse("unknown_challenge") }
        guard ConstantTime.equals(boundAccount, passkey.accountRef) else { throw await refuse("account_binding_mismatch") }
        guard challenge.state == "pending" else { throw await refuse("challenge_not_pending") }
        guard challenge.expiresAt > now else { throw await refuse("challenge_expired") }
        guard let nonce = Base64URL.decode(challenge.nonce) else { throw await refuse("unknown_challenge") }

        // 5. WebAuthn with UV, against the logged key.
        let verified: VerifiedAuthentication
        do {
            verified = try PasskeyWebAuthn.finish(credential, credentialId: credentialId, origin: clientData.origin, passkey: passkey, nonce: nonce,
                                                  relyingPartyID: ctx.config.webAuthnRelyingPartyID)
        } catch { throw await refuse("assertion_invalid") }

        // 6. Counter, then single use.
        guard try await PasskeyWebAuthn.advanceCounter(db, credentialId: credentialId, from: passkey.signCount, to: verified.newSignCount) else {
            throw await refuse("sign_count_race")
        }
        guard try await PasskeyWebAuthn.consume(db, challengeId: challenge.id!, now: now) else { throw await refuse("challenge_not_pending") }

        // 7. The recovery is still pending (an activated or already cancelled one is never reported as cancelled).
        let ref = passkey.accountRef
        let kid = PasskeyWebAuthn.kid(passkey)
        let cancelled: Bool = try await db.transaction { tx in
            guard let recovery = try await AuthorityRecovery.find(recoveryRef, on: tx), recovery.state == "pending", ConstantTime.equals(recovery.accountRef, ref) else {
                return false
            }
            recovery.state = "cancelled"
            try await recovery.update(on: tx)
            try await AuthorityKeyLog.append(tx, accountRef: ref, type: "recovery_cancel", kid: kid, publicKey: passkey.publicKey, keyPurpose: "passkey",
                                             detail: ["recovery_id": .string(recovery.recoveryId), "method": .string("passkey"), "credential_id": .string(credentialId)], now: now)
            return true
        }
        guard cancelled else { throw await refuse("recovery_not_pending") }
        await AuthorityAudit.record(db, "authority.recovery_cancel", outcome: "success", reason: "passkey", accountRef: ref, challengeId: challenge.id, kid: kid,
                                    caller: caller?.name, at: now)
        return ["ach": .string(challenge.id!), "decision": .string("approve"), "head": .string(try await AuthorityHeads(ctx: ctx, db: db).signed(accountRef: ref))]
    }
}
