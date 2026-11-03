@preconcurrency import Crypto
import Fluent
import Foundation
import SQLKit
import Vapor
import ViadereCore
import WebAuthn

// Stage 6 OIDC open items (ADR-0023 §3a, ADR-0024 §4, §8): the passkey method verified by the authority itself, consent records, and the
// `login_hint` check. The api only relays; every decision here is the authority's, against its own records.

// MARK: Records

/// A passkey the authority accepts (ADR-0023 §4 key log). Entered only by the reviewed `keylog-import` (residual R-16); passkeys created on web pages
/// are never added (ADR-0023 §4 `passkey_added`). `credential_id` is the canonical unpadded base64url id the browser sends.
final class AuthorityPasskey: Model, @unchecked Sendable {
    static let schema = "authority_passkeys"
    @ID(custom: "credential_id", generatedBy: .user) var id: String?
    @Field(key: "account_ref") var accountRef: String
    /// The COSE public key (ES256), base64url.
    @Field(key: "public_key") var publicKey: String
    @Field(key: "sign_count") var signCount: Int
    /// True only when attestation showed a device-bound authenticator (`amr` then carries `hwk`, else `swk`).
    @Field(key: "hardware_bound") var hardwareBound: Bool
    @Field(key: "grant_capable") var grantCapable: Bool
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "revoked_at") var revokedAt: Date?
    init() {}
}

/// A passkey challenge (`oidc_login` only). Kept apart from `authority_challenges`, so a passkey assertion can never be matched to an app-path,
/// link or key-log challenge (ADR-0023 §3a item 1, ST-REC-17), and a factor JWS can never be matched to a passkey challenge.
final class AuthorityPasskeyChallenge: Model, @unchecked Sendable {
    static let schema = "authority_passkey_challenges"
    @ID(custom: "id", generatedBy: .user) var id: String?
    @Field(key: "purpose") var purpose: String
    /// 256-bit nonce, base64url: the WebAuthn challenge.
    @Field(key: "nonce") var nonce: String
    @Field(key: "state") var state: String
    @Field(key: "tenant_id") var tenantId: String
    @Field(key: "client_id") var clientId: String
    @Field(key: "redirect_uri") var redirectURI: String
    @Field(key: "code_challenge") var codeChallenge: String
    @Field(key: "oidc_nonce") var oidcNonce: String
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "used_at") var usedAt: Date?
    init() {}
}

/// Consent records (ADR-0024 §8): one per (client, account), class T while active, deleted on revoke.
final class AuthorityOIDCConsent: Model, @unchecked Sendable {
    static let schema = "authority_oidc_consents"
    @ID(key: .id) var id: UUID?
    @Field(key: "client_id") var clientId: String
    @Field(key: "account_ref") var accountRef: String
    @Field(key: "granted_at") var grantedAt: Date
    @Field(key: "last_used_at") var lastUsedAt: Date
    init() {}
}

/// `AuthorityOIDC.v1` (additive): passkeys, passkey challenges, consents, and the optional `business_id` of an OIDC client (`login_hint`).
struct CreateAuthorityOIDCMethodsSchema: AsyncMigration {
    var name: String { "AuthorityOIDC.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema(AuthorityPasskey.schema)
            .field("credential_id", .string, .identifier(auto: false))
            .field("account_ref", .string, .required).field("public_key", .string, .required).field("sign_count", .int, .required)
            .field("hardware_bound", .bool, .required).field("grant_capable", .bool, .required).field("created_at", .datetime, .required)
            .field("revoked_at", .datetime).create()
        try await db.schema(AuthorityPasskeyChallenge.schema)
            .field("id", .string, .identifier(auto: false))
            .field("purpose", .string, .required).field("nonce", .string, .required).field("state", .string, .required)
            .field("tenant_id", .string, .required).field("client_id", .string, .required).field("redirect_uri", .string, .required)
            .field("code_challenge", .string, .required).field("oidc_nonce", .string, .required)
            .field("created_at", .datetime, .required).field("expires_at", .datetime, .required).field("used_at", .datetime).create()
        try await db.schema(AuthorityOIDCConsent.schema)
            .id()
            .field("client_id", .string, .required).field("account_ref", .string, .required)
            .field("granted_at", .datetime, .required).field("last_used_at", .datetime, .required)
            .unique(on: "client_id", "account_ref").create()
        try await db.schema(AuthorityOIDCClient.schema).field("business_id", .uuid).update()
    }

    func revert(on db: any Database) async throws {
        try await db.schema(AuthorityOIDCClient.schema).deleteField("business_id").update()
        for table in [AuthorityOIDCConsent.schema, AuthorityPasskeyChallenge.schema, AuthorityPasskey.schema] { try await db.schema(table).delete() }
    }
}

/// The OIDC client's business (`login_hint` = that business's `subject_ref`), read without widening the registration model.
enum OIDCClientBusiness {
    static func businessId(_ clientId: String, db: any Database) async throws -> UUID? {
        guard let sql = db as? any SQLDatabase else { return nil }
        struct Row: Decodable { let business_id: UUID? }
        return try await sql.select().column("business_id").from(AuthorityOIDCClient.schema).where("client_id", .equal, clientId)
            .first(decoding: Row.self)?.business_id
    }

    static func set(_ clientId: String, businessId: UUID, db: any Database) async throws {
        guard let sql = db as? any SQLDatabase else { return }
        try await sql.update(AuthorityOIDCClient.schema).set("business_id", to: businessId).where("client_id", .equal, clientId).run()
    }
}

// MARK: Routes

enum AuthorityOIDCMethodRoutes {
    /// Registered by `AuthorityApplication.routes` (the route list is pinned by `AuthorityControlTests`).
    static func register(evidence: any RoutesBuilder, revocations: any RoutesBuilder) {
        evidence.post("v1", "oidc", "passkey", "challenges") { req async throws -> Response in
            let body = try AuthorityApplication.decodeStrict(AuthorityPasskeyChallengeRequest.self, req)
            let response = try await PasskeyChallengeService(ctx: req.application.authority, db: req.db).create(body, caller: req.authorityCaller)
            return try AuthorityApplication.json(response, status: .created)
        }
        evidence.post("v1", "oidc", "passkey", "evidence") { req async throws -> Response in
            let body = try AuthorityApplication.decodeStrict(AuthorityPasskeyEvidenceRequest.self, req)
            let response = try await PasskeyEvidenceVerifier(ctx: req.application.authority, db: req.db).submit(body, caller: req.authorityCaller)
            return try AuthorityApplication.json(response, status: .ok)
        }
        evidence.post("v1", "oidc", "consents") { req async throws -> Response in
            let body = try AuthorityApplication.decodeStrict(AuthorityConsentListRequest.self, req)
            let consents = try await AuthorityConsents(ctx: req.application.authority, db: req.db).list(accountId: body.accountId)
            return try AuthorityApplication.json(AuthorityConsentListResponse(consents: consents), status: .ok)
        }
        // Reduce-only: deleting a consent only ever removes (ADR-0024 §8).
        revocations.post("v1", "oidc", "consents", "revoke") { req async throws -> Response in
            let body = try AuthorityApplication.decodeStrict(AuthorityConsentRevokeRequest.self, req)
            let revoked = try await AuthorityConsents(ctx: req.application.authority, db: req.db).revoke(accountId: body.accountId, clientId: body.clientId,
                                                                                                      caller: req.authorityCaller)
            return try AuthorityApplication.json(["revoked": revoked], status: .ok)
        }
    }
}

// MARK: Shared authorization-request checks

/// The checks every `oidc_login` challenge runs against the authority's own registration, whatever the api checked before (ADR-0024 §4).
enum OIDCAuthorizationChecks {
    static func client(for oidc: AuthorityChallengeCreateRequest.OIDCAuthorization, db: any Database) async throws -> AuthorityOIDCClient {
        guard let client = try await AuthorityOIDCClient.find(oidc.clientId, on: db), client.status == "active",
              OIDCClientRules.redirectURIs(client).contains(oidc.redirectURI) else { throw Abort(.unprocessableEntity, reason: "invalid_client") }
        guard oidc.codeChallengeMethod == "S256", OIDCProfile.isValidCodeChallenge(oidc.codeChallenge) else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
        guard (1...255).contains(oidc.nonce.utf8.count), oidc.nonce.unicodeScalars.allSatisfy({ $0.isASCII && $0.value >= 0x21 && $0.value < 0x7F }) else {
            throw Abort(.unprocessableEntity, reason: "invalid_request")
        }
        guard (oidc.acrValues ?? []).allSatisfy({ [OIDCProfile.acrApp, OIDCProfile.acrPasskey].contains($0) }) else {
            throw Abort(.unprocessableEntity, reason: "invalid_request")
        }
        return client
    }

    /// `login_hint` (ADR-0024 §4 method 2): accepted only when the client has a registered business, the named account is one the authority knows
    /// and is not frozen, and `SubjectRefDeriver(business, account) == login_hint` (constant time). Never an error: a hint that does not verify only
    /// means no push (the QR path still works).
    static func verifyHint(_ oidc: AuthorityChallengeCreateRequest.OIDCAuthorization, client: AuthorityOIDCClient, ctx: AuthorityContext,
                           db: any Database) async throws -> Bool? {
        guard oidc.loginHint != nil || oidc.hintAccountId != nil else { return nil }
        guard let hint = oidc.loginHint, SubjectRef(hint) != nil, let accountId = oidc.hintAccountId,
              let business = try await OIDCClientBusiness.businessId(client.id!, db: db),
              let account = try await AuthorityAccount.find(accountId, on: db), !account.frozen else { return false }
        let expected = SubjectRefDeriver(key: ctx.config.subjectRefKey).subjectRef(businessId: BusinessID(business), consumerId: ConsumerID(accountId)).rawValue
        return ConstantTime.equals(expected, hint)
    }
}

// MARK: Passkey challenges

/// `POST /v1/oidc/passkey/challenges`: created only after the person chose the passkey (api side), behind the same per-tenant bulkhead as every
/// challenge. Nothing is signed: the WebAuthn challenge is the authority's own random nonce.
struct PasskeyChallengeService {
    let ctx: AuthorityContext
    let db: any Database

    static let timeoutMilliseconds = 120_000

    func create(_ request: AuthorityPasskeyChallengeRequest, caller: AuthorityCaller?) async throws -> AuthorityPasskeyChallengeResponse {
        _ = try ctx.requireKeys()
        guard ctx.config.oidcEnabled else { throw Abort(.notFound) }
        let oidc = request.oidc
        guard oidc.loginHint == nil, oidc.hintAccountId == nil else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
        let client = try await OIDCAuthorizationChecks.client(for: oidc, db: db)
        let now = ctx.now
        guard await ctx.bulkhead.admit(tenant: client.tenantId, now: now) else { throw Abort(.tooManyRequests, reason: "challenge_budget") }
        let challenge = AuthorityPasskeyChallenge()
        challenge.id = AuthorityChallengeID.generate()
        challenge.purpose = AuthorityPurpose.oidcLogin.rawValue
        challenge.nonce = AuthorityNonce.generate()
        challenge.state = "pending"
        challenge.tenantId = client.tenantId
        challenge.clientId = client.id!
        challenge.redirectURI = oidc.redirectURI
        challenge.codeChallenge = oidc.codeChallenge
        challenge.oidcNonce = oidc.nonce
        challenge.createdAt = now
        challenge.expiresAt = now.addingTimeInterval(ctx.config.challengeLifetime)
        try await challenge.create(on: db)
        await AuthorityAudit.record(db, "authority.passkey_challenge_created", outcome: "success", tenant: client.tenantId, challengeId: challenge.id,
                                    caller: caller?.name, detail: client.id, at: now)
        return AuthorityPasskeyChallengeResponse(challengeId: challenge.id!, challenge: challenge.nonce, relyingPartyId: ctx.config.webAuthnRelyingPartyID,
                                                 timeoutMilliseconds: Self.timeoutMilliseconds, expiresAt: Int64(challenge.expiresAt.timeIntervalSince1970))
    }
}

/// A passkey assertion that passed every check below and consumed its challenge. Only `PasskeyEvidenceVerifier` (this file) constructs one.
struct VerifiedPasskey: Sendable {
    let challengeId: String
    let accountId: UUID
    let accountRef: String
    let credentialId: String
    let hardwareBound: Bool
    var amr: [String] { OIDCProfile.passkeyAMR(hardwareBound: hardwareBound) }

    fileprivate init(challengeId: String, accountId: UUID, accountRef: String, credentialId: String, hardwareBound: Bool) {
        self.challengeId = challengeId
        self.accountId = accountId
        self.accountRef = accountRef
        self.credentialId = credentialId
        self.hardwareBound = hardwareBound
    }
}

/// The `clientDataJSON` members the authority checks itself before the WebAuthn library (ADR-0023 §3a item 2): `type`, the per-purpose origin
/// allow-list, and no `crossOrigin: true` or `topOrigin`.
struct PasskeyClientData {
    let type: String
    let origin: String
    let challenge: String

    static func parse(_ base64url: String) -> PasskeyClientData? {
        guard base64url.utf8.count <= 4096, let bytes = Base64URL.decode(base64url),
              case .object(let o)? = try? JSONDecoder().decode(JSONValue.self, from: bytes),
              let type = o["type"]?.stringValue, let origin = o["origin"]?.stringValue, let challenge = o["challenge"]?.stringValue else { return nil }
        // `crossOrigin` may be absent or false; anything else (true, a string) is refused. `topOrigin` exists only for cross-origin iframes.
        if let cross = o["crossOrigin"], cross != .bool(false) { return nil }
        if o["topOrigin"] != nil { return nil }
        return PasskeyClientData(type: type, origin: origin, challenge: challenge)
    }
}

/// `POST /v1/oidc/passkey/evidence`: the authority verifies the assertion itself (webauthn-swift) against its own passkey log. Any failure is the
/// same `401 evidence_invalid` with the reason audited; the challenge is consumed only after every check passed.
struct PasskeyEvidenceVerifier {
    let ctx: AuthorityContext
    let db: any Database

    func submit(_ request: AuthorityPasskeyEvidenceRequest, caller: AuthorityCaller?) async throws -> AuthorityEvidenceResponse {
        _ = try ctx.requireKeys()
        guard ctx.config.oidcEnabled else { throw Abort(.notFound) }
        let now = ctx.now
        var auditAccount: String?
        var auditTenant: String?
        func refuse(_ reason: String) async -> Abort {
            await AuthorityAudit.record(db, "authority.passkey_evidence", outcome: "denied", reason: reason, tenant: auditTenant, accountRef: auditAccount,
                                        challengeId: AuthorityChallengeID.isValid(request.challengeId) ? request.challengeId : nil,
                                        policyVersion: AuthorityPolicy.v1.version, caller: caller?.name, at: now)
            return Abort.evidenceInvalid
        }
        let credential = request.credential

        // 1. Shape: a valid challenge id; `id` and `rawId` name the same credential.
        guard AuthorityChallengeID.isValid(request.challengeId) else { throw await refuse("malformed") }
        let credentialId = PasskeyCredentialIDs.canonical(credential.id)
        guard Base64URL.isValid(credentialId, minLength: 16, maxLength: 1366), let idBytes = Base64URL.decode(credentialId),
              Base64URL.decode(PasskeyCredentialIDs.canonical(credential.rawId)) == idBytes else { throw await refuse("malformed") }

        // 2. clientDataJSON: `webauthn.get`, an allow-listed origin for `oidc_login`, not cross-origin (ADR-0023 §3a item 2).
        guard let clientData = PasskeyClientData.parse(credential.clientDataJSON) else { throw await refuse("client_data") }
        guard clientData.type == "webauthn.get" else { throw await refuse("ceremony_type") }
        let origins = OIDCProfile.passkeyOrigins(for: .oidcLogin, issuer: ctx.config.issuer)
        guard origins.contains(clientData.origin) else { throw await refuse("origin_not_allowed") }

        // 3. The passkey is in the authority's own log, not revoked, grant-capable; its account exists and is not frozen.
        guard let passkey = try await AuthorityPasskey.find(credentialId, on: db), passkey.revokedAt == nil else { throw await refuse("unknown_passkey") }
        auditAccount = passkey.accountRef
        guard passkey.grantCapable else { throw await refuse("not_grant_capable") }
        guard let account = try await AuthorityAccount.query(on: db).filter(\.$accountRef == passkey.accountRef).first(), let accountId = account.id else {
            throw await refuse("unknown_account")
        }
        guard !account.frozen else { throw await refuse("account_frozen") }

        // 4. The challenge: a pending, unexpired passkey challenge (never an app, link or key-log challenge).
        guard let challenge = try await AuthorityPasskeyChallenge.find(request.challengeId, on: db), challenge.purpose == AuthorityPurpose.oidcLogin.rawValue else {
            throw await refuse("unknown_challenge")
        }
        auditTenant = challenge.tenantId
        guard challenge.state == "pending" else { throw await refuse("challenge_not_pending") }
        guard challenge.expiresAt > now else { throw await refuse("challenge_expired") }
        guard let nonce = Base64URL.decode(challenge.nonce) else { throw await refuse("unknown_challenge") }

        // 5. WebAuthn (webauthn-swift): type, challenge, origin, rpIdHash, user presence and **user verification**, signature with the logged key,
        //    signature counter.
        let verified: VerifiedAuthentication
        do {
            let manager = WebAuthnManager(configuration: .init(relyingPartyID: ctx.config.webAuthnRelyingPartyID, relyingPartyName: "Viadere",
                                                               relyingPartyOrigin: clientData.origin))
            guard let publicKey = Base64URL.decode(passkey.publicKey) else { throw await refuse("unknown_passkey") }
            var response: [String: Any] = ["authenticatorData": credential.authenticatorData, "clientDataJSON": credential.clientDataJSON, "signature": credential.signature]
            if let handle = credential.userHandle { response["userHandle"] = handle }
            let json = try JSONSerialization.data(withJSONObject: ["id": credentialId, "rawId": credentialId, "type": "public-key", "response": response])
            let decoded = try JSONDecoder().decode(AuthenticationCredential.self, from: json)
            verified = try manager.finishAuthentication(credential: decoded, expectedChallenge: [UInt8](nonce), credentialPublicKey: [UInt8](publicKey),
                                                        credentialCurrentSignCount: UInt32(clamping: passkey.signCount), requireUserVerification: true)
        } catch let abort as Abort {
            throw abort
        } catch {
            throw await refuse("assertion_invalid")
        }

        // 6. The client's registration still allows this redirect, and its raises are met (a UV passkey meets `require_biometric` and `acr:passkey`).
        guard let client = try await AuthorityOIDCClient.find(challenge.clientId, on: db), client.status == "active",
              OIDCClientRules.redirectURIs(client).contains(challenge.redirectURI) else { throw await refuse("client_inactive") }

        // 7. Signature counter: moves forward exactly once (a counter that did not grow was refused above as a possible clone).
        if verified.newSignCount > 0 {
            guard let sql = db as? any SQLDatabase,
                  try await sql.update(AuthorityPasskey.schema).set("sign_count", to: Int(verified.newSignCount)).where("credential_id", .equal, credentialId)
                    .where("sign_count", .equal, passkey.signCount).returning("credential_id").all().count == 1 else { throw await refuse("sign_count_race") }
        }

        // 8. Single use: exactly one row moves pending → used.
        guard let sql = db as? any SQLDatabase,
              try await sql.update(AuthorityPasskeyChallenge.schema).set("state", to: "used").set("used_at", to: now).where("id", .equal, challenge.id!)
                .where("state", .equal, "pending").returning("id").all().count == 1 else { throw await refuse("challenge_not_pending") }

        let evidence = VerifiedPasskey(challengeId: challenge.id!, accountId: accountId, accountRef: passkey.accountRef, credentialId: credentialId,
                                       hardwareBound: passkey.hardwareBound)
        await AuthorityAudit.record(db, "authority.passkey_evidence", outcome: "success", tenant: challenge.tenantId, accountRef: passkey.accountRef,
                                    challengeId: challenge.id, policyVersion: AuthorityPolicy.v1.version, caller: caller?.name, detail: "passkey", at: now)
        let code = try await OIDCCodeIssuer(ctx: ctx, db: db).issue(for: evidence, challenge: challenge)
        return AuthorityEvidenceResponse(challengeId: challenge.id!, decision: .approve, code: code)
    }
}

/// Canonical credential ids: unpadded base64url (the form browsers send and the reviewed import stores).
enum PasskeyCredentialIDs {
    static func canonical(_ id: String) -> String {
        var out = id.replacingOccurrences(of: "+", with: "-").replacingOccurrences(of: "/", with: "_")
        while out.hasSuffix("=") { out.removeLast() }
        return out
    }
}

// MARK: Authorization codes

/// Authorization codes for verified `oidc_login` evidence (app or passkey): 256-bit, stored only as a hash, 60 s, single use (ADR-0024 §6). Each
/// issuance also records the consent (client, account, granted at, last used; ADR-0024 §8).
struct OIDCCodeIssuer {
    let ctx: AuthorityContext
    let db: any Database

    /// App path: `acr:app`, `amr` from the key's `uv` and attestation.
    func issue(for evidence: VerifiedEvidence, challenge: AuthorityChallenge) async throws -> String {
        try await store(clientId: challenge.clientId, redirectURI: challenge.targetURL, codeChallenge: challenge.codeChallenge ?? "",
                        nonce: challenge.oidcNonce ?? "", acr: OIDCProfile.acrApp, amr: evidence.amr, accountId: evidence.accountId,
                        accountRef: evidence.accountRef, kid: evidence.kid)
    }

    /// Passkey path: `acr:passkey`, `amr` `user`, `mfa` and `hwk` or `swk`.
    func issue(for evidence: VerifiedPasskey, challenge: AuthorityPasskeyChallenge) async throws -> String {
        try await store(clientId: challenge.clientId, redirectURI: challenge.redirectURI, codeChallenge: challenge.codeChallenge, nonce: challenge.oidcNonce,
                        acr: OIDCProfile.acrPasskey, amr: evidence.amr, accountId: evidence.accountId, accountRef: evidence.accountRef,
                        kid: "passkey:" + evidence.credentialId)
    }

    private func store(clientId: String, redirectURI: String, codeChallenge: String, nonce: String, acr: String, amr: [String], accountId: UUID,
                       accountRef: String, kid: String) async throws -> String {
        let code = Base64URL.encode(SecureToken.randomBytes(32))
        let row = AuthorityOIDCCode()
        row.id = SecureToken.sha256Hex(Data(code.utf8))
        row.clientId = clientId
        row.redirectURI = redirectURI
        row.codeChallenge = codeChallenge
        row.nonce = nonce
        row.acr = acr
        row.amr = String(decoding: try JSONEncoder().encode(amr), as: UTF8.self)
        row.authTime = ctx.now
        row.accountId = accountId
        row.accountRef = accountRef
        row.kid = String(kid.prefix(255))
        row.expiresAt = ctx.now.addingTimeInterval(OIDCProfile.codeLifetime)
        try await row.create(on: db)
        try await AuthorityConsents(ctx: ctx, db: db).recordUse(clientId: clientId, accountRef: accountRef)
        return code
    }
}

// MARK: Consents

/// ADR-0024 §8: consent records kept by the authority, listed for the account's own app and deleted by a reduce-only revoke.
struct AuthorityConsents {
    let ctx: AuthorityContext
    let db: any Database

    /// Called on every code issuance: creates the consent on first use, otherwise moves `last_used_at`.
    func recordUse(clientId: String, accountRef: String) async throws {
        let now = ctx.now
        if let existing = try await AuthorityOIDCConsent.query(on: db).filter(\.$clientId == clientId).filter(\.$accountRef == accountRef).first() {
            existing.lastUsedAt = now
            try await existing.update(on: db)
            return
        }
        let consent = AuthorityOIDCConsent()
        consent.id = UUID()
        consent.clientId = clientId
        consent.accountRef = accountRef
        consent.grantedAt = now
        consent.lastUsedAt = now
        do {
            try await consent.create(on: db)
            await AuthorityAudit.record(db, "authority.oidc_consent_granted", outcome: "success", accountRef: accountRef, detail: clientId, at: now)
        } catch {
            // A concurrent first use created it (unique client + account): move its last use instead.
            try await AuthorityOIDCConsent.query(on: db).filter(\.$clientId == clientId).filter(\.$accountRef == accountRef).set(\.$lastUsedAt, to: now).update()
        }
    }

    func list(accountId: UUID) async throws -> [AuthorityConsent] {
        guard ctx.config.oidcEnabled else { throw Abort(.notFound) }
        let ref = OIDCProfile.accountRef(key: ctx.config.accountRefKey, accountId: accountId)
        let rows = try await AuthorityOIDCConsent.query(on: db).filter(\.$accountRef == ref).sort(\.$lastUsedAt, .descending).limit(200).all()
        var out: [AuthorityConsent] = []
        for row in rows {
            guard let client = try await AuthorityOIDCClient.find(row.clientId, on: db) else { continue }
            out.append(AuthorityConsent(clientId: row.clientId, clientName: client.displayName, host: client.sectorIdentifier,
                                        grantedAt: Int64(row.grantedAt.timeIntervalSince1970), lastUsedAt: Int64(row.lastUsedAt.timeIntervalSince1970)))
        }
        return out
    }

    /// Reduce-only: deletes the one consent of this account for this client, nothing else.
    func revoke(accountId: UUID, clientId: String, caller: AuthorityCaller?) async throws -> Bool {
        guard ctx.config.oidcEnabled else { throw Abort(.notFound) }
        guard OIDCClientID.isValid(clientId) else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
        let ref = OIDCProfile.accountRef(key: ctx.config.accountRefKey, accountId: accountId)
        guard let row = try await AuthorityOIDCConsent.query(on: db).filter(\.$clientId == clientId).filter(\.$accountRef == ref).first() else { return false }
        try await row.delete(on: db)
        await AuthorityAudit.record(db, "authority.oidc_consent_revoked", outcome: "success", accountRef: ref, caller: caller?.name, detail: clientId, at: ctx.now)
        return true
    }
}

// MARK: Reviewed passkey import (ADR-0023 §4 migration, residual R-16)

/// The `passkeys` member of an account in a `keylog-import` change file: `[{credential_id, public_key, sign_count?, hardware_bound?}]`.
/// Only ES256 COSE keys in the CTAP2 canonical form are accepted (what Viadere's passkey registrations store); anything else is refused.
enum AuthorityPasskeyImport {
    struct Imported { let credentialId: String; let publicKey: Data; let signCount: Int; let hardwareBound: Bool }

    static func parse(_ o: [String: JSONValue]) throws -> [UUID: [Imported]] {
        guard case .array(let accounts)? = o["accounts"] else { throw AuthorityAdmin.Failure.invalid("accounts") }
        var out: [UUID: [Imported]] = [:]
        var seen = Set<String>()
        for item in accounts {
            guard case .object(let a) = item, let accountId = a["account_id"]?.stringValue.flatMap(UUID.init(uuidString:)) else { throw AuthorityAdmin.Failure.invalid("account") }
            guard let raw = a["passkeys"] else { continue }
            guard case .array(let passkeys) = raw, !passkeys.isEmpty, passkeys.count <= 20 else { throw AuthorityAdmin.Failure.invalid("passkeys") }
            var parsed: [Imported] = []
            for value in passkeys {
                guard case .object(let p) = value, Set(p.keys).isSubset(of: ["credential_id", "public_key", "sign_count", "hardware_bound"]),
                      let rawId = p["credential_id"]?.stringValue, let rawKey = p["public_key"]?.stringValue else { throw AuthorityAdmin.Failure.invalid("passkey") }
                let id = PasskeyCredentialIDs.canonical(rawId)
                guard Base64URL.isValid(id, minLength: 16, maxLength: 1366), let key = Base64URL.decode(PasskeyCredentialIDs.canonical(rawKey)),
                      isCanonicalES256COSE(key) else { throw AuthorityAdmin.Failure.invalid("passkey") }
                var signCount = 0
                if let count = p["sign_count"] { guard let value = count.authorityInteger, (0...Int64(UInt32.max)).contains(value) else { throw AuthorityAdmin.Failure.invalid("sign_count") }; signCount = Int(value) }
                var hardwareBound = false
                if let flag = p["hardware_bound"] { guard case .bool(let value) = flag else { throw AuthorityAdmin.Failure.invalid("hardware_bound") }; hardwareBound = value }
                // One account per credential, inside the file as well (ADR-0023 §4, S3-A2-4).
                guard seen.insert(id).inserted else { throw AuthorityAdmin.Failure.invalid("key_in_use") }
                parsed.append(Imported(credentialId: id, publicKey: key, signCount: signCount, hardwareBound: hardwareBound))
            }
            out[accountId, default: []] += parsed
        }
        return out
    }

    /// `{1: 2, 3: -7, -1: 1, -2: x(32), -3: y(32)}` in CTAP2 canonical order, with a point on P-256.
    static func isCanonicalES256COSE(_ key: Data) -> Bool {
        let bytes = [UInt8](key)
        let prefix: [UInt8] = [0xA5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01, 0x21, 0x58, 0x20]
        guard bytes.count == 77, Array(bytes[0..<10]) == prefix, bytes[42] == 0x22, bytes[43] == 0x58, bytes[44] == 0x20 else { return false }
        return (try? P256.Signing.PublicKey(rawRepresentation: Data(bytes[10..<42]) + Data(bytes[45..<77]))) != nil
    }

    /// Staging check (admin job): no credential already active in the log.
    static func checkUnused(_ parsed: [UUID: [Imported]], db: any Database) async throws {
        for passkey in parsed.values.joined() {
            if let existing = try await AuthorityPasskey.find(passkey.credentialId, on: db), existing.revokedAt == nil { throw AuthorityAdmin.Failure.invalid("key_in_use") }
        }
    }

    /// Applies one account's passkeys inside the import transaction; each enters the hash-chained log as an `imported` entry.
    static func apply(_ tx: any Database, passkeys: [Imported], accountRef: String, commit: String, now: Date) async throws {
        for imported in passkeys {
            if try await AuthorityPasskey.find(imported.credentialId, on: tx) != nil { throw AuthorityAdmin.Failure.invalid("key_in_use") }
            let row = AuthorityPasskey()
            row.id = imported.credentialId
            row.accountRef = accountRef
            row.publicKey = Base64URL.encode(imported.publicKey)
            row.signCount = imported.signCount
            row.hardwareBound = imported.hardwareBound
            row.grantCapable = true
            row.createdAt = now
            try await row.create(on: tx)
            try await AuthorityKeyLog.append(tx, accountRef: accountRef, type: "imported", kid: "passkey:" + imported.credentialId, publicKey: row.publicKey,
                                             keyPurpose: "passkey", detail: ["commit": .string(commit), "hardware_bound": .bool(imported.hardwareBound)], now: now)
        }
    }
}
