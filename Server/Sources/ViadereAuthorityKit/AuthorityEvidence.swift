@preconcurrency import Crypto
import Fluent
import Foundation
import SQLKit
import Vapor
import ViadereCore

/// Evidence that passed every step of ADR-0023 §3 and consumed its challenge. Only `EvidenceVerifier` (this file) can construct one, so the grant
/// and token builders cannot be reached with anything the caller made up.
struct VerifiedEvidence: Sendable {
    let challengeId: String
    let purpose: AuthorityPurpose
    let accountId: UUID
    let accountRef: String
    let kid: String
    let userVerification: FactorUserVerification
    let hardwareAttested: Bool
    let policyVersion: String
    var amr: [String] { OIDCProfile.appAMR(userVerification: userVerification, hardwareAttested: hardwareAttested) }

    fileprivate init(challengeId: String, purpose: AuthorityPurpose, accountId: UUID, accountRef: String, kid: String, userVerification: FactorUserVerification,
                     hardwareAttested: Bool, policyVersion: String) {
        self.challengeId = challengeId
        self.purpose = purpose
        self.accountId = accountId
        self.accountRef = accountRef
        self.kid = kid
        self.userVerification = userVerification
        self.hardwareAttested = hardwareAttested
        self.policyVersion = policyVersion
    }
}

/// `POST /v1/challenges` (ADR-0033 §1, ADR-0024 §4): references only; the authority validates them against its own registrations and builds the display.
struct AuthorityChallengeService {
    let ctx: AuthorityContext
    let db: any Database

    static let maxMatchFailures = 3

    func create(_ request: AuthorityChallengeCreateRequest, caller: AuthorityCaller?) async throws -> AuthorityChallengeCreateResponse {
        let keys = try ctx.requireKeys()
        let now = ctx.now
        let challenge = AuthorityChallenge()
        challenge.id = AuthorityChallengeID.generate()
        challenge.purpose = request.purpose.rawValue
        challenge.nonce = AuthorityNonce.generate()
        challenge.state = "pending"
        challenge.matchFailures = 0
        challenge.createdAt = now
        challenge.expiresAt = now.addingTimeInterval(ctx.config.challengeLifetime)
        let display: JSONValue
        var hintAccepted: Bool?
        switch request.purpose {
        case .oidcLogin:
            guard ctx.config.oidcEnabled else { throw Abort(.notFound) }
            guard let oidc = request.oidc, request.link == nil else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
            // Client, exact redirect URI, PKCE, nonce and acr values are re-validated here, whatever the api checked before (ADR-0024 §4).
            let client = try await OIDCAuthorizationChecks.client(for: oidc, db: db)
            let acr = oidc.acrValues ?? []
            // A client (or request) that requires the passkey acr can never be satisfied by app approval: no app challenge is created for it.
            if client.requirePasskey || (!acr.isEmpty && !acr.contains(OIDCProfile.acrApp)) { throw Abort(.unprocessableEntity, reason: "passkey_required") }
            guard await ctx.bulkhead.admit(tenant: client.tenantId, now: now) else { throw Abort(.tooManyRequests, reason: "challenge_budget") }
            hintAccepted = try await OIDCAuthorizationChecks.verifyHint(oidc, client: client, ctx: ctx, db: db)
            challenge.tenantId = client.tenantId
            challenge.clientId = client.id!
            challenge.targetURL = oidc.redirectURI
            challenge.matchCode = AuthorityMatchCode.twoDigits()
            challenge.codeChallenge = oidc.codeChallenge
            challenge.oidcNonce = oidc.nonce
            display = AuthorityDisplay.oidcLogin(clientName: client.displayName, redirectURI: oidc.redirectURI, matchDigits: 2)
        case .linkOpen:
            guard let link = request.link, request.oidc == nil else { throw Abort(.unprocessableEntity, reason: "invalid_request") }
            guard let client = try await AuthorityLinkClient.find(link.linkClientId, on: db), client.status == "active",
                  OIDCClientRules.jsonArray(client.returnURLs).contains(link.returnURL) else { throw Abort(.unprocessableEntity, reason: "invalid_client") }
            guard AuthDeliveryID(link.deliveryId) != nil, OIDCProfile.isValidCodeChallenge(link.codeChallenge), ["sign_in", "step_up"].contains(link.purpose) else {
                throw Abort(.unprocessableEntity, reason: "invalid_request")
            }
            guard await ctx.bulkhead.admit(tenant: client.tenantId, now: now) else { throw Abort(.tooManyRequests, reason: "challenge_budget") }
            challenge.tenantId = client.tenantId
            challenge.clientId = client.id!
            challenge.targetURL = link.returnURL
            challenge.matchCode = link.crossDevice ? AuthorityMatchCode.twoDigits() : nil
            challenge.codeChallenge = link.codeChallenge
            challenge.deliveryId = link.deliveryId
            challenge.linkPurpose = link.purpose
            display = AuthorityDisplay.linkOpen(tenantName: client.tenantName, clientName: client.displayName, returnURL: link.returnURL,
                                                matchDigits: link.crossDevice ? 2 : nil)
        default:
            // Key-log and recovery purposes arrive with their stage (ADR-0032, ADR-0034); never a silent fallback.
            throw Abort(.unprocessableEntity, reason: "purpose_not_supported")
        }
        challenge.display = String(decoding: try CanonicalJSON.serialize(display), as: UTF8.self)
        challenge.displayDigest = try AuthorityDisplay.digest(display)
        try await challenge.create(on: db)
        let statement = try await StatementBuilder(kms: ctx.kms, keys: keys, environment: ctx.environment).sign(challenge)
        await AuthorityAudit.record(db, "authority.challenge_created", outcome: "success", tenant: challenge.tenantId, challengeId: challenge.id,
                                    caller: caller?.name, detail: challenge.purpose, at: now)
        if let hintAccepted {
            await AuthorityAudit.record(db, "authority.login_hint", outcome: hintAccepted ? "success" : "denied", tenant: challenge.tenantId,
                                        challengeId: challenge.id, caller: caller?.name, at: now)
        }
        return AuthorityChallengeCreateResponse(challengeId: challenge.id!, statement: statement, matchCode: challenge.matchCode,
                                                expiresAt: Int64(challenge.expiresAt.timeIntervalSince1970), hintAccepted: hintAccepted)
    }
}

/// Registration data helpers.
enum OIDCClientRules {
    static func jsonArray(_ text: String) -> [String] { (try? JSONDecoder().decode([String].self, from: Data(text.utf8))) ?? [] }
    static func redirectURIs(_ client: AuthorityOIDCClient) -> [String] { jsonArray(client.redirectURIs) }
}

/// `POST /v1/evidence`: ADR-0023 §3 in order. Any failure is the same `401 evidence_invalid`; the reason is audited. The challenge is consumed only
/// after every check passed, so a forged assertion cannot burn a real challenge; a **signature-valid** wrong `match` counts toward the challenge's
/// three failures (S1-A3-05).
struct EvidenceVerifier {
    let ctx: AuthorityContext
    let db: any Database

    func submit(_ request: AuthorityEvidenceRequest, caller: AuthorityCaller?) async throws -> AuthorityEvidenceResponse {
        let keys = try ctx.requireKeys()
        let now = ctx.now
        var auditKid: String?
        var auditChallenge: String?
        func refuse(_ reason: String, accountRef: String? = nil, tenant: String? = nil) async -> Abort {
            await AuthorityAudit.record(db, "authority.evidence", outcome: "denied", reason: reason, tenant: tenant, accountRef: accountRef,
                                        challengeId: auditChallenge, kid: auditKid, policyVersion: AuthorityPolicy.v1.version, caller: caller?.name, at: now)
            return Abort.evidenceInvalid
        }

        // 1. Strict parse and JOSE profile.
        let parsed: ParsedFactorAssertion
        do { parsed = try FactorAssertion.parse(request.factor) } catch { throw await refuse("malformed") }
        let claims = parsed.claims
        auditKid = parsed.kid
        auditChallenge = claims.challengeId
        guard claims.purpose == .oidcLogin || claims.purpose == .linkOpen else { throw await refuse("purpose_not_supported") }
        if claims.purpose == .oidcLogin, !ctx.config.oidcEnabled { throw Abort(.notFound) }

        // 2. The key is in the authority's own log, active, grant-capable, usable, consistent with `uv`; the account is not frozen.
        guard let key = try await AuthorityKey.find(parsed.kid, on: db), key.revokedAt == nil else { throw await refuse("unknown_key") }
        guard let account = try await AuthorityAccount.query(on: db).filter(\.$accountRef == key.accountRef).first() else { throw await refuse("unknown_account") }
        if claims.purpose.yieldsGrant, !key.grantCapable { throw await refuse("not_grant_capable", accountRef: key.accountRef) }
        guard key.usableFrom <= now else { throw await refuse("not_yet_usable", accountRef: key.accountRef) }
        if claims.userVerification == .biometric, key.keyPurpose != DeviceKeyPurpose.approvalBiometric.rawValue {
            throw await refuse("uv_inconsistent", accountRef: key.accountRef)
        }
        guard !account.frozen else { throw await refuse("account_frozen", accountRef: key.accountRef) }

        // 3. Signature with the logged public key (the kid is recomputed from the stored key).
        guard let publicKey = try? DevicePublicKey(base64URL: key.publicKey).signingKey() else { throw await refuse("unknown_key") }
        do { try FactorAssertion.verifySignature(parsed, loggedKey: publicKey) } catch { throw await refuse("bad_signature", accountRef: key.accountRef) }

        // 3a. Account binding: an account id the api names must be the signing key's account (constant time on the references).
        if let named = request.accountId {
            let namedRef = OIDCProfile.accountRef(key: ctx.config.accountRefKey, accountId: named)
            guard ConstantTime.equals(namedRef, key.accountRef) else { throw await refuse("account_binding_mismatch", accountRef: key.accountRef) }
        }

        // 4. Audience, challenge, nonce, purpose.
        guard claims.audience == ctx.environment.authorityURN else { throw await refuse("audience", accountRef: key.accountRef) }
        guard let challenge = try await AuthorityChallenge.find(claims.challengeId, on: db) else { throw await refuse("unknown_challenge", accountRef: key.accountRef) }
        guard challenge.state == "pending" else { throw await refuse("challenge_not_pending", accountRef: key.accountRef, tenant: challenge.tenantId) }
        guard challenge.expiresAt > now else {
            _ = try? await swap(challenge.id!, to: "expired")
            throw await refuse("challenge_expired", accountRef: key.accountRef, tenant: challenge.tenantId)
        }
        guard ConstantTime.equals(claims.nonce, challenge.nonce), claims.purpose.rawValue == challenge.purpose else {
            throw await refuse("challenge_mismatch", accountRef: key.accountRef, tenant: challenge.tenantId)
        }

        // 5. What the person saw: the digest of the authority-built display; for link_open the exact return URL.
        guard ConstantTime.equals(claims.displayDigest, challenge.displayDigest) else { throw await refuse("display_mismatch", accountRef: key.accountRef, tenant: challenge.tenantId) }
        if claims.purpose == .linkOpen {
            guard let url = claims.returnURL, Data(url.utf8) == Data(challenge.targetURL.utf8) else {
                throw await refuse("return_url_mismatch", accountRef: key.accountRef, tenant: challenge.tenantId)
            }
            // Same-device link opens carry the device-generated code hash; cross-device ones the typed number.
            if challenge.matchCode == nil, claims.decision == .approve, claims.codeHash == nil {
                throw await refuse("code_hash_required", accountRef: key.accountRef, tenant: challenge.tenantId)
            }
            if challenge.matchCode != nil, claims.codeHash != nil { throw await refuse("code_hash_unexpected", accountRef: key.accountRef, tenant: challenge.tenantId) }
        }

        // 7. Time bounds (±60 s).
        let t = Int64(now.timeIntervalSince1970)
        guard claims.issuedAt <= t + FactorAssertionClaims.skew, t <= claims.expiresAt + FactorAssertionClaims.skew else {
            throw await refuse("time_bounds", accountRef: key.accountRef, tenant: challenge.tenantId)
        }

        // A deny or report ends the challenge (reduce-only; no grant, no code).
        if claims.decision != .approve {
            guard try await swap(challenge.id!, to: "denied") else { throw await refuse("challenge_not_pending", accountRef: key.accountRef, tenant: challenge.tenantId) }
            await AuthorityAudit.record(db, "authority.evidence", outcome: "denied_by_person", reason: claims.decision.rawValue, tenant: challenge.tenantId,
                                        accountRef: key.accountRef, challengeId: challenge.id, kid: key.id, caller: caller?.name, at: now)
            return AuthorityEvidenceResponse(challengeId: challenge.id!, decision: claims.decision)
        }

        // 6. Number matching (constant time). A signature-valid wrong number counts; the third ends the challenge.
        if let expected = challenge.matchCode {
            guard let typed = claims.match, typed.count == expected.count, ConstantTime.equals(typed, expected) else {
                let failures = try await countMatchFailure(challenge)
                throw await refuse(failures >= Self.maxFailures ? "match_failed_final" : "match_mismatch", accountRef: key.accountRef, tenant: challenge.tenantId)
            }
        } else if claims.match != nil {
            throw await refuse("match_unexpected", accountRef: key.accountRef, tenant: challenge.tenantId)
        }

        // 8. Policy: the platform floor plus the client's raises.
        var policy = AuthorityPolicy.v1
        if claims.purpose == .oidcLogin, let client = try await AuthorityOIDCClient.find(challenge.clientId, on: db) {
            policy = policy.raised(requireBiometric: client.requireBiometric, requirePasskey: client.requirePasskey || (challenge.requirePasskey ?? false))
        } else if claims.purpose == .linkOpen, let client = try await AuthorityLinkClient.find(challenge.clientId, on: db) {
            policy = policy.raised(requireBiometric: client.requireBiometric, requirePasskey: false)
        }
        if case .deny(let reason) = policy.evaluateAppEvidence(userVerification: claims.userVerification, decision: claims.decision) {
            throw await refuse("policy_\(reason)", accountRef: key.accountRef, tenant: challenge.tenantId)
        }

        // 9. Single use: exactly one row moves pending → used, or nothing is issued.
        guard try await swap(challenge.id!, to: "used") else { throw await refuse("challenge_not_pending", accountRef: key.accountRef, tenant: challenge.tenantId) }
        guard let accountId = account.id else { throw await refuse("unknown_account") }
        let evidence = VerifiedEvidence(challengeId: challenge.id!, purpose: claims.purpose, accountId: accountId, accountRef: key.accountRef, kid: key.id!,
                                        userVerification: claims.userVerification, hardwareAttested: key.hardwareAttested, policyVersion: policy.version)
        await AuthorityAudit.record(db, "authority.evidence", outcome: "success", tenant: challenge.tenantId, accountRef: key.accountRef, challengeId: challenge.id,
                                    kid: key.id, policyVersion: policy.version, caller: caller?.name, detail: claims.userVerification.rawValue, at: now)
        switch claims.purpose {
        case .oidcLogin:
            let code = try await OIDCCodeIssuer(ctx: ctx, db: db).issue(for: evidence, challenge: challenge)
            return AuthorityEvidenceResponse(challengeId: challenge.id!, decision: .approve, code: code)
        case .linkOpen:
            guard let client = try await AuthorityLinkClient.find(challenge.clientId, on: db) else { throw Abort.evidenceInvalid }
            let (grant, grantClaims) = try await GrantBuilder(kms: ctx.kms, keys: keys, config: ctx.config).sign(evidence: evidence, client: client, challenge: challenge, now: now)
            let record = AuthorityGrantRecord()
            record.id = grantClaims.jti
            record.kind = "grant"
            record.kid = keys.grant.kid
            record.clientId = client.id!
            record.accountRef = evidence.accountRef
            record.subHash = SecureToken.sha256Hex(Data(grantClaims.subject.utf8))
            record.acr = grantClaims.acr
            record.policyVersion = evidence.policyVersion
            record.challengeId = evidence.challengeId
            record.createdAt = now
            try await record.create(on: db)
            return AuthorityEvidenceResponse(challengeId: challenge.id!, decision: .approve, grant: grant)
        default:
            throw Abort.evidenceInvalid
        }
    }

    static let maxFailures = 3

    /// pending → `state`, exactly once (compare-and-swap on the state column).
    private func swap(_ id: String, to state: String) async throws -> Bool {
        guard let sql = db as? any SQLDatabase else { return false }
        let rows = try await sql.update(AuthorityChallenge.schema).set("state", to: state).set("used_at", to: ctx.now)
            .where("id", .equal, id).where("state", .equal, "pending").returning("id").all()
        return rows.count == 1
    }

    /// Atomically increments the failure count; at three the challenge is `failed`.
    private func countMatchFailure(_ challenge: AuthorityChallenge) async throws -> Int {
        guard let sql = db as? any SQLDatabase else { return Self.maxFailures }
        try await sql.raw("UPDATE \(ident: AuthorityChallenge.schema) SET match_failures = match_failures + 1 WHERE id = \(bind: challenge.id!) AND state = 'pending'").run()
        let failures = try await AuthorityChallenge.find(challenge.id!, on: db)?.matchFailures ?? Self.maxFailures
        if failures >= Self.maxFailures { _ = try await swap(challenge.id!, to: "failed") }
        return failures
    }
}

// `OIDCCodeIssuer` (app and passkey paths, with consent records) lives in `AuthorityOIDCMethods.swift`.
