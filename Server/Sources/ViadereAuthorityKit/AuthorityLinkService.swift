@preconcurrency import Crypto
import Fluent
import Foundation
import SQLKit
import Vapor
import ViadereCore

/// A link code that passed every redemption check and was consumed. Only `AuthorityLinkService.redeem` (this file) can construct one, so the grant
/// builder cannot be reached with anything a caller made up (ADR-0023 §6).
struct VerifiedLinkCode: Sendable {
    let challengeId: String
    let accountId: UUID
    let accountRef: String
    let amr: [String]
    let policyVersion: String
    let deliveryId: String
    let purpose: String
    let codeChallenge: String
    let authTime: Date

    fileprivate init(row: AuthorityLinkCode, challenge: AuthorityChallenge) {
        challengeId = row.challengeId
        accountId = row.accountId
        accountRef = row.accountRef
        amr = (try? JSONDecoder().decode([String].self, from: Data(row.amr.utf8))) ?? []
        policyVersion = row.policyVersion
        deliveryId = challenge.deliveryId ?? ""
        purpose = challenge.linkPurpose ?? "sign_in"
        codeChallenge = row.codeChallenge
        authTime = row.authTime
    }
}

/// Link-service codes and redemption (ADR-0021 §5.3-§5.5, §6; ADR-0023 §5, §7).
///
/// 1. Accepted `link_open` evidence registers a code row: the hash of the device-generated code (same device) or, for cross-device evidence that
///    carried the correct number, the challenge reference. 120 s, single use. No grant exists yet.
/// 2. The business backend redeems through the api (`POST /v1/business/auth-links/redeem`), which names its **authenticated** business; the authority
///    compares that with its link-client record (equality only, never a source), checks `S256(code_verifier) == code_challenge` in constant time,
///    consumes the row by compare-and-swap, and only then signs the grant, whose `aud`, `tid` and `sub` come from its own records.
struct AuthorityLinkService {
    let ctx: AuthorityContext
    let db: any Database

    static let codeLifetime: TimeInterval = 120

    func registerCode(evidence: VerifiedEvidence, challenge: AuthorityChallenge, codeHash: String?) async throws {
        let row = AuthorityLinkCode()
        row.id = "lcd_" + Base64URL.encode(SecureToken.randomBytes(16))
        // Same device: the code hash the device signed. Cross device: no code; redemption names the challenge and only works because the evidence
        // carried the correct number (the verifier refuses a code hash on a cross-device challenge and requires one on a same-device challenge).
        row.codeHash = challenge.matchCode == nil ? codeHash : nil
        row.challengeId = challenge.id!
        row.clientId = challenge.clientId
        row.codeChallenge = challenge.codeChallenge ?? ""
        row.accountId = evidence.accountId
        row.accountRef = evidence.accountRef
        row.kid = evidence.kid
        row.amr = String(decoding: try JSONEncoder().encode(evidence.amr), as: UTF8.self)
        row.policyVersion = evidence.policyVersion
        row.authTime = ctx.now
        row.expiresAt = ctx.now.addingTimeInterval(Self.codeLifetime)
        try await row.create(on: db)
    }

    /// `{link_client_id, business_id, code_verifier, code | ach}`. Every refusal is the same `400 invalid_grant`; the reason is audited.
    func redeem(_ o: [String: JSONValue], caller: AuthorityCaller?) async throws -> [String: JSONValue] {
        let keys = try ctx.requireKeys()
        let now = ctx.now
        func refuse(_ reason: String, client: String? = nil) async -> Abort {
            await AuthorityAudit.record(db, "authority.link_redeem", outcome: "denied", reason: reason, tenant: client, caller: caller?.name, at: now)
            return Abort(.badRequest, reason: "invalid_grant")
        }
        guard Set(o.keys) == ["link_client_id", "business_id", "code_verifier", "code"] || Set(o.keys) == ["link_client_id", "business_id", "code_verifier", "ach"],
              let clientId = o["link_client_id"]?.stringValue, let business = o["business_id"]?.stringValue.flatMap(UUID.init(uuidString:)),
              let verifier = o["code_verifier"]?.stringValue, OIDCProfile.isValidCodeVerifier(verifier) else { throw await refuse("malformed") }
        let row: AuthorityLinkCode?
        if let code = o["code"]?.stringValue {
            guard Base64URL.isValid(code, minLength: 43, maxLength: 43) else { throw await refuse("malformed") }
            row = try await AuthorityLinkCode.query(on: db).filter(\.$codeHash == Base64URL.encode(Data(SHA256.hash(data: Data(code.utf8))))).first()
        } else {
            guard let ach = o["ach"]?.stringValue, AuthorityChallengeID.isValid(ach) else { throw await refuse("malformed") }
            // Code-less redemption only for cross-device evidence that carried the correct number (ADR-0021 §6).
            row = try await AuthorityLinkCode.query(on: db).filter(\.$challengeId == ach).filter(\.$codeHash == nil).first()
        }
        guard let row else { throw await refuse("unknown_code") }
        guard let client = try await AuthorityLinkClient.find(row.clientId, on: db), client.status == "active", Data(clientId.utf8) == Data(row.clientId.utf8) else {
            throw await refuse("client_mismatch")
        }
        // The authenticated caller's business, compared for equality with the client record (never used as a source).
        guard client.businessId == business else { throw await refuse("tenant_mismatch", client: client.tenantId) }
        guard row.usedAt == nil, row.expiresAt > now else { throw await refuse("expired_or_used", client: client.tenantId) }
        guard OIDCProfile.pkceMatches(verifier: verifier, challenge: row.codeChallenge) else { throw await refuse("pkce", client: client.tenantId) }
        guard let challenge = try await AuthorityChallenge.find(row.challengeId, on: db), challenge.state == "used" else { throw await refuse("challenge", client: client.tenantId) }
        guard let sql = db as? any SQLDatabase else { throw await refuse("store") }
        let consumed = try await sql.update(AuthorityLinkCode.schema).set("used_at", to: now).where("id", .equal, row.id!).where("used_at", .is, SQLLiteral.null)
            .returning("id").all()
        guard consumed.count == 1 else { throw await refuse("expired_or_used", client: client.tenantId) }
        let verified = VerifiedLinkCode(row: row, challenge: challenge)
        let (grant, claims) = try await GrantBuilder(kms: ctx.kms, keys: keys, config: ctx.config).sign(link: verified, client: client, now: now)
        let record = AuthorityGrantRecord()
        record.id = claims.jti
        record.kind = "grant"
        record.kid = keys.grant.kid
        record.clientId = client.id!
        record.accountRef = verified.accountRef
        record.subHash = SecureToken.sha256Hex(Data(claims.subject.utf8))
        record.acr = claims.acr
        record.policyVersion = verified.policyVersion
        record.challengeId = verified.challengeId
        record.createdAt = now
        try await record.create(on: db)
        await AuthorityAudit.record(db, "authority.link_redeem", outcome: "success", tenant: client.tenantId, accountRef: verified.accountRef, challengeId: verified.challengeId,
                                    kid: row.kid, policyVersion: verified.policyVersion, caller: caller?.name, at: now)
        return ["grant": .string(grant), "delivery_id": .string(verified.deliveryId)]
    }
}
