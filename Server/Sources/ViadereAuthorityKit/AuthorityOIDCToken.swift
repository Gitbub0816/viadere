@preconcurrency import Crypto
import _CryptoExtras
import Fluent
import Foundation
import SQLKit
import Vapor
import ViadereCore

/// An authorization code that was authenticated (client), matched (redirect URI, PKCE) and consumed. Only `OIDCTokenService` (this file) constructs one.
struct VerifiedCode: Sendable {
    let clientId: String
    let accountId: UUID
    let accountRef: String
    let nonce: String
    let acr: String
    let amr: [String]
    let authTime: Date

    fileprivate init(clientId: String, accountId: UUID, accountRef: String, nonce: String, acr: String, amr: [String], authTime: Date) {
        self.clientId = clientId
        self.accountId = accountId
        self.accountRef = accountRef
        self.nonce = nonce
        self.acr = acr
        self.amr = amr
        self.authTime = authTime
    }
}

/// An OAuth error answer (RFC 6749 §5.2).
struct OAuthError: Error, Sendable {
    let status: HTTPResponseStatus
    let code: String
}

/// `POST /v1/oidc/token` (the api forwards `/oidc/token` unchanged): `authorization_code` only, `private_key_jwt` only (ADR-0024 §2, §6).
struct OIDCTokenService {
    let ctx: AuthorityContext
    let db: any Database

    static let allowedParameters: Set<String> = ["grant_type", "code", "redirect_uri", "code_verifier", "client_id", "client_assertion_type", "client_assertion"]

    /// Parses an `application/x-www-form-urlencoded` body; a repeated parameter or an unknown one is `invalid_request` (RFC 6749 §3.2).
    static func parseForm(_ body: String) throws -> [String: String] {
        var out: [String: String] = [:]
        guard body.utf8.count <= 16 * 1024 else { throw OAuthError(status: .badRequest, code: "invalid_request") }
        for pair in body.split(separator: "&", omittingEmptySubsequences: true) {
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2, let name = String(parts[0]).replacingOccurrences(of: "+", with: " ").removingPercentEncoding,
                  let value = String(parts[1]).replacingOccurrences(of: "+", with: " ").removingPercentEncoding else { throw OAuthError(status: .badRequest, code: "invalid_request") }
            guard allowedParameters.contains(name), out[name] == nil else { throw OAuthError(status: .badRequest, code: "invalid_request") }
            out[name] = value
        }
        return out
    }

    func exchange(form body: String) async throws -> [String: JSONValue] {
        let keys = try ctx.requireKeys()
        guard ctx.config.oidcEnabled else { throw Abort(.notFound) }
        let now = ctx.now
        let form = try Self.parseForm(body)
        guard form["grant_type"] == "authorization_code" else { throw OAuthError(status: .badRequest, code: "unsupported_grant_type") }
        guard let code = form["code"], let redirectURI = form["redirect_uri"], let verifier = form["code_verifier"] else {
            throw OAuthError(status: .badRequest, code: "invalid_request")
        }
        // Client authentication first: private_key_jwt only.
        guard form["client_assertion_type"] == OIDCProfile.clientAssertionType, let assertion = form["client_assertion"] else {
            throw OAuthError(status: .unauthorized, code: "invalid_client")
        }
        let client = try await authenticate(assertion: assertion, claimedClientId: form["client_id"], now: now)

        // The code: exists, this client's, unexpired, unused; exact redirect URI; PKCE S256.
        let hash = SecureToken.sha256Hex(Data(code.utf8))
        guard let row = try await AuthorityOIDCCode.find(hash, on: db) else { return try await invalidGrant("unknown_code", client: client.id) }
        guard row.usedAt == nil else { return try await invalidGrant("code_reused", client: client.id) }
        guard ConstantTime.equals(row.clientId, client.id!) else { return try await invalidGrant("client_mismatch", client: client.id) }
        guard row.expiresAt > now else { return try await invalidGrant("code_expired", client: client.id) }
        guard Data(redirectURI.utf8) == Data(row.redirectURI.utf8) else { return try await invalidGrant("redirect_uri_mismatch", client: client.id) }
        guard OIDCProfile.pkceMatches(verifier: verifier, challenge: row.codeChallenge) else { return try await invalidGrant("pkce_mismatch", client: client.id) }
        guard let sql = db as? any SQLDatabase,
              try await sql.update(AuthorityOIDCCode.schema).set("used_at", to: now).where("code_hash", .equal, hash).where("used_at", .is, SQLLiteral.null)
                .returning("code_hash").all().count == 1 else { return try await invalidGrant("code_reused", client: client.id) }
        let amr = (try? JSONDecoder().decode([String].self, from: Data(row.amr.utf8))) ?? []
        let verified = VerifiedCode(clientId: client.id!, accountId: row.accountId, accountRef: row.accountRef, nonce: row.nonce, acr: row.acr, amr: amr, authTime: row.authTime)

        let tokens = try await OIDCTokenBuilder(kms: ctx.kms, keys: keys, config: ctx.config).sign(code: verified, client: client, now: now)
        for (jti, kind, kid) in [(tokens.idTokenJTI, "id_token", tokens.idTokenKid), (tokens.accessTokenJTI, "access_token", tokens.accessTokenKid)] {
            let record = AuthorityGrantRecord()
            record.id = jti
            record.kind = kind
            record.kid = kid
            record.clientId = client.id!
            record.accountRef = verified.accountRef
            record.subHash = SecureToken.sha256Hex(Data(tokens.subject.utf8))
            record.acr = verified.acr
            record.policyVersion = AuthorityPolicy.v1.version
            record.challengeId = String(hash.prefix(16))
            record.createdAt = now
            try await record.create(on: db)
        }
        await AuthorityAudit.record(db, "authority.oidc_token", outcome: "success", tenant: client.tenantId, accountRef: verified.accountRef,
                                    kid: tokens.idTokenKid, policyVersion: AuthorityPolicy.v1.version, detail: client.id, at: now)
        return ["access_token": .string(tokens.accessToken), "token_type": .string("Bearer"), "expires_in": .integer(OIDCProfile.tokenLifetime),
                "id_token": .string(tokens.idToken), "scope": .string("openid")]
    }

    private func invalidGrant(_ reason: String, client: String?) async throws -> [String: JSONValue] {
        await AuthorityAudit.record(db, "authority.oidc_token", outcome: "denied", reason: reason, detail: client, at: ctx.now)
        throw OAuthError(status: .badRequest, code: "invalid_grant")
    }

    /// `private_key_jwt` (RFC 7523, OIDC Core §9): `iss` = `sub` = client id; `aud` a **single string** exactly equal to the issuer (arrays and the
    /// token endpoint URL refused); algorithm resolved from the registered JWK (never from the header alone); `iat` required; `exp` ≤ 5 minutes ahead;
    /// `jti` single use until `exp` + 60 s.
    func authenticate(assertion: String, claimedClientId: String?, now: Date) async throws -> AuthorityOIDCClient {
        func fail(_ reason: String, _ client: String? = nil) async -> OAuthError {
            await AuthorityAudit.record(db, "authority.client_auth", outcome: "denied", reason: reason, detail: client, at: now)
            return OAuthError(status: .unauthorized, code: "invalid_client")
        }
        let segments = assertion.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard assertion.utf8.count <= 4096, segments.count == 3, segments.allSatisfy({ !$0.isEmpty && Base64URL.isValid($0) }),
              let headerBytes = Base64URL.decode(segments[0]), let payloadBytes = Base64URL.decode(segments[1]), let signature = Base64URL.decode(segments[2]),
              case .object(let header)? = try? JSONDecoder().decode(JSONValue.self, from: headerBytes),
              case .object(let claims)? = try? JSONDecoder().decode(JSONValue.self, from: payloadBytes) else { throw await fail("malformed") }
        // Header: `alg`, `kid`, optional `typ: JWT`; nothing that could carry or point to a key.
        guard Set(header.keys).isSubset(of: ["alg", "kid", "typ"]), let alg = header["alg"]?.stringValue, let kid = header["kid"]?.stringValue,
              header["typ"] == nil || header["typ"]?.stringValue == "JWT" else { throw await fail("header") }
        guard let iss = claims["iss"]?.stringValue, let sub = claims["sub"]?.stringValue, iss == sub, iss.hasPrefix("ocl_") else { throw await fail("iss") }
        if let claimedClientId, claimedClientId != iss { throw await fail("client_id_mismatch", iss) }
        guard let client = try await AuthorityOIDCClient.find(iss, on: db), client.status == "active" else { throw await fail("unknown_client", iss) }
        guard case .string(let aud)? = claims["aud"], aud == ctx.config.issuer else { throw await fail("audience", iss) }
        guard let iat = claims["iat"]?.authorityInteger, let exp = claims["exp"]?.authorityInteger, let jti = claims["jti"]?.stringValue, (1...256).contains(jti.utf8.count) else {
            throw await fail("claims", iss)
        }
        let t = Int64(now.timeIntervalSince1970)
        guard iat <= t + 60, exp > t - 60, exp - t <= OIDCProfile.clientAssertionMaxLifetime, exp > iat else { throw await fail("time", iss) }
        if let nbf = claims["nbf"]?.authorityInteger, nbf > t + 60 { throw await fail("time", iss) }

        // The registered key decides the algorithm.
        guard let jwk = OIDCClientKeys.jwk(in: client.jwks, kid: kid), let registeredAlg = jwk["alg"]?.stringValue, registeredAlg == alg else {
            throw await fail("key", iss)
        }
        let input = Data((segments[0] + "." + segments[1]).utf8)
        guard OIDCClientKeys.verify(jwk: jwk, alg: alg, input: input, signature: signature) else { throw await fail("signature", iss) }

        // Single use of the assertion.
        let replay = AuthorityReplayRecord()
        replay.id = "client-assertion:" + SecureToken.sha256Hex(Data((iss + "\n" + jti).utf8))
        replay.expiresAt = Date(timeIntervalSince1970: TimeInterval(exp + 60))
        do { try await replay.create(on: db) } catch { throw await fail("jti_replayed", iss) }
        return client
    }
}

/// Client JWKS registered by the admin job: EC P-256 (`ES256`) and RSA ≥ 2048 (`RS256`, `PS256`); every JWK carries `kid` and `alg`.
enum OIDCClientKeys {
    static func jwk(in jwks: String, kid: String) -> [String: JSONValue]? {
        guard case .object(let set)? = try? JSONDecoder().decode(JSONValue.self, from: Data(jwks.utf8)), case .array(let keys)? = set["keys"] else { return nil }
        let matches = keys.compactMap(\.objectValue).filter { $0["kid"]?.stringValue == kid }
        return matches.count == 1 ? matches[0] : nil
    }

    static func isRegistrable(_ jwk: [String: JSONValue]) -> Bool {
        guard let kid = jwk["kid"]?.stringValue, !kid.isEmpty, let alg = jwk["alg"]?.stringValue, jwk["d"] == nil, jwk["p"] == nil else { return false }
        switch (jwk["kty"]?.stringValue, alg) {
        case ("EC", "ES256"): return p256(jwk) != nil
        case ("RSA", "RS256"), ("RSA", "PS256"): return rsa(jwk) != nil
        default: return false
        }
    }

    static func p256(_ jwk: [String: JSONValue]) -> P256.Signing.PublicKey? {
        guard jwk["crv"]?.stringValue == "P-256", let x = jwk["x"]?.stringValue.flatMap(Base64URL.decode), let y = jwk["y"]?.stringValue.flatMap(Base64URL.decode),
              x.count == 32, y.count == 32 else { return nil }
        return try? P256.Signing.PublicKey(rawRepresentation: x + y)
    }

    static func rsa(_ jwk: [String: JSONValue]) -> _RSA.Signing.PublicKey? {
        guard let n = jwk["n"]?.stringValue.flatMap(Base64URL.decode), let e = jwk["e"]?.stringValue.flatMap(Base64URL.decode), n.count >= 256 else { return nil }
        return try? _RSA.Signing.PublicKey(n: n, e: e)
    }

    static func verify(jwk: [String: JSONValue], alg: String, input: Data, signature: Data) -> Bool {
        switch alg {
        case "ES256":
            guard let key = p256(jwk), signature.count == 64, let sig = try? P256.Signing.ECDSASignature(rawRepresentation: signature) else { return false }
            return key.isValidSignature(sig, for: input)
        case "RS256":
            guard let key = rsa(jwk) else { return false }
            return key.isValidSignature(_RSA.Signing.RSASignature(rawRepresentation: signature), for: input, padding: .insecurePKCS1v1_5)
        case "PS256":
            guard let key = rsa(jwk) else { return false }
            return key.isValidSignature(_RSA.Signing.RSASignature(rawRepresentation: signature), for: input, padding: .PSS)
        default:
            return false
        }
    }
}
