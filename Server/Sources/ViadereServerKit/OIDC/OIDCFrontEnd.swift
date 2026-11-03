@preconcurrency import Crypto
import _CryptoExtras
import Fluent
import Foundation
import Vapor
import ViadereCore

/// The browser-facing half of the staging OpenID provider (ADR-0024 §4, §6, §8) and the device relay of the app path. Served by the api on the `id.` host;
/// **nothing here signs or mints**: the authorization code, the id_token and the access token come only from the authority. Discovery and JWKS are static
/// files published by `authority-publish.yml`, never served here (ADR-0024 §7).
///
/// Residual R-17 (named exception, ADR-0024 §4): a compromised api can bind a victim's in-progress login to an attacker's RP session.
enum OIDCFrontEnd {
    static let pathPrefix = "/oidc/"
    static let cookieName = "__Host-vdr_oidc"
    /// Strict page policy: no script, no style, no frame; forms post only to this origin.
    static let pageCSP = "default-src 'none'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'"

    static func register(_ app: Application) {
        app.get("oidc", "authorize") { req in try await authorize(req) }
        app.post("oidc", "authorize", "app") { req in try await chooseApp(req) }
        app.get("oidc", "authorize", "status") { req in try await status(req) }
        app.post("oidc", "token") { req in try await token(req) }
        app.get("oidc", "userinfo") { req in try await userinfo(req) }
        app.post("oidc", "userinfo") { req in try await userinfo(req) }
        app.get("oidc", "logout") { req in try await logout(req) }

        app.api(APIRoutes.oidcChallengeGet) { req in
            _ = try OIDCGate.require(req)
            let principal = try req.consumer
            guard principal.deviceId != nil else { throw APIError.notFound }
            let row = try await pendingByChallenge(req)
            return try req.jsonResponse(OIDCDeviceChallenge(statement: row.statement ?? ""))
        }
        app.api(APIRoutes.oidcChallengeEvidence) { req in
            let client = try OIDCGate.require(req)
            let principal = try req.consumer
            guard let device = principal.deviceId else { throw APIError.notFound }
            try await req.ctx.limiter.enforce("oidc-evidence", key: device.description, rule: .perMinute(30, burst: 10))
            let body: OIDCDeviceEvidenceRequest
            do { body = try ViadereJSON.decode(OIDCDeviceEvidenceRequest.self, from: req.bodyBytes) } catch { throw APIError.validation("The request failed validation.") }
            let row = try await pendingByChallenge(req)
            // The api names the signed-in account; the authority checks it against the signing key's account (ADR-0023 §3 step 3a). It never selects it.
            guard let answer = try await relay(client, AuthorityEvidenceRequest(factor: body.factor, accountId: principal.consumerId.uuid)) else {
                throw APIError(.forbidden, .forbidden, "This sign-in couldn't be confirmed.")
            }
            guard answer.challengeId == row.challengeId else { throw APIError.internalError }
            if answer.decision == .approve, let code = answer.code {
                try await OIDCAuthorizationRecord.query(on: req.db).filter(\.$id == row.id!).filter(\.$status == "challenged")
                    .set(\.$status, to: "approved").set(\.$code, to: code).update()
            } else {
                try await OIDCAuthorizationRecord.query(on: req.db).filter(\.$id == row.id!).filter(\.$status == "challenged").set(\.$status, to: "denied").update()
            }
            return try req.jsonResponse(OIDCDeviceEvidenceResponse(decision: answer.decision))
        }
    }

    static func relay(_ client: AuthorityClient, _ request: AuthorityEvidenceRequest) async throws -> AuthorityEvidenceResponse? {
        do { return try await client.submitEvidence(request) } catch { throw APIError(.serviceUnavailable, .unavailable, "Sign-in with Viadere is unavailable right now.") }
    }

    static func pendingByChallenge(_ req: Request) async throws -> OIDCAuthorizationRecord {
        guard let ach = req.parameters.get("challengeId"), AuthorityChallengeID.isValid(ach),
              let row = try await OIDCAuthorizationRecord.query(on: req.db).filter(\.$challengeId == ach).first(),
              row.status == "challenged", row.expiresAt > req.ctx.now else { throw APIError.notFound }
        return row
    }

    // MARK: Query parsing

    /// Query parameters; a repeated parameter is refused (RFC 6749 §3.1).
    static func query(_ req: Request) -> [String: String]? {
        guard let items = URLComponents(string: req.url.string)?.queryItems else { return [:] }
        var out: [String: String] = [:]
        for item in items {
            guard out[item.name] == nil, let value = item.value, value.utf8.count <= 1024 else { return nil }
            out[item.name] = value
        }
        return out
    }

    static func form(_ req: Request) -> [String: String]? {
        guard let body = req.body.string, body.utf8.count <= 4096 else { return nil }
        var out: [String: String] = [:]
        for pair in body.split(separator: "&") {
            let parts = pair.split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2, let name = String(parts[0]).removingPercentEncoding,
                  let value = String(parts[1]).replacingOccurrences(of: "+", with: " ").removingPercentEncoding, out[name] == nil else { return nil }
            out[name] = value
        }
        return out
    }

    // MARK: Responses

    static func escape(_ text: String) -> String {
        text.replacingOccurrences(of: "&", with: "&amp;").replacingOccurrences(of: "<", with: "&lt;").replacingOccurrences(of: ">", with: "&gt;")
            .replacingOccurrences(of: "\"", with: "&quot;").replacingOccurrences(of: "'", with: "&#39;")
    }

    static func page(_ title: String, _ body: String, status: HTTPResponseStatus = .ok, refresh: Bool = false) -> Response {
        let meta = refresh ? "<meta http-equiv=\"refresh\" content=\"3\">" : ""
        let html = "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\(meta)"
            + "<meta name=\"referrer\" content=\"no-referrer\"><title>\(escape(title))</title></head><body><main><h1>\(escape(title))</h1>\(body)</main></body></html>"
        let response = Response(status: status, body: .init(string: html))
        response.headers.contentType = .html
        response.headers.replaceOrAdd(name: "Content-Security-Policy", value: pageCSP)
        response.headers.replaceOrAdd(name: .cacheControl, value: "no-store")
        return response
    }

    /// RFC 6749 §4.1.2 / RFC 9207: back to the **registered** redirect URI, always with `iss`, and `state` when the RP sent one.
    static func redirect(_ redirectURI: String, _ items: [(String, String)], state: String?, issuer: String) -> Response {
        var all = items
        if let state { all.append(("state", state)) }
        all.append(("iss", issuer))
        let separator = redirectURI.contains("?") ? "&" : "?"
        let response = Response(status: .seeOther)
        response.headers.replaceOrAdd(name: .location, value: redirectURI + separator + AuthorityClient.query(all))
        response.headers.replaceOrAdd(name: .cacheControl, value: "no-store")
        response.headers.replaceOrAdd(name: "Referrer-Policy", value: "no-referrer")
        return response
    }

    static func errorPage(_ status: HTTPResponseStatus = .badRequest) -> Response {
        page("Sign-in request not valid", "<p>This sign-in link isn't valid. Go back to the website and try again.</p>", status: status)
    }

    static func tooMany() -> Response {
        page("Too many sign-in attempts", "<p>Too many sign-in attempts. Wait a minute and try again.</p>", status: .tooManyRequests)
    }

    // MARK: /oidc/authorize

    static func authorize(_ req: Request) async throws -> Response {
        let client = try OIDCGate.require(req)
        let issuer = req.ctx.config.oidc.issuer
        guard let q = query(req), let clientId = q["client_id"], let redirectURI = q["redirect_uri"] else { return errorPage() }
        // An unknown client or redirect URI never redirects (RFC 6749 §4.1.2.1). A database lookup at the authority: no challenge, no Key Vault call.
        let check: AuthorityClientCheckResponse
        do { check = try await client.checkRedirect(clientId: clientId, redirectURI: redirectURI) } catch { return page("Sign-in unavailable", "<p>Sign-in with Viadere is unavailable right now. Try again later.</p>", status: .serviceUnavailable) }
        guard check.valid, let clientName = check.displayName else { return errorPage() }
        let state = q["state"]
        func fail(_ error: String) -> Response { redirect(redirectURI, [("error", error)], state: state, issuer: issuer) }
        let known: Set<String> = ["response_type", "client_id", "redirect_uri", "scope", "state", "nonce", "code_challenge", "code_challenge_method", "response_mode",
                                  "prompt", "max_age", "acr_values", "login_hint", "ui_locales", "request", "request_uri", "claims", "display", "id_token_hint"]
        if q["request"] != nil { return fail("request_not_supported") }
        if q["request_uri"] != nil { return fail("request_uri_not_supported") }
        guard q["response_type"] == "code" else { return fail("unsupported_response_type") }
        guard Set(q.keys).isSubset(of: known), q["claims"] == nil else { return fail("invalid_request") }
        if let mode = q["response_mode"], mode != "query" { return fail("invalid_request") }
        guard let scope = q["scope"], Set(scope.split(separator: " ").map(String.init)) == ["openid"] else { return fail("invalid_scope") }
        guard q["code_challenge_method"] == "S256", let challenge = q["code_challenge"], OIDCProfile.isValidCodeChallenge(challenge) else { return fail("invalid_request") }
        guard let nonce = q["nonce"], (1...255).contains(nonce.utf8.count), nonce.unicodeScalars.allSatisfy({ $0.isASCII && $0.value >= 0x21 && $0.value < 0x7F }) else {
            return fail("invalid_request")
        }
        if let state, state.utf8.count > 512 { return fail("invalid_request") }
        var acr: [String] = []
        if let raw = q["acr_values"] {
            acr = raw.split(separator: " ").map(String.init)
            guard acr.allSatisfy({ [OIDCProfile.acrApp, OIDCProfile.acrPasskey].contains($0) }) else { return fail("invalid_request") }
        }
        // No SSO session exists at this OP: `prompt=none` can never be satisfied.
        if let prompt = q["prompt"], prompt.split(separator: " ").contains("none") { return fail("login_required") }

        let now = req.ctx.now
        try await OIDCAuthorizationRecord.query(on: req.db).filter(\.$expiresAt < now).delete()
        let binding = SecureToken.generate(byteCount: 32), csrf = SecureToken.generate(byteCount: 32)
        let row = OIDCAuthorizationRecord()
        row.bindingHash = SecureToken.sha256Hex(Data(binding.utf8))
        row.csrfHash = SecureToken.sha256Hex(Data(csrf.utf8))
        row.clientId = clientId
        row.clientName = clientName
        row.redirectURI = redirectURI
        row.state = state
        row.nonce = nonce
        row.codeChallenge = challenge
        row.acrValues = acr.isEmpty ? nil : acr.joined(separator: " ")
        row.status = "pending"
        row.createdAt = now
        row.expiresAt = now.addingTimeInterval(req.ctx.config.oidc.authorizationLifetime)
        try await row.create(on: req.db)
        let host = OIDCProfile.host(of: redirectURI) ?? ""
        let response = page("Sign in to \(clientName)",
            "<p>\(escape(clientName)) wants to confirm it's you. It gets an ID that only \(escape(clientName)) can use. It doesn't get your name, email or phone number, and other apps can't match it.</p>"
            + "<p>Website: \(escape(host))</p>"
            + "<form method=\"post\" action=\"/oidc/authorize/app\"><input type=\"hidden\" name=\"id\" value=\"\(row.id!.uuidString.lowercased())\">"
            + "<input type=\"hidden\" name=\"csrf\" value=\"\(csrf)\"><button type=\"submit\">Continue with the Viadere app</button></form>")
        response.headers.add(name: .setCookie, value: "\(cookieName)=\(binding); Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=600")
        return response
    }

    /// The browser that started the authorization (cookie binding, constant time).
    static func boundRow(_ req: Request, id raw: String?) async throws -> OIDCAuthorizationRecord? {
        guard let raw, let id = UUID(uuidString: raw), let cookie = req.cookies[cookieName]?.string,
              let row = try await OIDCAuthorizationRecord.find(id, on: req.db),
              ConstantTime.equals(SecureToken.sha256Hex(Data(cookie.utf8)), row.bindingHash) else { return nil }
        return row
    }

    // MARK: POST /oidc/authorize/app (the person chose a method: only now is an authority challenge created, S2-A2-6)

    static func chooseApp(_ req: Request) async throws -> Response {
        let client = try OIDCGate.require(req)
        let ctx = req.ctx
        guard let form = form(req), let row = try await boundRow(req, id: form["id"]), let csrf = form["csrf"],
              ConstantTime.equals(SecureToken.sha256Hex(Data(csrf.utf8)), row.csrfHash) else { return errorPage(.forbidden) }
        guard row.expiresAt > ctx.now else { return errorPage() }
        guard row.status == "pending" else { return statusRedirect(row) }
        // Fail-closed edge limits (namespaces on the DatabaseRateLimitStore fail-closed list).
        let ip = ClientIP.rawAddress(req, trustedProxies: ctx.config.trustedProxyCount)
        guard await ctx.limiter.allow("oidc-authorize-ip", key: ip, rule: ctx.config.oidc.ipMinuteRate),
              await ctx.limiter.allow("oidc-authorize-ip-hour", key: ip, rule: ctx.config.oidc.ipHourRate),
              await ctx.limiter.allow("oidc-authorize-client", key: row.clientId, rule: ctx.config.oidc.clientRate) else { return tooMany() }
        let request = AuthorityChallengeCreateRequest(purpose: .oidcLogin, oidc: .init(clientId: row.clientId, redirectURI: row.redirectURI, codeChallenge: row.codeChallenge,
                                                                                         codeChallengeMethod: "S256", nonce: row.nonce,
                                                                                         acrValues: row.acrValues.map { $0.split(separator: " ").map(String.init) }))
        let created: (status: Int, response: AuthorityChallengeCreateResponse?)
        do { created = try await client.createChallenge(request) } catch {
            return page("Sign-in unavailable", "<p>Sign-in with Viadere is unavailable right now. Try again later.</p>", status: .serviceUnavailable)
        }
        guard let challenge = created.response else {
            if created.status == 429 { return tooMany() }
            try await row.delete(on: req.db)
            return redirect(row.redirectURI, [("error", "access_denied")], state: row.state, issuer: ctx.config.oidc.issuer)
        }
        try await OIDCAuthorizationRecord.query(on: req.db).filter(\.$id == row.id!).filter(\.$status == "pending")
            .set(\.$status, to: "challenged").set(\.$challengeId, to: challenge.challengeId).set(\.$statement, to: challenge.statement)
            .set(\.$matchCode, to: challenge.matchCode).update()
        return statusRedirect(row)
    }

    static func statusRedirect(_ row: OIDCAuthorizationRecord) -> Response {
        let response = Response(status: .seeOther)
        response.headers.replaceOrAdd(name: .location, value: "/oidc/authorize/status?id=" + row.id!.uuidString.lowercased())
        return response
    }

    // MARK: GET /oidc/authorize/status

    static func status(_ req: Request) async throws -> Response {
        _ = try OIDCGate.require(req)
        let issuer = req.ctx.config.oidc.issuer
        guard let q = query(req), let row = try await boundRow(req, id: q["id"]) else { return errorPage(.forbidden) }
        if row.expiresAt <= req.ctx.now {
            try await row.delete(on: req.db)
            return redirect(row.redirectURI, [("error", "access_denied")], state: row.state, issuer: issuer)
        }
        switch row.status {
        case "approved":
            // The code goes to the browser that started the request, once; the row is gone afterwards.
            guard let code = row.code else { return errorPage() }
            try await row.delete(on: req.db)
            return redirect(row.redirectURI, [("code", code)], state: row.state, issuer: issuer)
        case "denied":
            try await row.delete(on: req.db)
            return redirect(row.redirectURI, [("error", "access_denied")], state: row.state, issuer: issuer)
        case "challenged":
            let number = row.matchCode.map { "<p>Number to enter on your phone: <strong>\(escape($0))</strong></p>" } ?? ""
            return page("Sign in to \(row.clientName)", "<p>Open the Viadere app on your phone and approve the sign-in to \(escape(row.clientName)).</p>" + number
                        + "<p>Sign-in code for the app: \(escape(row.challengeId ?? ""))</p>", refresh: true)
        default:
            return errorPage()
        }
    }

    // MARK: POST /oidc/token (forwarded unchanged to the authority, which authenticates the client and signs)

    static func token(_ req: Request) async throws -> Response {
        let client = try OIDCGate.require(req)
        let body = req.body.data.map { Data(buffer: $0) } ?? Data()
        let result: (status: Int, body: Data)
        do { result = try await client.token(form: body) } catch { result = (503, Data(#"{"error":"temporarily_unavailable"}"#.utf8)) }
        let response = Response(status: HTTPResponseStatus(statusCode: result.status), body: .init(data: result.body))
        response.headers.contentType = .json
        response.headers.replaceOrAdd(name: .cacheControl, value: "no-store")
        response.headers.replaceOrAdd(name: .pragma, value: "no-cache")
        return response
    }

    // MARK: /oidc/userinfo (verify with the authority's public keys; the api never signs)

    static func userinfo(_ req: Request) async throws -> Response {
        let client = try OIDCGate.require(req)
        func unauthorized() -> Response {
            let response = Response(status: .unauthorized)
            response.headers.replaceOrAdd(name: .wwwAuthenticate, value: "Bearer error=\"invalid_token\"")
            response.headers.replaceOrAdd(name: .cacheControl, value: "no-store")
            return response
        }
        guard let token = req.headers.bearerAuthorization?.token else { return unauthorized() }
        let issuer = req.ctx.config.oidc.issuer
        guard let claims = try? await req.application.oidcVerificationKeys.verify(token, typ: "at+jwt", client: client, now: req.ctx.now),
              claims["iss"]?.stringValue == issuer, claims["aud"]?.stringValue == issuer + "/oidc/userinfo",
              let exp = claims["exp"]?.authorityInteger, Int64(req.ctx.now.timeIntervalSince1970) <= exp + 60,
              claims["scope"]?.stringValue == "openid", let sub = claims["sub"]?.stringValue else { return unauthorized() }
        let response = Response(status: .ok, body: .init(data: try CanonicalJSON.serialize(.object(["sub": .string(sub)]))))
        response.headers.contentType = .json
        response.headers.replaceOrAdd(name: .cacheControl, value: "no-store")
        return response
    }

    // MARK: /oidc/logout (RP-Initiated Logout 1.0; no OP session exists, so logout only redirects)

    static func logout(_ req: Request) async throws -> Response {
        let client = try OIDCGate.require(req)
        let signedOut = page("Signed out", "<p>You're signed out. You can close this page.</p>")
        guard let q = query(req), let target = q["post_logout_redirect_uri"] else { return signedOut }
        // A redirect needs a verified id_token_hint (expiry is not required for logout) naming the client, and an exactly registered URI.
        guard let hint = q["id_token_hint"],
              let claims = try? await req.application.oidcVerificationKeys.verify(hint, typ: "JWT", client: client, now: req.ctx.now),
              claims["iss"]?.stringValue == req.ctx.config.oidc.issuer, let clientId = claims["aud"]?.stringValue,
              q["client_id"] == nil || q["client_id"] == clientId,
              let check = try? await client.checkLogout(clientId: clientId, postLogoutRedirectURI: target), check.valid else { return signedOut }
        var items: [(String, String)] = []
        if let state = q["state"] { items.append(("state", state)) }
        let response = Response(status: .seeOther)
        response.headers.replaceOrAdd(name: .location, value: target + (items.isEmpty ? "" : (target.contains("?") ? "&" : "?") + AuthorityClient.query(items)))
        return response
    }
}

/// The authority's OIDC public keys as the api uses them (verify only): fetched over the internal interface, refetched on an unknown `kid` at most once per
/// 5 minutes. Each key's `kid` must equal its recomputed RFC 7638 thumbprint.
actor OIDCVerificationKeys {
    private var keys: [String: [String: JSONValue]] = [:]
    private var fetchedAt: Date?

    func verify(_ compact: String, typ: String, client: AuthorityClient, now: Date) async throws -> [String: JSONValue] {
        let parts = try AuthorityJWS.parse(compact, expectedType: typ, allowedAlgorithms: ["ES256", "RS256"])
        var jwk = keys[parts.kid]
        if jwk == nil, fetchedAt.map({ now.timeIntervalSince($0) >= 300 }) ?? true {
            var fresh: [String: [String: JSONValue]] = [:]
            for key in try await client.oidcKeys().keys {
                guard let object = key.objectValue, let kid = object["kid"]?.stringValue else { continue }
                fresh[kid] = object
            }
            keys = fresh
            fetchedAt = now
            jwk = fresh[parts.kid]
        }
        guard let jwk else { throw AuthorityJOSEError.unknownKey }
        switch (jwk["kty"]?.stringValue, parts.alg) {
        case ("EC", "ES256"):
            guard let x = jwk["x"]?.stringValue.flatMap(Base64URL.decode), let y = jwk["y"]?.stringValue.flatMap(Base64URL.decode),
                  let key = try? P256.Signing.PublicKey(rawRepresentation: x + y), JWKThumbprint.p256(key) == parts.kid else { throw AuthorityJOSEError.unknownKey }
            try AuthorityJWS.verifyES256(parts, key: key)
        case ("RSA", "RS256"):
            guard let n = jwk["n"]?.stringValue.flatMap(Base64URL.decode), let e = jwk["e"]?.stringValue.flatMap(Base64URL.decode),
                  JWKThumbprint.rsa(modulus: n, exponent: e) == parts.kid, let key = try? _RSA.Signing.PublicKey(n: n, e: e),
                  key.isValidSignature(_RSA.Signing.RSASignature(rawRepresentation: parts.signature), for: parts.signingInput, padding: .insecurePKCS1v1_5) else {
                throw AuthorityJOSEError.badSignature
            }
        default:
            throw AuthorityJOSEError.unsupportedAlgorithm
        }
        return parts.payload
    }
}
