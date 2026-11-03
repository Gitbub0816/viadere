@preconcurrency import Crypto
import Fluent
import Foundation
import SQLKit
import Vapor
import ViadereCore

/// The staging OP's method choice (ADR-0024 §4) and consent list (§8), api side. **Relay only**: the passkey challenge, its verification, the code and
/// the consent records are the authority's; the api checks this browser's binding and CSRF token, applies the edge limits, and carries values unchanged.
///
/// Methods in the order offered (passkey bias, owner decision 4): "Use your Viadere passkey" (WebAuthn at `https://id.<domain>`, verified by the
/// authority, ADR-0023 §3a), then "Use the Viadere app instead" (QR universal link `https://{link domain}/o/{ach}`, or a push when `login_hint` names
/// an account the authority verified).
enum OIDCMethodsFrontEnd {
    static func register(_ app: Application) {
        app.post("oidc", "authorize", "passkey", "begin") { req in try await passkeyBegin(req) }
        app.post("oidc", "authorize", "passkey", "finish") { req in try await passkeyFinish(req) }
        app.post("oidc", "authorize", "cancel") { req in try await cancel(req) }

        app.api(APIRoutes.oidcConsentsList) { req in
            let client = try OIDCGate.require(req)
            let principal = try req.consumer
            guard principal.deviceId != nil else { throw APIError.notFound }
            try await req.ctx.limiter.enforce("oidc-consents", key: principal.consumerId.description, rule: .perMinute(30, burst: 10))
            let consents: [AuthorityConsent]
            do { consents = try await client.consents(accountId: principal.consumerId.uuid) } catch { throw unavailable }
            return try req.jsonResponse(OIDCConsentListResponse(consents: consents.map {
                OIDCConsentView(clientId: $0.clientId, clientName: $0.clientName, host: $0.host, grantedAt: Date(timeIntervalSince1970: TimeInterval($0.grantedAt)),
                                lastUsedAt: Date(timeIntervalSince1970: TimeInterval($0.lastUsedAt)))
            }))
        }
        app.api(APIRoutes.oidcConsentRevoke) { req in
            let client = try OIDCGate.require(req)
            let principal = try req.consumer
            guard principal.deviceId != nil, let clientId = req.parameters.get("clientId"), OIDCClientID.isValid(clientId) else { throw APIError.notFound }
            try await req.ctx.limiter.enforce("oidc-consents", key: principal.consumerId.description, rule: .perMinute(30, burst: 10))
            // Reduce-only and scoped to the signed-in account: the authority deletes only this account's consent for this client.
            let revoked: Bool
            do { revoked = try await client.revokeConsent(accountId: principal.consumerId.uuid, clientId: clientId) } catch { throw unavailable }
            return try req.jsonResponse(OIDCConsentRevokeResponse(revoked: revoked))
        }
    }

    static var unavailable: APIError { APIError(.serviceUnavailable, .unavailable, "Sign-in with Viadere is unavailable right now.") }

    // MARK: Page content (UX_COPY OIDC-01 to OIDC-07)

    /// OIDC-01.
    static func heading(_ client: String) -> String { "Sign in to \(client) with Viadere" }

    /// OIDC-05 with the redirect host, the passkey first (OIDC-02), the app second (OIDC-03), and Cancel (OIDC-06).
    static func methodsBody(row: OIDCAuthorizationRecord, csrf: String, offerApp: Bool) -> String {
        let e = OIDCFrontEnd.escape
        let client = e(row.clientName), host = e(OIDCProfile.host(of: row.redirectURI) ?? "")
        let id = row.id!.uuidString.lowercased()
        var html = "<p>\(client) wants to confirm it's you. It gets an ID that only \(client) can use. It doesn't get your name, email or phone number, "
            + "and other apps can't match it. You'll return to <strong>\(host)</strong>.</p>"
        html += "<button type=\"button\" class=\"primary\" data-oidc-passkey data-id=\"\(id)\" data-csrf=\"\(csrf)\">Use your Viadere passkey</button>"
        html += "<p id=\"pk-msg\" class=\"notice\" role=\"status\" aria-live=\"polite\"></p>"
        html += "<noscript><p class=\"notice\">Your browser needs JavaScript for passkeys. You can use the Viadere app instead.</p></noscript>"
        if offerApp {
            html += "<form method=\"post\" action=\"/oidc/authorize/app\"><input type=\"hidden\" name=\"id\" value=\"\(id)\">"
                + "<input type=\"hidden\" name=\"csrf\" value=\"\(csrf)\"><button type=\"submit\" class=\"secondary\">Use the Viadere app instead</button></form>"
        }
        html += "<form method=\"post\" action=\"/oidc/authorize/cancel\"><input type=\"hidden\" name=\"id\" value=\"\(id)\">"
            + "<input type=\"hidden\" name=\"csrf\" value=\"\(csrf)\"><button type=\"submit\" class=\"quiet\">Cancel</button></form>"
        return html
    }

    /// The app path while the challenge is open: the number (never on the phone), the QR universal link with OIDC-04, and the redirect host.
    static func appWaitingBody(row: OIDCAuthorizationRecord, linkDomain: LinkDomain) -> String {
        let e = OIDCFrontEnd.escape
        var html = "<p>Open the Viadere app on your phone and approve the sign-in to \(e(row.clientName)).</p>"
        if let number = row.matchCode { html += "<p>Number to enter on your phone: <strong class=\"number\">\(e(number))</strong></p>" }
        if let ach = row.challengeId, AuthorityChallengeID.isValid(ach) {
            let link = OIDCChallengeLink.build(challengeId: ach, domain: linkDomain)
            if let svg = (try? QRCode.encode(link, errorCorrection: .medium))?.svg(title: "QR code to open this sign-in in the Viadere app") {
                html += "<div class=\"qr\">\(svg)</div>"
            }
            html += "<p class=\"notice\">Scan with the Viadere app. Only scan a code on this page. Don't scan one that someone sent or showed you.</p>"
        }
        return html
    }

    // MARK: login_hint push (ADR-0024 §4 method 2)

    /// The api's own relationship for this `subject_ref` (active only). The authority then checks the hint against the client's business; the api's
    /// answer is never trusted on its own.
    static func resolveHint(_ hint: String?, db: any Database) async throws -> UUID? {
        guard let hint, SubjectRef(hint) != nil else { return nil }
        return try await RelationshipRecord.query(on: db).filter(\.$subjectRef == hint).filter(\.$status == "active").first()?.consumerId
    }

    /// A generic push to the account's devices (`viadere.oidc`, `ach` only), counted per (client, account) and fail closed (`oidc-` namespace,
    /// ADR-0022 §5 fatigue rules): over the limit nothing is sent and the QR keeps working.
    static func pushHinted(_ req: Request, consumerId: UUID, clientId: String, challengeId: String) async {
        let ctx = req.ctx
        guard AuthorityChallengeID.isValid(challengeId) else { return }
        guard await ctx.limiter.allow("oidc-hint-push", key: "\(clientId)|\(consumerId.uuidString.lowercased())", rule: ctx.config.oidc.hintPushRate) else {
            ctx.logger.warning("oidc login_hint push limited", metadata: ["client": "\(clientId)"])
            return
        }
        do {
            let devices = try await DeviceRecord.query(on: req.db).filter(\.$consumerId == consumerId).filter(\.$revokedAt == nil).all().compactMap(\.id)
            guard !devices.isEmpty else { return }
            let tokens = try await APNsTokenRecord.query(on: req.db).filter(\.$consumerId == consumerId).filter(\.$deviceId ~~ devices)
                .filter(\.$invalidatedAt == nil).all()
            for token in tokens {
                let message = PushMessage(deviceToken: token.record.token, environment: token.record.environment,
                                          topic: token.record.bundleId.isEmpty ? ctx.config.appBundleID : token.record.bundleId,
                                          title: PushPayloadBuilder.genericTitle, body: "Action needed. Open to review a sign-in request.",
                                          category: OIDCPushPayloadPolicy.category, threadID: "viadere.oidc", interruptionLevel: OIDCPushPayloadPolicy.interruptionLevel,
                                          mutableContent: true, interactionId: nil, highPriority: true, collapseID: challengeId, oidcChallengeId: challengeId)
                if await ctx.apns.send(message) == .tokenInvalid {
                    try await APNsTokenRecord.query(on: req.db).filter(\.$id == token.id!).set(\.$invalidatedAt, to: ctx.now).update()
                }
            }
        } catch {
            // Best effort: the QR on the page still works.
        }
    }

    // MARK: Passkey (ADR-0024 §4 method 1)

    static func jsonError(_ status: HTTPResponseStatus, _ message: String) -> Response {
        let response = Response(status: status, body: .init(data: (try? ViadereJSON.encode(["error": ["message": message]])) ?? Data()))
        response.headers.contentType = .json
        response.headers.replaceOrAdd(name: .cacheControl, value: "no-store")
        return response
    }

    static func json<T: Encodable>(_ value: T) throws -> Response {
        let response = Response(status: .ok, body: .init(data: try ViadereJSON.encode(value)))
        response.headers.contentType = .json
        response.headers.replaceOrAdd(name: .cacheControl, value: "no-store")
        return response
    }

    /// A call from this page (form-encoded, like every `/oidc/` body): same origin when the browser names one, this browser's cookie, the CSRF token.
    static func bound(_ req: Request) async throws -> ([String: String], OIDCAuthorizationRecord)? {
        if let origin = req.headers.first(name: .origin), origin != req.ctx.config.oidc.issuer { return nil }
        guard let form = OIDCFrontEnd.form(req), let row = try await OIDCFrontEnd.boundRow(req, id: form["id"]), let csrf = form["csrf"],
              ConstantTime.equals(SecureToken.sha256Hex(Data(csrf.utf8)), row.csrfHash) else { return nil }
        return (form, row)
    }

    /// The assertion members as the page posts them (`credential.<member>`), relayed unchanged.
    static func credential(_ form: [String: String]) -> PasskeyAssertionCredential? {
        guard let id = form["credential.id"], let rawId = form["credential.rawId"], let authenticatorData = form["credential.authenticatorData"],
              let clientDataJSON = form["credential.clientDataJSON"], let signature = form["credential.signature"] else { return nil }
        let handle = form["credential.userHandle"].flatMap { $0.isEmpty ? nil : $0 }
        return PasskeyAssertionCredential(id: id, rawId: rawId, authenticatorData: authenticatorData, clientDataJSON: clientDataJSON, signature: signature, userHandle: handle)
    }

    /// The person chose the passkey: only now is an authority (passkey) challenge created, behind the same fail-closed edge limits as the app path.
    static func passkeyBegin(_ req: Request) async throws -> Response {
        let client = try OIDCGate.require(req)
        let ctx = req.ctx
        guard let (_, row) = try await bound(req) else { return jsonError(.forbidden, "This sign-in request isn't valid.") }
        guard row.expiresAt > ctx.now, row.status == "pending" || row.status == "passkey" else { return jsonError(.gone, "This sign-in request expired. Go back to the website and try again.") }
        let ip = ClientIP.rawAddress(req, trustedProxies: ctx.config.trustedProxyCount)
        guard await ctx.limiter.allow("oidc-authorize-ip", key: ip, rule: ctx.config.oidc.ipMinuteRate),
              await ctx.limiter.allow("oidc-authorize-ip-hour", key: ip, rule: ctx.config.oidc.ipHourRate),
              await ctx.limiter.allow("oidc-authorize-client", key: row.clientId, rule: ctx.config.oidc.clientRate) else {
            return jsonError(.tooManyRequests, OIDCFrontEnd.tooManyText)
        }
        let request = AuthorityPasskeyChallengeRequest(oidc: .init(clientId: row.clientId, redirectURI: row.redirectURI, codeChallenge: row.codeChallenge,
                                                                   codeChallengeMethod: "S256", nonce: row.nonce,
                                                                   acrValues: row.acrValues.map { $0.split(separator: " ").map(String.init) }))
        let created: (status: Int, response: AuthorityPasskeyChallengeResponse?)
        do { created = try await client.createPasskeyChallenge(request) } catch { return jsonError(.serviceUnavailable, "Sign-in with Viadere is unavailable right now. Try again later.") }
        guard let challenge = created.response else {
            if created.status == 429 { return jsonError(.tooManyRequests, OIDCFrontEnd.tooManyText) }
            return jsonError(.forbidden, "This sign-in request isn't valid.")
        }
        try await OIDCAuthorizationRecord.query(on: req.db).filter(\.$id == row.id!).filter(\.$status ~~ ["pending", "passkey"])
            .set(\.$status, to: "passkey").set(\.$challengeId, to: challenge.challengeId).set(\.$statement, to: nil).set(\.$matchCode, to: nil).update()
        struct Options: Encodable { let challenge: String; let rp_id: String; let timeout_ms: Int }
        return try json(Options(challenge: challenge.challenge, rp_id: challenge.relyingPartyId, timeout_ms: challenge.timeoutMilliseconds))
    }

    /// The browser's assertion, relayed unchanged; the authority verifies it and issues the code, which this browser receives through the status page.
    static func passkeyFinish(_ req: Request) async throws -> Response {
        let client = try OIDCGate.require(req)
        let ctx = req.ctx
        guard let (form, row) = try await bound(req), let credential = credential(form) else { return jsonError(.forbidden, "This sign-in request isn't valid.") }
        guard row.expiresAt > ctx.now, row.status == "passkey", let ach = row.challengeId else { return jsonError(.gone, "This sign-in request expired. Go back to the website and try again.") }
        guard await ctx.limiter.allow("oidc-passkey-finish", key: row.id!.uuidString, rule: .perMinute(10, burst: 5)) else { return jsonError(.tooManyRequests, OIDCFrontEnd.tooManyText) }
        let answer: AuthorityEvidenceResponse?
        do { answer = try await client.submitPasskeyEvidence(AuthorityPasskeyEvidenceRequest(challengeId: ach, credential: credential)) } catch {
            return jsonError(.serviceUnavailable, "Sign-in with Viadere is unavailable right now. Try again later.")
        }
        guard let answer, answer.challengeId == ach, answer.decision == .approve, let code = answer.code else {
            return jsonError(.forbidden, "That passkey couldn't be used to sign in. Try again, or use the Viadere app instead.")
        }
        try await OIDCAuthorizationRecord.query(on: req.db).filter(\.$id == row.id!).filter(\.$status == "passkey").set(\.$status, to: "approved").set(\.$code, to: code).update()
        struct Next: Encodable { let redirect: String }
        return try json(Next(redirect: "/oidc/authorize/status?id=" + row.id!.uuidString.lowercased()))
    }

    /// OIDC-06 Cancel: back to the RP with `access_denied` (this browser's binding and CSRF token required).
    static func cancel(_ req: Request) async throws -> Response {
        _ = try OIDCGate.require(req)
        guard let form = OIDCFrontEnd.form(req), let row = try await OIDCFrontEnd.boundRow(req, id: form["id"]), let csrf = form["csrf"],
              ConstantTime.equals(SecureToken.sha256Hex(Data(csrf.utf8)), row.csrfHash) else { return OIDCFrontEnd.errorPage(.forbidden) }
        try await row.delete(on: req.db)
        return OIDCFrontEnd.redirect(row.redirectURI, [("error", "access_denied")], state: row.state, issuer: req.ctx.config.oidc.issuer)
    }
}

// MARK: Authority calls

extension AuthorityClient {
    private func decode<T: Decodable>(_ type: T.Type, _ result: (status: Int, body: Data), expect: Int = 200) throws -> T {
        guard result.status == expect else { throw AuthorityClientError.unavailable(status: result.status) }
        do { return try ViadereJSON.decode(T.self, from: result.body) } catch { throw AuthorityClientError.malformed }
    }

    /// `nil` when the authority refused (`4xx`); throws when it is unavailable.
    func createPasskeyChallenge(_ request: AuthorityPasskeyChallengeRequest) async throws -> (status: Int, response: AuthorityPasskeyChallengeResponse?) {
        let result = try await transport.send(method: .POST, path: AuthorityRoute.oidcPasskeyChallenges, contentType: "application/json", body: try ViadereJSON.encode(request))
        if result.status == 201 { return (201, try decode(AuthorityPasskeyChallengeResponse.self, result, expect: 201)) }
        guard (400..<500).contains(result.status) else { throw AuthorityClientError.unavailable(status: result.status) }
        return (result.status, nil)
    }

    func submitPasskeyEvidence(_ request: AuthorityPasskeyEvidenceRequest) async throws -> AuthorityEvidenceResponse? {
        let result = try await transport.send(method: .POST, path: AuthorityRoute.oidcPasskeyEvidence, contentType: "application/json", body: try ViadereJSON.encode(request))
        if result.status == 200 { return try decode(AuthorityEvidenceResponse.self, result) }
        guard (400..<500).contains(result.status) else { throw AuthorityClientError.unavailable(status: result.status) }
        return nil
    }

    func consents(accountId: UUID) async throws -> [AuthorityConsent] {
        let result = try await transport.send(method: .POST, path: AuthorityRoute.oidcConsents, contentType: "application/json",
                                              body: try ViadereJSON.encode(AuthorityConsentListRequest(accountId: accountId)))
        return try decode(AuthorityConsentListResponse.self, result).consents
    }

    func revokeConsent(accountId: UUID, clientId: String) async throws -> Bool {
        let result = try await transport.send(method: .POST, path: AuthorityRoute.oidcConsentRevoke, contentType: "application/json",
                                              body: try ViadereJSON.encode(AuthorityConsentRevokeRequest(accountId: accountId, clientId: clientId)))
        struct Answer: Decodable { let revoked: Bool }
        return try decode(Answer.self, result).revoked
    }
}

// MARK: Page assets

/// One stylesheet and one small passkey script, both pinned by SHA-256 in the CSP (no other script, no third-party asset). Brand colours from
/// `Design/brand-guide.html`: charcoal, ivory, champagne; no shield imagery.
enum OIDCPageAssets {
    static let css = """
    :root{color-scheme:light dark;--bg:#f6f2ea;--fg:#26241f;--muted:#5d584f;--accent:#b79c6a;--card:#fffdf8}
    @media(prefers-color-scheme:dark){:root{--bg:#1d1c1a;--fg:#f1ece1;--muted:#c9c1b2;--card:#272522}}
    body{margin:0;background:var(--bg);color:var(--fg);font:17px/1.5 -apple-system,system-ui,sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center}
    main{max-width:28rem;width:100%;margin:1rem;padding:2rem;box-sizing:border-box;background:var(--card);border-radius:16px;border:1px solid var(--accent)}
    h1{font-size:1.4rem;margin:.2rem 0 1rem;overflow-wrap:anywhere}p{margin:.6rem 0;overflow-wrap:anywhere}.brand{letter-spacing:.08em;color:var(--muted);font-size:.9rem;margin:0}
    button{display:block;width:100%;min-height:44px;margin-top:.8rem;padding:.7rem 1.2rem;border-radius:999px;font:inherit;cursor:pointer;border:1px solid var(--fg)}
    .primary{background:var(--fg);color:var(--bg)}.secondary{background:transparent;color:var(--fg)}.quiet{background:transparent;color:var(--muted);border-color:transparent}
    .notice{color:var(--muted);font-size:.95rem}.number{font:2rem ui-monospace,monospace;letter-spacing:.2em}
    .qr{max-width:14rem;margin:1rem auto}.qr svg{width:100%;height:auto;display:block;border-radius:8px}
    """

    static let script = """
    (function(){'use strict';
    function b2a(s){s=s.replace(/-/g,'+').replace(/_/g,'/');while(s.length%4)s+='=';var b=atob(s),a=new Uint8Array(b.length);for(var i=0;i<b.length;i++)a[i]=b.charCodeAt(i);return a.buffer}
    function a2b(b){var a=new Uint8Array(b),s='';for(var i=0;i<a.length;i++)s+=String.fromCharCode(a[i]);return btoa(s).replace(/\\+/g,'-').replace(/\\//g,'_').replace(/=+$/,'')}
    function post(u,body){return fetch(u,{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:new URLSearchParams(body).toString(),credentials:'same-origin'}).then(function(r){return r.json().catch(function(){return null}).then(function(j){if(!r.ok)throw new Error(j&&j.error&&j.error.message||'Something went wrong.');return j})})}
    function run(b){var id=b.getAttribute('data-id'),csrf=b.getAttribute('data-csrf'),msg=document.getElementById('pk-msg');if(msg)msg.textContent='';b.disabled=true;
    post('/oidc/authorize/passkey/begin',{id:id,csrf:csrf}).then(function(o){return navigator.credentials.get({publicKey:{challenge:b2a(o.challenge),rpId:o.rp_id,userVerification:'required',timeout:o.timeout_ms}}).then(function(c){var r=c.response;return post('/oidc/authorize/passkey/finish',{id:id,csrf:csrf,'credential.id':c.id,'credential.rawId':a2b(c.rawId),'credential.authenticatorData':a2b(r.authenticatorData),'credential.clientDataJSON':a2b(r.clientDataJSON),'credential.signature':a2b(r.signature),'credential.userHandle':r.userHandle?a2b(r.userHandle):''})})}).then(function(r){var p=r&&r.redirect;if(typeof p==='string'&&p.indexOf('/oidc/authorize/status?id=')===0)location.assign(p)}).catch(function(e){b.disabled=false;if(msg)msg.textContent=e&&e.name==='NotAllowedError'?'The passkey prompt was closed. You can try again.':(e&&e.message)||'Something went wrong.'})}
    document.addEventListener('click',function(e){var b=e.target&&e.target.closest&&e.target.closest('button[data-oidc-passkey]');if(b){e.preventDefault();run(b)}});
    })();
    """

    static let styleHash = Data(SHA256.hash(data: Data(css.utf8))).base64EncodedString()
    static let scriptHash = Data(SHA256.hash(data: Data(script.utf8))).base64EncodedString()

    /// No script, no frame, forms and fetches to this origin only. The script is allowed only on the method page, by hash.
    static func csp(script: Bool) -> String {
        var parts = ["default-src 'none'", "style-src 'sha256-\(styleHash)'", "form-action 'self'", "frame-ancestors 'none'", "base-uri 'none'"]
        if script { parts += ["script-src 'sha256-\(scriptHash)'", "connect-src 'self'"] }
        return parts.joined(separator: "; ")
    }
}

/// `OIDC.v2` (additive): the RP's `login_hint` on a browser authorization.
struct CreateOIDCMethodsFrontEndSchema: AsyncMigration {
    var name: String { "OIDC.v2" }
    func prepare(on db: any Database) async throws {
        try await db.schema(OIDCAuthorizationRecord.schema).field("login_hint", .string).update()
    }
    func revert(on db: any Database) async throws {
        try await db.schema(OIDCAuthorizationRecord.schema).deleteField("login_hint").update()
    }
}
