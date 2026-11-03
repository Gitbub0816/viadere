@preconcurrency import Crypto
import _CryptoExtras
import Fluent
import Foundation
import NIOHTTP1
import SQLKit
import Vapor
import ViadereAuthorityKit
import ViadereCore
import XCTest
import XCTVapor
@testable import ViadereServerKit

/// ADR-0024 §4 method 1 (passkey, verified by the authority), method 2 (QR universal link, `login_hint` push) and §8 (consent list and revoke), through
/// the api front end with the authority in process.
final class OIDCMethodsFrontEndTests: XCTestCase {
    static let issuer = "https://id.viadere.test"
    static let clientId = "ocl_frontend"
    static let redirect = "https://rp.example.com/callback"
    static let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    static let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
    static let now = Date(timeIntervalSince1970: 1_800_000_000)
    static let formType = "application/x-www-form-urlencoded"

    struct Authority {
        let app: Application
        let statementKey: P256.Signing.PublicKey
        let clientKey: P256.Signing.PrivateKey
        let deviceKeys: [UUID: SoftwareP256SigningKey]
        let passkey: PasskeyCredential
    }

    /// An authority sharing the api's `SUBJECT_REF_KEY` (both hold a copy), one client registered with `business`, each account's approval key
    /// imported, and a passkey for the first account.
    func makeAuthority(accounts: [UUID], business: UUID?, subjectRefKey: SymmetricKey) async throws -> Authority {
        let kms = LocalKMS()
        try kms.createRSASigningKey("oidc-signing-rs256", key: try _RSA.Signing.PrivateKey(keySize: .bits2048))
        for name in ["oidc-signing-es256", "grant-signing", "device-statement-signing"] { kms.createSigningKey(name) }
        let statementKey = try await kms.publicKey(keyRef: "device-statement-signing")
        var config = AuthorityConfig.testing()
        config.issuer = Self.issuer
        config.subjectRefKey = subjectRefKey
        config.developmentStatementPins = [JWKThumbprint.p256(statementKey)]
        let clientKey = P256.Signing.PrivateKey()
        var pins: [JSONValue] = []
        for name in ["oidc-signing-es256", "grant-signing", "device-statement-signing"] {
            let version = String(try await kms.resolveVersion(keyRef: name).split(separator: "/")[1])
            pins.append(.object(["name": .string(name), "version": .string(version), "thumbprint": .string(JWKThumbprint.p256(try await kms.publicKey(keyRef: name)))]))
        }
        let rsa = try await kms.rsaPublicKey(keyRef: "oidc-signing-rs256").getKeyPrimitives()
        pins.append(.object(["name": .string("oidc-signing-rs256"), "version": .string(String(try await kms.resolveVersion(keyRef: "oidc-signing-rs256").split(separator: "/")[1])),
                             "thumbprint": .string(JWKThumbprint.rsa(modulus: rsa.modulus, exponent: rsa.publicExponent))]))
        var jwk = JWKThumbprint.p256JWK(clientKey.publicKey)
        jwk["kid"] = .string("k1")
        var client: [String: JSONValue] = ["client_id": .string(Self.clientId), "tenant_id": .string("tnt"), "display_name": .string("Example Shop"),
                                           "redirect_uris": .array([.string(Self.redirect)]), "jwks": .object(["keys": .array([.object(jwk)])])]
        if let business { client["business_id"] = .string(business.uuidString) }
        let passkey = try WebAuthnAuthenticator.makeCredential(rpId: "viadere.test", userHandle: Data([1, 2, 3]), userName: "a", clientDataHash: Data(repeating: 0, count: 32),
                                                               requireUserVerification: true, userVerified: true, backedUp: true, now: Self.now).credential
        var deviceKeys: [UUID: SoftwareP256SigningKey] = [:]
        var importAccounts: [JSONValue] = []
        for (index, account) in accounts.enumerated() {
            let key = SoftwareP256SigningKey()
            deviceKeys[account] = key
            var entry: [String: JSONValue] = ["account_id": .string(account.uuidString),
                                              "keys": .array([.object(["public_key": .string(key.publicKey.base64URL), "key_purpose": .string("approvalBiometric")])])]
            if index == 0 {
                entry["passkeys"] = .array([.object(["credential_id": .string(Base64URL.encode(passkey.credentialId)), "public_key": .string(Base64URL.encode(try passkey.cosePublicKey()))])])
            }
            importAccounts.append(.object(entry))
        }
        let commit = String(repeating: "c", count: 40)
        var overrides = AuthorityOverrides()
        overrides.kms = kms
        overrides.callerVerifier = APICaller()
        overrides.clock = { Self.now }
        let frozen = config, pinList = pins, registration = client, imports = importAccounts
        overrides.prepare = { db in
            for pin in pinList { try await AuthorityAdmin.run(command: "key-version-pin", changeFile: try CanonicalJSON.serialize(pin), commit: commit, db: db, config: frozen) }
            try await AuthorityAdmin.run(command: "client-register", changeFile: try CanonicalJSON.serialize(.object(registration)), commit: commit, db: db, config: frozen)
            try await AuthorityAdmin.run(command: "keylog-import", changeFile: try CanonicalJSON.serialize(.object(["accounts": .array(imports)])), commit: commit, db: db, config: frozen)
        }
        let app = try await Application.make(.testing)
        try await AuthorityApplication.configure(app, config: config, overrides: overrides, migrateInMemory: true)
        return Authority(app: app, statementKey: statementKey, clientKey: clientKey, deviceKeys: deviceKeys, passkey: passkey)
    }

    func authorizeURL(extra: String = "") -> String {
        "/oidc/authorize?response_type=code&client_id=\(Self.clientId)&redirect_uri=https%3A%2F%2Frp.example.com%2Fcallback&scope=openid&state=st-1"
            + "&nonce=n-1&code_challenge=\(Self.challenge)&code_challenge_method=S256" + extra
    }

    struct Page { let cookie: String; let id: String; let csrf: String; let html: String; let csp: String }

    func open(_ h: TestHarness, extra: String = "") async throws -> Page {
        let page = try await h.request(.GET, authorizeURL(extra: extra))
        XCTAssertEqual(page.status, .ok, page.text)
        return Page(cookie: try XCTUnwrap(OIDCFrontEndTests.cookie(page)), id: try XCTUnwrap(OIDCFrontEndTests.hidden("id", in: page.text)),
                    csrf: try XCTUnwrap(OIDCFrontEndTests.hidden("csrf", in: page.text)), html: page.text,
                    csp: page.headers.first(name: "Content-Security-Policy") ?? "")
    }

    /// The page's form body: binding id, CSRF token, and the assertion as `credential.<member>` (as the pinned script posts it).
    func form(_ page: Page, credential: [String: Any]? = nil) throws -> Data {
        var items = [("id", page.id), ("csrf", page.csrf)]
        for (key, value) in (credential ?? [:]).sorted(by: { $0.key < $1.key }) { items.append(("credential." + key, value as? String ?? "")) }
        return Data(AuthorityClient.query(items).utf8)
    }

    /// A WebAuthn assertion as a browser at `origin` would send it.
    func assertion(_ passkey: PasskeyCredential, challenge: String, origin: String = OIDCMethodsFrontEndTests.issuer, userVerified: Bool = true) throws -> [String: Any] {
        let clientData = Data("{\"type\":\"webauthn.get\",\"challenge\":\"\(challenge)\",\"origin\":\"\(origin)\",\"crossOrigin\":false}".utf8)
        let result = try WebAuthnAuthenticator.getAssertion(credential: passkey, rpId: "viadere.test", clientDataHash: Data(SHA256.hash(data: clientData)),
                                                            requireUserVerification: userVerified, userVerified: userVerified, backedUp: true)
        let id = Base64URL.encode(passkey.credentialId)
        return ["id": id, "rawId": id, "authenticatorData": Base64URL.encode(result.authenticatorData), "clientDataJSON": Base64URL.encode(clientData),
                "signature": Base64URL.encode(result.signature), "userHandle": Base64URL.encode(result.userHandle)]
    }

    static func claims(_ jwt: String) throws -> [String: Any] {
        try JSONSerialization.jsonObject(with: Base64URL.decode(String(jwt.split(separator: ".")[1]))!) as! [String: Any]
    }

    func tokenForm(_ code: String, clientKey: P256.Signing.PrivateKey) throws -> String {
        let t = Int64(Self.now.timeIntervalSince1970)
        let header = Base64URL.encode(try CanonicalJSON.serialize(.object(["alg": .string("ES256"), "kid": .string("k1"), "typ": .string("JWT")])))
        let payload = Base64URL.encode(try CanonicalJSON.serialize(.object(["iss": .string(Self.clientId), "sub": .string(Self.clientId), "aud": .string(Self.issuer),
                                                                              "jti": .string(UUID().uuidString), "iat": .integer(t), "exp": .integer(t + 60)])))
        let assertion = header + "." + payload + "." + Base64URL.encode(try clientKey.signature(for: Data((header + "." + payload).utf8)).rawRepresentation)
        return AuthorityClient.query([("grant_type", "authorization_code"), ("code", code), ("redirect_uri", Self.redirect), ("code_verifier", Self.verifier),
                                      ("client_assertion_type", OIDCProfile.clientAssertionType), ("client_assertion", assertion)])
    }

    func passkeyCount(_ db: any Database) async throws -> Int {
        guard let sql = db as? any SQLDatabase else { return -1 }
        struct Row: Decodable { let n: Int }
        return try await sql.raw("SELECT COUNT(*) AS n FROM authority_passkey_challenges").first(decoding: Row.self)?.n ?? -1
    }

    // MARK: Passkey

    func testPasskeyPathEndToEnd() async throws {
        let box = Box<Authority>()
        try await withHarness(overrides: { _ in }, { $0.oidc.enabled = true; $0.oidc.issuer = Self.issuer }) { h in
            let consumer = try await h.readyConsumer()
            let authority = try await self.makeAuthority(accounts: [consumer.id.uuid], business: nil, subjectRefKey: h.ctx.config.subjectRefKey)
            box.value = authority
            h.app.authorityTransport = InProcessAuthorityTransport(app: authority.app)

            // OIDC-01, OIDC-05 with the host, the passkey first (OIDC-02), then the app (OIDC-03), then Cancel. The one script is pinned by hash.
            let page = try await self.open(h)
            XCTAssertTrue(page.html.contains("Sign in to Example Shop with Viadere"))
            XCTAssertTrue(page.html.contains("You'll return to <strong>rp.example.com</strong>"))
            let passkeyAt = try XCTUnwrap(page.html.range(of: "Use your Viadere passkey")), appAt = try XCTUnwrap(page.html.range(of: "Use the Viadere app instead"))
            XCTAssertTrue(passkeyAt.lowerBound < appAt.lowerBound)
            XCTAssertTrue(page.csp.contains("script-src 'sha256-\(OIDCPageAssets.scriptHash)'"), page.csp)
            XCTAssertFalse(page.csp.contains("unsafe-inline"))
            XCTAssertTrue(page.html.contains("<script>\(OIDCPageAssets.script)</script>"))
            let none = try await self.passkeyCount(authority.app.db)
            XCTAssertEqual(none, 0) // ST-OIDC-17: loading the page creates no challenge

            // begin: this browser's cookie, the CSRF token, and (when sent) this origin.
            let begin = try self.form(page)
            aeq(try await h.request(.POST, "/oidc/authorize/passkey/begin", body: begin, contentType: Self.formType).status, .forbidden)
            aeq(try await h.request(.POST, "/oidc/authorize/passkey/begin", headers: ["Cookie": page.cookie],
                                    body: Data("id=\(page.id)&csrf=wrong".utf8), contentType: Self.formType).status, .forbidden)
            aeq(try await h.request(.POST, "/oidc/authorize/passkey/begin", headers: ["Cookie": page.cookie, "Origin": "https://evil.example"],
                                    body: begin, contentType: Self.formType).status, .forbidden)
            let options = try await h.request(.POST, "/oidc/authorize/passkey/begin", headers: ["Cookie": page.cookie, "Origin": Self.issuer],
                                              body: begin, contentType: Self.formType)
            XCTAssertEqual(options.status, .ok, options.text)
            let o = try JSONSerialization.jsonObject(with: options.body) as! [String: Any]
            XCTAssertEqual(o["rp_id"] as? String, "viadere.test")
            let challenge = try XCTUnwrap(o["challenge"] as? String)
            let created = try await self.passkeyCount(authority.app.db)
            XCTAssertEqual(created, 1)
            let appChallenges = try await AuthorityChallengeCount.count(authority.app.db)
            XCTAssertEqual(appChallenges, 0)

            // A refused assertion (another origin) is a generic error; the browser can try again.
            let wrong = try self.form(page, credential: try self.assertion(authority.passkey, challenge: challenge, origin: "https://viadere.test"))
            let refused = try await h.request(.POST, "/oidc/authorize/passkey/finish", headers: ["Cookie": page.cookie], body: wrong, contentType: Self.formType)
            XCTAssertEqual(refused.status, .forbidden)
            XCTAssertFalse(refused.text.contains("origin"))

            let good = try self.form(page, credential: try self.assertion(authority.passkey, challenge: challenge))
            // Not from another browser.
            aeq(try await h.request(.POST, "/oidc/authorize/passkey/finish", body: good, contentType: Self.formType).status, .forbidden)
            let finished = try await h.request(.POST, "/oidc/authorize/passkey/finish", headers: ["Cookie": page.cookie], body: good, contentType: Self.formType)
            XCTAssertEqual(finished.status, .ok, finished.text)
            XCTAssertFalse(finished.text.contains("code="))
            let next = try XCTUnwrap((try JSONSerialization.jsonObject(with: finished.body) as! [String: Any])["redirect"] as? String)
            XCTAssertTrue(next.hasPrefix("/oidc/authorize/status?id="))

            let done = try await h.request(.GET, next, headers: ["Cookie": page.cookie])
            XCTAssertEqual(done.status, .seeOther)
            let location = try XCTUnwrap(done.headers.first(name: .location))
            let items = Dictionary(uniqueKeysWithValues: (URLComponents(string: location)?.queryItems ?? []).map { ($0.name, $0.value ?? "") })
            XCTAssertEqual(items["state"], "st-1")
            XCTAssertEqual(items["iss"], Self.issuer)
            let code = try XCTUnwrap(items["code"])
            let tokens = try await h.request(.POST, "/oidc/token", body: Data(try self.tokenForm(code, clientKey: authority.clientKey).utf8), contentType: Self.formType)
            XCTAssertEqual(tokens.status, .ok, tokens.text)
            let idToken = try XCTUnwrap((try JSONSerialization.jsonObject(with: tokens.body) as! [String: Any])["id_token"] as? String)
            let id = try Self.claims(idToken)
            XCTAssertEqual(id["acr"] as? String, OIDCProfile.acrPasskey)
            XCTAssertEqual(id["amr"] as? [String], ["swk", "user", "mfa"])

            // The consent the authority recorded is in the account's list on the device; revoking it is reduce-only.
            let list = try await h.signed(consumer, .GET, "/v1/oidc/consents")
            XCTAssertEqual(list.status, .ok, list.text)
            let consents = try list.json(OIDCConsentListResponse.self).consents
            XCTAssertEqual(consents.map(\.clientName), ["Example Shop"])
            XCTAssertEqual(consents.first?.host, "rp.example.com")
            let other = try await h.readyConsumer(name: "Other")
            let empty = try await h.signed(other, .GET, "/v1/oidc/consents")
            XCTAssertEqual(try empty.json(OIDCConsentListResponse.self).consents, [])
            let foreign = try await h.signed(other, .POST, "/v1/oidc/consents/\(Self.clientId)/revoke")
            XCTAssertEqual(try foreign.json(OIDCConsentRevokeResponse.self).revoked, false)
            aeq(try await h.signed(consumer, .POST, "/v1/oidc/consents/lcl_notanoidcclient/revoke").status, .notFound)
            let revoke = try await h.signed(consumer, .POST, "/v1/oidc/consents/\(Self.clientId)/revoke")
            XCTAssertEqual(try revoke.json(OIDCConsentRevokeResponse.self).revoked, true)
            let after = try await h.signed(consumer, .GET, "/v1/oidc/consents")
            XCTAssertEqual(try after.json(OIDCConsentListResponse.self).consents, [])
        }
        try await box.value?.app.asyncShutdown()
    }

    func testCancelReturnsAccessDeniedToThisBrowserOnly() async throws {
        let box = Box<Authority>()
        try await withHarness(overrides: { _ in }, { $0.oidc.enabled = true; $0.oidc.issuer = Self.issuer }) { h in
            let authority = try await self.makeAuthority(accounts: [UUID()], business: nil, subjectRefKey: h.ctx.config.subjectRefKey)
            box.value = authority
            h.app.authorityTransport = InProcessAuthorityTransport(app: authority.app)
            let page = try await self.open(h)
            let form = Data("id=\(page.id)&csrf=\(page.csrf)".utf8)
            aeq(try await h.request(.POST, "/oidc/authorize/cancel", body: form, contentType: Self.formType).status, .forbidden)
            let cancelled = try await h.request(.POST, "/oidc/authorize/cancel", headers: ["Cookie": page.cookie], body: form, contentType: Self.formType)
            XCTAssertEqual(cancelled.status, .seeOther)
            let location = cancelled.headers.first(name: .location) ?? ""
            XCTAssertTrue(location.hasPrefix(Self.redirect + "?error=access_denied&state=st-1&iss="), location)
        }
        try await box.value?.app.asyncShutdown()
    }

    // MARK: App path: QR universal link and login_hint push

    func testAppWaitingPageShowsTheNumberAndAQRUniversalLink() async throws {
        let box = Box<Authority>()
        try await withHarness(overrides: { _ in }, { $0.oidc.enabled = true; $0.oidc.issuer = Self.issuer }) { h in
            let authority = try await self.makeAuthority(accounts: [UUID()], business: nil, subjectRefKey: h.ctx.config.subjectRefKey)
            box.value = authority
            h.app.authorityTransport = InProcessAuthorityTransport(app: authority.app)
            let page = try await self.open(h)
            let chosen = try await h.request(.POST, "/oidc/authorize/app", headers: ["Cookie": page.cookie], body: Data("id=\(page.id)&csrf=\(page.csrf)".utf8),
                                             contentType: Self.formType)
            let waiting = try await h.request(.GET, try XCTUnwrap(chosen.headers.first(name: .location)), headers: ["Cookie": page.cookie])
            let row = try unwrap(try await OIDCAuthorizationRecord.query(on: h.db).first())
            let ach = try unwrap(row.challengeId)
            // The QR encodes exactly `https://{link domain}/o/{ach}` (no number, no client), with OIDC-04 beside it; the challenge id is not printed.
            let link = OIDCChallengeLink.build(challengeId: ach, domain: h.ctx.config.linkDomain)
            XCTAssertEqual(OIDCChallengeLink.parse(URL(string: link)!, domain: h.ctx.config.linkDomain), ach)
            let qr = try QRCode.encode(link, errorCorrection: .medium).svg(title: "QR code to open this sign-in in the Viadere app")
            XCTAssertTrue(waiting.text.contains(qr))
            XCTAssertTrue(waiting.text.contains("Only scan a code on this page. Don't scan one that someone sent or showed you."))
            XCTAssertTrue(waiting.text.contains(try unwrap(row.matchCode)))
            XCTAssertFalse(waiting.text.contains(ach))
            XCTAssertFalse(waiting.headers.first(name: "Content-Security-Policy")?.contains("script-src") ?? true)
            XCTAssertTrue(h.push.sent.isEmpty, "no login_hint, no push")

            // The universal link's web fallback looks nothing up, and the app owns `/o/*`.
            let landing = try await h.request(.GET, "/o/\(ach)")
            XCTAssertEqual(landing.status, .ok)
            XCTAssertTrue(landing.text.contains("Nothing was approved here."))
            let aasa = try await h.request(.GET, "/.well-known/apple-app-site-association")
            XCTAssertTrue(aasa.text.contains("\"/o/*\""))
        }
        try await box.value?.app.asyncShutdown()
    }

    func testLoginHintPushGoesOnlyToTheVerifiedAccountAndIsLimited() async throws {
        let box = Box<Authority>()
        try await withHarness(overrides: { _ in }, { $0.oidc.enabled = true; $0.oidc.issuer = Self.issuer }) { h in
            let consumer = try await h.readyConsumer()
            let business = try await h.makeBusiness(name: "Example Shop", handle: "exampleshop")
            let otherBusiness = try await h.makeBusiness(name: "Other Shop", handle: "othershop")
            _ = try await h.connect(consumer, to: business)
            _ = try await h.connect(consumer, to: otherBusiness)
            let device = try XCTUnwrap(consumer.device)
            try await APNsTokenRecord(consumerId: consumer.id.uuid, deviceId: device.id.uuid,
                                      registration: APNsTokenRegistration(token: String(repeating: "ab", count: 32), environment: .sandbox, bundleId: "com.viadere.app"),
                                      now: h.clock.now()).create(on: h.db)
            let authority = try await self.makeAuthority(accounts: [consumer.id.uuid], business: business.id.uuid, subjectRefKey: h.ctx.config.subjectRefKey)
            box.value = authority
            h.app.authorityTransport = InProcessAuthorityTransport(app: authority.app)
            let deriver = SubjectRefDeriver(key: h.ctx.config.subjectRefKey)
            let hint = deriver.subjectRef(businessId: business.id, consumerId: consumer.id).rawValue
            let elsewhere = deriver.subjectRef(businessId: otherBusiness.id, consumerId: consumer.id).rawValue

            func choose(_ extra: String) async throws -> String? {
                let page = try await self.open(h, extra: extra)
                _ = try await h.request(.POST, "/oidc/authorize/app", headers: ["Cookie": page.cookie], body: Data("id=\(page.id)&csrf=\(page.csrf)".utf8),
                                        contentType: Self.formType)
                return try await OIDCAuthorizationRecord.find(UUID(uuidString: page.id)!, on: h.db)?.challengeId
            }

            // The hint of this account at this client's business: one generic push carrying only the challenge id.
            let ach = try await choose("&login_hint=\(hint)")
            XCTAssertEqual(h.push.sent.count, 1)
            let push = try XCTUnwrap(h.push.sent.first)
            XCTAssertEqual(push.category, OIDCPushPayloadPolicy.category)
            XCTAssertEqual(push.oidcChallengeId, ach)
            XCTAssertEqual(push.interruptionLevel, "active")
            XCTAssertFalse(push.body.contains("Example"))
            XCTAssertNil(push.approveRequestId)
            XCTAssertNil(push.interactionId)

            // A hint the api resolves but the authority does not verify (the same person at another business), a malformed one, none: no push.
            _ = try await choose("&login_hint=\(elsewhere)")
            _ = try await choose("&login_hint=someone%40example.com")
            _ = try await choose("")
            XCTAssertEqual(h.push.sent.count, 1)

            // Fatigue: per (client, account), fail closed; the QR keeps working.
            for _ in 0..<4 { _ = try await choose("&login_hint=\(hint)") }
            XCTAssertEqual(h.push.sent.count, 3)
            // login_hint is never written to the browser authorization beyond its own column, and never into a log line we control.
            let rows = try await OIDCAuthorizationRecord.query(on: h.db).filter(\.$loginHint == hint).count()
            XCTAssertGreaterThan(rows, 0)
        }
        try await box.value?.app.asyncShutdown()
    }

    func testConsentRoutesAreOffWithTheFlag() async throws {
        try await withHarness { h in
            let consumer = try await h.readyConsumer()
            aeq(try await h.signed(consumer, .GET, "/v1/oidc/consents").status, .notFound)
            aeq(try await h.signed(consumer, .POST, "/v1/oidc/consents/\(Self.clientId)/revoke").status, .notFound)
            aeq(try await h.request(.POST, "/oidc/authorize/passkey/begin", body: Data("id=x".utf8), contentType: Self.formType).status, .notFound)
        }
    }

    func testPushPayloadPolicyAllowsOnlyTheChallengeId() throws {
        let ach = AuthorityChallengeID.generate()
        let message = PushMessage(deviceToken: "t", environment: .sandbox, topic: "com.viadere.app", title: "Viadere", body: "Action needed. Open to review a sign-in request.",
                                  category: OIDCPushPayloadPolicy.category, threadID: "viadere.oidc", interruptionLevel: "active", interactionId: nil, highPriority: true,
                                  collapseID: ach, oidcChallengeId: ach)
        let data = try JSONEncoder().encode(APNSwiftSender.notification(for: message).payload)
        var payload = try JSONSerialization.jsonObject(with: data) as! [String: Any]
        payload["aps"] = ["alert": ["title": "Viadere", "body": message.body], "category": message.category, "interruption-level": "active", "mutable-content": 1]
        XCTAssertTrue(OIDCPushPayloadPolicy.isAllowed(payload), "\(payload)")
        payload["iid"] = "x"
        XCTAssertFalse(OIDCPushPayloadPolicy.isAllowed(payload))
    }
}
