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
        /// The CKey Safe Action issuer key, when the authority was given one.
        var safeActionKey: P256.Signing.PublicKey? = nil
    }

    /// An authority sharing the api's `SUBJECT_REF_KEY` (both hold a copy), one client registered with `business`, each account's approval key
    /// imported, and a passkey for the first account.
    /// - Parameters:
    ///   - safeActionIssuer: `CKEY_SAFE_ACTION_ISSUER`; with `safeActionPin` the authority signs a Safe Action with every `oidc_login` challenge.
    ///   - kms: wraps the local KMS (to test what the authority does with a misbehaving key service).
    func makeAuthority(accounts: [UUID], business: UUID?, subjectRefKey: SymmetricKey, safeActionIssuer: String? = nil, safeActionPin: Bool = true,
                       challengeLifetime: TimeInterval = 120, kms wrap: ((LocalKMS) -> any KeyManagementService)? = nil) async throws -> Authority {
        let kms = LocalKMS()
        try kms.createRSASigningKey("oidc-signing-rs256", key: try _RSA.Signing.PrivateKey(keySize: .bits2048))
        for name in ["oidc-signing-es256", "grant-signing", "device-statement-signing", "ckey-safe-action-signing"] { kms.createSigningKey(name) }
        let statementKey = try await kms.publicKey(keyRef: "device-statement-signing")
        var config = AuthorityConfig.testing()
        config.issuer = Self.issuer
        config.subjectRefKey = subjectRefKey
        config.developmentStatementPins = [JWKThumbprint.p256(statementKey)]
        config.ckeySafeActionIssuer = safeActionIssuer
        config.challengeLifetime = challengeLifetime
        let clientKey = P256.Signing.PrivateKey()
        var pins: [JSONValue] = []
        for name in ["oidc-signing-es256", "grant-signing", "device-statement-signing"] + (safeActionPin ? ["ckey-safe-action-signing"] : []) {
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
        overrides.kms = wrap?(kms) ?? kms
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
        // Imported keys (and with them the account's imported passkey) produce nothing until the device confirmed the log (ADR-0032 §1.4, §1.6).
        for (account, key) in deviceKeys {
            try await AuthorityEnrollment.confirm(app: app, statementKey: statementKey, accountId: account, keys: [key], now: Self.now)
        }
        return Authority(app: app, statementKey: statementKey, clientKey: clientKey, deviceKeys: deviceKeys, passkey: passkey,
                         safeActionKey: safeActionIssuer == nil || !safeActionPin ? nil : try await kms.publicKey(keyRef: "ckey-safe-action-signing"))
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
            // First the Viadere code: a CKey in the concept style, for the app's scanner.
            let ckey = try CKeySymbol.encode(link, level: .medium).svg(style: .concept, label: "Viadere code to open this sign-in in the Viadere app")
            XCTAssertTrue(waiting.text.contains("<div class=\"ckey\">\(ckey)</div>"))
            let qr = try QRCode.encode(link, errorCorrection: .medium).svg(title: "QR code to open this sign-in in the Viadere app")
            XCTAssertFalse(waiting.text.contains(qr))
            XCTAssertTrue(waiting.text.contains("Scan with the Viadere app. Only scan a code on this page. Don't scan one that someone sent or showed you."))
            // The same link as a QR code for the phone's camera, one plain link away (no script); it survives the refresh and switches back.
            let statusPath = "/oidc/authorize/status?id=\(page.id)"
            XCTAssertTrue(waiting.text.contains("<a href=\"\(statusPath)&amp;code=qr\">"))
            let fallback = try await h.request(.GET, statusPath + "&code=qr", headers: ["Cookie": page.cookie])
            XCTAssertEqual(fallback.status, .ok)
            XCTAssertTrue(fallback.text.contains("<div class=\"qr\">\(qr)</div>"))
            XCTAssertFalse(fallback.text.contains("class=\"ckey\""))
            XCTAssertTrue(fallback.text.contains("Scan with your phone's camera. Only scan a code on this page. Don't scan one that someone sent or showed you."))
            XCTAssertTrue(fallback.text.contains("<a href=\"\(statusPath)\">Back to the Viadere code</a>"))
            XCTAssertTrue(fallback.text.contains(try unwrap(row.matchCode)))
            XCTAssertFalse(fallback.text.contains(ach))
            XCTAssertEqual(fallback.headers.first(name: "Content-Security-Policy"), waiting.headers.first(name: "Content-Security-Policy"))
            // The QR page is only for the browser that started the request.
            let foreign = try await h.request(.GET, statusPath + "&code=qr")
            XCTAssertEqual(foreign.status, .forbidden)
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

    // MARK: The Viadere code as a CKey Safe Action (SECURITY.md §2.104 "Safe Actions"; CKey spec "What an issuer must do")

    static let chromeOnWindows = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"
    static let codeLabel = "Viadere code to open this sign-in in the Viadere app"

    struct RequestInfoBody: Decodable, Equatable { let request_id: String; let device: String?; let location: String?; let requested_at: String?; let status: String }

    static let p256Order: [UInt8] = [0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
                                     0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51]

    /// A key service that answers every Safe Action signature with the high-S twin (a valid ECDSA signature CKey readers refuse), or with garbage.
    struct SafeActionKMS: KeyManagementService {
        enum Mode { case highS, garbage }
        let base: LocalKMS
        let mode: Mode
        func sign(keyRef: String, digest: Data) async throws -> Data {
            let raw = try await base.sign(keyRef: keyRef, digest: digest)
            guard keyRef.hasPrefix("ckey-safe-action-signing") else { return raw }
            switch mode {
            case .garbage: return Data(repeating: 0x42, count: 64)
            case .highS:
                let s = [UInt8](raw.suffix(32))
                var out = [UInt8](repeating: 0, count: 32), borrow = 0
                for i in stride(from: 31, through: 0, by: -1) {
                    var d = Int(OIDCMethodsFrontEndTests.p256Order[i]) - Int(s[i]) - borrow
                    if d < 0 { d += 256; borrow = 1 } else { borrow = 0 }
                    out[i] = UInt8(d)
                }
                return raw.prefix(32) + Data(out)
            }
        }
        func publicKey(keyRef: String) async throws -> P256.Signing.PublicKey { try await base.publicKey(keyRef: keyRef) }
        func wrap(keyRef: String, plaintext: Data) async throws -> KMSWrappedKey { try await base.wrap(keyRef: keyRef, plaintext: plaintext) }
        func unwrap(keyRef: String, ciphertext: Data) async throws -> Data { try await base.unwrap(keyRef: keyRef, ciphertext: ciphertext) }
        func resolveVersion(keyRef: String) async throws -> String { try await base.resolveVersion(keyRef: keyRef) }
        func signRS256(keyRef: String, digest: Data) async throws -> Data { try await base.signRS256(keyRef: keyRef, digest: digest) }
        func rsaPublicKey(keyRef: String) async throws -> _RSA.Signing.PublicKey { try await base.rsaPublicKey(keyRef: keyRef) }
    }

    /// Opens the page, chooses the app (with a User-Agent and an edge country) and returns the waiting page, its status path and the row.
    func chooseApp(_ h: TestHarness, headers: [String: String] = [:]) async throws -> (page: Page, statusPath: String, waiting: HTTPResult, row: OIDCAuthorizationRecord) {
        let page = try await open(h)
        let chosen = try await h.request(.POST, "/oidc/authorize/app", headers: ["Cookie": page.cookie].merging(headers) { $1 },
                                         body: Data("id=\(page.id)&csrf=\(page.csrf)".utf8), contentType: Self.formType)
        let statusPath = try XCTUnwrap(chosen.headers.first(name: .location))
        let waiting = try await h.request(.GET, statusPath, headers: ["Cookie": page.cookie])
        return (page, statusPath, waiting, try unwrap(try await OIDCAuthorizationRecord.query(on: h.db).first()))
    }

    func testTheAuthoritySignsTheSafeActionOnceAndTheApiOnlyDrawsAndPublishesIt() async throws {
        let box = Box<Authority>()
        let token = "edge-token-for-safe-action-test"
        try await withHarness(overrides: { _ in }, {
            $0.oidc.enabled = true; $0.oidc.issuer = Self.issuer; $0.operations.edgeTokens = [Data(token.utf8)]
        }) { h in
            h.edgeTokenForRequests = token
            let domain = h.ctx.config.linkDomain
            let authority = try await self.makeAuthority(accounts: [UUID()], business: nil, subjectRefKey: h.ctx.config.subjectRefKey, safeActionIssuer: domain.host)
            box.value = authority
            h.app.authorityTransport = InProcessAuthorityTransport(app: authority.app)
            let issuerKey = try XCTUnwrap(authority.safeActionKey)
            let (page, statusPath, waiting, row) = try await self.chooseApp(h, headers: ["User-Agent": Self.chromeOnWindows, "CF-IPCountry": "US"])
            let ach = try unwrap(row.challengeId)
            let text = try unwrap(row.safeAction)

            // The envelope: this issuer (the link domain), the Viadere app, `signin.request`, cross-device, the challenge id, no params, issued
            // now and dead in 120 s, ES256 under the authority's key and no other, low-S.
            let keyId = "p256-" + JWKThumbprint.p256(issuerKey).prefix(27)
            let expected = CKeySafeAction(scope: .crossDevice, issuer: domain.host, app: "com.viadere.app", action: "signin.request", keyId: keyId, requestId: ach,
                                          issuedAt: UInt64(Self.now.timeIntervalSince1970), expiresAt: UInt64(Self.now.timeIntervalSince1970) + 120)
            XCTAssertEqual(CKeySafeAction.verify(text: text, key: .es256(issuerKey), now: Self.now, maxLifetime: 120), .ok(expected))
            XCTAssertEqual(CKeySafeAction.verify(text: text, key: .es256(P256.Signing.PrivateKey().publicKey), now: Self.now), .integrity)
            XCTAssertEqual(expected.app, h.ctx.config.appBundleID)
            XCTAssertTrue(CKeySafeAction.isCanonicalES256(try XCTUnwrap(Base64URL.decode(String(text.dropFirst(CKeySafeAction.prefix.count)))).suffix(64)))

            // The page draws exactly that text as the Viadere code, not the link; the QR fallback keeps the plain link.
            let link = OIDCChallengeLink.build(challengeId: ach, domain: domain)
            let symbol = try CKeySymbol.encode(text, level: .medium)
            XCTAssertTrue(waiting.text.contains("<div class=\"ckey\">\(symbol.svg(style: .concept, label: Self.codeLabel))</div>"))
            XCTAssertFalse(waiting.text.contains(try CKeySymbol.encode(link, level: .medium).svg(style: .concept, label: Self.codeLabel)))
            XCTAssertLessThanOrEqual(text.utf8.count, ViadereSignInSafeAction.maxTextBytes(issuer: domain.host))
            XCTAssertFalse(waiting.text.contains(ach))
            XCTAssertFalse(waiting.text.contains(text), "the envelope is drawn, never printed")
            XCTAssertFalse(waiting.headers.first(name: "Content-Security-Policy")?.contains("script-src") ?? true)
            let fallback = try await h.request(.GET, statusPath + "&code=qr", headers: ["Cookie": page.cookie])
            XCTAssertTrue(fallback.text.contains("<div class=\"qr\">\(try QRCode.encode(link, errorCorrection: .medium).svg(title: "QR code to open this sign-in in the Viadere app"))</div>"))
            XCTAssertFalse(fallback.text.contains("class=\"ckey\""))

            // Signed once per challenge: the three-second refresh redraws the stored envelope and mints nothing.
            h.clock.advance(by: 9)
            let again = try await h.request(.GET, statusPath, headers: ["Cookie": page.cookie])
            XCTAssertTrue(again.text.contains(symbol.svg(style: .concept, label: Self.codeLabel)))
            let stored = try await OIDCAuthorizationRecord.query(on: h.db).first()?.safeAction
            XCTAssertEqual(stored, text)

            // Only a vocabulary label and the edge's country are kept about the browser: never the User-Agent.
            XCTAssertEqual(row.requestedDevice, "Chrome on Windows")
            XCTAssertEqual(row.requestedCountry, "US")

            // The issuer's key file: the authority's public key (ES256, compressed SEC 1), the request_info template on the issuer's own host,
            // cacheable for an hour.
            let keyFile = try await h.request(.GET, "/.well-known/ckey-safe-actions.json")
            XCTAssertEqual(keyFile.status, .ok)
            XCTAssertEqual(keyFile.headers.first(name: .cacheControl), "public, max-age=3600")
            XCTAssertEqual(keyFile.headers.contentType, .json)
            let file = try keyFile.json(CKeySafeActionKeyFile.self)
            XCTAssertEqual(file, CKeySafeActionKeyFile(issuer: domain.host, keys: [.init(id: keyId, alg: "ES256", publicKey: CKeySafeAction.PublicKey.es256(issuerKey).hex)],
                                                       requestInfo: "https://\(domain.host)/ckey/requests/{request_id}"))
            XCTAssertEqual(file.keys.first?.publicKey.count, 66)
            XCTAssertEqual(try CKeySafeAction.PublicKey(alg: "ES256", hex: try XCTUnwrap(file.keys.first?.publicKey)), .es256(issuerKey))

            // Request information: pending, with who is asking; no session needed, never cached.
            let info = try await h.request(.GET, "/ckey/requests/\(ach)")
            XCTAssertEqual(info.status, .ok)
            XCTAssertEqual(info.headers.first(name: .cacheControl), "no-store")
            XCTAssertEqual(try info.json(RequestInfoBody.self), RequestInfoBody(request_id: ach, device: "Chrome on Windows", location: "United States",
                                                                               requested_at: CKeySafeActionRoutes.timestamp(Self.now), status: "pending"))
            let number = try unwrap(row.matchCode)
            XCTAssertFalse(info.text.contains("Mozilla") || info.text.contains(row.clientName) || info.text.contains("\"" + number + "\""))

            // Anything that is not a pending request of this issuer gets one indistinguishable 404.
            let unknown = try await h.request(.GET, "/ckey/requests/\(AuthorityChallengeID.generate())")
            XCTAssertEqual(unknown.status, .notFound)
            XCTAssertEqual(unknown.headers.first(name: .cacheControl), "no-store")
            for path in ["/ckey/requests/ach_short", "/ckey/requests/\(row.id!.uuidString)", "/ckey/requests/\(ach)x"] {
                let other = try await h.request(.GET, path)
                XCTAssertEqual(other.status, .notFound, path)
                XCTAssertEqual(other.body, unknown.body, path)
            }
            // The envelope's 120 s are over while the browser authorization (10 minutes) still exists: no longer pending.
            h.clock.advance(by: 112)
            let lapsed = try await h.request(.GET, "/ckey/requests/\(ach)")
            XCTAssertEqual(lapsed.status, .notFound)
            XCTAssertEqual(lapsed.body, unknown.body)
            // Approved, denied, or the row gone: the same answer.
            h.clock.advance(by: -112)
            aeq(try await h.request(.GET, "/ckey/requests/\(ach)").status, .ok)
            for status in ["approved", "denied", "pending", "passkey"] {
                try await OIDCAuthorizationRecord.query(on: h.db).set(\.$status, to: status).update()
                let done = try await h.request(.GET, "/ckey/requests/\(ach)")
                XCTAssertEqual(done.status, .notFound, status)
                XCTAssertEqual(done.body, unknown.body, status)
            }
        }
        try await box.value?.app.asyncShutdown()
    }

    func testRequestInformationIsLimitedFailClosedAndABrowserWithoutALabelIsAWebBrowser() async throws {
        let box = Box<Authority>()
        try await withHarness(overrides: { _ in }, { $0.oidc.enabled = true; $0.oidc.issuer = Self.issuer; $0.oidc.requestInfoRate = .perMinute(3) }) { h in
            let authority = try await self.makeAuthority(accounts: [UUID()], business: nil, subjectRefKey: h.ctx.config.subjectRefKey,
                                                         safeActionIssuer: h.ctx.config.linkDomain.host)
            box.value = authority
            h.app.authorityTransport = InProcessAuthorityTransport(app: authority.app)
            // No origin lock in this harness: a forged country header is ignored. An unrecognised agent gets the neutral label.
            let row = try await self.chooseApp(h, headers: ["User-Agent": "curl/8.9 <script>alert(1)</script>", "CF-IPCountry": "US"]).row
            XCTAssertNil(row.requestedCountry)
            XCTAssertEqual(row.requestedDevice, "A web browser")
            let ach = try unwrap(row.challengeId)
            let info = try await h.request(.GET, "/ckey/requests/\(ach)")
            XCTAssertEqual(try info.json(RequestInfoBody.self), RequestInfoBody(request_id: ach, device: "A web browser", location: nil,
                                                                               requested_at: CKeySafeActionRoutes.timestamp(Self.now), status: "pending"))
            XCTAssertFalse(info.text.contains("location"))
            var statuses: [HTTPStatus] = [info.status]
            for _ in 0..<3 { statuses.append(try await h.request(.GET, "/ckey/requests/\(ach)").status) }
            XCTAssertEqual(statuses, [.ok, .ok, .ok, .tooManyRequests])
            XCTAssertTrue(DatabaseRateLimitStore.defaultFailClosed.contains { "oidc-ckey-request-info".hasPrefix($0) })
        }
        try await box.value?.app.asyncShutdown()
        // The vocabulary: a known browser on a known system, or the neutral label. Nothing from the agent string is ever passed through.
        XCTAssertEqual(OIDCRequestDevice.label(userAgent: "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/19.0 Safari/605.1.15"), "Safari on macOS")
        XCTAssertEqual(OIDCRequestDevice.label(userAgent: Self.chromeOnWindows), "Chrome on Windows")
        for agent in [nil, "", "curl/8.9", "Mozilla/5.0 (Windows NT 10.0)", String(repeating: "A", count: 5000)] as [String?] {
            XCTAssertEqual(OIDCRequestDevice.label(userAgent: agent), "A web browser")
        }
        XCTAssertEqual(OIDCRequestDevice.sanitized("Chrome on Windows"), "Chrome on Windows")
        for stored in [nil, "", "<b>Chrome</b> on Windows", "Chrome on Windows 11", String(repeating: "a", count: 30) + " on " + String(repeating: "b", count: 30), "Chrome"] as [String?] {
            XCTAssertEqual(OIDCRequestDevice.sanitized(stored), "A web browser")
        }
        XCTAssertEqual(OIDCRequestDevice.countryName("NG"), "Nigeria")
        for code in [nil, "", "us", "USA", "U", "1A", "ZZ9"] as [String?] { XCTAssertNil(OIDCRequestDevice.countryName(code)) }
    }

    func testSafeActionsAreOffWithoutTheAuthorityKeyAndThePageDrawsThePlainLink() async throws {
        // (issuer configured, pinned key) is the test above; here every other combination, and an authority naming another issuer.
        let cases: [(issuer: String?, pin: Bool)] = [(nil, true), ("viadere.io", false), ("other.example", true)]
        for (issuer, pin) in cases {
            let box = Box<Authority>()
            try await withHarness(overrides: { _ in }, { $0.oidc.enabled = true; $0.oidc.issuer = Self.issuer }) { h in
                XCTAssertEqual(h.ctx.config.linkDomain.host, "viadere.io")
                let authority = try await self.makeAuthority(accounts: [UUID()], business: nil, subjectRefKey: h.ctx.config.subjectRefKey,
                                                             safeActionIssuer: issuer, safeActionPin: pin)
                box.value = authority
                h.app.authorityTransport = InProcessAuthorityTransport(app: authority.app)
                let (_, _, waiting, row) = try await self.chooseApp(h)
                XCTAssertNil(row.safeAction, "\(String(describing: issuer)) \(pin)")
                let link = OIDCChallengeLink.build(challengeId: try unwrap(row.challengeId), domain: h.ctx.config.linkDomain)
                XCTAssertTrue(waiting.text.contains(try CKeySymbol.encode(link, level: .medium).svg(style: .concept, label: Self.codeLabel)))
                aeq(try await h.request(.GET, "/.well-known/ckey-safe-actions.json").status, .notFound)
                aeq(try await h.request(.GET, "/ckey/requests/\(try unwrap(row.challengeId))").status, .notFound)
                // A stored envelope for another challenge is never drawn.
                let foreign = try ViadereSignInSafeAction.envelope(issuer: h.ctx.config.linkDomain, keyId: "k1", challengeId: AuthorityChallengeID.generate(),
                                                                    now: Self.now, notAfter: Self.now.addingTimeInterval(60))!.signed(with: P256.Signing.PrivateKey())
                row.safeAction = foreign
                XCTAssertTrue(OIDCMethodsFrontEnd.appWaitingBody(row: row, linkDomain: h.ctx.config.linkDomain)
                    .contains(try CKeySymbol.encode(link, level: .medium).svg(style: .concept, label: Self.codeLabel)))
            }
            try await box.value?.app.asyncShutdown()
        }
        // Provider off: both routes answer 404.
        try await withHarness(overrides: { _ in }, { _ in }) { h in
            aeq(try await h.request(.GET, "/.well-known/ckey-safe-actions.json").status, .notFound)
            aeq(try await h.request(.GET, "/ckey/requests/\(AuthorityChallengeID.generate())").status, .notFound)
        }
    }

    func testTheApiStoresOnlyTheSignInEnvelopeForThisChallenge() throws {
        let domain = LinkDomain.production
        let ach = AuthorityChallengeID.generate()
        let key = P256.Signing.PrivateKey()
        func text(_ change: (inout CKeySafeAction) -> Void = { _ in }) throws -> String {
            var action = try XCTUnwrap(ViadereSignInSafeAction.envelope(issuer: domain, keyId: "p256-k", challengeId: ach, now: Self.now, notAfter: Self.now.addingTimeInterval(600)))
            change(&action)
            return try action.signed(with: key)
        }
        let good = try text()
        XCTAssertEqual(CKeySafeActionText.accepted(good, challengeId: ach, linkDomain: domain), good)
        XCTAssertNil(CKeySafeActionText.accepted(good, challengeId: AuthorityChallengeID.generate(), linkDomain: domain))
        XCTAssertNil(CKeySafeActionText.accepted(good, challengeId: ach, linkDomain: LinkDomain("viadere.cksites.dev")!))
        XCTAssertNil(CKeySafeActionText.accepted(nil, challengeId: ach, linkDomain: domain))
        XCTAssertNil(CKeySafeActionText.accepted("ckey-action:1:AAAA", challengeId: ach, linkDomain: domain))
        XCTAssertNil(CKeySafeActionText.accepted(OIDCChallengeLink.build(challengeId: ach, domain: domain), challengeId: ach, linkDomain: domain))
        for bad in [try text { $0.scope = .sameDevice }, try text { $0.app = "com.viadere.app.Clip" }, try text { $0.action = "signin.approve" },
                    try text { $0.params = Data("{}".utf8) }, try text { $0.expiresAt = $0.issuedAt + 121 }] {
            XCTAssertNil(CKeySafeActionText.accepted(bad, challengeId: ach, linkDomain: domain))
        }
    }

    func testTheAuthoritySafeActionKeyConfigurationLifetimeAndKeyServiceFaults() async throws {
        // Configuration: the issuer is a lower-case DNS name and needs the OIDC provider; the key name is a name, never a version.
        let base = ["ENVIRONMENT": "development", "AUTHORITY_OIDC_ENABLED": "true"]
        func config(_ extra: [String: String], _ env: [String: String]? = nil) throws -> AuthorityConfig {
            try AuthorityConfig.fromEnvironment((env ?? base).merging(extra) { $1 })
        }
        XCTAssertNil(try config([:]).ckeySafeActionIssuer)
        XCTAssertEqual(try config([:]).ckeySafeActionKeyName, "ckey-safe-action-signing")
        XCTAssertEqual(try config(["CKEY_SAFE_ACTION_ISSUER": "viadere.io"]).ckeySafeActionIssuer, "viadere.io")
        XCTAssertEqual(try config(["AUTHORITY_KEY_CKEY_SAFE_ACTION": "ckey-2"]).ckeySafeActionKeyName, "ckey-2")
        for bad in [["CKEY_SAFE_ACTION_ISSUER": "Viadere.io"], ["CKEY_SAFE_ACTION_ISSUER": "https://viadere.io"], ["CKEY_SAFE_ACTION_ISSUER": "viadere"],
                    ["CKEY_SAFE_ACTION_ISSUER": "viadere.io/x"], ["AUTHORITY_KEY_CKEY_SAFE_ACTION": "ckey-safe-action-signing/0123"]] {
            XCTAssertThrowsError(try config(bad), "\(bad)")
        }
        XCTAssertThrowsError(try config(["CKEY_SAFE_ACTION_ISSUER": "viadere.io"], ["ENVIRONMENT": "development"]), "needs the OIDC provider")

        // The envelope never outlives the challenge; `GET /v1/ckey/keys` serves the issuer and the public key only.
        let account = UUID()
        let short = try await makeAuthority(accounts: [account], business: nil, subjectRefKey: SymmetricKey(size: .bits256), safeActionIssuer: "viadere.io",
                                            challengeLifetime: 45)
        let transport = InProcessAuthorityTransport(app: short.app)
        func challenge(_ transport: InProcessAuthorityTransport) async throws -> AuthorityChallengeCreateResponse {
            let request = AuthorityChallengeCreateRequest(purpose: .oidcLogin, oidc: .init(clientId: Self.clientId, redirectURI: Self.redirect, codeChallenge: Self.challenge,
                                                                                         codeChallengeMethod: "S256", nonce: "n-1", acrValues: nil, loginHint: nil, hintAccountId: nil))
            let created = try await transport.send(method: .POST, path: AuthorityRoute.challenges, contentType: "application/json", body: try ViadereJSON.encode(request))
            XCTAssertEqual(created.status, 201)
            return try ViadereJSON.decode(AuthorityChallengeCreateResponse.self, from: created.body)
        }
        let created = try await challenge(transport)
        let action = try CKeySafeAction.parse(text: try XCTUnwrap(created.safeAction))
        XCTAssertEqual(action.expiresAt - action.issuedAt, 45)
        XCTAssertEqual(Int64(action.expiresAt), created.expiresAt)
        XCTAssertEqual(action.requestId, created.challengeId)
        let keys = try ViadereJSON.decode(AuthorityCKeyKeySet.self, from: try await transport.send(method: .GET, path: AuthorityRoute.ckeySafeActionKeys, contentType: nil, body: nil).body)
        XCTAssertEqual(keys, AuthorityCKeyKeySet(issuer: "viadere.io", keys: [.init(id: action.keyId, alg: "ES256", publicKey: CKeySafeAction.PublicKey.es256(try XCTUnwrap(short.safeActionKey)).hex)]))
        XCTAssertLessThanOrEqual(action.keyId.count, 32)
        try await short.app.asyncShutdown()

        // A key service answering with the high-S twin: the authority folds it, so the published envelope still has one valid signature value.
        let highS = try await makeAuthority(accounts: [account], business: nil, subjectRefKey: SymmetricKey(size: .bits256), safeActionIssuer: "viadere.io",
                                            kms: { SafeActionKMS(base: $0, mode: .highS) })
        let foldedResponse = try await challenge(InProcessAuthorityTransport(app: highS.app))
        let folded = try XCTUnwrap(foldedResponse.safeAction)
        guard case .ok = CKeySafeAction.verify(text: folded, key: .es256(try XCTUnwrap(highS.safeActionKey)), now: Self.now, maxLifetime: 120) else {
            return XCTFail("the folded envelope must verify")
        }
        try await highS.app.asyncShutdown()
        // A signature that does not verify: no Safe Action (verify before publishing), and the sign-in challenge itself is unaffected.
        let broken = try await makeAuthority(accounts: [account], business: nil, subjectRefKey: SymmetricKey(size: .bits256), safeActionIssuer: "viadere.io",
                                             kms: { SafeActionKMS(base: $0, mode: .garbage) })
        let plain = try await challenge(InProcessAuthorityTransport(app: broken.app))
        XCTAssertNil(plain.safeAction)
        XCTAssertFalse(plain.statement.isEmpty)
        try await broken.app.asyncShutdown()
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
