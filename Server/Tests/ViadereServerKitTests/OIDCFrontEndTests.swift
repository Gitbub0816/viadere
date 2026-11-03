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

/// The api relays to the in-process authority over the same interface the internal network carries (Entra token replaced by a fixed caller).
struct InProcessAuthorityTransport: AuthorityTransport {
    let app: Application
    func send(method: NIOHTTP1.HTTPMethod, path: String, contentType: String?, body: Data?) async throws -> (status: Int, body: Data) {
        var headers = HTTPHeaders()
        headers.bearerAuthorization = BearerAuthorization(token: "api")
        if let contentType { headers.replaceOrAdd(name: .contentType, value: contentType) }
        let box = Box<(Int, Data)>()
        try await app.testable(method: .inMemory).test(method, path, headers: headers, body: body.map { ByteBuffer(data: $0) }) { res async in
            box.value = (Int(res.status.code), Data(res.body.readableBytesView))
        }
        return box.value!
    }
}

struct APICaller: AuthorityCallerVerifier {
    func verify(bearer: String) async throws -> AuthorityCaller {
        guard bearer == "api" else { throw AuthorityCallerError.notAllowed }
        return AuthorityCaller(name: "api", objectId: "00000000-0000-0000-0000-0000000000a1", roles: [AuthorityAppRole.evidenceSubmit.rawValue])
    }
}

/// ADR-0024 end to end through the api front end and the authority: authorize page, method choice, device evidence, code redirect with `iss`,
/// token exchange at the authority, userinfo verified by the api with the authority's public keys.
final class OIDCFrontEndTests: XCTestCase {
    static let issuer = "https://id.viadere.test"
    static let clientId = "ocl_frontend"
    static let redirect = "https://rp.example.com/callback"
    static let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    static let challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

    struct Authority {
        let app: Application
        let statementKey: P256.Signing.PublicKey
        let clientKey: P256.Signing.PrivateKey
        let deviceKey: SoftwareP256SigningKey
    }

    /// An authority with pinned keys, one confidential client and the consumer's approval key imported (account id = consumer id, ADR-0023 §4 import).
    func makeAuthority(accountId: UUID) async throws -> Authority {
        let kms = LocalKMS()
        try kms.createRSASigningKey("oidc-signing-rs256", key: try _RSA.Signing.PrivateKey(keySize: .bits2048))
        for name in ["oidc-signing-es256", "grant-signing", "device-statement-signing"] { kms.createSigningKey(name) }
        let statementKey = try await kms.publicKey(keyRef: "device-statement-signing")
        var config = AuthorityConfig.testing()
        config.issuer = Self.issuer
        config.developmentStatementPins = [JWKThumbprint.p256(statementKey)]
        let clientKey = P256.Signing.PrivateKey(), deviceKey = SoftwareP256SigningKey()
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
        let client: JSONValue = .object(["client_id": .string(Self.clientId), "tenant_id": .string("tnt"), "display_name": .string("Example Shop"),
                                         "redirect_uris": .array([.string(Self.redirect)]), "post_logout_redirect_uris": .array([.string("https://rp.example.com/bye")]),
                                         "jwks": .object(["keys": .array([.object(jwk)])])])
        let keys: JSONValue = .object(["accounts": .array([.object(["account_id": .string(accountId.uuidString),
            "keys": .array([.object(["public_key": .string(deviceKey.publicKey.base64URL), "key_purpose": .string("approvalBiometric"), "hardware_attested": .bool(true)])])])])])
        let commit = String(repeating: "b", count: 40)
        var overrides = AuthorityOverrides()
        overrides.kms = kms
        overrides.callerVerifier = APICaller()
        overrides.clock = { Date(timeIntervalSince1970: 1_800_000_000) }
        let frozen = config, pinList = pins
        overrides.prepare = { db in
            for pin in pinList { try await AuthorityAdmin.run(command: "key-version-pin", changeFile: try CanonicalJSON.serialize(pin), commit: commit, db: db, config: frozen) }
            try await AuthorityAdmin.run(command: "client-register", changeFile: try CanonicalJSON.serialize(client), commit: commit, db: db, config: frozen)
            try await AuthorityAdmin.run(command: "keylog-import", changeFile: try CanonicalJSON.serialize(keys), commit: commit, db: db, config: frozen)
        }
        let app = try await Application.make(.testing)
        try await AuthorityApplication.configure(app, config: config, overrides: overrides, migrateInMemory: true)
        // Imported keys become grant-capable only after the device confirmed a head containing them (ADR-0032 §1.4, §1.6).
        try await AuthorityEnrollment.confirm(app: app, statementKey: statementKey, accountId: accountId, keys: [deviceKey], now: Date(timeIntervalSince1970: 1_800_000_000))
        return Authority(app: app, statementKey: statementKey, clientKey: clientKey, deviceKey: deviceKey)
    }

    func authorizeURL(state: String = "st-1", extra: String = "") -> String {
        "/oidc/authorize?response_type=code&client_id=\(Self.clientId)&redirect_uri=https%3A%2F%2Frp.example.com%2Fcallback&scope=openid&state=\(state)"
            + "&nonce=n-1&code_challenge=\(Self.challenge)&code_challenge_method=S256" + extra
    }

    static func hidden(_ name: String, in html: String) -> String? {
        guard let range = html.range(of: "name=\"\(name)\" value=\"") else { return nil }
        return String(html[range.upperBound...].prefix { $0 != "\"" })
    }

    static func cookie(_ result: HTTPResult) -> String? {
        result.headers[.setCookie].first.flatMap { $0.split(separator: ";").first.map(String.init) }
    }

    func testAppPathEndToEnd() async throws {
        let box = Box<Authority>()
        try await withHarness(overrides: { _ in }, { $0.oidc.enabled = true; $0.oidc.issuer = Self.issuer }) { h in
            let consumer = try await h.readyConsumer()
            let authority = try await self.makeAuthority(accountId: consumer.id.uuid)
            box.value = authority
            h.app.authorityTransport = InProcessAuthorityTransport(app: authority.app)

            // An unregistered redirect URI is an error page, never a redirect (RFC 6749 §4.1.2.1).
            let bad = try await h.request(.GET, self.authorizeURL().replacingOccurrences(of: "callback", with: "evil"))
            XCTAssertEqual(bad.status, .badRequest)
            XCTAssertNil(bad.headers.first(name: .location))

            // The page: client name from the authority's registration, the redirect host, a CSRF token, a __Host- cookie, a strict CSP. No challenge yet.
            let page = try await h.request(.GET, self.authorizeURL())
            XCTAssertEqual(page.status, .ok, page.text)
            XCTAssertTrue(page.text.contains("Example Shop"))
            XCTAssertTrue(page.text.contains("rp.example.com"))
            XCTAssertTrue(page.headers.first(name: "Content-Security-Policy")?.contains("frame-ancestors 'none'") == true)
            let cookie = try XCTUnwrap(Self.cookie(page))
            XCTAssertTrue(cookie.hasPrefix(OIDCFrontEnd.cookieName + "="))
            XCTAssertTrue(page.headers[.setCookie].first?.contains("HttpOnly") == true)
            let id = try XCTUnwrap(Self.hidden("id", in: page.text)), csrf = try XCTUnwrap(Self.hidden("csrf", in: page.text))
            let challengesBefore = try await AuthorityChallengeCount.count(authority.app.db)
            XCTAssertEqual(challengesBefore, 0) // ST-OIDC-17

            // Choosing the app needs this browser's cookie and the CSRF token.
            let form = "id=\(id)&csrf=\(csrf)"
            let formType = "application/x-www-form-urlencoded"
            aeq(try await h.request(.POST, "/oidc/authorize/app", body: Data(form.utf8), contentType: formType).status, .forbidden)
            aeq(try await h.request(.POST, "/oidc/authorize/app", headers: ["Cookie": cookie], body: Data("id=\(id)&csrf=wrong".utf8), contentType: formType).status, .forbidden)
            aeq(try await h.request(.POST, "/oidc/authorize/app", headers: ["Cookie": cookie], body: Data(form.utf8), contentType: "application/json").status, .unsupportedMediaType)
            let chosen = try await h.request(.POST, "/oidc/authorize/app", headers: ["Cookie": cookie], body: Data(form.utf8), contentType: formType)
            XCTAssertEqual(chosen.status, .seeOther, chosen.text)
            let statusPath = try XCTUnwrap(chosen.headers.first(name: .location))
            let waiting = try await h.request(.GET, statusPath, headers: ["Cookie": cookie])
            XCTAssertTrue(waiting.text.contains("Number to enter on your phone"))
            aeq(try await h.request(.GET, statusPath).status, .forbidden) // another browser

            // The device: fetch the statement, verify it against the pinned key, sign over its display with the number from the website.
            let row = try unwrap(try await OIDCAuthorizationRecord.query(on: h.db).first())
            let ach = try unwrap(row.challengeId)
            let fetched = try await h.signed(consumer, .GET, "/v1/oidc/challenges/\(ach)")
            XCTAssertEqual(fetched.status, .ok, fetched.text)
            let statement = try AuthorityStatementVerifier.verifyChallenge(try fetched.json(OIDCDeviceChallenge.self).statement, pinnedKeys: [authority.statementKey],
                                                                           environment: .staging, now: Date(timeIntervalSince1970: 1_800_000_000))
            XCTAssertEqual(statement.redirectURI, Self.redirect)
            let claims = try FactorAssertionClaims.answering(statement, decision: .approve, userVerification: .biometric, match: row.matchCode,
                                                             now: Date(timeIntervalSince1970: 1_800_000_000))
            let factor = try await FactorAssertion.sign(claims, with: authority.deviceKey)
            // Another consumer naming this evidence fails the authority's account binding.
            let other = try await h.readyConsumer(name: "Other")
            let foreign = try await h.signed(other, .POST, "/v1/oidc/challenges/\(ach)/evidence", body: try ViadereJSON.encode(OIDCDeviceEvidenceRequest(factor: factor)))
            XCTAssertEqual(foreign.status, .forbidden, foreign.text)
            let evidence = try await h.signed(consumer, .POST, "/v1/oidc/challenges/\(ach)/evidence", body: try ViadereJSON.encode(OIDCDeviceEvidenceRequest(factor: factor)))
            XCTAssertEqual(evidence.status, .ok, evidence.text)
            XCTAssertEqual(try evidence.json(OIDCDeviceEvidenceResponse.self).decision, .approve)
            XCTAssertFalse(evidence.text.contains("code"))

            // The browser that started it gets the code, with state and iss (RFC 9207); once.
            let done = try await h.request(.GET, statusPath, headers: ["Cookie": cookie])
            XCTAssertEqual(done.status, .seeOther)
            let location = try XCTUnwrap(done.headers.first(name: .location))
            XCTAssertTrue(location.hasPrefix(Self.redirect + "?code="))
            let items = Dictionary(uniqueKeysWithValues: (URLComponents(string: location)?.queryItems ?? []).map { ($0.name, $0.value ?? "") })
            XCTAssertEqual(items["state"], "st-1")
            XCTAssertEqual(items["iss"], Self.issuer)
            let code = try XCTUnwrap(items["code"])
            aeq(try await h.request(.GET, statusPath, headers: ["Cookie": cookie]).status, .forbidden)

            // The token endpoint is the authority's (forwarded unchanged).
            let t = Int64(1_800_000_000)
            let header = Base64URL.encode(try CanonicalJSON.serialize(.object(["alg": .string("ES256"), "kid": .string("k1"), "typ": .string("JWT")])))
            let payload = Base64URL.encode(try CanonicalJSON.serialize(.object(["iss": .string(Self.clientId), "sub": .string(Self.clientId), "aud": .string(Self.issuer),
                                                                                  "jti": .string(UUID().uuidString), "iat": .integer(t), "exp": .integer(t + 60)])))
            let assertion = header + "." + payload + "." + Base64URL.encode(try authority.clientKey.signature(for: Data((header + "." + payload).utf8)).rawRepresentation)
            var allowed = CharacterSet.alphanumerics
            allowed.insert(charactersIn: "-._~")
            let tokenForm = [("grant_type", "authorization_code"), ("code", code), ("redirect_uri", Self.redirect), ("code_verifier", Self.verifier),
                             ("client_assertion_type", OIDCProfile.clientAssertionType), ("client_assertion", assertion)]
                .map { "\($0.0)=\($0.1.addingPercentEncoding(withAllowedCharacters: allowed)!)" }.joined(separator: "&")
            let tokens = try await h.request(.POST, "/oidc/token", body: Data(tokenForm.utf8), contentType: formType)
            XCTAssertEqual(tokens.status, .ok, tokens.text)
            XCTAssertEqual(tokens.headers.first(name: .cacheControl), "no-store")
            let json = try JSONSerialization.jsonObject(with: tokens.body) as! [String: Any]
            let accessToken = try XCTUnwrap(json["access_token"] as? String), idToken = try XCTUnwrap(json["id_token"] as? String)

            // userinfo: verified by the api with the authority's public keys; an id_token is not an access token.
            let info = try await h.request(.GET, "/oidc/userinfo", headers: ["Authorization": "Bearer " + accessToken])
            XCTAssertEqual(info.status, .ok, info.text)
            let sub = (try JSONSerialization.jsonObject(with: info.body) as! [String: Any])["sub"] as? String
            XCTAssertEqual(sub?.count, 43)
            aeq(try await h.request(.GET, "/oidc/userinfo", headers: ["Authorization": "Bearer " + idToken]).status, .unauthorized)
            var tampered = accessToken
            tampered.removeLast(2)
            aeq(try await h.request(.GET, "/oidc/userinfo", headers: ["Authorization": "Bearer " + tampered + "AA"]).status, .unauthorized)

            // RP-initiated logout: only to a registered URI and only with a verified id_token_hint.
            let logout = try await h.request(.GET, "/oidc/logout?id_token_hint=\(idToken)&post_logout_redirect_uri=https%3A%2F%2Frp.example.com%2Fbye&state=s2")
            XCTAssertEqual(logout.status, .seeOther)
            XCTAssertEqual(logout.headers.first(name: .location), "https://rp.example.com/bye?state=s2")
            let unregistered = try await h.request(.GET, "/oidc/logout?id_token_hint=\(idToken)&post_logout_redirect_uri=https%3A%2F%2Fevil.example.com%2F")
            XCTAssertEqual(unregistered.status, .ok)
            XCTAssertNil(unregistered.headers.first(name: .location))
        }
        try await box.value?.app.asyncShutdown()
    }

    func testProtocolRefusalsRedirectWithIssAndState() async throws {
        let box = Box<Authority>()
        try await withHarness(overrides: { _ in }, { $0.oidc.enabled = true; $0.oidc.issuer = Self.issuer }) { h in
            let authority = try await self.makeAuthority(accountId: UUID())
            box.value = authority
            h.app.authorityTransport = InProcessAuthorityTransport(app: authority.app)
            for (extra, error) in [("&prompt=none", "login_required"), ("&request=eyJ", "request_not_supported"), ("&response_mode=fragment", "invalid_request")] {
                let result = try await h.request(.GET, self.authorizeURL(extra: extra))
                XCTAssertEqual(result.status, .seeOther, extra)
                let location = result.headers.first(name: .location) ?? ""
                XCTAssertTrue(location.contains("error=\(error)"), location)
                XCTAssertTrue(location.contains("state=st-1") && location.contains("iss=https%3A%2F%2Fid.viadere.test"), location)
            }
            let plain = try await h.request(.GET, self.authorizeURL().replacingOccurrences(of: "S256", with: "plain"))
            XCTAssertTrue(plain.headers.first(name: .location)?.contains("error=invalid_request") == true)
            let scope = try await h.request(.GET, self.authorizeURL().replacingOccurrences(of: "scope=openid", with: "scope=openid%20email"))
            XCTAssertTrue(scope.headers.first(name: .location)?.contains("error=invalid_scope") == true)
            let implicit = try await h.request(.GET, self.authorizeURL().replacingOccurrences(of: "response_type=code", with: "response_type=token"))
            XCTAssertTrue(implicit.headers.first(name: .location)?.contains("error=unsupported_response_type") == true)
            let noNonce = try await h.request(.GET, self.authorizeURL().replacingOccurrences(of: "&nonce=n-1", with: ""))
            XCTAssertTrue(noNonce.headers.first(name: .location)?.contains("error=invalid_request") == true)
            // A repeated parameter is an error page.
            aeq(try await h.request(.GET, self.authorizeURL() + "&client_id=\(Self.clientId)").status, .badRequest)
        }
        try await box.value?.app.asyncShutdown()
    }

    func testEdgeLimitOnChoosingTheAppIsFailClosed() async throws {
        let box = Box<Authority>()
        try await withHarness(overrides: { _ in }, { $0.oidc.enabled = true; $0.oidc.issuer = Self.issuer; $0.oidc.ipMinuteRate = .perMinute(2) }) { h in
            let authority = try await self.makeAuthority(accountId: UUID())
            box.value = authority
            h.app.authorityTransport = InProcessAuthorityTransport(app: authority.app)
            var statuses: [HTTPStatus] = []
            for _ in 0..<3 {
                let page = try await h.request(.GET, self.authorizeURL())
                let cookie = try XCTUnwrap(Self.cookie(page))
                let form = "id=\(Self.hidden("id", in: page.text)!)&csrf=\(Self.hidden("csrf", in: page.text)!)"
                statuses.append(try await h.request(.POST, "/oidc/authorize/app", headers: ["Cookie": cookie], body: Data(form.utf8),
                                                    contentType: "application/x-www-form-urlencoded").status)
            }
            XCTAssertEqual(statuses, [.seeOther, .seeOther, .tooManyRequests])
            let created = try await AuthorityChallengeCount.count(authority.app.db)
            XCTAssertEqual(created, 2)
        }
        try await box.value?.app.asyncShutdown()
    }

    func testEverythingIsOffWithTheFlagAndTheFlagIsRefusedInProduction() async throws {
        try await withHarness { h in
            aeq(try await h.request(.GET, self.authorizeURL()).status, .notFound)
            aeq(try await h.request(.POST, "/oidc/token", body: Data("a=b".utf8), contentType: "application/x-www-form-urlencoded").status, .notFound)
            aeq(try await h.request(.GET, "/oidc/userinfo").status, .notFound)
            let consumer = try await h.readyConsumer()
            aeq(try await h.signed(consumer, .GET, "/v1/oidc/challenges/\(AuthorityChallengeID.generate())").status, .notFound)
        }
        var config = ServerConfig.testing()
        XCTAssertThrowsError(try config.applyOIDCEnvironment(["OIDC_PROVIDER_ENABLED": "true"], environment: .production))
        XCTAssertThrowsError(try config.applyOIDCEnvironment(["OIDC_PROVIDER_ENABLED": "true"], environment: .staging)) // needs issuer, authority URL, audience
        XCTAssertNoThrow(try config.applyOIDCEnvironment(["OIDC_PROVIDER_ENABLED": "true", "OIDC_ISSUER": "https://id.staging.example",
                                                          "AUTHORITY_URL": "https://ca-viadere-authority.internal.example", "AUTHORITY_ENTRA_AUDIENCE": "api://viadere-authority-staging"],
                                                         environment: .staging))
        XCTAssertThrowsError(try config.applyOIDCEnvironment(["AUTHORITY_URL": "http://ca-viadere-authority.internal.example"], environment: .staging))
        XCTAssertFalse(ServerConfig.testing().oidc.enabled)
    }

    func testOIDCRateLimitNamespacesFailClosed() {
        XCTAssertTrue(DatabaseRateLimitStore.defaultFailClosed.contains { "oidc-authorize-ip".hasPrefix($0) })
        XCTAssertTrue(DatabaseRateLimitStore.defaultFailClosed.contains { "oidc-evidence".hasPrefix($0) })
    }
}

/// Counts authority challenges without making the authority's models public.
enum AuthorityChallengeCount {
    static func count(_ db: any Database) async throws -> Int {
        guard let sql = db as? any SQLDatabase else { return -1 }
        struct Row: Decodable { let n: Int }
        return try await sql.raw("SELECT COUNT(*) AS n FROM authority_challenges WHERE purpose = 'oidc_login'").first(decoding: Row.self)?.n ?? -1
    }
}
