@preconcurrency import Crypto
import _CryptoExtras
import Fluent
import Foundation
import SQLKit
import Vapor
import ViadereCore
import XCTest
@testable import ViadereAuthorityKit

/// ADR-0024 §2, §6: authorization code + PKCE only, private_key_jwt only, tokens signed by the authority.
final class AuthorityOIDCTests: XCTestCase {
    var h: AuthorityHarness!

    override func setUp() async throws { h = try await AuthorityHarness.make() }
    override func tearDown() async throws { try await h.shutdown() }

    func exchange(_ form: String) async throws -> (status: HTTPStatus, json: [String: Any]) {
        let result = try await h.call(.POST, AuthorityRoute.oidcToken, form: form)
        return (result.status, (try? JSONSerialization.jsonObject(with: result.body) as? [String: Any]) ?? [:])
    }

    func claims(_ jwt: String) throws -> [String: Any] {
        try JSONSerialization.jsonObject(with: Base64URL.decode(String(jwt.split(separator: ".")[1]))!) as! [String: Any]
    }

    func testCodeExchangeIssuesAnRS256IDTokenAndAnES256AccessToken() async throws {
        let code = try await h.approvedCode()
        let result = try await exchange(try h.tokenForm(code: code))
        XCTAssertEqual(result.status, .ok)
        let idToken = try XCTUnwrap(result.json["id_token"] as? String)
        let accessToken = try XCTUnwrap(result.json["access_token"] as? String)
        XCTAssertEqual(result.json["token_type"] as? String, "Bearer")
        XCTAssertNil(result.json["refresh_token"])

        // id_token: RS256 with the pinned RSA key, kid = RFC 7638 thumbprint.
        let idParts = try AuthorityJWS.parse(idToken, expectedType: "JWT", allowedAlgorithms: ["RS256"])
        let primitives = try h.oidcRSAKey.getKeyPrimitives()
        XCTAssertEqual(idParts.kid, JWKThumbprint.rsa(modulus: primitives.modulus, exponent: primitives.publicExponent))
        XCTAssertTrue(h.oidcRSAKey.isValidSignature(_RSA.Signing.RSASignature(rawRepresentation: idParts.signature), for: idParts.signingInput, padding: .insecurePKCS1v1_5))
        let id = try claims(idToken)
        XCTAssertEqual(id["iss"] as? String, AuthorityHarness.issuer)
        XCTAssertEqual(id["aud"] as? String, AuthorityHarness.clientId)
        XCTAssertEqual(id["azp"] as? String, AuthorityHarness.clientId)
        XCTAssertEqual(id["nonce"] as? String, "n-0S6_WzA2Mj")
        XCTAssertEqual(id["acr"] as? String, OIDCProfile.acrApp)
        XCTAssertEqual(id["amr"] as? [String], ["hwk", "user", "mfa"])
        XCTAssertEqual((id["exp"] as! Int) - (id["iat"] as! Int), 300)
        // Pairwise sub over the sector host and the account id; 43 characters, never truncated.
        let sub = OIDCProfile.pairwiseSubject(key: h.config.oidcPairwiseKey, sectorHost: "rp.example.com", accountId: h.accountId)
        XCTAssertEqual(id["sub"] as? String, sub)
        XCTAssertEqual(sub.count, 43)

        // Access token: at+jwt, ES256, audience the userinfo endpoint.
        let atParts = try AuthorityJWS.parse(accessToken, expectedType: "at+jwt", allowedAlgorithms: ["ES256"])
        try AuthorityJWS.verifyES256(atParts, key: h.oidcESKey)
        let at = try claims(accessToken)
        XCTAssertEqual(at["aud"] as? String, AuthorityHarness.issuer + "/oidc/userinfo")
        XCTAssertEqual(at["sub"] as? String, sub)
        XCTAssertEqual(at["scope"] as? String, "openid")

        // Both are recorded (jti, kid, client, sub hash); the grant table is append-only.
        await XCTAssertEqualAsync(try await AuthorityGrantRecord.query(on: h.app.db).count(), 2)
        if let sql = h.app.db as? any SQLDatabase {
            do { try await sql.raw("DELETE FROM \(ident: AuthorityGrantRecord.schema)").run(); XCTFail("authority_grants must be append-only") } catch {}
        }
    }

    func testES256IDTokenWhenTheClientRegisteredIt() async throws {
        try await h.shutdown()
        var options = AuthorityHarness.Options()
        options.idTokenAlg = "ES256"
        h = try await AuthorityHarness.make(options)
        let result = try await exchange(try h.tokenForm(code: try await h.approvedCode()))
        let idToken = try XCTUnwrap(result.json["id_token"] as? String)
        try AuthorityJWS.verifyES256(try AuthorityJWS.parse(idToken, expectedType: "JWT", allowedAlgorithms: ["ES256"]), key: h.oidcESKey)
    }

    func testCodesAreSingleUseShortLivedAndBoundToRedirectAndPKCE() async throws {
        let code = try await h.approvedCode()
        await XCTAssertEqualAsync(try await exchange(try h.tokenForm(code: code, redirectURI: "https://rp.example.com/callback/")).json["error"] as? String, "invalid_grant")
        await XCTAssertEqualAsync(try await exchange(try h.tokenForm(code: code, verifier: String(repeating: "a", count: 43))).json["error"] as? String, "invalid_grant")
        await XCTAssertEqualAsync(try await exchange(try h.tokenForm(code: code)).status, .ok)
        await XCTAssertEqualAsync(try await exchange(try h.tokenForm(code: code)).json["error"] as? String, "invalid_grant")

        let late = try await h.approvedCode()
        h.clock.advance(OIDCProfile.codeLifetime + 1)
        await XCTAssertEqualAsync(try await exchange(try h.tokenForm(code: late)).json["error"] as? String, "invalid_grant")
        await XCTAssertEqualAsync(try await exchange(try h.tokenForm(code: "not-a-code")).json["error"] as? String, "invalid_grant")
    }

    func testClientAssertionRules() async throws {
        let code = try await h.approvedCode()
        func status(_ assertion: String) async throws -> (HTTPStatus, String?) {
            let r = try await exchange(try h.tokenForm(code: code, assertion: assertion))
            return (r.status, r.json["error"] as? String)
        }
        // `aud` must be one string equal to the issuer: arrays and the token endpoint URL are refused.
        var r = try await status(try h.clientAssertion(aud: .array([.string(AuthorityHarness.issuer)])))
        XCTAssertEqual(r.0, .unauthorized); XCTAssertEqual(r.1, "invalid_client")
        r = try await status(try h.clientAssertion(aud: .string(AuthorityHarness.issuer + "/oidc/token")))
        XCTAssertEqual(r.0, .unauthorized)
        // The algorithm comes from the registered key: a header claiming RS256 over the EC key fails.
        r = try await status(try h.clientAssertion(alg: "RS256"))
        XCTAssertEqual(r.0, .unauthorized)
        // A key carried in the header is never used.
        r = try await status(try h.clientAssertion(extraHeader: ["jwk": .object(JWKThumbprint.p256JWK(P256.Signing.PrivateKey().publicKey))]))
        XCTAssertEqual(r.0, .unauthorized)
        // Wrong signer, unknown kid, other client id, too long a lifetime.
        r = try await status(try h.clientAssertion(signer: P256.Signing.PrivateKey()))
        XCTAssertEqual(r.0, .unauthorized)
        r = try await status(try h.clientAssertion(kid: "other"))
        XCTAssertEqual(r.0, .unauthorized)
        r = try await status(try h.clientAssertion(iss: "ocl_someoneelse"))
        XCTAssertEqual(r.0, .unauthorized)
        r = try await status(try h.clientAssertion(lifetime: 3600))
        XCTAssertEqual(r.0, .unauthorized)
        // The code is still unused after all of that.
        let jti = UUID().uuidString
        r = try await status(try h.clientAssertion(jti: jti))
        XCTAssertEqual(r.0, .ok)
        // A replayed assertion jti is refused even for a new code.
        let second = try await h.approvedCode()
        let replay = try await exchange(try h.tokenForm(code: second, assertion: try h.clientAssertion(jti: jti)))
        XCTAssertEqual(replay.json["error"] as? String, "invalid_client")
    }

    func testFormRules() async throws {
        let code = try await h.approvedCode()
        let form = try h.tokenForm(code: code)
        // Repeated and unknown parameters, other grant types, and a missing assertion.
        await XCTAssertEqualAsync(try await exchange(form + "&code=" + code).json["error"] as? String, "invalid_request")
        await XCTAssertEqualAsync(try await exchange(form + "&scope=openid").json["error"] as? String, "invalid_request")
        await XCTAssertEqualAsync(try await exchange(form.replacingOccurrences(of: "grant_type=authorization_code", with: "grant_type=refresh_token")).json["error"] as? String,
                       "unsupported_grant_type")
        let noAssertion = AuthorityHarness.form([("grant_type", "authorization_code"), ("code", code), ("redirect_uri", AuthorityHarness.redirectURI),
                                                 ("code_verifier", AuthorityHarness.codeVerifier), ("client_id", AuthorityHarness.clientId)])
        await XCTAssertEqualAsync(try await exchange(noAssertion).json["error"] as? String, "invalid_client")
        await XCTAssertEqualAsync(try await exchange(form).status, .ok)
    }

    func testClientCheckIsALookupThatCreatesNoChallenge() async throws {
        var r = try await h.call(.GET, AuthorityRoute.oidcClientCheck + "?client_id=ocl_testclient&redirect_uri=https%3A%2F%2Frp.example.com%2Fcallback")
        var body = try ViadereJSON.decode(AuthorityClientCheckResponse.self, from: r.body)
        XCTAssertTrue(body.valid)
        XCTAssertEqual(body.displayName, "Example Shop")
        r = try await h.call(.GET, AuthorityRoute.oidcClientCheck + "?client_id=ocl_testclient&redirect_uri=https%3A%2F%2Frp.example.com%2Fcallback%2F")
        body = try ViadereJSON.decode(AuthorityClientCheckResponse.self, from: r.body)
        XCTAssertFalse(body.valid)
        XCTAssertNil(body.displayName)
        r = try await h.call(.GET, AuthorityRoute.oidcClientCheck + "?client_id=ocl_testclient&post_logout_redirect_uri=https%3A%2F%2Frp.example.com%2Fbye")
        XCTAssertTrue(try ViadereJSON.decode(AuthorityClientCheckResponse.self, from: r.body).valid)
        await XCTAssertEqualAsync(try await AuthorityChallenge.query(on: h.app.db).filter(\.$purpose == "oidc_login").count(), 0) // ST-OIDC-17
    }

    func testPublicKeysRouteServesOnlyTheOIDCKeys() async throws {
        let r = try await h.call(.GET, AuthorityRoute.oidcKeys)
        let set = try ViadereJSON.decode(AuthorityPublicKeySet.self, from: r.body)
        let kids = Set(set.keys.compactMap { $0.objectValue?["kid"]?.stringValue })
        XCTAssertTrue(kids.contains(JWKThumbprint.p256(h.oidcESKey)))
        XCTAssertFalse(kids.contains(JWKThumbprint.p256(h.grantKey)))
        XCTAssertFalse(kids.contains(JWKThumbprint.p256(h.statementKey)))
        XCTAssertEqual(set.keys.count, 2)
        XCTAssertTrue(set.keys.allSatisfy { $0.objectValue?["d"] == nil && $0.objectValue?["use"]?.stringValue == "sig" })
    }

    func testOIDCRoutesAreOffWithTheFlag() async throws {
        try await h.shutdown()
        var options = AuthorityHarness.Options()
        options.oidc = false
        h = try await AuthorityHarness.make(options)
        await XCTAssertEqualAsync(try await h.createOIDCChallenge().status, .notFound)
        await XCTAssertEqualAsync(try await h.call(.POST, AuthorityRoute.oidcToken, form: "grant_type=authorization_code").status, .notFound)
        await XCTAssertEqualAsync(try await h.call(.GET, AuthorityRoute.oidcKeys).status, .notFound)
    }
}
