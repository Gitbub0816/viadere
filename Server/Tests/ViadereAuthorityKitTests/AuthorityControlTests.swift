@preconcurrency import Crypto
import _CryptoExtras
import Fluent
import Foundation
import NIOHTTP1
import Vapor
import ViadereCore
import ViadereServiceSupport
import XCTest
@testable import ViadereAuthorityKit

/// Configuration contract with `Infra/azure-authority`, caller authentication, key pins, admin commands and structural controls.
final class AuthorityControlTests: XCTestCase {
    static let strictEnv: [String: String] = [
        "ENVIRONMENT": "staging", "AZURE_TENANT_ID": "11111111-2222-3333-4444-555555555555", "AUTHORITY_ENTRA_AUDIENCE": "api://viadere-authority-staging",
        "AUTHORITY_CALLER_OIDS": "api:aaaaaaaa-0000-0000-0000-000000000001,worker:bbbbbbbb-0000-0000-0000-000000000002",
        "AUTHORITY_OUTBOUND_ALLOWLIST": "login.microsoftonline.com,kv-vdr-auth-stgl.vault.azure.net,psql-viadere-stgl.postgres.database.azure.com",
        "AZURE_KEY_VAULT_URL": "https://kv-vdr-auth-stgl.vault.azure.net/", "DATABASE_AUTH": "entra", "DATABASE_HOST": "psql-viadere-stgl.postgres.database.azure.com",
        "DATABASE_NAME": "viadere_authority", "DATABASE_USER": "viadere_authority", "AUTHORITY_KEY_GRANT_SIGNING": "grant-signing",
        "AUTHORITY_KEY_OIDC_RS256": "oidc-signing-rs256", "AUTHORITY_KEY_OIDC_ES256": "oidc-signing-es256", "AUTHORITY_KEY_DEVICE_STATEMENT": "device-statement-signing",
        "AUTHORITY_KEY_SEAL_KEK": "recovery-seal-kek", "AUTHORITY_KEY_SEAL_RSA": "", "PORT": "8080", "BIND_HOST": "0.0.0.0",
    ]

    static func secret() -> String { Base64URL.encode(SecureToken.randomBytes(32)) }

    // MARK: Configuration (the infra contract)

    func testStrictConfigurationReadsTheInfraVariableNamesAndDefaultsOff() throws {
        let config = try AuthorityConfig.fromEnvironment(Self.strictEnv)
        XCTAssertFalse(config.enabled)
        XCTAssertFalse(config.oidcEnabled)
        XCTAssertEqual(config.entraDatabase?.name, "viadere_authority")
        XCTAssertEqual(config.callerObjectIds["api"], "aaaaaaaa-0000-0000-0000-000000000001")
        XCTAssertTrue(config.outboundAllowlist.contains("login.microsoftonline.com"))
        XCTAssertEqual(config.deviceStatementKeyName, "device-statement-signing")
    }

    func testEnablingInStagingNeedsEverySecretAndTheIssuer() throws {
        var env = Self.strictEnv
        env["AUTHORITY_ENABLED"] = "true"
        XCTAssertThrowsError(try AuthorityConfig.fromEnvironment(env))
        env["OIDC_ISSUER"] = "https://id.staging.viadere.example"
        XCTAssertThrowsError(try AuthorityConfig.fromEnvironment(env))
        env["OIDC_PAIRWISE_KEY"] = Self.secret()
        env["ACCOUNT_REF_KEY"] = Self.secret()
        env["SUBJECT_REF_KEY"] = Self.secret()
        XCTAssertNoThrow(try AuthorityConfig.fromEnvironment(env))
        env["ACCOUNT_REF_KEY"] = env["OIDC_PAIRWISE_KEY"]
        XCTAssertThrowsError(try AuthorityConfig.fromEnvironment(env)) // one key per purpose
        env["ACCOUNT_REF_KEY"] = Self.secret()
        env["OIDC_ISSUER"] = "https://id.staging.viadere.example/"
        XCTAssertThrowsError(try AuthorityConfig.fromEnvironment(env))
    }

    func testOIDCIsRefusedInProduction() throws {
        var env = Self.strictEnv
        env["ENVIRONMENT"] = "production"
        env["AUTHORITY_OIDC_ENABLED"] = "true"
        XCTAssertThrowsError(try AuthorityConfig.fromEnvironment(env)) { error in
            XCTAssertTrue("\(error)".contains("AUTHORITY_OIDC_ENABLED"))
        }
        env["ENVIRONMENT"] = "staging"
        XCTAssertTrue(try AuthorityConfig.fromEnvironment(env).oidcEnabled)
    }

    func testStrictRefusesPasswordsVersionsInKeyNamesAndDevelopmentPins() throws {
        var env = Self.strictEnv
        env["DATABASE_AUTH"] = "password"
        env["DATABASE_URL"] = "postgres://u:p@h/db"
        XCTAssertThrowsError(try AuthorityConfig.fromEnvironment(env))
        env = Self.strictEnv
        env["AUTHORITY_KEY_GRANT_SIGNING"] = "grant-signing/0123456789abcdef0123456789abcdef"
        XCTAssertThrowsError(try AuthorityConfig.fromEnvironment(env))
        env = Self.strictEnv
        env["AUTHORITY_DEV_STATEMENT_PINS"] = "abc"
        XCTAssertThrowsError(try AuthorityConfig.fromEnvironment(env))
        env = Self.strictEnv
        env["AUTHORITY_CALLER_OIDS"] = "admin:aaaaaaaa-0000-0000-0000-000000000001"
        XCTAssertThrowsError(try AuthorityConfig.fromEnvironment(env))
        env = Self.strictEnv
        env["AUTHORITY_CALLER_OIDS"] = ""
        XCTAssertThrowsError(try AuthorityConfig.fromEnvironment(env))
    }

    func testStagingStatementPinsAreTheCoreConstants() throws {
        let config = try AuthorityConfig.fromEnvironment(Self.strictEnv)
        XCTAssertEqual(config.statementPins, AuthorityPinnedKeys.deviceStatementKids(.staging))
    }

    func testInfraModuleSetsTheVariablesTheConfigReads() throws {
        // Infra/azure-authority/containerapps.tf is the other side of this contract.
        let root = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        let tf = try String(contentsOf: root.appendingPathComponent("Infra/azure-authority/containerapps.tf"), encoding: .utf8)
        for name in ["AUTHORITY_ENTRA_AUDIENCE", "AUTHORITY_CALLER_OIDS", "AUTHORITY_OUTBOUND_ALLOWLIST", "AUTHORITY_KEY_GRANT_SIGNING", "AUTHORITY_KEY_OIDC_RS256",
                     "AUTHORITY_KEY_OIDC_ES256", "AUTHORITY_KEY_DEVICE_STATEMENT", "AUTHORITY_ENABLED", "DATABASE_AUTH", "DATABASE_HOST", "DATABASE_NAME",
                     "DATABASE_USER", "AZURE_KEY_VAULT_URL", "AZURE_TENANT_ID", "/app/ViadereAuthority"] {
            XCTAssertTrue(tf.contains(name), name)
        }
        let locals = try String(contentsOf: root.appendingPathComponent("Infra/azure-authority/locals.tf"), encoding: .utf8)
        for name in ["OIDC_PAIRWISE_KEY", "ACCOUNT_REF_KEY", "SUBJECT_REF_KEY"] { XCTAssertTrue(locals.contains(name), name) }
        let dockerfile = try String(contentsOf: root.appendingPathComponent("Server/Dockerfile.authority"), encoding: .utf8)
        XCTAssertTrue(dockerfile.contains("/app/ViadereAuthority"))
        XCTAssertTrue(dockerfile.contains("--product ViadereAuthority"))
        XCTAssertFalse(dockerfile.contains("Public"))
    }

    // MARK: Disabled

    func testDisabledAuthorityRunsButRefusesEveryGrantRoute() async throws {
        var options = AuthorityHarness.Options()
        options.enabled = false
        let h = try await AuthorityHarness.make(options)
        await XCTAssertEqualAsync(try await h.call(.GET, "/healthz", token: nil).status, .ok)
        await XCTAssertEqualAsync(try await h.createOIDCChallenge().status, .serviceUnavailable)
        XCTAssertNil(h.app.authority.keys)
        try await h.shutdown()
    }

    // MARK: Callers (ADR-0019 §4.2, ADR-0028 §9)

    func testCallersNeedATokenTheRoleAndTheRightIdentity() async throws {
        let h = try await AuthorityHarness.make()
        let body = try ViadereJSON.encode(AuthorityEvidenceRequest(factor: "x.y.z"))
        await XCTAssertEqualAsync(try await h.call(.POST, AuthorityRoute.evidence, token: nil, json: body).status, .unauthorized)
        await XCTAssertEqualAsync(try await h.call(.POST, AuthorityRoute.evidence, token: "forged", json: body).status, .unauthorized)
        // ST-AUTH-18: a worker token on evidence is 403; an api token without the app role too.
        await XCTAssertEqualAsync(try await h.call(.POST, AuthorityRoute.evidence, token: StaticCallerVerifier.workerToken, json: body).status, .forbidden)
        await XCTAssertEqualAsync(try await h.call(.POST, AuthorityRoute.challenges, token: StaticCallerVerifier.workerToken, json: body).status, .forbidden)
        await XCTAssertEqualAsync(try await h.call(.POST, AuthorityRoute.oidcToken, token: StaticCallerVerifier.workerToken, form: "a=b").status, .forbidden)
        await XCTAssertEqualAsync(try await h.call(.POST, AuthorityRoute.evidence, token: StaticCallerVerifier.apiWithoutRoleToken, json: body).status, .forbidden)
        // The worker reaches revocations.
        let revoke = try ViadereJSON.encode(AuthorityRevocationRequest(kid: KeyIdentifier.make(P256.Signing.PrivateKey().publicKey), reason: "device_lost"))
        await XCTAssertEqualAsync(try await h.call(.POST, AuthorityRoute.revocations, token: StaticCallerVerifier.workerToken, json: revoke).status, .ok)
        try await h.shutdown()
    }

    struct FixedKeys: EntraSigningKeySource {
        let keys: [String: _RSA.Signing.PublicKey]
        func key(kid: String) async throws -> _RSA.Signing.PublicKey? { keys[kid] }
    }

    func entraToken(_ key: _RSA.Signing.PrivateKey, kid: String = "k1", alg: String = "RS256", claims overrides: [String: Any] = [:]) throws -> String {
        let now = Date().timeIntervalSince1970
        var claims: [String: Any] = ["iss": "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0", "aud": "api://viadere-authority-staging",
                                     "tid": "11111111-2222-3333-4444-555555555555", "oid": "aaaaaaaa-0000-0000-0000-000000000001", "roles": ["Authority.Evidence.Submit"],
                                     "exp": Int(now) + 600, "nbf": Int(now) - 10, "iat": Int(now) - 10]
        for (k, v) in overrides { claims[k] = v }
        let header = try JSONSerialization.data(withJSONObject: ["alg": alg, "kid": kid, "typ": "JWT"])
        let payload = try JSONSerialization.data(withJSONObject: claims.filter { !($0.value is NSNull) })
        let input = Base64URL.encode(header) + "." + Base64URL.encode(payload)
        let signature = try key.signature(for: Data(input.utf8), padding: .insecurePKCS1v1_5)
        return input + "." + Base64URL.encode(signature.rawRepresentation)
    }

    func testEntraVerifierChecksSignatureIssuerAudienceTimeAndObjectId() async throws {
        let key = try _RSA.Signing.PrivateKey(keySize: .bits2048)
        let verifier = EntraCallerVerifier(tenantId: "11111111-2222-3333-4444-555555555555", audience: "api://viadere-authority-staging",
                                           callers: ["api": "aaaaaaaa-0000-0000-0000-000000000001"], keys: FixedKeys(keys: ["k1": key.publicKey]))
        let caller = try await verifier.verify(bearer: try entraToken(key))
        XCTAssertEqual(caller.name, "api")
        XCTAssertEqual(caller.roles, ["Authority.Evidence.Submit"])
        let v1 = try await verifier.verify(bearer: try entraToken(key, claims: ["iss": "https://sts.windows.net/11111111-2222-3333-4444-555555555555/"]))
        XCTAssertEqual(v1.name, "api")
        let refused: [String] = [
            try entraToken(key, claims: ["aud": "api://other"]),
            try entraToken(key, claims: ["iss": "https://login.microsoftonline.com/99999999-2222-3333-4444-555555555555/v2.0"]),
            try entraToken(key, claims: ["tid": "99999999-2222-3333-4444-555555555555"]),
            try entraToken(key, claims: ["exp": Int(Date().timeIntervalSince1970) - 120]),
            try entraToken(key, claims: ["nbf": Int(Date().timeIntervalSince1970) + 600]),
            try entraToken(key, claims: ["oid": "cccccccc-0000-0000-0000-000000000003"]),
            try entraToken(key, kid: "unknown"),
            try entraToken(try _RSA.Signing.PrivateKey(keySize: .bits2048)),
            try entraToken(key, alg: "HS256"),
            try entraToken(key, alg: "none"),
        ]
        for token in refused {
            do { _ = try await verifier.verify(bearer: token); XCTFail("accepted a token that must be refused") } catch {}
        }
    }

    func testOutboundIsAllowListed() async throws {
        struct Recorder: OutboundHTTP {
            func send(method: NIOHTTP1.HTTPMethod, url: String, headers: [String: String], body: Data?) async throws -> (status: Int, body: Data) { (200, Data()) }
        }
        let http = AllowListOutboundHTTP(allowed: ["login.microsoftonline.com"], base: Recorder())
        _ = try await http.send(method: .GET, url: "https://login.microsoftonline.com/t/discovery/v2.0/keys", headers: [:], body: nil)
        for url in ["https://example.com/", "http://login.microsoftonline.com/", "https://login.microsoftonline.com.evil.example/", "https://user@login.microsoftonline.com/"] {
            do { _ = try await http.send(method: .GET, url: url, headers: [:], body: nil); XCTFail(url) } catch {}
        }
    }

    // MARK: Key pins (ADR-0028 §2)

    func testStartupFailsClosedWithoutAPinOrWithAWrongThumbprint() async throws {
        var a = AuthorityHarness.Options(); a.skipPin = "grant-signing"
        var b = AuthorityHarness.Options(); b.wrongThumbprintFor = "oidc-signing-es256"
        var c = AuthorityHarness.Options(); c.skipPin = "oidc-signing-rs256"
        var d = AuthorityHarness.Options(); d.pinStatementInApp = false
        for options in [a, b, c, d] {
            do {
                let h = try await AuthorityHarness.make(options)
                try await h.shutdown()
                XCTFail("the authority started with \(options)")
            } catch is AuthorityKeyError {
            } catch {
                XCTFail("unexpected \(error)")
            }
        }
    }

    func testInventoryLinesCarryPublicJWKsOnly() async throws {
        let h = try await AuthorityHarness.make()
        let lines = try XCTUnwrap(h.app.authority.keys).inventoryLines()
        XCTAssertEqual(lines.count, 4)
        for line in lines {
            XCTAssertTrue(line.contains("\"authority_key_inventory\":1"))
            XCTAssertFalse(line.contains("\"d\":"))
        }
        try await h.shutdown()
    }

    // MARK: Admin commands (ADR-0019 §5, ADR-0024 §3)

    func testClientRegistrationRules() async throws {
        let h = try await AuthorityHarness.make()
        let jwk = JWKThumbprint.p256JWK(P256.Signing.PrivateKey().publicKey)
        func register(_ extra: [String: JSONValue]) async throws {
            var change: [String: JSONValue] = ["client_id": .string("ocl_second"), "tenant_id": .string("tnt"), "display_name": .string("Second"),
                                               "redirect_uris": .array([.string("https://second.example.com/cb")]), "jwks": .object(["keys": .array([.object(jwk)])])]
            for (k, v) in extra { change[k] = v }
            try await AuthorityAdmin.run(command: "client-register", changeFile: try CanonicalJSON.serialize(.object(change)), commit: AuthorityHarness.commit,
                                         db: h.app.db, config: h.config)
        }
        let bad: [[String: JSONValue]] = [
            ["redirect_uris": .array([.string("http://second.example.com/cb")])],
            ["redirect_uris": .array([.string("https://*.example.com/cb")])],
            ["redirect_uris": .array([.string("https://second.example.com/cb#x")])],
            ["redirect_uris": .array([.string("https://127.0.0.1/cb")])],
            ["redirect_uris": .array([.string("https://localhost/cb")])],
            ["redirect_uris": .array([.string("myapp://cb")])],
            ["redirect_uris": .array([.string("https://a.example.com/cb"), .string("https://b.example.com/cb")])],
            ["client_id": .string("lcl_second")],
            ["client_id": .string(AuthorityHarness.clientId)],
            ["jwks": .object(["keys": .array([.object(jwk.filter { $0.key != "alg" })])])],
            ["jwks": .object(["keys": .array([.object(jwk.merging(["d": .string("secret")]) { $1 })])])],
            ["id_token_signed_response_alg": .string("none")],
            ["token_endpoint_auth_method": .string("none")],
            ["display_name": .string("Bank\u{202E}")],
        ]
        for extra in bad {
            do { try await register(extra); XCTFail("registered \(extra)") } catch is AuthorityAdmin.Failure {}
        }
        try await register([:])
        do {
            try await AuthorityAdmin.run(command: "client-register", changeFile: Data("{}".utf8), commit: "abc", db: h.app.db, config: h.config)
            XCTFail("a change without its commit")
        } catch is AuthorityAdmin.Failure {}
        try await h.shutdown()
    }

    func testKeyImportRefusesAKeyAlreadyInUse() async throws {
        let h = try await AuthorityHarness.make()
        let change: JSONValue = .object(["accounts": .array([.object(["account_id": .string(UUID().uuidString),
                                                                      "keys": .array([.object(["public_key": .string(h.biometricKey.publicKey.base64URL), "key_purpose": .string("approvalBiometric")])])])])])
        do {
            try await AuthorityAdmin.run(command: "keylog-import", changeFile: try CanonicalJSON.serialize(change), commit: AuthorityHarness.commit, db: h.app.db, config: h.config)
            XCTFail("one account per key")
        } catch is AuthorityAdmin.Failure {}
        try await h.shutdown()
    }

    // MARK: Structure

    /// ADR-0023 §6: KMS `sign` is invoked only by the builders in `AuthoritySigning.swift`.
    func testOnlyTheBuildersCallKMSSign() throws {
        let sources = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/ViadereAuthorityKit")
        let files = try FileManager.default.contentsOfDirectory(atPath: sources.path).filter { $0.hasSuffix(".swift") }
        XCTAssertTrue(files.contains("AuthoritySigning.swift"))
        for file in files where file != "AuthoritySigning.swift" {
            let text = try String(contentsOf: sources.appendingPathComponent(file), encoding: .utf8)
            for needle in [".sign(keyRef", "signRS256(", "kms.", "unwrap(keyRef", "decrypt("] {
                XCTAssertFalse(text.contains(needle), "\(file) calls \(needle)")
            }
        }
    }

    /// L-14: the complete route list; no debug or admin endpoint over HTTP.
    func testRouteListIsExactlyTheInternalInterface() async throws {
        let h = try await AuthorityHarness.make()
        let routes = Set(h.app.routes.all.map { "\($0.method.rawValue) /" + $0.path.map(\.description).joined(separator: "/") })
        XCTAssertEqual(routes, ["GET /healthz", "GET /readyz", "POST /v1/challenges", "POST /v1/evidence", "GET /v1/oidc/client-check", "POST /v1/oidc/token",
                                "GET /v1/oidc/keys", "POST /v1/revocations"])
        try await h.shutdown()
    }

    func testProcessHardeningApplies() {
        XCTAssertTrue(AuthorityProcessHardening.apply())
        XCTAssertTrue(AuthorityProcessHardening.isApplied)
    }

    func testOverridesAreRefusedWhenStrict() async throws {
        var config = try AuthorityConfig.fromEnvironment(Self.strictEnv)
        config.entraDatabase = nil
        let app = try await Application.make(.testing)
        var overrides = AuthorityOverrides()
        overrides.kms = LocalKMS()
        do {
            try await AuthorityApplication.configure(app, config: config, overrides: overrides)
            XCTFail("strict configuration accepted an override or a missing database")
        } catch {}
        try await app.asyncShutdown()
    }
}
