@preconcurrency import Crypto
import _CryptoExtras
import Fluent
import Foundation
import Vapor
import ViadereCore
import ViadereServiceSupport
import XCTest
import XCTVapor
@testable import ViadereAuthorityKit

/// Fixed bearer tokens standing in for Entra tokens (the Entra verifier itself is tested in `AuthorityCallerTests`).
struct StaticCallerVerifier: AuthorityCallerVerifier {
    static let apiToken = "api-token"
    static let workerToken = "worker-token"
    static let apiWithoutRoleToken = "api-without-role"

    func verify(bearer: String) async throws -> AuthorityCaller {
        switch bearer {
        case Self.apiToken: return AuthorityCaller(name: "api", objectId: "00000000-0000-0000-0000-0000000000a1", roles: [AuthorityAppRole.evidenceSubmit.rawValue])
        case Self.workerToken: return AuthorityCaller(name: "worker", objectId: "00000000-0000-0000-0000-0000000000b2", roles: [AuthorityAppRole.revocations.rawValue])
        case Self.apiWithoutRoleToken: return AuthorityCaller(name: "api", objectId: "00000000-0000-0000-0000-0000000000a1", roles: [])
        default: throw AuthorityCallerError.notAllowed
        }
    }
}

final class TestClock: @unchecked Sendable {
    private let lock = NSLock()
    private var value = Date(timeIntervalSince1970: 1_800_000_000)
    var now: Date { lock.withLock { value } }
    func advance(_ seconds: TimeInterval) { lock.withLock { value = value.addingTimeInterval(seconds) } }
}

/// An authority with real keys in a `LocalKMS`, reviewed pins, one OIDC client, one link client and one imported account with a biometric key.
final class AuthorityHarness: @unchecked Sendable {
    static let commit = String(repeating: "a", count: 40)
    static let issuer = "https://id.viadere.test"
    static let clientId = "ocl_testclient"
    static let linkClientId = "lcl_testlink"
    static let redirectURI = "https://rp.example.com/callback"
    static let returnURL = "https://shop.example.com/auth/return"
    static let businessId = UUID(uuidString: "6F9619FF-8B86-D011-B42D-00C04FC964FF")!

    let app: Application
    let kms = LocalKMS()
    let clock = TestClock()
    let clientKey = P256.Signing.PrivateKey()
    let accountId = UUID()
    let biometricKey = SoftwareP256SigningKey()
    let presenceKey = SoftwareP256SigningKey()
    /// A discoverable passkey of the imported account for the RP id `viadere.test` (the passkey method, ADR-0024 §4 method 1).
    let passkey: PasskeyCredential = try! WebAuthnAuthenticator.makeCredential(
        rpId: "viadere.test", userHandle: Data([7, 7, 7, 7]), userName: "account", clientDataHash: Data(repeating: 1, count: 32), requireUserVerification: true,
        userVerified: true, backedUp: true, now: Date(timeIntervalSince1970: 1_800_000_000)).credential
    var config: AuthorityConfig
    var statementKey: P256.Signing.PublicKey!
    var oidcRSAKey: _RSA.Signing.PublicKey!
    var oidcESKey: P256.Signing.PublicKey!
    var grantKey: P256.Signing.PublicKey!

    struct Options {
        var enabled = true
        var oidc = true
        var pinStatementInApp = true
        var skipPin: String?
        var wrongThumbprintFor: String?
        var clientExtras: [String: JSONValue] = [:]
        var idTokenAlg = "RS256"
    }

    static func make(_ options: Options = Options()) async throws -> AuthorityHarness {
        let harness = try await AuthorityHarness(options: options)
        return harness
    }

    private init(options: Options) async throws {
        config = AuthorityConfig.testing()
        config.enabled = options.enabled
        config.oidcEnabled = options.oidc
        config.issuer = Self.issuer
        if let url = ProcessInfo.processInfo.environment["TEST_AUTHORITY_DATABASE_URL"], !url.isEmpty { config.databaseURL = url }
        app = try await Application.make(.testing)
        try kms.createRSASigningKey("oidc-signing-rs256", key: try _RSA.Signing.PrivateKey(keySize: .bits2048))
        kms.createSigningKey("oidc-signing-es256")
        kms.createSigningKey("grant-signing")
        kms.createSigningKey("device-statement-signing")
        statementKey = try await kms.publicKey(keyRef: "device-statement-signing")
        oidcESKey = try await kms.publicKey(keyRef: "oidc-signing-es256")
        grantKey = try await kms.publicKey(keyRef: "grant-signing")
        oidcRSAKey = try await kms.rsaPublicKey(keyRef: "oidc-signing-rs256")
        if options.pinStatementInApp { config.developmentStatementPins = [JWKThumbprint.p256(statementKey)] }

        var pins: [(String, String, String)] = []
        for name in ["grant-signing", "oidc-signing-es256", "device-statement-signing"] where name != options.skipPin {
            let version = String(try await kms.resolveVersion(keyRef: name).split(separator: "/")[1])
            var thumb = JWKThumbprint.p256(try await kms.publicKey(keyRef: name))
            if options.wrongThumbprintFor == name { thumb = JWKThumbprint.p256(P256.Signing.PrivateKey().publicKey) }
            pins.append((name, version, thumb))
        }
        if options.skipPin != "oidc-signing-rs256" {
            let version = String(try await kms.resolveVersion(keyRef: "oidc-signing-rs256").split(separator: "/")[1])
            let p = try oidcRSAKey.getKeyPrimitives()
            pins.append(("oidc-signing-rs256", version, JWKThumbprint.rsa(modulus: p.modulus, exponent: p.publicExponent)))
        }

        var clientChange: [String: JSONValue] = [
            "client_id": .string(Self.clientId), "tenant_id": .string("tnt_test"), "display_name": .string("Example Shop"),
            "redirect_uris": .array([.string(Self.redirectURI)]), "post_logout_redirect_uris": .array([.string("https://rp.example.com/bye")]),
            "jwks": .object(["keys": .array([.object(JWKThumbprint.p256JWK(clientKey.publicKey).merging(["kid": .string("client-key-1")]) { $1 })])]),
            "id_token_signed_response_alg": .string(options.idTokenAlg),
        ]
        for (k, v) in options.clientExtras { clientChange[k] = v }
        let linkChange: [String: JSONValue] = [
            "client_id": .string(Self.linkClientId), "tenant_id": .string("tnt_test"), "business_id": .string(Self.businessId.uuidString),
            "tenant_name": .string("Example Shop"), "display_name": .string("Example Shop sign-in"), "return_urls": .array([.string(Self.returnURL)]),
        ]
        let importChange: JSONValue = .object(["accounts": .array([.object([
            "account_id": .string(accountId.uuidString),
            "keys": .array([
                .object(["public_key": .string(biometricKey.publicKey.base64URL), "key_purpose": .string("approvalBiometric"), "hardware_attested": .bool(true)]),
                .object(["public_key": .string(presenceKey.publicKey.base64URL), "key_purpose": .string("approvalUserPresence")]),
            ]),
            "passkeys": .array([.object(["credential_id": .string(Base64URL.encode(passkey.credentialId)),
                                         "public_key": .string(Base64URL.encode(try passkey.cosePublicKey()))])]),
        ])])])
        let config = self.config
        let clock = self.clock
        var overrides = AuthorityOverrides()
        overrides.kms = kms
        overrides.callerVerifier = StaticCallerVerifier()
        overrides.clock = { clock.now }
        let commit = Self.commit
        let pinList = pins, clientRegistration = clientChange
        overrides.prepare = { db in
            for (name, version, thumb) in pinList {
                try await AuthorityAdmin.run(command: "key-version-pin", changeFile: try CanonicalJSON.serialize(.object(["name": .string(name), "version": .string(version), "thumbprint": .string(thumb)])),
                                             commit: commit, db: db, config: config, now: clock.now)
            }
            try await AuthorityAdmin.run(command: "client-register", changeFile: try CanonicalJSON.serialize(.object(clientRegistration)), commit: commit, db: db, config: config, now: clock.now)
            try await AuthorityAdmin.run(command: "link-client-register", changeFile: try CanonicalJSON.serialize(.object(linkChange)), commit: commit, db: db, config: config, now: clock.now)
            try await AuthorityAdmin.run(command: "keylog-import", changeFile: try CanonicalJSON.serialize(importChange), commit: commit, db: db, config: config, now: clock.now)
        }
        do {
            try await AuthorityApplication.configure(app, config: config, overrides: overrides, migrateInMemory: true)
        } catch {
            try? await app.asyncShutdown()
            throw error
        }
    }

    func shutdown() async throws { try await app.asyncShutdown() }

    // MARK: Calls

    func call(_ method: HTTPMethod, _ path: String, token: String? = StaticCallerVerifier.apiToken, json: Data? = nil, form: String? = nil) async throws -> (status: HTTPStatus, body: Data) {
        var status: HTTPStatus = .internalServerError
        var body = Data()
        try await app.test(method, path, beforeRequest: { req in
            if let token { req.headers.bearerAuthorization = BearerAuthorization(token: token) }
            if let json { req.headers.contentType = .json; req.body = ByteBuffer(data: json) }
            if let form { req.headers.contentType = .urlEncodedForm; req.body = ByteBuffer(string: form) }
        }, afterResponse: { res async in
            status = res.status
            body = Data(buffer: res.body)
        })
        return (status, body)
    }

    func createOIDCChallenge(verifier: String = AuthorityHarness.codeVerifier, nonce: String = "n-0S6_WzA2Mj", redirectURI: String = AuthorityHarness.redirectURI,
                             acr: [String]? = nil) async throws -> (status: HTTPStatus, response: AuthorityChallengeCreateResponse?) {
        let body = AuthorityChallengeCreateRequest(purpose: .oidcLogin, oidc: .init(clientId: Self.clientId, redirectURI: redirectURI,
                                                                                    codeChallenge: Self.challenge(for: verifier), codeChallengeMethod: "S256",
                                                                                    nonce: nonce, acrValues: acr))
        let result = try await call(.POST, AuthorityRoute.challenges, json: try ViadereJSON.encode(body))
        return (result.status, result.status == .created ? try ViadereJSON.decode(AuthorityChallengeCreateResponse.self, from: result.body) : nil)
    }

    func createLinkChallenge(crossDevice: Bool) async throws -> AuthorityChallengeCreateResponse {
        let body = AuthorityChallengeCreateRequest(purpose: .linkOpen, link: .init(linkClientId: Self.linkClientId, returnURL: Self.returnURL,
                                                                                   deliveryId: AuthDeliveryID().description, codeChallenge: Self.challenge(for: Self.codeVerifier),
                                                                                   purpose: "sign_in", crossDevice: crossDevice))
        let result = try await call(.POST, AuthorityRoute.challenges, json: try ViadereJSON.encode(body))
        XCTAssertEqual(result.status, .created, String(decoding: result.body, as: UTF8.self))
        return try ViadereJSON.decode(AuthorityChallengeCreateResponse.self, from: result.body)
    }

    /// The device side: verify the statement against the pinned key, then sign a factor assertion over its display.
    func answer(_ challenge: AuthorityChallengeCreateResponse, key: (any DeviceSigningKey)? = nil, uv: FactorUserVerification = .biometric,
                match: String?? = nil, decision: FactorDecision = .approve, codeHash: String? = nil,
                mutate: ((inout FactorAssertionClaims) -> Void)? = nil) async throws -> String {
        let statement = try AuthorityStatementVerifier.verifyChallenge(challenge.statement, pinnedKeys: [statementKey], environment: .staging, now: clock.now)
        var claims = try FactorAssertionClaims.answering(statement, decision: decision, userVerification: uv,
                                                         match: decision == .approve ? (match ?? challenge.matchCode) : nil, codeHash: codeHash, now: clock.now)
        mutate?(&claims)
        return try await FactorAssertion.sign(claims, with: key ?? biometricKey)
    }

    func submit(_ factor: String, accountId: UUID? = nil, token: String = StaticCallerVerifier.apiToken) async throws -> (status: HTTPStatus, response: AuthorityEvidenceResponse?) {
        let result = try await call(.POST, AuthorityRoute.evidence, token: token, json: try ViadereJSON.encode(AuthorityEvidenceRequest(factor: factor, accountId: accountId)))
        return (result.status, result.status == .ok ? try ViadereJSON.decode(AuthorityEvidenceResponse.self, from: result.body) : nil)
    }

    // MARK: OIDC client side

    static let codeVerifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    static func challenge(for verifier: String) -> String { Base64URL.encode(Data(SHA256.hash(data: Data(verifier.utf8)))) }

    func clientAssertion(aud: JSONValue = .string(AuthorityHarness.issuer), iss: String = AuthorityHarness.clientId, kid: String = "client-key-1",
                         alg: String = "ES256", jti: String = UUID().uuidString, lifetime: Int64 = 120, extraHeader: [String: JSONValue] = [:],
                         signer: P256.Signing.PrivateKey? = nil) throws -> String {
        let t = Int64(clock.now.timeIntervalSince1970)
        var header: [String: JSONValue] = ["alg": .string(alg), "kid": .string(kid), "typ": .string("JWT")]
        for (k, v) in extraHeader { header[k] = v }
        let payload: [String: JSONValue] = ["iss": .string(iss), "sub": .string(iss), "aud": aud, "jti": .string(jti), "iat": .integer(t), "exp": .integer(t + lifetime)]
        let input = Base64URL.encode(try CanonicalJSON.serialize(.object(header))) + "." + Base64URL.encode(try CanonicalJSON.serialize(.object(payload)))
        let signature = try (signer ?? clientKey).signature(for: Data(input.utf8))
        return input + "." + Base64URL.encode(signature.rawRepresentation)
    }

    static func form(_ items: [(String, String)]) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return items.map { "\($0.0)=\($0.1.addingPercentEncoding(withAllowedCharacters: allowed)!)" }.joined(separator: "&")
    }

    func tokenForm(code: String, verifier: String = AuthorityHarness.codeVerifier, redirectURI: String = AuthorityHarness.redirectURI, assertion: String? = nil) throws -> String {
        Self.form([("grant_type", "authorization_code"), ("code", code), ("redirect_uri", redirectURI), ("code_verifier", verifier),
                   ("client_assertion_type", OIDCProfile.clientAssertionType), ("client_assertion", try assertion ?? clientAssertion())])
    }

    /// The full app path: challenge, device approval, code.
    func approvedCode() async throws -> String {
        let challenge = try await createOIDCChallenge().response!
        let result = try await submit(try await answer(challenge), accountId: accountId)
        XCTAssertEqual(result.status, .ok)
        return result.response!.code!
    }
}

/// `XCTAssertEqual` for an `async` expression (XCTest's autoclosures are synchronous).
func XCTAssertEqualAsync<T: Equatable>(_ expression: @autoclosure () async throws -> T, _ expected: @autoclosure () throws -> T,
                                       _ message: String = "", file: StaticString = #filePath, line: UInt = #line) async {
    do {
        let value = try await expression()
        XCTAssertEqual(value, try expected(), message, file: file, line: line)
    } catch {
        XCTFail("threw \(error)", file: file, line: line)
    }
}

extension Dictionary where Key == String, Value == JSONValue {
    func merging(_ other: [String: JSONValue]) -> [String: JSONValue] { merging(other) { $1 } }
}
