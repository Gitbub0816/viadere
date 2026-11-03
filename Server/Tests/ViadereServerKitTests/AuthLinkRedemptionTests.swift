@preconcurrency import Crypto
import _CryptoExtras
import Fluent
import Foundation
import NIOHTTP1
import Vapor
import ViadereAuthorityKit
import ViadereCore
import ViadereServiceSupport
import XCTest
import XCTVapor
@testable import ViadereServerKit

/// The device's enrollment confirmation against an in-process authority (ADR-0032 §1.4): imported keys become grant-capable only after it.
enum AuthorityEnrollment {
    static func post(_ app: Application, _ path: String, _ object: [String: JSONValue]) async throws -> [String: JSONValue] {
        let result = try await InProcessAuthorityTransport(app: app).send(method: .POST, path: path, contentType: "application/json",
                                                                          body: try CanonicalJSON.serialize(.object(object)))
        guard result.status == 200, case .object(let o)? = try? JSONDecoder().decode(JSONValue.self, from: result.body) else {
            throw Abort(.internalServerError, reason: "authority \(path): \(result.status) \(String(decoding: result.body, as: UTF8.self))")
        }
        return o
    }

    static func confirm(app: Application, statementKey: P256.Signing.PublicKey, accountId: UUID, keys: [SoftwareP256SigningKey], now: Date) async throws {
        let kids = keys.map { KeyIdentifier.make(try! $0.publicKey.signingKey()) }
        let headText = try await post(app, AuthorityKeyLogRoute.head, ["account_id": .string(accountId.uuidString)])["head"]!.stringValue!
        let head = try AuthorityStatementVerifier.verifyHead(headText, pinnedKeys: [statementKey], environment: .staging, ownKids: kids, minimumSeq: 0, now: now)
        try AuthorityStatementVerifier.requireExactEntry(head, ownKids: kids)
        let created = try await post(app, AuthorityKeyLogRoute.challenges, ["purpose": .string("enrollment_confirmed"), "account_id": .string(accountId.uuidString),
                                                                           "kids": .array(kids.map { .string($0) })])
        let statement = try AuthorityStatementVerifier.verifyChallenge(created["statement"]!.stringValue!, pinnedKeys: [statementKey], environment: .staging, now: now)
        var claims = try FactorAssertionClaims.answering(statement, decision: .approve, userVerification: .biometric, match: nil, now: now)
        claims.headHash = head.headHash
        claims.seq = head.seq
        let factor = try await FactorAssertion.sign(claims, with: keys[0])
        var pops: [JSONValue] = []
        for (key, kid) in zip(keys, kids) {
            let pop = try await AuthorityKeyLogFormat.signPoP(key, message: AuthorityKeyLogFormat.popMessage(environment: .staging, type: "enrollment_confirmed", kid: kid,
                                                                                                             nonce: head.headHash))
            pops.append(.object(["kid": .string(kid), "pop": .string(pop)]))
        }
        _ = try await post(app, AuthorityKeyLogRoute.evidence, ["factor": .string(factor), "pops": .array(pops)])
    }
}

/// `POST /v1/business/auth-links/redeem` (ADR-0021 §5.4; ledger S6-05): the api relays with the authenticated business; the grant exists only at
/// redemption and only for the business the link client belongs to.
final class AuthLinkRedemptionTests: XCTestCase {
    static let linkClient = "lcl_redeemtest"
    static let returnURL = "https://shop.example.com/auth/return"
    static let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    static let now = Date(timeIntervalSince1970: 1_800_000_000)

    struct Authority {
        let app: Application
        let statementKey: P256.Signing.PublicKey
        let grantKey: P256.Signing.PublicKey
        let deviceKey: SoftwareP256SigningKey
    }

    func makeAuthority(businessId: UUID, accountId: UUID) async throws -> Authority {
        let kms = LocalKMS()
        for name in ["grant-signing", "device-statement-signing"] { kms.createSigningKey(name) }
        let statementKey = try await kms.publicKey(keyRef: "device-statement-signing"), grantKey = try await kms.publicKey(keyRef: "grant-signing")
        var config = AuthorityConfig.testing()
        config.oidcEnabled = false
        config.developmentStatementPins = [JWKThumbprint.p256(statementKey)]
        var pins: [JSONValue] = []
        for name in ["grant-signing", "device-statement-signing"] {
            let version = String(try await kms.resolveVersion(keyRef: name).split(separator: "/")[1])
            pins.append(.object(["name": .string(name), "version": .string(version), "thumbprint": .string(JWKThumbprint.p256(try await kms.publicKey(keyRef: name)))]))
        }
        let deviceKey = SoftwareP256SigningKey()
        let link: JSONValue = .object(["client_id": .string(Self.linkClient), "tenant_id": .string("tnt"), "business_id": .string(businessId.uuidString),
                                       "tenant_name": .string("Example Shop"), "display_name": .string("Example Shop sign-in"), "return_urls": .array([.string(Self.returnURL)])])
        let keys: JSONValue = .object(["accounts": .array([.object(["account_id": .string(accountId.uuidString),
            "keys": .array([.object(["public_key": .string(deviceKey.publicKey.base64URL), "key_purpose": .string("approvalBiometric")])])])])])
        let commit = String(repeating: "c", count: 40)
        var overrides = AuthorityOverrides()
        overrides.kms = kms
        overrides.callerVerifier = APICaller()
        overrides.clock = { Self.now }
        let frozen = config, pinList = pins
        overrides.prepare = { db in
            for pin in pinList { try await AuthorityAdmin.run(command: "key-version-pin", changeFile: try CanonicalJSON.serialize(pin), commit: commit, db: db, config: frozen) }
            try await AuthorityAdmin.run(command: "link-client-register", changeFile: try CanonicalJSON.serialize(link), commit: commit, db: db, config: frozen)
            try await AuthorityAdmin.run(command: "keylog-import", changeFile: try CanonicalJSON.serialize(keys), commit: commit, db: db, config: frozen)
        }
        let app = try await Application.make(.testing)
        try await AuthorityApplication.configure(app, config: config, overrides: overrides, migrateInMemory: true)
        try await AuthorityEnrollment.confirm(app: app, statementKey: statementKey, accountId: accountId, keys: [deviceKey], now: Self.now)
        return Authority(app: app, statementKey: statementKey, grantKey: grantKey, deviceKey: deviceKey)
    }

    /// The device path (relayed by the api in production): challenge with the authority-built display, then a same-device factor with a code hash.
    func approveSameDevice(_ authority: Authority, code: String) async throws -> String {
        let request = AuthorityChallengeCreateRequest(purpose: .linkOpen, link: .init(linkClientId: Self.linkClient, returnURL: Self.returnURL,
            deliveryId: AuthDeliveryID().description, codeChallenge: Base64URL.encode(Data(SHA256.hash(data: Data(Self.verifier.utf8)))), purpose: "sign_in", crossDevice: false))
        let created = try await InProcessAuthorityTransport(app: authority.app).send(method: .POST, path: AuthorityRoute.challenges, contentType: "application/json",
                                                                                    body: try ViadereJSON.encode(request))
        XCTAssertEqual(created.status, 201)
        let response = try ViadereJSON.decode(AuthorityChallengeCreateResponse.self, from: created.body)
        let statement = try AuthorityStatementVerifier.verifyChallenge(response.statement, pinnedKeys: [authority.statementKey], environment: .staging, now: Self.now)
        let claims = try FactorAssertionClaims.answering(statement, decision: .approve, userVerification: .biometric, match: nil,
                                                         codeHash: Base64URL.encode(Data(SHA256.hash(data: Data(code.utf8)))), now: Self.now)
        let evidence = try await InProcessAuthorityTransport(app: authority.app).send(method: .POST, path: AuthorityRoute.evidence, contentType: "application/json",
            body: try ViadereJSON.encode(AuthorityEvidenceRequest(factor: try await FactorAssertion.sign(claims, with: authority.deviceKey))))
        XCTAssertEqual(evidence.status, 200, String(decoding: evidence.body, as: UTF8.self))
        return response.challengeId
    }

    func testRedemptionIsOffByDefaultAndFailsClosedWithoutAnAuthority() async throws {
        try await withHarness { h in
            let shop = try await h.makeBusiness(name: "Shop", handle: "acmeoff")
            let body = try ViadereJSON.encode(AuthLinkRedeemRequest(linkClientId: Self.linkClient, code: Base64URL.encode(SecureToken.randomBytes(32)), codeVerifier: Self.verifier))
            await XCTAssertEqualAsync(try await h.business(shop, .POST, "/v1/business/auth-links/redeem", body: body).status, .notFound)
        }
        try await withHarness({ $0.authDelivery.linkServiceEnabled = true }) { h in
            let shop = try await h.makeBusiness(name: "Shop", handle: "acmeclosed")
            let body = try ViadereJSON.encode(AuthLinkRedeemRequest(linkClientId: Self.linkClient, code: Base64URL.encode(SecureToken.randomBytes(32)), codeVerifier: Self.verifier))
            await XCTAssertEqualAsync(try await h.business(shop, .POST, "/v1/business/auth-links/redeem", body: body).status, .serviceUnavailable)
        }
    }

    func testTheBusinessRedeemsOnceAndAnotherBusinessCannot() async throws {
        let box = Box<Authority>()
        try await withHarness({ $0.authDelivery.linkServiceEnabled = true }) { h in
            let shop = try await h.makeBusiness(name: "Shop", handle: "acmelink")
            let other = try await h.makeBusiness(name: "Other", handle: "globexlink")
            let authority = try await self.makeAuthority(businessId: shop.id.uuid, accountId: UUID())
            box.value = authority
            h.app.authorityTransport = InProcessAuthorityTransport(app: authority.app)
            let code = Base64URL.encode(SecureToken.randomBytes(32))
            _ = try await self.approveSameDevice(authority, code: code)
            let body = try ViadereJSON.encode(AuthLinkRedeemRequest(linkClientId: Self.linkClient, code: code, codeVerifier: Self.verifier))
            // Another tenant's API key: the authority compares the authenticated business with its client record.
            await XCTAssertEqualAsync(try await h.business(other, .POST, "/v1/business/auth-links/redeem", body: body).status, .badRequest)
            // A body with a member the api would not relay is refused before anything reaches the authority.
            var raw = try JSONDecoder().decode(JSONValue.self, from: body).objectValue!
            raw["business_id"] = .string(other.id.uuid.uuidString)
            await XCTAssertEqualAsync(try await h.business(shop, .POST, "/v1/business/auth-links/redeem", body: try CanonicalJSON.serialize(.object(raw))).status, .unprocessableEntity)
            let ok = try await h.business(shop, .POST, "/v1/business/auth-links/redeem", body: body)
            XCTAssertEqual(ok.status, .ok, ok.text)
            let grant = try ok.json(AuthLinkRedeemResponse.self).grant
            let claims = try AuthorityGrantVerifier.verify(grant, keys: [JWKThumbprint.p256(authority.grantKey): authority.grantKey], issuer: "https://id.viadere.test/grant",
                                                           audience: Self.linkClient, codeChallenge: Base64URL.encode(Data(SHA256.hash(data: Data(Self.verifier.utf8)))),
                                                           now: Self.now)
            XCTAssertEqual(claims.tenantId, "tnt")
            // Single use.
            await XCTAssertEqualAsync(try await h.business(shop, .POST, "/v1/business/auth-links/redeem", body: body).status, .badRequest)
        }
        try await box.value?.app.asyncShutdown()
    }

    func testExpiredOIDCAuthorizationsArePurgedByTheBackgroundTick() async throws {
        try await withHarness { h in
            let row = OIDCAuthorizationRecord()
            row.bindingHash = "b"
            row.csrfHash = "c"
            row.clientId = "ocl_x"
            row.clientName = "X"
            row.redirectURI = "https://rp.example.com/cb"
            row.nonce = "n"
            row.codeChallenge = "cc"
            row.status = "approved"
            row.code = "a-code-that-must-not-outlive-the-row"
            row.createdAt = h.clock.now()
            row.expiresAt = h.clock.now().addingTimeInterval(600)
            try await row.create(on: h.db)
            await XCTAssertEqualAsync(try await OIDCRetention.purge(on: h.db, now: h.clock.now()), 0)
            await XCTAssertEqualAsync(try await OIDCRetention.purge(on: h.db, now: h.clock.now().addingTimeInterval(601)), 1)
            await XCTAssertEqualAsync(try await OIDCAuthorizationRecord.query(on: h.db).count(), 0)
        }
    }

    func testLinkServiceFlagParsing() throws {
        var config = ServerConfig.testing()
        try config.applyAuthDeliveryEnvironment([:], production: false)
        XCTAssertFalse(config.authDelivery.linkServiceEnabled)
        try config.applyAuthDeliveryEnvironment(["AUTH_LINK_SERVICE_ENABLED": "true"], production: false)
        XCTAssertTrue(config.authDelivery.linkServiceEnabled)
        XCTAssertThrowsError(try config.applyAuthDeliveryEnvironment(["AUTH_LINK_SERVICE_ENABLED": "yes"], production: false))
    }
}

fileprivate func XCTAssertEqualAsync<T: Equatable>(_ expression: @autoclosure () async throws -> T, _ expected: @autoclosure () throws -> T,
                                                  file: StaticString = #filePath, line: UInt = #line) async {
    do {
        let value = try await expression()
        XCTAssertEqual(value, try expected(), file: file, line: line)
    } catch {
        XCTFail("threw \(error)", file: file, line: line)
    }
}
