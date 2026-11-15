@preconcurrency import Crypto
import Fluent
import Foundation
import NIOHTTP1
import Vapor
import ViadereAuthorityKit
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// The business-facing relay of the destination-key registration nonce (`POST /v1/business/destination-keys/registration-nonce`; ADR-0031 §1.2,
/// SECURITY.md §2.110 "Registration") against an in-process authority. Each exploit-path test fails if the control it names is removed.
final class AuthDestinationKeyNonceRelayTests: AuthDeliveryTestBase {
    static let path = "/v1/business/destination-keys/registration-nonce"
    static let commit = String(repeating: "c", count: 40)

    struct Registration {
        var key = SoftwareP256SigningKey()
        var kid: String { JWKThumbprint.p256(try! key.publicKey.signingKey()) }
        var jwk: JSONValue {
            let raw = try! key.publicKey.signingKey().rawRepresentation
            return .object(["kty": .string("EC"), "crv": .string("P-256"), "x": .string(Base64URL.encode(raw.prefix(32))), "y": .string(Base64URL.encode(raw.suffix(32)))])
        }
    }

    func relayHarness(_ body: (TestHarness) async throws -> Void) async throws {
        try await harness({ $0.authDelivery.destinationRecordsEnabled = true }, body)
    }

    func setUp(_ h: TestHarness) async throws -> (Scene, AuthLinkRedemptionTests.Authority) {
        let s = try await scene(h)
        let authority = try await AuthLinkRedemptionTests.makeAuthority(businessId: s.b.id.uuid, accountId: s.consumer.id.uuid)
        h.app.authorityTransport = InProcessAuthorityTransport(app: authority.app)
        return (s, authority)
    }

    func tenant(_ h: TestHarness, _ b: TestBusiness) -> String { WebhookService(db: h.db, ctx: h.ctx).tenantId(of: b.id) }

    func admin(_ authority: AuthLinkRedemptionTests.Authority, _ command: String, _ change: [String: JSONValue]) async throws {
        try await AuthorityAdmin.run(command: command, changeFile: try CanonicalJSON.serialize(.object(change)), commit: Self.commit, db: authority.app.db,
                                     config: .testing(), now: AuthLinkRedemptionTests.now)
    }

    /// The first admin run of a registration (`tenant-key-nonce`) for this tenant's key and hosts.
    func issue(_ authority: AuthLinkRedemptionTests.Authority, tenant: String, _ r: Registration, hosts: [String]) async throws {
        try await admin(authority, "tenant-key-nonce", ["tenant_id": .string(tenant), "kid": .string(r.kid), "hosts": .array(hosts.map { .string($0) })])
    }

    func read(_ h: TestHarness, _ b: TestBusiness, kid: String, key: String? = nil) async throws -> HTTPResult {
        try await h.business(b, .POST, Self.path, body: try ViadereJSON.encode(AuthDestinationKeyNonceRequest(kid: kid)), key: key)
    }

    func evidence(_ kid: String, hosts: [String]) -> JSONValue {
        .array(hosts.map { host in
            .object(["host": .string(host), "method": .string("dns_txt"), "dnssec": .string("validated"),
                     "answers": .array(["cloudflare-dns.com", "dns.google"].map { .object(["resolver": .string($0), "records": .array([.string("v=1; kid=\(kid)")])]) })])
        })
    }

    func register(_ authority: AuthLinkRedemptionTests.Authority, tenant: String, _ r: Registration, hosts: [String], pop: String) async throws {
        try await admin(authority, "tenant-key-register", ["tenant_id": .string(tenant), "display_name": .string("Northwind"), "public_key": r.jwk,
                                                          "hosts": .array(hosts.map { .string($0) }),
                                                          "not_after": .integer(Int64(AuthLinkRedemptionTests.now.addingTimeInterval(300 * 86_400).timeIntervalSince1970)),
                                                          "pop": .string(pop), "evidence": evidence(r.kid, hosts: hosts)])
    }

    // MARK: The ceremony

    func testTheBusinessReadsExactlyWhatItsProofSignsAndTheNonceIsAcceptedOnce() async throws {
        try await relayHarness { h in
            let (s, authority) = try await setUp(h)
            let r = Registration(), hosts = ["login.northwind.example"]
            let tenant = tenant(h, s.b)
            try await issue(authority, tenant: tenant, r, hosts: hosts)
            let first = try await read(h, s.b, kid: r.kid)
            XCTAssertEqual(first.status, .ok, first.text)
            XCTAssertEqual(first.headers.first(name: .cacheControl), "no-store")
            // Exactly the members the proof needs, nothing about the tenant's other keys or the change.
            let object = try XCTUnwrap(try JSONSerialization.jsonObject(with: first.body) as? [String: Any])
            XCTAssertEqual(Set(object.keys), ["tenant_id", "aud", "kid", "hosts", "nonce", "expires_at"])
            let answer = try first.json(AuthDestinationKeyNonceResponse.self)
            XCTAssertEqual(answer.tenantId, tenant, "the authenticated key's tenant, never a request member")
            XCTAssertEqual(answer.aud, AuthorityEnvironment.staging.authorityURN)
            XCTAssertEqual(answer.kid, r.kid)
            XCTAssertEqual(answer.hosts, hosts)
            // The business signs the proof with what it read; the reviewed job registers the key and consumes the nonce.
            let pop = try await DestinationKeyRegistration.sign(tenantId: answer.tenantId, hosts: answer.hosts, nonce: answer.nonce, environment: .staging, key: r.key,
                                                                issuedAt: AuthLinkRedemptionTests.now)
            try await register(authority, tenant: tenant, r, hosts: hosts, pop: pop)
            // Single use: the consumed nonce is no longer handed out, and the same proof cannot register again.
            await XCTAssertEqualAsync(try await read(h, s.b, kid: r.kid).status, .notFound)
            do {
                try await register(authority, tenant: tenant, r, hosts: hosts, pop: pop)
                XCTFail("a replayed proof registered again")
            } catch {}
            // Reading is audited (ids and the outcome only, never the nonce).
            let events = try await AuditEventRecord.query(on: h.db).filter(\.$action == "auth_destination_key.registration_nonce").all()
            XCTAssertEqual(events.count, 2)
            XCTAssertFalse(events.contains { $0.metadataJSON.contains(answer.nonce) })
            try await authority.app.asyncShutdown()
        }
    }

    // MARK: Exploit paths

    func testAnotherTenantsNonceIsNeverHandedOut() async throws {
        try await relayHarness { h in
            let (s, authority) = try await setUp(h)
            let r = Registration()
            try await issue(authority, tenant: tenant(h, s.b), r, hosts: ["login.northwind.example"])
            // Another business names this business's key: the authority looks it up under the caller's own tenant and finds nothing.
            let other = try await scene(h, name: "Globex", handle: "globex")
            let refused = try await read(h, other.b, kid: r.kid)
            XCTAssertEqual(refused.status, .notFound)
            XCTAssertFalse(refused.text.contains("nonce"))
            // The tenant cannot be chosen in the body.
            let named = try JSONSerialization.data(withJSONObject: ["kid": r.kid, "tenant_id": tenant(h, s.b)])
            await XCTAssertEqualAsync(try await h.business(other.b, .POST, Self.path, body: named).status, .unprocessableEntity)
            // An unknown key, a malformed kid and an expired nonce get nothing either.
            await XCTAssertEqualAsync(try await read(h, s.b, kid: Registration().kid).status, .notFound)
            await XCTAssertEqualAsync(try await read(h, s.b, kid: "short").status, .unprocessableEntity)
            try await authority.app.asyncShutdown()
        }
    }

    func testOnlyALiveKeyReadsAndTheRelayIsRateLimitedFailClosed() async throws {
        try await relayHarness { h in
            let (s, authority) = try await setUp(h)
            let r = Registration()
            try await issue(authority, tenant: tenant(h, s.b), r, hosts: ["login.northwind.example"])
            let testKey = try await BusinessAPIKeys.issue(businessId: s.b.record.id!, name: "test", live: false, scopes: BusinessAPIKeys.Scope.all,
                                                          capabilities: Capability.operational, now: h.clock.now(), on: h.db).key
            await XCTAssertEqualAsync(try await read(h, s.b, kid: r.kid, key: testKey).status, .forbidden)
            // Per tenant: the burst, then 429 (the namespace fails closed when the shared store is down).
            XCTAssertTrue(DatabaseRateLimitStore.defaultFailClosed.contains { AuthDestinationKeyNonceRelay.rateNamespace.hasPrefix($0) })
            var statuses: [HTTPResponseStatus] = []
            for _ in 0..<8 { statuses.append(try await read(h, s.b, kid: r.kid).status) }
            XCTAssertEqual(statuses.filter { $0 == .ok }.count, 5)
            XCTAssertEqual(statuses.last, .tooManyRequests)
            try await authority.app.asyncShutdown()
        }
    }

    func testTheRelayIsFlagGatedAndFailsClosed() async throws {
        // Off by default.
        try await harness { h in
            let s = try await scene(h)
            await XCTAssertEqualAsync(try await read(h, s.b, kid: Registration().kid).status, .notFound)
        }
        // AUTH_DELIVERY_ENABLED off.
        try await harness({ $0.authDelivery.enabled = false; $0.authDelivery.destinationRecordsEnabled = true }) { h in
            let s = try await scene(h)
            await XCTAssertEqualAsync(try await read(h, s.b, kid: Registration().kid).status, .notFound)
        }
        // (A generous per-tenant limit here: this test is about the gates, not the budget.)
        try await harness({ $0.authDelivery.destinationRecordsEnabled = true; $0.authDelivery.registrationNonceRate = .perMinute(100) }) { h in
            let s = try await scene(h)
            // No authority: 503.
            h.app.authorityTransport = nil
            await XCTAssertEqualAsync(try await read(h, s.b, kid: Registration().kid).status, .serviceUnavailable)
            // The authority's AUTHORITY_TENANT_KEYS_ENABLED off (its route answers 404): nothing to read.
            h.app.authorityTransport = StaticAuthorityTransport(status: 404, body: Data())
            await XCTAssertEqualAsync(try await read(h, s.b, kid: Registration().kid).status, .notFound)
            // An authority answer with an extra member, a short nonce or a bad host is never passed on.
            let nonce = Base64URL.encode(SecureToken.randomBytes(32))
            for body in ["{\"nonce\":\"\(nonce)\",\"hosts\":[\"login.northwind.example\"],\"expires_at\":1,\"tenant_hint\":\"x\"}",
                         "{\"nonce\":\"abc\",\"hosts\":[\"login.northwind.example\"],\"expires_at\":1}",
                         "{\"nonce\":\"\(nonce)\",\"hosts\":[\"https://evil.example/\"],\"expires_at\":1}",
                         "{\"nonce\":\"\(nonce)\",\"hosts\":[],\"expires_at\":1}"] {
                h.app.authorityTransport = StaticAuthorityTransport(status: 200, body: Data(body.utf8))
                await XCTAssertEqualAsync(try await read(h, s.b, kid: Registration().kid).status, .serviceUnavailable)
            }
            // Without an API key: refused.
            await XCTAssertEqualAsync(try await h.request(.POST, Self.path, body: try ViadereJSON.encode(AuthDestinationKeyNonceRequest(kid: Registration().kid))).status,
                                      .unauthorized)
        }
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
