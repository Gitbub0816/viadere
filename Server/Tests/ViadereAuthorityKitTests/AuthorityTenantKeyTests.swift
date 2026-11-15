@preconcurrency import Crypto
import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereAuthorityKit

/// Tenant destination keys at the authority (ADR-0031 §1, §2; ST-AUTH-16, ST-ML-12). Each exploit-path test fails if its control is removed.
final class AuthorityTenantKeyTests: XCTestCase {
    static let tenant = "ten_acme"
    static let hosts = ["login.acme.com", "www.acme.com"]

    struct Registration {
        var key = SoftwareP256SigningKey()
        var kid: String { JWKThumbprint.p256(try! key.publicKey.signingKey()) }
        var jwk: JSONValue {
            let raw = try! key.publicKey.signingKey().rawRepresentation
            return .object(["kty": .string("EC"), "crv": .string("P-256"), "x": .string(Base64URL.encode(raw.prefix(32))), "y": .string(Base64URL.encode(raw.suffix(32)))])
        }
    }

    func admin(_ h: AuthorityHarness, _ command: String, _ change: [String: JSONValue]) async throws {
        try await AuthorityAdmin.run(command: command, changeFile: try CanonicalJSON.serialize(.object(change)), commit: AuthorityHarness.commit, db: h.app.db,
                                     config: h.config, now: h.clock.now)
    }

    func evidence(_ kid: String, hosts: [String] = AuthorityTenantKeyTests.hosts, dnssec: String = "validated", resolvers: [String] = ["cloudflare-dns.com", "dns.google"],
                  value: String? = nil) -> JSONValue {
        .array(hosts.map { host in
            .object(["host": .string(host), "method": .string("dns_txt"), "dnssec": .string(dnssec),
                     "answers": .array(resolvers.map { .object(["resolver": .string($0), "records": .array([.string(value ?? "v=1; kid=\(kid)")])]) })])
        })
    }

    /// Issues the nonce (first admin run) and returns it as the tenant reads it.
    func issueNonce(_ h: AuthorityHarness, _ r: Registration, hosts: [String] = AuthorityTenantKeyTests.hosts) async throws -> String {
        try await admin(h, "tenant-key-nonce", ["tenant_id": .string(Self.tenant), "kid": .string(r.kid), "hosts": .array(hosts.map { .string($0) })])
        let read = try await h.call(.POST, AuthorityTenantKeyRoute.registrationNonce, json: try CanonicalJSON.serialize(.object(["tenant_id": .string(Self.tenant), "kid": .string(r.kid)])))
        XCTAssertEqual(read.status, .ok)
        guard case .object(let o)? = try? JSONDecoder().decode(JSONValue.self, from: read.body), let nonce = o["nonce"]?.stringValue else { throw Abort(.internalServerError) }
        return nonce
    }

    func change(_ h: AuthorityHarness, _ r: Registration, pop: String, hosts: [String] = AuthorityTenantKeyTests.hosts, notAfter: Date? = nil,
                evidence: JSONValue? = nil) -> [String: JSONValue] {
        ["tenant_id": .string(Self.tenant), "display_name": .string("Acme Bank"), "public_key": r.jwk, "hosts": .array(hosts.map { .string($0) }),
         "not_after": .integer(Int64((notAfter ?? h.clock.now.addingTimeInterval(300 * 86_400)).timeIntervalSince1970)), "pop": .string(pop),
         "evidence": evidence ?? self.evidence(r.kid, hosts: hosts)]
    }

    func register(_ h: AuthorityHarness, _ r: Registration = Registration()) async throws {
        let nonce = try await issueNonce(h, r)
        let pop = try await DestinationKeyRegistration.sign(tenantId: Self.tenant, hosts: Self.hosts, nonce: nonce, environment: .staging, key: r.key, issuedAt: h.clock.now)
        try await admin(h, "tenant-key-register", change(h, r, pop: pop))
    }

    func assertRefused(_ h: AuthorityHarness, _ command: String, _ change: [String: JSONValue], _ message: String, file: StaticString = #filePath, line: UInt = #line) async {
        do {
            try await admin(h, command, change)
            XCTFail("\(message): accepted", file: file, line: line)
        } catch {
            XCTAssertTrue(error is AuthorityAdmin.Failure, "\(message): \(error)", file: file, line: line)
        }
    }

    func record(_ h: AuthorityHarness, tenant: String = AuthorityTenantKeyTests.tenant, token: String? = StaticCallerVerifier.apiToken) async throws -> (status: HTTPStatus, record: String?, list: String?) {
        let result = try await h.call(.POST, AuthorityTenantKeyRoute.record, token: token, json: try CanonicalJSON.serialize(.object(["tenant_id": .string(tenant)])))
        guard result.status == .ok, case .object(let o)? = try? JSONDecoder().decode(JSONValue.self, from: result.body) else { return (result.status, nil, nil) }
        return (result.status, o["record"]?.stringValue, o["revocation_list"]?.stringValue)
    }

    func verified(_ h: AuthorityHarness, _ compact: String?) throws -> AuthorityTenantRecord {
        try AuthorityStatementVerifier.verifyTenantRecord(try XCTUnwrap(compact), pinnedKeys: [h.statementKey], environment: .staging, tenantId: Self.tenant,
                                                         minimumSeq: 0, now: h.clock.now)
    }

    // MARK: Registration (ST-AUTH-16)

    func testARegisteredKeyIsServedInARecordTheDeviceVerifies() async throws {
        let h = try await AuthorityHarness.make()
        let r = Registration()
        try await register(h, r)
        let served = try await record(h)
        let record = try verified(h, served.record)
        XCTAssertEqual(record.keys.map(\.kid), [r.kid])
        XCTAssertEqual(record.allowedHosts, Self.hosts)
        XCTAssertEqual(record.displayName, "Acme Bank")
        XCTAssertEqual(record.seq, 1)
        XCTAssertNil(served.list, "nothing is revoked")
        try await h.shutdown()
    }

    func testRegistrationWithoutAValidProofOfPossessionIsRefused() async throws {
        let h = try await AuthorityHarness.make()
        let r = Registration()
        let nonce = try await issueNonce(h, r)
        // AS-1 sits between the dashboard and the operator and substitutes its own key: the proof is by another key than the one submitted.
        let forged = try await DestinationKeyRegistration.sign(tenantId: Self.tenant, hosts: Self.hosts, nonce: nonce, environment: .staging, key: SoftwareP256SigningKey(),
                                                               issuedAt: h.clock.now)
        await assertRefused(h, "tenant-key-register", change(h, r, pop: forged), "PoP by another key")
        await assertRefused(h, "tenant-key-register", change(h, r, pop: "x.y.z"), "garbage PoP")
        // A proof for another tenant, another audience, or a different host set.
        let otherTenant = try await DestinationKeyRegistration.sign(tenantId: "ten_other", hosts: Self.hosts, nonce: nonce, environment: .staging, key: r.key, issuedAt: h.clock.now)
        await assertRefused(h, "tenant-key-register", change(h, r, pop: otherTenant), "wrong iss")
        let production = try await DestinationKeyRegistration.sign(tenantId: Self.tenant, hosts: Self.hosts, nonce: nonce, environment: .production, key: r.key, issuedAt: h.clock.now)
        await assertRefused(h, "tenant-key-register", change(h, r, pop: production), "wrong aud")
        let fewer = try await DestinationKeyRegistration.sign(tenantId: Self.tenant, hosts: [Self.hosts[0]], nonce: nonce, environment: .staging, key: r.key, issuedAt: h.clock.now)
        await assertRefused(h, "tenant-key-register", change(h, r, pop: fewer), "hosts[] differs from the change file")
        // Expired and future-dated proofs.
        let old = try await DestinationKeyRegistration.sign(tenantId: Self.tenant, hosts: Self.hosts, nonce: nonce, environment: .staging, key: r.key,
                                                            issuedAt: h.clock.now.addingTimeInterval(-7200))
        await assertRefused(h, "tenant-key-register", change(h, r, pop: old), "expired PoP")
        let future = try await DestinationKeyRegistration.sign(tenantId: Self.tenant, hosts: Self.hosts, nonce: nonce, environment: .staging, key: r.key,
                                                               issuedAt: h.clock.now.addingTimeInterval(120))
        await assertRefused(h, "tenant-key-register", change(h, r, pop: future), "future-dated PoP")
        // A nonce the job never issued.
        let invented = try await DestinationKeyRegistration.sign(tenantId: Self.tenant, hosts: Self.hosts, nonce: Base64URL.encode(SecureToken.randomBytes(32)),
                                                                 environment: .staging, key: r.key, issuedAt: h.clock.now)
        await assertRefused(h, "tenant-key-register", change(h, r, pop: invented), "invented nonce")
        // None of the refused attempts burned the real nonce: the genuine proof still registers.
        let genuine = try await DestinationKeyRegistration.sign(tenantId: Self.tenant, hosts: Self.hosts, nonce: nonce, environment: .staging, key: r.key, issuedAt: h.clock.now)
        try await admin(h, "tenant-key-register", change(h, r, pop: genuine))
        let count = try await AuthorityTenantKeyRow.query(on: h.app.db).count()
        XCTAssertEqual(count, 1)
        try await h.shutdown()
    }

    func testRegistrationReplayingAProofOfPossessionNonceIsRefused() async throws {
        let h = try await AuthorityHarness.make()
        let r = Registration()
        let nonce = try await issueNonce(h, r)
        let pop = try await DestinationKeyRegistration.sign(tenantId: Self.tenant, hosts: Self.hosts, nonce: nonce, environment: .staging, key: r.key, issuedAt: h.clock.now)
        try await admin(h, "tenant-key-register", change(h, r, pop: pop))
        // The same reviewed change file run again (or the same proof in a renewal): the nonce was consumed.
        await assertRefused(h, "tenant-key-register", change(h, r, pop: pop), "replayed nonce")
        // An expired nonce is refused too.
        let late = Registration()
        let lateNonce = try await issueNonce(h, late)
        h.clock.advance(AuthorityAdmin.registrationNonceLifetime + 1)
        let latePop = try await DestinationKeyRegistration.sign(tenantId: Self.tenant, hosts: Self.hosts, nonce: lateNonce, environment: .staging, key: late.key, issuedAt: h.clock.now)
        await assertRefused(h, "tenant-key-register", change(h, late, pop: latePop), "expired nonce")
        try await h.shutdown()
    }

    func testRegistrationNeedsTheThumbprintInTheAttestedEvidenceForEveryHostAndAThirteenMonthLimit() async throws {
        let h = try await AuthorityHarness.make()
        let r = Registration()
        let nonce = try await issueNonce(h, r)
        let pop = try await DestinationKeyRegistration.sign(tenantId: Self.tenant, hosts: Self.hosts, nonce: nonce, environment: .staging, key: r.key, issuedAt: h.clock.now)
        let other = JWKThumbprint.p256(P256.Signing.PrivateKey().publicKey)
        await assertRefused(h, "tenant-key-register", change(h, r, pop: pop, evidence: evidence(r.kid, value: "v=1; kid=\(other)")), "evidence names another key")
        await assertRefused(h, "tenant-key-register", change(h, r, pop: pop, evidence: evidence(r.kid, hosts: [Self.hosts[0]])), "evidence for one host only")
        await assertRefused(h, "tenant-key-register", change(h, r, pop: pop, evidence: evidence(r.kid, dnssec: "bogus")), "DNSSEC-bogus answer")
        await assertRefused(h, "tenant-key-register", change(h, r, pop: pop, evidence: evidence(r.kid, resolvers: ["dns.google"])), "one resolver")
        await assertRefused(h, "tenant-key-register", change(h, r, pop: pop, evidence: evidence(r.kid, resolvers: ["dns.google", "dns.google"])), "the same resolver twice")
        await assertRefused(h, "tenant-key-register", change(h, r, pop: pop, notAfter: AuthorityAdmin.maxNotAfter(h.clock.now).addingTimeInterval(1)), "not_after beyond 13 months")
        // The evidence checks run before the nonce is touched: the proof still registers.
        try await admin(h, "tenant-key-register", change(h, r, pop: pop))
        try await h.shutdown()
    }

    func testTheApiCanNeitherAddAKeyNorAHost() async throws {
        let h = try await AuthorityHarness.make()
        let r = Registration()
        try await register(h, r)
        // No route adds anything (ST-AUTH-16): every guess is 404.
        for path in ["/v1/tenant-keys", "/v1/tenant-keys/register", "/v1/tenant-keys/hosts", "/v1/tenant-keys/record/update"] {
            let attempt = try await h.call(.POST, path, json: try CanonicalJSON.serialize(.object(["tenant_id": .string(Self.tenant), "kid": .string(r.kid)])))
            XCTAssertEqual(attempt.status, .notFound, path)
        }
        // The revocation route is reduce-only: a host that is not listed is not added.
        let add = try await h.call(.POST, AuthorityTenantKeyRoute.revocations,
                                   json: try CanonicalJSON.serialize(.object(["tenant_id": .string(Self.tenant), "host": .string("evil.example"), "reason": .string("x")])))
        XCTAssertEqual(add.status, .ok)
        let unchanged = try await record(h).record
        XCTAssertEqual(try verified(h, unchanged).allowedHosts, Self.hosts)
        try await h.shutdown()
    }

    // MARK: Reduction and the record (ST-ML-12)

    func testRevocationAndHostRemovalReachTheRecordWithAHigherSeq() async throws {
        let h = try await AuthorityHarness.make()
        let r = Registration()
        try await register(h, r)
        let first = try verified(h, try await record(h).record)
        // The worker's weekly domain re-check removes a host (reduce-only, works for the worker identity too).
        let removed = try await h.call(.POST, AuthorityTenantKeyRoute.revocations, token: StaticCallerVerifier.workerToken,
                                       json: try CanonicalJSON.serialize(.object(["tenant_id": .string(Self.tenant), "host": .string("www.acme.com"), "reason": .string("domain_recheck")])))
        XCTAssertEqual(removed.status, .ok)
        let second = try verified(h, try await record(h).record)
        XCTAssertEqual(second.allowedHosts, ["login.acme.com"])
        XCTAssertGreaterThan(second.seq, first.seq)
        // The admin job revokes the key without the api.
        try await admin(h, "revoke-tenant-key", ["tenant_id": .string(Self.tenant), "kid": .string(r.kid), "reason": .string("compromise")])
        let third = try verified(h, try await record(h).record)
        XCTAssertTrue(third.keys.isEmpty, "a revoked key is never listed")
        XCTAssertGreaterThan(third.seq, second.seq)
        // A device that saw `third` refuses `first` as a replayed record.
        let latestRecord = try await record(h).record
        let latest = try XCTUnwrap(latestRecord)
        XCTAssertThrowsError(try AuthorityStatementVerifier.verifyTenantRecord(latest, pinnedKeys: [h.statementKey], environment: .staging,
                                                                              tenantId: Self.tenant, minimumSeq: third.seq + 1, now: h.clock.now))
        // A revoked key cannot be registered again.
        let nonce = try await issueNonce(h, r)
        let pop = try await DestinationKeyRegistration.sign(tenantId: Self.tenant, hosts: Self.hosts, nonce: nonce, environment: .staging, key: r.key, issuedAt: h.clock.now)
        await assertRefused(h, "tenant-key-register", change(h, r, pop: pop), "revoked key re-registered")
        try await h.shutdown()
    }

    func testAKeyPastNotAfterIsNotListedAndTheRecordIsReSignedWhenStale() async throws {
        let h = try await AuthorityHarness.make()
        let r = Registration()
        let nonce = try await issueNonce(h, r)
        let pop = try await DestinationKeyRegistration.sign(tenantId: Self.tenant, hosts: Self.hosts, nonce: nonce, environment: .staging, key: r.key, issuedAt: h.clock.now)
        try await admin(h, "tenant-key-register", change(h, r, pop: pop, notAfter: h.clock.now.addingTimeInterval(3600)))
        let a = try await record(h).record
        let again = try await record(h).record
        XCTAssertEqual(again, a, "served from the cache within 5 minutes (not a Key Vault sign per request)")
        h.clock.advance(301)
        let b = try await record(h).record
        XCTAssertNotEqual(b, a, "re-signed once the cached copy is older than 5 minutes")
        XCTAssertEqual(try verified(h, b).keys.count, 1)
        h.clock.advance(3600)
        let expired = try await record(h).record
        XCTAssertTrue(try verified(h, expired).keys.isEmpty, "a key past not_after is not listed")
        try await h.shutdown()
    }

    func testRecordsAreOffByFlagUnknownForOtherTenantsAndNeverForTheWorker() async throws {
        let h = try await AuthorityHarness.make()
        try await register(h)
        let unknown = try await record(h, tenant: "ten_other")
        XCTAssertEqual(unknown.status, .notFound)
        let worker = try await record(h, token: StaticCallerVerifier.workerToken)
        XCTAssertEqual(worker.status, .forbidden)
        try await h.shutdown()
        var options = AuthorityHarness.Options()
        options.mutateConfig = { $0.tenantKeysEnabled = false }
        let off = try await AuthorityHarness.make(options)
        let refused = try await record(off)
        XCTAssertEqual(refused.status, .notFound)
        try await off.shutdown()
    }

    // MARK: Pinned-key revocation list (ADR-0033 §3.3)

    func testAStatementFamilyRevocationIsNeverSignedByTheKeyItRevokes() async throws {
        let h = try await AuthorityHarness.make()
        try await register(h)
        // Only the active pinned key can be named; a standby or unknown key is refused.
        await assertRefused(h, "device-key-revoke", ["key_family": .string("device-statement"), "kid": .string(JWKThumbprint.p256(P256.Signing.PrivateKey().publicKey))],
                            "not the active key")
        try await admin(h, "device-key-revoke", ["key_family": .string("device-statement"), "kid": .string(JWKThumbprint.p256(h.statementKey))])
        // The authority still runs on the active key: it does not sign a list revoking itself (the device would refuse it anyway).
        let served = try await record(h)
        XCTAssertNotNil(served.record)
        XCTAssertNil(served.list)
        // Sticky: the recorded revocation cannot be deleted.
        do {
            try await AuthorityDeviceKeyRevocation.query(on: h.app.db).delete()
            XCTFail("the revocation row was deleted")
        } catch {}
        try await h.shutdown()
    }
}
