@preconcurrency import Crypto
import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

/// What the api relays: whatever the test (playing AS-1 where it says so) puts here.
final class FakeTenantKeys: TenantDestinationKeysFetching, @unchecked Sendable {
    var answer: AuthTenantDestinationKeys?
    private(set) var asked: [String] = []
    func destinationKeys(tenantId: String) async throws -> AuthTenantDestinationKeys {
        asked.append(tenantId)
        guard let answer else { throw AuthDeliveryError.offline }
        return answer
    }
}

/// ADR-0031 §4 on the device. Each exploit-path test fails if the control it names is removed.
@Suite("Business-link destination verification (ADR-0031 §4)")
@MainActor
struct DestinationVerifierTests {
    static let t0: Int64 = 1_800_000_000
    let now = Date(timeIntervalSince1970: TimeInterval(t0))
    let active = P256.Signing.PrivateKey()
    let standby = P256.Signing.PrivateKey()
    let tenantKey = SoftwareP256SigningKey()
    let otherTenantKey = SoftwareP256SigningKey()
    let tenant = "ten_acme"
    let url = "https://login.acme.com/magic?token=Zm9vYmFy&s=1"
    let requestId = "req_login_1"
    let deliveryId = UUID()
    let sealKids = [Base64URL.encode(Data(repeating: 1, count: 32)), Base64URL.encode(Data(repeating: 2, count: 32))]

    // MARK: Builders

    func jws(_ typ: String, _ payload: [String: JSONValue], key: P256.Signing.PrivateKey) throws -> String {
        let input = try AuthorityJWS.signingInput(alg: "ES256", kid: JWKThumbprint.p256(key.publicKey), typ: typ, payload: payload)
        return input + "." + ViadereSignatureEncoding.encode(try key.signature(for: Data(input.utf8)))
    }

    func tenantKeyEntry(_ key: SoftwareP256SigningKey, notAfter: Int64? = nil) throws -> AuthorityTenantKey {
        AuthorityTenantKey(try key.publicKey.signingKey(), notAfter: notAfter ?? Self.t0 + 86_400 * 300)
    }

    func record(tenantId: String? = nil, seq: Int64 = 3, hosts: [String] = ["login.acme.com"], keys: [AuthorityTenantKey]? = nil, issuedAt: Int64? = nil,
                signer: P256.Signing.PrivateKey? = nil, typ: String = AuthorityTenantRecord.type) throws -> String {
        let r = AuthorityTenantRecord(environment: .staging, tenantId: tenantId ?? tenant, seq: seq, displayName: "Acme Bank", allowedHosts: hosts,
                                      keys: try keys ?? [tenantKeyEntry(tenantKey)], issuedAt: issuedAt ?? Self.t0 - 30)
        return try jws(typ, r.payload, key: signer ?? active)
    }

    func statement(url: String? = nil, digestOf: String? = nil, issuer: String? = nil, requestId: String? = nil, key: SoftwareP256SigningKey? = nil,
                   kidOf: SoftwareP256SigningKey? = nil, iat: Int64? = nil, jti: String? = nil) async throws -> String {
        let signer = key ?? tenantKey
        var s = try AuthDestinationStatement.build(url: url ?? self.url, tenantId: issuer ?? tenant, subjectRef: SubjectRef("sub_" + String(repeating: "A", count: 43))!,
                                                   requestId: requestId ?? self.requestId, purpose: .signIn, kid: JWKThumbprint.p256(try (kidOf ?? signer).publicKey.signingKey()),
                                                   issuedAt: Date(timeIntervalSince1970: TimeInterval(iat ?? Self.t0)), jti: jti ?? AuthDestinationStatement.newJTI())
        if let digestOf { s.urlSHA256 = AuthDestinationStatement.digest(of: digestOf) }
        return try await s.sign(with: signer)
    }

    func display(_ statement: String?, id: UUID? = nil, host: String = "login.acme.com") -> AuthLinkDisplay {
        AuthLinkDisplay(deliveryId: id ?? deliveryId, business: "Totally Acme (api text)", businessVerified: false, host: host,
                        expiresAt: now.addingTimeInterval(300), destinationStatement: statement, requestId: requestId, purpose: .signIn)
    }

    func verifier(_ fetcher: FakeTenantKeys, secrets: InMemorySecretStore = InMemorySecretStore(), pinned: [P256.Signing.PublicKey]? = nil,
                  clock: Date? = nil) -> AuthorityDestinationVerifier {
        let at = clock ?? now
        return AuthorityDestinationVerifier(fetcher: fetcher, state: DestinationVerificationState(secrets: secrets), pinnedKeys: pinned ?? [active.publicKey, standby.publicKey],
                                            sealKids: sealKids, environment: .staging, clock: { at })
    }

    func fetcher(record: String, revocations: String? = nil) -> FakeTenantKeys {
        let f = FakeTenantKeys()
        f.answer = AuthTenantDestinationKeys(record: record, revocationList: revocations)
        return f
    }

    // MARK: The genuine path

    @Test func aGenuineStatementVerifiesShowsTheAuthorityNameAndOpensOnlyTheSignedBytes() async throws {
        let api = MockAuthDeliveryAPI()
        let shown = display(try await statement())
        await api.add(shown, url: URL(string: url)!)
        let opener = RecordingOpener()
        let now = self.now
        let m = LinkConfirmationViewModel(deliveryId: deliveryId, api: api, verifier: verifier(fetcher(record: try record())), opener: opener, clock: { now })
        await m.load()
        #expect(m.phase == .reviewing && m.canContinue)
        #expect(m.display?.business == "Acme Bank", "the name comes from the authority record, never the api")
        #expect(m.display?.businessVerified == true)
        await m.proceed()
        #expect(m.phase == .opened(host: "login.acme.com"))
        #expect(opener.opened.map(\.absoluteString) == [url])
        #expect(await api.reduceCalls.isEmpty)
    }

    // MARK: Exploit paths (integrity: S-LINK-09 and destination_unverified)

    @Test func aForgedStatementIsRefused() async throws {
        // AS-1 signs its own statement under the tenant's kid.
        let forged = try await statement(key: otherTenantKey, kidOf: tenantKey)
        #expect(await verifier(fetcher(record: try record())).verify(display(forged)) == .signatureFailed)
    }

    @Test func aStatementSignedByARevokedKeyIsRefused() async throws {
        // Revocation removes the key from the record: a statement under it is refused.
        let revokedRecord = try record(seq: 4, keys: [try tenantKeyEntry(otherTenantKey)])
        #expect(await verifier(fetcher(record: revokedRecord)).verify(display(try await statement())) == .signatureFailed)
    }

    @Test func aKeyPastNotAfterIsRefused() async throws {
        let expired = try record(keys: [try tenantKeyEntry(tenantKey, notAfter: Self.t0 - 1)])
        #expect(await verifier(fetcher(record: expired)).verify(display(try await statement())) == .signatureFailed)
    }

    @Test func aKeyOfAnotherTenantIsRefused() async throws {
        // Signed by another tenant's genuine key but naming this tenant: this tenant's record does not list it.
        let s = try await statement(key: otherTenantKey)
        #expect(await verifier(fetcher(record: try record())).verify(display(s)) == .signatureFailed)
        // The api serves the other tenant's record for this tenant's statement.
        let other = try record(tenantId: "ten_other", keys: [try tenantKeyEntry(otherTenantKey)])
        #expect(await verifier(fetcher(record: other)).verify(display(s)) == .signatureFailed)
    }

    @Test func aHostOutsideAllowedHostsIsRefused() async throws {
        let narrowed = try record(seq: 5, hosts: ["www.acme.com"])
        #expect(await verifier(fetcher(record: narrowed)).verify(display(try await statement())) == .signatureFailed)
    }

    @Test func urlBytesChangedAfterSigningAreNeverOpened() async throws {
        let api = MockAuthDeliveryAPI()
        // The api rewrote one byte of the stored URL after create (ST-ML-10).
        await api.add(display(try await statement()), url: URL(string: url.replacingOccurrences(of: "s=1", with: "s=2"))!)
        let opener = RecordingOpener()
        let now = self.now
        let m = LinkConfirmationViewModel(deliveryId: deliveryId, api: api, verifier: verifier(fetcher(record: try record())), opener: opener, clock: { now })
        await m.load()
        #expect(m.canContinue)
        await m.proceed()
        #expect(m.phase == .notOpened(.signatureFailed))
        #expect(opener.opened.isEmpty)
        #expect(await api.reduceCalls.map(\.1) == [.denyDestinationUnverified])
        // The byte check on its own: one added slash is a different URL.
        let v = verifier(fetcher(record: try record()))
        let d = display(try await statement())
        #expect(await v.verify(d) == .verifiedBy(host: "login.acme.com", business: "Acme Bank"))
        #expect(await v.verifyOpened(url.replacingOccurrences(of: ".com/", with: ".com//"), for: d) == false)
        #expect(await v.verifyOpened(url, for: d) == false, "a verified statement is checked against one opened URL only")
    }

    @Test func aReplayedJTIOnAnotherDeliveryIsRefusedButReopeningTheSameDeliveryIsNot() async throws {
        let secrets = InMemorySecretStore()
        let jti = AuthDestinationStatement.newJTI()
        let s = try await statement(jti: jti)
        let f = fetcher(record: try record())
        #expect(await verifier(f, secrets: secrets).verify(display(s)) == .verifiedBy(host: "login.acme.com", business: "Acme Bank"))
        #expect(await verifier(f, secrets: secrets).verify(display(s)) == .verifiedBy(host: "login.acme.com", business: "Acme Bank"), "same delivery, reopened")
        #expect(await verifier(f, secrets: secrets).verify(display(s, id: UUID())) == .signatureFailed, "the statement replayed on another delivery")
    }

    @Test func aTenantRecordSignedByANonAuthorityKeyIsRefused() async throws {
        let fake = try record(signer: P256.Signing.PrivateKey())
        #expect(await verifier(fetcher(record: fake)).verify(display(try await statement())) == .signatureFailed)
    }

    @Test func aLowerSeqThanStoredIsAReplayedRecord() async throws {
        let secrets = InMemorySecretStore()
        #expect(await verifier(fetcher(record: try record(seq: 9)), secrets: secrets).verify(display(try await statement())) != .signatureFailed)
        #expect(await verifier(fetcher(record: try record(seq: 8)), secrets: secrets).verify(display(try await statement())) == .signatureFailed)
    }

    @Test func crossTypSubstitutionIsRefused() async throws {
        let s = try await statement()
        let genuine = try record()
        // The record relabelled as a challenge or head, or a revocation list served as the record.
        for typ in [AuthorityChallengeStatement.type, AuthorityKeyLogHead.type, AuthorityRevocationList.type, AuthDestinationStatement.type] {
            #expect(await verifier(fetcher(record: try record(typ: typ))).verify(display(s)) == .signatureFailed, "\(typ)")
        }
        // The tenant record presented as the destination statement.
        #expect(await verifier(fetcher(record: genuine)).verify(display(genuine)) == .signatureFailed)
        // A tenant record in the revocation-list slot is ignored, never applied.
        let secrets = InMemorySecretStore()
        #expect(await verifier(fetcher(record: genuine, revocations: genuine), secrets: secrets).verify(display(s)) == .verifiedBy(host: "login.acme.com", business: "Acme Bank"))
        #expect(try DestinationVerificationState(secrets: secrets).revokedKids().isEmpty)
    }

    @Test func anApiDisplayHostThatIsNotTheSignedHostIsReported() async throws {
        let api = MockAuthDeliveryAPI()
        await api.add(display(try await statement(), host: "login.acme-secure.com"), url: URL(string: url)!)
        let now = self.now
        let m = LinkConfirmationViewModel(deliveryId: deliveryId, api: api, verifier: verifier(fetcher(record: try record())), opener: RecordingOpener(), clock: { now })
        await m.load()
        #expect(m.phase == .notOpened(.signatureFailed) && !m.canContinue)
        #expect(await api.reduceCalls.map(\.1) == [.denyDestinationUnverified])
    }

    @Test func aMissingStatementIsRefused() async {
        #expect(await verifier(FakeTenantKeys()).verify(display(nil)) == .signatureFailed)
    }

    // MARK: Availability (no server call, the link waits)

    @Test func aStaleRecordOrNoRecordLeavesTheDeliveryOpenAndSendsNothing() async throws {
        let api = MockAuthDeliveryAPI()
        await api.add(display(try await statement()), url: URL(string: url)!)
        let now = self.now
        let stale = try record(issuedAt: Self.t0 - 901)
        let m = LinkConfirmationViewModel(deliveryId: deliveryId, api: api, verifier: verifier(fetcher(record: stale)), opener: RecordingOpener(), clock: { now })
        await m.load()
        #expect(m.phase == .cannotCheck(clock: false) && m.offersTryAgain)
        #expect(await api.reduceCalls.isEmpty)
        #expect(await api.openCalls.isEmpty)
        #expect(await verifier(FakeTenantKeys()).verify(display(try await statement())) == .unavailable, "authority outage")
    }

    @Test func clockSkewIsAvailabilityButAStaleStatementWithACorrectClockIsIntegrity() async throws {
        let old = try await statement(iat: Self.t0 - 700)
        // The device clock agrees with the authority's (record issued 30 s ago): the statement really is expired.
        #expect(await verifier(fetcher(record: try record())).verify(display(old)) == .signatureFailed)
        // The device clock is an hour ahead of authority time: S-LINK-12.
        let ahead = now.addingTimeInterval(3600)
        let fresh = try await statement()
        let skewed = try record(issuedAt: Self.t0 + 3600 - 600)
        #expect(await verifier(fetcher(record: skewed), clock: ahead).verify(display(fresh)) == .clockOutsideWindow)
        // A record signed after the device's "now": the device clock is behind.
        #expect(await verifier(fetcher(record: try record(issuedAt: Self.t0 + 120))).verify(display(fresh)) == .clockOutsideWindow)
    }

    // MARK: Pinned keys and revocation

    @Test func withoutPinnedKeysNothingIsVerifiableAndNothingIsReported() async throws {
        #expect(await verifier(fetcher(record: try record()), pinned: []).verify(display(try await statement())) == .notYetSupported)
    }

    @Test func aStandbySignedRevocationOfTheActiveKeyIsStickyAcrossRestarts() async throws {
        let secrets = InMemorySecretStore()
        let list = AuthorityRevocationList(environment: .staging, revoked: [AuthorityRevokedKey(family: .deviceStatement, kid: JWKThumbprint.p256(active.publicKey))],
                                           issuedAt: Self.t0 - 60)
        let signed = try jws(AuthorityRevocationList.type, list.payload, key: standby)
        #expect(await verifier(fetcher(record: try record(signer: standby), revocations: signed), secrets: secrets).verify(display(try await statement()))
                == .verifiedBy(host: "login.acme.com", business: "Acme Bank"))
        // A new process with the same Keychain, and an api that stops sending the list: a record by the revoked active key is refused.
        #expect(await verifier(fetcher(record: try record()), secrets: secrets).verify(display(try await statement())) == .signatureFailed)
        // A list signed by the active key revoking the standby is ignored (ADR-0033 §3.3).
        let fresh = InMemorySecretStore()
        let hostile = AuthorityRevocationList(environment: .staging, revoked: [AuthorityRevokedKey(family: .deviceStatement, kid: JWKThumbprint.p256(standby.publicKey))],
                                              issuedAt: Self.t0 - 60)
        _ = await verifier(fetcher(record: try record(), revocations: try jws(AuthorityRevocationList.type, hostile.payload, key: active)), secrets: fresh)
            .verify(display(try await statement()))
        #expect(try DestinationVerificationState(secrets: fresh).revokedKids().isEmpty)
    }

    // MARK: Wiring

    @Test func theFlagShipsOffAndTheFailClosedVerifierStaysTheDefault() {
        let f = FakeTenantKeys()
        let pinned = [active.publicKey, standby.publicKey]
        for flags in [AuthDeliveryFlags.shipping, .staging] {
            #expect(DestinationVerifiers.make(flags: flags, fetcher: f, secrets: InMemorySecretStore(), environment: .staging, pinnedKeys: pinned, sealKids: sealKids)
                    is FailClosedDestinationVerifier)
        }
        let on = AuthDeliveryFlags(destinationVerification: true)
        #expect(DestinationVerifiers.make(flags: on, fetcher: f, secrets: InMemorySecretStore(), environment: .staging, pinnedKeys: [], sealKids: sealKids)
                is FailClosedDestinationVerifier, "flag on but no pinned key: still fail closed")
        #expect(DestinationVerifiers.make(flags: on, fetcher: f, secrets: InMemorySecretStore(), environment: .staging, pinnedKeys: pinned, sealKids: sealKids)
                is AuthorityDestinationVerifier)
    }

    @Test func aLinkServiceDeliveryIsNeverCheckedAsABusinessLinkNorReported() async throws {
        var d = display(nil)
        d.linkService = true
        let f = fetcher(record: try record())
        #expect(await verifier(f).verify(d) == .notYetSupported)
        #expect(f.asked.isEmpty)
    }

    @Test func theFailClosedVerifierNeverPassesAnOpenedURL() async {
        #expect(await FailClosedDestinationVerifier().verifyOpened(url, for: display(nil)) == false)
    }
}
