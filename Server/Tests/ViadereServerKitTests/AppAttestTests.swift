@preconcurrency import Crypto
import Fluent
import Foundation
import ViadereCore
import XCTest
@preconcurrency import X509
@testable import ViadereServerKit

/// App Attest: the verifier against a synthetic CA chain, and the enrollment policy (`APP_ATTEST_MODE`).
final class AppAttestVerifierTests: XCTestCase {
    let clock = ManualClock(Date(timeIntervalSince1970: 1_800_000_000))
    let pki = TestAppAttestPKI()
    let consumer = ConsumerID()
    let challenge = "challenge-0123456789abcdef"

    func keys(_ purposes: [DeviceKeyPurpose] = [.request, .approvalBiometric]) -> [DeviceKeyRegistration] {
        purposes.map { DeviceKeyRegistration(purpose: $0, publicKey: SoftwareP256SigningKey().publicKey, hardwareBacked: true, proof: "x") }
    }

    /// Attests over the genuine client data for `keys`, then verifies with `verifier`.
    func check(flaws: TestAppAttestPKI.Flaws = .init(), clientKind: DeviceClientKind = .app, verifyKind: DeviceClientKind? = nil, attestEnvironment: AppAttestEnvironment = .production,
               verifier: AppAttestVerifier? = nil, verifyChallenge: String? = nil, verifyConsumer: ConsumerID? = nil, verifyKeys: [DeviceKeyRegistration]? = nil,
               file: StaticString = #filePath, line: UInt = #line) async throws -> AttestationResult {
        let attestedKeys = keys()
        let made = try pki.attest(clientDataHash: AppAttestBinding.clientDataHash(consumerId: consumer, challenge: challenge, keys: attestedKeys),
                                  environment: attestEnvironment, clientKind: clientKind, now: clock.now(), flaws: flaws)
        let verifier = verifier ?? pki.verifier(clock: clock)
        return await verifier.verifyEnrollment(made.evidence, consumerId: verifyConsumer ?? consumer, challenge: verifyChallenge ?? challenge,
                                               keys: verifyKeys ?? attestedKeys, clientKind: verifyKind ?? clientKind)
    }

    func expectRefused(_ reason: String, _ result: AttestationResult, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertFalse(result.attested, "must not verify (\(reason))", file: file, line: line)
        XCTAssertEqual(result.reason, reason, file: file, line: line)
        XCTAssertNil(result.keyId, file: file, line: line)
    }

    func testAGenuineAttestationVerifiesAndYieldsTheKey() async throws {
        let result = try await check()
        XCTAssertTrue(result.attested, result.reason)
        XCTAssertEqual(result.reason, "verified")
        XCTAssertEqual(result.counter, 0)
        XCTAssertEqual(result.environment, "production")
        XCTAssertEqual(result.keyId?.count, 64)
        let key = try XCTUnwrap(result.publicKey.flatMap(Base64URL.decode))
        XCTAssertEqual(result.keyId, Hex.encode(SHA256.hash(data: key)))
        // The App Clip has its own app id.
        let clip = try await check(clientKind: .appClip)
        XCTAssertTrue(clip.attested, clip.reason)
    }

    func testNoEvidenceIsNotProvided() async {
        let result = await pki.verifier(clock: clock).verifyEnrollment(nil, consumerId: consumer, challenge: challenge, keys: keys(), clientKind: .app)
        expectRefused("not_provided", result)
    }

    // MARK: Exploits: an attestation replayed to vouch for something else

    func testAnAttestationDoesNotVouchForAnotherChallengeAccountOrKeyList() async throws {
        expectRefused("bad_nonce", try await check(verifyChallenge: "another-challenge-0123456789"))
        expectRefused("bad_nonce", try await check(verifyConsumer: ConsumerID()))
        // Key-list mismatch: a different key, an extra key, a missing key, or a key moved to another purpose.
        expectRefused("bad_nonce", try await check(verifyKeys: keys()))
        let attested = keys()
        let made = try pki.attest(clientDataHash: AppAttestBinding.clientDataHash(consumerId: consumer, challenge: challenge, keys: attested), now: clock.now())
        let verifier = pki.verifier(clock: clock)
        let extra = await verifier.verifyEnrollment(made.evidence, consumerId: consumer, challenge: challenge, keys: attested + keys([.approvalUserPresence]), clientKind: .app)
        expectRefused("bad_nonce", extra)
        let missing = await verifier.verifyEnrollment(made.evidence, consumerId: consumer, challenge: challenge, keys: [attested[0]], clientKind: .app)
        expectRefused("bad_nonce", missing)
        let moved = [DeviceKeyRegistration(purpose: .approvalUserPresence, publicKey: attested[0].publicKey, hardwareBacked: true, proof: "x"), attested[1]]
        expectRefused("bad_nonce", await verifier.verifyEnrollment(made.evidence, consumerId: consumer, challenge: challenge, keys: moved, clientKind: .app))
        // The exact binding verifies.
        let same = await verifier.verifyEnrollment(made.evidence, consumerId: consumer, challenge: challenge, keys: attested.reversed(), clientKind: .app)
        XCTAssertTrue(same.attested, same.reason)
    }

    func testAForgedNonceInTheCertificateIsRefused() async throws {
        expectRefused("bad_nonce", try await check(flaws: .init(nonceOverride: Data(repeating: 7, count: 32))))
    }

    func testAnotherAppIdOrAnotherKindOfClientIsRefused() async throws {
        expectRefused("bad_rp_id", try await check(flaws: .init(rpId: "OTHERTEAM1.com.viadere.app")))
        expectRefused("bad_rp_id", try await check(flaws: .init(rpId: "TEAMID1234.com.attacker.app")))
        // An attestation made by the full app does not count for the App Clip, and the other way round.
        expectRefused("bad_rp_id", try await check(clientKind: .app, verifyKind: .appClip))
        expectRefused("bad_rp_id", try await check(clientKind: .appClip, verifyKind: .app))
    }

    func testAChainThatDoesNotEndAtTheTrustedRootIsRefused() async throws {
        // Signed by another CA entirely.
        expectRefused("bad_chain", try await check(flaws: .init(otherPKI: TestAppAttestPKI())))
        // The right chain, but the verifier trusts a different root.
        expectRefused("bad_chain", try await check(verifier: pki.verifier(clock: clock, roots: [TestAppAttestPKI().root])))
        // No intermediate (malformed chain), or the production verifier whose only root is Apple's.
        expectRefused("malformed_object", try await check(flaws: .init(skipIntermediate: true)))
        let config = ServerConfig.testing()
        let apple = try AppAttestVerifier.apple(config: config, clock: clock)
        expectRefused("bad_chain", try await check(verifier: apple))
    }

    func testExpiredAndNotYetValidCredentialCertificatesAreRefused() async throws {
        let now = clock.now()
        expectRefused("bad_chain", try await check(flaws: .init(leafNotBefore: now.addingTimeInterval(-86_400), leafNotAfter: now.addingTimeInterval(-10))))
        expectRefused("bad_chain", try await check(flaws: .init(leafNotBefore: now.addingTimeInterval(3600))))
        // A few minutes of clock skew between Apple and this server is tolerated.
        let skewed = try await check(flaws: .init(leafNotBefore: now.addingTimeInterval(120)))
        XCTAssertTrue(skewed.attested, skewed.reason)
    }

    func testCounterAaguidFormatAndIdentifierChecks() async throws {
        expectRefused("bad_counter", try await check(flaws: .init(counter: 1)))
        expectRefused("bad_counter", try await check(flaws: .init(counter: 0x0100_0000)))
        // Development attestations are refused by a production verifier and the other way round.
        expectRefused("bad_aaguid", try await check(attestEnvironment: .development))
        expectRefused("bad_aaguid", try await check(attestEnvironment: .production, verifier: pki.verifier(clock: clock, environment: .development)))
        let dev = try await check(attestEnvironment: .development, verifier: pki.verifier(clock: clock, environment: .development))
        XCTAssertTrue(dev.attested, dev.reason)
        XCTAssertEqual(dev.environment, "development")
        expectRefused("bad_aaguid", try await check(flaws: .init(aaguid: Data(repeating: 0, count: 16))))
        expectRefused("bad_format", try await check(flaws: .init(format: "packed")))
        // The key identifier the client sent must be the hash of the credential key, and the authData credential id must match it.
        expectRefused("bad_key_id", try await check(flaws: .init(keyIdOverride: Data(repeating: 9, count: 32))))
        expectRefused("bad_credential_id", try await check(flaws: .init(credentialIdOverride: Data(repeating: 9, count: 32))))
    }

    func testMalformedEvidenceNeverVerifiesAndNeverCrashes() async throws {
        let verifier = pki.verifier(clock: clock)
        let ks = keys()
        let made = try pki.attest(clientDataHash: AppAttestBinding.clientDataHash(consumerId: consumer, challenge: challenge, keys: ks), now: clock.now())
        let object = made.attestationObject
        var candidates: [(String, String)] = [("", ""), ("not base64 !!", "also not"), (made.evidence.keyId, "AAAA"), (made.evidence.keyId, String(repeating: "A", count: 60_000))]
        for cut in [1, 5, object.count / 2, object.count - 1] { candidates.append((made.evidence.keyId, Base64URL.encode(object.prefix(cut)))) }
        candidates.append((made.evidence.keyId, Base64URL.encode(object + Data([0]))))
        candidates.append(("AAAA", Base64URL.encode(object)))
        for (keyId, attestation) in candidates {
            let result = await verifier.verifyEnrollment(AppAttestEvidence(keyId: keyId, attestation: attestation), consumerId: consumer, challenge: challenge, keys: ks, clientKind: .app)
            XCTAssertFalse(result.attested, "\(keyId.prefix(8)) / \(attestation.prefix(8)): \(result.reason)")
        }
    }

    func testTheAppleRootIsEmbeddedAndFingerprintChecked() throws {
        let root = try AppleAppAttestRoot.certificate()
        XCTAssertEqual(String(describing: root.subject).contains("Apple App Attestation Root CA"), true)
        XCTAssertEqual(AppleAppAttestRoot.fingerprint, "1cb9823ba28ba6ad2d33a006941de2ae4f513ef1d4e831b9f7e0fa7b6242c932")
        XCTAssertTrue(root.notValidAfter > Date(timeIntervalSince1970: 2_300_000_000), "valid until 2045")
    }

    // MARK: Assertions

    func testAssertionsNeedTheStoredKeyTheAppIdAndAStrictlyIncreasingCounter() throws {
        let key = P256.Signing.PrivateKey()
        let x963 = key.publicKey.x963Representation
        let verifier = pki.verifier(clock: clock)
        let data = Data("approve:abc".utf8)
        func assertion(_ counter: UInt32, clientData: Data? = nil, signedFor: Data? = nil, rp: String? = nil, signWith: P256.Signing.PrivateKey? = nil,
                       kind: DeviceClientKind = .app) throws -> Data {
            try TestAppAttestPKI.assertion(key: key, clientData: clientData ?? data, counter: counter, rpId: rp, clientKind: kind, signWith: signWith, signedClientData: signedFor)
        }
        XCTAssertEqual(try verifier.verifyAssertion(try assertion(1), clientData: data, publicKeyX963: x963, storedCounter: 0, clientKind: .app), 1)
        XCTAssertEqual(try verifier.verifyAssertion(try assertion(7), clientData: data, publicKeyX963: x963, storedCounter: 1, clientKind: .app), 7, "gaps are fine")
        func refused(_ blob: Data, stored: Int, clientData: Data? = nil, kind: DeviceClientKind = .app, _ what: String) {
            XCTAssertThrowsError(try verifier.verifyAssertion(blob, clientData: clientData ?? data, publicKeyX963: x963, storedCounter: stored, clientKind: kind), what)
        }
        refused(try assertion(1), stored: 1, "replay of the same counter")
        refused(try assertion(3), stored: 7, "an older counter")
        refused(try assertion(0), stored: 0, "counter zero")
        refused(try assertion(2, signWith: P256.Signing.PrivateKey()), stored: 1, "signed by another key")
        refused(try assertion(2), stored: 1, clientData: Data("approve:xyz".utf8), "other client data")
        refused(try assertion(2, signedFor: Data("approve:xyz".utf8)), stored: 1, "signed over other client data")
        refused(try assertion(2, rp: "TEAMID1234.com.attacker.app"), stored: 1, "wrong app id")
        refused(try assertion(2), stored: 1, kind: .appClip, "the clip's app id differs")
        refused(Data([1, 2, 3]), stored: 0, "garbage")
    }

    func testTheCounterIsPersistedWithACompareAndSwap() async throws {
        try await withAttestHarness(pki, mode: .require) { h, pki in
            let user = try await h.registerConsumer()
            let key = P256.Signing.PrivateKey()
            let (response, device, _) = try await h.enrollAttested(user, evidence: genuineEvidence(pki, clock: h.clock, key: key))
            XCTAssertEqual(response.status, .created, response.text)
            let deviceId = try XCTUnwrap(device).id.uuid
            let stored = try await XCTUnwrapAsync(try await AppAttestKeyRecord.query(on: h.db).filter(\.$deviceId == deviceId).first())
            XCTAssertEqual(stored.counter, 0)
            XCTAssertEqual(stored.environment, "production")
            XCTAssertEqual(stored.keyId, Hex.encode(SHA256.hash(data: key.publicKey.x963Representation)))
            let service = AppAttestAssertions(db: h.db, ctx: h.ctx)
            let data = Data("step-up".utf8)
            try await service.verify(deviceId: deviceId, assertion: try TestAppAttestPKI.assertion(key: key, clientData: data, counter: 1), clientData: data)
            do {
                try await service.verify(deviceId: deviceId, assertion: try TestAppAttestPKI.assertion(key: key, clientData: data, counter: 1), clientData: data)
                XCTFail("a replayed assertion must be refused")
            } catch let error as APIError { XCTAssertEqual(error.code, .signatureInvalid) }
            try await service.verify(deviceId: deviceId, assertion: try TestAppAttestPKI.assertion(key: key, clientData: data, counter: 2), clientData: data)
            let after = try await XCTUnwrapAsync(try await AppAttestKeyRecord.query(on: h.db).filter(\.$deviceId == deviceId).first())
            XCTAssertEqual(after.counter, 2)
            XCTAssertNotNil(after.lastAssertionAt)
        }
    }

    // MARK: CBOR

    func testTheCBORReaderIsStrict() throws {
        let value = try CBOR.decode(CBOR.encode(.map([.init(key: .text("a"), value: .array([.unsigned(1), .negative(-5), .bytes(Data([1])), .text("é"), .bool(true), .null]))])))
        XCTAssertEqual(value["a"]?.arrayValue?.count, 6)
        XCTAssertThrowsError(try CBOR.decode(Data([0x5F, 0x41, 0x01, 0xFF])), "indefinite length")
        XCTAssertThrowsError(try CBOR.decode(Data([0xA2, 0x61, 0x61, 0x01, 0x61, 0x61, 0x02])), "duplicate keys")
        XCTAssertThrowsError(try CBOR.decode(Data([0x01, 0x02])), "trailing bytes")
        XCTAssertThrowsError(try CBOR.decode(Data([0x44, 0x01])), "truncated")
        XCTAssertThrowsError(try CBOR.decode(Data([0xC1, 0x01])), "tags are not used")
        XCTAssertThrowsError(try CBOR.decode(Data([0xF9, 0x3C, 0x00])), "floats are not used")
        XCTAssertThrowsError(try CBOR.decode(Data(repeating: 0x81, count: 40) + Data([0x01])), "depth")
        XCTAssertThrowsError(try CBOR.decode(Data([0x62, 0xFF, 0xFE])), "invalid UTF-8")
        XCTAssertThrowsError(try CBOR.decode(Data(repeating: 0, count: 70_000)), "too large")
    }
}

/// Enrollment policy (`APP_ATTEST_MODE`) end to end.
final class AppAttestEnrollmentTests: XCTestCase {
    let pki = TestAppAttestPKI()

    func devices(_ h: TestHarness, _ consumer: TestConsumer) async throws -> [Device] {
        try await h.signed(consumer, .GET, "/v1/devices").json([Device].self)
    }

    func testRequireModeRefusesAnUnattestedAppDeviceAndAnUnattestedClip() async throws {
        try await withAttestHarness(pki, mode: .require) { h, pki in
            let user = try await h.registerConsumer()
            // Exploit (before): a software key enrolled by anyone who completed the passkey assertion, with no attestation at all.
            let none = try await h.enrollAttested(user) { _, _, _ in nil }
            XCTAssertEqual(none.0.status, .forbidden, none.0.text)
            XCTAssertEqual(none.0.errorCode, .attestationRequired)
            // Garbage evidence is the same.
            let garbage = try await h.enrollAttested(user) { _, _, _ in AppAttestEvidence(keyId: "AAAA", attestation: "AAAA") }
            XCTAssertEqual(garbage.0.errorCode, .attestationRequired)
            // App Clip devices attest too.
            let clipNone = try await h.enrollAttested(user, purposes: [.request], clientKind: .appClip) { _, _, _ in nil }
            XCTAssertEqual(clipNone.0.errorCode, .attestationRequired)
            let clipWrongApp = try await h.enrollAttested(user, purposes: [.request], clientKind: .appClip, evidence: genuineEvidence(pki, clock: h.clock, clientKind: .app))
            XCTAssertEqual(clipWrongApp.0.errorCode, .attestationRequired, "the full app's attestation is not the clip's")
            try await eq(try await DeviceRecord.query(on: h.db).count(), 0, "nothing was created")
            let audited = try await AuditEventRecord.query(on: h.db).filter(\.$action == "device.enroll_failed").all()
            XCTAssertTrue(audited.contains { $0.metadataJSON.contains("attestation_required") })
            // With a genuine attestation both enroll, and every key is attested.
            let ok = try await h.enrollAttested(user, evidence: genuineEvidence(pki, clock: h.clock))
            XCTAssertEqual(ok.0.status, .created, ok.0.text)
            var enrolled = user
            enrolled.device = ok.1
            let listed = try await devices(h, enrolled)
            XCTAssertTrue(listed[0].keys.allSatisfy { $0.attested && $0.hardwareBacked })
            let record = try await XCTUnwrapAsync(try await DeviceRecord.find(ok.1!.id.uuid, on: h.db))
            XCTAssertEqual(record.attestationStatus, "attested")
            let clipOk = try await h.enrollAttested(user, purposes: [.request], clientKind: .appClip, evidence: genuineEvidence(pki, clock: h.clock, clientKind: .appClip))
            XCTAssertEqual(clipOk.0.status, .created, clipOk.0.text)
        }
    }

    func testAnAttestationCannotBeReplayedToVouchForDifferentKeys() async throws {
        try await withAttestHarness(pki, mode: .require) { h, pki in
            let user = try await h.registerConsumer()
            // The attacker holds a genuine attestation (for some key list) but enrolls their own software keys.
            let foreign = [DeviceKeyRegistration(purpose: .request, publicKey: SoftwareP256SigningKey().publicKey, hardwareBacked: true, proof: "x")]
            let replayed = try await h.enrollAttested(user) { _, challenge, consumer in
                try pki.attest(clientDataHash: AppAttestBinding.clientDataHash(consumerId: consumer, challenge: challenge, keys: foreign), now: h.clock.now()).evidence
            }
            XCTAssertEqual(replayed.0.errorCode, .attestationRequired, replayed.0.text)
            // An attestation made for another challenge (a previous enrollment) is just as useless.
            let stale = try await h.enrollAttested(user) { keys, _, consumer in
                try pki.attest(clientDataHash: AppAttestBinding.clientDataHash(consumerId: consumer, challenge: "an-old-challenge", keys: keys), now: h.clock.now()).evidence
            }
            XCTAssertEqual(stale.0.errorCode, .attestationRequired)
            try await eq(try await DeviceRecord.query(on: h.db).count(), 0)
        }
    }

    func testOneAppAttestKeyVouchesForOneDeviceOnly() async throws {
        try await withAttestHarness(pki, mode: .require) { h, pki in
            let key = P256.Signing.PrivateKey()
            let first = try await h.enrollAttested(try await h.registerConsumer(), evidence: genuineEvidence(pki, clock: h.clock, key: key))
            XCTAssertEqual(first.0.status, .created, first.0.text)
            let second = try await h.enrollAttested(try await h.registerConsumer(), evidence: genuineEvidence(pki, clock: h.clock, key: key))
            XCTAssertEqual(second.0.errorCode, .attestationRequired, "the same App Attest key cannot back another device")
            try await eq(try await AppAttestKeyRecord.query(on: h.db).count(), 1)
        }
    }

    func testReportModeAcceptsUnattestedDevicesButFlagsThemAndCoolsThemDownFor72Hours() async throws {
        try await withAttestHarness(pki, mode: .report) { h, pki in
            let user = try await h.registerConsumer()
            // A brand-new account's first device has nobody to confirm it: no cool-down, but it is flagged.
            let first = try await h.enrollAttested(user) { _, _, _ in nil }
            XCTAssertEqual(first.0.status, .created, first.0.text)
            var a = user
            a.device = first.1
            let firstRecord = try await XCTUnwrapAsync(try await DeviceRecord.find(first.1!.id.uuid, on: h.db))
            XCTAssertNil(firstRecord.approvalsLockedUntil)
            XCTAssertEqual(firstRecord.attestationStatus, "unattested")
            // A second device that cannot attest cools down for 72 h; one that does, 24 h.
            let plain = try await h.enrollAttested(a) { _, _, _ in nil }
            XCTAssertEqual(plain.0.status, .created, plain.0.text)
            let plainRecord = try await XCTUnwrapAsync(try await DeviceRecord.find(plain.1!.id.uuid, on: h.db))
            XCTAssertEqual(plainRecord.approvalsLockedUntil, h.clock.now().addingTimeInterval(72 * 3600))
            let attested = try await h.enrollAttested(a, evidence: genuineEvidence(pki, clock: h.clock))
            XCTAssertEqual(attested.0.status, .created, attested.0.text)
            let attestedRecord = try await XCTUnwrapAsync(try await DeviceRecord.find(attested.1!.id.uuid, on: h.db))
            XCTAssertEqual(attestedRecord.approvalsLockedUntil, h.clock.now().addingTimeInterval(24 * 3600))
            XCTAssertEqual(attestedRecord.attestationStatus, "attested")
            // Flagged in the audit log.
            let events = try await AuditEventRecord.query(on: h.db).filter(\.$action == "device.enrolled").all()
            XCTAssertEqual(events.filter { $0.metadataJSON.contains("\"flagged\":\"unattested\"") }.count, 2)
            XCTAssertTrue(events.contains { $0.metadataJSON.contains("\"cool_down_hours\":\"72\"") })
            // A rejected (invalid) attestation is recorded as such.
            let bad = try await h.enrollAttested(a) { _, _, _ in AppAttestEvidence(keyId: "AAAA", attestation: "AAAA") }
            XCTAssertEqual(bad.0.status, .created)
            try await eq(try await DeviceRecord.find(bad.1!.id.uuid, on: h.db)?.attestationStatus, "rejected")
        }
    }

    func testOffModeVerifiesWhenSentAndNeverRequiresIt() async throws {
        try await withAttestHarness(pki, mode: .off) { h, pki in
            let user = try await h.registerConsumer()
            let attested = try await h.enrollAttested(user, evidence: genuineEvidence(pki, clock: h.clock))
            XCTAssertEqual(attested.0.status, .created)
            var a = user
            a.device = attested.1
            let listed = try await devices(h, a)
            XCTAssertTrue(listed[0].keys.allSatisfy(\.attested))
            let plain = try await h.enrollAttested(a) { _, _, _ in nil }
            XCTAssertEqual(plain.0.status, .created)
            let record = try await XCTUnwrapAsync(try await DeviceRecord.find(plain.1!.id.uuid, on: h.db))
            XCTAssertEqual(record.approvalsLockedUntil, h.clock.now().addingTimeInterval(24 * 3600), "off mode keeps the ordinary 24 h cool-down")
            // A wrongly bound attestation is not an error in off mode, it just does not attest.
            let foreign = try await h.enrollAttested(a) { _, challenge, consumer in
                try pki.attest(clientDataHash: AppAttestBinding.clientDataHash(consumerId: consumer, challenge: challenge, keys: []), now: h.clock.now()).evidence
            }
            XCTAssertEqual(foreign.0.status, .created)
            let listedB = try await devices(h, foreign.2)
            XCTAssertTrue(listedB.first { $0.id == foreign.1!.id }!.keys.allSatisfy { !$0.attested })
        }
    }

    func testALapsedAccountsNewDeviceCoolsDownForeverAndMustAttest() async throws {
        try await withAttestHarness(pki, mode: .require) { h, pki in
            let user = try await h.registerConsumer()
            let first = try await h.enrollAttested(user, evidence: genuineEvidence(pki, clock: h.clock))
            XCTAssertEqual(first.0.status, .created, first.0.text)
            var a = user
            a.device = first.1
            // The only device is removed; a year passes; the thief arrives with the synced passkey.
            try await eq(try await h.signed(a, .DELETE, "/v1/devices/\(first.1!.id)").status, .ok)
            h.clock.advance(by: 400 * 86_400)
            let unattested = try await h.enrollAttested(a) { _, _, _ in nil }
            XCTAssertEqual(unattested.0.errorCode, .attestationRequired, "a lapsed account's new device must attest in require mode")
            let ok = try await h.enrollAttested(a, evidence: genuineEvidence(pki, clock: h.clock))
            XCTAssertEqual(ok.0.status, .created, ok.0.text)
            let record = try await XCTUnwrapAsync(try await DeviceRecord.find(ok.1!.id.uuid, on: h.db))
            XCTAssertEqual(record.approvalsLockedUntil, h.clock.now().addingTimeInterval(24 * 3600), "no lookback limit: it is not a trusted device for 24 h")
            let events = try await AuditEventRecord.query(on: h.db).filter(\.$action == "device.enrolled").all()
            XCTAssertTrue(events.last?.metadataJSON.contains("\"cool_down\":\"true\"") == true)
        }
    }

    func testTheModeAndEnvironmentComeFromTheEnvironmentWithSafeDefaults() throws {
        func config(_ env: [String: String]) throws -> ServerConfig {
            var config = ServerConfig.testing()
            try config.applyIdentityEnvironment(env, production: env["ENVIRONMENT"] == "production")
            return config
        }
        XCTAssertEqual(try config(["ENVIRONMENT": "production"]).appAttestMode, .require, "require is the production default")
        XCTAssertEqual(try config([:]).appAttestMode, .off)
        XCTAssertEqual(try config(["ENVIRONMENT": "production", "APP_ATTEST_MODE": "report"]).appAttestMode, .report)
        XCTAssertEqual(try config(["APP_ATTEST_MODE": "REQUIRE"]).appAttestMode, .require)
        XCTAssertThrowsError(try config(["APP_ATTEST_MODE": "maybe"]))
        // `off` waives integrity as a D1 condition (§2.5a): it never boots in staging or production.
        XCTAssertThrowsError(try config(["ENVIRONMENT": "production", "APP_ATTEST_MODE": "off"]))
        XCTAssertEqual(try config(["APP_ATTEST_MODE": "off"]).appAttestMode, .off)
        XCTAssertEqual(try config(["APP_ATTEST_ENVIRONMENT": "development"]).appAttestEnvironment, .development)
        XCTAssertThrowsError(try config(["APP_ATTEST_ENVIRONMENT": "sandbox"]))
        // The full loader wires it up and refuses a typo.
        var env = ["ENVIRONMENT": "development", "APP_ATTEST_MODE": "report"]
        XCTAssertEqual(try ServerConfig.fromEnvironment(env).appAttestMode, .report)
        env["APP_ATTEST_MODE"] = "nope"
        XCTAssertThrowsError(try ServerConfig.fromEnvironment(env))
    }
}
