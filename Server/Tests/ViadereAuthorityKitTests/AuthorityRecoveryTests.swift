@preconcurrency import Crypto
import _CryptoExtras
import Fluent
import Foundation
import SQLKit
import Vapor
import ViadereCore
import ViadereServiceSupport
import XCTest
@testable import ViadereAuthorityKit

/// Sealed recovery (ADR-0032 §3, ADR-0034), link-service redemption (ADR-0021 §5), retention purge (S6-08) and the Key Vault reconciliation (S6-07).
final class AuthorityRecoveryTests: XCTestCase {
    var h: AuthorityHarness!
    static let recoveryId = "ABCD-EFGH-JKMN"

    override func setUp() async throws {
        h = try await AuthorityHarness.make()
        try await h.installSealKey()
    }
    override func tearDown() async throws { try await h.shutdown() }

    var accountRef: String { OIDCProfile.accountRef(key: h.config.accountRefKey, accountId: h.accountId) }
    var recoveryId: String { RecoveryCodeFormat.normalizeRecoveryID(Self.recoveryId)! }

    /// The device registers a set: challenge naming its set id, envelope sealed to the pinned seal key, factor JWS with `envelope_digest`.
    func registerSet(codes: [String] = RecoverySeal.generateCodes(), key: SoftwareP256SigningKey? = nil, uv: FactorUserVerification = .biometric,
                     mutatePlaintext: ((inout [String: JSONValue]) -> Void)? = nil) async throws -> (status: HTTPStatus, codes: [String], setId: String) {
        let setId = RecoverySeal.generateSetId()
        let created = try await h.keylogChallenge(["purpose": .string("recovery_codes_set"), "account_id": .string(h.accountId.uuidString), "set_id": .string(setId)])
        let statement = try XCTUnwrap(created.statement)
        var plaintext = RecoverySeal.setPlaintext(accountRef: accountRef, setId: setId, nonce: statement.nonce, codes: codes).objectValue!
        mutatePlaintext?(&plaintext)
        let envelope = try RecoverySeal.seal(.object(plaintext), to: h.sealPublicKey, purpose: .codesSet, environment: .staging, challengeId: statement.challengeId, nonce: statement.nonce)
        let factor = try await h.factor(statement, key: key ?? h.biometricKey, uv: uv) { $0.envelopeDigest = envelope.digest }
        let result = try await h.post(AuthorityKeyLogRoute.evidence, ["factor": .string(factor), "envelope": envelope.json])
        return (result.status, codes, setId)
    }

    func startChallenge() async throws -> AuthorityChallengeStatement {
        let created = try await h.keylogChallenge(["purpose": .string("recovery_started"), "account_id": .string(h.accountId.uuidString), "recovery_id": .string(recoveryId)])
        return try XCTUnwrap(created.statement, "\(created.body)")
    }

    func start(code: String, newKeys: [(SoftwareP256SigningKey, DeviceKeyPurpose)], sealedKids: [String]? = nil, statement given: AuthorityChallengeStatement? = nil,
               aadChallenge: AuthorityChallengeStatement? = nil) async throws -> (status: HTTPStatus, body: [String: JSONValue]) {
        let statement: AuthorityChallengeStatement
        if let given { statement = given } else { statement = try await startChallenge() }
        let kids = sealedKids ?? newKeys.map { AuthorityHarness.kid($0.0) }
        let sealFor = aadChallenge ?? statement
        let envelope = try RecoverySeal.seal(RecoverySeal.startPlaintext(recoveryId: recoveryId, nonce: statement.nonce, code: code, newKids: kids), to: h.sealPublicKey,
                                             purpose: .start, environment: .staging, challengeId: sealFor.challengeId, nonce: sealFor.nonce)
        let keys = try await h.submitted(newKeys, type: "recovery_started", nonce: statement.nonce, extra: [envelope.digest])
        return try await h.post(AuthorityKeyLogRoute.recoveryStart, ["ach": .string(statement.challengeId), "envelope": envelope.json, "keys": keys])
    }

    // MARK: Code sets (ADR-0032 §3.1, ADR-0034 §4; ST-REC-16)

    func testACodeSetIsSealedVerifiedAndStoredOnlyAsKeyedVerifiers() async throws {
        let result = try await registerSet()
        XCTAssertEqual(result.status, .ok)
        let rows = try await AuthorityRecoveryCode.query(on: h.app.db).filter(\.$accountRef == accountRef).all()
        XCTAssertEqual(rows.count, 10)
        XCTAssertTrue(rows.allSatisfy { $0.state == "active" && $0.sealKid == h.app.authority.seal!.kid && $0.setId == result.setId })
        // No code appears anywhere in the authority's rows.
        for code in result.codes { XCTAssertFalse(rows.contains { $0.verifier.contains(code) }) }
        let head = try AuthorityStatementVerifier.verifyHead(try await h.head(h.accountId), pinnedKeys: [h.statementKey], environment: .staging,
                                                             ownKids: [AuthorityHarness.kid(h.biometricKey)], minimumSeq: 0, now: h.clock.now)
        XCTAssertEqual(head.recoverySet, "active")
        // A second set supersedes the first.
        await XCTAssertEqualAsync(try await registerSet().status, .ok)
        await XCTAssertEqualAsync(try await AuthorityRecoveryCode.query(on: h.app.db).filter(\.$state == "superseded").count(), 10)
    }

    func testAUserPresenceKeyCannotRegisterASet() async throws {
        await XCTAssertEqualAsync(try await registerSet(key: h.presenceKey, uv: .userPresence).status, .unauthorized)
        await XCTAssertEqualAsync(try await AuthorityRecoveryCode.query(on: h.app.db).count(), 0)
    }

    func testASetForAnotherAccountOrSetIdOrNonceIsRefused() async throws {
        await XCTAssertEqualAsync(try await registerSet { $0["account_ref"] = .string("acct_" + String(repeating: "0", count: 32)) }.status, .unauthorized)
        await XCTAssertEqualAsync(try await registerSet { $0["set_id"] = .string(RecoverySeal.generateSetId()) }.status, .unauthorized)
        await XCTAssertEqualAsync(try await registerSet { $0["nonce"] = .string(AuthorityNonce.generate()) }.status, .unauthorized)
        await XCTAssertEqualAsync(try await AuthorityRecoveryCode.query(on: h.app.db).count(), 0)
    }

    // MARK: Start, activation, cancel (ADR-0032 §3.2-§3.3; ST-REC-07, -11, -14, -15)

    func testASealedStartActivatesAfter72HoursWithExactlyTheNewKeys() async throws {
        let set = try await registerSet()
        let newDevice = (SoftwareP256SigningKey(), SoftwareP256SigningKey())
        let started = try await start(code: set.codes[3], newKeys: [(newDevice.0, .approvalBiometric), (newDevice.1, .approvalUserPresence)])
        XCTAssertEqual(started.status, .ok, "\(started.body)")
        let head = try AuthorityStatementVerifier.verifyHead(try XCTUnwrap(started.body["head"]?.stringValue), pinnedKeys: [h.statementKey], environment: .staging,
                                                             ownKids: [], minimumSeq: 0, now: h.clock.now)
        try AuthorityStatementVerifier.requireExactPendingRecovery(head, newKids: [AuthorityHarness.kid(newDevice.0), AuthorityHarness.kid(newDevice.1)])
        let maintenance = { AuthorityRecoveryService(ctx: self.h.app.authority, db: self.h.app.db) }
        h.clock.advance(71 * 3600)
        await XCTAssertEqualAsync(try await maintenance().activateDue(), 0)
        h.clock.advance(3601)
        await XCTAssertEqualAsync(try await maintenance().activateDue(), 1)
        await XCTAssertEqualAsync(try await AuthorityKey.find(AuthorityHarness.kid(h.biometricKey), on: h.app.db)?.revokedAt != nil, true)
        await XCTAssertEqualAsync(try await AuthorityKey.find(AuthorityHarness.kid(newDevice.0), on: h.app.db)?.grantCapable, true)
        // The used code cannot start again.
        await XCTAssertEqualAsync(try await start(code: set.codes[3], newKeys: [(SoftwareP256SigningKey(), .approvalBiometric)]).status, .unauthorized)
    }

    func testAWrongCodeCountsAndTheLimitHolds() async throws {
        _ = try await registerSet()
        for _ in 0..<5 {
            await XCTAssertEqualAsync(try await start(code: RecoveryCodeFormat.normalizeCode(RecoveryCodeFormat.generateCode())!, newKeys: [(SoftwareP256SigningKey(), .approvalBiometric)]).status,
                           .unauthorized)
        }
        await XCTAssertEqualAsync(try await AuthorityRecoveryAttempt.query(on: h.app.db).filter(\.$reason == "code_mismatch").count(), 5)
        let blocked = try await h.keylogChallenge(["purpose": .string("recovery_started"), "account_id": .string(h.accountId.uuidString), "recovery_id": .string(recoveryId)])
        XCTAssertEqual(blocked.status, .tooManyRequests)
    }

    /// ST-REC-15: the PoP keys must equal the sealed `new_kids` exactly; an api-substituted key never becomes active.
    func testSubstitutedOrExtraKeysAreRefused() async throws {
        let set = try await registerSet()
        let genuine = SoftwareP256SigningKey(), attacker = SoftwareP256SigningKey()
        await XCTAssertEqualAsync(try await start(code: set.codes[0], newKeys: [(attacker, .approvalBiometric)], sealedKids: [AuthorityHarness.kid(genuine)]).status, .unauthorized)
        await XCTAssertEqualAsync(try await start(code: set.codes[0], newKeys: [(genuine, .approvalBiometric), (attacker, .approvalBiometric)],
                                       sealedKids: [AuthorityHarness.kid(genuine)]).status, .unauthorized)
        await XCTAssertEqualAsync(try await AuthorityRecoveryAttempt.query(on: h.app.db).filter(\.$reason == "new_kids_mismatch").count(), 2)
        // The code was not spent by the refused attempts.
        await XCTAssertEqualAsync(try await start(code: set.codes[0], newKeys: [(genuine, .approvalBiometric)]).status, .ok)
    }

    /// ST-REC-14: an envelope sealed for one challenge cannot be replayed against another (AEAD `aad`), and opens nothing.
    func testAnEnvelopeReplayedAgainstAnotherChallengeIsRefused() async throws {
        let set = try await registerSet()
        let first = try await startChallenge()
        let second = try await startChallenge()
        let result = try await start(code: set.codes[1], newKeys: [(SoftwareP256SigningKey(), .approvalBiometric)], statement: second, aadChallenge: first)
        XCTAssertEqual(result.status, .unauthorized)
        await XCTAssertEqualAsync(try await AuthorityRecoveryAttempt.query(on: h.app.db).filter(\.$reason == "envelope_open_failed").count(), 1)
    }

    func testAnyLoggedKeyCanCancelAPendingRecovery() async throws {
        let set = try await registerSet()
        await XCTAssertEqualAsync(try await start(code: set.codes[2], newKeys: [(SoftwareP256SigningKey(), .approvalBiometric)]).status, .ok)
        let created = try await h.keylogChallenge(["purpose": .string("recovery_cancel"), "account_id": .string(h.accountId.uuidString)])
        let factor = try await h.factor(try XCTUnwrap(created.statement), key: h.presenceKey, uv: .userPresence)
        await XCTAssertEqualAsync(try await h.post(AuthorityKeyLogRoute.evidence, ["factor": .string(factor)]).status, .ok)
        h.clock.advance(73 * 3600)
        await XCTAssertEqualAsync(try await AuthorityRecoveryService(ctx: h.app.authority, db: h.app.db).activateDue(), 0)
        await XCTAssertEqualAsync(try await AuthorityKey.find(AuthorityHarness.kid(h.biometricKey), on: h.app.db)?.revokedAt == nil, true)
    }

    /// ST-REC-07, -08, -20: a legacy start is refused while an authority set is active; without one its keys are never grant-capable.
    func testLegacyStartsNeverYieldGrantCapableKeys() async throws {
        func legacy(_ key: SoftwareP256SigningKey) async throws -> HTTPStatus {
            let nonce = try await h.nonce("recovery_started_legacy")
            return try await h.post(AuthorityKeyLogRoute.recoveryLegacyStart, ["account_id": .string(h.accountId.uuidString), "recovery_id": .string(recoveryId),
                "nonce_id": .string(nonce.id), "keys": try await h.submitted([(key, .approvalBiometric)], type: "recovery_started_legacy", nonce: nonce.value)]).status
        }
        let key = SoftwareP256SigningKey()
        await XCTAssertEqualAsync(try await legacy(key), .ok)
        h.clock.advance(73 * 3600)
        await XCTAssertEqualAsync(try await AuthorityRecoveryService(ctx: h.app.authority, db: h.app.db).activateDue(), 1)
        await XCTAssertEqualAsync(try await AuthorityKey.find(AuthorityHarness.kid(key), on: h.app.db)?.grantCapable, false)
        // That key cannot register a set (not grant-capable).
        let recovered = try await AuthorityHarness.make()
        try await recovered.installSealKey()
        _ = try await recovered.registerLegacyGuard()
        try await recovered.shutdown()
    }

    func testALegacyStartIsRefusedWithAnActiveAuthoritySet() async throws {
        _ = try await registerSet()
        let nonce = try await h.nonce("recovery_started_legacy")
        let result = try await h.post(AuthorityKeyLogRoute.recoveryLegacyStart, ["account_id": .string(h.accountId.uuidString), "recovery_id": .string(recoveryId),
            "nonce_id": .string(nonce.id), "keys": try await h.submitted([(SoftwareP256SigningKey(), .approvalBiometric)], type: "recovery_started_legacy", nonce: nonce.value)])
        XCTAssertEqual(result.status, .conflict)
    }

    /// ST-REC-23: `seal-key-exposed` invalidates exactly the sets sealed to that key; a start against them is refused; grant capability stays.
    func testAnExposedSealKeyInvalidatesExactlyItsSets() async throws {
        let set = try await registerSet()
        let kid = h.app.authority.seal!.kid
        try await AuthorityAdmin.run(command: "seal-key-exposed", changeFile: try CanonicalJSON.serialize(.object(["kid": .string(kid)])), commit: AuthorityHarness.commit,
                                     db: h.app.db, config: h.config, now: h.clock.now)
        await XCTAssertEqualAsync(try await AuthorityRecoveryCode.query(on: h.app.db).filter(\.$state == "invalidated").count(), 10)
        let head = try AuthorityStatementVerifier.verifyHead(try await h.head(h.accountId), pinnedKeys: [h.statementKey], environment: .staging,
                                                             ownKids: [AuthorityHarness.kid(h.biometricKey)], minimumSeq: 0, now: h.clock.now)
        XCTAssertEqual(head.recoverySet, "invalidated")
        await XCTAssertEqualAsync(try await start(code: set.codes[0], newKeys: [(SoftwareP256SigningKey(), .approvalBiometric)]).status, .unauthorized)
        await XCTAssertEqualAsync(try await AuthorityKey.find(AuthorityHarness.kid(h.biometricKey), on: h.app.db)?.grantCapable, true)
        // The exposed key is no longer loaded at the next start.
        try await h.reloadSeal(pins: [kid])
        XCTAssertNil(h.app.authority.seal)
    }

    // MARK: Seal-key custody (ADR-0034 §5.1, ST-AUTH-25)

    func testSealKeyCustodyRules() async throws {
        // One creation per job execution, and never a second ready key of the same role.
        do {
            try await h.installSealKey(role: "active")
            XCTFail("a second ready active seal key")
        } catch is AuthorityAdmin.Failure {}
        // The unwrap at start wrote its sign record before the Key Vault call.
        await XCTAssertEqualAsync(try await AuthoritySignRecord.query(on: h.app.db).filter(\.$kind == "unwrap").count(), 1)
        // A key that is not app-pinned is never loaded.
        try await h.reloadSeal(pins: [])
        XCTAssertNil(h.app.authority.seal)
        // Past its lifetime it is not loaded either.
        let kid = try await AuthoritySealKey.query(on: h.app.db).first()!.id!
        h.clock.advance(183 * 86_400)
        try await h.reloadSeal(pins: [kid])
        XCTAssertNil(h.app.authority.seal)
        // Without a seal key recovery fails closed.
        await XCTAssertEqualAsync(try await h.keylogChallenge(["purpose": .string("recovery_codes_set"), "account_id": .string(h.accountId.uuidString),
                                                    "set_id": .string(RecoverySeal.generateSetId())]).status, .serviceUnavailable)
    }

    func testTheStandbyComesFromAnotherExecution() async throws {
        let execution = "exec-standby"
        try await h.installSealKey(role: "standby", executionId: execution)
        do {
            try await h.installSealKey(role: "standby", executionId: execution)
            XCTFail("one seal-key create per execution")
        } catch is AuthorityAdmin.Failure {}
        let rows = try await AuthoritySealKey.query(on: h.app.db).all()
        XCTAssertEqual(Set(rows.map(\.jobExecutionId)).count, rows.count)
        // The wrapped blob never contains the private scalar in clear (it is RSA-OAEP output).
        XCTAssertTrue(rows.allSatisfy { ($0.wrappedPrivate.count) > 400 })
    }

    // MARK: Link-service redemption (ADR-0021 §5.4, §6; S6-05)

    func redeem(_ extra: [String: JSONValue], verifier: String = AuthorityHarness.codeVerifier, business: UUID = AuthorityHarness.businessId,
                client: String = AuthorityHarness.linkClientId) async throws -> (status: HTTPStatus, body: [String: JSONValue]) {
        var body: [String: JSONValue] = ["link_client_id": .string(client), "business_id": .string(business.uuidString), "code_verifier": .string(verifier)]
        for (k, v) in extra { body[k] = v }
        return try await h.post(AuthorityKeyLogRoute.linkRedeem, body)
    }

    func testSameDeviceCodeRedeemsOnceWithTheRightVerifierAndBusiness() async throws {
        let challenge = try await h.createLinkChallenge(crossDevice: false)
        let code = Base64URL.encode(SecureToken.randomBytes(32))
        let codeHash = Base64URL.encode(Data(SHA256.hash(data: Data(code.utf8))))
        await XCTAssertEqualAsync(try await h.submit(try await h.answer(challenge, codeHash: codeHash)).status, .ok)
        // Wrong verifier, another business, another client: refused and nothing consumed.
        await XCTAssertEqualAsync(try await redeem(["code": .string(code)], verifier: String(repeating: "x", count: 43)).status, .badRequest)
        await XCTAssertEqualAsync(try await redeem(["code": .string(code)], business: UUID()).status, .badRequest)
        await XCTAssertEqualAsync(try await redeem(["code": .string(code)], client: "lcl_other").status, .badRequest)
        // A code-less redemption of a same-device challenge is refused.
        await XCTAssertEqualAsync(try await redeem(["ach": .string(challenge.challengeId)]).status, .badRequest)
        let ok = try await redeem(["code": .string(code)])
        XCTAssertEqual(ok.status, .ok)
        let grant = try XCTUnwrap(ok.body["grant"]?.stringValue)
        XCTAssertNoThrow(try AuthorityGrantVerifier.verify(grant, keys: [JWKThumbprint.p256(h.grantKey): h.grantKey], issuer: AuthorityHarness.issuer + "/grant",
                                                           audience: AuthorityHarness.linkClientId, codeChallenge: AuthorityHarness.challenge(for: AuthorityHarness.codeVerifier),
                                                           now: h.clock.now))
        // Single use.
        await XCTAssertEqualAsync(try await redeem(["code": .string(code)]).status, .badRequest)
        await XCTAssertEqualAsync(try await AuthorityGrantRecord.query(on: h.app.db).filter(\.$kind == "grant").count(), 1)
        await XCTAssertEqualAsync(try await AuthorityAuditEvent.query(on: h.app.db).filter(\.$reason == "tenant_mismatch").count(), 1)
    }

    func testLinkCodesExpireAfter120Seconds() async throws {
        let challenge = try await h.createLinkChallenge(crossDevice: true)
        await XCTAssertEqualAsync(try await h.submit(try await h.answer(challenge)).status, .ok)
        h.clock.advance(121)
        await XCTAssertEqualAsync(try await redeem(["ach": .string(challenge.challengeId)]).status, .badRequest)
    }

    // MARK: Retention (S6-08) and reconciliation (S6-07)

    func testRetentionPurgesClassTRowsAndKeepsAppendOnlyEvidence() async throws {
        _ = try await h.approvedCode()
        let challenge = try await h.createLinkChallenge(crossDevice: true)
        await XCTAssertEqualAsync(try await h.submit(try await h.answer(challenge)).status, .ok)
        let audits = try await AuthorityAuditEvent.query(on: h.app.db).count(), entries = try await AuthorityKeylogEntry.query(on: h.app.db).count()
        // After a day: codes, link codes and nonces go; challenges stay (30 days of metadata).
        h.clock.advance(86_400 + 300)
        var deleted = try await AuthorityRetention.purge(h.app.db, now: h.clock.now)
        XCTAssertEqual(deleted[AuthorityOIDCCode.schema], 1)
        XCTAssertEqual(deleted[AuthorityLinkCode.schema], 1)
        XCTAssertEqual(deleted[AuthorityChallenge.schema] ?? 0, 0)
        h.clock.advance(30 * 86_400)
        deleted = try await AuthorityRetention.purge(h.app.db, now: h.clock.now)
        XCTAssertGreaterThan(deleted[AuthorityChallenge.schema] ?? 0, 0)
        XCTAssertGreaterThan(deleted[AuthoritySignRecord.schema] ?? 0, 0)
        await XCTAssertEqualAsync(try await AuthorityChallenge.query(on: h.app.db).count(), 0)
        // Class E evidence is untouched.
        await XCTAssertEqualAsync(try await AuthorityAuditEvent.query(on: h.app.db).count() >= audits, true)
        await XCTAssertEqualAsync(try await AuthorityKeylogEntry.query(on: h.app.db).count(), entries)
    }

    func testEverySignWritesARecordAndAnUnmatchedKeyVaultOperationAlerts() async throws {
        let before = try await AuthoritySignRecord.query(on: h.app.db).filter(\.$kind == "sign").count()
        _ = try await h.createLinkChallenge(crossDevice: true)
        let records = try await AuthoritySignRecord.query(on: h.app.db).filter(\.$kind == "sign").all()
        XCTAssertEqual(records.count, before + 1)
        let statementRef = try XCTUnwrap(records.last?.keyRef)
        XCTAssertTrue(statementRef.hasPrefix("device-statement-signing/"))
        let now = h.clock.now
        // Every operation matched: success.
        let matched = records.map { KeyVaultAuditOperation(operation: "KeySign", keyRef: $0.keyRef, at: $0.at.addingTimeInterval(1)) }
        let ok = try await AuthorityReconciliation.run(operations: matched, db: h.app.db, since: now.addingTimeInterval(-3600), until: now.addingTimeInterval(60))
        XCTAssertTrue(ok.unmatched.isEmpty)
        // One extra sign with no record (an oracle use outside the builders, or another identity): alert and failure.
        let rogue = KeyVaultAuditOperation(operation: "KeySign", keyRef: statementRef, at: now.addingTimeInterval(2))
        do {
            _ = try await AuthorityReconciliation.run(operations: matched + [rogue], db: h.app.db, since: now.addingTimeInterval(-3600), until: now.addingTimeInterval(60))
            XCTFail("an unmatched Key Vault sign must fail the reconciliation")
        } catch is AuthorityReconciliation.ReconciliationFailure {}
        await XCTAssertEqualAsync(try await AuthorityAuditEvent.query(on: h.app.db).filter(\.$event == "authority.kv_unmatched_operation").count(), 1)
        // An unwrap without a start record alerts the same way.
        let unwrap = KeyVaultAuditOperation(operation: "KeyUnwrap", keyRef: "recovery-seal-kek/0000", at: now)
        XCTAssertEqual(AuthorityReconciliation.reconcile(operations: [unwrap], records: []).unmatched, [unwrap])
        // Log Analytics rows parse.
        let rows: [[JSONValue]] = [[.string("2026-11-03T10:00:00.123Z"), .string("KeySign"), .string("https://kv-vdr-auth.vault.azure.net/keys/grant-signing/abc123")]]
        XCTAssertEqual(KeyVaultAuditOperation.parse(rows: rows).first?.keyRef, "grant-signing/abc123")
    }
}

extension AuthorityHarness {
    /// A key recovered through a legacy start is not grant-capable, so it cannot register a code set (ST-REC-20).
    func registerLegacyGuard() async throws -> HTTPStatus {
        let nonce = try await nonce("recovery_started_legacy")
        let key = SoftwareP256SigningKey()
        let recovery = "ABCDEFGHJKMN"
        await XCTAssertEqualAsync(try await post(AuthorityKeyLogRoute.recoveryLegacyStart, ["account_id": .string(accountId.uuidString), "recovery_id": .string(recovery),
            "nonce_id": .string(nonce.id), "keys": try await submitted([(key, .approvalBiometric)], type: "recovery_started_legacy", nonce: nonce.value)]).status, .ok)
        clock.advance(73 * 3600)
        try await AuthorityRecoveryService(ctx: app.authority, db: app.db).activateDue()
        let setId = RecoverySeal.generateSetId()
        let created = try await keylogChallenge(["purpose": .string("recovery_codes_set"), "account_id": .string(accountId.uuidString), "set_id": .string(setId)])
        let statement = try XCTUnwrap(created.statement)
        let ref = OIDCProfile.accountRef(key: config.accountRefKey, accountId: accountId)
        let envelope = try RecoverySeal.seal(RecoverySeal.setPlaintext(accountRef: ref, setId: setId, nonce: statement.nonce, codes: RecoverySeal.generateCodes()),
                                             to: sealPublicKey, purpose: .codesSet, environment: .staging, challengeId: statement.challengeId, nonce: statement.nonce)
        let factor = try await factor(statement, key: key) { $0.envelopeDigest = envelope.digest }
        let status = try await post(AuthorityKeyLogRoute.evidence, ["factor": .string(factor), "envelope": envelope.json]).status
        XCTAssertEqual(status, .unauthorized)
        return status
    }
}
