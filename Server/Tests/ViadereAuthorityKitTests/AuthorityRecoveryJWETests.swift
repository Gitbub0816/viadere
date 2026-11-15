@preconcurrency import Crypto
import _CryptoExtras
import Fluent
import Foundation
import Vapor
import ViadereCore
import ViadereServiceSupport
import XCTest
@testable import ViadereAuthorityKit

/// ADR-0034 §9 (C-16): the JWE `RSA-OAEP-256` + `A256GCM` seal construction to `recovery-seal-rsa`, decrypted by the KMS at most once per challenge,
/// behind the seal switch (`AUTHORITY_KEY_SEAL_RSA`). The lean HPKE construction stays the default.
final class AuthorityRecoveryJWETests: XCTestCase {
    var h: AuthorityHarness!
    var sealKid: String!
    var sealPublicKey: _RSA.Encryption.PublicKey!
    static let recoveryId = RecoveryCodeFormat.normalizeRecoveryID("ABCD-EFGH-JKMN")!

    override func setUp() async throws {
        h = try await AuthorityHarness.makeWith { $0.recoverySeal = .jweRSA }
        // The decrypt-only RSA 3072 key in the KMS, its reviewed version pin, and the thumbprint as the development app pin.
        let version = try h.kms.createDecryptionKey("recovery-seal-rsa")
        let rsa = try await h.kms.rsaPublicKey(keyRef: "recovery-seal-rsa/\(version)")
        let p = try rsa.getKeyPrimitives()
        sealKid = JWKThumbprint.rsa(modulus: p.modulus, exponent: p.publicExponent)
        sealPublicKey = try _RSA.Encryption.PublicKey(derRepresentation: rsa.derRepresentation)
        try await AuthorityAdmin.run(command: "key-version-pin", changeFile: try CanonicalJSON.serialize(.object([
            "name": .string("recovery-seal-rsa"), "version": .string(version), "thumbprint": .string(sealKid)])), commit: AuthorityHarness.commit, db: h.app.db,
            config: h.config, now: h.clock.now)
        try await reload(pins: [sealKid])
        XCTAssertNotNil(h.app.authority.rsaSeal)
        XCTAssertNil(h.app.authority.seal)
    }
    override func tearDown() async throws { try await h.shutdown() }

    func reload(pins: [String]) async throws {
        let ctx = h.app.authority
        let rsaSeal = try await RSASealKey.load(kms: ctx.kms, db: h.app.db, name: "recovery-seal-rsa", pinnedKids: pins)
        h.app.authority = AuthorityContext(config: ctx.config, kms: ctx.kms, keys: ctx.keys, clock: ctx.clock, seal: nil, rsaSeal: rsaSeal, appAttest: ctx.appAttest)
    }

    var accountRef: String { h.harnessAccountRef }

    /// The device: RSA-OAEP-256 (SHA-256 and MGF1-SHA-256) of the content key under the pinned public key.
    func seal(_ plaintext: JSONValue, purpose: RecoverySealPurpose, challengeId: String, nonce: String, kid: String? = nil,
              padding: _RSA.Encryption.Padding = .PKCS1_OAEP_SHA256) throws -> RecoverySealJWE.Envelope {
        try RecoverySealJWE.seal(plaintext, kid: kid ?? sealKid, purpose: purpose, environment: .staging, challengeId: challengeId, nonce: nonce) { cek in
            try self.sealPublicKey.encrypt(cek, padding: padding)
        }
    }

    func decryptRecords() async throws -> [AuthoritySignRecord] { try await AuthoritySignRecord.query(on: h.app.db).filter(\.$kind == "decrypt").all() }

    func registerSet(codes: [String] = RecoverySeal.generateCodes(), purpose: RecoverySealPurpose = .codesSet, envelopeFor: ((AuthorityChallengeStatement, JSONValue) throws -> JSONValue)? = nil)
        async throws -> (status: HTTPStatus, codes: [String], statement: AuthorityChallengeStatement) {
        let setId = RecoverySeal.generateSetId()
        let created = try await h.keylogChallenge(["purpose": .string("recovery_codes_set"), "account_id": .string(h.accountId.uuidString), "set_id": .string(setId)])
        let statement = try XCTUnwrap(created.statement, "\(created.body)")
        let plaintext = RecoverySeal.setPlaintext(accountRef: accountRef, setId: setId, nonce: statement.nonce, codes: codes)
        let envelope: JSONValue = try envelopeFor?(statement, plaintext)
            ?? .string(try seal(plaintext, purpose: purpose, challengeId: statement.challengeId, nonce: statement.nonce).compact)
        let digest = envelope.stringValue.map(RecoverySealJWE.digest) ?? (try? RecoverySealEnvelope.parse(envelope))?.digest ?? ""
        let factor = try await h.factor(statement, key: h.biometricKey) { $0.envelopeDigest = digest }
        let result = try await h.post(AuthorityKeyLogRoute.evidence, ["factor": .string(factor), "envelope": envelope])
        return (result.status, codes, statement)
    }

    func startChallenge() async throws -> AuthorityChallengeStatement {
        let created = try await h.keylogChallenge(["purpose": .string("recovery_started"), "account_id": .string(h.accountId.uuidString), "recovery_id": .string(Self.recoveryId)])
        return try XCTUnwrap(created.statement, "\(created.body)")
    }

    func start(code: String, key: SoftwareP256SigningKey, statement given: AuthorityChallengeStatement? = nil, sealedFor: AuthorityChallengeStatement? = nil,
               popSigner: SoftwareP256SigningKey? = nil) async throws -> (status: HTTPStatus, body: [String: JSONValue], statement: AuthorityChallengeStatement, compact: String) {
        let statement: AuthorityChallengeStatement
        if let given { statement = given } else { statement = try await startChallenge() }
        let target = sealedFor ?? statement
        let envelope = try seal(RecoverySeal.startPlaintext(recoveryId: Self.recoveryId, nonce: statement.nonce, code: code, newKids: [AuthorityHarness.kid(key)]),
                                purpose: .start, challengeId: target.challengeId, nonce: target.nonce)
        let keys = try await h.submitted([(key, .approvalBiometric)], type: "recovery_started", nonce: statement.nonce, extra: [envelope.digest], popSigner: popSigner)
        let result = try await h.post(AuthorityKeyLogRoute.recoveryStart, ["ach": .string(statement.challengeId), "envelope": .string(envelope.compact), "keys": keys])
        return (result.status, result.body, statement, envelope.compact)
    }

    // MARK: The construction end to end

    func testASetAndAStartSealedWithJWEOpenThroughOneRecordedDecryptEachAndActivate() async throws {
        let set = try await registerSet()
        XCTAssertEqual(set.status, .ok)
        let rows = try await AuthorityRecoveryCode.query(on: h.app.db).filter(\.$accountRef == accountRef).all()
        XCTAssertEqual(rows.count, 10)
        XCTAssertTrue(rows.allSatisfy { $0.sealKid == sealKid })
        var records = try await decryptRecords()
        XCTAssertEqual(records.count, 1)
        XCTAssertEqual(records.first?.challengeId, set.statement.challengeId)
        XCTAssertTrue(records.first?.keyRef.hasPrefix("recovery-seal-rsa/") == true)
        let head = try AuthorityStatementVerifier.verifyHead(try await h.head(h.accountId), pinnedKeys: [h.statementKey], environment: .staging,
                                                             ownKids: [AuthorityHarness.kid(h.biometricKey)], minimumSeq: 0, now: h.clock.now)
        XCTAssertEqual(head.recoverySet, "active")

        let newKey = SoftwareP256SigningKey()
        let started = try await start(code: set.codes[4], key: newKey)
        XCTAssertEqual(started.status, .ok, "\(started.body)")
        records = try await decryptRecords()
        XCTAssertEqual(records.count, 2)
        XCTAssertEqual(Set(records.compactMap(\.challengeId)), [set.statement.challengeId, started.statement.challengeId])
        await XCTAssertEqualAsync(try await AuthorityChallenge.find(started.statement.challengeId, on: h.app.db)?.state, "used")
        h.clock.advance(72 * 3600 + 1)
        await XCTAssertEqualAsync(try await AuthorityRecoveryService(ctx: h.app.authority, db: h.app.db).activateDue(), 1)
        await XCTAssertEqualAsync(try await AuthorityKey.find(AuthorityHarness.kid(newKey), on: h.app.db)?.grantCapable, true)

        // Reconciliation: one Key Vault decrypt per record matches; one more alerts.
        let now = h.clock.now
        let ops = records.map { KeyVaultAuditOperation(operation: "KeyDecrypt", keyRef: $0.keyRef, at: $0.at.addingTimeInterval(1)) }
        XCTAssertTrue(AuthorityReconciliation.reconcile(operations: ops, records: records.map { ($0.keyRef, $0.kind, $0.at) }).unmatched.isEmpty)
        let rogue = KeyVaultAuditOperation(operation: "Decrypt", keyRef: records[0].keyRef, at: now)
        XCTAssertEqual(AuthorityReconciliation.reconcile(operations: ops + [rogue], records: records.map { ($0.keyRef, $0.kind, $0.at) }).unmatched, [rogue])
    }

    // MARK: Exploit paths (ST-REC-14, -15, -21 on this construction)

    /// ST-REC-14: an envelope sealed for one challenge, relayed for another, is refused on its header before any Key Vault call (no decrypt record),
    /// and the challenge it was relayed for stays answerable.
    func testAnEnvelopeRelayedForAnotherChallengeIsRefusedBeforeAnyDecrypt() async throws {
        let set = try await registerSet()
        let first = try await startChallenge()
        let second = try await startChallenge()
        let before = try await decryptRecords().count
        let relayed = try await start(code: set.codes[0], key: SoftwareP256SigningKey(), statement: second, sealedFor: first)
        XCTAssertEqual(relayed.status, .unauthorized)
        await XCTAssertEqualAsync(try await decryptRecords().count, before)
        await XCTAssertEqualAsync(try await AuthorityChallenge.find(second.challengeId, on: h.app.db)?.state, "pending")
        await XCTAssertEqualAsync(try await AuthorityRecoveryAttempt.query(on: h.app.db).filter(\.$reason == "envelope_binding").count(), 1)
        // The wrong purpose type, another key id, an HPKE object and a tampered header are refused the same way.
        let wrongType = try await registerSet(purpose: .start)
        XCTAssertEqual(wrongType.status, .unauthorized)
        let otherKid = try await registerSet { statement, plaintext in
            .string(try self.seal(plaintext, purpose: .codesSet, challengeId: statement.challengeId, nonce: statement.nonce, kid: JWKThumbprint.p256(P256.Signing.PrivateKey().publicKey)).compact)
        }
        XCTAssertEqual(otherKid.status, .unauthorized)
        let hpke = try await registerSet { statement, plaintext in
            try RecoverySeal.seal(plaintext, to: P256.KeyAgreement.PrivateKey().publicKey, purpose: .codesSet, environment: .staging,
                                  challengeId: statement.challengeId, nonce: statement.nonce).json
        }
        XCTAssertEqual(hpke.status, .unauthorized)
        await XCTAssertEqualAsync(try await decryptRecords().count, before)
        let reasons = try await h.deniedReasons("authority.keylog_evidence")
        XCTAssertTrue(reasons.isSuperset(of: ["envelope_binding", "seal_kid", "envelope_malformed"]), "\(reasons)")
    }

    /// §9.3: at most one decrypt per challenge. The challenge moves `pending → opening` before the Key Vault call, so a second envelope for the same
    /// challenge (an adaptive query) is refused without another decrypt, and a failed open spends the challenge.
    func testASecondEnvelopeForTheSameChallengeGetsNoSecondDecrypt() async throws {
        let set = try await registerSet()
        let before = try await decryptRecords().count
        let statement = try await startChallenge()
        // A wrong code: one decrypt, then the code check fails; the challenge is spent.
        let wrong = try await start(code: RecoveryCodeFormat.normalizeCode(RecoveryCodeFormat.generateCode())!, key: SoftwareP256SigningKey(), statement: statement)
        XCTAssertEqual(wrong.status, .unauthorized)
        await XCTAssertEqualAsync(try await decryptRecords().count, before + 1)
        await XCTAssertEqualAsync(try await AuthorityChallenge.find(statement.challengeId, on: h.app.db)?.state, "opening")
        // The right code for the same challenge: refused, no second decrypt.
        let again = try await start(code: set.codes[0], key: SoftwareP256SigningKey(), statement: statement)
        XCTAssertEqual(again.status, .unauthorized)
        await XCTAssertEqualAsync(try await decryptRecords().count, before + 1)
        // A new challenge works with the unspent code.
        await XCTAssertEqualAsync(try await start(code: set.codes[0], key: SoftwareP256SigningKey()).status, .ok)
    }

    /// The race: two openings of the same challenge that both read it while `pending` (concurrent requests). Only the compare-and-swap to `opening`
    /// stands between them and a second, adaptive decrypt.
    func testConcurrentOpeningsOfOneChallengeMakeOneDecrypt() async throws {
        _ = try await registerSet()
        let before = try await decryptRecords().count
        let statement = try await startChallenge()
        let challenge = try await XCTUnwrapAsync(try await AuthorityChallenge.find(statement.challengeId, on: h.app.db))
        let envelope = try seal(RecoverySeal.startPlaintext(recoveryId: Self.recoveryId, nonce: statement.nonce, code: RecoverySeal.generateCodes()[0],
                                                            newKids: [AuthorityHarness.kid(SoftwareP256SigningKey())]),
                                purpose: .start, challengeId: statement.challengeId, nonce: statement.nonce)
        let service = AuthorityRecoveryService(ctx: h.app.authority, db: h.app.db)
        let opened = try await service.openSeal(.jwe(envelope), purpose: .start, challenge: challenge)
        XCTAssertEqual(opened.consumedFrom, "opening")
        do {
            _ = try await service.openSeal(.jwe(envelope), purpose: .start, challenge: challenge)
            XCTFail("a second opening of the same challenge must be refused")
        } catch let refusal as SealRefusal { XCTAssertEqual(refusal.reason, "challenge_not_pending") }
        await XCTAssertEqualAsync(try await decryptRecords().count, before + 1)
    }

    /// ST-REC-15 on this construction: a PoP that does not commit to this envelope is refused before the decrypt (no Key Vault call is spent on it).
    func testAPoPNotCommittingToTheEnvelopeCostsNoDecrypt() async throws {
        let set = try await registerSet()
        let before = try await decryptRecords().count
        let result = try await start(code: set.codes[0], key: SoftwareP256SigningKey(), popSigner: SoftwareP256SigningKey())
        XCTAssertEqual(result.status, .unauthorized)
        await XCTAssertEqualAsync(try await decryptRecords().count, before)
        await XCTAssertEqualAsync(try await AuthorityRecoveryAttempt.query(on: h.app.db).filter(\.$reason == "pop_invalid").count(), 1)
    }

    /// The content key wrapped with the provider default (OAEP with SHA-1 / MGF1-SHA-1) does not decrypt: one generic refusal, like any other.
    func testTheWrongOAEPParametersFailClosedWithTheGenericAnswer() async throws {
        let result = try await registerSet { statement, plaintext in
            .string(try self.seal(plaintext, purpose: .codesSet, challengeId: statement.challengeId, nonce: statement.nonce, padding: .PKCS1_OAEP).compact)
        }
        XCTAssertEqual(result.status, .unauthorized)
        await XCTAssertEqualAsync(try await decryptRecords().count, 1)
        await XCTAssertEqualAsync(try await AuthorityRecoveryCode.query(on: h.app.db).count(), 0)
        let reasons = try await h.deniedReasons("authority.keylog_evidence")
        XCTAssertTrue(reasons.contains("envelope_open_failed"), "\(reasons)")
    }

    /// Every seal decrypt carries its challenge: the recording KMS refuses a decrypt without one, so none can bypass the record.
    func testADecryptWithoutAChallengeIsRefused() async throws {
        let kms = try XCTUnwrap(h.app.authority.kms as? RecordingKMS)
        let ref = try XCTUnwrap(h.app.authority.rsaSeal?.keyRef)
        do {
            _ = try await kms.decrypt(keyRef: ref, ciphertext: Data(repeating: 0, count: 384))
            XCTFail("an unbound decrypt must be refused")
        } catch KMSError.wrongKeyType {}
        await XCTAssertEqualAsync(try await decryptRecords().count, 0)
    }

    /// Fail closed: without the app pin no RSA seal key loads and every recovery route answers `503`; the HPKE default never reads an RSA envelope.
    func testTheSwitchFailsClosedAndHPKEStaysTheDefault() async throws {
        try await reload(pins: [])
        XCTAssertNil(h.app.authority.rsaSeal)
        let blocked = try await h.keylogChallenge(["purpose": .string("recovery_codes_set"), "account_id": .string(h.accountId.uuidString), "set_id": .string(RecoverySeal.generateSetId())])
        XCTAssertEqual(blocked.status, .serviceUnavailable)
        XCTAssertEqual(AuthorityConfig.testing().recoverySeal, .hpke)
        var env = AuthorityControlTests.strictEnv
        XCTAssertEqual(try AuthorityConfig.fromEnvironment(env).recoverySeal, .hpke)
        env["AUTHORITY_KEY_SEAL_KEK"] = ""
        env["AUTHORITY_KEY_SEAL_RSA"] = "recovery-seal-rsa"
        XCTAssertEqual(try AuthorityConfig.fromEnvironment(env).recoverySeal, .jweRSA)
        env["AUTHORITY_KEY_SEAL_KEK"] = "recovery-seal-kek"
        XCTAssertThrowsError(try AuthorityConfig.fromEnvironment(env))
        // Production stays refused for recovery on either construction until the owner and reviewers lift C-16 (ADR-0034 §9.4).
        env["AUTHORITY_KEY_SEAL_KEK"] = ""
        env["ENVIRONMENT"] = "production"
        env["AUTHORITY_RECOVERY_ENABLED"] = "true"
        env["AUTHORITY_KEYLOG_ENABLED"] = "true"
        env["APPLE_TEAM_ID"] = "ABCDE12345"
        XCTAssertThrowsError(try AuthorityConfig.fromEnvironment(env)) { XCTAssertTrue("\($0)".contains("AUTHORITY_RECOVERY_ENABLED")) }
        // A pinned key whose thumbprint differs stops the start.
        let version = try h.kms.createDecryptionKey("recovery-seal-rsa")
        try await AuthorityAdmin.run(command: "key-version-pin", changeFile: try CanonicalJSON.serialize(.object([
            "name": .string("recovery-seal-rsa"), "version": .string(version), "thumbprint": .string(sealKid)])), commit: AuthorityHarness.commit, db: h.app.db,
            config: h.config, now: h.clock.now)
        do {
            try await reload(pins: [sealKid])
            XCTFail("a pinned version with another thumbprint must stop the start")
        } catch AuthorityKeyError.thumbprintMismatch(_) {}
    }
}
