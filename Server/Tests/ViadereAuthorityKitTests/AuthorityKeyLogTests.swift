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

/// Key-log entries with proof (ADR-0023 §4, ADR-0032 §1, ADR-0033 §2, §4.1, §5): genesis, enrollment confirmation, device add with the C-13 caps,
/// signed heads and the hash chain. Each test names the control it would catch the removal of.
final class AuthorityKeyLogTests: XCTestCase {
    var h: AuthorityHarness!

    override func setUp() async throws { h = try await AuthorityHarness.make() }
    override func tearDown() async throws { try await h.shutdown() }

    func newDevice() -> (biometric: SoftwareP256SigningKey, presence: SoftwareP256SigningKey) { (SoftwareP256SigningKey(), SoftwareP256SigningKey()) }

    func audits(_ reason: String) async throws -> Int { try await AuthorityAuditEvent.query(on: h.app.db).filter(\.$reason == reason).count() }

    // MARK: Genesis (ADR-0032 §1.1-§1.3, ST-AUTH-15)

    func testGenesisMintsTheAccountIdAndRefusesACallerChosenOne() async throws {
        let device = newDevice()
        let result = try await h.genesis([(device.biometric, .approvalBiometric), (device.presence, .approvalUserPresence)])
        XCTAssertEqual(result.status, .ok)
        let accountId = try XCTUnwrap(result.accountId)
        let account = try await AuthorityAccount.find(accountId, on: h.app.db)
        XCTAssertEqual(account?.origin, "minted")
        // Keys are not grant-capable until enrollment_confirmed.
        await XCTAssertEqualAsync(try await AuthorityKey.find(AuthorityHarness.kid(device.biometric), on: h.app.db)?.grantCapable, false)
        // The head lists exactly the device's keys and verifies on the device.
        let head = try AuthorityStatementVerifier.verifyHead(try XCTUnwrap(result.head), pinnedKeys: [h.statementKey], environment: .staging,
                                                             ownKids: [AuthorityHarness.kid(device.biometric)], minimumSeq: 0, now: h.clock.now)
        XCTAssertEqual(head.accountRef, OIDCProfile.accountRef(key: h.config.accountRefKey, accountId: accountId))
        XCTAssertEqual(head.keys.count, 2)
        // A body naming an account id is refused (no such member).
        let nonce = try await h.nonce("genesis")
        let named = try await h.post(AuthorityKeyLogRoute.genesis, ["nonce_id": .string(nonce.id), "account_id": .string(UUID().uuidString),
                                                                    "keys": try await h.submitted([(newDevice().biometric, .approvalBiometric)], type: "genesis", nonce: nonce.value)])
        XCTAssertEqual(named.status, .unprocessableEntity)
    }

    func testGenesisNeedsAPoPByEveryKeyOverAFreshSingleUseNonce() async throws {
        let device = newDevice(), stranger = SoftwareP256SigningKey()
        // A PoP signed by another key.
        var nonce = try await h.nonce("genesis")
        var result = try await h.post(AuthorityKeyLogRoute.genesis, ["nonce_id": .string(nonce.id),
                                                                     "keys": try await h.submitted([(device.biometric, .approvalBiometric)], type: "genesis", nonce: nonce.value, popSigner: stranger)])
        XCTAssertEqual(result.status, .unauthorized)
        // A PoP over another type's string (a device_added PoP is not a genesis PoP).
        nonce = try await h.nonce("genesis")
        result = try await h.post(AuthorityKeyLogRoute.genesis, ["nonce_id": .string(nonce.id),
                                                                 "keys": try await h.submitted([(device.biometric, .approvalBiometric)], type: "device_added", nonce: nonce.value)])
        XCTAssertEqual(result.status, .unauthorized)
        // A valid PoP, then the same nonce again.
        nonce = try await h.nonce("genesis")
        let keys = try await h.submitted([(device.biometric, .approvalBiometric)], type: "genesis", nonce: nonce.value)
        await XCTAssertEqualAsync(try await h.post(AuthorityKeyLogRoute.genesis, ["nonce_id": .string(nonce.id), "keys": keys]).status, .ok)
        await XCTAssertEqualAsync(try await h.post(AuthorityKeyLogRoute.genesis, ["nonce_id": .string(nonce.id), "keys": keys]).status, .unauthorized)
        // A device_added nonce is not a genesis nonce.
        let other = try await h.nonce("device_added")
        await XCTAssertEqualAsync(try await h.post(AuthorityKeyLogRoute.genesis, ["nonce_id": .string(other.id),
            "keys": try await h.submitted([(newDevice().biometric, .approvalBiometric)], type: "genesis", nonce: other.value)]).status, .unauthorized)
    }

    /// S3-A2-4: one account per kid. A retried genesis with a key already logged (any account) is `409 key_in_use`.
    func testOneAccountPerKey() async throws {
        let device = newDevice()
        await XCTAssertEqualAsync(try await h.genesis([(device.biometric, .approvalBiometric)]).status, .ok)
        await XCTAssertEqualAsync(try await h.genesis([(device.biometric, .approvalBiometric)]).status, .conflict)
        // The harness's imported key too.
        await XCTAssertEqualAsync(try await h.genesis([(h.biometricKey, .approvalBiometric)]).status, .conflict)
        await XCTAssertEqualAsync(try await audits("key_in_use"), 2)
    }

    // MARK: Enrollment confirmation (ADR-0032 §1.4, ST-AUTH-23)

    func testEnrollmentConfirmationMakesTheEntryGrantCapableAndAnUnconfirmedKeyCannotYieldAGrant() async throws {
        let device = newDevice()
        let accountId = try await XCTUnwrapAsync(try await h.genesis([(device.biometric, .approvalBiometric), (device.presence, .approvalUserPresence)]).accountId)
        // Before confirmation: link evidence by the new key is refused (not grant-capable).
        let before = try await h.createLinkChallenge(crossDevice: true)
        await XCTAssertEqualAsync(try await h.submit(try await h.answer(before, key: device.biometric)).status, .unauthorized)
        await XCTAssertEqualAsync(try await audits("not_grant_capable"), 1)
        let confirmed = try await h.confirmEnrollment(keys: [device.biometric, device.presence], accountId: accountId)
        XCTAssertEqual(confirmed.status, .ok, "\(confirmed.body)")
        await XCTAssertEqualAsync(try await AuthorityKey.find(AuthorityHarness.kid(device.biometric), on: h.app.db)?.grantCapable, true)
        await XCTAssertEqualAsync(try await AuthorityAccountState.find(OIDCProfile.accountRef(key: h.config.accountRefKey, accountId: accountId), on: h.app.db)?.state, "active")
        let after = try await h.createLinkChallenge(crossDevice: true)
        await XCTAssertEqualAsync(try await h.submit(try await h.answer(after, key: device.biometric)).status, .ok)
    }

    func testEnrollmentRefusesAStaleHeadAndMissingPoPs() async throws {
        let device = newDevice()
        let accountId = try await XCTUnwrapAsync(try await h.genesis([(device.biometric, .approvalBiometric), (device.presence, .approvalUserPresence)]).accountId)
        let kids = [AuthorityHarness.kid(device.biometric), AuthorityHarness.kid(device.presence)]
        let head = try AuthorityStatementVerifier.verifyHead(try await h.head(accountId), pinnedKeys: [h.statementKey], environment: .staging, ownKids: kids, minimumSeq: 0, now: h.clock.now)
        // A head_hash other than the current head.
        var created = try await h.keylogChallenge(["purpose": .string("enrollment_confirmed"), "account_id": .string(accountId.uuidString), "kids": .array(kids.map { .string($0) })])
        var factor = try await h.factor(created.statement!, key: device.biometric) { $0.headHash = String(repeating: "a", count: 64); $0.seq = head.seq }
        var pops: [JSONValue] = []
        for key in [device.biometric, device.presence] {
            pops.append(.object(["kid": .string(AuthorityHarness.kid(key)), "pop": .string(try await AuthorityKeyLogFormat.signPoP(key, message: AuthorityKeyLogFormat.popMessage(
                environment: .staging, type: "enrollment_confirmed", kid: AuthorityHarness.kid(key), nonce: head.headHash)))]))
        }
        await XCTAssertEqualAsync(try await h.post(AuthorityKeyLogRoute.evidence, ["factor": .string(factor), "pops": .array(pops)]).status, .unauthorized)
        await XCTAssertEqualAsync(try await audits("head_mismatch"), 1)
        // The right head but only one of the two PoPs.
        created = try await h.keylogChallenge(["purpose": .string("enrollment_confirmed"), "account_id": .string(accountId.uuidString), "kids": .array(kids.map { .string($0) })])
        factor = try await h.factor(created.statement!, key: device.biometric) { $0.headHash = head.headHash; $0.seq = head.seq }
        await XCTAssertEqualAsync(try await h.post(AuthorityKeyLogRoute.evidence, ["factor": .string(factor), "pops": .array([pops[0]])]).status, .unauthorized)
        await XCTAssertEqualAsync(try await AuthorityKey.query(on: h.app.db).filter(\.$id ~~ kids).filter(\.$grantCapable == true).count(), 0)
    }

    /// ST-AUTH-23: genesis with the victim's keys plus an attacker key: the victim's device refuses the head (not exactly its keys); and if the
    /// victim's keys confirm without the attacker key, no key of the entry becomes grant-capable.
    func testAnAttackerKeyBesideTheVictimsKeysBlocksGrantCapability() async throws {
        let victim = newDevice(), attacker = SoftwareP256SigningKey()
        let accountId = try await XCTUnwrapAsync(try await h.genesis([(victim.biometric, .approvalBiometric), (victim.presence, .approvalUserPresence),
                                                            (attacker, .approvalBiometric)]).accountId)
        let head = try AuthorityStatementVerifier.verifyHead(try await h.head(accountId), pinnedKeys: [h.statementKey], environment: .staging,
                                                             ownKids: [AuthorityHarness.kid(victim.biometric)], minimumSeq: 0, now: h.clock.now)
        XCTAssertThrowsError(try AuthorityStatementVerifier.requireExactEntry(head, ownKids: [AuthorityHarness.kid(victim.biometric), AuthorityHarness.kid(victim.presence)]))
        // Bypass the device check (a compromised app): the victim's keys confirm, the attacker key never does.
        let kids = [AuthorityHarness.kid(victim.biometric), AuthorityHarness.kid(victim.presence)]
        let created = try await h.keylogChallenge(["purpose": .string("enrollment_confirmed"), "account_id": .string(accountId.uuidString), "kids": .array(kids.map { .string($0) })])
        let factor = try await h.factor(created.statement!, key: victim.biometric) { $0.headHash = head.headHash; $0.seq = head.seq }
        var pops: [JSONValue] = []
        for key in [victim.biometric, victim.presence] {
            pops.append(.object(["kid": .string(AuthorityHarness.kid(key)), "pop": .string(try await AuthorityKeyLogFormat.signPoP(key, message: AuthorityKeyLogFormat.popMessage(
                environment: .staging, type: "enrollment_confirmed", kid: AuthorityHarness.kid(key), nonce: head.headHash)))]))
        }
        await XCTAssertEqualAsync(try await h.post(AuthorityKeyLogRoute.evidence, ["factor": .string(factor), "pops": .array(pops)]).status, .ok)
        await XCTAssertEqualAsync(try await AuthorityKey.query(on: h.app.db).filter(\.$accountRef == head.accountRef).filter(\.$grantCapable == true).count(), 0)
    }

    func testAnUnconfirmedImportedKeyStaysNonGrantCapable() async throws {
        let unconfirmed = try await AuthorityHarness.make(.init(confirmImportedKeys: false))
        let challenge = try await unconfirmed.createLinkChallenge(crossDevice: true)
        await XCTAssertEqualAsync(try await unconfirmed.submit(try await unconfirmed.answer(challenge)).status, .unauthorized)
        await XCTAssertEqualAsync(try await AuthorityAuditEvent.query(on: unconfirmed.app.db).filter(\.$reason == "not_grant_capable").count(), 1)
        try await unconfirmed.shutdown()
    }

    func testUnconfirmedMintedAccountsAreClosedAfter24Hours() async throws {
        let device = newDevice()
        let accountId = try await XCTUnwrapAsync(try await h.genesis([(device.biometric, .approvalBiometric)]).accountId)
        h.clock.advance(23 * 3600)
        await XCTAssertEqualAsync(try await AuthorityMaintenance(ctx: h.app.authority, db: h.app.db).closeUnconfirmedAccounts(), 0)
        h.clock.advance(2 * 3600)
        await XCTAssertEqualAsync(try await AuthorityMaintenance(ctx: h.app.authority, db: h.app.db).closeUnconfirmedAccounts(), 1)
        await XCTAssertEqualAsync(try await AuthorityKey.find(AuthorityHarness.kid(device.biometric), on: h.app.db)?.revokedAt != nil, true)
        // The api is told the account does not exist.
        await XCTAssertEqualAsync(try await h.post(AuthorityKeyLogRoute.head, ["account_id": .string(accountId.uuidString)]).status, .notFound)
        // The harness's confirmed account is untouched.
        await XCTAssertEqualAsync(try await AuthorityKey.find(AuthorityHarness.kid(h.biometricKey), on: h.app.db)?.revokedAt == nil, true)
    }

    // MARK: Device add (ADR-0033 §4.1, C-13, ST-REC-10, -18, -22)

    func submitEntry(_ device: (biometric: SoftwareP256SigningKey, presence: SoftwareP256SigningKey), accountId: UUID? = nil) async throws -> (status: HTTPStatus, entryId: String?) {
        let nonce = try await h.nonce("device_added")
        let result = try await h.post(AuthorityKeyLogRoute.deviceAdded, [
            "account_id": .string((accountId ?? h.accountId).uuidString), "nonce_id": .string(nonce.id), "reported_name": .string("Pat's tablet"),
            "keys": try await h.submitted([(device.biometric, .approvalBiometric), (device.presence, .approvalUserPresence)], type: "device_added", nonce: nonce.value),
        ])
        return (result.status, result.body["entry_id"]?.stringValue)
    }

    func entryChallenge(_ entryId: String) async throws -> (status: HTTPStatus, statement: AuthorityChallengeStatement?) {
        let result = try await h.keylogChallenge(["purpose": .string("keylog_device_added"), "account_id": .string(h.accountId.uuidString), "entry_id": .string(entryId)])
        return (result.status, result.statement)
    }

    func testDeviceAddWithTheComparisonCodeAddsTheKeysAfterTheCoolDown() async throws {
        let device = newDevice()
        let entryId = try await XCTUnwrapAsync(try await submitEntry(device).entryId)
        let challenge = try await entryChallenge(entryId)
        let statement = try XCTUnwrap(challenge.statement)
        // The new device: the statement's kids are exactly its keys; it shows the code.
        let ownKids = [AuthorityHarness.kid(device.biometric), AuthorityHarness.kid(device.presence)]
        XCTAssertEqual(Set(statement.kids ?? []), Set(ownKids))
        XCTAssertTrue(statement.matchRequired)
        XCTAssertNil(statement.display.objectValue?["code"])
        let code = AuthorityDeviceAddCode.code(environment: .staging, nonce: statement.nonce, kids: ownKids)
        // The approving device types it.
        let factor = try await h.factor(statement, key: h.biometricKey, match: code)
        let result = try await h.post(AuthorityKeyLogRoute.evidence, ["factor": .string(factor), "account_id": .string(h.accountId.uuidString)])
        XCTAssertEqual(result.status, .ok, "\(result.body)")
        let added = try await XCTUnwrapAsync(try await AuthorityKey.find(ownKids[0], on: h.app.db))
        XCTAssertFalse(added.grantCapable)
        XCTAssertEqual(added.usableFrom, h.clock.now.addingTimeInterval(72 * 3600))
        await XCTAssertEqualAsync(try await AuthorityDeviceAddEntry.find(entryId, on: h.app.db)?.state, "added")
        await XCTAssertNilAsync(try await AuthorityKeyLog.verifyChain(h.app.db, accountRef: added.accountRef))
    }

    func testAWrongComparisonCodeThreeTimesEndsTheEntryAndNoKeyIsAdded() async throws {
        let device = newDevice()
        let entryId = try await XCTUnwrapAsync(try await submitEntry(device).entryId)
        let statement = try await XCTUnwrapAsync(try await entryChallenge(entryId).statement)
        for _ in 0..<3 {
            let factor = try await h.factor(statement, key: h.biometricKey, match: "000000" == AuthorityDeviceAddCode.code(environment: .staging, nonce: statement.nonce,
                kids: statement.kids!) ? "000001" : "000000")
            await XCTAssertEqualAsync(try await h.post(AuthorityKeyLogRoute.evidence, ["factor": .string(factor)]).status, .unauthorized)
        }
        await XCTAssertEqualAsync(try await AuthorityDeviceAddEntry.find(entryId, on: h.app.db)?.state, "abandoned")
        await XCTAssertEqualAsync(try await AuthorityKey.find(AuthorityHarness.kid(device.biometric), on: h.app.db) == nil, true)
        // The entry has had its one challenge.
        await XCTAssertEqualAsync(try await entryChallenge(entryId).status, .conflict)
    }

    func testOneChallengePerEntryAndASecondEntryCancelsTheFirst() async throws {
        let first = try await XCTUnwrapAsync(try await submitEntry(newDevice()).entryId)
        await XCTAssertEqualAsync(try await entryChallenge(first).status, .ok)
        await XCTAssertEqualAsync(try await entryChallenge(first).status, .conflict)
        await XCTAssertEqualAsync(try await audits("challenge_exists"), 1)
        let second = try await XCTUnwrapAsync(try await submitEntry(newDevice()).entryId)
        await XCTAssertEqualAsync(try await AuthorityDeviceAddEntry.find(first, on: h.app.db)?.state, "cancelled")
        let firstChallenge = try await AuthorityDeviceAddEntry.find(first, on: h.app.db)!.challengeId!
        await XCTAssertEqualAsync(try await AuthorityChallenge.find(firstChallenge, on: h.app.db)?.state, "cancelled")
        await XCTAssertEqualAsync(try await entryChallenge(second).status, .ok)
    }

    func testAtMostFiveEntriesPerAccountPerDayWithAlerts() async throws {
        for _ in 0..<5 { await XCTAssertEqualAsync(try await submitEntry(newDevice()).status, .ok) }
        await XCTAssertEqualAsync(try await submitEntry(newDevice()).status, .tooManyRequests)
        // Alerts from the fourth entry and on every refusal.
        await XCTAssertEqualAsync(try await AuthorityAuditEvent.query(on: h.app.db).filter(\.$event == "authority.device_add_alert").count(), 3)
        h.clock.advance(86_401)
        await XCTAssertEqualAsync(try await submitEntry(newDevice()).status, .ok)
    }

    func testTheApproverMustBeAGrantCapableBiometricKeyOfTheSameAccount() async throws {
        let device = newDevice()
        let entryId = try await XCTUnwrapAsync(try await submitEntry(device).entryId)
        let statement = try await XCTUnwrapAsync(try await entryChallenge(entryId).statement)
        let code = AuthorityDeviceAddCode.code(environment: .staging, nonce: statement.nonce, kids: statement.kids!)
        // A user-presence key is not D1-equivalent.
        let presence = try await h.factor(statement, key: h.presenceKey, uv: .userPresence, match: code)
        await XCTAssertEqualAsync(try await h.post(AuthorityKeyLogRoute.evidence, ["factor": .string(presence)]).status, .unauthorized)
        // Another account's key.
        let other = newDevice()
        let otherAccount = try await XCTUnwrapAsync(try await h.genesis([(other.biometric, .approvalBiometric)]).accountId)
        await XCTAssertEqualAsync(try await h.confirmEnrollment(keys: [other.biometric], accountId: otherAccount).status, .ok)
        let foreign = try await h.factor(statement, key: other.biometric, match: code)
        await XCTAssertEqualAsync(try await h.post(AuthorityKeyLogRoute.evidence, ["factor": .string(foreign)]).status, .unauthorized)
        await XCTAssertEqualAsync(try await audits("account_binding_mismatch"), 1)
        // A new key in its cool-down cannot approve the next device either (usable_from + 72 h).
        await XCTAssertEqualAsync(try await AuthorityDeviceAddEntry.find(entryId, on: h.app.db)?.state, "pending")
    }

    func testAPopByEveryNewKeyIsRequired() async throws {
        let device = newDevice()
        let nonce = try await h.nonce("device_added")
        var keys = try await h.submitted([(device.biometric, .approvalBiometric)], type: "device_added", nonce: nonce.value)
        let forged = try await h.submitted([(device.presence, .approvalUserPresence)], type: "device_added", nonce: nonce.value, popSigner: device.biometric)
        if case .array(let a) = keys, case .array(let b) = forged { keys = .array(a + b) }
        let result = try await h.post(AuthorityKeyLogRoute.deviceAdded, ["account_id": .string(h.accountId.uuidString), "nonce_id": .string(nonce.id),
                                                                         "reported_name": .string("Tablet"), "keys": keys])
        XCTAssertEqual(result.status, .unauthorized)
        await XCTAssertEqualAsync(try await AuthorityDeviceAddEntry.query(on: h.app.db).count(), 0)
    }

    func testReportedNamesAreBounded() {
        XCTAssertNil(AuthorityKeyLogFormat.reportedName("evil\u{202E}name"))
        XCTAssertNil(AuthorityKeyLogFormat.reportedName(String(repeating: "a", count: 41)))
        XCTAssertNil(AuthorityKeyLogFormat.reportedName("zero\u{200B}width"))
        XCTAssertEqual(AuthorityKeyLogFormat.reportedName("Pat's iPad"), "Pat's iPad")
    }

    // MARK: Heads and the chain (ADR-0033 §2, §5)

    func testHeadsAreCachedAndResignedWhenStaleOrChanged() async throws {
        let first = try await h.head(h.accountId)
        await XCTAssertEqualAsync(try await h.head(h.accountId), first)
        let records = try await AuthoritySignRecord.query(on: h.app.db).count()
        h.clock.advance(301)
        let resigned = try await h.head(h.accountId)
        XCTAssertNotEqual(resigned, first)
        await XCTAssertEqualAsync(try await AuthoritySignRecord.query(on: h.app.db).count(), records + 1)
        await XCTAssertNilAsync(try await AuthorityKeyLog.verifyChain(h.app.db, accountRef: OIDCProfile.accountRef(key: h.config.accountRefKey, accountId: h.accountId)))
    }

    func testTheChainDetectsATamperedEntry() async throws {
        let ref = OIDCProfile.accountRef(key: h.config.accountRefKey, accountId: h.accountId)
        await XCTAssertNilAsync(try await AuthorityKeyLog.verifyChain(h.app.db, accountRef: ref))
        // Append a forged entry with a wrong prev_hash directly (the triggers refuse UPDATE, so tampering means inserting).
        let entry = AuthorityKeylogEntry()
        entry.accountRef = ref
        entry.seq = try await AuthorityKeylogEntry.query(on: h.app.db).filter(\.$accountRef == ref).count()
        entry.type = "imported"
        entry.kid = AuthorityHarness.kid(SoftwareP256SigningKey())
        entry.publicKey = ""
        entry.keyPurpose = "approvalBiometric"
        entry.detail = "{}"
        entry.createdAt = h.clock.now
        entry.prevHash = AuthorityKeyLog.genesisHash
        entry.entryHash = AuthorityKeyLog.genesisHash
        try await entry.create(on: h.app.db)
        await XCTAssertNotNilAsync(try await AuthorityKeyLog.verifyChain(h.app.db, accountRef: ref))
    }

    func testKeyLogRoutesAreOffWithTheFlag() async throws {
        var options = AuthorityHarness.Options()
        options.confirmImportedKeys = false
        let off = try await AuthorityHarness.makeWith(options) { $0.keylogEnabled = false; $0.recoveryEnabled = false }
        await XCTAssertEqualAsync(try await off.post(AuthorityKeyLogRoute.nonces, ["entry_type": .string("genesis")]).status, .notFound)
        await XCTAssertEqualAsync(try await off.post(AuthorityKeyLogRoute.head, ["account_id": .string(off.accountId.uuidString)]).status, .notFound)
        // The worker cannot reach any of them.
        await XCTAssertEqualAsync(try await h.post(AuthorityKeyLogRoute.nonces, ["entry_type": .string("genesis")], token: StaticCallerVerifier.workerToken).status, .forbidden)
        try await off.shutdown()
    }
}
