@preconcurrency import Crypto
import Fluent
import FluentSQL
import Foundation
import SQLKit
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// WP1 key directory and transparency log (SEC-CR-006, ADR-07), exercised through the HTTP API the way a business, a device and a monitor
/// use it: the verifying side is ViadereCore's `KeyDirectoryVerifier`, pinned to the log key only.
final class ApproveDirectoryTests: XCTestCase {
    private func verifier(_ h: TestHarness) -> KeyDirectoryVerifier { KeyDirectoryVerifier(logKeys: [h.ctx.config.approve.logKey.publicKey], logId: h.ctx.config.approve.logId) }

    private func directory(_ h: TestHarness, _ business: TestBusiness, since: Int? = nil) async throws -> KeyDirectoryResponse {
        let query = since.map { "?since=\($0)" } ?? ""
        let result = try await h.request(.GET, "/v1/key-directory/businesses/\(business.id)\(query)")
        XCTAssertEqual(result.status, .ok, result.text)
        return try result.json(KeyDirectoryResponse.self)
    }

    // MARK: Publishing rules

    func testOnlyAKeyWithTheDirectoryScopeCanPublishAndOnlyLiveKeysWriteTheProductionLog() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            let keys = TestBusinessKeys()
            let entry = try await KeyLogEntry.sign(.root(RootRegistration(businessId: b.id, publicKey: keys.root.publicKey, createdAt: h.clock.now())), rootKey: keys.root)
            let noScope = try await BusinessAPIKeys.issue(businessId: b.record.id!, name: "n", live: true, scopes: [BusinessAPIKeys.Scope.approvalsManage, BusinessAPIKeys.Scope.interactionsWrite],
                                                          capabilities: Capability.operational, now: h.clock.now(), on: h.db).key
            aeq(try await h.publishEntry(b, entry, key: noScope).status, .forbidden)
            aeq(try await h.publishEntry(b, entry, key: noScope).errorCode, .insufficientScope)
            let test = try await BusinessAPIKeys.issue(businessId: b.record.id!, name: "t", live: false, scopes: BusinessAPIKeys.Scope.all, now: h.clock.now(), on: h.db).key
            aeq(try await h.publishEntry(b, entry, key: test).status, .forbidden)
            // Another business cannot register a root for this one (the entry names the business; the credential must be that business's).
            let other = try await h.makeBusiness(name: "Other Bank", handle: "otherbank5")
            let wrong = try await h.publishEntry(other, entry)
            XCTAssertEqual(wrong.status, .unprocessableEntity)
            XCTAssertEqual(try wrong.json(APIErrorResponse.self).error.details?["reason"], "wrong_business")
            aeq(try await KDLogEntryRecord.query(on: h.db).count(), 0, "nothing was logged")
            // A suspended business cannot publish.
            let ok = try await h.publishEntry(b, entry)
            XCTAssertEqual(ok.status, .created, ok.text)
            let response = try ok.json(PublishKeyEntryResponse.self)
            XCTAssertEqual(response.index, 0)
            XCTAssertEqual(response.treeSize, 1)
            _ = try response.sth.verified(logKeys: [h.ctx.config.approve.logKey.publicKey])
            aeq(try await h.approvalAudit("keydirectory.root_registered").count, 1)
        }
    }

    func testTheServerEnforcesTheRulesBeforeLoggingAndTheLogNeverBreaksAHistory() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            let keys = try await h.publishDirectory(b)
            let rootKid = keys.rootKid
            let before = try await KDLogEntryRecord.query(on: h.db).count()
            func attempt(_ statement: KeyStatement, signer: SoftwareP256SigningKey? = nil, newRoot: SoftwareP256SigningKey? = nil) async throws -> HTTPResult {
                try await h.publishEntry(b, try await KeyLogEntry.sign(statement, rootKey: signer ?? keys.root, newRootKey: newRoot))
            }
            func publication(serial: Int64, purpose: BusinessKeyPurpose = .hpkeEncryption, root: String? = nil, notBefore: TimeInterval = -60, notAfter: TimeInterval = 3600) throws -> KeyPublication {
                try KeyPublication(businessId: b.id, rootKid: root ?? rootKid, purpose: purpose, publicKey: SoftwareE2EEPrivateKey().publicKey.x963,
                                   notBefore: h.clock.now().addingTimeInterval(notBefore), notAfter: h.clock.now().addingTimeInterval(notAfter), serial: serial)
            }
            let next = keys.serial + 1
            let attacker = SoftwareP256SigningKey()
            // Wrong signer, serial gap, serial reuse, expired key, far-future key, over-long validity, second root, revoking nothing.
            aeq(try await attempt(.key(try publication(serial: next)), signer: attacker).status, .unprocessableEntity)
            aeq(try await attempt(.key(try publication(serial: next + 1))).status, .unprocessableEntity)
            aeq(try await attempt(.key(try publication(serial: keys.serial))).status, .unprocessableEntity)
            aeq(try await attempt(.key(try publication(serial: next, notBefore: -7200, notAfter: -3600))).status, .unprocessableEntity)
            aeq(try await attempt(.key(try publication(serial: next, notBefore: 3 * 86_400, notAfter: 4 * 86_400))).status, .unprocessableEntity)
            aeq(try await attempt(.key(try publication(serial: next, notAfter: 86_400 * 500))).status, .unprocessableEntity)
            aeq(try await attempt(.root(RootRegistration(businessId: b.id, publicKey: attacker.publicKey, createdAt: h.clock.now())), signer: attacker).status, .unprocessableEntity)
            aeq(try await attempt(.revocation(KeyRevocation(businessId: b.id, rootKid: rootKid, kid: KeyIdentifier.make(try attacker.publicKey.signingKey()), reason: "retired", revokedAt: h.clock.now(), serial: next))).status, .unprocessableEntity)
            // A succession without the new root's signature (as a thief of the old root alone would send).
            let thiefRoot = SoftwareP256SigningKey()
            let oneSided = RootSuccession(businessId: b.id, oldRootKid: rootKid, newPublicKey: thiefRoot.publicKey, createdAt: h.clock.now())
            aeq(try await attempt(.succession(oneSided), newRoot: keys.root).status, .unprocessableEntity)
            // Garbage and oversize entries.
            aeq(try await h.businessPost(b, "/v1/business/key-directory/entries", PublishKeyEntryRequest(entry: "!!")).status, .unprocessableEntity)
            aeq(try await h.businessPost(b, "/v1/business/key-directory/entries", PublishKeyEntryRequest(entry: Base64URL.encode(Data(repeating: 65, count: 20_000)))).status, .unprocessableEntity)
            aeq(try await KDLogEntryRecord.query(on: h.db).count(), before, "every refused entry left the log untouched")
            aeq(try await h.approvalAudit("keydirectory.entry_rejected").count > 0, true)
            // The valid next statement still goes in.
            aeq(try await attempt(.key(try publication(serial: next))).status, .created)
        }
    }

    func testRacingPublishesCannotBothBeValidAgainstTheSameState() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            let keys = try await h.publishDirectory(b)
            let serial = keys.serial + 1
            var entries: [KeyLogEntry] = []
            for _ in 0..<4 {
                entries.append(try await KeyLogEntry.sign(.key(try KeyPublication(businessId: b.id, rootKid: keys.rootKid, purpose: .hpkeEncryption, publicKey: SoftwareE2EEPrivateKey().publicKey.x963,
                                                                                  notBefore: h.clock.now().addingTimeInterval(-60), notAfter: h.clock.now().addingTimeInterval(3600), serial: serial)), rootKey: keys.root))
            }
            var statuses: [HTTPStatus] = []
            for entry in entries { statuses.append(try await h.publishEntry(b, entry).status) }
            XCTAssertEqual(statuses.filter { $0 == .created }.count, 1, "\(statuses)")
            // The business's history still replays: no entry in the log breaks it.
            let verified = try verifier(h).verify(try await directory(h, b), businessId: b.id, lastSeen: nil, now: h.clock.now())
            XCTAssertEqual(verified.state.lastSerial, serial)
        }
    }

    // MARK: What a device sees

    func testADeviceVerifiesTheDirectoryFromTheLogKeyAlone() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            let keys = try await h.publishDirectory(b)
            let response = try await directory(h, b)
            let first = try verifier(h).verify(response, businessId: b.id, lastSeen: nil, now: h.clock.now())
            XCTAssertEqual(first.head.treeSize, 4)
            XCTAssertEqual(first.state.currentRoot?.kid, keys.rootKid)
            XCTAssertNotNil(first.state.validKey(kid: keys.requestSigningKid, purpose: .approvalRequestSigning, at: h.clock.now()))
            XCTAssertEqual(first.state.validKeys(for: .hpkeEncryption, at: h.clock.now()).first?.encryptionKey, keys.hpke.publicKey)
            XCTAssertEqual(KeyDirectoryVerifier.pinStatus(pin: nil, state: first.state), .firstUse(rootKid: keys.rootKid))

            // The log is shared: another business's entries make the tree grow and the consistency proof from what the device saw verifies.
            let other = try await h.makeBusiness(name: "Other Bank", handle: "otherbank6")
            _ = try await h.publishDirectory(other)
            let seen = SeenTreeHead(first.head)
            let second = try verifier(h).verify(try await directory(h, b, since: seen.treeSize), businessId: b.id, lastSeen: seen, now: h.clock.now())
            XCTAssertGreaterThan(second.head.treeSize, seen.treeSize)
            // Without the proof the device refuses to move forward.
            assertDirectoryError(.consistencyProofMissing, verifier(h), try await directory(h, b), business: b.id, lastSeen: seen, now: h.clock.now())
            // The public endpoints agree with each other.
            let sth = try await h.request(.GET, "/v1/key-directory/sth").json(SignedTreeHead.self)
            XCTAssertEqual(try sth.verified(logKeys: [h.ctx.config.approve.logKey.publicKey]).treeSize, second.head.treeSize)
            let proof = try await h.request(.GET, "/v1/key-directory/consistency?first=\(seen.treeSize)&second=\(second.head.treeSize)").json(ConsistencyProofResponse.self)
            XCTAssertTrue(MerkleTree.verifyConsistency(first: seen.treeSize, second: second.head.treeSize, firstRoot: Hex.decode(seen.rootHash)!, secondRoot: Hex.decode(second.head.rootHash)!,
                                                       proof: try proof.proof.map { try KeyDirectoryVerifier.hash($0) }))
            aeq(try await h.request(.GET, "/v1/key-directory/consistency?first=5&second=2").status, .unprocessableEntity)
            aeq(try await h.request(.GET, "/v1/key-directory/consistency?first=a").status, .unprocessableEntity)
            // A business that does not exist or is not verified has no directory page.
            aeq(try await h.request(.GET, "/v1/key-directory/businesses/\(BusinessID())").status, .notFound)
            let pending = try await h.makeBusiness(name: "Pending Co", handle: "pendingco", status: .pending)
            aeq(try await h.request(.GET, "/v1/key-directory/businesses/\(pending.id)").status, .notFound)
        }
    }

    func testTreeHeadsAreFreshAndCoverEveryEntry() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            _ = try await h.publishDirectory(b)
            let first = try await h.request(.GET, "/v1/key-directory/sth").json(SignedTreeHead.self)
            let again = try await h.request(.GET, "/v1/key-directory/sth").json(SignedTreeHead.self)
            XCTAssertEqual(first, again, "the same head is served until it ages")
            h.clock.advance(by: 3700)
            let refreshed = try await h.request(.GET, "/v1/key-directory/sth").json(SignedTreeHead.self)
            let old = try first.verified(logKeys: [h.ctx.config.approve.logKey.publicKey])
            let new = try refreshed.verified(logKeys: [h.ctx.config.approve.logKey.publicKey])
            XCTAssertEqual(new.rootHash, old.rootHash)
            XCTAssertGreaterThan(new.timestamp, old.timestamp)
            // Heads are signed over the log id, so a head from another log (or key) never verifies.
            XCTAssertThrowsError(try refreshed.verified(logKeys: [SoftwareP256SigningKey().publicKey]))
        }
    }

    func testTheLogIsAppendOnlyAtTheDatabaseLevel() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            _ = try await h.publishDirectory(b)
            let sql = try XCTUnwrap(h.db as? any SQLDatabase)
            for statement in ["UPDATE kd_log_entries SET entry_type = 'x'", "DELETE FROM kd_log_entries", "UPDATE kd_tree_heads SET tree_size = 0", "DELETE FROM kd_tree_heads"] {
                do {
                    try await sql.raw(SQLQueryString(statement)).run()
                    XCTFail("\(statement) succeeded")
                } catch { /* refused by the trigger */ }
            }
            agt(try await KDLogEntryRecord.query(on: h.db).count(), 0)
        }
    }

    // MARK: Key substitution and history attacks (SEC-CR-006)

    func testAnOmittedStatementIsAGapAndAReplacedRootIsAConflict() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            let keys = try await h.publishDirectory(b)
            let device = verifier(h)
            let honest = try await directory(h, b)
            // Relay drops the middle statement (say, a rotation) from the business's page: the serial gap shows.
            var dropped = honest
            dropped.entries.remove(at: 2)
            assertDirectoryError(.serialOutOfOrder(expected: 2, got: 3), device, dropped, business: b.id, lastSeen: nil, now: h.clock.now())
            // Relay swaps an entry for one it made (the inclusion proof no longer fits the signed head).
            let attacker = SoftwareP256SigningKey()
            let injected = try await KeyLogEntry.sign(.key(try KeyPublication(businessId: b.id, rootKid: keys.rootKid, purpose: .hpkeEncryption, publicKey: SoftwareE2EEPrivateKey().publicKey.x963,
                                                                              notBefore: h.clock.now(), notAfter: h.clock.now().addingTimeInterval(3600), serial: 3)), rootKey: attacker)
            var swapped = honest
            swapped.entries[3].entry = Base64URL.encode(try injected.leafData())
            assertDirectoryError(.inclusionFailed(index: swapped.entries[3].index), device, swapped, business: b.id, lastSeen: nil, now: h.clock.now())
            // Relay serves a log it built itself, root included: it cannot sign the head with Viadere's log key.
            let evil = TestLog(now: h.clock.now())
            let evilRoot = SoftwareP256SigningKey()
            try evil.append(try await KeyLogEntry.sign(.root(RootRegistration(businessId: b.id, publicKey: evilRoot.publicKey, createdAt: h.clock.now())), rootKey: evilRoot))
            assertDirectoryError(.treeHeadSignature, device, try await evil.response(for: b.id), business: b.id, lastSeen: nil, now: h.clock.now())
            // A device that pinned the root and sees a different one at the start of the history has a conflict, whatever else verifies.
            let pin = PinnedRoot(from: try device.verify(honest, businessId: b.id, lastSeen: nil, now: h.clock.now()).state.currentRoot!, businessId: b.id, at: h.clock.now())
            XCTAssertEqual(pin.rootKid, keys.rootKid)
            // The pin holds against the relay's replacement history.
            let evilState = try evil.verifier.verify(try await evil.response(for: b.id), businessId: b.id, lastSeen: nil, now: h.clock.now()).state
            XCTAssertEqual(KeyDirectoryVerifier.pinStatus(pin: pin, state: evilState), .conflict(pinnedKid: keys.rootKid, currentKid: KeyIdentifier.make(try evilRoot.publicKey.signingKey())))
        }
    }

    func testARootChangeThroughTheAPIAlertsPinnedDevicesAndOrphansTheOldRootsKeys() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            let keys = try await h.publishDirectory(b)
            let device = verifier(h)
            let before = try device.verify(try await directory(h, b), businessId: b.id, lastSeen: nil, now: h.clock.now())
            let pin = PinnedRoot(from: before.state.currentRoot!, businessId: b.id, at: h.clock.now())
            let next = SoftwareP256SigningKey()
            let succession = RootSuccession(businessId: b.id, oldRootKid: keys.rootKid, newPublicKey: next.publicKey, createdAt: h.clock.now())
            let published = try await h.publishEntry(b, try await KeyLogEntry.sign(.succession(succession), rootKey: keys.root, newRootKey: next))
            XCTAssertEqual(published.status, .created, published.text)
            aeq(try await h.approvalAudit("keydirectory.root_changed").count, 1)
            let after = try device.verify(try await directory(h, b), businessId: b.id, lastSeen: nil, now: h.clock.now())
            XCTAssertEqual(KeyDirectoryVerifier.pinStatus(pin: pin, state: after.state), .rotated(pinnedKid: keys.rootKid, currentKid: KeyIdentifier.make(try next.publicKey.signingKey())))
            XCTAssertTrue(after.state.validKeys(for: .approvalEnrollmentConfirmation, at: h.clock.now()).isEmpty, "no key is inherited across a root change")
            // Until the new root re-publishes a confirmation key, enrollments cannot start (and nothing signs with the old one).
            let consumer = try await h.readyConsumer()
            _ = try await h.connect(consumer, to: b)
            let blocked = try await h.businessPost(b, "/v1/business/approve/enrollments", CreateApprovalEnrollmentRequest(subjectRef: h.subjectRef(b, consumer), capability: .transactionApprove))
            XCTAssertEqual(blocked.status, .conflict)
            // The old root can no longer publish.
            let late = try KeyPublication(businessId: b.id, rootKid: keys.rootKid, purpose: .hpkeEncryption, publicKey: SoftwareE2EEPrivateKey().publicKey.x963,
                                          notBefore: h.clock.now(), notAfter: h.clock.now().addingTimeInterval(3600), serial: keys.serial + 1)
            aeq(try await h.publishEntry(b, try await KeyLogEntry.sign(.key(late), rootKey: keys.root)).status, .unprocessableEntity)
        }
    }

    func testABusinessMonitorSeesItsOwnEntriesWithProofs() async throws {
        try await withHarness { h in
            let b = try await h.makeBusiness(name: "Northwind Bank", handle: "northwindbank")
            _ = try await h.publishDirectory(b)
            let result = try await h.business(b, .GET, "/v1/business/key-directory/entries")
            XCTAssertEqual(result.status, .ok, result.text)
            let response = try result.json(KeyDirectoryResponse.self)
            XCTAssertEqual(response.entries.count, 4)
            _ = try verifier(h).verify(response, businessId: b.id, lastSeen: nil, now: h.clock.now())
            // Only its own: another business's key sees its own page.
            let other = try await h.makeBusiness(name: "Other Bank", handle: "otherbank7")
            let theirs = try await h.business(other, .GET, "/v1/business/key-directory/entries").json(KeyDirectoryResponse.self)
            XCTAssertTrue(theirs.entries.isEmpty)
        }
    }
}
