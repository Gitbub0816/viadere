@preconcurrency import Crypto
import Fluent
import FluentSQL
import Foundation
import SQLKit
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Key rotation tooling (G-8): multi-key `DATA_ENCRYPTION_KEY` with re-encryption and verification, versioned `SERVER_PEPPER`,
/// `AUDIT_CHAIN_KEY` epochs and `CONNECT_LINK_SIGNING_KEY` ids.
final class WP6RotationTests: XCTestCase {
    private let oldKey = SymmetricKey(data: Data(repeating: 0x11, count: 32))
    private let newKey = SymmetricKey(data: Data(repeating: 0x22, count: 32))

    private func rotated(_ config: inout ServerConfig) {
        config.dataEncryptionKey = newKey
        config.operations.dataKeyId = "k2"
        config.operations.previousDataKeys = ["k1": oldKey]
    }

    // MARK: Data encryption key

    func testRotateDataKeyReSealsEverythingAndTheOldKeyCanThenBeRetired() async throws {
        try await withHarness(rotated) { h in
            let (_, _, businessId) = try await h.verifiedOwner(email: "first@example.com")
            let (_, _, otherBusiness) = try await h.verifiedOwner(email: "second@example.com", org: "Second Co", handle: "secondco")
            let users = try await DashboardUserRecord.query(on: h.db).all()
            XCTAssertEqual(users.count, 2)
            XCTAssertEqual(h.ctx.cipher.currentKeyId, "k2")
            XCTAssertEqual(FieldCipher.keyId(of: users[0].emailCiphertext), "k2", "new values are written under the current key")
            // State as it was before the rotation: one value under the old key (v2), one in the oldest legacy form (v1).
            let old = FieldCipher(key: oldKey)
            let email0 = try h.ctx.cipher.openString(users[0].emailCiphertext, context: "dashboard_users.email", rowId: users[0].id!)
            let email1 = try h.ctx.cipher.openString(users[1].emailCiphertext, context: "dashboard_users.email", rowId: users[1].id!)
            users[0].emailCiphertext = try old.seal(email0, context: "dashboard_users.email", rowId: users[0].id!)
            users[1].emailCiphertext = try old.sealLegacy(email1, context: "dashboard_users.email")
            try await users[0].update(on: h.db)
            try await users[1].update(on: h.db)
            XCTAssertEqual(FieldCipher.keyId(of: users[0].emailCiphertext), "k1")
            XCTAssertTrue(FieldCipher.isLegacy(users[1].emailCiphertext))

            let rotator = DataKeyRotator(db: h.db, ctx: h.ctx)
            // Verify only: nothing changes, the old key is still needed, nothing fails to open.
            let before = try await rotator.run(rewrite: false)
            XCTAssertEqual(before.failed, 0)
            XCTAssertGreaterThanOrEqual(before.byKeyId["k1", default: 0], 2)
            XCTAssertEqual(before.rewritten, 0)
            let unchanged = try await DashboardUserRecord.find(users[0].id!, on: h.db)
            XCTAssertEqual(FieldCipher.keyId(of: unchanged!.emailCiphertext), "k1")
            // Rotate: everything old is re-sealed under k2, including the legacy form, and the second run finds nothing to do.
            let rewrite = try await rotator.run(rewrite: true)
            XCTAssertGreaterThanOrEqual(rewrite.rewritten, 2)
            XCTAssertEqual(rewrite.failed, 0)
            let after = try await rotator.run(rewrite: false)
            XCTAssertEqual(after.byKeyId.keys.filter { $0 != "k2" }.count, 0, "nothing is left under another key or format: \(after.byKeyId)")
            let again = try await rotator.run(rewrite: true)
            XCTAssertEqual(again.rewritten, 0, "idempotent")
            // The plaintext is unchanged, and the application still reads it.
            let refreshed = try await DashboardUserRecord.find(users[1].id!, on: h.db)
            XCTAssertEqual(try h.ctx.cipher.openString(refreshed!.emailCiphertext, context: "dashboard_users.email", rowId: users[1].id!), email1)
            let recipients = await Notifier(db: h.db, ctx: h.ctx).recipients(businessId: otherBusiness, roles: [.owner], includeSecurityContacts: false)
            XCTAssertEqual(recipients, ["second@example.com"])
            // Retiring the old key: a cipher without it opens everything now stored, and cannot open anything still under k1.
            let retired = FieldCipher(key: newKey, keyId: "k2", previous: [:])
            for user in try await DashboardUserRecord.query(on: h.db).all() {
                XCTAssertNoThrow(try retired.open(user.emailCiphertext, context: "dashboard_users.email", rowId: user.id!))
            }
            let straggler = try old.seal("x@example.com", context: "dashboard_users.email", rowId: UUID())
            XCTAssertThrowsError(try retired.open(straggler, context: "dashboard_users.email", rowId: UUID()))
            _ = businessId
        }
    }

    func testAValueThatCannotBeOpenedIsReportedNotOverwritten() async throws {
        try await withHarness(rotated) { h in
            _ = try await h.verifiedOwner()
            let user = try await XCTUnwrapAsync(await DashboardUserRecord.query(on: h.db).first())
            // Sealed under a key that is no longer configured (someone dropped DATA_ENCRYPTION_KEYS_PREVIOUS too early).
            let lost = FieldCipher(key: SymmetricKey(data: Data(repeating: 0x33, count: 32)), keyId: "k0", previous: [:])
            let sealed = try lost.seal("who@example.com", context: "dashboard_users.email", rowId: user.id!)
            user.emailCiphertext = sealed
            try await user.update(on: h.db)
            let report = try await DataKeyRotator(db: h.db, ctx: h.ctx).run(rewrite: true)
            XCTAssertEqual(report.failed, 1)
            XCTAssertTrue(report.failedColumns.contains("dashboard_users.email_ciphertext"))
            let kept = try await DashboardUserRecord.find(user.id!, on: h.db)
            XCTAssertEqual(kept?.emailCiphertext, sealed, "nothing is rewritten that could not be read")
            // A value moved to another row does not open either (row binding), so a rotation cannot launder a swapped ciphertext.
            let swapped = try h.ctx.cipher.seal("a@example.com", context: "dashboard_users.email", rowId: UUID())
            XCTAssertThrowsError(try h.ctx.cipher.open(swapped, context: "dashboard_users.email", rowId: user.id!))
        }
    }

    func testTheSealedColumnRegistryCoversEveryEncryptionContextInTheSource() throws {
        let sources = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Sources/ViadereServerKit")
        let enumerator = try XCTUnwrap(FileManager.default.enumerator(at: sources, includingPropertiesForKeys: nil))
        let pattern = try NSRegularExpression(pattern: #"context: "([a-z_]+\.[a-z_]+)""#)
        var found = Set<String>()
        for case let url as URL in enumerator where url.pathExtension == "swift" {
            let text = try String(contentsOf: url, encoding: .utf8)
            for match in pattern.matches(in: text, range: NSRange(text.startIndex..., in: text)) {
                if let range = Range(match.range(at: 1), in: text) { found.insert(String(text[range])) }
            }
        }
        let registered = Set(SealedColumns.all.map(\.context))
        XCTAssertGreaterThan(found.count, 15)
        XCTAssertEqual(found.subtracting(registered), [], "a sealed column is missing from SealedColumns: rotate-data-key would leave it under the old key")
    }

    func testRegisteredColumnsExistInTheSchema() async throws {
        try await withHarness { h in
            let report = try await DataKeyRotator(db: h.db, ctx: h.ctx).run(rewrite: false)
            XCTAssertEqual(report.failed, 0)
            guard let sql = h.db as? any SQLDatabase else { return XCTFail("SQL database expected") }
            for column in SealedColumns.all {
                // A missing table or column would be skipped silently by the rotator; here it must exist.
                _ = try await sql.raw("SELECT \(unsafeRaw: column.column) FROM \(unsafeRaw: column.table) LIMIT 1").all()
            }
        }
    }

    // MARK: Pepper, audit chain, connect links

    func testPepperIdsKeepVersionedHashesVerifiableAcrossARotation() {
        let oldPepper = Data(repeating: 0xA1, count: 32), newPepper = Data(repeating: 0xB2, count: 32)
        let before = Hasher256(pepper: oldPepper)
        let stored = before.versionedHex("contract-ip", "203.0.113.9")
        XCTAssertTrue(stored.hasPrefix("p1:"))
        let after = Hasher256(pepper: newPepper, pepperId: "p2", previous: ["p1": oldPepper])
        XCTAssertTrue(after.verifyVersioned(stored, domain: "contract-ip", value: "203.0.113.9"), "the old pepper still verifies what it made")
        XCTAssertFalse(after.verifyVersioned(stored, domain: "contract-ip", value: "203.0.113.10"))
        XCTAssertFalse(after.verifyVersioned(stored, domain: "other-domain", value: "203.0.113.9"))
        XCTAssertFalse(after.isCurrentVersion(stored))
        let fresh = after.versionedHex("contract-ip", "203.0.113.9")
        XCTAssertTrue(fresh.hasPrefix("p2:"))
        XCTAssertTrue(after.isCurrentVersion(fresh))
        XCTAssertNotEqual(fresh, stored)
        // Retiring the old pepper: its hashes no longer verify (that is the point of retiring it).
        let retired = Hasher256(pepper: newPepper, pepperId: "p2", previous: [:])
        XCTAssertFalse(retired.verifyVersioned(stored, domain: "contract-ip", value: "203.0.113.9"))
        XCTAssertFalse(retired.verifyVersioned("garbage", domain: "x", value: "y"))
    }

    func testAuditChainStaysVerifiableAcrossAKeyEpochAndCannotBeRelabelled() async throws {
        let epoch1 = SymmetricKey(data: Data(repeating: 0x44, count: 32))
        let epoch2 = SymmetricKey(data: Data(repeating: 0x55, count: 32))
        try await withHarness({ config in
            config.auditChainKey = epoch2
            config.operations.auditKeyEpoch = 2
            config.operations.previousAuditKeys = [1: epoch1]
        }) { h in
            // The first event was written under epoch 1 (version 2 form).
            let first = AuditEventRecord()
            first.id = UUID(); first.seq = 1; first.occurredAt = ViadereDate.truncatedToMilliseconds(h.clock.now()); first.actorKind = "system"; first.action = "legacy.event"
            first.outcome = "success"; first.metadataJSON = "{}"; first.prevHash = AuditService.genesisHash; first.chainVersion = 2
            first.hash = try AuditService.hash(of: first, key: epoch1)
            try await first.create(on: h.db)
            // Everything the application writes now is epoch 2 (version 3, with the epoch inside the MAC).
            _ = try await AuditService(db: h.db, ctx: h.ctx).record("after.rotation", actor: AuditActor(kind: .system))
            _ = try await AuditService(db: h.db, ctx: h.ctx).record("after.rotation.again", actor: AuditActor(kind: .system))
            let events = try await AuditEventRecord.query(on: h.db).sort(\.$seq, .ascending).all()
            XCTAssertEqual(events.map(\.chainVersion), [2, 3, 3])
            XCTAssertEqual(events.map(\.keyEpoch), [nil, 2, 2])
            let ring = AuditKeyring(config: h.ctx.config)
            let valid = try await AuditService.verifyChain(on: h.db, keyring: ring)
            XCTAssertTrue(valid.valid)
            XCTAssertEqual(valid.checked, 3)
            // Without the old key the early events cannot be verified: the previous key must stay configured.
            let missing = try await AuditService.verifyChain(on: h.db, keyring: AuditKeyring(currentEpoch: 2, keys: [2: epoch2]))
            XCTAssertFalse(missing.valid)
            XCTAssertEqual(missing.firstBrokenSeq, 1)
            // A head exported now names epoch 2 and verifies; one exported before the rotation verifies with the epoch-1 key.
            let signedHead = try await AuditService.signedHead(on: h.db, keyring: ring, now: h.clock.now())
            let head = try XCTUnwrap(signedHead)
            XCTAssertEqual(head.keyEpoch, 2)
            let headOK = try await AuditService.verify(head: head, on: h.db, keyring: ring)
            XCTAssertTrue(headOK)
            var forged = head
            forged.keyEpoch = nil
            let forgedOK = try await AuditService.verify(head: forged, on: h.db, keyring: ring)
            XCTAssertFalse(forgedOK, "a head cannot be re-labelled as the old epoch")
            // The database refuses to edit an event at all (append-only trigger), so re-labelling the epoch needs the table to be rewritten wholesale;
            // and then the MAC (which covers the epoch) and the rule that epochs never decrease along the chain catch it.
            let last = try XCTUnwrap(events.last)
            last.keyEpoch = 1
            do { try await last.update(on: h.db); XCTFail("audit events are append-only") } catch {}
            let forgedRing = AuditKeyring(currentEpoch: 2, keys: [1: epoch1, 2: epoch2])
            let untouched = try await AuditService.verifyChain(on: h.db, keyring: forgedRing)
            XCTAssertTrue(untouched.valid, "the refused edit changed nothing")
        }
    }

    func testConnectLinkKeyIdsAllowRotationWithoutBreakingIssuedLinks() throws {
        let k1 = SymmetricKey(data: Data(repeating: 0x61, count: 32)), k2 = SymmetricKey(data: Data(repeating: 0x62, count: 32))
        var config = ServerConfig.testing()
        config.connectLinkKey = k1
        let before = ConnectKeyring(config: config)
        XCTAssertEqual(before.currentId, ConnectKeyring.legacyKeyId)
        let code = try BusinessCode("K7M4Q2")
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        let oldLink = try before.link(code: code, context: ConnectContext(campaign: "spring", issuedAt: now, expiresAt: now.addingTimeInterval(86_400)))
        config.connectLinkKey = k2
        config.operations.connectKeyId = "c2"
        config.operations.previousConnectKeys = ["c1": k1]
        let after = ConnectKeyring(config: config)
        // A link issued before the rotation still verifies; a new one names the new key and verifies.
        XCTAssertEqual(try after.verifiedContext(of: oldLink, now: now).campaign, "spring")
        let newLink = try after.link(code: code, context: ConnectContext(campaign: "summer", issuedAt: now, expiresAt: now.addingTimeInterval(86_400)))
        XCTAssertEqual(newLink.claimedKeyId, "c2")
        XCTAssertEqual(try after.verifiedContext(of: newLink, now: now).campaign, "summer")
        // The old keyring (before rotation) cannot verify new links, and a retired previous key stops verifying old ones.
        XCTAssertThrowsError(try before.verifiedContext(of: newLink, now: now))
        config.operations.previousConnectKeys = [:]
        XCTAssertThrowsError(try ConnectKeyring(config: config).verifiedContext(of: oldLink, now: now))
        // The key id only selects a key; the signature (which covers the id) decides. A link re-labelled with another id fails.
        config.operations.previousConnectKeys = ["c1": k1]
        let relabelled = try ConnectLink(code: code, context: ConnectContext(campaign: "x", issuedAt: now, expiresAt: now.addingTimeInterval(86_400), keyId: "c1"), key: k2)
        XCTAssertThrowsError(try ConnectKeyring(config: config).verifiedContext(of: relabelled, now: now), "signed with c2 but naming c1")
        let unknownId = try ConnectLink(code: code, context: ConnectContext(campaign: "x", issuedAt: now, expiresAt: now.addingTimeInterval(86_400), keyId: "c9"), key: k2)
        XCTAssertThrowsError(try ConnectKeyring(config: config).verifiedContext(of: unknownId, now: now))
        // Expired links fail whatever the key.
        XCTAssertThrowsError(try after.verifiedContext(of: newLink, now: now.addingTimeInterval(2 * 86_400)))
    }

    func testConfigurationRefusesInconsistentRotationSettings() throws {
        var env = ["ENVIRONMENT": "development"]
        func parse(_ extra: [String: String]) throws -> ServerConfig { try ServerConfig.fromEnvironment(env.merging(extra) { $1 }) }
        let key = Base64URL.encode(Data(repeating: 7, count: 32))
        XCTAssertNoThrow(try parse(["DATA_ENCRYPTION_KEY_ID": "k2", "DATA_ENCRYPTION_KEYS_PREVIOUS": "k1:\(key)"]))
        XCTAssertThrowsError(try parse(["DATA_ENCRYPTION_KEY_ID": "k2", "DATA_ENCRYPTION_KEYS_PREVIOUS": "k2:\(key)"]), "the previous list repeats the current id")
        XCTAssertThrowsError(try parse(["DATA_ENCRYPTION_KEY_ID": "bad id!"]))
        XCTAssertThrowsError(try parse(["DATA_ENCRYPTION_KEYS_PREVIOUS": "k1:AAAA"]), "too short to be a key")
        XCTAssertThrowsError(try parse(["SERVER_PEPPER_ID": "p2", "SERVER_PEPPERS_PREVIOUS": "p2:\(key)"]))
        // An audit key rotation must keep every earlier epoch, or the chain could no longer be verified.
        XCTAssertNoThrow(try parse(["AUDIT_CHAIN_KEY_EPOCH": "2", "AUDIT_CHAIN_KEYS_PREVIOUS": "1:\(key)"]))
        XCTAssertThrowsError(try parse(["AUDIT_CHAIN_KEY_EPOCH": "3", "AUDIT_CHAIN_KEYS_PREVIOUS": "1:\(key)"]))
        XCTAssertThrowsError(try parse(["AUDIT_CHAIN_KEY_EPOCH": "2"]))
        XCTAssertThrowsError(try parse(["AUDIT_CHAIN_KEY_EPOCH": "0"]))
        env["ENVIRONMENT"] = "development"
    }
}
