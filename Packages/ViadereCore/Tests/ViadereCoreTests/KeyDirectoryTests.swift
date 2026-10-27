import Crypto
import Foundation
import XCTest
@testable import ViadereCore

final class MerkleTreeTests: XCTestCase {
    private func tree(_ n: Int) -> MerkleTree {
        var tree = MerkleTree()
        for i in 0..<n { tree.append(leafData: Data("leaf-\(i)".utf8)) }
        return tree
    }

    func testRFC6962Structure() {
        XCTAssertEqual(MerkleTree.emptyRoot, Data(SHA256.hash(data: Data())))
        let one = tree(1)
        XCTAssertEqual(one.root(), MerkleTree.leafHash(Data("leaf-0".utf8)))
        XCTAssertEqual(Data(SHA256.hash(data: Data([0x00]) + Data("leaf-0".utf8))), one.root())
        let two = tree(2)
        XCTAssertEqual(two.root(), MerkleTree.nodeHash(MerkleTree.leafHash(Data("leaf-0".utf8)), MerkleTree.leafHash(Data("leaf-1".utf8))))
        // Three leaves: split point 2.
        let three = tree(3)
        XCTAssertEqual(three.root(), MerkleTree.nodeHash(two.root(), MerkleTree.leafHash(Data("leaf-2".utf8))))
        // Domain separation: a leaf hash is never a node hash of the same bytes.
        XCTAssertNotEqual(MerkleTree.leafHash(Data(repeating: 1, count: 64)), MerkleTree.nodeHash(Data(repeating: 1, count: 32), Data(repeating: 1, count: 32)))
    }

    func testEveryInclusionProofVerifiesAndNothingElseDoes() {
        for size in 1...33 {
            let t = tree(size)
            let root = t.root()
            for index in 0..<size {
                let proof = t.inclusionProof(index: index, size: size)!
                let leaf = t.leafHashes[index]
                XCTAssertTrue(MerkleTree.verifyInclusion(leafHash: leaf, index: index, treeSize: size, proof: proof, root: root), "\(index)/\(size)")
                // Wrong index, wrong leaf, wrong root, wrong size, truncated/extended proof.
                if size > 1 {
                    XCTAssertFalse(MerkleTree.verifyInclusion(leafHash: leaf, index: (index + 1) % size, treeSize: size, proof: proof, root: root))
                }
                XCTAssertFalse(MerkleTree.verifyInclusion(leafHash: MerkleTree.leafHash(Data("other".utf8)), index: index, treeSize: size, proof: proof, root: root))
                XCTAssertFalse(MerkleTree.verifyInclusion(leafHash: leaf, index: index, treeSize: size, proof: proof, root: Data(repeating: 9, count: 32)))
                // The same proof does not verify against the root of a different tree.
                XCTAssertFalse(MerkleTree.verifyInclusion(leafHash: leaf, index: index, treeSize: size + 1, proof: proof, root: tree(size + 1).root()))
                if !proof.isEmpty { XCTAssertFalse(MerkleTree.verifyInclusion(leafHash: leaf, index: index, treeSize: size, proof: Array(proof.dropLast()), root: root)) }
                XCTAssertFalse(MerkleTree.verifyInclusion(leafHash: leaf, index: index, treeSize: size, proof: proof + [Data(repeating: 0, count: 32)], root: root))
            }
        }
    }

    func testEveryConsistencyProofVerifiesAndForksDoNot() {
        let big = tree(40)
        for second in 1...40 {
            for first in 1...second {
                let proof = big.consistencyProof(first: first, second: second)!
                XCTAssertTrue(MerkleTree.verifyConsistency(first: first, second: second, firstRoot: big.root(size: first), secondRoot: big.root(size: second), proof: proof), "\(first)->\(second)")
                if first < second {
                    // A different history (a forked log) is not consistent.
                    var forked = MerkleTree()
                    for i in 0..<second { forked.append(leafData: Data((i == 0 ? "forged" : "leaf-\(i)").utf8)) }
                    XCTAssertFalse(MerkleTree.verifyConsistency(first: first, second: second, firstRoot: big.root(size: first), secondRoot: forked.root(size: second), proof: proof))
                    XCTAssertFalse(MerkleTree.verifyConsistency(first: first, second: second, firstRoot: forked.root(size: first), secondRoot: big.root(size: second), proof: proof))
                    XCTAssertFalse(MerkleTree.verifyConsistency(first: first, second: second, firstRoot: big.root(size: first), secondRoot: big.root(size: second), proof: []))
                }
            }
        }
    }

    func testEmptyAndEqualSizes() {
        let t = tree(5)
        XCTAssertTrue(MerkleTree.verifyConsistency(first: 0, second: 5, firstRoot: MerkleTree.emptyRoot, secondRoot: t.root(), proof: []))
        XCTAssertFalse(MerkleTree.verifyConsistency(first: 0, second: 5, firstRoot: Data(repeating: 1, count: 32), secondRoot: t.root(), proof: []))
        XCTAssertTrue(MerkleTree.verifyConsistency(first: 5, second: 5, firstRoot: t.root(), secondRoot: t.root(), proof: []))
        XCTAssertFalse(MerkleTree.verifyConsistency(first: 5, second: 5, firstRoot: t.root(), secondRoot: tree(4).root(), proof: []))
        XCTAssertFalse(MerkleTree.verifyConsistency(first: 6, second: 5, firstRoot: t.root(), secondRoot: t.root(), proof: []))
    }
}

/// An in-memory log with a log key, producing the responses the server produces.
final class TestLog {
    let key = SoftwareP256SigningKey()
    var tree = MerkleTree()
    var entries: [(entry: KeyLogEntry, bytes: Data)] = []
    var now: Date

    init(now: Date) { self.now = now }

    var verifier: KeyDirectoryVerifier { KeyDirectoryVerifier(logKeys: [key.publicKey]) }

    @discardableResult
    func append(_ entry: KeyLogEntry) throws -> Int {
        let bytes = try entry.leafData()
        entries.append((entry, bytes))
        tree.append(leafData: bytes)
        return entries.count - 1
    }

    func sth(size: Int? = nil, at: Date? = nil) async throws -> SignedTreeHead {
        let size = size ?? tree.size
        return try await SignedTreeHead.sign(TreeHead(treeSize: size, rootHash: tree.root(size: size), timestamp: at ?? now), with: key)
    }

    func response(for business: BusinessID, since: Int? = nil, sth override: SignedTreeHead? = nil, includeOtherBusinesses: Bool = false) async throws -> KeyDirectoryResponse {
        let head: SignedTreeHead
        if let override { head = override } else { head = try await sth() }
        var consistencyFrom: Int?
        var consistency: [String]?
        if let since, since > 0, since < tree.size {
            consistencyFrom = since
            consistency = tree.consistencyProof(first: since, second: tree.size)!.map(Hex.encode)
        }
        let items = entries.enumerated().filter { includeOtherBusinesses || $0.element.entry.businessId == business }.map { index, item in
            KeyLogEntryProof(index: index, entry: Base64URL.encode(item.bytes), inclusionProof: tree.inclusionProof(index: index, size: tree.size)!.map(Hex.encode))
        }
        return KeyDirectoryResponse(sth: head, consistencyFrom: consistencyFrom, consistencyProof: consistency, entries: items)
    }
}

func assertDirectoryError(_ expected: KeyDirectoryError, _ verifier: KeyDirectoryVerifier, _ response: KeyDirectoryResponse, business: BusinessID,
                          lastSeen: SeenTreeHead?, now: Date, file: StaticString = #filePath, line: UInt = #line) {
    XCTAssertThrowsError(try verifier.verify(response, businessId: business, lastSeen: lastSeen, now: now), file: file, line: line) {
        XCTAssertEqual($0 as? KeyDirectoryError, expected, file: file, line: line)
    }
}

final class KeyDirectoryTests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)
    private let business = BusinessID()

    private func registered(_ log: TestLog, root: SoftwareP256SigningKey) async throws {
        let entry = try await KeyLogEntry.sign(.root(RootRegistration(businessId: business, publicKey: root.publicKey, createdAt: now)), rootKey: root)
        try log.append(entry)
    }

    private func publishKey(_ log: TestLog, root: SoftwareP256SigningKey, purpose: BusinessKeyPurpose, key publicKey: Data, serial: Int64,
                            from: TimeInterval = -60, to: TimeInterval = 86_400 * 30) async throws -> String {
        let rootKid = KeyIdentifier.make(try root.publicKey.signingKey())
        let statement = try KeyPublication(businessId: business, rootKid: rootKid, purpose: purpose, publicKey: publicKey,
                                           notBefore: now.addingTimeInterval(from), notAfter: now.addingTimeInterval(to), serial: serial)
        try log.append(try await KeyLogEntry.sign(.key(statement), rootKey: root))
        return statement.kid
    }

    func testRegisteredKeysVerifyAndPin() async throws {
        let log = TestLog(now: now)
        let root = SoftwareP256SigningKey()
        let hpke = SoftwareE2EEPrivateKey()
        let signing = SoftwareP256SigningKey()
        try await registered(log, root: root)
        let hpkeKid = try await publishKey(log, root: root, purpose: .hpkeEncryption, key: hpke.publicKey.x963, serial: 1)
        let signKid = try await publishKey(log, root: root, purpose: .approvalRequestSigning, key: signing.publicKey.x963, serial: 2)
        let verified = try log.verifier.verify(try await log.response(for: business), businessId: business, lastSeen: nil, now: now)
        XCTAssertEqual(verified.head.treeSize, 3)
        XCTAssertEqual(verified.state.validKey(kid: hpkeKid, purpose: .hpkeEncryption, at: now)?.encryptionKey, hpke.publicKey)
        XCTAssertEqual(verified.state.validKey(kid: signKid, purpose: .approvalRequestSigning, at: now)?.signingKey, signing.publicKey)
        // A key is only valid for its own purpose.
        XCTAssertNil(verified.state.validKey(kid: signKid, purpose: .hpkeEncryption, at: now))
        XCTAssertNil(verified.state.validKey(kid: signKid, purpose: .approvalRequestSigning, at: now.addingTimeInterval(86_400 * 31)), "expired")
        XCTAssertNil(verified.state.validKey(kid: signKid, purpose: .approvalRequestSigning, at: now.addingTimeInterval(-3600)), "not yet valid")
        XCTAssertEqual(KeyDirectoryVerifier.pinStatus(pin: nil, state: verified.state), .firstUse(rootKid: KeyIdentifier.make(try root.publicKey.signingKey())))
        let pin = PinnedRoot(from: verified.state.currentRoot!, businessId: business, at: now)
        XCTAssertEqual(KeyDirectoryVerifier.pinStatus(pin: pin, state: verified.state), .unchanged)
    }

    func testRotationOverlapAndRevocation() async throws {
        let log = TestLog(now: now)
        let root = SoftwareP256SigningKey()
        try await registered(log, root: root)
        let oldKey = SoftwareE2EEPrivateKey()
        let newKey = SoftwareE2EEPrivateKey()
        let oldKid = try await publishKey(log, root: root, purpose: .hpkeEncryption, key: oldKey.publicKey.x963, serial: 1)
        let newKid = try await publishKey(log, root: root, purpose: .hpkeEncryption, key: newKey.publicKey.x963, serial: 2, from: -10)
        var state = try log.verifier.verify(try await log.response(for: business), businessId: business, lastSeen: nil, now: now).state
        // Overlap: both valid, the newest listed first.
        XCTAssertEqual(state.validKeys(for: .hpkeEncryption, at: now).map(\.kid), [newKid, oldKid])
        let rootKid = KeyIdentifier.make(try root.publicKey.signingKey())
        try log.append(try await KeyLogEntry.sign(.revocation(KeyRevocation(businessId: business, rootKid: rootKid, kid: oldKid, reason: "superseded", revokedAt: now, serial: 3)), rootKey: root))
        state = try log.verifier.verify(try await log.response(for: business), businessId: business, lastSeen: nil, now: now).state
        XCTAssertEqual(state.validKeys(for: .hpkeEncryption, at: now).map(\.kid), [newKid])
        XCTAssertNil(state.validKey(kid: oldKid, purpose: .hpkeEncryption, at: now), "a revoked key is never valid")
    }

    func testStatementsMustBeSignedByTheRootAndInOrder() async throws {
        let log = TestLog(now: now)
        let root = SoftwareP256SigningKey()
        let attacker = SoftwareP256SigningKey()
        try await registered(log, root: root)
        let rootKid = KeyIdentifier.make(try root.publicKey.signingKey())
        func publication(serial: Int64, key: Data = SoftwareE2EEPrivateKey().publicKey.x963, rootKid: String? = nil) throws -> KeyPublication {
            try KeyPublication(businessId: business, rootKid: rootKid ?? KeyIdentifier.make(try root.publicKey.signingKey()), purpose: .hpkeEncryption, publicKey: key,
                               notBefore: now.addingTimeInterval(-60), notAfter: now.addingTimeInterval(3600), serial: serial)
        }
        func verify(_ entry: KeyLogEntry) async throws {
            let copy = TestLog(now: now)
            for (existing, _) in log.entries { try copy.append(existing) }
            try copy.append(entry)
            _ = try copy.verifier.verify(try await copy.response(for: business, includeOtherBusinesses: true), businessId: business, lastSeen: nil, now: now)
        }
        // Signed by someone else (a relay inserting its own key).
        do {
            try await verify(try await KeyLogEntry.sign(.key(try publication(serial: 1)), rootKey: attacker))
            XCTFail("forged statement accepted")
        } catch { XCTAssertEqual(error as? KeyDirectoryError, .invalidSignature("key")) }
        // Serial gap (an omitted statement).
        do {
            try await verify(try await KeyLogEntry.sign(.key(try publication(serial: 2)), rootKey: root))
            XCTFail("gap accepted")
        } catch { XCTAssertEqual(error as? KeyDirectoryError, .serialOutOfOrder(expected: 1, got: 2)) }
        // Wrong root kid inside the statement.
        do {
            try await verify(try await KeyLogEntry.sign(.key(try publication(serial: 1, rootKid: KeyIdentifier.make(try attacker.publicKey.signingKey()))), rootKey: root))
            XCTFail()
        } catch { XCTAssertEqual(error as? KeyDirectoryError, .rootMismatch) }
        // Validity longer than allowed.
        do {
            let long = try KeyPublication(businessId: business, rootKid: rootKid, purpose: .hpkeEncryption, publicKey: SoftwareE2EEPrivateKey().publicKey.x963,
                                          notBefore: now, notAfter: now.addingTimeInterval(86_400 * 800), serial: 1)
            try await verify(try await KeyLogEntry.sign(.key(long), rootKey: root))
            XCTFail()
        } catch { XCTAssertEqual(error as? KeyDirectoryError, .invalidValidity("window")) }
        // A second root registration.
        do {
            try await verify(try await KeyLogEntry.sign(.root(RootRegistration(businessId: business, publicKey: attacker.publicKey, createdAt: now)), rootKey: attacker))
            XCTFail()
        } catch { XCTAssertEqual(error as? KeyDirectoryError, .rootAlreadyRegistered) }
        // Revoking an unknown key.
        do {
            try await verify(try await KeyLogEntry.sign(.revocation(KeyRevocation(businessId: business, rootKid: rootKid, kid: KeyIdentifier.make(try attacker.publicKey.signingKey()), reason: "retired", revokedAt: now, serial: 1)), rootKey: root))
            XCTFail()
        } catch { XCTAssertEqual(error as? KeyDirectoryError, .unknownKey) }
        // A statement for another business inside this business's response.
        do {
            let other = BusinessID()
            let foreign = try KeyPublication(businessId: other, rootKid: rootKid, purpose: .hpkeEncryption, publicKey: SoftwareE2EEPrivateKey().publicKey.x963,
                                             notBefore: now, notAfter: now.addingTimeInterval(3600), serial: 1)
            try await verify(try await KeyLogEntry.sign(.key(foreign), rootKey: root))
            XCTFail()
        } catch { XCTAssertEqual(error as? KeyDirectoryError, .wrongBusiness) }
    }

    func testRootChangeNeedsBothSignaturesAndAlertsEvenWhenValid() async throws {
        let log = TestLog(now: now)
        let root = SoftwareP256SigningKey()
        let next = SoftwareP256SigningKey()
        try await registered(log, root: root)
        let hpke = SoftwareE2EEPrivateKey()
        let hpkeKid = try await publishKey(log, root: root, purpose: .hpkeEncryption, key: hpke.publicKey.x963, serial: 1)
        let first = try log.verifier.verify(try await log.response(for: business), businessId: business, lastSeen: nil, now: now)
        let pin = PinnedRoot(from: first.state.currentRoot!, businessId: business, at: now)
        let rootKid = KeyIdentifier.make(try root.publicKey.signingKey())

        // The relay (or a thief of the old root) tries a succession without the new root's consent: refused.
        let succession = RootSuccession(businessId: business, oldRootKid: rootKid, newPublicKey: next.publicKey, createdAt: now)
        let oneSided = try await KeyLogEntry.sign(.succession(succession), rootKey: root, newRootKey: root)
        let copy = TestLog(now: now)
        for (e, _) in log.entries { try copy.append(e) }
        try copy.append(oneSided)
        assertDirectoryError(.invalidSignature("new root"), copy.verifier, try await copy.response(for: business), business: business, lastSeen: nil, now: now)

        // A proper succession: valid, but the pinned device must alert and re-confirm, and nothing is inherited.
        try log.append(try await KeyLogEntry.sign(.succession(succession), rootKey: root, newRootKey: next))
        let rotated = try log.verifier.verify(try await log.response(for: business), businessId: business, lastSeen: nil, now: now)
        let newRootKid = KeyIdentifier.make(try next.publicKey.signingKey())
        XCTAssertEqual(KeyDirectoryVerifier.pinStatus(pin: pin, state: rotated.state), .rotated(pinnedKid: rootKid, currentKid: newRootKid))
        XCTAssertNil(rotated.state.validKey(kid: hpkeKid, purpose: .hpkeEncryption, at: now), "keys of the old root are not inherited")
        // Statements by the old root after the succession are refused.
        let stale = try KeyPublication(businessId: business, rootKid: rootKid, purpose: .hpkeEncryption, publicKey: SoftwareE2EEPrivateKey().publicKey.x963,
                                       notBefore: now, notAfter: now.addingTimeInterval(3600), serial: 2)
        try log.append(try await KeyLogEntry.sign(.key(stale), rootKey: root))
        assertDirectoryError(.rootMismatch, log.verifier, try await log.response(for: business), business: business, lastSeen: nil, now: now)
    }

    func testRelaySubstitutingTheRootBeforeFirstContactIsAConflictForAPinnedDevice() async throws {
        // Device pinned the real root. Later the relay serves a log whose business history starts with an attacker root.
        let real = TestLog(now: now)
        let root = SoftwareP256SigningKey()
        try await registered(real, root: root)
        let pinned = PinnedRoot(from: try real.verifier.verify(try await real.response(for: business), businessId: business, lastSeen: nil, now: now).state.currentRoot!,
                                businessId: business, at: now)
        let evil = TestLog(now: now)
        let attacker = SoftwareP256SigningKey()
        try await registered(evil, root: attacker)
        let state = try evil.verifier.verify(try await evil.response(for: business), businessId: business, lastSeen: nil, now: now).state
        XCTAssertEqual(KeyDirectoryVerifier.pinStatus(pin: pinned, state: state),
                       .conflict(pinnedKid: pinned.rootKid, currentKid: KeyIdentifier.make(try attacker.publicKey.signingKey())))
        // A different log key (the relay's own log) does not verify at all.
        assertDirectoryError(.treeHeadSignature, real.verifier, try await evil.response(for: business), business: business, lastSeen: nil, now: now)
    }

    func testConsistencyDetectsRollbackForkAndOmission() async throws {
        let log = TestLog(now: now)
        let root = SoftwareP256SigningKey()
        try await registered(log, root: root)
        _ = try await publishKey(log, root: root, purpose: .hpkeEncryption, key: SoftwareE2EEPrivateKey().publicKey.x963, serial: 1)
        let seen = SeenTreeHead(try log.verifier.verify(try await log.response(for: business), businessId: business, lastSeen: nil, now: now).head)
        XCTAssertEqual(seen.treeSize, 2)

        // Append and verify with a consistency proof: fine.
        _ = try await publishKey(log, root: root, purpose: .hpkeEncryption, key: SoftwareE2EEPrivateKey().publicKey.x963, serial: 2)
        let ok = try log.verifier.verify(try await log.response(for: business, since: 2), businessId: business, lastSeen: seen, now: now)
        XCTAssertEqual(ok.head.treeSize, 3)
        // The proof is required once the log grew.
        assertDirectoryError(.consistencyProofMissing, log.verifier, try await log.response(for: business), business: business, lastSeen: seen, now: now)
        // A forked log (same size growth, different history) fails consistency.
        let forked = TestLog(now: now)
        let forkedKey = log.key
        _ = forkedKey
        // Build a fork signed by the same log key: first entry different.
        let fork = TestLog(now: now)
        let attacker = SoftwareP256SigningKey()
        try await registered(fork, root: attacker)
        for _ in 0..<2 { try fork.append(log.entries[1].entry) }
        let forkResponse = KeyDirectoryResponse(sth: try await SignedTreeHead.sign(TreeHead(treeSize: fork.tree.size, rootHash: fork.tree.root(), timestamp: now), with: log.key),
                                                consistencyFrom: 2, consistencyProof: fork.tree.consistencyProof(first: 2, second: 3)!.map(Hex.encode), entries: [])
        _ = forked
        assertDirectoryError(.consistencyFailed, log.verifier, forkResponse, business: business, lastSeen: seen, now: now)
        // Rollback: a head older than the one already seen.
        let older = KeyDirectoryResponse(sth: try await log.sth(size: 1), entries: [])
        assertDirectoryError(.treeShrank, log.verifier, older, business: business, lastSeen: seen, now: now)
        // Same size, different root: equivocation.
        let equivocation = KeyDirectoryResponse(sth: try await SignedTreeHead.sign(TreeHead(treeSize: 2, rootHash: Data(repeating: 7, count: 32), timestamp: now), with: log.key), entries: [])
        assertDirectoryError(.forkDetected, log.verifier, equivocation, business: business, lastSeen: seen, now: now)
    }

    func testInclusionAndOrderingAndFreshness() async throws {
        let log = TestLog(now: now)
        let root = SoftwareP256SigningKey()
        try await registered(log, root: root)
        let kid = try await publishKey(log, root: root, purpose: .hpkeEncryption, key: SoftwareE2EEPrivateKey().publicKey.x963, serial: 1)
        _ = kid
        var response = try await log.response(for: business)
        // An entry the log never contained (a relay-fabricated statement) has no valid inclusion proof.
        let fake = SoftwareP256SigningKey()
        let injected = try await KeyLogEntry.sign(.key(try KeyPublication(businessId: business, rootKid: KeyIdentifier.make(try root.publicKey.signingKey()), purpose: .hpkeEncryption,
                                                                          publicKey: fake.publicKey.x963, notBefore: now, notAfter: now.addingTimeInterval(60), serial: 2)), rootKey: root)
        var tampered = response
        tampered.entries.append(KeyLogEntryProof(index: 2, entry: Base64URL.encode(try injected.leafData()), inclusionProof: []))
        assertDirectoryError(.inclusionFailed(index: 2), log.verifier, tampered, business: business, lastSeen: nil, now: now)
        // Reordered entries.
        var reordered = response
        reordered.entries.reverse()
        assertDirectoryError(.entriesOutOfOrder, log.verifier, reordered, business: business, lastSeen: nil, now: now)
        // A modified entry fails its inclusion proof.
        response.entries[1].entry = Base64URL.encode(try injected.leafData())
        assertDirectoryError(.inclusionFailed(index: 1), log.verifier, response, business: business, lastSeen: nil, now: now)
        // Stale and future heads.
        let stale = try await log.response(for: business, sth: try await log.sth(at: now.addingTimeInterval(-8 * 86_400)))
        assertDirectoryError(.treeHeadStale, log.verifier, stale, business: business, lastSeen: nil, now: now)
        let future = try await log.response(for: business, sth: try await log.sth(at: now.addingTimeInterval(3600)))
        assertDirectoryError(.treeHeadFromFuture, log.verifier, future, business: business, lastSeen: nil, now: now)
        // The wrong log id.
        var other = log.verifier
        other.logId = "someone.else"
        assertDirectoryError(.wrongLog, other, try await log.response(for: business), business: business, lastSeen: nil, now: now)
    }

    func testStrictEntryParsing() async throws {
        let root = SoftwareP256SigningKey()
        let entry = try await KeyLogEntry.sign(.root(RootRegistration(businessId: business, publicKey: root.publicKey, createdAt: now)), rootKey: root)
        let bytes = try entry.leafData()
        XCTAssertEqual(try KeyLogEntry.parse(bytes), entry)
        // Non-canonical re-encodings (whitespace, member order) are refused: one leaf, one byte string.
        let spaced = Data(String(decoding: bytes, as: UTF8.self).replacingOccurrences(of: ",", with: ", ").utf8)
        XCTAssertThrowsError(try KeyLogEntry.parse(spaced))
        XCTAssertThrowsError(try KeyLogEntry.parse(Data(#"{"v":2}"#.utf8))) { XCTAssertEqual($0 as? KeyDirectoryError, .unsupportedVersion(2)) }
        XCTAssertThrowsError(try KeyLogEntry.parse(Data(repeating: 0x20, count: KeyLogEntry.maxBytes + 1)))
        // Algorithm / purpose pairing is enforced.
        var object = try XCTUnwrap(SignedStatement(payload: entry.statement, signature: "").canonicalObject())
        object["type"] = .string("key")
        XCTAssertThrowsError(try KeyLogEntry(type: "key", businessId: business, statement: Base64URL.encode(CanonicalJSON.serialize(.object(object))), signatures: entry.signatures).decodeStatement())
    }
}
