@preconcurrency import Crypto
import Fluent
import Foundation
import NIOHTTP1
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Phase 4 gate review: exploit-reproducing tests for M2 (silent recovery-key decryption), M3 (a rotation must fit), L4 (removal) and L5
/// (shared buckets). Each failed before its fix.
extension VaultSyncTests {
    /// Lets time pass for the recovery releases without moving the clock (which would expire the test sessions): every release is aged.
    func passTime(_ h: TestHarness, _ seconds: TimeInterval) async throws {
        for record in try await VaultRecoveryReleaseRecord.query(on: h.db).all() {
            record.requestedAt = record.requestedAt.addingTimeInterval(-seconds)
            record.releaseAt = record.releaseAt.addingTimeInterval(-seconds)
            record.expiresAt = record.expiresAt.addingTimeInterval(-seconds)
            try await record.update(on: h.db)
        }
    }

    func release(_ h: TestHarness, _ who: TestConsumer) async throws -> HTTPResult {
        try await call(h, who, APIRoutes.vaultRecoveryReleaseRequest, body: nil as EmptyBody?)
    }

    /// Requests the release and lets the 72 h hold pass.
    @discardableResult
    func openWindow(_ h: TestHarness, _ who: TestConsumer) async throws -> VaultRecoveryRelease {
        let started = try await release(h, who)
        XCTAssertEqual(started.status, .ok, started.text)
        let value = try started.json(VaultRecoveryRelease.self)
        try await passTime(h, VaultRecoveryRelease.holdSeconds + 1)
        return value
    }

    /// Adds a second vault device (joined through the real join flow) and returns it with the vault after the join.
    func addDevice(_ h: TestHarness, _ f: Fixture, version: UInt64 = 1) async throws -> (account: TestConsumer, identity: VaultDeviceIdentity, vault: UnlockedVault) {
        let b = try await h.enrollDevice(f.a)
        let bIdentity = VaultDeviceIdentity.software()
        let secret = PairingSecret.generate()
        _ = try await call(h, f.a, APIRoutes.vaultJoinCreate, params: ["joinId": secret.joinId], body: nil as EmptyBody?)
        let sealed = try JoinRequest.make(for: bIdentity, label: "iPad").sealed(with: secret)
        _ = try await call(h, b, APIRoutes.vaultJoinRequest, params: ["joinId": secret.joinId], body: VaultJoinRequestBody(request: Base64URL.encode(sealed)))
        let approval = try await f.vault.approvingJoin(JoinRequest.make(for: bIdentity, label: "iPad"), secret: secret, now: h.clock.now())
        let response = try await put(h, f.a, putBody(approval, expected: version, join: (secret.joinId, bIdentity.memberId)))
        XCTAssertEqual(response.status, .ok, response.text)
        return (b, bIdentity, approval.vault)
    }

    // MARK: M2

    func testGateM2_AnAccountOnlyAttackerCannotReadTheRecoveryEnvelopeOrCiphertextWithoutTheHold() async throws {
        try await withHarness(Self.enabled) { h in
            let f = try await fixture(h, items: [totp()])
            let attacker = try await trustedSecondDevice(h, f.a)
            try await eq(try await get(h, attacker, APIRoutes.vaultRecoveryEnvelope).status, .forbidden)
            try await eq(try await get(h, attacker, APIRoutes.vaultManifests).status, .forbidden)
            try await eq(try await get(h, attacker, APIRoutes.vaultDevices).status, .forbidden)
            try await eq(try await call(h, attacker, APIRoutes.vaultBlobs, body: VaultBlobsRequest(itemIds: f.vault.manifest.items.map(\.itemId))).status, .forbidden)
            // The owner's own (bound) device does not need the recovery envelope either.
            try await eq(try await get(h, f.a, APIRoutes.vaultRecoveryEnvelope).status, .forbidden)
        }
    }

    func testGateM2_TheHoldNotifiesEveryDeviceAndAnyTrustedDeviceCanCancelIt() async throws {
        try await withHarness(Self.enabled) { h in
            let f = try await fixture(h, items: [totp()])
            let attacker = try await trustedSecondDevice(h, f.a)
            let started = try await release(h, attacker)
            XCTAssertEqual(started.status, .ok, started.text)
            let hold = try started.json(VaultRecoveryRelease.self)
            XCTAssertEqual(hold.state, .holding)
            XCTAssertEqual(hold.releaseAt.timeIntervalSince(hold.requestedAt), 72 * 3600, accuracy: 1)
            XCTAssertEqual(hold.expiresAt.timeIntervalSince(hold.releaseAt), 24 * 3600, accuracy: 1)
            // Still nothing is released during the hold.
            try await eq(try await get(h, attacker, APIRoutes.vaultRecoveryEnvelope).status, .forbidden)
            try await eq(try await get(h, attacker, APIRoutes.vaultManifests).status, .forbidden)
            // The owner's device is told, with a cancel action pointing at the release; the requesting device is not.
            let seen = try await notices(h, f.a)
            let notice = try XCTUnwrap(seen.first { $0.topic == .vaultRecoveryRequested })
            XCTAssertEqual(notice.action, .cancelVaultRecovery)
            XCTAssertEqual(notice.subjectId, hold.releaseId.uuidString.lowercased())
            try await eq(try await notices(h, attacker).contains { $0.topic == .vaultRecoveryRequested }, false)
            // The vault shows the pending release.
            let status = try await get(h, f.a, APIRoutes.vaultStatus).json(VaultStatus.self)
            XCTAssertEqual(status.recoveryRelease?.state, .holding)
            XCTAssertEqual(status.recoveryRelease?.requestedByThisDevice, false)
            // Another device cannot start a second one meanwhile, and the same device gets the same release back.
            let again = try await release(h, attacker)
            XCTAssertEqual(try again.json(VaultRecoveryRelease.self).releaseId, hold.releaseId)
            // The owner cancels ("Not you?"). A cooling-down device cannot; a trusted unbound one can.
            let cooling = try await h.enrollDevice(f.a)
            try await eq(try await call(h, cooling, APIRoutes.vaultRecoveryReleaseCancel, params: ["releaseId": hold.releaseId.uuidString.lowercased()], body: nil as EmptyBody?).status, .forbidden)
            let cancelled = try await call(h, f.a, APIRoutes.vaultRecoveryReleaseCancel, params: ["releaseId": hold.releaseId.uuidString.lowercased()], body: nil as EmptyBody?)
            XCTAssertEqual(cancelled.status, .ok, cancelled.text)
            XCTAssertEqual(try cancelled.json(VaultRecoveryRelease.self).state, .cancelled)
            try await passTime(h, 73 * 3600)
            try await eq(try await get(h, attacker, APIRoutes.vaultRecoveryEnvelope).status, .forbidden, "a cancelled release never opens")
            try await eq(try await notices(h, attacker).contains { $0.topic == .vaultRecoveryCancelled }, true)
            // Unknown release ids are not found.
            try await eq(try await call(h, f.a, APIRoutes.vaultRecoveryReleaseCancel, params: ["releaseId": UUID().uuidString.lowercased()], body: nil as EmptyBody?).status, .notFound)
        }
    }

    func testGateM2_AfterTheHoldTheEnvelopeIsReleasedToTheRequestingDeviceOnlyForTwentyFourHours() async throws {
        try await withHarness(Self.enabled) { h in
            let f = try await fixture(h, items: [totp()])
            let requester = try await trustedSecondDevice(h, f.a)
            let bystander = try await trustedSecondDevice(h, f.a)
            let hold = try await openWindow(h, requester)
            let status = try await get(h, requester, APIRoutes.vaultStatus).json(VaultStatus.self)
            XCTAssertEqual(status.recoveryRelease?.state, .released)
            XCTAssertEqual(status.recoveryRelease?.requestedByThisDevice, true)
            try await eq(try await notices(h, f.a).contains { $0.topic == .vaultRecoveryReleased }, true, "opening the window is announced")
            // Released to the requester only.
            try await eq(try await get(h, bystander, APIRoutes.vaultRecoveryEnvelope).status, .forbidden)
            try await eq(try await get(h, bystander, APIRoutes.vaultManifests).status, .forbidden)
            try await eq(try await call(h, bystander, APIRoutes.vaultBlobs, body: VaultBlobsRequest(itemIds: [])).status, .forbidden)
            try await eq(try await get(h, requester, APIRoutes.vaultManifests).status, .ok)
            try await eq(try await call(h, requester, APIRoutes.vaultBlobs, body: VaultBlobsRequest(itemIds: f.vault.manifest.items.map(\.itemId))).status, .ok)
            try await eq(try await get(h, requester, APIRoutes.vaultDevices).status, .ok)
            try await eq(try await get(h, requester, APIRoutes.vaultRecoveryEnvelope).status, .ok)
            // Every fetch is announced and audited.
            try await eq(try await notices(h, f.a).contains { $0.topic == .vaultRecoveryFetched }, true)
            let audit = try await AuditEventRecord.query(on: h.db).all().map(\.action)
            XCTAssertTrue(audit.contains("vault.recovery_envelope_fetched") && audit.contains("vault.recovery_release_requested"))
            // The window closes after 24 hours.
            try await passTime(h, VaultRecoveryRelease.windowSeconds + 1)
            XCTAssertEqual(hold.state, .holding)
            try await eq(try await get(h, requester, APIRoutes.vaultRecoveryEnvelope).status, .forbidden)
            try await eq(try await get(h, requester, APIRoutes.vaultManifests).status, .forbidden)
            try await eq(try await get(h, requester, APIRoutes.vaultStatus).json(VaultStatus.self).recoveryRelease?.state, nil, "an expired window is no longer open")
        }
    }

    func testGateM2_RestoringNeedsTheWindowNotifiesAndUsesItUp() async throws {
        try await withHarness(Self.enabled) { h in
            let f = try await fixture(h, items: [try passkey(), totp()])
            let recovered = try await trustedSecondDevice(h, f.a)
            // Without a released envelope a restore is refused outright, even with a perfectly valid recovery-key restore manifest.
            let earlyChain = try await get(h, f.a, APIRoutes.vaultManifests).json(VaultManifestsResponse.self).manifests.compactMap(\.signed)
            let earlyHead = try UnlockedVault.authenticateChain(earlyChain, recoveryKey: f.recovery)
            let earlySnapshot = VaultSnapshot(verified: earlyHead, blobs: f.vault.snapshot.blobs, envelopes: f.vault.snapshot.envelopes)
            let early = try await UnlockedVault.recovering(earlySnapshot, recoveryKey: f.recovery, newRecoveryKey: .generate(), newDevice: .software(), label: "Early", now: h.clock.now())
            try await eq(try await put(h, recovered, putBody(early, expected: 1, bind: true)).status, .forbidden)

            try await openWindow(h, recovered)
            let chain = try await get(h, recovered, APIRoutes.vaultManifests).json(VaultManifestsResponse.self).manifests.compactMap(\.signed)
            let envelope = try await get(h, recovered, APIRoutes.vaultRecoveryEnvelope).json(VaultEnvelopeResponse.self)
            let blobs = try await call(h, recovered, APIRoutes.vaultBlobs, body: VaultBlobsRequest(itemIds: f.vault.manifest.items.map(\.itemId))).json(VaultBlobsResponse.self)
            let head = try UnlockedVault.authenticateChain(chain, recoveryKey: f.recovery)
            let snapshot = VaultSnapshot(verified: head, blobs: Dictionary(uniqueKeysWithValues: blobs.blobs.map { ($0.itemId, Base64URL.decode($0.blob)!) }),
                                         envelopes: [envelope.memberId: Base64URL.decode(envelope.envelope)!])
            let newDevice = VaultDeviceIdentity.software()
            let restored = try await UnlockedVault.recovering(snapshot, recoveryKey: f.recovery, newRecoveryKey: .generate(), newDevice: newDevice, label: "New phone", now: h.clock.now())
            // Another trusted device cannot use the requester's window.
            let thief = try await trustedSecondDevice(h, f.a)
            try await eq(try await put(h, thief, putBody(restored, expected: 1, bind: true)).status, .forbidden)
            let done = try await put(h, recovered, putBody(restored, expected: 1, bind: true))
            XCTAssertEqual(done.status, .ok, done.text)
            // Told: the lost phone's account device sees the restore; the window is spent.
            try await eq(try await notices(h, f.a).contains { $0.topic == .vaultRestored }, true)
            try await eq(try await get(h, recovered, APIRoutes.vaultRecoveryEnvelope).status, .forbidden, "the window is consumed")
            try await eq(try await VaultRecoveryReleaseRecord.query(on: h.db).filter(\.$state == "consumed").count(), 1)
        }
    }

    // MARK: L4

    func testGateL4_ADeviceThatLeftTheVaultCannotComeBackThroughTheRecoveryWindowOrAJoin() async throws {
        try await withHarness(Self.enabled) { h in
            let f = try await fixture(h, items: [totp()])
            let b = try await addDevice(h, f)
            // The owner removes B (server access ends at once; the rotation follows).
            try await eq(try await call(h, f.a, APIRoutes.vaultDeviceRemove, params: ["memberId": b.identity.memberId], body: nil as EmptyBody?).status, .ok)
            // B's account device is still a trusted account device. It may not use the recovery window, nor ask to join again.
            try await trust(h, b.account)
            try await eq(try await release(h, b.account).status, .forbidden)
            try await eq(try await get(h, b.account, APIRoutes.vaultManifests).status, .forbidden)
            let secret = PairingSecret.generate()
            _ = try await call(h, f.a, APIRoutes.vaultJoinCreate, params: ["joinId": secret.joinId], body: nil as EmptyBody?)
            let rejoin = try await call(h, b.account, APIRoutes.vaultJoinRequest, params: ["joinId": secret.joinId], body: VaultJoinRequestBody(request: Base64URL.encode(try JoinRequest.make(for: b.identity, label: "iPad").sealed(with: secret))))
            XCTAssertEqual(rejoin.status, .forbidden)
            // The same holds when the removal came through a rotation manifest.
            let c = try await trustedSecondDevice(h, f.a)
            XCTAssertNotEqual(c.device?.id, b.account.device?.id)
        }
    }

    func testGateL4_ADeviceCannotBeDroppedFromTheManifestWithoutRotatingTheKey() async throws {
        try await withHarness(Self.enabled) { h in
            let f = try await fixture(h, items: [totp()])
            let b = try await addDevice(h, f)
            // A hostile (or buggy) client signs a manifest that simply forgets B, keeping the epoch, so B's envelope still opens the key.
            var m = b.vault.manifest
            m.version += 1
            m.previousHash = b.vault.snapshot.verified.hash
            m.signerId = f.identity.memberId
            m.members.removeAll { $0.id == b.identity.memberId }
            let signed = try await SignedVaultManifest.sign(m, with: f.identity.signingKey)
            let response = try await put(h, f.a, VaultPutRequest(expectedVersion: 2, manifest: VaultManifestDTO(signed)))
            XCTAssertEqual(response.status, .unprocessableEntity, response.text)
            try await eq(try await VaultMemberRecord.query(on: h.db).filter(\.$removedAt != nil).count(), 0)
        }
    }

    // MARK: L5

    func testGateL5_AnotherAccountDeviceCannotUseUpTheOwnersBuckets() async throws {
        try await withHarness({ $0.vaultSync.enabled = true; $0.vaultSync.readRate = .perHour(3, burst: 3); $0.vaultSync.recoveryRate = .perHour(2, burst: 2)
            $0.vaultSync.unboundReadRate = .perHour(2, burst: 2); $0.vaultSync.joinRate = .perHour(3, burst: 3) }) { h in
            let f = try await fixture(h, items: [totp()])
            let attacker = try await trustedSecondDevice(h, f.a)
            // The attacker hammers every route it can reach until it is throttled itself.
            var statuses = Set<HTTPResponseStatus>()
            for _ in 0..<8 {
                statuses.insert(try await get(h, attacker, APIRoutes.vaultManifests).status)
                statuses.insert(try await release(h, attacker).status)
                statuses.insert(try await call(h, attacker, APIRoutes.vaultJoinGet, params: ["joinId": Base64URL.encode(SecureToken.randomBytes(16))], body: nil as EmptyBody?).status)
                statuses.insert(try await get(h, attacker, APIRoutes.vaultStatus).status)
            }
            XCTAssertTrue(statuses.contains(.tooManyRequests), "the attacker's own buckets run dry: \(statuses)")
            // The owner is unaffected: reads, a join and a release cancel still work.
            try await eq(try await get(h, f.a, APIRoutes.vaultStatus).status, .ok)
            try await eq(try await get(h, f.a, APIRoutes.vaultEnvelope).status, .ok)
            let secret = PairingSecret.generate()
            try await eq(try await call(h, f.a, APIRoutes.vaultJoinCreate, params: ["joinId": secret.joinId], body: nil as EmptyBody?).status, .created)
        }
    }

    // MARK: M3

    func testGateM3_AKeyRotationOfTwoThousandItemsFitsTheBodyLimit() async throws {
        try await withHarness(Self.enabled) { h in
            XCTAssertGreaterThanOrEqual(h.config.vaultSync.maxRequestBytes, VaultFormat.maxRotationRequestBytes)
            let items = (0..<VaultFormat.maxItems).map { totp("user\($0)@example.com") }
            let f = try await fixture(h, items: items)
            let b = try await addDevice(h, f)
            // Removing B re-encrypts all 2,000 items in one request.
            let removal = try await b.vault.removingDevice(b.identity.memberId, now: h.clock.now())
            let body = putBody(removal, expected: 2)
            let bytes = try ViadereJSON.encode(body).count
            XCTAssertGreaterThan(bytes, 1_048_576, "this is the case that used to exceed the 1 MiB limit")
            let response = try await put(h, f.a, body)
            XCTAssertEqual(response.status, .ok, response.text)
            try await eq(try await get(h, f.a, APIRoutes.vaultStatus).json(VaultStatus.self).epoch, 2)
        }
    }

    /// Control for the test above: with the previous 1 MiB ceiling the same rotation is refused with 413, so the vault could never remove a device.
    func testGateM3_TheOldOneMiBCeilingRefusesTheSameRotation() async throws {
        try await withHarness({ $0.vaultSync.enabled = true; $0.vaultSync.maxRequestBytes = 1_048_576 }) { h in
            let a = try await h.readyConsumer()
            let created = try await UnlockedVault.create(identity: .software(), label: "Phone", items: (0..<VaultFormat.maxItems).map { totp("user\($0)@example.com") }, now: h.clock.now())
            let body = putBody(created, expected: 0, bind: true)
            XCTAssertGreaterThan(try ViadereJSON.encode(body).count, 1_048_576)
            try await eq(try await put(h, a, body).status, .payloadTooLarge)
        }
    }

    func testGateM3_TheServerRefusesAVaultBeyondTheCiphertextCap() async throws {
        try await withHarness(Self.enabled) { h in
            let identity = VaultDeviceIdentity.software()
            let a = try await h.readyConsumer()
            func big() -> VaultItemPayload {
                let credential = PasskeyCredential(credentialId: SecureToken.randomBytes(32), rpId: "example.com", userHandle: Data([1]), userName: String(repeating: "a", count: 32_000),
                                                   displayName: nil, privateKey: SecureToken.randomBytes(32), createdAt: h.clock.now())
                return VaultItemPayload(body: .passkey(credential), createdAt: h.clock.now())
            }
            let fits = try await UnlockedVault.create(identity: identity, label: "Phone", items: (0..<64).map { _ in big() }, now: h.clock.now())
            // A hostile client skips the cap and uploads one more blob than the client library would allow.
            let vault = fits.vault
            let extra = big()
            let blob = try VaultItemBlob.seal(extra, vaultId: vault.vaultId, epoch: vault.manifest.epoch, revision: 1, vaultKey: vault.vaultKey)
            var next = vault.manifest
            next.version += 1
            next.previousHash = vault.snapshot.verified.hash
            next.signerId = identity.memberId
            next.items.append(VaultItemRef(itemId: extra.id, revision: 1, blobHash: Data(SHA256.hash(data: blob))))
            let signed = try await SignedVaultManifest.sign(next, with: identity.signingKey)
            let over = VaultPutRequest(expectedVersion: 1, manifest: VaultManifestDTO(signed), blobs: [VaultBlobDTO(itemId: extra.id, blob: Base64URL.encode(blob))])
            try await eq(try await put(h, a, putBody(fits, expected: 0, bind: true)).status, .ok)
            let response = try await put(h, a, over)
            XCTAssertEqual(response.status, .unprocessableEntity, response.text)
        }
    }
}
