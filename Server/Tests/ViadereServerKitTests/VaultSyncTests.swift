@preconcurrency import Crypto
import Fluent
import Foundation
import NIOHTTP1
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Credential-vault sync (WP5). The server must hold ciphertext and public keys only, verify every write with the same chain rules the
/// clients use, and refuse an attacker who has the account but not a vault key.
final class VaultSyncTests: XCTestCase {
    static let enabled: @Sendable (inout ServerConfig) -> Void = { $0.vaultSync.enabled = true }

    // MARK: Helpers

    func call<Req: Encodable & Sendable, Res: Sendable>(_ h: TestHarness, _ who: TestConsumer, _ route: Endpoint<Req, Res>, params: [String: String] = [:],
                                                         query: [(String, String)] = [], body: Req? = nil) async throws -> HTTPResult {
        let path = try route.path(params, query: query)
        return try await h.signed(who, NIOHTTP1.HTTPMethod(rawValue: route.method.rawValue), path, body: try body.map { try ViadereJSON.encode($0) })
    }

    func get<Res: Sendable>(_ h: TestHarness, _ who: TestConsumer, _ route: Endpoint<EmptyBody, Res>, params: [String: String] = [:],
                            query: [(String, String)] = []) async throws -> HTTPResult {
        try await call(h, who, route, params: params, query: query, body: nil as EmptyBody?)
    }

    func putBody(_ m: VaultMutation, expected: UInt64, bind: Bool = false, join: (id: String, memberId: String)? = nil) -> VaultPutRequest {
        VaultPutRequest(expectedVersion: expected, manifest: VaultManifestDTO(m.delta.manifest),
                        blobs: m.delta.blobs.map { VaultBlobDTO(itemId: $0.key, blob: Base64URL.encode($0.value)) },
                        envelopes: m.delta.envelopes.map { VaultEnvelopeDTO(memberId: $0.key, envelope: Base64URL.encode($0.value)) },
                        bindMemberId: bind ? m.vault.memberId : nil, joinId: join?.id, joinApproval: join == nil ? nil : m.approval.map { Base64URL.encode($0) },
                        joinMemberId: join?.memberId)
    }

    func put(_ h: TestHarness, _ who: TestConsumer, _ body: VaultPutRequest) async throws -> HTTPResult {
        try await Self.rawPut(h, who, body)
    }

    static func rawPut(_ h: TestHarness, _ who: TestConsumer, _ body: VaultPutRequest) async throws -> HTTPResult {
        try await h.signed(who, .PUT, "/v1/vault", body: try ViadereJSON.encode(body))
    }

    func totp(_ name: String = "alice@example.com") -> VaultItemPayload {
        VaultItemPayload(body: .totp(TOTPParameters(secret: Data("12345678901234567890".utf8), issuer: "Example", accountName: name)), createdAt: Date(timeIntervalSince1970: 1_800_000_000))
    }

    func passkey(rp: String = "example.com") throws -> VaultItemPayload {
        let made = try WebAuthnAuthenticator.makeCredential(rpId: rp, userHandle: Data([1, 2, 3]), userName: "alice@example.com", clientDataHash: Data(repeating: 1, count: 32),
                                                            requireUserVerification: true, userVerified: true, backedUp: true, now: Date(timeIntervalSince1970: 1_800_000_000))
        return VaultItemPayload(body: .passkey(made.credential), createdAt: Date(timeIntervalSince1970: 1_800_000_000))
    }

    /// A consumer with a trusted first device and a vault created from it.
    struct Fixture {
        var a: TestConsumer
        var identity: VaultDeviceIdentity
        var recovery: RecoveryKey
        var vault: UnlockedVault
        var createdAt: Date
    }

    func fixture(_ h: TestHarness, items: [VaultItemPayload] = []) async throws -> Fixture {
        let a = try await h.readyConsumer()
        let identity = VaultDeviceIdentity.software()
        let recovery = RecoveryKey.generate()
        let created = try await UnlockedVault.create(identity: identity, label: "Anna's iPhone", recoveryKey: recovery, items: items, now: h.clock.now())
        let response = try await put(h, a, putBody(created, expected: 0, bind: true))
        XCTAssertEqual(response.status, .ok, response.text)
        return Fixture(a: a, identity: identity, recovery: recovery, vault: created.vault, createdAt: h.clock.now())
    }

    /// A second account device that becomes trusted (outside its cool-down).
    func trustedSecondDevice(_ h: TestHarness, _ a: TestConsumer) async throws -> TestConsumer {
        let b = try await h.enrollDevice(a)
        try await trust(h, b)
        return b
    }

    /// Ends the new-device cool-down (as 24 hours passing, or a confirmation from another device, would) without moving the clock, so tokens stay valid.
    func trust(_ h: TestHarness, _ who: TestConsumer) async throws {
        try await DeviceRecord.query(on: h.db).filter(\.$id == who.device!.id.uuid).set(\.$approvalsLockedUntil, to: nil).update()
    }

    func notices(_ h: TestHarness, _ who: TestConsumer) async throws -> [SecurityNotice] {
        try await h.signed(who, .GET, "/v1/security-notices").json([SecurityNotice].self)
    }

    // MARK: Release gate

    func testEveryVaultRouteAnswers404WhileTheGateIsOffButStillRequiresAuthentication() async throws {
        try await withHarness { h in
            XCTAssertFalse(h.config.vaultSync.enabled, "the gate defaults to off")
            let id = Base64URL.encode(SecureToken.randomBytes(16))
            let member = Base64URL.encode(SecureToken.randomBytes(32))
            let consumer = try await h.readyConsumer()
            let vaultRoutes = APIRoutes.all.filter { $0.template.hasPrefix("/v1/vault") }
            XCTAssertGreaterThanOrEqual(vaultRoutes.count, 15)
            for endpoint in vaultRoutes {
                let path = endpoint.template.replacingOccurrences(of: "{joinId}", with: id).replacingOccurrences(of: "{memberId}", with: member).replacingOccurrences(of: "{releaseId}", with: UUID().uuidString.lowercased())
                let method = NIOHTTP1.HTTPMethod(rawValue: endpoint.method.rawValue)
                let body: Data? = endpoint.method == .GET || endpoint.method == .DELETE ? nil : Data("{}".utf8)
                let anonymous = try await h.request(method, path, body: body)
                XCTAssertEqual(anonymous.status, .unauthorized, "\(endpoint.name) needs authentication even while gated")
                let signed = try await h.signed(consumer, method, path, body: body)
                XCTAssertEqual(signed.status, .notFound, "\(endpoint.name) must not exist while VAULT_SYNC_ENABLED is off")
            }
            // A genuine create attempt is not even parsed.
            let created = try await UnlockedVault.create(identity: .software(), label: "x", now: h.clock.now())
            let refused = try await put(h, consumer, putBody(created, expected: 0, bind: true))
            XCTAssertEqual(refused.status, .notFound)
            let rows = try await VaultRecord.query(on: h.db).count()
            XCTAssertEqual(rows, 0)
        }
    }

    func testTheGateParsesFromTheEnvironmentAndDefaultsOff() throws {
        let base = ["ENVIRONMENT": "development"]
        XCTAssertFalse(try ServerConfig.fromEnvironment(base).vaultSync.enabled)
        XCTAssertFalse(try ServerConfig.fromEnvironment(base.merging(["VAULT_SYNC_ENABLED": "1"]) { $1 }).vaultSync.enabled, "only the literal true enables it")
        XCTAssertTrue(try ServerConfig.fromEnvironment(base.merging(["VAULT_SYNC_ENABLED": "true"]) { $1 }).vaultSync.enabled)
        var config = ServerConfig.testing()
        XCTAssertEqual(config.maxBodyBytes(forPath: "/v1/vault"), 64 * 1024)
        config.vaultSync.enabled = true
        XCTAssertEqual(config.maxBodyBytes(forPath: "/v1/vault"), 4 * 1_048_576)
        XCTAssertEqual(config.maxBodyBytes(forPath: "/v1/vault/joins/x"), 4 * 1_048_576)
        XCTAssertGreaterThanOrEqual(config.vaultSync.maxRequestBytes, VaultFormat.maxRotationRequestBytes, "a full rotation must fit the request ceiling")
        XCTAssertEqual(config.maxBodyBytes(forPath: "/v1/vaulty"), 64 * 1024)
        XCTAssertEqual(config.maxBodyBytes(forPath: "/v1/devices"), 64 * 1024)
    }

    // MARK: Ciphertext-only storage

    func testTheServerStoresOnlyCiphertextAndPublicKeys() async throws {
        try await withHarness(Self.enabled) { h in
            let pk = try passkey(rp: "secret-bank.example")
            guard case .passkey(let credential) = pk.body else { return XCTFail() }
            let f = try await fixture(h, items: [pk, totp("alice@secret-mail.example")])
            // Everything the server holds, serialized: no private key, secret, relying party, user name, device name or recovery key.
            var dump = Data()
            for row in try await VaultBlobRecord.query(on: h.db).all() { dump += row.blob; dump += Data(row.blobHash.utf8) }
            for row in try await VaultMemberRecord.query(on: h.db).all() { dump += row.envelope ?? Data(); dump += Data((row.signingKey + row.memberId).utf8) }
            for row in try await VaultManifestRecord.query(on: h.db).all() { dump += Data((row.manifest + row.signature).utf8); dump += Base64URL.decode(row.manifest) ?? Data() }
            let secrets: [Data] = [credential.privateKey, Data("12345678901234567890".utf8), Data("secret-bank.example".utf8), Data("alice@secret-mail.example".utf8),
                                   Data("alice@example.com".utf8), Data("Anna's iPhone".utf8), Data("Example".utf8), credential.credentialId, f.recovery.displayString.data(using: .utf8)!,
                                   Data(Base32.encode(Data("12345678901234567890".utf8)).utf8)]
            for secret in secrets { XCTAssertNil(dump.range(of: secret), "plaintext found in server storage") }
            XCTAssertGreaterThan(dump.count, 1000)
            // The audit log records the event, never content.
            let audit = try await AuditEventRecord.query(on: h.db).filter(\.$action == "vault.created").all()
            XCTAssertEqual(audit.count, 1)
            XCTAssertFalse(audit[0].metadataJSON.contains("secret-bank"))
        }
    }

    func testStatusBindingAndRoundTripOfCiphertext() async throws {
        try await withHarness(Self.enabled) { h in
            let none = try await h.readyConsumer()
            let empty = try await get(h, none, APIRoutes.vaultStatus).json(VaultStatus.self)
            XCTAssertFalse(empty.exists)

            let item = totp()
            let f = try await fixture(h, items: [item])
            let status = try await get(h, f.a, APIRoutes.vaultStatus).json(VaultStatus.self)
            XCTAssertTrue(status.exists && status.bound)
            XCTAssertEqual(status.version, 1)
            XCTAssertEqual(status.memberId, f.identity.memberId)
            XCTAssertEqual(status.deviceCount, 1)
            XCTAssertTrue(status.recoveryConfigured)

            // The bound device reads back its envelope and the blobs, and opens the vault from them.
            let envelope = try await get(h, f.a, APIRoutes.vaultEnvelope).json(VaultEnvelopeResponse.self)
            let blobs = try await call(h, f.a, APIRoutes.vaultBlobs, body: VaultBlobsRequest(itemIds: [item.id])).json(VaultBlobsResponse.self)
            let chain = try await get(h, f.a, APIRoutes.vaultManifests).json(VaultManifestsResponse.self)
            let head = try VaultChainVerifier.verifyChain(chain.manifests.compactMap(\.signed), trusted: nil)
            let snapshot = VaultSnapshot(verified: head, blobs: Dictionary(uniqueKeysWithValues: blobs.blobs.map { ($0.itemId, Base64URL.decode($0.blob)!) }),
                                         envelopes: [envelope.memberId: Base64URL.decode(envelope.envelope)!])
            XCTAssertEqual(try UnlockedVault.open(snapshot, identity: f.identity).items(), [item])
        }
    }

    // MARK: Compare-and-swap, chain rules

    func testWritesAreCompareAndSwapOnTheVersionAndOldOrForkedManifestsAreRefused() async throws {
        try await withHarness(Self.enabled) { h in
            let f = try await fixture(h, items: [totp()])
            let v2 = try await f.vault.applying(upserts: [totp("two")], now: h.clock.now())
            // A stale expectation is a conflict that names the current version.
            let stale = try await put(h, f.a, putBody(v2, expected: 5))
            XCTAssertEqual(stale.status, .conflict)
            let ok = try await put(h, f.a, putBody(v2, expected: 1))
            XCTAssertEqual(ok.status, .ok, ok.text)
            // Replaying the same write loses (the vault is at version 2 now).
            let replay = try await put(h, f.a, putBody(v2, expected: 1))
            XCTAssertEqual(replay.status, .conflict)
            XCTAssertEqual(try replay.json(APIErrorResponse.self).error.details?["currentVersion"], "2")
            // A fork: another version 2 from version 1.
            let fork = try await f.vault.applying(upserts: [totp("fork")], now: h.clock.now())
            let forked = try await put(h, f.a, putBody(fork, expected: 2))
            XCTAssertEqual(forked.status, .unprocessableEntity, "a manifest that does not chain from the stored head is refused")
            // Rolling back: re-submitting version 1's manifest at expected 2.
            let rollback = try await put(h, f.a, VaultPutRequest(expectedVersion: 2, manifest: VaultManifestDTO(f.vault.snapshot.verified.signed)))
            XCTAssertEqual(rollback.status, .unprocessableEntity)
            let status = try await get(h, f.a, APIRoutes.vaultStatus).json(VaultStatus.self)
            XCTAssertEqual(status.version, 2)
        }
    }

    func testConcurrentWritersCannotBothWin() async throws {
        try await withHarness(Self.enabled) { h in
            let f = try await fixture(h, items: [totp()])
            let one = try await f.vault.applying(upserts: [totp("one")], now: h.clock.now())
            let two = try await f.vault.applying(upserts: [totp("two")], now: h.clock.now())
            let bodyOne = putBody(one, expected: 1), bodyTwo = putBody(two, expected: 1)
            async let first = Self.rawPut(h, f.a, bodyOne)
            async let second = Self.rawPut(h, f.a, bodyTwo)
            let results = try await [first.status, second.status]
            XCTAssertEqual(results.filter { $0 == .ok }.count, 1, "\(results)")
            XCTAssertTrue(results.contains(.conflict) || results.contains(.unprocessableEntity))
            let versions = try await VaultManifestRecord.query(on: h.db).all().map(\.version).sorted()
            XCTAssertEqual(versions, [1, 2])
        }
    }

    func testBlobsAndEnvelopesMustMatchTheSignedManifest() async throws {
        try await withHarness(Self.enabled) { h in
            let f = try await fixture(h, items: [totp()])
            let good = try await f.vault.applying(upserts: [totp("new")], now: h.clock.now())
            var tampered = putBody(good, expected: 1)
            tampered.blobs[0].blob = Base64URL.encode(SecureToken.randomBytes(300))
            let mismatch = try await put(h, f.a, tampered)
            XCTAssertEqual(mismatch.status, .unprocessableEntity)
            var missing = putBody(good, expected: 1)
            missing.blobs = []
            let absent = try await put(h, f.a, missing)
            XCTAssertEqual(absent.status, .unprocessableEntity)
            var extra = putBody(good, expected: 1)
            extra.blobs.append(VaultBlobDTO(itemId: UUID(), blob: Base64URL.encode(SecureToken.randomBytes(100))))
            let unlisted = try await put(h, f.a, extra)
            XCTAssertEqual(unlisted.status, .unprocessableEntity)
            var oversized = putBody(good, expected: 1)
            oversized.blobs[0].blob = Base64URL.encode(SecureToken.randomBytes(VaultFormat.maxItemBlobBytes + 1))
            try await eq(try await put(h, f.a, oversized).status, .unprocessableEntity)
            var notBase64 = putBody(good, expected: 1)
            notBase64.blobs[0].blob = "not base64url!"
            try await eq(try await put(h, f.a, notBase64).status, .unprocessableEntity)
            // Nothing changed.
            try await eq(try await get(h, f.a, APIRoutes.vaultStatus).json(VaultStatus.self).version, 1)
            try await eq(try await put(h, f.a, putBody(good, expected: 1)).status, .ok)
            // A rotation must carry a fresh envelope for each member: omitting one is refused.
            let rotatedFromCurrent = try await good.vault.settingRecoveryKey(RecoveryKey.generate(), rotateKey: true, now: h.clock.now())
            var noEnvelopes = putBody(rotatedFromCurrent, expected: 2)
            noEnvelopes.envelopes = []
            try await eq(try await put(h, f.a, noEnvelopes).status, .unprocessableEntity)
            try await eq(try await put(h, f.a, putBody(rotatedFromCurrent, expected: 2)).status, .ok)
        }
    }

    func testBodyLimitAppliesWhileEnabledAndOversizedRequestsAreRefused() async throws {
        try await withHarness(Self.enabled) { h in
            let f = try await fixture(h)
            let huge = Data(repeating: 0x61, count: 4 * 1_048_576 + 10)
            let response = try await h.signed(f.a, .PUT, "/v1/vault", body: huge)
            XCTAssertEqual(response.status, .payloadTooLarge)
        }
    }

    // MARK: An attacker who has the account but no vault key

    func testAnAccountOnlyAttackerCannotWriteReadOrBindWithoutAVaultKey() async throws {
        try await withHarness(Self.enabled) { h in
            let f = try await fixture(h, items: [totp()])
            // The attacker enrolled a device with a stolen passkey and waited out the cool-down: a trusted account device, unbound to the vault.
            let attacker = try await trustedSecondDevice(h, f.a)
            let status = try await get(h, attacker, APIRoutes.vaultStatus).json(VaultStatus.self)
            XCTAssertTrue(status.exists && !status.bound)
            // Cannot read the device's envelope or write.
            try await eq(try await get(h, attacker, APIRoutes.vaultEnvelope).status, .forbidden)
            let evilIdentity = VaultDeviceIdentity.software()
            let evilVault = try await UnlockedVault.create(identity: evilIdentity, label: "evil", now: h.clock.now())
            try await eq(try await put(h, attacker, putBody(evilVault, expected: 0, bind: true)).status, .conflict, "cannot create a second vault")
            // Cannot extend the real chain without a member key, however it signs.
            var forged = f.vault.manifest
            forged.version = 2
            forged.previousHash = f.vault.snapshot.verified.hash
            forged.signerId = evilIdentity.memberId
            forged.members.append(VaultMember(role: .device, signingKey: evilIdentity.signingPublicKey, agreementKey: evilIdentity.agreementPublicKey,
                                              envelopeHash: Data(repeating: 1, count: 32), addedAt: 1, sealedLabel: Data(repeating: 2, count: 40)))
            let signed = try await SignedVaultManifest.sign(forged, with: evilIdentity.signingKey)
            let forgedPut = VaultPutRequest(expectedVersion: 1, manifest: VaultManifestDTO(signed), envelopes: [VaultEnvelopeDTO(memberId: evilIdentity.memberId, envelope: Base64URL.encode(Data(repeating: 1, count: VaultFormat.envelopeLength)))],
                                            bindMemberId: evilIdentity.memberId)
            try await eq(try await put(h, attacker, forgedPut).status, .unprocessableEntity)
            // Claiming a join that nobody approved binds nothing.
            let joinId = Base64URL.encode(SecureToken.randomBytes(16))
            try await eq(try await call(h, attacker, APIRoutes.vaultJoinRequest, params: ["joinId": joinId], body: VaultJoinRequestBody(request: Base64URL.encode(SecureToken.randomBytes(80)))).status, .notFound)
            // Reads nothing at all until a recovery release has held for 72 hours (see VaultGateTests); then only ciphertext and public keys.
            try await eq(try await get(h, attacker, APIRoutes.vaultManifests).status, .forbidden)
            try await eq(try await call(h, attacker, APIRoutes.vaultBlobs, body: VaultBlobsRequest(itemIds: f.vault.manifest.items.map(\.itemId))).status, .forbidden)
            try await eq(try await get(h, attacker, APIRoutes.vaultRecoveryEnvelope).status, .forbidden)
            try await openWindow(h, attacker)
            let chain = try await get(h, attacker, APIRoutes.vaultManifests).json(VaultManifestsResponse.self)
            XCTAssertEqual(chain.manifests.count, 1)
            let blobs = try await call(h, attacker, APIRoutes.vaultBlobs, body: VaultBlobsRequest(itemIds: f.vault.manifest.items.map(\.itemId))).json(VaultBlobsResponse.self)
            XCTAssertEqual(blobs.blobs.count, 1)
            // The envelope that exists for the recovery member opens only with the recovery key.
            let recovery = try await get(h, attacker, APIRoutes.vaultRecoveryEnvelope).json(VaultEnvelopeResponse.self)
            let snapshot = VaultSnapshot(verified: f.vault.snapshot.verified, blobs: [:], envelopes: [recovery.memberId: Base64URL.decode(recovery.envelope)!])
            XCTAssertThrowsError(try UnlockedVault.open(snapshot, identity: evilIdentity))
            // The real device is unaffected.
            try await eq(try await get(h, f.a, APIRoutes.vaultStatus).json(VaultStatus.self).version, 1)
        }
    }

    func testAFreshlyEnrolledDeviceStillInItsCoolDownCannotCreateOrRead() async throws {
        try await withHarness(Self.enabled) { h in
            let f = try await fixture(h, items: [totp()])
            let cooling = try await h.enrollDevice(f.a)
            try await eq(try await get(h, cooling, APIRoutes.vaultRecoveryEnvelope).status, .forbidden)
            try await eq(try await get(h, cooling, APIRoutes.vaultManifests).status, .forbidden)
            try await eq(try await get(h, cooling, APIRoutes.vaultDevices).status, .forbidden)
            try await eq(try await call(h, cooling, APIRoutes.vaultBlobs, body: VaultBlobsRequest(itemIds: [])).status, .forbidden)
        }
    }

    func testCreatingAVaultNeedsATrustedDevice() async throws {
        try await withHarness(Self.enabled) { h in
            let a = try await h.readyConsumer()
            let cooling = try await h.enrollDevice(a)
            let created = try await UnlockedVault.create(identity: .software(), label: "x", now: h.clock.now())
            try await eq(try await put(h, cooling, putBody(created, expected: 0, bind: true)).status, .forbidden)
        }
    }

    // MARK: Adding a device (join), removal, notices

    func testAddingADeviceNeedsApprovalFromAVaultDeviceAndNotifiesTheOthers() async throws {
        try await withHarness(Self.enabled) { h in
            let item = totp()
            let f = try await fixture(h, items: [item])
            let b = try await h.enrollDevice(f.a)           // the new phone (cooling down: it needs no trust to ask)
            let bIdentity = VaultDeviceIdentity.software()

            // A opens a join and shows the pairing code; B types it and sends its sealed keys.
            let secret = PairingSecret.generate()
            let created = try await call(h, f.a, APIRoutes.vaultJoinCreate, params: ["joinId": secret.joinId], body: nil as EmptyBody?)
            XCTAssertEqual(created.status, .created, created.text)
            let sealed = try JoinRequest.make(for: bIdentity, label: "Ben's iPad").sealed(with: secret)
            let submitted = try await call(h, b, APIRoutes.vaultJoinRequest, params: ["joinId": secret.joinId], body: VaultJoinRequestBody(request: Base64URL.encode(sealed)))
            XCTAssertEqual(submitted.status, .ok, submitted.text)
            // One request per join: a second attempt (a guess, or the server being replayed) is refused.
            let second = try await call(h, f.a, APIRoutes.vaultJoinRequest, params: ["joinId": secret.joinId], body: VaultJoinRequestBody(request: Base64URL.encode(sealed)))
            XCTAssertEqual(second.status, .conflict)

            // A reads the request (the server only ever held ciphertext), decrypts it with the secret and approves.
            let state = try await get(h, f.a, APIRoutes.vaultJoinGet, params: ["joinId": secret.joinId]).json(VaultJoinState.self)
            let request = try JoinRequest.open(Base64URL.decode(try XCTUnwrap(state.request))!, with: secret)
            XCTAssertEqual(request.label, "Ben's iPad")
            let approval = try await f.vault.approvingJoin(request, secret: secret, now: h.clock.now())
            // Without a join, an extra device cannot be added.
            try await eq(try await put(h, f.a, putBody(approval, expected: 1)).status, .unprocessableEntity)
            // With the wrong member named, the join is not valid.
            try await eq(try await put(h, f.a, putBody(approval, expected: 1, join: (secret.joinId, f.identity.memberId))).status, .unprocessableEntity)
            // B cannot approve itself.
            let selfApproved = try await put(h, b, putBody(approval, expected: 1, join: (secret.joinId, bIdentity.memberId)))
            XCTAssertEqual(selfApproved.status, .forbidden)
            try await eq(try await put(h, f.a, putBody(approval, expected: 1, join: (secret.joinId, bIdentity.memberId))).status, .ok)

            // B sees the approval, is bound to its member, learns the manifest through the approval, and opens the vault.
            let done = try await get(h, b, APIRoutes.vaultJoinGet, params: ["joinId": secret.joinId]).json(VaultJoinState.self)
            XCTAssertEqual(done.approvedMemberId, bIdentity.memberId)
            XCTAssertEqual(done.approvedVersion, 2)
            let bStatus = try await get(h, b, APIRoutes.vaultStatus).json(VaultStatus.self)
            XCTAssertTrue(bStatus.bound)
            let envelope = try await get(h, b, APIRoutes.vaultEnvelope).json(VaultEnvelopeResponse.self)
            let manifests = try await get(h, b, APIRoutes.vaultManifests, query: [("after", "1")]).json(VaultManifestsResponse.self)
            let joined = try UnlockedVault.acceptingJoin(approval: Base64URL.decode(try XCTUnwrap(done.approval))!, secret: secret,
                                                         manifest: try XCTUnwrap(manifests.manifests.first?.signed), envelope: Base64URL.decode(envelope.envelope)!, identity: bIdentity)
            XCTAssertEqual(joined.vaultKey.keyCheck(epoch: 1), f.vault.vaultKey.keyCheck(epoch: 1))
            XCTAssertEqual(joined.label(of: bIdentity.memberId), "Ben's iPad")

            // The other devices were told (an in-app notice and the stored audit record).
            let seenByA = try await notices(h, f.a)
            XCTAssertFalse(seenByA.contains { $0.topic == .vaultDeviceAdded }, "the approving device caused it")
            let seenByB = try await notices(h, b)
            XCTAssertTrue(seenByB.contains { $0.topic == .vaultDeviceAdded })
            let audit = try await AuditEventRecord.query(on: h.db).filter(\.$action == "vault.updated").all()
            XCTAssertEqual(audit.count, 1)

            // Devices are listed with their (sealed) names left to the client.
            let devices = try await get(h, f.a, APIRoutes.vaultDevices).json([VaultDeviceInfo].self)
            XCTAssertEqual(Set(devices.map(\.memberId)).count, 3)
            XCTAssertEqual(devices.filter { $0.role == "device" }.count, 2)
            XCTAssertTrue(devices.filter { $0.role == "device" }.allSatisfy(\.accountDeviceActive))
        }
    }

    func testJoinsExpireAreScopedToTheAccountAndLimited() async throws {
        try await withHarness(Self.enabled) { h in
            let f = try await fixture(h)
            let other = try await h.readyConsumer(name: "Someone Else")
            let secret = PairingSecret.generate()
            try await eq(try await call(h, f.a, APIRoutes.vaultJoinCreate, params: ["joinId": secret.joinId], body: nil as EmptyBody?).status, .created)
            // Another account cannot see or use it.
            try await eq(try await get(h, other, APIRoutes.vaultJoinGet, params: ["joinId": secret.joinId]).status, .notFound)
            try await eq(try await call(h, other, APIRoutes.vaultJoinRequest, params: ["joinId": secret.joinId], body: VaultJoinRequestBody(request: Base64URL.encode(SecureToken.randomBytes(80)))).status, .notFound)
            // Malformed identifiers.
            try await eq(try await call(h, f.a, APIRoutes.vaultJoinCreate, params: ["joinId": "short"], body: nil as EmptyBody?).status, .unprocessableEntity)
            // Open joins are capped.
            for _ in 0..<2 { try await eq(try await call(h, f.a, APIRoutes.vaultJoinCreate, params: ["joinId": PairingSecret.generate().joinId], body: nil as EmptyBody?).status, .created) }
            try await eq(try await call(h, f.a, APIRoutes.vaultJoinCreate, params: ["joinId": PairingSecret.generate().joinId], body: nil as EmptyBody?).status, .conflict)
            // They expire.
            h.clock.advance(by: 11 * 60)
            try await eq(try await get(h, f.a, APIRoutes.vaultJoinGet, params: ["joinId": secret.joinId]).status, .gone)
            // And can be cancelled.
            let fresh = PairingSecret.generate()
            try await eq(try await call(h, f.a, APIRoutes.vaultJoinCreate, params: ["joinId": fresh.joinId], body: nil as EmptyBody?).status, .created)
            try await eq(try await get(h, f.a, APIRoutes.vaultJoinCancel, params: ["joinId": fresh.joinId]).status, .ok)
        }
    }

    func testRemovingADeviceRotatesTheKeyAndEndsItsAccessAtOnce() async throws {
        try await withHarness(Self.enabled) { h in
            let item = totp()
            let f = try await fixture(h, items: [item])
            let b = try await h.enrollDevice(f.a)
            let bIdentity = VaultDeviceIdentity.software()
            let secret = PairingSecret.generate()
            _ = try await call(h, f.a, APIRoutes.vaultJoinCreate, params: ["joinId": secret.joinId], body: nil as EmptyBody?)
            _ = try await call(h, b, APIRoutes.vaultJoinRequest, params: ["joinId": secret.joinId], body: VaultJoinRequestBody(request: Base64URL.encode(try JoinRequest.make(for: bIdentity, label: "iPad").sealed(with: secret))))
            let approval = try await f.vault.approvingJoin(JoinRequest.make(for: bIdentity, label: "iPad"), secret: secret, now: h.clock.now())
            try await eq(try await put(h, f.a, putBody(approval, expected: 1, join: (secret.joinId, bIdentity.memberId))).status, .ok)
            try await eq(try await get(h, b, APIRoutes.vaultEnvelope).status, .ok)

            let removal = try await approval.vault.removingDevice(bIdentity.memberId, now: h.clock.now())
            let response = try await put(h, f.a, putBody(removal, expected: 2))
            XCTAssertEqual(response.status, .ok, response.text)
            // B is cut off immediately: no envelope, no blobs, no writes, however it signs.
            try await eq(try await get(h, b, APIRoutes.vaultEnvelope).status, .forbidden)
            try await eq(try await call(h, b, APIRoutes.vaultBlobs, body: VaultBlobsRequest(itemIds: [item.id])).status, .forbidden)
            let bAttempt = try UnlockedVault.open(approval.vault.snapshot, identity: bIdentity)
            let sneaky = try await bAttempt.applying(upserts: [totp("x")], now: h.clock.now())
            let sneakyStatus = try await put(h, b, putBody(sneaky, expected: 3)).status
            XCTAssertNotEqual(sneakyStatus, .ok)
            // The stored envelope is gone, the key epoch advanced, the blob was re-encrypted.
            let members = try await VaultMemberRecord.query(on: h.db).all()
            XCTAssertNil(members.first { $0.memberId == bIdentity.memberId }?.envelope)
            XCTAssertNotNil(members.first { $0.memberId == bIdentity.memberId }?.removedAt)
            try await eq(try await get(h, f.a, APIRoutes.vaultStatus).json(VaultStatus.self).epoch, 2)
            try await eq(try await notices(h, b).contains { $0.topic == .vaultDeviceRemoved }, true)
        }
    }

    func testRemovingADeviceByEndpointEndsServerAccessAndNeedsTrust() async throws {
        try await withHarness(Self.enabled) { h in
            let f = try await fixture(h)
            let b = try await h.enrollDevice(f.a)
            let bIdentity = VaultDeviceIdentity.software()
            let secret = PairingSecret.generate()
            _ = try await call(h, f.a, APIRoutes.vaultJoinCreate, params: ["joinId": secret.joinId], body: nil as EmptyBody?)
            _ = try await call(h, b, APIRoutes.vaultJoinRequest, params: ["joinId": secret.joinId], body: VaultJoinRequestBody(request: Base64URL.encode(try JoinRequest.make(for: bIdentity, label: "iPad").sealed(with: secret))))
            let approval = try await f.vault.approvingJoin(JoinRequest.make(for: bIdentity, label: "iPad"), secret: secret, now: h.clock.now())
            try await eq(try await put(h, f.a, putBody(approval, expected: 1, join: (secret.joinId, bIdentity.memberId))).status, .ok)
            // B is cooling down: it cannot remove A.
            try await eq(try await call(h, b, APIRoutes.vaultDeviceRemove, params: ["memberId": f.identity.memberId], body: nil as EmptyBody?).status, .forbidden)
            // A cannot remove itself, nor an unknown member.
            try await eq(try await call(h, f.a, APIRoutes.vaultDeviceRemove, params: ["memberId": f.identity.memberId], body: nil as EmptyBody?).status, .notFound)
            try await eq(try await call(h, f.a, APIRoutes.vaultDeviceRemove, params: ["memberId": Base64URL.encode(SecureToken.randomBytes(32))], body: nil as EmptyBody?).status, .notFound)
            try await eq(try await call(h, f.a, APIRoutes.vaultDeviceRemove, params: ["memberId": bIdentity.memberId], body: nil as EmptyBody?).status, .ok)
            try await eq(try await get(h, b, APIRoutes.vaultEnvelope).status, .forbidden)
            try await eq(try await notices(h, b).contains { $0.topic == .vaultDeviceRemoved }, true)
        }
    }

    // MARK: Recovery is separate from account recovery

    func testAccountAccessAloneNeverRestoresTheVaultButTheRecoveryKeyDoes() async throws {
        try await withHarness(Self.enabled) { h in
            let item = try passkey()
            let f = try await fixture(h, items: [item, totp()])
            // The account is recovered: a brand-new device, trusted after its cool-down. It can read all the server holds.
            let recovered = try await trustedSecondDevice(h, f.a)
            try await openWindow(h, recovered)
            let chainResponse = try await get(h, recovered, APIRoutes.vaultManifests).json(VaultManifestsResponse.self)
            let chain = chainResponse.manifests.compactMap(\.signed)
            let recoveryEnvelope = try await get(h, recovered, APIRoutes.vaultRecoveryEnvelope).json(VaultEnvelopeResponse.self)
            let blobs = try await call(h, recovered, APIRoutes.vaultBlobs, body: VaultBlobsRequest(itemIds: f.vault.manifest.items.map(\.itemId))).json(VaultBlobsResponse.self)
            let newDevice = VaultDeviceIdentity.software()
            // ...but nothing in it opens without the recovery key, and the account cannot sign for the vault.
            let guess = RecoveryKey.generate()
            XCTAssertThrowsError(try UnlockedVault.authenticateChain(chain, recoveryKey: guess))
            try await eq(try await get(h, recovered, APIRoutes.vaultEnvelope).status, .forbidden)
            XCTAssertThrowsError(try UnlockedVault.open(VaultSnapshot(verified: try VaultChainVerifier.restore(chain[0]), blobs: [:], envelopes: [recoveryEnvelope.memberId: Base64URL.decode(recoveryEnvelope.envelope)!]), identity: newDevice))

            // With the recovery key (typed from the paper it was written on):
            let typed = try RecoveryKey(parsing: f.recovery.displayString)
            let head = try UnlockedVault.authenticateChain(chain, recoveryKey: typed)
            var snapshot = VaultSnapshot(verified: head, blobs: Dictionary(uniqueKeysWithValues: blobs.blobs.map { ($0.itemId, Base64URL.decode($0.blob)!) }),
                                         envelopes: [recoveryEnvelope.memberId: Base64URL.decode(recoveryEnvelope.envelope)!])
            try snapshot.validateContents()
            let newRecovery = RecoveryKey.generate()
            let restored = try await UnlockedVault.recovering(snapshot, recoveryKey: typed, newRecoveryKey: newRecovery, newDevice: newDevice, label: "New phone", now: h.clock.now())
            // The restoring device must bind to itself, and the old (lost) device is removed by the rotation.
            try await eq(try await put(h, recovered, putBody(restored, expected: 1)).status, .unprocessableEntity)
            let put = try await put(h, recovered, putBody(restored, expected: 1, bind: true))
            XCTAssertEqual(put.status, .ok, put.text)
            try await eq(try await get(h, recovered, APIRoutes.vaultEnvelope).status, .ok)
            try await eq(try await get(h, f.a, APIRoutes.vaultEnvelope).status, .forbidden, "the lost phone is out")
            XCTAssertEqual(try restored.vault.items().count, 2)
            try await eq(try await get(h, recovered, APIRoutes.vaultStatus).json(VaultStatus.self).epoch, 2)
            // Fetching the recovery envelope was audited; the recovery restore too.
            let audit = try await AuditEventRecord.query(on: h.db).all().map(\.action)
            XCTAssertTrue(audit.contains("vault.recovery_envelope_fetched"))
            snapshot = restored.vault.snapshot
            XCTAssertEqual(snapshot.manifest.version, 2)
            // The old recovery key no longer authenticates the new chain.
            let newChain = try await get(h, recovered, APIRoutes.vaultManifests).json(VaultManifestsResponse.self).manifests.compactMap(\.signed)
            XCTAssertThrowsError(try UnlockedVault.authenticateChain(newChain, recoveryKey: typed))
            XCTAssertNoThrow(try UnlockedVault.authenticateChain(newChain, recoveryKey: newRecovery))
        }
    }

    func testRecoveryEnvelopeFetchesAreRateLimited() async throws {
        try await withHarness({ $0.vaultSync.enabled = true; $0.vaultSync.recoveryRate = .perHour(2, burst: 2) }) { h in
            let f = try await fixture(h)
            let requester = try await trustedSecondDevice(h, f.a)
            try await openWindow(h, requester)
            try await eq(try await get(h, requester, APIRoutes.vaultRecoveryEnvelope).status, .ok)
            try await eq(try await get(h, requester, APIRoutes.vaultRecoveryEnvelope).status, .ok)
            let limited = try await get(h, requester, APIRoutes.vaultRecoveryEnvelope)
            XCTAssertEqual(limited.status, .tooManyRequests)
            XCTAssertNotNil(limited.headers.first(name: "Retry-After"))
        }
    }

    func testWritesAreRateLimited() async throws {
        try await withHarness({ $0.vaultSync.enabled = true; $0.vaultSync.writeRate = .perHour(3, burst: 3) }) { h in
            let f = try await fixture(h)
            var vault = f.vault
            var statuses: [HTTPResponseStatus] = []
            for index in 0..<4 {
                let next = try await vault.applying(upserts: [totp("n\(index)")], now: h.clock.now())
                let response = try await put(h, f.a, putBody(next, expected: UInt64(index + 1)))
                statuses.append(response.status)
                if response.status == .ok { vault = next.vault }
            }
            XCTAssertEqual(statuses.last, .tooManyRequests, "\(statuses)")
        }
    }

    // MARK: Deletion

    func testDeletingTheVaultErasesEveryRowAndNotifiesOtherDevices() async throws {
        try await withHarness(Self.enabled) { h in
            let f = try await fixture(h, items: [totp(), try passkey()])
            let b = try await h.enrollDevice(f.a)
            try await eq(try await call(h, b, APIRoutes.vaultDelete, body: nil as EmptyBody?).status, .forbidden, "an unbound, cooling device cannot")
            try await eq(try await call(h, f.a, APIRoutes.vaultDelete, body: nil as EmptyBody?).status, .ok)
            for count in try await [VaultRecord.query(on: h.db).count(), VaultBlobRecord.query(on: h.db).count(), VaultMemberRecord.query(on: h.db).count(),
                                    VaultManifestRecord.query(on: h.db).count(), VaultJoinRecord.query(on: h.db).count()] { XCTAssertEqual(count, 0) }
            try await eq(try await get(h, f.a, APIRoutes.vaultStatus).json(VaultStatus.self).exists, false)
            try await eq(try await notices(h, b).contains { $0.topic == .vaultDeleted }, true)
        }
    }

    func testAccountDeletionWipesTheVaultAndLeavesOthersAlone() async throws {
        try await withHarness(Self.enabled) { h in
            let mine = try await fixture(h, items: [totp()])
            let theirs = try await fixture(h, items: [totp("other")])
            try await eq(try await h.signed(mine.a, .DELETE, "/v1/account").status, .ok)
            let vaults = try await VaultRecord.query(on: h.db).all()
            XCTAssertEqual(vaults.map { $0.consumerId }, [theirs.a.id.uuid])
            try await eq(try await VaultBlobRecord.query(on: h.db).count(), 1)
            try await eq(try await VaultMemberRecord.query(on: h.db).count(), 2, "device + recovery member of the other account")
            try await eq(try await VaultManifestRecord.query(on: h.db).count(), 1)
        }
    }
}
