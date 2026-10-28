import Crypto
import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

/// One simulated phone: its own store, keys and engine, talking to a shared in-memory vault server.
private struct Phone {
    let store: any VaultLocalStore
    let keys: SoftwareVaultKeyProvider
    let anchors: InMemorySecretStore
    let engine: VaultEngine
    let api: InMemoryVaultSyncAPI?

    init(server: InMemoryVaultServer?, label: String = "Phone", store: (any VaultLocalStore)? = nil, clock: @escaping @Sendable () -> Date = { Date(timeIntervalSince1970: 1_800_000_000) }) {
        self.store = store ?? InMemoryVaultLocalStore()
        keys = SoftwareVaultKeyProvider()
        anchors = InMemorySecretStore()
        api = server.map { InMemoryVaultSyncAPI(server: $0) }
        engine = VaultEngine(store: self.store, keys: keys, api: api, anchors: anchors, deviceLabel: label, clock: clock)
    }
}

private let secretBase32 = Base32.encode(Data("12345678901234567890".utf8))
private func uri(_ name: String) -> String { "otpauth://totp/Example:\(name)?secret=\(secretBase32)&issuer=Example" }

@Suite("Vault engine: local")
struct VaultEngineLocalTests {
    @Test func phasesAndLocking() async throws {
        let phone = Phone(server: nil)
        #expect(try await phone.engine.phase() == .empty)
        await #expect(throws: VaultEngineError.notCreated) { try await phone.engine.unlock() }
        try await phone.engine.create()
        #expect(try await phone.engine.phase() == .unlocked)
        await #expect(throws: VaultEngineError.alreadyExists) { try await phone.engine.create() }
        await phone.engine.lock()
        #expect(try await phone.engine.phase() == .locked)
        await #expect(throws: VaultEngineError.locked) { _ = try await phone.engine.items() }
        try await phone.engine.unlock()
        #expect(try await phone.engine.phase() == .unlocked)
        // The device key is gone (restored from a backup to another phone, say): the vault cannot be opened.
        try await phone.keys.deleteIdentity()
        await phone.engine.lock()
        await #expect(throws: VaultEngineError.deviceKeyMissing) { try await phone.engine.unlock() }
    }

    @Test func totpItemsAndCodes() async throws {
        let phone = Phone(server: nil)
        try await phone.engine.create()
        let id = try await phone.engine.addTOTP(uri: uri("alice"))
        #expect(try await phone.engine.oneTimeCode(for: id, at: Date(timeIntervalSince1970: 59)) == "287082")
        #expect(try await phone.engine.items().count == 1)
        await #expect(throws: VaultEngineError.invalidItem) { try await phone.engine.addTOTP(uri: "otpauth://hotp/x?secret=\(secretBase32)") }
        await #expect(throws: VaultEngineError.invalidItem) { try await phone.engine.addTOTP(TOTPParameters(secret: Data([1]), accountName: "short")) }
        try await phone.engine.deleteItem(id)
        #expect(try await phone.engine.items().isEmpty)
        await #expect(throws: VaultEngineError.itemNotFound) { try await phone.engine.deleteItem(id) }
        // Locked: no codes.
        await phone.engine.lock()
        await #expect(throws: VaultEngineError.locked) { _ = try await phone.engine.oneTimeCode(for: id) }
    }

    @Test func liveCodesFollowTheClockChangesAndLocking() async throws {
        let phone = Phone(server: nil)
        try await phone.engine.create()
        let first = try await phone.engine.addTOTP(uri: uri("one"))
        let codes = try await phone.engine.liveCodes(at: Date(timeIntervalSince1970: 59))
        #expect(codes[first]?.code == "287082" && codes[first]?.secondsRemaining == 1 && codes[first]?.period == 30)
        #expect(try await phone.engine.liveCodes(at: Date(timeIntervalSince1970: 60))[first]?.secondsRemaining == 30)
        // A new item appears at the next tick; a deleted one disappears.
        let second = try await phone.engine.addTOTP(uri: uri("two"))
        #expect(try await phone.engine.liveCodes(at: Date(timeIntervalSince1970: 59)).keys.sorted { $0.uuidString < $1.uuidString } == [first, second].sorted { $0.uuidString < $1.uuidString })
        try await phone.engine.deleteItem(first)
        #expect(try await phone.engine.liveCodes(at: Date(timeIntervalSince1970: 59)).keys.map { $0 } == [second])
        // Locked: nothing, and the cache is gone (unlocking decrypts again).
        await phone.engine.lock()
        await #expect(throws: VaultEngineError.locked) { _ = try await phone.engine.liveCodes() }
        try await phone.engine.unlock()
        #expect(try await phone.engine.liveCodes(at: Date(timeIntervalSince1970: 59))[second]?.code == "287082")
    }

    @Test func passkeysAreCreatedAndAssertedThroughTheEngine() async throws {
        let phone = Phone(server: nil)
        try await phone.engine.create()
        let hash = Data(SHA256.hash(data: Data("cd".utf8)))
        let request = PasskeyRegistrationRequest(rpId: "example.com", userName: "alice", displayName: "Alice", userHandle: Data([1, 2]), clientDataHash: hash)
        // Registering without user verification when the RP requires it creates nothing.
        await #expect(throws: WebAuthnError.userVerificationRequired) { _ = try await phone.engine.registerPasskey(request, userVerified: false) }
        #expect(try await phone.engine.items().isEmpty)
        let created = try await phone.engine.registerPasskey(request, userVerified: true)
        #expect(try await phone.engine.passkeys(for: "example.com").count == 1)
        // The same user cannot be excluded-and-recreated.
        let again = PasskeyRegistrationRequest(rpId: "example.com", userName: "alice", userHandle: Data([1, 2]), clientDataHash: hash, excludedCredentialIds: [created.credential.credentialId])
        await #expect(throws: WebAuthnError.credentialExcluded) { _ = try await phone.engine.registerPasskey(again, userVerified: true) }
        let assertion = try await phone.engine.assertPasskey(credentialId: created.credential.credentialId, rpId: "example.com", clientDataHash: hash, userVerified: true)
        let key = try P256.Signing.PrivateKey(rawRepresentation: created.credential.privateKey).publicKey
        #expect(try ReferenceCheck.verify(assertion, key: key, rpId: "example.com", clientDataHash: hash))
        await #expect(throws: VaultEngineError.itemNotFound) { _ = try await phone.engine.assertPasskey(credentialId: Data([9]), rpId: "example.com", clientDataHash: hash, userVerified: true) }
        await #expect(throws: VaultEngineError.itemNotFound) { _ = try await phone.engine.assertPasskey(credentialId: created.credential.credentialId, rpId: "evil.com", clientDataHash: hash, userVerified: true) }
        await #expect(throws: WebAuthnError.userVerificationRequired) {
            _ = try await phone.engine.assertPasskey(credentialId: created.credential.credentialId, rpId: "example.com", clientDataHash: hash, userVerified: false)
        }
        // BS is 0 until the vault syncs (the credential is not backed up anywhere).
        #expect(!(try WebAuthnAuthenticator.parseAuthenticatorData(assertion.authenticatorData).flags.contains(.backupState)))
    }

    @Test func identityStoreMetadataCarriesNoSecrets() async throws {
        let phone = Phone(server: nil)
        try await phone.engine.create()
        let hash = Data(repeating: 7, count: 32)
        let created = try await phone.engine.registerPasskey(PasskeyRegistrationRequest(rpId: "bank.example", userName: "anna", userHandle: Data([5]), clientDataHash: hash), userVerified: true)
        _ = try await phone.engine.addTOTP(uri: uri("anna@mail.example"))
        let passkeys = try await phone.engine.passkeyIdentities()
        #expect(passkeys.count == 1 && passkeys[0].rpId == "bank.example" && passkeys[0].userName == "anna" && passkeys[0].credentialId == created.credential.credentialId)
        let codes = try await phone.engine.oneTimeCodeIdentities()
        #expect(codes.count == 1 && codes[0].label == "Example · anna@mail.example")
        let text = String(describing: passkeys) + String(describing: codes)
        #expect(!text.contains(Hex.encode(created.credential.privateKey)) && !text.contains(secretBase32))
        // The metadata types have no field that could hold key material.
        #expect(Mirror(reflecting: passkeys[0]).children.map { $0.label ?? "" }.sorted() == ["credentialId", "recordIdentifier", "rpId", "userHandle", "userName"])
        #expect(Mirror(reflecting: codes[0]).children.map { $0.label ?? "" }.sorted() == ["label", "recordIdentifier"])
    }

    @Test func aRolledBackOrReplacedStateFileIsRefused() async throws {
        let phone = Phone(server: nil)
        try await phone.engine.create()
        let old = try #require(try phone.store.load())
        _ = try await phone.engine.addTOTP(uri: uri("one"))
        // An attacker (or a bad restore) puts the older file back.
        try phone.store.erase()
        try phone.store.save(old, ifHeadIs: nil)
        await #expect(throws: VaultEngineError.stateTampered) { _ = try await phone.engine.phase() }
        // A different device's vault dropped in is refused for the same reason (older version than the keychain remembers) or cannot be opened.
        let other = Phone(server: nil)
        try await other.engine.create()
        try phone.store.erase()
        try phone.store.save(try #require(try other.store.load()), ifHeadIs: nil)
        let result = try? await phone.engine.phase()
        #expect(result == nil || result == .locked)
        await phone.engine.lock()
        await #expect(throws: (any Error).self) { try await phone.engine.unlock() }
    }
}

enum ReferenceCheck {
    static func verify(_ assertion: PasskeyAssertion, key: P256.Signing.PublicKey, rpId: String, clientDataHash: Data) throws -> Bool {
        guard Data(assertion.authenticatorData.prefix(32)) == Data(SHA256.hash(data: Data(rpId.utf8))) else { return false }
        return key.isValidSignature(try P256.Signing.ECDSASignature(derRepresentation: assertion.signature), for: assertion.authenticatorData + clientDataHash)
    }
}

@Suite("Vault engine: sync, devices, recovery")
struct VaultEngineSyncTests {
    @Test func enablingSyncUploadsCiphertextOnlyAndIsGated() async throws {
        let server = InMemoryVaultServer()
        let a = Phone(server: server)
        try await a.engine.create()
        let hash = Data(repeating: 2, count: 32)
        let created = try await a.engine.registerPasskey(PasskeyRegistrationRequest(rpId: "private-bank.example", userName: "anna.private", userHandle: Data([1]), clientDataHash: hash), userVerified: true)
        _ = try await a.engine.addTOTP(uri: uri("anna@private-mail.example"))
        let recovery = await a.engine.makeRecoveryKey()

        // Gate off: no sync, local vault unaffected.
        server.available = false
        await #expect(throws: VaultEngineError.syncUnavailable) { try await a.engine.enableSync(recoveryKey: recovery) }
        #expect(await a.engine.syncAvailable() == false)
        #expect(try await a.engine.items().count == 2)
        server.available = true
        #expect(await a.engine.syncAvailable() == true)

        try await a.engine.enableSync(recoveryKey: recovery)
        #expect(try await a.engine.syncInfo()?.enabled == true)
        #expect(try await a.engine.syncInfo()?.hasRecoveryKey == true)
        #expect(server.version == 1 && server.blobCount == 2)
        let stored = server.storedBytes
        for secret in [created.credential.privateKey, Data("private-bank.example".utf8), Data("anna.private".utf8), Data("anna@private-mail.example".utf8), Data("12345678901234567890".utf8),
                       Data(secretBase32.utf8), Data(recovery.displayString.utf8)] {
            #expect(stored.range(of: secret) == nil)
        }
        // The credential's backup state flag follows sync.
        let assertion = try await a.engine.assertPasskey(credentialId: created.credential.credentialId, rpId: "private-bank.example", clientDataHash: hash, userVerified: true)
        #expect(try WebAuthnAuthenticator.parseAuthenticatorData(assertion.authenticatorData).flags.contains(.backupState))
        // A second vault cannot be created for the same account.
        let b = Phone(server: server)
        try await b.engine.create()
        await #expect(throws: VaultEngineError.remoteVaultExists) { try await b.engine.enableSync(recoveryKey: nil) }
    }

    @Test func offlineChangesQueueAndUpload() async throws {
        let server = InMemoryVaultServer()
        let a = Phone(server: server)
        try await a.engine.create()
        try await a.engine.enableSync(recoveryKey: nil)
        _ = try await a.engine.addTOTP(uri: uri("one"))
        _ = try await a.engine.addTOTP(uri: uri("two"))
        #expect(try await a.engine.syncInfo()?.pendingChanges == 2)
        #expect(server.version == 1)
        let report = try await a.engine.syncNow()
        #expect(report == SyncReport(outcome: .pushed, version: 3))
        #expect(try await a.engine.syncInfo()?.pendingChanges == 0)
        #expect(try await a.engine.syncNow().outcome == .upToDate)
        #expect(server.version == 3 && server.blobCount == 2)
    }

    /// Two phones, one vault: B joined A through the pairing channel.
    private func pair(_ server: InMemoryVaultServer) async throws -> (a: Phone, b: Phone) {
        let a = Phone(server: server, label: "Anna's iPhone")
        try await a.engine.create()
        _ = try await a.engine.addTOTP(uri: uri("first"))
        try await a.engine.enableSync(recoveryKey: RecoveryKey.generate())
        let b = Phone(server: server, label: "Ben's iPad")
        let invite = try await a.engine.beginAddingDevice()
        let handle = try await b.engine.requestJoin(code: invite.code)
        let preview = try #require(try await a.engine.joinRequest(for: invite))
        #expect(preview.deviceLabel == "Ben's iPad" && preview.fingerprint.count == 11)
        try await a.engine.approveJoin(invite)
        try await b.engine.completeJoin(handle)
        return (a, b)
    }

    @Test func aNewDeviceJoinsThroughThePairingCodeAndSeesTheItems() async throws {
        let server = InMemoryVaultServer()
        let (a, b) = try await pair(server)
        #expect(try await b.engine.phase() == .unlocked)
        #expect(try await b.engine.items().count == 1)
        let devices = try await b.engine.devices()
        #expect(devices.filter { !$0.isRecovery }.map(\.label).sorted() == ["Anna's iPhone", "Ben's iPad"])
        #expect(devices.first { $0.isThisDevice }?.label == "Ben's iPad")
        // Changes flow both ways.
        _ = try await b.engine.addTOTP(uri: uri("from-b"))
        _ = try await b.engine.syncNow()
        #expect(try await a.engine.syncNow().outcome == .pulled)
        #expect(try await a.engine.items().count == 2)
        // The pairing code is single use: a second device cannot reuse the same code.
        let invite = try await a.engine.beginAddingDevice()
        let c = Phone(server: server)
        _ = try await c.engine.requestJoin(code: invite.code)
        let thief = Phone(server: server)
        await #expect(throws: (any Error).self) { _ = try await thief.engine.requestJoin(code: invite.code) }
    }

    @Test func aWrongPairingCodeOrAnUnapprovedJoinGetsNothing() async throws {
        let server = InMemoryVaultServer()
        let a = Phone(server: server)
        try await a.engine.create()
        try await a.engine.enableSync(recoveryKey: nil)
        let invite = try await a.engine.beginAddingDevice()
        // A typo is caught by the checksum before anything is sent.
        let b = Phone(server: server)
        var typo = Array(invite.code)
        let index = typo.lastIndex { $0 != "-" }!
        typo[index] = typo[index] == "0" ? "1" : "0"
        await #expect(throws: VaultError.invalidPairingCode) { _ = try await b.engine.requestJoin(code: String(typo)) }
        // A different (valid) code does not match the join A opened.
        await #expect(throws: (any Error).self) { _ = try await b.engine.requestJoin(code: PairingSecret.generate().displayString) }
        // The right code but A never approves: nothing to complete.
        let handle = try await b.engine.requestJoin(code: invite.code)
        await #expect(throws: VaultEngineError.joinNotApproved) { try await b.engine.completeJoin(handle) }
        #expect(try await b.engine.phase() == .empty)
        // The request is only readable with the code: the server holds ciphertext.
        #expect(server.storedBytes.range(of: Data("Phone".utf8)) == nil)
    }

    @Test func concurrentItemChangesOnTwoDevicesMerge() async throws {
        let server = InMemoryVaultServer()
        let (a, b) = try await pair(server)
        _ = try await a.engine.addTOTP(uri: uri("from-a"))
        _ = try await b.engine.addTOTP(uri: uri("from-b"))
        #expect(try await a.engine.syncNow().outcome == .pushed)
        #expect(try await b.engine.syncNow().outcome == .merged)
        #expect(try await a.engine.syncNow().outcome == .pulled)
        let names = try await a.engine.items().compactMap { item -> String? in if case .totp(let t) = item.body { t.accountName } else { nil } }.sorted()
        #expect(names == ["first", "from-a", "from-b"])
        #expect(try await b.engine.items().count == 3)
    }

    @Test func removingADeviceCutsItOffAndRotatesTheKey() async throws {
        let server = InMemoryVaultServer()
        let (a, b) = try await pair(server)
        let bMember = try #require(try await b.engine.devices().first { $0.isThisDevice }).memberId
        try await a.engine.removeDevice(bMember)
        #expect(try await a.engine.devices().filter { !$0.isRecovery }.count == 1)
        #expect(server.version == 3)
        // B is out: it can no longer sync, and what it sees is refused.
        await #expect(throws: (any Error).self) { _ = try await b.engine.syncNow() }
        // A keeps working with the new key.
        _ = try await a.engine.addTOTP(uri: uri("after"))
        #expect(try await a.engine.syncNow().outcome == .pushed)
        // Local changes on B (made before it learned) are never accepted by the server.
        _ = try await b.engine.addTOTP(uri: uri("sneaky"))
        await #expect(throws: (any Error).self) { _ = try await b.engine.syncNow() }
        #expect(server.version == 4)
    }

    @Test func aRewoundOrForkedServerIsDetected() async throws {
        let server = InMemoryVaultServer()
        let a = Phone(server: server)
        try await a.engine.create()
        try await a.engine.enableSync(recoveryKey: nil)
        _ = try await a.engine.addTOTP(uri: uri("one"))
        _ = try await a.engine.syncNow()
        _ = try await a.engine.addTOTP(uri: uri("two"))
        _ = try await a.engine.syncNow()
        #expect(server.version == 3)
        server.rewind(toVersion: 2)
        await #expect(throws: VaultEngineError.rollbackDetected) { _ = try await a.engine.syncNow() }
        // And the device did not accept or overwrite anything.
        #expect(try await a.engine.syncInfo()?.version == 3)
    }

    @Test func conflictsAreRetried() async throws {
        let server = InMemoryVaultServer()
        let a = Phone(server: server)
        try await a.engine.create()
        try await a.engine.enableSync(recoveryKey: nil)
        _ = try await a.engine.addTOTP(uri: uri("one"))
        server.failNextPutWithConflict = true
        #expect(try await a.engine.syncNow().outcome == .pushed)
        #expect(server.version == 2)
    }

    @Test func theRecoveryKeyIsVerifiedLocallyAndRestoresOnANewDeviceOnly() async throws {
        let server = InMemoryVaultServer()
        let a = Phone(server: server)
        try await a.engine.create()
        let item = try await a.engine.addTOTP(uri: uri("precious"))
        let recovery = await a.engine.makeRecoveryKey()
        try await a.engine.enableSync(recoveryKey: recovery)
        #expect(try await a.engine.verifyRecoveryKey(recovery.displayString))
        #expect(try await a.engine.verifyRecoveryKey(recovery.displayString.lowercased().replacingOccurrences(of: "-", with: " ")))
        #expect(try await a.engine.verifyRecoveryKey(RecoveryKey.generate().displayString) == false)
        #expect(try await a.engine.verifyRecoveryKey("not a key") == false)

        // The phone is lost. Account recovery gives a new device an account session, nothing more: signing in cannot reach the vault.
        let fresh = Phone(server: server, label: "New phone")
        await #expect(throws: VaultEngineError.alreadyExists) { _ = try await a.engine.prepareRestore(recoveryKey: recovery.displayString) }
        await #expect(throws: VaultEngineError.restoreNotReleased) { _ = try await fresh.engine.prepareRestore(recoveryKey: recovery.displayString) }
        _ = try await fresh.engine.requestRestoreRelease()
        server.advance(by: VaultRecoveryRelease.holdSeconds + 1)
        await #expect(throws: (any Error).self) { _ = try await fresh.engine.prepareRestore(recoveryKey: RecoveryKey.generate().displayString) }
        #expect(try await fresh.engine.phase() == .empty)
        await #expect(throws: (any Error).self) { try await fresh.engine.unlock() }

        // With the recovery key, a preview, and a new key that was shown first:
        let preview = try await fresh.engine.prepareRestore(recoveryKey: recovery.displayString)
        #expect(preview.itemCount == 1 && preview.deviceNames == ["Phone"])
        let newKey = await fresh.engine.makeRecoveryKey()
        try await fresh.engine.commitRestore(newRecoveryKey: newKey)
        #expect(try await fresh.engine.items().map(\.id) == [item])
        #expect(try await fresh.engine.verifyRecoveryKey(newKey.displayString))
        #expect(try await fresh.engine.verifyRecoveryKey(recovery.displayString) == false, "the used key is retired")
        // The lost phone is cut off.
        await #expect(throws: (any Error).self) { _ = try await a.engine.syncNow() }
        // And the used recovery key cannot restore a second time.
        let another = Phone(server: server)
        _ = try await another.engine.requestRestoreRelease()
        server.advance(by: VaultRecoveryRelease.holdSeconds + 1)
        await #expect(throws: (any Error).self) { _ = try await another.engine.prepareRestore(recoveryKey: recovery.displayString) }
    }

    @Test func disablingSyncKeepsTheLocalVaultAndCanErasetheServerCopy() async throws {
        let server = InMemoryVaultServer()
        let a = Phone(server: server)
        try await a.engine.create()
        _ = try await a.engine.addTOTP(uri: uri("keep"))
        try await a.engine.enableSync(recoveryKey: nil)
        try await a.engine.disableSync(deleteFromServer: true)
        #expect(server.blobCount == 0 && server.version == 0)
        #expect(try await a.engine.items().count == 1)
        #expect(try await a.engine.syncInfo()?.enabled == false)
        await #expect(throws: VaultEngineError.syncNotEnabled) { _ = try await a.engine.syncNow() }
    }
}

@Suite("Credential-provider extension boundary")
struct VaultExtensionBoundaryTests {
    private func container() throws -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("vault-test-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }

    @Test func theSharedContainerHoldsCiphertextOnly() async throws {
        let dir = try container()
        defer { try? FileManager.default.removeItem(at: dir) }
        let app = Phone(server: nil, store: FileVaultLocalStore(directory: dir))
        try await app.engine.create()
        let hash = Data(repeating: 4, count: 32)
        let created = try await app.engine.registerPasskey(PasskeyRegistrationRequest(rpId: "container-test.example", userName: "container.user", userHandle: Data([1]), clientDataHash: hash), userVerified: true)
        _ = try await app.engine.addTOTP(uri: uri("container@test.example"))
        let files = try FileManager.default.contentsOfDirectory(atPath: dir.path)
        #expect(Set(files).isSubset(of: FileVaultLocalStore.fileNames), "unexpected files in the shared container: \(files)")
        var all = Data()
        for name in files { all += try Data(contentsOf: dir.appendingPathComponent(name)) }
        for secret in [created.credential.privateKey, Data("container-test.example".utf8), Data("container.user".utf8), Data("container@test.example".utf8), Data("12345678901234567890".utf8),
                       Data(secretBase32.utf8), Data(Base64URL.encode(created.credential.privateKey).utf8), Data(Base64URL.encode(Data("12345678901234567890".utf8)).utf8),
                       Data(Base64URL.encode(Data("container-test.example".utf8)).utf8)] {
            #expect(all.range(of: secret) == nil)
        }
        #expect(all.count > 500)
    }

    @Test func theExtensionNeverTouchesTheNetworkAndTheAppPicksUpItsChanges() async throws {
        let dir = try container()
        defer { try? FileManager.default.removeItem(at: dir) }
        let server = InMemoryVaultServer()
        let store = FileVaultLocalStore(directory: dir)
        let app = Phone(server: server, store: store)
        try await app.engine.create()
        try await app.engine.enableSync(recoveryKey: nil)

        // The extension: same store and same device keys, no sync API at all.
        let ext = VaultEngine(store: FileVaultLocalStore(directory: dir), keys: app.keys, api: nil, anchors: app.anchors, deviceLabel: "ext")
        try await ext.unlock()
        await #expect(throws: VaultEngineError.syncUnavailable) { _ = try await ext.syncNow() }
        await #expect(throws: VaultEngineError.syncUnavailable) { _ = try await ext.beginAddingDevice() }
        await #expect(throws: VaultEngineError.syncUnavailable) { try await ext.enableSync(recoveryKey: nil) }
        let requestsBefore = server.requestLog.count
        let hash = Data(repeating: 6, count: 32)
        let created = try await ext.registerPasskey(PasskeyRegistrationRequest(rpId: "ext.example", userName: "e", userHandle: Data([3]), clientDataHash: hash), userVerified: true)
        #expect(server.requestLog.count == requestsBefore, "the extension made a network request")

        // The app, already unlocked, sees the extension's passkey without relaunching, then uploads it.
        #expect(try await app.engine.passkeys(for: "ext.example").map(\.credentialId) == [created.credential.credentialId])
        #expect(try await app.engine.syncInfo()?.pendingChanges == 1)
        #expect(try await app.engine.syncNow().outcome == .pushed)
        #expect(server.version == 2)
    }

    @Test func bothProcessesChangingAtOnceNeverLoseAWrite() async throws {
        let dir = try container()
        defer { try? FileManager.default.removeItem(at: dir) }
        let app = Phone(server: nil, store: FileVaultLocalStore(directory: dir))
        try await app.engine.create()
        let ext = VaultEngine(store: FileVaultLocalStore(directory: dir), keys: app.keys, api: nil, anchors: app.anchors)
        try await ext.unlock()
        // Interleave: each engine's cached head is stale after the other writes, and refreshes before changing anything.
        for index in 0..<5 {
            _ = try await app.engine.addTOTP(uri: uri("app\(index)"))
            _ = try await ext.addTOTP(uri: uri("ext\(index)"))
        }
        #expect(try await app.engine.items().count == 10)
        #expect(try await ext.items().count == 10)
        // The store itself refuses a stale overwrite.
        let state = try #require(try app.store.load())
        #expect(throws: VaultStoreError.changedElsewhere) { try app.store.save(state, ifHeadIs: Data(repeating: 1, count: 32)) }
    }

    @Test func aLockedExtensionCannotReadOrSign() async throws {
        let dir = try container()
        defer { try? FileManager.default.removeItem(at: dir) }
        let app = Phone(server: nil, store: FileVaultLocalStore(directory: dir))
        try await app.engine.create()
        _ = try await app.engine.addTOTP(uri: uri("x"))
        // A fresh extension process starts locked and has no key until the person unlocks.
        let ext = VaultEngine(store: FileVaultLocalStore(directory: dir), keys: SoftwareVaultKeyProvider(), api: nil, anchors: app.anchors)
        await #expect(throws: VaultEngineError.locked) { _ = try await ext.items() }
        await #expect(throws: VaultEngineError.deviceKeyMissing) { try await ext.unlock() }
        await #expect(throws: VaultEngineError.locked) { _ = try await ext.passkeyIdentities() }
        await #expect(throws: VaultEngineError.locked) { _ = try await ext.registerPasskey(PasskeyRegistrationRequest(rpId: "a.example", userName: "u", userHandle: Data([1]), clientDataHash: Data(repeating: 1, count: 32)), userVerified: true) }
    }
}
