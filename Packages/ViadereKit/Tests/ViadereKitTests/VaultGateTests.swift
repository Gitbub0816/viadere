import Crypto
import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

/// Phase 4 gate review (Kit): L1 restore preview, L2 fresh authentication per operation, L3 two-sided fingerprint, M2 hold, M3 vault-full
/// error, L7 OTP domain filtering. Written before the fixes.

/// A key provider that counts fresh authentications, like Face ID prompts on a device.
private final class CountingKeys: VaultKeyProvider, @unchecked Sendable {
    private let inner = SoftwareVaultKeyProvider()
    private let lock = NSLock()
    private var reasons: [String] = []
    var freshCount: Int { lock.withLock { reasons.count } }
    var freshReasons: [String] { lock.withLock { reasons } }
    func existingIdentity() async throws -> VaultDeviceIdentity? { try await inner.existingIdentity() }
    func createIdentity() async throws -> VaultDeviceIdentity { try await inner.createIdentity() }
    func deleteIdentity() async throws { try await inner.deleteIdentity() }
    func freshIdentity(reason: String) async throws -> VaultDeviceIdentity {
        lock.withLock { reasons.append(reason) }
        guard let identity = try await inner.existingIdentity() else { throw VaultEngineError.deviceKeyMissing }
        return identity
    }
}

private struct Phone {
    let keys = CountingKeys()
    let engine: VaultEngine
    let api: InMemoryVaultSyncAPI?

    init(server: InMemoryVaultServer?, label: String = "Phone") {
        let keys = keys
        api = server.map { InMemoryVaultSyncAPI(server: $0) }
        engine = VaultEngine(store: InMemoryVaultLocalStore(), keys: keys, api: api, anchors: InMemorySecretStore(), deviceLabel: label,
                             clock: { Date(timeIntervalSince1970: 1_800_000_000) })
    }
}

private let secretBase32 = Base32.encode(Data("12345678901234567890".utf8))
private func uri(_ name: String, issuer: String = "Example") -> String { "otpauth://totp/\(issuer):\(name)?secret=\(secretBase32)&issuer=\(issuer)" }

@Suite("Vault gate review (Kit)")
struct VaultGateKitTests {
    // MARK: M2 + L1: hold, preview, then commit

    private func syncedWithRecovery(_ server: InMemoryVaultServer) async throws -> (phone: Phone, recovery: RecoveryKey) {
        let a = Phone(server: server, label: "Anna's iPhone")
        try await a.engine.create()
        _ = try await a.engine.addTOTP(uri: uri("precious"))
        _ = try await a.engine.addTOTP(uri: uri("second"))
        let recovery = await a.engine.makeRecoveryKey()
        try await a.engine.enableSync(recoveryKey: recovery)
        return (a, recovery)
    }

    @Test func restoreWaitsForTheHoldThenPreviewsBeforeAnythingChanges() async throws {
        let server = InMemoryVaultServer()
        let (a, recovery) = try await syncedWithRecovery(server)
        let fresh = Phone(server: server, label: "New phone")
        // Account access alone reads nothing: before a release, the restore cannot even fetch the history.
        await #expect(throws: VaultEngineError.restoreNotReleased) { _ = try await fresh.engine.prepareRestore(recoveryKey: recovery.displayString) }
        let hold = try await fresh.engine.requestRestoreRelease()
        #expect(hold.state == .holding)
        await #expect(throws: VaultEngineError.restoreNotReleased) { _ = try await fresh.engine.prepareRestore(recoveryKey: recovery.displayString) }
        server.advance(by: VaultRecoveryRelease.holdSeconds + 1)
        #expect(try await fresh.engine.restoreRelease()?.state == .released)

        // Authenticate, then preview: nothing is committed, no device key is made, the server is untouched.
        let versionBefore = server.version
        let preview = try await fresh.engine.prepareRestore(recoveryKey: recovery.displayString)
        #expect(preview.itemCount == 2 && preview.passkeyCount == 0 && preview.codeCount == 2)
        #expect(preview.deviceNames == ["Anna's iPhone"])
        #expect(preview.lastChange == Date(timeIntervalSince1970: 1_800_000_000))
        #expect(preview.version == versionBefore)
        #expect(try await fresh.engine.phase() == .empty)
        #expect(try await fresh.keys.existingIdentity() == nil)
        #expect(server.version == versionBefore)

        // A wrong key authenticates nothing.
        await #expect(throws: (any Error).self) { _ = try await fresh.engine.prepareRestore(recoveryKey: RecoveryKey.generate().displayString) }
        // Commit: only now the device key is created, the vault key replaced and the server updated.
        let newKey = await fresh.engine.makeRecoveryKey()
        try await fresh.engine.commitRestore(newRecoveryKey: newKey)
        #expect(try await fresh.engine.items().count == 2)
        #expect(server.version == versionBefore + 1)
        #expect(try await fresh.engine.verifyRecoveryKey(newKey.displayString))
        await #expect(throws: (any Error).self) { _ = try await a.engine.syncNow() }
        // The prepared state is spent: a second commit has nothing to commit.
        await #expect(throws: VaultEngineError.noPreparedRestore) { try await fresh.engine.commitRestore(newRecoveryKey: .generate()) }
    }

    @Test func aCancelledReleaseOrADiscardedPreviewRestoresNothing() async throws {
        let server = InMemoryVaultServer()
        let (a, recovery) = try await syncedWithRecovery(server)
        let fresh = Phone(server: server)
        let hold = try await fresh.engine.requestRestoreRelease()
        // The owner's other device cancels ("Not you?").
        _ = try await a.api!.cancelRecoveryRelease(hold.releaseId)
        server.advance(by: VaultRecoveryRelease.holdSeconds + 1)
        await #expect(throws: VaultEngineError.restoreNotReleased) { _ = try await fresh.engine.prepareRestore(recoveryKey: recovery.displayString) }
        // A new release, a preview the person walks away from.
        _ = try await fresh.engine.requestRestoreRelease()
        server.advance(by: VaultRecoveryRelease.holdSeconds + 1)
        _ = try await fresh.engine.prepareRestore(recoveryKey: recovery.displayString)
        await fresh.engine.discardRestore()
        await #expect(throws: VaultEngineError.noPreparedRestore) { try await fresh.engine.commitRestore(newRecoveryKey: .generate()) }
        #expect(try await fresh.engine.phase() == .empty)
        // The window closes after 24 hours.
        server.advance(by: VaultRecoveryRelease.windowSeconds + 1)
        await #expect(throws: VaultEngineError.restoreNotReleased) { _ = try await fresh.engine.prepareRestore(recoveryKey: recovery.displayString) }
    }

    // MARK: L2

    @Test func everyMembershipAndRecoveryOperationAsksForAFreshAuthentication() async throws {
        let server = InMemoryVaultServer()
        let a = Phone(server: server, label: "Anna's iPhone")
        try await a.engine.create()
        _ = try await a.engine.addTOTP(uri: uri("x"))
        let key = await a.engine.makeRecoveryKey()
        try await a.engine.enableSync(recoveryKey: key)
        // Item work uses the unlock; it does not prompt again.
        let afterEnable = a.keys.freshCount
        _ = try await a.engine.addTOTP(uri: uri("y"))
        try await a.engine.deleteItem(try #require(try await a.engine.items().first).id)
        #expect(a.keys.freshCount == afterEnable)

        let b = Phone(server: server, label: "Ben's iPad")
        let invite = try await a.engine.beginAddingDevice()
        let handle = try await b.engine.requestJoin(code: invite.code)
        _ = handle
        let before = a.keys.freshCount
        try await a.engine.approveJoin(invite)
        #expect(a.keys.freshCount == before + 1, "approving a device")
        try await b.engine.completeJoin(handle)

        let beforeRecovery = a.keys.freshCount
        try await a.engine.installRecoveryKey(await a.engine.makeRecoveryKey(), rotateVaultKey: false)
        #expect(a.keys.freshCount == beforeRecovery + 1, "replacing the recovery key")

        let beforeRemoval = a.keys.freshCount
        let bMember = try #require(try await b.engine.devices().first { $0.isThisDevice }).memberId
        try await a.engine.removeDevice(bMember)
        #expect(a.keys.freshCount == beforeRemoval + 1, "removing a device")
        #expect(a.keys.freshReasons.allSatisfy { !$0.isEmpty })
    }

    // MARK: L3

    @Test func bothDevicesShowTheSameFingerprintOfTheNewDevice() async throws {
        let server = InMemoryVaultServer()
        let a = Phone(server: server, label: "Anna's iPhone")
        try await a.engine.create()
        try await a.engine.enableSync(recoveryKey: nil)
        let b = Phone(server: server, label: "Ben's iPad")
        let invite = try await a.engine.beginAddingDevice()
        let handle = try await b.engine.requestJoin(code: invite.code)
        let preview = try #require(try await a.engine.joinRequest(for: invite))
        #expect(handle.fingerprint == preview.fingerprint && handle.fingerprint.count == 11)
        // A different device (an attacker who guessed nothing but raced the join) shows a different fingerprint.
        let other = Phone(server: server)
        await #expect(throws: (any Error).self) { _ = try await other.engine.requestJoin(code: invite.code) }
        let attackerIdentity = VaultDeviceIdentity.software()
        #expect(CrockfordFingerprint.short(of: attackerIdentity.signingPublicKey) != handle.fingerprint)
    }

    // MARK: M3

    @Test func aFullVaultIsAClearErrorAndNotACorruptedWrite() async throws {
        let phone = Phone(server: nil)
        try await phone.engine.create()
        func big() -> VaultItemPayload {
            let credential = PasskeyCredential(credentialId: SecureToken.randomBytes(32), rpId: "example.com", userHandle: Data([1]), userName: String(repeating: "a", count: 32_000),
                                               displayName: nil, privateKey: SecureToken.randomBytes(32), createdAt: Date(timeIntervalSince1970: 1_800_000_000))
            return VaultItemPayload(body: .passkey(credential), createdAt: Date(timeIntervalSince1970: 1_800_000_000))
        }
        try await phone.engine.upsert((0..<64).map { _ in big() })
        await #expect(throws: VaultEngineError.vaultFull) { try await phone.engine.upsert([big()]) }
        #expect(try await phone.engine.items().count == 64)
        let text = await MainActor.run { AuthenticatorViewModel.describe(VaultEngineError.vaultFull) }
        #expect(text.contains("full"))
    }

    // MARK: L7: one-time codes are offered for the site that asked

    @Test func oneTimeCodesAreFilteredByTheRequestingDomain() async throws {
        #expect(OneTimeCodeDomainMatcher.matches(issuer: "GitHub", accountName: "alice", domain: "github.com"))
        #expect(OneTimeCodeDomainMatcher.matches(issuer: "GitHub", accountName: "alice", domain: "www.github.com"))
        #expect(OneTimeCodeDomainMatcher.matches(issuer: nil, accountName: "alice@example.org", domain: "login.example.org"))
        #expect(OneTimeCodeDomainMatcher.matches(issuer: "Amazon Web Services", accountName: "a", domain: "signin.aws.amazon.com"))
        #expect(OneTimeCodeDomainMatcher.matches(issuer: "Example", accountName: "a", domain: "example.co.uk"))
        #expect(!OneTimeCodeDomainMatcher.matches(issuer: "GitHub", accountName: "alice", domain: "evil.example"))
        #expect(!OneTimeCodeDomainMatcher.matches(issuer: "Bank", accountName: "alice", domain: "bank.evil.example"), "only the registrable label counts, not a subdomain an attacker chose")
        #expect(!OneTimeCodeDomainMatcher.matches(issuer: "", accountName: "", domain: "github.com"))
        #expect(!OneTimeCodeDomainMatcher.matches(issuer: "co", accountName: "x", domain: "example.co.uk"), "too-short and generic labels never match")

        let phone = Phone(server: nil)
        try await phone.engine.create()
        _ = try await phone.engine.addTOTP(uri: uri("alice", issuer: "GitHub"))
        _ = try await phone.engine.addTOTP(uri: uri("bob", issuer: "Bank"))
        let github = try await phone.engine.oneTimeCodeIdentities(matching: ["github.com"])
        #expect(github.count == 1 && github[0].label.contains("GitHub"))
        #expect(try await phone.engine.oneTimeCodeIdentities(matching: []).count == 2, "no domain given: everything")
        #expect(try await phone.engine.oneTimeCodeIdentities(matching: ["nothing.example"]).isEmpty)
    }
}

@MainActor
@Suite("Vault recovery notices")
struct VaultRecoveryNoticeTests {
    private func notice(_ raw: String, action: SecurityNoticeAction?, subject: String? = nil) -> SecurityNotice {
        SecurityNotice(id: UUID(), rawKind: raw, message: "Server text", createdAt: Date().addingTimeInterval(-60), subjectId: subject, action: action)
    }

    @Test func aRecoveryReleaseRequestOffersCancelAndCallsTheVaultRoute() async throws {
        let api = MockViadereAPI(seed: false)
        let model = SecurityNoticesViewModel(services: await ViadereServices.mock(api: api))
        let release = UUID()
        let n = notice("vaultRecoveryRequested", action: .cancelVaultRecovery, subject: release.uuidString.lowercased())
        await api.setSecurityNotices([n])
        await model.load()
        #expect(n.topic == .vaultRecoveryRequested)
        #expect(model.actionTitle(for: n) == "Cancel release")
        #expect(model.headline(for: n).contains("recovery key envelope") && model.prompt(for: n).contains("Cancel"))
        #expect(await model.perform(n))
        #expect(model.message == SecurityNoticesViewModel.vaultReleaseCancelledMessage)
        #expect(model.notices.isEmpty)
        // A bad id never reaches the network.
        #expect(await !model.perform(notice("vaultRecoveryRequested", action: .cancelVaultRecovery, subject: "nope")))
    }

    @Test func everyNewTopicHasItsOwnHeadline() async throws {
        let model = SecurityNoticesViewModel(services: await ViadereServices.mock(api: MockViadereAPI(seed: false)))
        for raw in ["vaultRecoveryCancelled", "vaultRecoveryReleased", "vaultRecoveryFetched", "vaultRestored"] {
            let n = notice(raw, action: nil)
            #expect(n.topic != .unknown, "\(raw)")
            #expect(!model.headline(for: n).contains("Server text"), "\(raw) must not fall back to the generic text")
        }
    }
}
