import Testing
import Foundation
import ViadereCore
@testable import ViadereKit

@Suite("Keys and enrollment")
struct KeyTests {
    @Test func provisioningProducesVerifiableProofs() async throws {
        let store = SoftwareDeviceKeyStore()
        let consumer = ConsumerID()
        let result = try await DeviceKeyProvisioner(store: store).provision(consumerId: consumer, challenge: "chal-123")
        #expect(result.registrations.count == 3)
        #expect(result.skipped.isEmpty)
        for registration in result.registrations {
            #expect(DeviceEnrollment.verify(registration, consumerId: consumer, challenge: "chal-123"))
            #expect(!DeviceEnrollment.verify(registration, consumerId: consumer, challenge: "other"))
            #expect(!registration.hardwareBacked)
        }
    }

    @Test func missingBiometricsSkipsOptionalKeys() async throws {
        let store = SoftwareDeviceKeyStore(unsupported: [.approvalBiometric])
        let result = try await DeviceKeyProvisioner(store: store).provision(consumerId: ConsumerID(), challenge: "c")
        #expect(result.registrations.map(\.purpose) == [.request, .approvalUserPresence])
        #expect(result.skipped == [.approvalBiometric])
    }

    @Test func requestKeyIsMandatory() async throws {
        let store = SoftwareDeviceKeyStore(unsupported: [.request])
        await #expect(throws: KeyStoreError.self) { _ = try await DeviceKeyProvisioner(store: store).provision(consumerId: ConsumerID(), challenge: "c") }
    }

    @Test func softwareKeysPersistThroughSecretStore() async throws {
        let secrets = InMemorySecretStore()
        let first = SoftwareDeviceKeyStore(secrets: secrets)
        let key = try await first.createKey(for: .request)
        let second = SoftwareDeviceKeyStore(secrets: secrets)
        #expect(try await second.existingKey(for: .request)?.publicKey == key.publicKey)
        // signatures from a restored key verify against the original public key
        let signature = try await (try await second.requireKey(for: .request)).signature(for: Data("x".utf8))
        #expect(try key.publicKey.signingKey().isValidSignature(signature, for: Data("x".utf8)))
    }

    @Test func healthDetectsInvalidatedKeys() async throws {
        let services = await ViadereServices.mock()
        #expect(await services.account.health() == .healthy)
        try await services.keys.deleteKey(for: .approvalBiometric)
        #expect(await services.account.health() == .needsReenrollment(missing: [.approvalBiometric]))
        let blank = await ViadereServices.mock(api: MockViadereAPI(seed: false), signedIn: false)
        #expect(await blank.account.health() == .notEnrolled)
    }

    @Test func reenrollmentReplacesDeviceAndRevokesOld() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api)
        let oldId = try #require(try await services.records.load()?.deviceId)
        try await services.keys.deleteKey(for: .approvalBiometric)
        let record = try await services.account.reenrollThisDevice(name: "New phone")
        #expect(record.deviceId != oldId)
        let devices = try await api.devices()
        #expect(devices.first { $0.id == oldId }?.isRevoked == true)
        #expect(devices.first { $0.id == record.deviceId }?.isRevoked == false)
        #expect(await services.account.health() == .healthy)
    }

    @Test func approvalKeysDifferFromRequestKey() async throws {
        let store = SoftwareDeviceKeyStore()
        let keys = try await DeviceKeyPurpose.allCases.asyncMap { try await store.createKey(for: $0).publicKey }
        #expect(Set(keys).count == 3)
    }
}

extension Sequence {
    func asyncMap<T>(_ transform: (Element) async throws -> T) async rethrows -> [T] {
        var out: [T] = []
        for element in self { out.append(try await transform(element)) }
        return out
    }
}

@Suite("Storage")
struct StorageTests {
    @Test func tokensRoundTripAndWipe() async throws {
        let secrets = InMemorySecretStore()
        let store = SecretTokenStore(secrets: secrets)
        #expect(try await store.load() == nil)
        let tokens = TokenSet(consumerId: ConsumerID(), accessToken: "a", accessExpiresAt: Date(timeIntervalSince1970: 2_000_000_000), refreshToken: "r")
        try await store.save(tokens)
        #expect(try await store.load() == tokens)
        try await store.clear()
        #expect(try await store.load() == nil)
    }

    @Test func corruptedItemsAreDroppedNotFatal() async throws {
        let secrets = InMemorySecretStore()
        try secrets.write(Data("not json".utf8), account: "session.tokens")
        #expect(try await SecretTokenStore(secrets: secrets).load() == nil)
        #expect(try secrets.read("session.tokens") == nil)
    }

    @Test func tokenRefreshWindow() {
        let tokens = TokenSet(consumerId: ConsumerID(), accessToken: "a", accessExpiresAt: Date(timeIntervalSince1970: 1_000))
        #expect(tokens.needsRefresh(now: Date(timeIntervalSince1970: 980)))
        #expect(!tokens.needsRefresh(now: Date(timeIntervalSince1970: 900)))
    }

    @Test func signOutErasesEverything() async throws {
        let services = await ViadereServices.mock()
        await services.account.signOut()
        #expect(await services.sessions.tokens() == nil)
        #expect(try await services.records.load() == nil)
        #expect(await services.keys.availablePurposes().isEmpty)
        #expect((services.secrets as? InMemorySecretStore)?.count == 0)
    }

    @Test func deleteAccountCallsServerThenWipes() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api)
        try await services.account.deleteAccount()
        #expect(await api.accountDeleted)
        #expect(await services.sessions.tokens() == nil)
    }

    @Test func preferences() {
        let prefs = InMemoryPreferences()
        #expect(!prefs.bool(.appLockEnabled))
        prefs.setBool(true, for: .appLockEnabled)
        #expect(prefs.bool(.appLockEnabled))
        prefs.removeAll()
        #expect(!prefs.bool(.appLockEnabled))
        #expect(SensitiveCopyPolicy.expiration(from: Date(timeIntervalSince1970: 100)) == Date(timeIntervalSince1970: 160))
    }
}
