import Foundation
import ViadereCore

/// Account lifecycle: passkey sign-up / sign-in, device enrollment, sign-out and the "wipe everything" path.
public struct AccountService: Sendable {
    public let api: any ViadereAPI
    let sessions: SessionManager
    let passkeys: any PasskeyService
    let keys: any DeviceKeyStore
    let records: any DeviceRecordStore
    let preferences: any PreferencesStore
    let secrets: any SecretStore
    let platform: DevicePlatform
    let clock: @Sendable () -> Date

    public init(api: any ViadereAPI, sessions: SessionManager, passkeys: any PasskeyService, keys: any DeviceKeyStore,
                records: any DeviceRecordStore, preferences: any PreferencesStore, secrets: any SecretStore,
                platform: DevicePlatform = .iOS, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.api = api
        self.sessions = sessions
        self.passkeys = passkeys
        self.keys = keys
        self.records = records
        self.preferences = preferences
        self.secrets = secrets
        self.platform = platform
        self.clock = clock
    }

    // MARK: Sign-up / sign-in

    public func signUp(displayName: String) async throws {
        let name = String(displayName.trimmingCharacters(in: .whitespacesAndNewlines).prefix(64))
        guard !name.isEmpty else { throw APIError.invalidRequest("name") }
        let options = try await api.beginRegistration(displayName: name)
        let credential = try await passkeys.register(options: options)
        let grant = try await api.finishRegistration(PasskeyRegistrationFinishRequest(ceremonyId: options.ceremonyId, credential: credential))
        try await store(grant)
    }

    public func signIn() async throws {
        let options = try await api.beginLogin()
        let credential = try await passkeys.assert(options: options)
        let grant = try await api.finishLogin(PasskeyLoginFinishRequest(ceremonyId: options.ceremonyId, credential: credential))
        try await store(grant)
    }

    private func store(_ session: AuthSession) async throws {
        try await sessions.set(TokenSet(session))
        preferences.setString(session.consumerId.description, for: .lastKnownConsumerId)
    }

    // MARK: Device enrollment

    /// Creates this device's Secure Enclave keys and registers them with proof of possession.
    @discardableResult
    public func enrollThisDevice(name: String) async throws -> DeviceRecord {
        guard let tokens = await sessions.tokens() else { throw APIError.sessionExpired }
        let challenge = try await api.beginDeviceEnrollment()
        let provisioned = try await DeviceKeyProvisioner(store: keys).provision(consumerId: tokens.consumerId, challenge: challenge.challenge)
        guard provisioned.registrations.contains(where: { $0.purpose == .request }) else { throw KeyStoreError.unavailable }
        let device = try await api.enrollDevice(DeviceEnrollRequest(name: String(name.prefix(64)), platform: platform,
                                                                    challenge: challenge.challenge, keys: provisioned.registrations))
        let record = DeviceRecord(deviceId: device.id, consumerId: tokens.consumerId, name: device.name,
                                  purposes: provisioned.registrations.map(\.purpose), enrolledAt: clock())
        try await records.save(record)
        return record
    }

    /// Replaces keys after invalidation (biometrics changed, restore). The old device record is revoked
    /// best-effort *before* its request key is deleted (revocation is device-signed).
    @discardableResult
    public func reenrollThisDevice(name: String) async throws -> DeviceRecord {
        if let old = try? await records.load() { try? await api.revokeDevice(old.deviceId) }
        try? await records.clear()
        try? await keys.deleteAllKeys()
        return try await enrollThisDevice(name: name)
    }

    public func health() async -> EnrollmentHealth {
        await EnrollmentHealth.check(record: try? await records.load(), store: keys)
    }

    // MARK: Sign-out / deletion

    /// Signs out: tells the server (best effort), then erases tokens, device record, Secure Enclave keys,
    /// preferences and every keychain item.
    public func signOut() async {
        try? await api.logout()
        await wipeLocalState()
    }

    public func deleteAccount() async throws {
        try await api.deleteAccount()
        await wipeLocalState()
    }

    /// Used on sign-out, account deletion and **device revocation** (the server no longer trusts this device).
    public func wipeLocalState() async {
        await sessions.clear()
        try? await records.clear()
        try? await keys.deleteAllKeys()
        try? secrets.deleteAll()
        preferences.removeAll()
    }
}
