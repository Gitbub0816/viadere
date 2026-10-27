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
    let residue: any LocalResidueCleaner
    let isAppClip: Bool
    let clock: @Sendable () -> Date
    /// How long sign-out waits for each best-effort server call before giving up and erasing locally anyway.
    let serverCallTimeout: Duration

    /// - Parameters:
    ///   - residue: clears notifications, Live Activities, watch context and dynamic categories on wipe.
    ///   - isAppClip: the clip enrolls a request-key-only, marked device; the full app revokes clip devices after enrolling.
    public init(api: any ViadereAPI, sessions: SessionManager, passkeys: any PasskeyService, keys: any DeviceKeyStore,
                records: any DeviceRecordStore, preferences: any PreferencesStore, secrets: any SecretStore,
                platform: DevicePlatform = .iOS, residue: any LocalResidueCleaner = NoLocalResidueCleaner(), isAppClip: Bool = false,
                serverCallTimeout: Duration = .seconds(5), clock: @escaping @Sendable () -> Date = { Date() }) {
        self.api = api
        self.sessions = sessions
        self.passkeys = passkeys
        self.keys = keys
        self.records = records
        self.preferences = preferences
        self.secrets = secrets
        self.platform = platform
        self.residue = residue
        self.isAppClip = isAppClip
        self.serverCallTimeout = serverCallTimeout
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
    ///
    /// The App Clip registers a **request key only** and marks the device as a clip device; the full app registers
    /// all keys and then (best effort) revokes the person's clip devices, which are meant to be short-lived.
    @discardableResult
    public func enrollThisDevice(name: String) async throws -> DeviceRecord {
        guard let tokens = await sessions.tokens() else { throw APIError.sessionExpired }
        let challenge = try await api.beginDeviceEnrollment()
        let purposes: [DeviceKeyPurpose] = isAppClip ? [.request] : DeviceKeyPurpose.allCases
        let provisioned = try await DeviceKeyProvisioner(store: keys).provision(
            consumerId: tokens.consumerId, challenge: challenge.challenge, purposes: purposes)
        guard provisioned.registrations.contains(where: { $0.purpose == .request }) else { throw KeyStoreError.unavailable }
        let device = try await api.enrollDevice(DeviceEnrollmentPayload(
            name: String(name.prefix(64)), platform: platform, challenge: challenge.challenge,
            keys: provisioned.registrations, clipDevice: isAppClip))
        let record = DeviceRecord(deviceId: device.id, consumerId: tokens.consumerId, name: device.name,
                                  purposes: provisioned.registrations.map(\.purpose), enrolledAt: clock())
        try await records.save(record)
        if !isAppClip { await revokeClipDevices(except: device.id) }
        return record
    }

    /// Revokes App Clip devices (best effort, bounded): the clip's session is a stop-gap, not a trusted device.
    public func revokeClipDevices(except current: DeviceID) async {
        let api = self.api
        await bestEffort {
            guard let ids = try? await api.clipDeviceIDs() else { return }
            for id in ids where id != current { try? await api.revokeDevice(id) }
        }
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

    /// Signs out. In this order:
    /// 1. tell the server to **revoke this device** and end the session (best effort, bounded; the revocation is
    ///    device-signed, so it must happen while the keys still exist),
    /// 2. erase everything local: delivered notifications, Live Activities, watch context, dynamic categories,
    ///    then tokens, device record, Secure Enclave keys, preferences and every keychain item.
    public func signOut() async {
        let api = self.api
        if let record = try? await records.load() {
            await bestEffort { try? await api.revokeDevice(record.deviceId) }
        }
        await bestEffort { try? await api.logout() }
        await wipeLocalState()
    }

    public func deleteAccount() async throws {
        try await api.deleteAccount()
        await wipeLocalState()
    }

    /// Used on sign-out, account deletion and **device revocation** (the server no longer trusts this device).
    public func wipeLocalState() async {
        await residue.cleanAll()
        await sessions.clear()
        try? await records.clear()
        try? await keys.deleteAllKeys()
        try? secrets.deleteAll()
        preferences.removeAll()
    }

    /// Runs `work` but stops waiting after `serverCallTimeout`, so being offline never blocks sign-out.
    private func bestEffort(_ work: @escaping @Sendable () async -> Void) async {
        let timeout = serverCallTimeout
        await withTaskGroup(of: Void.self) { group in
            group.addTask { await work() }
            group.addTask { try? await Task.sleep(for: timeout) }
            await group.next()
            group.cancelAll()
        }
    }
}
