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
    let appAttest: any AppAttestProviding
    let skipsAttestationWhenUnsupported: Bool
    let clock: @Sendable () -> Date
    /// How long sign-out waits for each best-effort server call before giving up and erasing locally anyway.
    let serverCallTimeout: Duration

    /// - Parameters:
    ///   - residue: clears notifications, Live Activities, watch context and dynamic categories on wipe.
    ///   - isAppClip: the clip enrolls a request-key-only, marked device; the full app revokes clip devices after enrolling.
    ///   - appAttest: vouches for the enrolled keys (`appAttest {keyId, attestation}`). Where it is unsupported (Simulator), DEBUG builds
    ///     enroll without it and Release reports `AppAttestError.unsupported`.
    public init(api: any ViadereAPI, sessions: SessionManager, passkeys: any PasskeyService, keys: any DeviceKeyStore,
                records: any DeviceRecordStore, preferences: any PreferencesStore, secrets: any SecretStore,
                platform: DevicePlatform = .iOS, residue: any LocalResidueCleaner = NoLocalResidueCleaner(), isAppClip: Bool = false,
                appAttest: any AppAttestProviding = UnavailableAppAttest(),
                skipsAttestationWhenUnsupported: Bool = AppAttestPolicy.skipsWhenUnsupported,
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
        self.appAttest = appAttest
        self.skipsAttestationWhenUnsupported = skipsAttestationWhenUnsupported
        self.serverCallTimeout = serverCallTimeout
        self.clock = clock
    }

    // MARK: Device-first account (§2.5a)

    /// Creates a pseudonymous account **from this device**: no name, email, phone or passkey.
    ///
    /// 1. `POST /v1/accounts/enroll/begin`: a single-use challenge and the reserved account id.
    /// 2. This device's Secure Enclave keys are created and prove possession over that id and challenge; a fresh App Attest key attests
    ///    exactly that key list (`AppAttestBinding`), sent as `IntegrityEvidence` (`apple-app-attest`).
    /// 3. `POST /v1/accounts` creates the account, this device and a session already bound to it.
    ///
    /// The App Clip registers a request key only (a D0, 7-day device). Recovery credentials are optional and added afterwards
    /// (`makeRecoveryCodes`, `addRecoveryPasskey`).
    @discardableResult
    public func createAccount(deviceName: String?) async throws -> DeviceRecord {
        let opened = try await api.beginAccountEnrollment()
        let purposes: [DeviceKeyPurpose] = isAppClip ? [.request] : DeviceKeyPurpose.allCases
        let provisioned = try await DeviceKeyProvisioner(store: keys).provision(consumerId: opened.accountId, challenge: opened.challenge, purposes: purposes)
        guard provisioned.registrations.contains(where: { $0.purpose == .request }) else { throw KeyStoreError.unavailable }
        let evidence = try await EnrollmentAttester(provider: appAttest, skipsWhenUnsupported: skipsAttestationWhenUnsupported)
            .evidence(consumerId: opened.accountId, challenge: opened.challenge, keys: provisioned.registrations)
        let name = deviceName.map { String($0.trimmingCharacters(in: .whitespacesAndNewlines).prefix(64)) }.flatMap { $0.isEmpty ? nil : $0 }
        let created: AccountCreateResponse
        do {
            created = try await api.createAccount(AccountCreateRequest(
                ceremonyId: opened.ceremonyId, challenge: opened.challenge, platform: platform, deviceName: name, keys: provisioned.registrations,
                integrity: evidence.map(IntegrityEvidence.init(appleAppAttest:)), clientKind: isAppClip ? .appClip : .app))
        } catch {
            // Nothing was created on the server: the keys made for it are useless.
            try? await keys.deleteAllKeys()
            throw error
        }
        try await store(created.session)
        let record = DeviceRecord(deviceId: created.device.id, consumerId: created.accountId, name: created.device.name,
                                  purposes: provisioned.registrations.map(\.purpose), enrolledAt: clock())
        try await records.save(record)
        return record
    }

    /// "Protect your account": a new set of recovery codes, proven with this device's Face ID / Touch ID / passcode key. The old codes stop
    /// working. The codes are shown once by the caller and never stored.
    public func makeRecoveryCodes(reason: String = "Make recovery codes for your account") async throws -> RecoveryCodeSet {
        let ceremony = try await api.beginRecoveryCodes()
        let proof = try await ConfirmationService(api: api, keys: keys, records: records, clock: clock)
            .recoveryCredentialProof(ceremonyId: ceremony.ceremonyId, reason: reason)
        return try await api.regenerateRecoveryCodes(RecoveryCodesRegenerateRequest(ceremonyId: ceremony.ceremonyId, proof: proof))
    }

    /// "Protect your account": a passkey (synced by iCloud Keychain where it is on) as an optional recovery and sign-in credential. The
    /// system passkey sheet appears, then this device confirms with its own key.
    public func addRecoveryPasskey(reason: String = "Add a passkey to your account") async throws -> RecoveryPasskeyAdded {
        let options = try await api.beginRecoveryPasskey()
        let credential = try await passkeys.register(options: options)
        let proof = try await ConfirmationService(api: api, keys: keys, records: records, clock: clock)
            .recoveryCredentialProof(ceremonyId: options.ceremonyId, reason: reason)
        return try await api.finishRecoveryPasskey(RecoveryPasskeyFinishRequest(ceremonyId: options.ceremonyId, credential: credential, proof: proof))
    }

    // MARK: Sign-up / sign-in (passkey: an existing account, or discovery on a new device)

    /// Creates the account the passkey-first way (kept for older flows; new accounts use `createAccount`). Returns the account's **recovery codes**, which the server sends exactly once: the caller shows them
    /// (`RecoveryCodesViewModel`) and must not keep them. They are never stored here.
    @discardableResult
    public func signUp(displayName: String = "") async throws -> RecoveryCodeSet? {
        let name = String(displayName.trimmingCharacters(in: .whitespacesAndNewlines).prefix(64))
        let options = try await api.beginRegistration(displayName: name)
        let credential = try await passkeys.register(options: options)
        let grant = try await api.finishRegistration(PasskeyRegistrationFinishRequest(ceremonyId: options.ceremonyId, credential: credential))
        try await store(grant)
        return grant.recoveryCodes
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

    /// Creates this device's Secure Enclave keys and registers them with proof of possession **and of the account's passkey**.
    ///
    /// 1. `POST /v1/devices/enroll/begin` returns the challenge and WebAuthn assertion options over that same challenge.
    /// 2. Unless the server said `assertionOptional` (a session minted by sign-up or sign-in minutes ago, usable once),
    ///    the person performs a user-verified passkey assertion over it. `.setUpAgain` **always** does, whatever the server
    ///    says: a re-enrollment is an ordinary enrollment and a stolen session must not be able to replace a device.
    ///    `explain` is shown first, so the system sheet is never a surprise; answering `false` cancels (nothing is created).
    /// 3. Keys are created and registered (`POST /v1/devices`) with the assertion.
    ///
    /// The App Clip registers a **request key only** and marks the device as a clip device; the full app registers
    /// all keys and then (best effort) revokes the person's clip devices, which are meant to be short-lived.
    @discardableResult
    public func enrollThisDevice(name: String, purpose: EnrollmentPurpose = .firstDevice, replacing: DeviceID? = nil,
                                 explain: PasskeyExplainer? = nil) async throws -> DeviceRecord {
        guard let tokens = await sessions.tokens() else { throw APIError.sessionExpired }
        let challenge = try await api.beginDeviceEnrollment()
        let assertion = try await assertionIfNeeded(for: challenge, purpose: purpose, explain: explain)
        let purposes: [DeviceKeyPurpose] = isAppClip ? [.request] : DeviceKeyPurpose.allCases
        let provisioned = try await DeviceKeyProvisioner(store: keys).provision(
            consumerId: tokens.consumerId, challenge: challenge.challenge, purposes: purposes)
        guard provisioned.registrations.contains(where: { $0.purpose == .request }) else { throw KeyStoreError.unavailable }
        // Attest exactly the keys that are sent below (the clientData names the key list), with a fresh App Attest key.
        let attestation = try await EnrollmentAttester(provider: appAttest, skipsWhenUnsupported: skipsAttestationWhenUnsupported)
            .evidence(consumerId: tokens.consumerId, challenge: challenge.challenge, keys: provisioned.registrations)
        let device = try await api.enrollDevice(DeviceEnrollRequest(
            name: String(name.prefix(64)), platform: platform, challenge: challenge.challenge, keys: provisioned.registrations,
            assertion: assertion, clientKind: isAppClip ? .appClip : .app, appAttest: attestation,
            replacesDeviceId: replacing))
        // A live device that is being replaced stays valid on the server for now, so the caller's session stays bound to it: the
        // response carries a session bound to the NEW device, which becomes this installation's session.
        if let replacement = device.replacementSession { try await store(replacement) }
        let record = DeviceRecord(deviceId: device.id, consumerId: tokens.consumerId, name: device.name,
                                  purposes: provisioned.registrations.map(\.purpose), enrolledAt: clock())
        try await records.save(record)
        if !isAppClip { await revokeClipDevices(except: device.id) }
        return record
    }

    /// The passkey assertion for this enrollment, or `nil` when the server allows enrolling without one (never for a re-enrollment).
    private func assertionIfNeeded(for challenge: DeviceEnrollmentChallenge, purpose: EnrollmentPurpose,
                                   explain: PasskeyExplainer?) async throws -> PasskeyAssertionCredential? {
        let mustAssert = purpose == .setUpAgain || !challenge.assertionOptional
        guard mustAssert else { return nil }
        // A server that sent no options cannot be satisfied: say what is missing instead of enrolling without proof.
        guard let options = challenge.assertion else { throw APIError.server(status: 401, code: .passkeyAssertionRequired, message: "") }
        // The authenticator signs these bytes: they must be this enrollment's challenge, and verification must be required.
        guard options.challenge == challenge.challenge, options.userVerification == "required" else { throw PasskeyError.failed("options") }
        if let explain {
            let context: PasskeyExplanation.Context = isAppClip ? .appClip : (purpose == .setUpAgain ? .setUpAgain : .addDevice)
            guard await explain(.make(context)) else { throw PasskeyError.cancelled }
        }
        return try await passkeys.assert(options: options)
    }

    /// Revokes App Clip devices (best effort, bounded): the clip's session is a stop-gap, not a trusted device.
    public func revokeClipDevices(except current: DeviceID) async {
        let api = self.api
        await bestEffort {
            guard let devices = try? await api.devices() else { return }
            for device in devices where device.clipDevice && device.revokedAt == nil && device.id != current { try? await api.revokeDevice(device.id) }
        }
    }

    /// Replaces keys after invalidation (biometrics changed, restore). The new enrollment always needs a passkey assertion
    /// (`EnrollmentPurpose.setUpAgain`).
    ///
    /// The old device is **not** revoked first: the server cascades a device revoke to the caller's own session, which would make
    /// the enrollment 401 and sign the person out. The enrollment carries `replacesDeviceId` instead, and the server revokes the
    /// old device atomically after enrolling the new one.
    @discardableResult
    public func reenrollThisDevice(name: String, explain: PasskeyExplainer? = nil) async throws -> DeviceRecord {
        // Explain first, so declining leaves everything as it was; the system sheet follows during the enrollment itself.
        if let explain { guard await explain(.make(.setUpAgain)) else { throw PasskeyError.cancelled } }
        let old = try? await records.load()
        try? await records.clear()
        try? await keys.deleteAllKeys()
        return try await enrollThisDevice(name: name, purpose: .setUpAgain, replacing: old?.deviceId, explain: nil)
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
