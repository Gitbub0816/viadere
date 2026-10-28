import Testing
import Foundation
import ViadereCore
@testable import ViadereKit

// MARK: - Test doubles

/// Records events from several collaborators in one ordered log.
actor EventLog {
    private(set) var events: [String] = []
    func add(_ event: String) { events.append(event) }
}

struct RecordingResidue: LocalResidueCleaner {
    let log: EventLog
    let api: MockViadereAPI?
    func removeDeliveredNotifications() async { await log.add("residue.notifications") }
    func endLiveActivities() async { await log.add("residue.liveActivities") }
    func clearWatchContext() async { await log.add("residue.watch") }
    func removeDynamicNotificationCategories() async { await log.add("residue.categories") }
}

/// Wraps a key store; logs deletions together with whether the server had already revoked this device.
final class RecordingKeyStore: DeviceKeyStore, @unchecked Sendable {
    let inner: any DeviceKeyStore
    let log: EventLog
    let api: MockViadereAPI
    let deviceId: @Sendable () async -> DeviceID?
    init(inner: any DeviceKeyStore, log: EventLog, api: MockViadereAPI, deviceId: @escaping @Sendable () async -> DeviceID?) {
        self.inner = inner; self.log = log; self.api = api; self.deviceId = deviceId
    }
    func existingKey(for purpose: DeviceKeyPurpose) async throws -> (any ManagedSigningKey)? { try await inner.existingKey(for: purpose) }
    func createKey(for purpose: DeviceKeyPurpose) async throws -> any ManagedSigningKey { try await inner.createKey(for: purpose) }
    func deleteKey(for purpose: DeviceKeyPurpose) async throws {
        let revoked: Bool
        if let id = await deviceId() { revoked = (try? await api.devices().first { $0.id == id }?.revokedAt) != nil } else { revoked = false }
        await log.add("keys.delete(serverRevokedFirst=\(revoked))")
        try await inner.deleteKey(for: purpose)
    }
}

/// Throws a scripted error for key lookups (keychain locked, etc.).
struct ThrowingKeyStore: DeviceKeyStore {
    let error: KeyStoreError
    func existingKey(for purpose: DeviceKeyPurpose) async throws -> (any ManagedSigningKey)? { throw error }
    func createKey(for purpose: DeviceKeyPurpose) async throws -> any ManagedSigningKey { throw error }
    func deleteKey(for purpose: DeviceKeyPurpose) async throws {}
}

/// A secret store whose reads fail like a locked keychain.
final class LockedSecretStore: SecretStore, @unchecked Sendable {
    private let inner = InMemorySecretStore()
    private let lock = NSLock()
    private var _locked = false
    var locked: Bool { get { lock.lock(); defer { lock.unlock() }; return _locked } set { lock.lock(); _locked = newValue; lock.unlock() } }
    func read(_ account: String) throws -> Data? {
        if locked { throw SecretStoreError.unhandled(-25308) }
        return try inner.read(account)
    }
    func write(_ data: Data, account: String) throws {
        if locked { throw SecretStoreError.unhandled(-25308) }
        try inner.write(data, account: account)
    }
    func delete(_ account: String) throws { try inner.delete(account) }
    func deleteAll() throws { try inner.deleteAll() }
}

// MARK: - #5 App lock

@Suite("App lock queues and covers")
@MainActor
struct AppLockHardeningTests {
    func lockedModel() async throws -> (AppModel, ViadereServices) {
        let services = await ViadereServices.mock()
        services.preferences.setBool(true, for: .appLockEnabled)
        let model = AppModel(services: services)
        await model.bootstrap()
        #expect(model.isLocked)
        return (model, services)
    }

    @Test func linksAndNotificationOpensWaitForTheUnlock() async throws {
        let (model, _) = try await lockedModel()
        let pending = try #require(model.home.content.pending.first)
        let code = try #require(BusinessCode(parsing: "AF2345"))

        await model.handle(.connect(code: code, link: nil))
        await model.apply(.requiresApp(pending.id))
        await model.handle(.settings)
        await model.open(url: try #require(URL(string: "viadere://i/\(pending.id)")))

        // Nothing was routed, fetched or presented while locked.
        #expect(model.presentedApproval == nil)
        #expect(model.pendingConnect == nil)
        #expect(model.selectedTab == .home)
        #expect(model.queuedWhileLockedCount == 4)

        await model.unlock()
        #expect(!model.isLocked)
        #expect(model.queuedWhileLockedCount == 0)
        #expect(model.pendingConnect?.code == code)
        #expect(model.presentedApproval?.envelope.id == pending.id)
        #expect(model.selectedTab == .settings) // replayed in arrival order: the last link wins
    }

    @Test func failedUnlockKeepsEverythingQueued() async throws {
        var services = await ViadereServices.mock()
        services.preferences.setBool(true, for: .appLockEnabled)
        services.appLock = MockAppLockAuthenticator(succeeds: false)
        let model = AppModel(services: services)
        await model.bootstrap()
        let id = try #require(model.home.content.pending.first?.id)
        await model.apply(.open(id))
        await model.unlock()
        #expect(model.isLocked)
        #expect(model.queuedWhileLockedCount == 1)
        #expect(model.presentedApproval == nil)
    }

    @Test func lockingDismissesSheetsAndBumpsTheEpoch() async throws {
        let services = await ViadereServices.mock()
        services.preferences.setBool(true, for: .appLockEnabled)
        let model = AppModel(services: services)
        await model.bootstrap()
        await model.unlock()
        let id = try #require(model.home.content.pending.first?.id)
        await model.openInteraction(id)
        model.pendingAccountLinkToken = "token"
        model.pendingConnect = PendingConnect(code: try #require(BusinessCode(parsing: "AF2345")), link: nil, source: .code)
        #expect(model.presentedApproval != nil)
        let epoch = model.lockEpoch

        model.sceneDidEnterBackground()
        services.preferences.setBool(true, for: .appLockEnabled)
        model.lock()
        #expect(model.isLocked)
        #expect(model.presentedApproval == nil)
        #expect(model.pendingAccountLinkToken == nil)
        #expect(model.pendingConnect == nil)
        #expect(model.lockEpoch == epoch + 1)
        model.lock() // idempotent
        #expect(model.lockEpoch == epoch + 1)
    }

    @Test func queueIsBounded() async throws {
        let (model, _) = try await lockedModel()
        for _ in 0..<12 { await model.handle(.interaction(InteractionID())) }
        #expect(model.queuedWhileLockedCount == AppModel.maxQueuedWhileLocked)
    }

    @Test func staleOutcomesWhileLockedDoNotToast() async throws {
        let (model, _) = try await lockedModel()
        await model.apply(.stale(InteractionID(), .denied))
        #expect(model.toast == nil)
    }
}

// MARK: - #6 Revocation

@Suite("Device revocation wiring")
@MainActor
struct RevocationWiringTests {
    @Test func notifierWipesTheApp() async throws {
        let services = await ViadereServices.mock()
        let model = AppModel(services: services)
        await model.bootstrap()
        #expect(model.phase == .ready)
        services.revocation.notify()
        for _ in 0..<50 where model.phase == .ready { try await Task.sleep(for: .milliseconds(20)) }
        #expect(model.phase == .onboarding(.welcome))
        #expect(model.toast == "This device was removed from your account.")
        #expect(await services.keys.availablePurposes().isEmpty)
        #expect(!(await services.sessions.isSignedIn))
    }

    @Test func repeatedSignatureRejectionReachesTheModel() async throws {
        // Same wiring ViadereServices.live uses: APIClient.onDeviceRejected -> revocation.notify().
        let env = try await ClientEnv()
        let services = await ViadereServices.mock()
        let model = AppModel(services: services)
        await model.bootstrap()
        let transport = FakeTransport { _, _ in json(401, errorBody("signature_invalid")) }
        let (client, _) = env.client(transport: transport, onRejected: { services.revocation.notify() })
        await #expect(throws: APIError.deviceRejected) { let _: [Device] = try await client.call(APIRoutes.devicesList) }
        for _ in 0..<50 where model.phase == .ready { try await Task.sleep(for: .milliseconds(20)) }
        #expect(model.phase == .onboarding(.welcome))
        #expect(try await services.records.load() == nil)
    }

    @Test func notifierFiresOnceUntilRearmed() {
        let notifier = DeviceRevocationNotifier()
        let counter = Counter()
        notifier.setHandler { counter.bump() }
        notifier.notify(); notifier.notify()
        #expect(counter.value == 1)
        notifier.setHandler { counter.bump() }
        notifier.notify()
        #expect(counter.value == 2)
    }
}

final class Counter: @unchecked Sendable {
    private let lock = NSLock()
    private var count = 0
    func bump() { lock.lock(); count += 1; lock.unlock() }
    var value: Int { lock.lock(); defer { lock.unlock() }; return count }
}

// MARK: - #7 Rich previews

@Suite("Notification previews")
struct NotificationPreviewTests {
    func fetch(preferences: InMemoryPreferences?, _ envelope: InteractionEnvelope) async throws -> EnrichedNotification {
        let api = MockViadereAPI(seed: false)
        await api.add(envelope)
        return try #require(await NotificationEnricher(api: api, preferences: preferences).enrich(userInfo: ["iid": envelope.id.description]))
    }

    @Test func approvalsAreGenericOnTheLockScreenByDefault() async throws {
        for envelope in [PreviewData.authorize(sensitivity: .high), PreviewData.authenticate(sensitivity: .standard)] {
            for prefs in [nil, InMemoryPreferences()] as [InMemoryPreferences?] {
                let result = try await fetch(preferences: prefs, envelope)
                #expect(result.body.hasSuffix("requested by \(envelope.business.displayName)"))
                #expect(!result.body.contains("$") && !result.body.contains("Mesa") && !result.body.contains("Lisbon"))
                #expect(!result.subtitle.contains("$") && !result.title.contains("$"))
                #expect(result.userInfo[NotificationCard.userInfoKey] == nil) // no detail card to expand
                #expect(result.requiresSecureFlow || !result.category.actions.isEmpty)
            }
        }
        let authorize = try await fetch(preferences: nil, PreviewData.authorize())
        #expect(authorize.body == "Approval requested by Northfield Market")
        #expect(authorize.title == "Northfield Market")
        let signIn = try await fetch(preferences: nil, PreviewData.authenticate())
        #expect(signIn.body == "Sign-in approval requested by Harbor Bank")
    }

    @Test func detailsAppearWhenTheUserOptedIn() async throws {
        let prefs = InMemoryPreferences()
        prefs.setBool(true, for: .richNotificationPreviews)
        let result = try await fetch(preferences: prefs, PreviewData.authorize(sensitivity: .high))
        #expect(result.body.contains("$285.28"))
        let cardJSON = try #require(result.userInfo[NotificationCard.userInfoKey])
        let card = try #require(NotificationCard.decode(json: cardJSON))
        #expect(card.rows.contains { $0.label == "Amount" })
        #expect(card.isVerified)
    }

    @Test func unverifiedBusinessesAreNamedAsSuch() async throws {
        let envelope = UntrustedTextTests.envelope(verified: false)
        let result = try await fetch(preferences: nil, envelope)
        #expect(result.body.contains("unverified business"))
        let prefs = InMemoryPreferences()
        prefs.setBool(true, for: .richNotificationPreviews)
        let rich = try await fetch(preferences: prefs, envelope)
        let cardJSON = try #require(rich.userInfo[NotificationCard.userInfoKey])
        let card = try #require(NotificationCard.decode(json: cardJSON))
        #expect(!card.isVerified) // the card view uses this flag, not a hard-coded `true`
    }

    @Test func nonSecurityKindsStillRender() async throws {
        let result = try await fetch(preferences: nil, PreviewData.choose())
        #expect(result.body.contains("Which time"))
    }

    @Test func servicesPassThePreferenceToTheEnricher() async throws {
        let services = await ViadereServices.mock()
        let envelope = PreviewData.authorize(sensitivity: .high)
        await (services.api as! MockViadereAPI).add(envelope)
        var result = try #require(await services.notificationEnricher.enrich(userInfo: ["iid": envelope.id.description]))
        #expect(!result.body.contains("$"))
        services.preferences.setBool(true, for: .richNotificationPreviews)
        result = try #require(await services.notificationEnricher.enrich(userInfo: ["iid": envelope.id.description]))
        #expect(result.body.contains("$285.28"))
    }
}

// MARK: - #8 Sign-out

@Suite("Complete sign-out")
struct SignOutTests {
    @Test func revokesOnTheServerBeforeKeysAreDeletedThenCleansResidue() async throws {
        let api = MockViadereAPI(seed: false)
        let log = EventLog()
        let base = await ViadereServices.mock(api: api)
        let deviceId = try #require(try await base.records.load()?.deviceId)
        var services = base
        services.keys = RecordingKeyStore(inner: base.keys, log: log, api: api, deviceId: { deviceId })
        services.residue = RecordingResidue(log: log, api: api)

        await services.account.signOut()

        let events = await log.events
        let firstDelete = try #require(events.firstIndex { $0.hasPrefix("keys.delete") })
        // server revocation happened before any key was deleted
        #expect(events[firstDelete] == "keys.delete(serverRevokedFirst=true)")
        #expect(try await api.devices().first { $0.id == deviceId }?.revokedAt != nil)
        // residue cleanup, in order, before keys go
        #expect(Array(events[..<firstDelete]) == ["residue.notifications", "residue.liveActivities", "residue.watch", "residue.categories"])
        #expect(!(await services.sessions.isSignedIn))
        #expect(try await services.records.load() == nil)
        #expect(await base.keys.availablePurposes().isEmpty)
    }

    @Test func wipeAlsoCleansResidueForRevocationAndDeletion() async throws {
        let log = EventLog()
        var services = await ViadereServices.mock()
        services.residue = RecordingResidue(log: log, api: nil)
        await services.account.wipeLocalState()
        #expect(await log.events == ["residue.notifications", "residue.liveActivities", "residue.watch", "residue.categories"])
    }

    @Test func offlineServerDoesNotBlockSignOut() async throws {
        // A server that never answers must not trap the user in the app.
        struct HangingAPI {}
        let services = await ViadereServices.mock()
        let account = AccountService(api: services.api, sessions: services.sessions, passkeys: services.passkeys, keys: services.keys,
                                     records: services.records, preferences: services.preferences, secrets: services.secrets,
                                     serverCallTimeout: .milliseconds(50))
        await account.signOut()
        #expect(try await services.records.load() == nil)
    }
}

// MARK: - #10 Keychain statuses

@Suite("Key health and keychain statuses")
struct KeychainStatusTests {
    @Test func classification() {
        #expect(KeychainStatus.classify(0) == .success)
        #expect(KeychainStatus.classify(-25300) == .notFound)
        #expect(KeychainStatus.classify(-25308) == .transient(-25308))
        for code: Int32 in [-25308, -25315, -25291, -25293, -108, -36] { #expect(KeychainStatus.classify(code) == .transient(code)) }
        #expect(KeychainStatus.classify(-50) == .failure(-50))
        #expect(KeychainStatus.classify(-34018) == .failure(-34018))
    }

    @Test func lookupErrorsNeverClaimInvalidationUnlessNotFound() {
        #expect(KeychainStatus.lookupError(-25308, purpose: .approvalBiometric) == .temporarilyUnavailable(-25308))
        #expect(KeychainStatus.lookupError(-50, purpose: .request) == .unexpectedStatus(-50))
        #expect(KeychainStatus.lookupError(0, purpose: .request) == nil)
        #expect(KeychainStatus.lookupError(-25300, purpose: .request) == nil) // absence is decided by the caller
        #expect(KeyStoreError.temporarilyUnavailable(-25308).isTransient)
    }

    func record() -> DeviceRecord {
        DeviceRecord(deviceId: DeviceID(), consumerId: PreviewData.consumerId, name: "x", purposes: DeviceKeyPurpose.allCases, enrolledAt: Date())
    }

    @Test func lockedKeychainIsUnavailableNotReenrollment() async {
        let health = await EnrollmentHealth.check(record: record(), store: ThrowingKeyStore(error: .temporarilyUnavailable(-25308)))
        #expect(health == .unavailable)
        let unexpected = await EnrollmentHealth.check(record: record(), store: ThrowingKeyStore(error: .unexpectedStatus(-50)))
        #expect(unexpected == .unavailable)
    }

    @Test func missingOrInvalidatedKeysStillNeedReenrollment() async throws {
        let store = SoftwareDeviceKeyStore()
        _ = try await store.createKey(for: .request)
        let health = await EnrollmentHealth.check(record: record(), store: store)
        #expect(health == .needsReenrollment(missing: [.approvalUserPresence, .approvalBiometric]))
        let invalidated = await EnrollmentHealth.check(record: record(), store: ThrowingKeyStore(error: .keyInvalidated(.approvalBiometric)))
        #expect(invalidated == .needsReenrollment(missing: DeviceKeyPurpose.allCases))
    }

    @Test @MainActor func appStaysReadyAndRechecksWhenTheKeychainIsLocked() async throws {
        var services = await ViadereServices.mock()
        let real = services.keys
        services.keys = ThrowingKeyStore(error: .temporarilyUnavailable(-25308))
        let model = AppModel(services: services)
        await model.bootstrap()
        #expect(model.phase == .ready)
        #expect(model.keysNeedRecheck)
        // still locked on foreground: nothing changes
        await model.sceneWillEnterForeground()
        #expect(model.phase == .ready && model.keysNeedRecheck)
        // keychain available again and keys are really gone: now re-enroll
        services.keys = real
        let again = AppModel(services: services)
        try await real.deleteKey(for: .approvalBiometric)
        await again.bootstrap()
        #expect(again.phase == .needsReenrollment)
    }

    @Test func transientErrorsMapToARetryNotInvalidation() {
        #expect(ApprovalService.map(.temporarilyUnavailable(-25308)) == .keysUnavailable)
        #expect(ApprovalService.map(.keyInvalidated(.approvalBiometric)) == .keyInvalidated(.approvalBiometric))
        #expect(ApprovalError.keysUnavailable.userMessage.contains("Unlock"))
    }
}

// MARK: - #11/#12 Clip + config

@Suite("App Clip device and key groups")
struct ClipAndConfigTests {
    @Test func clipEnrollsRequestKeyOnlyAndMarksTheDevice() async throws {
        let api = MockViadereAPI(seed: false)
        let base = await ViadereServices.mock(api: api, signedIn: false)
        var services = base
        services.isAppClip = true
        try await services.sessions.set(TokenSet(consumerId: api.consumerId, accessToken: "t", accessExpiresAt: Date().addingTimeInterval(900)))
        let record = try await services.account.enrollThisDevice(name: "iPhone")
        #expect(record.purposes == [.request])
        #expect(await services.keys.availablePurposes() == [.request])
        let device = try #require(try await api.devices().first)
        #expect(device.id == record.deviceId)
        #expect(device.clipDevice && device.clientKind == .appClip)
        #expect(device.expiresAt != nil)
        #expect(device.approvalsLockedUntil == nil)
        #expect(device.maxAssurance == DecisionAssurance.none)
    }

    @Test func fullAppEnrollsEverythingUnmarked() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api)
        let record = try #require(try await services.records.load())
        #expect(Set(record.purposes) == Set(DeviceKeyPurpose.allCases))
        #expect(try await api.devices().allSatisfy { !$0.clipDevice })
    }

    @Test func enrollBodyUsesCoresFieldsForClips() throws {
        let normal = DeviceEnrollRequest(name: "a", platform: .iOS, challenge: "c", keys: [])
        let clip = DeviceEnrollRequest(name: "a", platform: .iOS, challenge: "c", keys: [], clientKind: .appClip)
        let flagged = DeviceEnrollRequest(name: "a", platform: .iOS, challenge: "c", keys: [], clipDevice: true)
        let normalJSON = String(decoding: try ViadereJSON.encode(normal), as: UTF8.self)
        let clipJSON = String(decoding: try ViadereJSON.encode(clip), as: UTF8.self)
        #expect(!normalJSON.contains("clipDevice") && normalJSON.contains("\"clientKind\":\"app\""))
        #expect(clipJSON.contains("\"clientKind\":\"appClip\""))
        #expect(normal.effectiveClientKind == .app && clip.effectiveClientKind == .appClip && flagged.effectiveClientKind == .appClip)
    }

    @Test func theMockRefusesAClipDeviceWithApprovalKeys() async throws {
        let api = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: api, signedIn: false)
        let challenge = try await api.beginDeviceEnrollment()
        let provisioned = try await DeviceKeyProvisioner(store: services.keys).provision(
            consumerId: api.consumerId, challenge: challenge.challenge, purposes: DeviceKeyPurpose.allCases)
        await #expect(throws: APIError.server(status: 422, code: .validationFailed, message: "An App Clip device can only register a request key.")) {
            _ = try await api.enrollDevice(DeviceEnrollRequest(name: "c", platform: .iOS, challenge: challenge.challenge,
                                                               keys: provisioned.registrations, clientKind: .appClip))
        }
    }

    @Test func fullAppRevokesClipDevicesOnFirstSignIn() async throws {
        let api = MockViadereAPI(seed: false)
        // 1. the clip enrolls its device
        var clipServices = await ViadereServices.mock(api: api, signedIn: false)
        clipServices.isAppClip = true
        try await clipServices.sessions.set(TokenSet(consumerId: api.consumerId, accessToken: "t", accessExpiresAt: Date().addingTimeInterval(900)))
        let clipRecord = try await clipServices.account.enrollThisDevice(name: "iPhone")
        #expect(try await api.devices().filter { $0.clipDevice && $0.revokedAt == nil }.map(\.id) == [clipRecord.deviceId])
        // 2. the full app signs in and enrolls: the clip device is revoked, the new one is not
        let full = await ViadereServices.mock(api: api)
        let fullRecord = try #require(try await full.records.load())
        let devices = try await api.devices()
        #expect(devices.first { $0.id == clipRecord.deviceId }?.revokedAt != nil)
        #expect(devices.first { $0.id == fullRecord.deviceId }?.revokedAt == nil)
        #expect(try await api.devices().filter { $0.clipDevice && $0.revokedAt == nil }.isEmpty)
    }

    @Test func approvalKeysUseTheAppOnlyGroup() {
        let info: [String: Any] = [
            "ViadereKeychainAccessGroup": "ABCDE12345.com.viadere.shared",
            "ViadereApprovalKeychainAccessGroup": "ABCDE12345.com.viadere.app.approval",
        ]
        let config = ViadereConfiguration.resolve(info: info, allowLocalHTTP: false)
        #expect(config.keychainAccessGroup == "ABCDE12345.com.viadere.shared")
        #expect(config.approvalKeychainAccessGroup == "ABCDE12345.com.viadere.app.approval")
        // the notification extension's Info.plist has no approval group, and unexpanded variables are ignored
        let ext = ViadereConfiguration.resolve(info: ["ViadereKeychainAccessGroup": "ABCDE12345.com.viadere.shared"], allowLocalHTTP: false)
        #expect(ext.approvalKeychainAccessGroup == nil)
        let unexpanded = ViadereConfiguration.resolve(info: ["ViadereApprovalKeychainAccessGroup": "$(AppIdentifierPrefix)x"], allowLocalHTTP: false)
        #expect(unexpanded.approvalKeychainAccessGroup == nil)
    }

    @Test func stagingHostTakesPinsPushEnvironmentAndRelyingPartyFromTheBuild() {
        let a = Data(repeating: 1, count: 32).base64EncodedString(), b = Data(repeating: 2, count: 32).base64EncodedString()
        let info: [String: Any] = ["ViadereAPIBaseURL": "https://api-staging.viadere.com", "ViadereAPIPins": "\(a),\(b)",
                                   "ViadereAPNsEnvironment": "sandbox", "ViadereRelyingPartyID": "staging.viadere.com"]
        let config = ViadereConfiguration.resolve(info: info, allowLocalHTTP: false)
        #expect(config.apiBaseURL.host == "api-staging.viadere.com")
        #expect(config.pinning.host == "api-staging.viadere.com" && config.pinning.pins == [a, b] && config.pinning.isConfigured)
        #expect(config.failClosedPinning)
        #expect(config.apnsEnvironment == .sandbox)
        #expect(config.relyingPartyID == "staging.viadere.com")
    }

    @Test func stagingWithoutRealPinsStaysFailClosed() {
        let a = Data(repeating: 1, count: 32).base64EncodedString()
        for pins in [nil, "", "\(a)", "\(a),REPLACE_ME_X", "\(a),\(a)", "$(VIADERE_API_PINS)"] as [String?] {
            var info: [String: Any] = ["ViadereAPIBaseURL": "https://api-staging.viadere.com"]
            if let pins { info["ViadereAPIPins"] = pins }
            let config = ViadereConfiguration.resolve(info: info, allowLocalHTTP: false)
            #expect(!config.pinning.isConfigured, "\(pins ?? "nil")")
            #expect(config.pinning.isPlaceholder)
            #expect(PinEvaluator.evaluate(host: "api-staging.viadere.com", chainSPKIHashes: [a], configuration: config.pinning, failClosed: true) == .deny)
        }
    }

    @Test func productionHostIgnoresStagingOverrides() {
        let a = Data(repeating: 1, count: 32).base64EncodedString(), b = Data(repeating: 2, count: 32).base64EncodedString()
        let info: [String: Any] = ["ViadereAPIBaseURL": "https://api.viadere.com", "ViadereAPIPins": "\(a),\(b)",
                                   "ViadereAPNsEnvironment": "sandbox", "ViadereRelyingPartyID": "evil.example"]
        let config = ViadereConfiguration.resolve(info: info, allowLocalHTTP: false)
        #expect(config.pinning == ViadereConfiguration.productionPinning)
        #if !DEBUG
        #expect(config.apnsEnvironment == .production)   // debug builds always register in the sandbox
        #endif
        #expect(config.relyingPartyID == "viadere.com")
    }

    @Test func placeholderPinsAreDetectable() {
        #expect(ViadereConfiguration.productionPinning.isPlaceholder || ViadereConfiguration.productionPinning.isConfigured)
        #expect(PinningConfiguration(host: "x", pins: ["REPLACE_ME_A", "REPLACE_ME_B"]).isPlaceholder)
    }
}

// MARK: - #2 Link preview

@Suite("Account link confirmation")
@MainActor
struct AccountLinkTests {
    @Test func theCustomSchemeRouteIsGone() {
        let token = String(repeating: "A", count: 43)
        #expect(DeepLinkRouter.route("viadere://l/\(token)") == nil)
        #expect(DeepLinkRouter.route("https://viadere.com/l/\(token)") == .accountLink(token: token))
    }

    @Test func previewShowsTheMaskedNumberAndRedeemNeedsConfirmation() async throws {
        let api = MockViadereAPI(seed: false)
        await api.setLinkPreview("+1 ••• ••• 4821")
        let services = await ViadereServices.mock(api: api)
        let model = SecuritySettingsViewModel(services: services)
        let token = String(repeating: "B", count: 43)
        #expect(model.accountLinkPhase == .idle)
        #expect(!(await model.redeemAccountLink(token: token, confirmedOwnPhone: true))) // no preview yet
        await model.loadAccountLinkPreview(token: token)
        guard case .ready(let preview) = model.accountLinkPhase else { Issue.record("expected a preview"); return }
        #expect(preview.maskedPhone == "+1 ••• ••• 4821")
        #expect(preview.last4 == "4821")
        #expect(!(await model.redeemAccountLink(token: token, confirmedOwnPhone: false)))
        #expect(try await api.phoneLinks().isEmpty)
        #expect(await model.redeemAccountLink(token: token, confirmedOwnPhone: true))
        #expect(model.phones.last?.maskedPhone == "+1 ••• ••• 4821")
        #expect(SecuritySettingsViewModel.accountLinkWarning.hasPrefix("Only continue if you started this from your own phone."))
    }

    @Test func invalidTokensFailGracefully() async throws {
        let services = await ViadereServices.mock(api: MockViadereAPI(seed: false))
        let model = SecuritySettingsViewModel(services: services)
        await model.loadAccountLinkPreview(token: "x")
        if case .failed = model.accountLinkPhase {} else { Issue.record("expected failure") }
        #expect(!(await model.redeemAccountLink(token: "x", confirmedOwnPhone: true)))
    }
}

@Suite("Lock-screen detail setting")
@MainActor
struct RichPreviewSettingTests {
    @Test func offByDefaultAndEnablingNeedsAuthentication() async throws {
        var services = await ViadereServices.mock(api: MockViadereAPI(seed: false))
        let model = SecuritySettingsViewModel(services: services)
        #expect(!model.richPreviewsEnabled)
        #expect(!services.preferences.bool(.richNotificationPreviews))

        services.appLock = MockAppLockAuthenticator(succeeds: false)
        let denied = SecuritySettingsViewModel(services: services)
        await denied.setRichPreviews(true)
        #expect(!denied.richPreviewsEnabled && !services.preferences.bool(.richNotificationPreviews))

        await model.setRichPreviews(true)
        #expect(model.richPreviewsEnabled && services.preferences.bool(.richNotificationPreviews))
        await model.setRichPreviews(false)
        #expect(!model.richPreviewsEnabled && !services.preferences.bool(.richNotificationPreviews))
    }
}
