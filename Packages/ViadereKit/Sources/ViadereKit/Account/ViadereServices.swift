import Foundation
import ViadereCore

/// The object graph, built once at launch and shared by the app, extensions and previews.
public struct ViadereServices: Sendable {
    public var configuration: ViadereConfiguration
    public var api: any ViadereAPI
    public var sessions: SessionManager
    public var keys: any DeviceKeyStore
    public var records: any DeviceRecordStore
    public var preferences: any PreferencesStore
    public var secrets: any SecretStore
    public var passkeys: any PasskeyService
    public var notificationPermission: any NotificationPermissionService
    public var appLock: any AppLockAuthenticator
    public var clock: @Sendable () -> Date

    public var account: AccountService {
        AccountService(api: api, sessions: sessions, passkeys: passkeys, keys: keys, records: records,
                       preferences: preferences, secrets: secrets, clock: clock)
    }

    public var approvals: ApprovalService { ApprovalService(api: api, keys: keys, records: records, clock: clock) }

    public var notificationHandler: NotificationActionHandler {
        NotificationActionHandler(api: api, approvals: approvals, clock: clock)
    }

    public var notificationEnricher: NotificationEnricher { NotificationEnricher(api: api, clock: clock) }

    public init(configuration: ViadereConfiguration, api: any ViadereAPI, sessions: SessionManager, keys: any DeviceKeyStore,
                records: any DeviceRecordStore, preferences: any PreferencesStore, secrets: any SecretStore,
                passkeys: any PasskeyService, notificationPermission: any NotificationPermissionService,
                appLock: any AppLockAuthenticator, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.configuration = configuration
        self.api = api
        self.sessions = sessions
        self.keys = keys
        self.records = records
        self.preferences = preferences
        self.secrets = secrets
        self.passkeys = passkeys
        self.notificationPermission = notificationPermission
        self.appLock = appLock
        self.clock = clock
    }

    // MARK: Live

    #if canImport(Security)
    /// The production graph: Keychain-backed storage, Secure Enclave keys (software fallback only in DEBUG on the
    /// simulator), pinned URLSession transport, device-signed API client with single-flight refresh.
    /// - Parameters:
    ///   - passkeys: supply `ApplePasskeyService()` from the iOS app; extensions don't need one.
    public static func live(configuration: ViadereConfiguration, passkeys: any PasskeyService = UnavailablePasskeyService(),
                            notificationPermission: any NotificationPermissionService = MockNotificationPermissionService(result: false),
                            appLock: any AppLockAuthenticator = MockAppLockAuthenticator(succeeds: false)) -> ViadereServices {
        let secrets = KeychainSecretStore(service: configuration.keychainService, accessGroup: configuration.keychainAccessGroup)
        let keys = makeKeyStore(configuration: configuration, secrets: secrets)
        let records = SecretDeviceRecordStore(secrets: secrets)
        let tokens = SecretTokenStore(secrets: secrets)
        let transport = URLSessionTransport(configuration: configuration)
        let signer = DeviceRequestSigner(records: records, keys: keys)
        let executor = RequestExecutor(baseURL: configuration.apiBaseURL, transport: transport, signer: signer)
        // The app and its extensions rotate the same session; serialize that across processes (single-use refresh tokens).
        let lock: any CrossProcessLock = FileManager.default
            .containerURL(forSecurityApplicationGroupIdentifier: configuration.appGroupID)
            .map { FileCrossProcessLock(url: $0.appendingPathComponent("session-refresh.lock")) } ?? NoCrossProcessLock()
        let sessions = SessionManager(store: tokens, refresher: APITokenRefresher(executor: executor), lock: lock)
        let client = APIClient(executor: executor, sessions: sessions)
        return ViadereServices(configuration: configuration, api: LiveViadereAPI(client: client), sessions: sessions, keys: keys,
                               records: records, preferences: UserDefaultsPreferences(suiteName: configuration.appGroupID),
                               secrets: secrets, passkeys: passkeys, notificationPermission: notificationPermission, appLock: appLock)
    }

    static func makeKeyStore(configuration: ViadereConfiguration, secrets: any SecretStore) -> any DeviceKeyStore {
        #if targetEnvironment(simulator)
        #if DEBUG
        return SoftwareDeviceKeyStore(secrets: secrets)
        #else
        return UnavailableKeyStore()
        #endif
        #else
        return SecureEnclaveKeyStore(accessGroup: configuration.keychainAccessGroup)
        #endif
    }
    #endif

    // MARK: Mock

    #if DEBUG
    /// An in-memory world for previews, tests and demos. Uses software keys, so it is compiled out of release builds.
    public static func mock(api: MockViadereAPI = MockViadereAPI(), signedIn: Bool = true,
                            unsupportedKeys: Set<DeviceKeyPurpose> = [],
                            clock: @escaping @Sendable () -> Date = { Date() }) async -> ViadereServices {
        let secrets = InMemorySecretStore()
        let keys = SoftwareDeviceKeyStore(secrets: InMemorySecretStore(), unsupported: unsupportedKeys)
        let records = SecretDeviceRecordStore(secrets: secrets)
        let tokens = SecretTokenStore(secrets: secrets)
        let sessions = SessionManager(store: tokens, refresher: FailingRefresher(), clock: clock)
        let services = ViadereServices(configuration: .local, api: api, sessions: sessions, keys: keys, records: records,
                                       preferences: InMemoryPreferences(), secrets: secrets, passkeys: MockPasskeyService(),
                                       notificationPermission: MockNotificationPermissionService(), appLock: MockAppLockAuthenticator(),
                                       clock: clock)
        if signedIn {
            let consumerId = api.consumerId
            try? await sessions.set(TokenSet(consumerId: consumerId, accessToken: "mock", accessExpiresAt: clock().addingTimeInterval(3_600)))
            _ = try? await services.account.enrollThisDevice(name: "Preview iPhone")
            services.preferences.setBool(true, for: .onboardingComplete)
        }
        return services
    }
    #endif
}

/// Used when the process (e.g. an extension) can't present passkey UI.
public struct UnavailablePasskeyService: PasskeyService {
    public init() {}
    public func register(options: PasskeyRegistrationOptions) async throws -> PasskeyRegistrationCredential { throw PasskeyError.unsupported }
    public func assert(options: PasskeyAssertionOptions) async throws -> PasskeyAssertionCredential { throw PasskeyError.unsupported }
}

/// Release builds on the simulator (never shipped): no keys at all, so nothing can be signed.
public struct UnavailableKeyStore: DeviceKeyStore {
    public init() {}
    public func existingKey(for purpose: DeviceKeyPurpose) async throws -> (any ManagedSigningKey)? { throw KeyStoreError.unavailable }
    public func createKey(for purpose: DeviceKeyPurpose) async throws -> any ManagedSigningKey { throw KeyStoreError.unavailable }
    public func deleteKey(for purpose: DeviceKeyPurpose) async throws {}
}

struct FailingRefresher: TokenRefresher {
    func refresh(current: TokenSet?) async throws -> TokenSet { throw APIError.sessionExpired }
}
