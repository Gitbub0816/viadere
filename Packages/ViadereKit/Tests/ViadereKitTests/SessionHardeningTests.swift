import Testing
import Foundation
import ViadereCore
@testable import ViadereKit

/// A refresher that suspends until released, so tests can interleave sign-out with an in-flight refresh.
actor GatedRefresher: TokenRefresher {
    private(set) var calls = 0
    private var gate: CheckedContinuation<Void, Never>?
    private var opened = false
    private var waiting = false

    func refresh(current: TokenSet?) async throws -> TokenSet {
        calls += 1
        waiting = true
        if !opened { await withCheckedContinuation { gate = $0 } }
        return TokenSet(consumerId: PreviewData.consumerId, accessToken: "resurrected", accessExpiresAt: Date().addingTimeInterval(900), refreshToken: "r-new")
    }
    var isWaiting: Bool { waiting && !opened }
    func open() { opened = true; gate?.resume(); gate = nil }
}

/// A lock whose critical sections run but whose lease can be contended on purpose.
final class ContendedLock: CrossProcessLock, @unchecked Sendable {
    private let state = NSLock()
    private var leased = false
    private var denials = 0
    var leaseDenials: Int { state.withLock { denials } }
    func withLock<T: Sendable>(_ body: @Sendable () async throws -> T) async throws -> T { try await body() }
    func acquireRefreshLease(ttl: TimeInterval) async throws -> RefreshLease? {
        state.withLock {
            if leased { denials += 1; return nil }
            leased = true
            return RefreshLease()
        }
    }
    func releaseRefreshLease(_ lease: RefreshLease) async { state.withLock { leased = false } }
    func holdLease() { state.withLock { leased = true } }
}

@Suite("Session generation and cross-process safety")
struct SessionHardeningTests {
    static func tempLockURL() -> URL { FileManager.default.temporaryDirectory.appendingPathComponent("viadere-lock-\(UUID().uuidString)") }

    func expiredStore(refresh: String? = "r0") async throws -> SecretTokenStore {
        let store = SecretTokenStore(secrets: InMemorySecretStore())
        try await store.save(TokenSet(consumerId: PreviewData.consumerId, accessToken: "old", accessExpiresAt: Date().addingTimeInterval(-10), refreshToken: refresh))
        return store
    }

    @Test func aClearedSessionIsNotResurrectedByAnInFlightRefresh() async throws {
        let store = try await expiredStore()
        let refresher = GatedRefresher()
        let sessions = SessionManager(store: store, refresher: refresher)
        let pending = Task { try await sessions.validAccessToken() }
        for _ in 0..<200 where !(await refresher.isWaiting) { try await Task.sleep(for: .milliseconds(10)) }
        #expect(await refresher.isWaiting)

        await sessions.clear()                // sign-out while the refresh is on the network
        await refresher.open()                // the server answers afterwards
        await #expect(throws: APIError.sessionExpired) { _ = try await pending.value }

        #expect(await sessions.tokens() == nil)
        #expect(try await store.load() == nil)       // not saved
        #expect(!(await sessions.isSignedIn))
    }

    @Test func aNewSignInSurvivesTheOldSessionsRefresh() async throws {
        let store = try await expiredStore()
        let refresher = GatedRefresher()
        let sessions = SessionManager(store: store, refresher: refresher)
        let pending = Task { try await sessions.validAccessToken() }
        for _ in 0..<200 where !(await refresher.isWaiting) { try await Task.sleep(for: .milliseconds(10)) }
        let signedIn = TokenSet(consumerId: PreviewData.consumerId, accessToken: "new-login", accessExpiresAt: Date().addingTimeInterval(900), refreshToken: "r-login")
        try await sessions.set(signedIn)
        await refresher.open()
        _ = try? await pending.value
        #expect(await sessions.tokens()?.accessToken == "new-login")
        #expect(try await store.load()?.accessToken == "new-login")
        #expect(try await store.load()?.refreshToken == "r-login")
    }

    @Test func aSignOutInAnotherProcessIsNotOverwritten() async throws {
        // Process A starts refreshing; process B (the app) signs out by clearing the shared store; A must not write.
        let store = try await expiredStore()
        let refresher = GatedRefresher()
        let sessions = SessionManager(store: store, refresher: refresher)
        let pending = Task { try await sessions.validAccessToken() }
        for _ in 0..<200 where !(await refresher.isWaiting) { try await Task.sleep(for: .milliseconds(10)) }
        try await store.clear()
        await refresher.open()
        await #expect(throws: APIError.sessionExpired) { _ = try await pending.value }
        #expect(try await store.load() == nil)
    }

    @Test func concurrentManagersSpendTheRefreshTokenOnce() async throws {
        let store = try await expiredStore()
        let url = Self.tempLockURL()
        defer { try? FileManager.default.removeItem(at: url); try? FileManager.default.removeItem(atPath: url.path + ".lease") }
        let refresher = CountingRefresher(delay: .milliseconds(150))
        let managers = (0..<4).map { _ in SessionManager(store: store, refresher: refresher, lock: FileCrossProcessLock(url: url)) }
        let tokens = try await withThrowingTaskGroup(of: String.self) { group in
            for manager in managers { group.addTask { try await manager.validAccessToken() } }
            var out: [String] = []
            for try await token in group { out.append(token) }
            return out
        }
        #expect(Set(tokens).count == 1)
        #expect(await refresher.calls == 1)
        #expect(try await store.load()?.accessToken == tokens.first)
    }

    @Test func theFileLockIsNotHeldDuringTheNetworkCall() async throws {
        let store = try await expiredStore()
        let url = Self.tempLockURL()
        defer { try? FileManager.default.removeItem(at: url); try? FileManager.default.removeItem(atPath: url.path + ".lease") }
        let refresher = GatedRefresher()
        let sessions = SessionManager(store: store, refresher: refresher, lock: FileCrossProcessLock(url: url, timeout: 0.3))
        let pending = Task { try await sessions.validAccessToken() }
        for _ in 0..<200 where !(await refresher.isWaiting) { try await Task.sleep(for: .milliseconds(10)) }
        // While the request is "on the network" another party can take the short lock immediately.
        let other = FileCrossProcessLock(url: url, timeout: 0.3)
        let ran = try await other.withLock { true }
        #expect(ran)
        // ...but not the refresh lease, which is still held.
        #expect(try await other.acquireRefreshLease(ttl: 5) == nil)
        await refresher.open()
        #expect(try await pending.value == "resurrected")
        // lease released afterwards
        #expect(try await other.acquireRefreshLease(ttl: 5) != nil)
    }

    @Test func failsSafeWhenTheLockFileCannotBeOpened() async throws {
        let store = try await expiredStore()
        let bad = URL(fileURLWithPath: "/nonexistent-dir-\(UUID().uuidString)/session-refresh.lock")
        let refresher = CountingRefresher()
        let sessions = SessionManager(store: store, refresher: refresher, lock: FileCrossProcessLock(url: bad))
        await #expect(throws: APIError.transport("refresh-lock-unavailable")) { _ = try await sessions.validAccessToken() }
        #expect(await refresher.calls == 0)                        // no refresh without mutual exclusion
        #expect(try await store.load()?.refreshToken == "r0")       // and the session is kept for a retry
        #expect((APIError.transport("refresh-lock-unavailable")).userMessage.contains("try again"))

        let unavailable = SessionManager(store: store, refresher: refresher, lock: UnavailableCrossProcessLock())
        await #expect(throws: APIError.self) { _ = try await unavailable.validAccessToken() }
        #expect(await refresher.calls == 0)
    }

    @Test func lockAcquisitionTimesOut() async throws {
        let url = Self.tempLockURL()
        defer { try? FileManager.default.removeItem(at: url) }
        let holder = FileCrossProcessLock(url: url, timeout: 2)
        let contender = FileCrossProcessLock(url: url, timeout: 0.15)
        let gate = Counter()
        async let held: Void = holder.withLock {
            gate.bump()
            try await Task.sleep(for: .milliseconds(600))
        }
        for _ in 0..<100 where gate.value == 0 { try await Task.sleep(for: .milliseconds(10)) }
        let started = Date()
        await #expect(throws: APIError.transport("refresh-lock-timeout")) { try await contender.withLock { 1 } }
        #expect(Date().timeIntervalSince(started) < 0.5)
        try await held
    }

    @Test func waitsForAnotherProcessesLeaseThenAdoptsItsResult() async throws {
        let store = try await expiredStore()
        let lock = ContendedLock()
        lock.holdLease() // "another process" is refreshing
        let refresher = CountingRefresher()
        let sessions = SessionManager(store: store, refresher: refresher, lock: lock)
        let pending = Task { try await sessions.validAccessToken() }
        // Wait for the condition, not a fixed time: on a loaded machine the task may reach the lock late.
        for _ in 0..<500 where lock.leaseDenials == 0 { try await Task.sleep(for: .milliseconds(10)) }
        #expect(lock.leaseDenials >= 1)
        #expect(await refresher.calls == 0)
        // the other process finishes: it stores a fresh session and drops the lease
        try await store.save(TokenSet(consumerId: PreviewData.consumerId, accessToken: "from-other-process",
                                      accessExpiresAt: Date().addingTimeInterval(900), refreshToken: "r1"))
        #expect(try await pending.value == "from-other-process")
        #expect(await refresher.calls == 0)
    }
}

@Suite("Split token storage")
struct TokenStorageTests {
    @Test func refreshTokenLivesInItsOwnProtectionClass() async throws {
        let access = InMemorySecretStore(), refresh = InMemorySecretStore()
        let store = SecretTokenStore(secrets: access, refreshSecrets: refresh)
        try await store.save(TokenSet(consumerId: PreviewData.consumerId, accessToken: "a", accessExpiresAt: Date().addingTimeInterval(900), refreshToken: "secret-refresh"))
        let accessBlob = String(decoding: try #require(try access.read("session.tokens")), as: UTF8.self)
        #expect(accessBlob.contains("\"a\""))
        #expect(!accessBlob.contains("secret-refresh"))
        #expect(String(decoding: try #require(try refresh.read("session.refresh")), as: UTF8.self) == "secret-refresh")
        #expect(try await store.load()?.refreshToken == "secret-refresh")
        try await store.clear()
        #expect(try access.read("session.tokens") == nil && (try refresh.read("session.refresh")) == nil)
    }

    @Test func lockedRefreshStoreKeepsTheAccessTokenUsable() async throws {
        let access = InMemorySecretStore(), refresh = LockedSecretStore()
        let store = SecretTokenStore(secrets: access, refreshSecrets: refresh)
        try await store.save(TokenSet(consumerId: PreviewData.consumerId, accessToken: "a", accessExpiresAt: Date().addingTimeInterval(900), refreshToken: "r"))
        refresh.locked = true
        let loaded = try #require(try await store.load())
        #expect(loaded.accessToken == "a")
        #expect(loaded.refreshToken == nil && loaded.refreshTokenUnavailable)
        // saving the (unchanged) set while locked neither fails nor deletes the refresh token
        try await store.save(TokenSet(consumerId: PreviewData.consumerId, accessToken: "a2", accessExpiresAt: Date().addingTimeInterval(900), refreshTokenUnavailable: true))
        refresh.locked = false
        #expect(try await store.load()?.refreshToken == "r")
        #expect(try await store.load()?.accessToken == "a2")
    }

    @Test func extensionCannotRefreshWhileLockedButDoesNotSignOut() async throws {
        let access = InMemorySecretStore(), refresh = LockedSecretStore()
        let store = SecretTokenStore(secrets: access, refreshSecrets: refresh)
        try await store.save(TokenSet(consumerId: PreviewData.consumerId, accessToken: "old", accessExpiresAt: Date().addingTimeInterval(-10), refreshToken: "r"))
        refresh.locked = true
        let refresher = CountingRefresher()
        let sessions = SessionManager(store: store, refresher: refresher)
        await #expect(throws: APIError.transport("credentials-locked")) { _ = try await sessions.validAccessToken() }
        #expect(await refresher.calls == 0)
        refresh.locked = false
        #expect(try await store.load()?.refreshToken == "r") // still signed in
        #expect(await sessions.tokens() != nil)
        #expect(try await sessions.validAccessToken() == "fresh-1") // works once unlocked
    }

    @Test func legacySingleSlotSessionsAreMigrated() async throws {
        let access = InMemorySecretStore(), refresh = InMemorySecretStore()
        let legacy = #"{"consumerId":"\#(PreviewData.consumerId)","accessToken":"a","accessExpiresAt":4102444800,"refreshToken":"legacy-r"}"#
        try access.write(Data(legacy.utf8), account: "session.tokens")
        let store = SecretTokenStore(secrets: access, refreshSecrets: refresh)
        let loaded = try #require(try await store.load())
        #expect(loaded.refreshToken == "legacy-r")
        #expect(String(decoding: try #require(try refresh.read("session.refresh")), as: UTF8.self) == "legacy-r")
        #expect(!String(decoding: try #require(try access.read("session.tokens")), as: UTF8.self).contains("legacy-r"))
    }

    @Test func notificationExtensionShowsAGenericBannerWhenItCannotRefresh() async throws {
        // The extension's whole stack: expired access token + locked refresh token => API calls fail => generic banner.
        let secrets = InMemorySecretStore(), refresh = LockedSecretStore()
        let store = SecretTokenStore(secrets: secrets, refreshSecrets: refresh)
        try await store.save(TokenSet(consumerId: PreviewData.consumerId, accessToken: "old", accessExpiresAt: Date().addingTimeInterval(-10), refreshToken: "r"))
        refresh.locked = true
        let sessions = SessionManager(store: store, refresher: CountingRefresher())
        let env = try await ClientEnv()
        let signer = DeviceRequestSigner(records: env.records, keys: env.keys)
        let executor = RequestExecutor(baseURL: URL(string: "http://localhost:8080")!, transport: FakeTransport { _, _ in json("{}") }, signer: signer)
        let api = LiveViadereAPI(client: APIClient(executor: executor, sessions: sessions))
        let result = await NotificationEnricher(api: api).enrich(interactionId: InteractionID())
        #expect(result.isFallback)
        #expect(result.body == "Open Viadere to review a request.")
        #expect(result.category.identifier == "viadere.unknown")
    }
}
