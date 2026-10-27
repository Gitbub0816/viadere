import Foundation
import ViadereCore

/// Exchanges expired credentials for fresh ones.
public protocol TokenRefresher: Sendable {
    func refresh(current: TokenSet?) async throws -> TokenSet
}

/// Rotates the session through `POST /v1/auth/refresh` (`APIRoutes.authRefresh`).
///
/// The refresh token is the credential and is **single-use**: the server returns a new pair and treats reuse of
/// an old token as theft (revoking the whole session family). That is why refreshes are single-flight
/// in-process (`SessionManager`) and serialized across processes (`CrossProcessLock`).
public struct APITokenRefresher: TokenRefresher {
    private let executor: RequestExecutor

    public init(executor: RequestExecutor) { self.executor = executor }

    public func refresh(current: TokenSet?) async throws -> TokenSet {
        guard let refreshToken = current?.refreshToken else { throw APIError.sessionExpired }
        let endpoint = APIRoutes.authRefresh
        let path = try endpoint.path()
        let body = try ViadereJSON.encode(AuthRefreshRequest(refreshToken: refreshToken))
        let response = try await executor.run(endpoint.descriptor, pathAndQuery: path, body: body, bearer: nil)
        guard (200..<300).contains(response.status) else {
            if response.status == 400 || response.status == 401 || response.status == 403 { throw APIError.sessionExpired }
            throw RequestExecutor.error(from: response)
        }
        guard let session = try? ViadereJSON.decode(AuthSession.self, from: response.body) else { throw APIError.decoding("refresh") }
        var tokens = TokenSet(session)
        if tokens.refreshToken == nil { tokens.refreshToken = refreshToken }
        return tokens
    }
}

/// A claim on "I am rotating the session". Held (as a short-lived lease file) while the refresh request is on the
/// network, so another process does not spend the same single-use refresh token; the file lock itself is **not**
/// held across network I/O.
public struct RefreshLease: Sendable, Equatable {
    public let id: String
    public init(id: String = UUID().uuidString) { self.id = id }
}

/// Serializes token rotation between the app and its extensions (separate processes sharing the Keychain).
///
/// `withLock` guards short read-compare-write critical sections only (never network I/O: holding a file lock in a
/// suspended app risks a `0xdead10cc` kill). The long part of a refresh is covered by the lease instead.
public protocol CrossProcessLock: Sendable {
    /// Runs `body` while holding the lock. Throws if the lock can't be opened or acquired within the timeout, in
    /// which case the caller must **not** proceed (no refresh without mutual exclusion).
    func withLock<T: Sendable>(_ body: @Sendable () async throws -> T) async throws -> T
    /// Takes the refresh lease, or returns `nil` if another live process already holds it.
    func acquireRefreshLease(ttl: TimeInterval) async throws -> RefreshLease?
    func releaseRefreshLease(_ lease: RefreshLease) async
}

extension CrossProcessLock {
    public func acquireRefreshLease(ttl: TimeInterval) async throws -> RefreshLease? { RefreshLease() }
    public func releaseRefreshLease(_ lease: RefreshLease) async {}
}

/// No-op lock (single process, tests).
public struct NoCrossProcessLock: CrossProcessLock {
    public init() {}
    public func withLock<T: Sendable>(_ body: @Sendable () async throws -> T) async throws -> T { try await body() }
}

/// A lock that can never be taken: used when the shared container that should hold the lock file is missing.
/// Refreshes fail with a retryable error instead of running unprotected.
public struct UnavailableCrossProcessLock: CrossProcessLock {
    public init() {}
    public func withLock<T: Sendable>(_ body: @Sendable () async throws -> T) async throws -> T {
        throw APIError.transport("refresh-lock-unavailable")
    }
    public func acquireRefreshLease(ttl: TimeInterval) async throws -> RefreshLease? { throw APIError.transport("refresh-lock-unavailable") }
}

/// `flock(2)` on a file in the shared app-group container, plus a lease file next to it.
///
/// **Fail safe:** if the lock file cannot be opened, or the lock is not acquired within `timeout`, this throws a
/// retryable error; it never runs the body unlocked.
public struct FileCrossProcessLock: CrossProcessLock {
    private let url: URL
    private let timeout: TimeInterval
    private var leaseURL: URL { URL(fileURLWithPath: url.path + ".lease") }

    /// - Parameter timeout: how long to wait for the (short) critical-section lock.
    public init(url: URL, timeout: TimeInterval = 3) {
        self.url = url
        self.timeout = timeout
    }

    public func withLock<T: Sendable>(_ body: @Sendable () async throws -> T) async throws -> T {
        let descriptor = open(url.path, O_CREAT | O_RDWR | O_CLOEXEC, 0o600)
        guard descriptor >= 0 else { throw APIError.transport("refresh-lock-unavailable") }
        defer { close(descriptor) }
        let deadline = Date().addingTimeInterval(timeout)
        while flock(descriptor, LOCK_EX | LOCK_NB) != 0 {
            if Date() > deadline { throw APIError.transport("refresh-lock-timeout") }
            try await Task.sleep(for: .milliseconds(25))
        }
        defer { flock(descriptor, LOCK_UN) }
        return try await body()
    }

    private struct LeaseFile: Codable { var id: String; var expires: Double }

    public func acquireRefreshLease(ttl: TimeInterval) async throws -> RefreshLease? {
        let leaseURL = self.leaseURL
        return try await withLock {
            let now = Date().timeIntervalSince1970
            if let data = try? Data(contentsOf: leaseURL), let held = try? JSONDecoder().decode(LeaseFile.self, from: data), held.expires > now {
                return nil
            }
            let lease = RefreshLease()
            guard let data = try? JSONEncoder().encode(LeaseFile(id: lease.id, expires: now + ttl)),
                  (try? data.write(to: leaseURL, options: .atomic)) != nil else { throw APIError.transport("refresh-lock-unavailable") }
            return lease
        }
    }

    public func releaseRefreshLease(_ lease: RefreshLease) async {
        let leaseURL = self.leaseURL
        // Best effort: an unreleased lease simply expires.
        _ = try? await withLock {
            if let data = try? Data(contentsOf: leaseURL), let held = try? JSONDecoder().decode(LeaseFile.self, from: data), held.id == lease.id {
                try? FileManager.default.removeItem(at: leaseURL)
            }
        }
    }
}

private struct SessionSuperseded: Error {}

/// Owns the current credentials and guarantees that **at most one refresh is in flight** (single-flight):
/// concurrent requests that hit an expired token all await the same refresh.
///
/// Refreshing is a short read-compare-write around a network call:
/// 1. take the cross-process refresh lease (or wait and adopt whatever the other process stored),
/// 2. under the file lock, re-read the stored session and adopt it if another process already rotated it,
/// 3. call the server **without** holding the file lock,
/// 4. under the file lock again, write the new pair only if the stored session is still the one we spent and this
///    manager's `generation` has not moved (so a sign-out or new sign-in in between is never overwritten).
public actor SessionManager {
    private let store: any TokenStore
    private let refresher: any TokenRefresher
    private let lock: any CrossProcessLock
    private let clock: @Sendable () -> Date
    private var cache: TokenSet?
    private var loaded = false
    private var inflight: Task<TokenSet, any Error>?
    /// Bumped by every `set` and `clear`. A refresh remembers the generation it started in and refuses to store or
    /// cache its result if the session changed meanwhile, so a cleared session can't be resurrected.
    private var generation = 0
    /// Number of refresh network calls made (diagnostics / tests).
    public private(set) var refreshCount = 0

    static let leaseTTL: TimeInterval = 20
    static let maxLeaseWait: Duration = .seconds(25)
    static let leasePoll: Duration = .milliseconds(100)

    public init(store: any TokenStore, refresher: any TokenRefresher, lock: any CrossProcessLock = NoCrossProcessLock(),
                clock: @escaping @Sendable () -> Date = { Date() }) {
        self.store = store
        self.refresher = refresher
        self.lock = lock
        self.clock = clock
    }

    private func load() async throws -> TokenSet? {
        if !loaded {
            let gen = generation
            let stored = try await store.load()
            // A clear() or set() may have happened while we were reading: keep theirs.
            if gen == generation {
                cache = stored
                loaded = true
            } else {
                return cache
            }
        }
        return cache
    }

    public func tokens() async -> TokenSet? { try? await load() }

    public var isSignedIn: Bool {
        get async { (try? await load()) != nil }
    }

    public func set(_ tokens: TokenSet) async throws {
        generation += 1
        inflight?.cancel()
        inflight = nil
        try await store.save(tokens)
        cache = tokens
        loaded = true
    }

    /// Forgets the session (sign-out, revocation). Any refresh in flight is cancelled and can no longer store or
    /// cache its result.
    public func clear() async {
        generation += 1
        inflight?.cancel()
        inflight = nil
        cache = nil
        loaded = true
        try? await store.clear()
    }

    /// A bearer token that is valid now, refreshing proactively when it is about to expire.
    public func validAccessToken() async throws -> String {
        guard let tokens = try await load() else { throw APIError.sessionExpired }
        if tokens.needsRefresh(now: clock()) {
            return try await refresh(afterRejecting: tokens.accessToken).accessToken
        }
        return tokens.accessToken
    }

    /// Refreshes after the server rejected `rejected` (or proactively). If another caller or process already
    /// replaced the token, that newer token is returned without another network call.
    public func refresh(afterRejecting rejected: String?) async throws -> TokenSet {
        if let current = try await load(), let adopted = adopt(current, rejected: rejected) { return adopted }
        let gen = generation
        if let inflight {
            let shared = try await outcome(of: inflight)
            if gen == generation { cache = shared }
            return shared
        }
        let task = Task<TokenSet, any Error> { try await self.performRefresh(rejected: rejected, generation: gen) }
        inflight = task
        refreshCount += 1
        do {
            let fresh = try await outcome(of: task)
            // Publish in memory first (no suspension point), so requests that retry immediately see the new token.
            if gen == generation { cache = fresh; inflight = nil }
            return fresh
        } catch {
            if gen == generation {
                inflight = nil
                if let api = error as? APIError, api == .sessionExpired { cache = nil }
            }
            throw error
        }
    }

    private func outcome(of task: Task<TokenSet, any Error>) async throws -> TokenSet {
        do { return try await task.value } catch is SessionSuperseded { throw APIError.sessionExpired } catch is CancellationError {
            throw APIError.sessionExpired
        }
    }

    private nonisolated func adopt(_ stored: TokenSet?, rejected: String?) -> TokenSet? {
        guard let stored, let rejected, stored.accessToken != rejected, !stored.needsRefresh(now: clock(), leeway: 0) else { return nil }
        return stored
    }

    private func isCurrent(_ gen: Int) -> Bool { gen == generation }

    private func performRefresh(rejected: String?, generation gen: Int) async throws -> TokenSet {
        var waited: Duration = .zero
        while true {
            try Task.checkCancellation()
            guard isCurrent(gen) else { throw SessionSuperseded() }
            guard let lease = try await lock.acquireRefreshLease(ttl: Self.leaseTTL) else {
                // Another process is rotating the session: wait, then adopt what it stored.
                if waited >= Self.maxLeaseWait { throw APIError.transport("refresh-busy") }
                try await Task.sleep(for: Self.leasePoll)
                waited += Self.leasePoll
                if let stored = try await store.load(), let adopted = adopt(stored, rejected: rejected) { return adopted }
                continue
            }
            do {
                let result = try await rotate(rejected: rejected, generation: gen)
                await lock.releaseRefreshLease(lease)
                return result
            } catch {
                await lock.releaseRefreshLease(lease)
                throw error
            }
        }
    }

    private func rotate(rejected: String?, generation gen: Int) async throws -> TokenSet {
        let store = self.store
        let lock = self.lock
        let refresher = self.refresher
        // 1. Short critical section: what is stored right now?
        let stored = try await lock.withLock { try await store.load() }
        if let adopted = adopt(stored, rejected: rejected) { return adopted }
        guard let stored else { throw APIError.sessionExpired }
        // The refresh token can't be read right now (phone locked): say "try again", never "signed out".
        if stored.refreshTokenUnavailable { throw APIError.transport("credentials-locked") }
        guard isCurrent(gen) else { throw SessionSuperseded() }

        // 2. The network call, with no file lock held.
        let fresh: TokenSet
        do {
            fresh = try await refresher.refresh(current: stored)
        } catch let error as APIError where error == .sessionExpired {
            // The server rejected the refresh token. Forget the session, but only if it is still the one we used.
            try? await lock.withLock {
                let latest = try await store.load()
                if latest?.refreshToken == stored.refreshToken, await self.isCurrent(gen) { try await store.clear() }
            }
            throw error
        }

        // 3. Short critical section: compare, then write. Persist before releasing, so the next process sees the
        //    rotated pair and never the spent one.
        return try await lock.withLock {
            let latest = try await store.load()
            guard let latest else { throw SessionSuperseded() } // signed out meanwhile: don't resurrect it
            if latest.refreshToken != stored.refreshToken, !latest.refreshTokenUnavailable {
                // Someone else changed the session while we were on the network: theirs wins.
                if let adopted = self.adopt(latest, rejected: rejected) { return adopted }
                throw SessionSuperseded()
            }
            guard await self.isCurrent(gen) else { throw SessionSuperseded() }
            try await store.save(fresh)
            return fresh
        }
    }
}
