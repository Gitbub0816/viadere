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

/// Serializes token rotation between the app and its extensions (separate processes sharing the Keychain).
public protocol CrossProcessLock: Sendable {
    func withLock<T: Sendable>(_ body: @Sendable () async throws -> T) async throws -> T
}

/// No-op lock (single process, tests).
public struct NoCrossProcessLock: CrossProcessLock {
    public init() {}
    public func withLock<T: Sendable>(_ body: @Sendable () async throws -> T) async throws -> T { try await body() }
}

/// `flock(2)` on a file in the shared app-group container.
public struct FileCrossProcessLock: CrossProcessLock {
    private let url: URL
    private let timeout: TimeInterval

    public init(url: URL, timeout: TimeInterval = 10) {
        self.url = url
        self.timeout = timeout
    }

    public func withLock<T: Sendable>(_ body: @Sendable () async throws -> T) async throws -> T {
        let descriptor = open(url.path, O_CREAT | O_RDWR, 0o600)
        guard descriptor >= 0 else { return try await body() } // no shared container: fall back to in-process safety
        defer { close(descriptor) }
        let deadline = Date().addingTimeInterval(timeout)
        while flock(descriptor, LOCK_EX | LOCK_NB) != 0 {
            if Date() > deadline { throw APIError.transport("lock-timeout") }
            try await Task.sleep(for: .milliseconds(40))
        }
        defer { flock(descriptor, LOCK_UN) }
        return try await body()
    }
}

/// Owns the current credentials and guarantees that **at most one refresh is in flight** (single-flight):
/// concurrent requests that hit an expired token all await the same refresh. Under the cross-process lock
/// the stored credentials are re-read first, so a refresh already done by another process is adopted, not repeated.
public actor SessionManager {
    private let store: any TokenStore
    private let refresher: any TokenRefresher
    private let lock: any CrossProcessLock
    private let clock: @Sendable () -> Date
    private var cache: TokenSet?
    private var loaded = false
    private var inflight: Task<TokenSet, any Error>?
    /// Number of refresh network calls made (diagnostics / tests).
    public private(set) var refreshCount = 0

    public init(store: any TokenStore, refresher: any TokenRefresher, lock: any CrossProcessLock = NoCrossProcessLock(),
                clock: @escaping @Sendable () -> Date = { Date() }) {
        self.store = store
        self.refresher = refresher
        self.lock = lock
        self.clock = clock
    }

    private func load() async throws -> TokenSet? {
        if !loaded {
            cache = try await store.load()
            loaded = true
        }
        return cache
    }

    public func tokens() async -> TokenSet? { try? await load() }

    public var isSignedIn: Bool {
        get async { (try? await load()) != nil }
    }

    public func set(_ tokens: TokenSet) async throws {
        try await store.save(tokens)
        cache = tokens
        loaded = true
    }

    /// Forgets the session (sign-out, revocation).
    public func clear() async {
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
        if let current = try await load(), let rejected, current.accessToken != rejected, !current.needsRefresh(now: clock(), leeway: 0) {
            return current
        }
        if let inflight {
            let shared = try await inflight.value
            cache = shared
            return shared
        }
        let store = self.store
        let refresher = self.refresher
        let lock = self.lock
        let now = self.clock
        let task = Task<TokenSet, any Error> {
            try await lock.withLock {
                // Another process (the app or an extension) may have rotated the session while we waited.
                let stored = try await store.load()
                if let stored, let rejected, stored.accessToken != rejected, !stored.needsRefresh(now: now(), leeway: 0) { return stored }
                let fresh = try await refresher.refresh(current: stored)
                // Persist before releasing the lock: the next process must see the rotated pair, never the spent one.
                try await store.save(fresh)
                return fresh
            }
        }
        inflight = task
        refreshCount += 1
        do {
            let fresh = try await task.value
            // Publish in memory first (no suspension point), so requests that retry immediately see the new token.
            cache = fresh
            inflight = nil
            return fresh
        } catch {
            inflight = nil
            if let api = error as? APIError, api == .sessionExpired {
                cache = nil
                try? await store.clear()
            }
            throw error
        }
    }
}
