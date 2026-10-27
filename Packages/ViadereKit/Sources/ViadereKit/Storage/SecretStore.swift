import Foundation

/// A tiny key/value store for small secrets (tokens, device record). The production implementation is the
/// Keychain (`KeychainSecretStore`); tests and previews use `InMemorySecretStore`.
public protocol SecretStore: Sendable {
    func read(_ account: String) throws -> Data?
    func write(_ data: Data, account: String) throws
    func delete(_ account: String) throws
    /// Removes every item this store owns (sign-out, revocation).
    func deleteAll() throws
}

public enum SecretStoreError: Error, Equatable, Sendable {
    case unhandled(Int32)
    case encoding
}

/// Thread-safe in-memory store (tests, previews).
public final class InMemorySecretStore: SecretStore, @unchecked Sendable {
    private let lock = NSLock()
    private var items: [String: Data] = [:]
    private var history: [Data] = []

    public init() {}

    /// Every value ever written, including ones since deleted (tests check that secrets that must never be stored never appear).
    var everWritten: [Data] { lock.lock(); defer { lock.unlock() }; return history }

    public func read(_ account: String) throws -> Data? {
        lock.lock(); defer { lock.unlock() }
        return items[account]
    }

    public func write(_ data: Data, account: String) throws {
        lock.lock(); defer { lock.unlock() }
        items[account] = data
        history.append(data)
    }

    public func delete(_ account: String) throws {
        lock.lock(); defer { lock.unlock() }
        items[account] = nil
    }

    public func deleteAll() throws {
        lock.lock(); defer { lock.unlock() }
        items.removeAll()
    }

    public var count: Int {
        lock.lock(); defer { lock.unlock() }
        return items.count
    }
}

/// JSON value persisted in a `SecretStore`.
struct JSONSecretSlot<Value: Codable & Sendable>: Sendable {
    let secrets: any SecretStore
    let account: String

    func load() throws -> Value? {
        guard let data = try secrets.read(account) else { return nil }
        // A corrupted item is treated as absent (and removed) rather than crashing launch.
        guard let value = try? JSONDecoder().decode(Value.self, from: data) else {
            try? secrets.delete(account)
            return nil
        }
        return value
    }

    func save(_ value: Value) throws {
        try secrets.write(try JSONEncoder().encode(value), account: account)
    }

    func clear() throws { try secrets.delete(account) }
}
