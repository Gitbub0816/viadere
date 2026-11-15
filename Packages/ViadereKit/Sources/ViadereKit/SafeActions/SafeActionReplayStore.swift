import Crypto
import Foundation

/// The reader's memory of Safe Action request ids it has already accepted (spec "What a reader must do", steps 3 and 7). The issuer's
/// server is the authority on single use; this is the local half, so a code scanned twice on this phone opens nothing the second time.
public protocol SafeActionReplayStore: Sendable {
    /// Records `requestId` as used until `until`. `false` when it was already recorded and has not lapsed, or when it cannot be recorded
    /// (the store is full or unwritable): the caller then refuses the action.
    func claim(requestId: String, until: Date, now: Date) -> Bool
}

/// Request ids in the app's preferences, so the memory survives a restart for as long as a code could still be valid (expiry + 120 s).
/// Only a SHA-256 of each id is kept. Bounded: at most `capacity` live entries; when that many unexpired ids are held a new one is
/// **refused** rather than an old one forgotten (entries are written only after a signature verified, so only the pinned issuer can fill it,
/// and each lapses within four minutes).
public final class PreferencesSafeActionReplayStore: SafeActionReplayStore, @unchecked Sendable {
    public static let capacity = 64

    private struct Entry: Codable { var h: String; var u: Double }

    private let preferences: any PreferencesStore
    private let lock = NSLock()

    public init(preferences: any PreferencesStore) { self.preferences = preferences }

    public func claim(requestId: String, until: Date, now: Date) -> Bool {
        lock.lock(); defer { lock.unlock() }
        let digest = SHA256.hash(data: Data(requestId.utf8)).map { String(format: "%02x", $0) }.joined()
        var entries: [Entry] = []
        if let stored = preferences.string(.safeActionSeenRequests) {
            // Unreadable memory is not "nothing seen": this claim is refused and the memory starts again empty.
            guard let decoded = try? JSONDecoder().decode([Entry].self, from: Data(stored.utf8)) else {
                preferences.setString("[]", for: .safeActionSeenRequests)
                return false
            }
            entries = decoded
        }
        entries.removeAll { $0.u <= now.timeIntervalSince1970 }
        guard !entries.contains(where: { $0.h == digest }), entries.count < Self.capacity, until > now else { return false }
        entries.append(Entry(h: digest, u: until.timeIntervalSince1970))
        guard let data = try? JSONEncoder().encode(entries), let text = String(data: data, encoding: .utf8) else { return false }
        preferences.setString(text, for: .safeActionSeenRequests)
        // Read back: a preferences store that silently dropped the write must not let the same code through twice.
        return preferences.string(.safeActionSeenRequests) == text
    }
}

/// For tests and previews.
public final class InMemorySafeActionReplayStore: SafeActionReplayStore, @unchecked Sendable {
    private let lock = NSLock()
    private var seen: [String: Date] = [:]

    public init() {}

    public func claim(requestId: String, until: Date, now: Date) -> Bool {
        lock.lock(); defer { lock.unlock() }
        seen = seen.filter { $0.value > now }
        guard seen[requestId] == nil, until > now else { return false }
        seen[requestId] = until
        return true
    }
}
