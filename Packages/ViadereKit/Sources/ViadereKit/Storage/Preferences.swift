import Foundation

/// Non-secret local preferences (app group `UserDefaults`, shared with extensions).
public protocol PreferencesStore: Sendable {
    func bool(_ key: PreferenceKey) -> Bool
    func setBool(_ value: Bool, for key: PreferenceKey)
    func string(_ key: PreferenceKey) -> String?
    func setString(_ value: String?, for key: PreferenceKey)
    func removeAll()
}

public enum PreferenceKey: String, CaseIterable, Sendable {
    /// Face ID / passcode gate on launch and when returning from the background.
    case appLockEnabled
    case onboardingComplete
    case notificationPrimingShown
    /// The optional "Protect your account" step (passkey, recovery codes) was completed or skipped.
    case protectionPromptShown
    /// Show business detail in notification banners (user controls previews further in iOS Settings).
    case richNotificationPreviews
    case lastKnownConsumerId
}

public final class UserDefaultsPreferences: PreferencesStore, @unchecked Sendable {
    private let defaults: UserDefaults
    private static let prefix = "com.viadere.pref."

    /// - Parameter suiteName: the app group id; falls back to `.standard` if the group is unavailable.
    public init(suiteName: String? = nil) {
        defaults = suiteName.flatMap { UserDefaults(suiteName: $0) } ?? .standard
    }

    public func bool(_ key: PreferenceKey) -> Bool { defaults.bool(forKey: Self.prefix + key.rawValue) }
    public func setBool(_ value: Bool, for key: PreferenceKey) { defaults.set(value, forKey: Self.prefix + key.rawValue) }
    public func string(_ key: PreferenceKey) -> String? { defaults.string(forKey: Self.prefix + key.rawValue) }
    public func setString(_ value: String?, for key: PreferenceKey) {
        if let value { defaults.set(value, forKey: Self.prefix + key.rawValue) } else { defaults.removeObject(forKey: Self.prefix + key.rawValue) }
    }
    public func removeAll() {
        for key in PreferenceKey.allCases { defaults.removeObject(forKey: Self.prefix + key.rawValue) }
    }
}

public final class InMemoryPreferences: PreferencesStore, @unchecked Sendable {
    private let lock = NSLock()
    private var values: [PreferenceKey: String] = [:]

    public init() {}

    var allValues: [String] { lock.lock(); defer { lock.unlock() }; return Array(values.values) }

    public func bool(_ key: PreferenceKey) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return values[key] == "1"
    }
    public func setBool(_ value: Bool, for key: PreferenceKey) {
        lock.lock(); defer { lock.unlock() }
        values[key] = value ? "1" : "0"
    }
    public func string(_ key: PreferenceKey) -> String? {
        lock.lock(); defer { lock.unlock() }
        return values[key]
    }
    public func setString(_ value: String?, for key: PreferenceKey) {
        lock.lock(); defer { lock.unlock() }
        values[key] = value
    }
    public func removeAll() {
        lock.lock(); defer { lock.unlock() }
        values.removeAll()
    }
}
