import Foundation

/// Notification permission (the priming screen asks, the system prompt answers).
public protocol NotificationPermissionService: Sendable {
    func status() async -> NotificationPermissionStatus
    /// Presents the system prompt (alerts, sounds, badges). Returns whether it was granted.
    func request() async -> Bool
}

public enum NotificationPermissionStatus: Sendable, Equatable { case notDetermined, denied, authorized }

public struct MockNotificationPermissionService: NotificationPermissionService {
    public var result: Bool
    public init(result: Bool = true) { self.result = result }
    public func status() async -> NotificationPermissionStatus { .notDetermined }
    public func request() async -> Bool { result }
}

/// Face ID / Touch ID / passcode gate for the optional app lock.
public protocol AppLockAuthenticator: Sendable {
    /// True if the device can authenticate the owner (passcode set).
    func isAvailable() async -> Bool
    /// Presents the system sheet. Returns `true` when the owner authenticated.
    func authenticate(reason: String) async -> Bool
    /// The biometric kind for labels: "Face ID", "Touch ID", "Passcode".
    var methodName: String { get }
}

public struct MockAppLockAuthenticator: AppLockAuthenticator {
    public var succeeds: Bool
    public init(succeeds: Bool = true) { self.succeeds = succeeds }
    public func isAvailable() async -> Bool { true }
    public func authenticate(reason: String) async -> Bool { succeeds }
    public var methodName: String { "Face ID" }
}

/// Pure app-lock policy: when must the lock screen appear?
public struct AppLockPolicy: Sendable, Equatable {
    public var enabled: Bool
    /// Seconds in the background before re-locking (0 = lock immediately).
    public var gracePeriod: TimeInterval

    public init(enabled: Bool, gracePeriod: TimeInterval = 15) {
        self.enabled = enabled
        self.gracePeriod = gracePeriod
    }

    public func shouldLock(backgroundedAt: Date?, now: Date, isColdLaunch: Bool) -> Bool {
        guard enabled else { return false }
        if isColdLaunch { return true }
        guard let backgroundedAt else { return false }
        return now.timeIntervalSince(backgroundedAt) >= gracePeriod
    }
}
