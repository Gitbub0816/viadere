import Foundation

#if canImport(LocalAuthentication) && !os(watchOS)
import LocalAuthentication

/// Face ID / Touch ID / passcode gate for the optional app lock (`.deviceOwnerAuthentication`: biometrics with
/// passcode fallback, so a changed face never locks the owner out of their own app).
public struct LocalAuthenticationAppLock: AppLockAuthenticator {
    public init() {}

    public var methodName: String {
        let context = LAContext()
        var error: NSError?
        _ = context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
        switch context.biometryType {
        case .faceID: return "Face ID"
        case .touchID: return "Touch ID"
        default: return "Passcode"
        }
    }

    public func isAvailable() async -> Bool {
        var error: NSError?
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
    }

    public func authenticate(reason: String) async -> Bool {
        let context = LAContext()
        do { return try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) } catch { return false }
    }
}
#endif

#if canImport(UserNotifications)
import UserNotifications

public struct UserNotificationPermissionService: NotificationPermissionService {
    public init() {}

    public func status() async -> NotificationPermissionStatus {
        switch await UNUserNotificationCenter.current().notificationSettings().authorizationStatus {
        case .notDetermined: return .notDetermined
        case .denied: return .denied
        default: return .authorized
        }
    }

    /// Standard alerts, sounds and badges. Time Sensitive delivery is granted by the entitlement, not by this prompt.
    public func request() async -> Bool {
        (try? await UNUserNotificationCenter.current().requestAuthorization(options: [.alert, .sound, .badge])) ?? false
    }
}
#endif
