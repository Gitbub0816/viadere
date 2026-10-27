import Foundation
import UIKit
import ViadereKit

/// The app's object graph. `services` is a plain `Sendable` value so background callbacks can use it directly;
/// everything UI-related lives on the main actor.
@MainActor
final class AppEnvironment {
    static let shared = AppEnvironment()

    /// Keychain-backed, Secure Enclave-keyed, certificate-pinned. See `ViadereServices.live`.
    nonisolated static let services: ViadereServices = ViadereServices.live(
        configuration: ViadereRuntime.configuration,
        passkeys: ApplePasskeyService(anchorProvider: { KeyWindow.current }),
        notificationPermission: UserNotificationPermissionService(),
        appLock: LocalAuthenticationAppLock())

    let model: AppModel
    let privacyShield = PrivacyShield()
    let captureObserver = ScreenCaptureObserver()
    let liveActivities: LiveActivityManager
    let watchBridge: WatchBridge

    private init() {
        model = AppModel(services: Self.services)
        liveActivities = LiveActivityManager(services: Self.services)
        watchBridge = WatchBridge(services: Self.services)
    }

    /// Applies the result of a notification action (opens the secure sheet, shows a toast, refreshes Home).
    func apply(_ outcome: NotificationOutcome) async {
        await model.apply(outcome)
    }
}
