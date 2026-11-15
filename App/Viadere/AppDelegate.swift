import UIKit
import UserNotifications
import ViadereKit

/// Push registration, notification actions, and silent status pushes.
@MainActor
final class AppDelegate: NSObject, UIApplicationDelegate {
    private static let log = ViadereLog.notifications

    func application(_ application: UIApplication,
                     didFinishLaunchingWithOptions launchOptions: [UIApplication.LaunchOptionsKey: Any]? = nil) -> Bool {
        UNUserNotificationCenter.current().delegate = self
        _ = AppEnvironment.shared
        Task {
            await NotificationCategories.registerStatic()
            // Ask iOS for a push token only if the person already allowed notifications (the priming screen asks first).
            if await AppEnvironment.services.notificationPermission.status() == .authorized {
                application.registerForRemoteNotifications()
            }
        }
        return true
    }

    // MARK: Push token

    func application(_ application: UIApplication, didRegisterForRemoteNotificationsWithDeviceToken deviceToken: Data) {
        let services = AppEnvironment.services
        // Sandbox builds only (Debug, Staging; Release is pinned to production APNs): log the token, `.private` as always, so a developer
        // with Xcode attached can send a test push straight to APNs (App/Scripts/apns-send.swift). A sandbox token is useless against
        // production APNs.
        if services.configuration.apnsEnvironment == .sandbox {
            Self.log.info("push.token.sandbox", detail: deviceToken.map { String(format: "%02x", $0) }.joined())
        }
        Task {
            // Needs an enrolled device (device-signed route); retried on the next launch if not yet enrolled.
            guard (try? await services.records.load()) != nil else { return }
            try? await PushRegistrar(api: services.api, configuration: services.configuration).registerAPNs(deviceToken: deviceToken)
        }
    }

    func application(_ application: UIApplication, didFailToRegisterForRemoteNotificationsWithError error: any Error) {
        Self.log.error("push.register.failed")
    }

    // MARK: Silent status pushes (Live Activities)

    func application(_ application: UIApplication, didReceiveRemoteNotification userInfo: [AnyHashable: Any]) async -> UIBackgroundFetchResult {
        guard let id = PushPayload.interactionId(from: userInfo) else { return .noData }
        return await AppEnvironment.shared.liveActivities.handleStatusPush(interactionId: id) ? .newData : .noData
    }
}

// `@preconcurrency`: UserNotifications callbacks are not main-actor annotated in every SDK; this keeps the
// conformance valid either way (isolation is checked at runtime, and iOS calls these on the main thread).
extension AppDelegate: @preconcurrency UNUserNotificationCenterDelegate {
    func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        // Show requests even while the app is open: a sign-in prompt must never be silently swallowed.
        [.banner, .list, .sound]
    }

    func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        let content = response.notification.request.content
        // A verification request opens its own sheet: the push carries only the opaque request id (`iid`), and consent happens in the app.
        if content.categoryIdentifier == "viadere.verification.request", let id = VerificationCenter.requestId(fromPushUserInfo: content.userInfo) {
            AppEnvironment.shared.verification.present(id)
            return
        }
        // A Loop update: opaque push (no business, no content); open the instance if the payload names one, else Alerts.
        if let route = LoopNotificationRoute.route(categoryIdentifier: content.categoryIdentifier, userInfo: PushPayload.stringify(content.userInfo)) {
            await AppEnvironment.shared.loops.handle(route, model: AppEnvironment.shared.model)
            return
        }
        let info = NotificationResponseInfo(
            actionIdentifier: response.actionIdentifier,
            categoryIdentifier: content.categoryIdentifier,
            userInfo: PushPayload.stringify(content.userInfo),
            userText: (response as? UNTextInputNotificationResponse)?.userText)
        // Sensitive approvals never complete here: the handler answers `.requiresApp` and the secure sheet opens.
        let outcome = await AppEnvironment.services.notificationHandler.handle(info)
        await AppEnvironment.shared.apply(outcome)
    }
}
