import ActivityKit
import Foundation
import UserNotifications
import ViadereKit
import WatchConnectivity

/// What sign-out, account deletion and device revocation must erase beyond the Keychain: notifications still in
/// Notification Center (they can show names, amounts and places), Live Activities on the Lock Screen, the pending
/// list shared with the watch, and the per-interaction notification categories.
struct AppLocalResidueCleaner: LocalResidueCleaner {
    func removeDeliveredNotifications() async {
        let center = UNUserNotificationCenter.current()
        center.removeAllDeliveredNotifications()
        center.removeAllPendingNotificationRequests()
    }

    func endLiveActivities() async {
        for activity in Activity<ViadereActivityAttributes>.activities {
            await activity.end(nil, dismissalPolicy: .immediate)
        }
    }

    func clearWatchContext() async {
        guard WCSession.isSupported() else { return }
        let session = WCSession.default
        guard session.activationState == .activated, session.isPaired, session.isWatchAppInstalled else { return }
        // Latest-wins application context: replace the pending list with an empty one.
        if let empty = WatchSync.encode([]) { try? session.updateApplicationContext([WatchSync.contextKey: empty]) }
    }

    func removeDynamicNotificationCategories() async {
        await NotificationCategories.removeDynamic()
    }
}
