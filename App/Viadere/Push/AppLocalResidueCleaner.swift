import ActivityKit
import Foundation
import UserNotifications
import ViadereKit
import WatchConnectivity
import WidgetKit

/// What sign-out, account deletion and device revocation must erase beyond the Keychain: notifications still in
/// Notification Center (they can show names, amounts and places), Live Activities on the Lock Screen, the pending
/// list shared with the watch, the per-interaction notification categories and the Home Screen widget snapshot.
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

    /// The Home Screen widget's snapshot (numbers only) goes, and the widget returns to its neutral face.
    func clearSharedSnapshots() async {
        let services = AppEnvironment.services
        await MainActor.run {
            if let writer = services.homeWidget {
                writer.clear()
            } else {
                WidgetSnapshotStore(persistence: UserDefaultsWidgetSnapshotPersistence(suiteName: services.configuration.appGroupID)).clear()
                WidgetCenter.shared.reloadTimelines(ofKind: WidgetSnapshot.kind)
            }
        }
    }
}
