import Foundation
import Observation
import UserNotifications
import ViadereKit
import WatchConnectivity

/// Receives the phone's pending list and asks the phone to act. The watch holds no keys and no credentials:
/// every decision is signed on the iPhone, under the same rules as a notification action.
@MainActor @Observable
final class WatchModel: NSObject, WCSessionDelegate {
    private(set) var items: [WatchPendingItem] = []
    private(set) var statusMessage: String?
    private(set) var isReachable = false
    /// `AppearanceSelection.renderKey` of the synced choice; the root view re-draws when it changes (the stored or default choice until the phone syncs).
    private(set) var appearanceKey = ViadereThemeRuntime.shared.current.renderKey

    override init() {
        super.init()
        guard WCSession.isSupported() else { return }
        WCSession.default.delegate = self
        WCSession.default.activate()
        registerMirroredCategories()
    }

    /// The mirrored iPhone notifications (`viadere.approve`, `viadere.auth.link`) show Deny / This wasn't me on the wrist only if the watch app
    /// registers the same categories (ADR-0022 §8). There is no Approve action anywhere: the watch holds no key and never approves.
    /// **Verify on a device (Stage 4):** whether iOS delivers a mirrored action to this delegate once the watch app is installed.
    private func registerMirroredCategories() {
        let center = UNUserNotificationCenter.current()
        center.delegate = self
        let categories = AuthNotificationCategory.categories.map { model -> UNNotificationCategory in
            let actions = model.actions
                .filter { $0.identifier == AuthNotificationCategory.denyAction || $0.identifier == AuthNotificationCategory.reportAction }
                .map { UNNotificationAction(identifier: $0.identifier, title: $0.title, options: []) }
            return UNNotificationCategory(identifier: model.identifier, actions: actions, intentIdentifiers: [],
                                          hiddenPreviewsBodyPlaceholder: AuthDeliveryCopy.hiddenPreviewsPlaceholder, options: [])
        }
        center.setNotificationCategories(Set(categories))
    }

    /// Applies the phone's appearance choice (the night side of it) and keeps it for the next launch; without one the stored or default
    /// pairing stays in force.
    private func apply(appearance received: AppearanceSelection?) {
        let persistence = ViadereThemeRuntime.persistence()
        let selection = WatchSync.resolveWatchAppearance(received: received, stored: AppearanceModel.read(persistence))
        if received != nil, let data = WatchSync.encode(selection) { persistence.save(data) }
        ViadereThemeRuntime.shared.current = selection
        appearanceKey = selection.renderKey
    }

    func send(_ request: WatchActionRequest) {
        statusMessage = nil
        guard let data = WatchSync.encode(request) else { return }
        let session = WCSession.default
        guard session.isReachable else {
            // W-05: nothing is queued and nothing is signed on the wrist.
            statusMessage = AuthDeliveryCopy.watchPhoneUnreachable
            return
        }
        session.sendMessageData(data, replyHandler: { reply in
            let result = WatchSync.decodeResult(reply)
            Task { @MainActor in
                self.statusMessage = result.message
                if result == .done || result == .stale || result == .expired { self.items.removeAll { $0.id == request.interactionId } }
            }
        }, errorHandler: { _ in
            Task { @MainActor in self.statusMessage = AuthDeliveryCopy.watchPhoneUnreachable }
        })
    }

    // MARK: WCSessionDelegate

    nonisolated func session(_ session: WCSession, activationDidCompleteWith activationState: WCSessionActivationState, error: (any Error)?) {
        let context = session.receivedApplicationContext[WatchSync.contextKey] as? Data
        let appearance = WatchSync.appearance(fromContext: session.receivedApplicationContext)
        let reachable = session.isReachable
        Task { @MainActor in
            self.isReachable = reachable
            if let context { self.items = WatchSync.decode(context) }
            self.apply(appearance: appearance)
        }
    }

    nonisolated func session(_ session: WCSession, didReceiveApplicationContext applicationContext: [String: Any]) {
        let data = applicationContext[WatchSync.contextKey] as? Data
        let appearance = WatchSync.appearance(fromContext: applicationContext)
        Task { @MainActor in
            if let data { self.items = WatchSync.decode(data) }
            self.apply(appearance: appearance)
        }
    }

    nonisolated func sessionReachabilityDidChange(_ session: WCSession) {
        let reachable = session.isReachable
        Task { @MainActor in self.isReachable = reachable }
    }
}

// MARK: Mirrored notification actions (ADR-0022 §8)

extension WatchModel: UNUserNotificationCenterDelegate {
    /// Forwards Deny and This wasn't me from a mirrored authentication notification to the phone. Never anything else: there is no Approve
    /// here, and "Review" simply opens this app (the long look shows W-02).
    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, didReceive response: UNNotificationResponse) async {
        let content = response.notification.request.content
        guard AuthNotificationCategory.all.contains(content.categoryIdentifier) else { return }
        let decision: Decision
        switch response.actionIdentifier {
        case AuthNotificationCategory.denyAction: decision = .deny
        case AuthNotificationCategory.reportAction: decision = .report
        default: return
        }
        let request = WatchActionRequest(interactionId: "", decision: decision, categoryIdentifier: content.categoryIdentifier,
                                         pushUserInfo: PushPayload.stringify(content.userInfo))
        await MainActor.run { self.send(request) }
    }

    nonisolated func userNotificationCenter(_ center: UNUserNotificationCenter, willPresent notification: UNNotification) async -> UNNotificationPresentationOptions {
        [.banner, .list]
    }
}
