import Foundation
import Observation
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
            statusMessage = "iPhone not reachable"
            return
        }
        session.sendMessageData(data, replyHandler: { reply in
            let result = WatchSync.decodeResult(reply)
            Task { @MainActor in
                self.statusMessage = result.message
                if result == .done || result == .stale || result == .expired { self.items.removeAll { $0.id == request.interactionId } }
            }
        }, errorHandler: { _ in
            Task { @MainActor in self.statusMessage = "Couldn't reach iPhone" }
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
