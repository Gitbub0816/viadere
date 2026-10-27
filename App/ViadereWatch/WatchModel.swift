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

    override init() {
        super.init()
        guard WCSession.isSupported() else { return }
        WCSession.default.delegate = self
        WCSession.default.activate()
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
        let reachable = session.isReachable
        Task { @MainActor in
            self.isReachable = reachable
            if let context { self.items = WatchSync.decode(context) }
        }
    }

    nonisolated func session(_ session: WCSession, didReceiveApplicationContext applicationContext: [String: Any]) {
        guard let data = applicationContext[WatchSync.contextKey] as? Data else { return }
        Task { @MainActor in self.items = WatchSync.decode(data) }
    }

    nonisolated func sessionReachabilityDidChange(_ session: WCSession) {
        let reachable = session.isReachable
        Task { @MainActor in self.isReachable = reachable }
    }
}
