import Foundation
import ViadereKit
import WatchConnectivity

/// iPhone side of the watch companion: publishes a minimal, already-rendered pending list and applies watch
/// actions through the **same safety policy as notification actions** (sensitive approvals always finish on the
/// phone with Face ID; the watch just says "Review on iPhone").
final class WatchBridge: NSObject, WCSessionDelegate, @unchecked Sendable {
    private let services: ViadereServices

    init(services: ViadereServices) {
        self.services = services
        super.init()
        guard WCSession.isSupported() else { return }
        WCSession.default.delegate = self
        WCSession.default.activate()
    }

    /// Pushes the current pending list to the watch (latest-wins application context).
    func push(_ content: HomeContent) {
        guard WCSession.isSupported() else { return }
        let session = WCSession.default
        guard session.activationState == .activated, session.isPaired, session.isWatchAppInstalled,
              let data = WatchSync.encode(WatchSync.items(from: content, now: Date())) else { return }
        try? session.updateApplicationContext([WatchSync.contextKey: data])
    }

    // MARK: WCSessionDelegate

    func session(_ session: WCSession, activationDidCompleteWith activationState: WCSessionActivationState, error: (any Error)?) {}
    func sessionDidBecomeInactive(_ session: WCSession) {}
    func sessionDidDeactivate(_ session: WCSession) { session.activate() }

    func session(_ session: WCSession, didReceiveMessageData messageData: Data, replyHandler: @escaping (Data) -> Void) {
        guard let request = WatchSync.decodeRequest(messageData) else {
            replyHandler(WatchSync.encode(.failed))
            return
        }
        let reply = ReplyBox(replyHandler)
        let handler = services.notificationHandler
        Task {
            let outcome = await WatchSync.handle(request, using: handler)
            reply.send(WatchSync.encode(WatchActionResult(outcome)))
            if case .requiresApp = outcome { await AppEnvironment.shared.apply(outcome) }
        }
    }
}

/// WatchConnectivity reply handlers aren't `Sendable`; they are safe to call once from any thread.
private final class ReplyBox: @unchecked Sendable {
    private let handler: (Data) -> Void
    init(_ handler: @escaping (Data) -> Void) { self.handler = handler }
    func send(_ data: Data) { handler(data) }
}
