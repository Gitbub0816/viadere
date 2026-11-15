import Foundation
import UIKit
import ViadereKit

/// The app's side of `ViadereDecisionIntent` (the widget extension has a refusing stub of the same name).
///
/// Runs `LiveDecisionPerformer`, which decides through `NotificationActionHandler` (signed with the device request key exactly as a
/// notification action) and refuses while protected data is unavailable: the request key's keychain class is `AfterFirstUnlock`, so a
/// locked phone could otherwise still sign. On a final result the activity shows the stage and is dismissed shortly after; anything
/// else (locked, needs the secure sheet, failure) leaves the activity untouched so the person can open the app from it.
enum ViadereDecisionIntentBridge {
    static func perform(interactionId: String, actionId: String) async {
        let services = AppEnvironment.services
        let performer = LiveDecisionPerformer(
            api: services.api, handler: services.notificationHandler,
            isProtectedDataAvailable: { await MainActor.run { UIApplication.shared.isProtectedDataAvailable } })
        let result = await performer.perform(interactionId: interactionId, actionIdentifier: actionId)
        switch result {
        case .finished(let stage):
            await AppEnvironment.shared.liveActivities.finishDecision(interactionId: interactionId, stage: stage)
            // Home refreshes like after a notification action.
            await AppEnvironment.shared.model.home.load()
        case .openApp, .locked, .rejected, .failed:
            ViadereLog.notifications.info("liveactivity.decision.notdone")
        }
    }
}
