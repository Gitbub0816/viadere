import Foundation

/// The widget extension's side of `ViadereDecisionIntent`. A `LiveActivityIntent` runs in the app's process, so this is never expected
/// to run; if it ever did, it refuses: the extension holds no signing path and must never decide anything.
enum ViadereDecisionIntentBridge {
    static func perform(interactionId: String, actionId: String) async {}
}
