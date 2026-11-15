import AppIntents
import Foundation

/// A decision activity's Lock Screen / Dynamic Island button (docs/SECURITY.md §2.16).
///
/// Compiled into the app and the widget extension (the widget needs the type for `Button(intent:)`). As a `LiveActivityIntent` it runs
/// in the **app's** process; `ViadereDecisionIntentBridge` is defined per target: the app's runs `LiveDecisionPerformer` (the notification
/// action's signed path, fail closed while the phone is locked), the widget extension's refuses.
///
/// The parameters are only the interaction id and one of the notification action identifiers (`viadere.confirm`, `viadere.decline`,
/// `viadere.option.<id>`); the performer re-fetches the interaction and checks both before anything is signed.
struct ViadereDecisionIntent: LiveActivityIntent {
    // Constant literals (`static let`), as the App Intents metadata extractor expects.
    static let title: LocalizedStringResource = "Answer a request"
    static let description = IntentDescription("Answers a confirmation or a choice from the Lock Screen.")
    /// Never surfaced in Shortcuts or Spotlight: it only makes sense from the activity that carries it.
    static let isDiscoverable = false
    static let openAppWhenRun = false
    /// The system asks for Face ID, Touch ID or the passcode before running it on a locked phone. The performer checks again.
    static let authenticationPolicy: IntentAuthenticationPolicy = .requiresAuthentication

    @Parameter(title: "Request")
    var interactionId: String

    @Parameter(title: "Answer")
    var actionId: String

    init() {}

    init(interactionId: String, actionId: String) {
        self.interactionId = interactionId
        self.actionId = actionId
    }

    func perform() async throws -> some IntentResult {
        await ViadereDecisionIntentBridge.perform(interactionId: interactionId, actionId: actionId)
        return .result()
    }
}
