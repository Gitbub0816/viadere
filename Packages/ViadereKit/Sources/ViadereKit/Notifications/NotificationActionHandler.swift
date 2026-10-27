import Foundation
import ViadereCore

public enum NotificationOutcome: Sendable, Equatable {
    /// The decision was signed and accepted.
    case submitted(InteractionID, InteractionStatus)
    /// This request needs the secure approval sheet (Face ID, or the action isn't safe to run inline).
    case requiresApp(InteractionID)
    /// Open the app (optionally on a specific interaction).
    case open(InteractionID?)
    case stale(InteractionID, InteractionStatus)
    case expired(InteractionID)
    case failed(InteractionID?, String)
    case ignored
}

/// Maps a tapped notification action to a signed decision, enforcing the rule that **sensitive decisions are
/// never completed straight from a notification**.
///
/// Inline (no UI) execution is allowed only when no user verification is required to sign it:
/// - `choose`, `confirm`, `acknowledge`, `reply`, `message` at low/standard sensitivity, signed with the `request` key.
/// - `deny` / `report` on sign-in and approval requests, signed at the lowest assurance. A denial can never
///   cause harm; if the server insists on stronger evidence we fall back to opening the app.
/// - **Never** `approve` (or any affirmative decision) on `authenticate` / `authorize` / unknown kinds.
public struct NotificationActionHandler: Sendable {
    private let api: any ViadereAPI
    private let approvals: ApprovalService
    private let clock: @Sendable () -> Date

    public init(api: any ViadereAPI, approvals: ApprovalService, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.api = api
        self.approvals = approvals
        self.clock = clock
    }

    public func handle(_ response: NotificationResponseInfo) async -> NotificationOutcome {
        let intent = NotificationActionParser.parse(actionIdentifier: response.actionIdentifier)
        let id = response.interactionId
        switch intent {
        case .dismiss, .unknown:
            return .ignored
        case .open:
            return .open(id)
        case .decision(let decision, let optionId):
            guard let id else { return .open(nil) }
            return await decide(id: id, decision: decision, optionId: optionId, text: response.userText)
        }
    }

    private func decide(id: InteractionID, decision: Decision, optionId: String?, text: String?) async -> NotificationOutcome {
        let envelope: InteractionEnvelope
        do { envelope = try await api.interaction(id) } catch { return .requiresApp(id) }

        guard envelope.status == .pending else { return .stale(id, envelope.status) }
        guard !envelope.interaction.isExpired(at: clock()) else { return .expired(id) }

        guard let lowAssurance = Self.inlineAssurance(for: envelope.interaction, decision: decision) else { return .requiresApp(id) }

        let selected = decision == .select ? optionId.map { [$0] } : nil
        let reply = decision == .reply ? text?.trimmingCharacters(in: .whitespacesAndNewlines) : nil
        do {
            let outcome = try await approvals.submit(envelope, decision: decision, selectedOptionIds: selected, reply: reply,
                                                     channel: .nativePush, assuranceOverride: lowAssurance)
            return .submitted(id, outcome.status)
        } catch let error as ApprovalError {
            switch error {
            case .expired: return .expired(id)
            case .notActionable(let status): return .stale(id, status)
            case .deviceCannotSatisfy, .keyInvalidated, .notEnrolled, .userCancelled, .authenticationFailed: return .requiresApp(id)
            case .invalidSelection, .decisionNotAllowed: return .requiresApp(id)
            default: return .failed(id, error.userMessage)
            }
        } catch {
            return .failed(id, "Something went wrong.")
        }
    }

    /// The assurance to sign with when the decision may run inline, or `nil` if it must open the app.
    public static func inlineAssurance(for interaction: Interaction, decision: Decision) -> DecisionAssurance? {
        if interaction.kind.isUnknown { return nil }
        if interaction.kind.isSecuritySensitive {
            // Only refusals may be completed from the lock screen.
            return (decision == .deny || decision == .report) ? DecisionAssurance.none : nil
        }
        let plan = SigningPlan.plan(for: AssurancePolicy.requiredAssurance(for: interaction))
        return plan.assurance == .none ? DecisionAssurance.none : nil
    }
}
