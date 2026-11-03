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
    /// A reduce-only answer (Deny, This wasn't me) to an authentication-delivery push was signed and accepted. No unlock was needed.
    case reduced(ReduceAction)
    /// A tapped Approve v2 push or its "Review" action: open that request (F-15), not the Alerts list.
    case openApproveRequest(String)
    /// A tapped link or code push or its "Open" action: open the confirm screen for that delivery. Nothing is opened or consumed yet.
    case openAuthDelivery(UUID)
    /// A tapped `viadere.oidc` push (`login_hint` path): open the OIDC confirm screen. Nothing is signed from the notification.
    case openOIDCSignIn(String)
    /// An authentication-delivery push that names nothing usable: open the list of requests.
    case openRequests
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
    private let authDelivery: any AuthDeliveryAPI
    private let notices: any LocalSecurityNoticePosting

    public init(api: any ViadereAPI, approvals: ApprovalService, clock: @escaping @Sendable () -> Date = { Date() },
                authDelivery: any AuthDeliveryAPI = UnavailableAuthDeliveryAPI(),
                notices: any LocalSecurityNoticePosting = NoLocalSecurityNotices()) {
        self.api = api
        self.approvals = approvals
        self.clock = clock
        self.authDelivery = authDelivery
        self.notices = notices
    }

    /// - Parameter fromWatch: the action was forwarded by the watch app. The watch is a notification surface, never an authenticator
    ///   (ADR-0022 §8): on a security item it may only deny or report, so anything else is refused (`.ignored`) rather than sent to the phone.
    public func handle(_ response: NotificationResponseInfo, fromWatch: Bool = false) async -> NotificationOutcome {
        // Authentication-delivery pushes (`viadere.approve`, `viadere.auth.*`): Deny and This wasn't me reduce without unlock; everything
        // else opens the request or the confirm screen. There is no approve path from a notification (ADR-0022 §5.5).
        if AuthNotificationCategory.all.contains(response.categoryIdentifier) {
            return await handleAuthDelivery(response, fromWatch: fromWatch)
        }
        // A security push has no subject: tapping it or "Review" opens the app, which fetches the notices itself.
        if response.categoryIdentifier == SecurityPush.categoryIdentifier || response.actionIdentifier == SecurityPush.reviewActionIdentifier {
            return response.actionIdentifier == NotificationActionID.systemDismiss ? .ignored : .open(nil)
        }
        let intent = NotificationActionParser.parse(actionIdentifier: response.actionIdentifier)
        let id = response.interactionId
        switch intent {
        case .dismiss, .unknown:
            return .ignored
        case .open:
            return .open(id)
        case .decision(let decision, let optionId):
            guard let id else { return .open(nil) }
            return await decide(id: id, decision: decision, optionId: optionId, text: response.userText, fromWatch: fromWatch)
        }
    }

    private func handleAuthDelivery(_ response: NotificationResponseInfo, fromWatch: Bool) async -> NotificationOutcome {
        if response.actionIdentifier == NotificationActionID.systemDismiss { return .ignored }
        let target = PushPayload.target(category: response.categoryIdentifier, userInfo: response.userInfo)
        let reduce: ReduceAction?
        switch response.actionIdentifier {
        case AuthNotificationCategory.denyAction: reduce = .deny
        case AuthNotificationCategory.reportAction: reduce = .report
        default: reduce = nil
        }
        if let reduce {
            let pushTarget: AuthPushTarget
            switch target {
            case .approveRequest(let id)?: pushTarget = .approveRequest(id)
            case .authDelivery(let id)?: pushTarget = .delivery(id)
            default:
                // Nothing usable to refuse. Deny runs in the background (the app is not brought forward), so the person must be told that
                // nothing was sent (N-09) rather than left believing the request was denied.
                await notices.postDenyNotSent()
                return .openRequests
            }
            do {
                try await authDelivery.reduce(pushTarget, action: reduce)
                return .reduced(reduce)
            } catch {
                // Never queued (ADR-0022 §5.6): one attempt, then a local notice and the inbox item. The business sees `pending` until expiry.
                await notices.postDenyNotSent()
                return .failed(nil, AuthDeliveryCopy.n09Body)
            }
        }
        // Review, Open, the default tap, and anything unexpected (including an `approve` identifier, which no auth category offers): open the
        // item. Nothing is signed and nothing is consumed.
        if fromWatch { return .ignored }
        switch target {
        case .approveRequest(let id)?: return .openApproveRequest(id)
        case .authDelivery(let id)?: return .openAuthDelivery(id)
        case .oidcSignIn(let ach)?: return .openOIDCSignIn(ach)
        case .interaction(let id)?: return .open(id)
        default: return .openRequests
        }
    }

    private func decide(id: InteractionID, decision: Decision, optionId: String?, text: String?, fromWatch: Bool = false) async -> NotificationOutcome {
        let envelope: InteractionEnvelope
        do { envelope = try await api.interaction(id) } catch { return .requiresApp(id) }
        // The watch never approves a security item (ADR-0022 §8): only a refusal from the wrist is honoured, and nothing is handed to the phone.
        if fromWatch, envelope.interaction.kind.isSecuritySensitive, decision != .deny, decision != .report { return .ignored }

        guard envelope.status == .pending else { return .stale(id, envelope.status) }
        guard !envelope.interaction.isExpired(at: clock()) else { return .expired(id) }

        guard let lowAssurance = Self.inlineAssurance(for: envelope.interaction, decision: decision) else { return .requiresApp(id) }

        let selected = decision == .select ? optionId.map { [$0] } : nil
        let reply = decision == .reply ? text?.trimmingCharacters(in: .whitespacesAndNewlines) : nil
        do {
            let outcome = try await approvals.submit(envelope, decision: decision, selectedOptionIds: selected, reply: reply,
                                                     channel: .nativePush, assuranceOverride: lowAssurance, verifyFresh: false)
            return .submitted(id, outcome.status)
        } catch let error as ApprovalError {
            switch error {
            case .expired: return .expired(id)
            case .notActionable(let status): return .stale(id, status)
            case .deviceCannotSatisfy, .keyInvalidated, .keysUnavailable, .notEnrolled, .userCancelled, .authenticationFailed: return .requiresApp(id)
            case .invalidSelection, .decisionNotAllowed: return .requiresApp(id)
            // The request changed or this device is in its cool-down: the secure sheet shows the current details and the reason.
            case .contextChanged, .deviceCoolingDown, .updateRequired: return .requiresApp(id)
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
