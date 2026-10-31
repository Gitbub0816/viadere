import Foundation
import ViadereCore

// Decision Live Activities (docs/SECURITY.md §2.16): a pending `confirm` / `choose` on the Lock Screen and in the Dynamic Island, with
// buttons that answer it through the same signed path as a notification action.
//
// The server starts the activity with a neutral state (no business text). The app then fetches the interaction over the authenticated
// API and writes the sanitized title, detail and options into the activity itself (`LiveDecisionEnrichment`). The widget lays out
// `LiveDecisionPresentation`; a button runs the app's `LiveActivityIntent`, which calls `LiveDecisionPerformer`.

/// The action identifiers a decision activity's buttons carry. They are the notification action identifiers (`viadere.confirm`,
/// `viadere.decline`, `viadere.option.<id>`), so the decision goes through `NotificationActionHandler` unchanged. Nothing else is
/// accepted: never approve, deny, report, reply or acknowledge.
public enum LiveDecisionAction: Sendable, Equatable {
    case confirm
    case decline
    case select(optionId: String)

    /// The category the performer reports to `NotificationActionHandler` (never the security-push category).
    public static let categoryIdentifier = "viadere.liveactivity.decision"

    public init?(actionIdentifier: String) {
        guard actionIdentifier.count <= 128 else { return nil }
        switch NotificationActionParser.parse(actionIdentifier: actionIdentifier) {
        case .decision(.confirm, _): self = .confirm
        case .decision(.decline, _): self = .decline
        case .decision(.select, let option?) where Self.isValidOptionId(option): self = .select(optionId: option)
        default: return nil
        }
    }

    public var actionIdentifier: String {
        switch self {
        case .confirm: NotificationActionID.prefix + "confirm"
        case .decline: NotificationActionID.prefix + "decline"
        case .select(let option): NotificationActionID.optionPrefix + option
        }
    }

    /// Option ids follow the interaction contract: 1–64 of `[A-Za-z0-9_.-]`.
    public static func isValidOptionId(_ id: String) -> Bool {
        (1...64).contains(id.count) && id.unicodeScalars.allSatisfy { $0.isASCII && (CharacterSet.alphanumerics.contains($0) || "_.-".unicodeScalars.contains($0)) }
    }
}

/// Interaction → the enriched, device-only content of a decision activity. Pure; every business string is sanitized and bounded.
public enum LiveDecisionEnrichment {
    public static let titleMax = 80
    public static let detailMax = 120
    public static let labelMax = 24

    /// The enriched state, or `state` unchanged (neutral, the generic presentation) when the envelope is not the activity's interaction,
    /// belongs to another business, or is no longer something the Lock Screen may answer.
    public static func enriched(_ state: DecisionActivityState, businessId: String, from envelope: InteractionEnvelope,
                                now: Date) -> DecisionActivityState {
        let interaction = envelope.interaction
        guard interaction.id == state.interactionId, envelope.business.id.description == businessId else { return state.neutral }
        var result = state.neutral
        result.expiresAt = interaction.expiresAt
        if envelope.status != .pending {
            result.stage = DecisionActivityState.stage(for: envelope.status)
            return result
        }
        if interaction.isExpired(at: now) {
            result.stage = .expired
            return result
        }
        // Eligibility can only have been true at issue time; re-checking keeps a rendering the renderer marks secure text-free here too.
        guard LiveActivityPolicy.isDecisionEligible(interaction, livemode: true) else { return result }
        switch (state.kind, interaction.payload) {
        case (.confirm, .confirm(let p)):
            result.title = nonEmpty(UntrustedText.line(p.title, max: titleMax))
            result.detail = UntrustedText.optionalLine(p.details, max: detailMax)
        case (.choose, .choose(let p)):
            result.title = nonEmpty(UntrustedText.line(p.prompt, max: titleMax))
            if !p.allowsMultiple, p.options.count <= DecisionActivityState.maxOptions {
                let options = p.options.compactMap { option -> DecisionActivityState.Option? in
                    guard LiveDecisionAction.isValidOptionId(option.id),
                          let label = UntrustedText.optionalLine(option.label, max: labelMax) else { return nil }
                    return DecisionActivityState.Option(id: option.id, label: label)
                }
                // All or nothing: a partial list would hide a choice the business offered.
                result.options = options.count == p.options.count && !options.isEmpty ? options : nil
            }
        default:
            return result
        }
        return result
    }

    private static func nonEmpty(_ text: String) -> String? { text.isEmpty ? nil : text }
}

/// What the widget draws for a decision activity, as plain data. Text is sanitized again at render time (content state is data).
public struct LiveDecisionPresentation: Equatable, Sendable {
    public struct ActionButton: Equatable, Sendable, Identifiable {
        public var id: String { actionIdentifier }
        public var actionIdentifier: String
        public var label: String
        public var isDestructive: Bool
        /// The one emphasized answer (Confirm). Choices are never emphasized: no option is nudged over another.
        public var isPrimary: Bool = false
        public var accessibilityLabel: String
    }

    public var business: String
    public var headline: String
    public var detail: String?
    /// Inline answers. Empty when the decision is finished, expired, or can only be answered in the app.
    public var buttons: [ActionButton]
    /// Show an "Open" link to the interaction in the app (`openURL`).
    public var showsOpen: Bool
    public var openURL: URL?
    /// "Answered", "Expired" or "Withdrawn" once finished.
    public var stageText: String?
    /// One short word for the compact Dynamic Island.
    public var compact: String
    public var expiresAt: Date
    public var isPending: Bool
    public var isEnriched: Bool

    public static let openLabel = "Open"

    public init(state: DecisionActivityState, businessName rawBusinessName: String, now: Date = Date()) {
        business = UntrustedText.name(rawBusinessName, max: 40, attribution: nil).text
        expiresAt = state.expiresAt
        isEnriched = state.isEnriched
        openURL = URL(string: "\(DeepLinkRouter.customScheme)://i/\(state.interactionId)")
        let stage: DecisionActivityState.Stage = state.stage == .pending && now >= state.expiresAt ? .expired : state.stage
        isPending = stage == .pending
        let title = state.title.flatMap { UntrustedText.optionalLine($0, max: LiveDecisionEnrichment.titleMax) }
        headline = title ?? "\(business) needs a quick decision"
        detail = state.detail.flatMap { UntrustedText.optionalLine($0, max: LiveDecisionEnrichment.detailMax) }
        switch stage {
        case .pending:
            stageText = nil
            compact = "Decide"
        case .answered:
            stageText = "Answered"
            compact = "Done"
        case .expired:
            stageText = "Expired"
            compact = "Expired"
        case .cancelled:
            stageText = "Withdrawn"
            compact = "Off"
        }
        guard isPending else {
            buttons = []
            showsOpen = false
            if title == nil { headline = "\(business): \(stageText?.lowercased() ?? "finished")" }
            return
        }
        switch state.kind {
        case .confirm:
            let subject = title ?? "this request"
            if title != nil {
                buttons = [
                    ActionButton(actionIdentifier: LiveDecisionAction.confirm.actionIdentifier, label: "Confirm", isDestructive: false,
                                 isPrimary: true, accessibilityLabel: "Confirm \(subject)"),
                    ActionButton(actionIdentifier: LiveDecisionAction.decline.actionIdentifier, label: "Decline", isDestructive: true,
                                 accessibilityLabel: "Decline \(subject)"),
                ]
                showsOpen = false
            } else {
                // Without the details (the fetch failed) only the safe direction is offered inline: nobody confirms what they could
                // not read. "Open" shows it in the app.
                buttons = [ActionButton(actionIdentifier: LiveDecisionAction.decline.actionIdentifier, label: "Decline", isDestructive: true,
                                        accessibilityLabel: "Decline the request from \(business)")]
                showsOpen = true
                if detail == nil { detail = "Open Viadere to see what it is." }
            }
        case .choose:
            let options = (state.options ?? []).prefix(DecisionActivityState.maxOptions).compactMap { option -> ActionButton? in
                guard LiveDecisionAction.isValidOptionId(option.id),
                      let label = UntrustedText.optionalLine(option.label, max: LiveDecisionEnrichment.labelMax) else { return nil }
                return ActionButton(actionIdentifier: LiveDecisionAction.select(optionId: option.id).actionIdentifier, label: label,
                                    isDestructive: false, accessibilityLabel: "Choose \(label)")
            }
            // Options only with the question they answer, and only all of them.
            if title != nil, !options.isEmpty, options.count == state.options?.count {
                buttons = options
                showsOpen = false
            } else {
                buttons = []
                showsOpen = true
                if detail == nil { detail = "Open Viadere to choose." }
            }
        }
    }
}

/// What happened when a decision activity's button was pressed.
public enum LiveDecisionResult: Sendable, Equatable {
    /// The decision is final (answered here, or already answered, expired or withdrawn): show the stage and end the activity.
    case finished(DecisionActivityState.Stage)
    /// Not something the Lock Screen may answer (or the details could not be checked): leave the activity and review it in the app.
    case openApp
    /// The device is locked (protected data unavailable). Nothing was fetched, signed or sent.
    case locked
    /// The button does not belong to this activity's decision. Nothing was sent.
    case rejected
    case failed(String)
}

/// Runs a decision activity's button. It adds checks in front of `NotificationActionHandler` and then calls it, so the decision is signed
/// exactly as a notification action is (the device request key, `channel: nativePush`, the context digest of what was fetched).
///
/// Fails closed: no decision while protected data is unavailable (the request key's keychain class is `AfterFirstUnlock`, so signing alone
/// would not stop a locked phone), only `confirm`, `decline` or one of the interaction's own options, and only for an interaction that is
/// still decision-eligible (`LiveActivityPolicy.isDecisionEligible`: never sign-in, approval, secure or promotional requests).
public struct LiveDecisionPerformer: Sendable {
    private let api: any ViadereAPI
    private let handler: NotificationActionHandler
    private let isProtectedDataAvailable: @Sendable () async -> Bool
    private let clock: @Sendable () -> Date

    public init(api: any ViadereAPI, handler: NotificationActionHandler, isProtectedDataAvailable: @escaping @Sendable () async -> Bool,
                clock: @escaping @Sendable () -> Date = { Date() }) {
        self.api = api
        self.handler = handler
        self.isProtectedDataAvailable = isProtectedDataAvailable
        self.clock = clock
    }

    public func perform(interactionId rawId: String, actionIdentifier: String) async -> LiveDecisionResult {
        guard let id = InteractionID(rawId), let action = LiveDecisionAction(actionIdentifier: actionIdentifier) else { return .rejected }
        guard await isProtectedDataAvailable() else { return .locked }
        let envelope: InteractionEnvelope
        do { envelope = try await api.interaction(id) } catch { return .openApp }
        guard envelope.status == .pending else { return .finished(DecisionActivityState.stage(for: envelope.status)) }
        guard !envelope.interaction.isExpired(at: clock()) else { return .finished(.expired) }
        let interaction = envelope.interaction
        guard LiveActivityPolicy.isDecisionEligible(interaction, livemode: true) else { return .openApp }
        switch (action, interaction.payload) {
        case (.confirm, .confirm), (.decline, .confirm):
            break
        case (.select(let option), .choose(let p)) where p.options.contains(where: { $0.id == option }):
            break
        default:
            return .rejected
        }
        // Checked again right before signing: the phone may have locked while the details were fetched.
        guard await isProtectedDataAvailable() else { return .locked }
        let outcome = await handler.handle(NotificationResponseInfo(
            actionIdentifier: action.actionIdentifier, categoryIdentifier: LiveDecisionAction.categoryIdentifier,
            userInfo: [PushPayload.interactionKey: id.description]))
        switch outcome {
        case .submitted(_, let status), .stale(_, let status): return .finished(DecisionActivityState.stage(for: status))
        case .expired: return .finished(.expired)
        case .requiresApp, .open: return .openApp
        case .failed(_, let message): return .failed(message)
        case .ignored: return .rejected
        }
    }
}
