import Foundation
import ViadereCore

/// What the iPhone shares with the watch app: a minimal, already-rendered list of pending requests.
/// Secrets never cross: no challenges, no tokens, no keys. The watch can *request* an action; the phone
/// applies the same inline-action policy as a notification action (sensitive approvals always need the phone).
public struct WatchPendingItem: Codable, Sendable, Equatable, Identifiable, Hashable {
    public var id: String
    public var business: String
    public var headline: String
    public var kindLabel: String
    public var expiresAt: Date
    /// True when approving needs Face ID / Touch ID on the phone: the watch shows "Review on iPhone".
    public var requiresPhone: Bool
    /// Inline options for a `choose` request.
    public var options: [ChoiceOption]
    public var isSecurity: Bool
}

public struct WatchActionRequest: Codable, Sendable, Equatable {
    public var interactionId: String
    public var decision: Decision
    public var optionId: String?

    public init(interactionId: String, decision: Decision, optionId: String? = nil) {
        self.interactionId = interactionId
        self.decision = decision
        self.optionId = optionId
    }

    /// The equivalent notification action identifier, so the watch goes through the exact same safety rules.
    var actionIdentifier: String {
        if decision == .select, let optionId { return NotificationActionID.optionPrefix + optionId }
        return NotificationActionID.prefix + decision.rawValue
    }
}

/// What the phone tells the watch after a watch-originated action.
public enum WatchActionResult: String, Codable, Sendable, Equatable {
    case done, needsPhone, stale, expired, failed

    public init(_ outcome: NotificationOutcome) {
        switch outcome {
        case .submitted: self = .done
        case .requiresApp, .open: self = .needsPhone
        case .stale: self = .stale
        case .expired: self = .expired
        case .failed, .ignored: self = .failed
        }
    }

    public var message: String {
        switch self {
        case .done: "Sent"
        case .needsPhone: "Finish on your iPhone"
        case .stale: "Already handled"
        case .expired: "Expired"
        case .failed: "Couldn't send"
        }
    }
}

public enum WatchSync {
    public static let contextKey = "pending.v1"
    public static let messageKey = "action.v1"
    public static let maxItems = 5

    public static func items(from content: HomeContent, now: Date) -> [WatchPendingItem] {
        content.pending.prefix(maxItems).map { envelope in
            let interaction = envelope.interaction
            var options: [ChoiceOption] = []
            if case .choose(let choose) = interaction.payload, !choose.allowsMultiple { options = Array(choose.options.prefix(4)) }
            return WatchPendingItem(
                id: interaction.id.description, business: envelope.business.displayName,
                headline: InteractionPresentation.headline(interaction), kindLabel: InteractionPresentation.kindLabel(interaction),
                expiresAt: interaction.expiresAt,
                requiresPhone: NotificationActionHandler.inlineAssurance(for: interaction, decision: .approve) == nil,
                options: options, isSecurity: interaction.kind.isSecuritySensitive)
        }
    }

    public static func encode(_ items: [WatchPendingItem]) -> Data? { try? ViadereJSON.encode(items) }
    public static func decode(_ data: Data) -> [WatchPendingItem] { (try? ViadereJSON.decode([WatchPendingItem].self, from: data)) ?? [] }

    public static func encode(_ request: WatchActionRequest) -> Data? { try? ViadereJSON.encode(request) }
    public static func decodeRequest(_ data: Data) -> WatchActionRequest? { try? ViadereJSON.decode(WatchActionRequest.self, from: data) }

    public static func encode(_ result: WatchActionResult) -> Data { Data(result.rawValue.utf8) }
    public static func decodeResult(_ data: Data) -> WatchActionResult {
        WatchActionResult(rawValue: String(decoding: data, as: UTF8.self)) ?? .failed
    }

    /// Phone side: runs a watch-originated request through the notification-action safety policy.
    public static func handle(_ request: WatchActionRequest, using handler: NotificationActionHandler) async -> NotificationOutcome {
        guard InteractionID(request.interactionId) != nil else { return .ignored }
        let response = NotificationResponseInfo(actionIdentifier: request.actionIdentifier, userInfo: ["iid": request.interactionId])
        return await handler.handle(response)
    }
}
