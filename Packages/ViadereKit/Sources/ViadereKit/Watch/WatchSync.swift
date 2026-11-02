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

    /// W-02: the first line of the long look for a security item. The watch holds no key and never approves (ADR-0022 §8).
    public var approveInstruction: String? { isSecurity ? AuthDeliveryCopy.watchInstruction : nil }
    /// The watch offers Approve only for non-security items that the phone allows inline. Never for a security item.
    public var watchMayApprove: Bool { !isSecurity && !requiresPhone }
}

public struct WatchActionRequest: Codable, Sendable, Equatable {
    public var interactionId: String
    public var decision: Decision
    public var optionId: String?
    /// Set when the action came from a mirrored authentication-delivery notification (`viadere.approve`, `viadere.auth.link`): the category
    /// and the opaque ids (`req`, `adl`) the push carried. Only deny and report are ever forwarded for these.
    public var categoryIdentifier: String?
    public var pushUserInfo: [String: String]?

    public init(interactionId: String, decision: Decision, optionId: String? = nil, categoryIdentifier: String? = nil,
                pushUserInfo: [String: String]? = nil) {
        self.interactionId = interactionId
        self.decision = decision
        self.optionId = optionId
        self.categoryIdentifier = categoryIdentifier
        self.pushUserInfo = pushUserInfo
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
        case .requiresApp, .open, .openApproveRequest, .openAuthDelivery, .openRequests: self = .needsPhone
        case .reduced: self = .done
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
            if case .choose(let choose) = interaction.payload, !choose.allowsMultiple {
                options = choose.options.prefix(4).map { ChoiceOption(id: $0.id, label: InteractionPresentation.optionLabel($0)) }
            }
            let business = UntrustedText.name(envelope.business.displayName, max: 40).text
            // W-01: a sign-in request reads "{Business} sign-in request" on the wrist (the action line is W-02: "Approve on your iPhone.").
            let headline = interaction.kind == .authenticate ? AuthDeliveryCopy.watchApprovalItem(business: business) : InteractionPresentation.headline(interaction)
            return WatchPendingItem(
                id: interaction.id.description, business: business,
                headline: headline, kindLabel: InteractionPresentation.kindLabel(interaction),
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
        if let category = request.categoryIdentifier, AuthNotificationCategory.all.contains(category) {
            // A mirrored authentication-delivery notification: the wrist can only reduce (deny, report). Any other decision is refused.
            guard request.decision == .deny || request.decision == .report else { return .ignored }
            let info = NotificationResponseInfo(actionIdentifier: request.actionIdentifier, categoryIdentifier: category,
                                                userInfo: request.pushUserInfo ?? [:])
            return await handler.handle(info, fromWatch: true)
        }
        guard InteractionID(request.interactionId) != nil else { return .ignored }
        let response = NotificationResponseInfo(actionIdentifier: request.actionIdentifier, userInfo: ["iid": request.interactionId])
        return await handler.handle(response, fromWatch: true)
    }
}
