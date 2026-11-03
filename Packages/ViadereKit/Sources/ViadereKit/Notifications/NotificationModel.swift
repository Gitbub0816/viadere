import Foundation
import ViadereCore

/// Action identifiers produced by `ChannelRenderer` (`viadere.<id>`) plus the system's own.
public enum NotificationActionID {
    public static let prefix = "viadere."
    public static let optionPrefix = "viadere.option."
    public static let systemDefaultTap = "com.apple.UNNotificationDefaultActionIdentifier"
    public static let systemDismiss = "com.apple.UNNotificationDismissActionIdentifier"
}

/// The opaque identifier carried by the push. Nothing sensitive travels in the payload: the notification
/// service extension resolves `iid` over the authenticated API.
///
/// Server push contract (documented in App/README.md):
/// ```
/// { "aps": { "alert": { "title": "Viadere", "body": "Open to review" }, "mutable-content": 1,
///            "category": "viadere.unknown", "thread-id": "business.<id>", "interruption-level": "time-sensitive" },
///   "v": 1, "iid": "<interaction uuid>" }
/// ```
public enum PushPayload {
    public static let interactionKey = "iid"

    public static func interactionId(from userInfo: [AnyHashable: Any]) -> InteractionID? {
        for key in [interactionKey, "interactionId"] {
            if let string = userInfo[key] as? String, let id = InteractionID(string) { return id }
        }
        return nil
    }

    /// Flattens a notification `userInfo` to strings (drops `aps` and non-string values).
    public static func stringify(_ userInfo: [AnyHashable: Any]) -> [String: String] {
        var result: [String: String] = [:]
        for (key, value) in userInfo {
            if let key = key as? String, key != "aps", let value = value as? String { result[key] = value }
        }
        return result
    }
}

/// The categories and actions of the authentication-delivery pushes (ADR-0020 §6, ADR-0022 §5.5, ADR-0021 §4 item 5; UX_COPY §1).
///
/// - `viadere.approve`: **Review** (foreground: iOS unlocks first) and **Deny** (no authentication, no foreground: works on a locked phone
///   after first unlock and signs a reduce-only deny). There is no Approve action and no Report action on an approval notification.
/// - `viadere.auth.link`: **Open** (foreground) and **This wasn't me** (reduce-only report, no unlock).
/// - `viadere.auth.code`: no actions; a tap opens the app, where the code is shown after unlock.
public enum AuthNotificationCategory {
    public static let approve = "viadere.approve"
    public static let link = "viadere.auth.link"
    public static let code = "viadere.auth.code"
    /// "Sign in with Viadere" `login_hint` push (`ach` only). Review opens the confirm screen; there is no inline answer (the factor needs the
    /// approval key and the typed number).
    public static let oidc = OIDCPushPayloadPolicy.category
    public static let all: Set<String> = [approve, link, code, oidc]

    public static let reviewAction = "viadere.review"
    public static let openAction = "viadere.open"
    public static let denyAction = "viadere.deny"
    public static let reportAction = "viadere.report"

    /// Neutral wording and style: equal prominence, no destructive (red) role on the safe action.
    /// Deny appears only when `flags.notificationDeny` is on (Stage 4 review R4-03).
    public static func approveCategory(flags: AuthDeliveryFlags) -> NotificationCategoryModel {
        var actions = [NotificationActionModel(identifier: reviewAction, title: AuthDeliveryCopy.review, style: .normal, requiresAuthentication: true, opensApp: true)]
        if flags.notificationDeny {
            actions.append(NotificationActionModel(identifier: denyAction, title: AuthDeliveryCopy.deny, style: .normal, requiresAuthentication: false, opensApp: false))
        }
        return NotificationCategoryModel(identifier: approve, actions: actions)
    }
    public static let approveCategory = approveCategory(flags: .shipping)
    public static let linkCategory = NotificationCategoryModel(identifier: link, actions: [
        NotificationActionModel(identifier: openAction, title: AuthDeliveryCopy.open, style: .normal, requiresAuthentication: true, opensApp: true),
        NotificationActionModel(identifier: reportAction, title: AuthDeliveryCopy.notMe, style: .normal, requiresAuthentication: false, opensApp: false),
    ])
    public static let codeCategory = NotificationCategoryModel(identifier: code, actions: [])
    public static let oidcCategory = NotificationCategoryModel(identifier: oidc, actions: [
        NotificationActionModel(identifier: reviewAction, title: AuthDeliveryCopy.review, style: .normal, requiresAuthentication: true, opensApp: true),
    ])
    public static let categories = [approveCategory, linkCategory, codeCategory, oidcCategory]
}

/// Where a tapped authentication-delivery push goes (F-14, F-15): the request itself, never the Alerts list.
public enum NotificationTarget: Sendable, Equatable {
    /// An Approve v2 request (`req`).
    case approveRequest(String)
    /// A link or code delivery (`adl`).
    case authDelivery(UUID)
    /// The category is ours but the payload names nothing usable: the request list in the app (still not "Alerts").
    case pendingRequests
    /// A legacy interaction (`iid`).
    case interaction(InteractionID)
    /// An OIDC sign-in (`ach`, `viadere.oidc`).
    case oidcSignIn(String)
}

extension PushPayload {
    public static let requestKey = "req"
    public static let deliveryKey = "adl"

    /// `req`: 1 to 64 characters of `[A-Za-z0-9_-]` (an opaque request id; anything else is ignored, never trusted).
    public static func requestId(from userInfo: [String: String]) -> String? {
        guard let value = userInfo[requestKey], (1...64).contains(value.utf8.count),
              value.unicodeScalars.allSatisfy({ $0.isASCII && (CharacterSet.alphanumerics.contains($0) || $0 == "-" || $0 == "_") }) else { return nil }
        return value
    }

    public static func deliveryId(from userInfo: [String: String]) -> UUID? { userInfo[deliveryKey].flatMap { UUID(uuidString: $0) } }

    /// Resolves a delivered push to its destination. The category decides which key is read, so a `req` on a link push is not followed.
    public static func target(category: String, userInfo: [String: String]) -> NotificationTarget? {
        switch category {
        case AuthNotificationCategory.approve:
            if let id = requestId(from: userInfo) { return .approveRequest(id) }
            if let id = userInfo[interactionKey].flatMap({ InteractionID($0) }) { return .interaction(id) }
            return .pendingRequests
        case AuthNotificationCategory.link, AuthNotificationCategory.code:
            if let id = deliveryId(from: userInfo) { return .authDelivery(id) }
            return .pendingRequests
        case AuthNotificationCategory.oidc:
            if let ach = userInfo[OIDCPushPayloadPolicy.challengeKey], AuthorityChallengeID.isValid(ach) { return .oidcSignIn(ach) }
            return nil
        default:
            return userInfo[interactionKey].flatMap { InteractionID($0) }.map(NotificationTarget.interaction)
        }
    }
}

/// A user's response to a delivered notification, in platform-neutral form.
public struct NotificationResponseInfo: Sendable, Equatable {
    public var actionIdentifier: String
    public var categoryIdentifier: String
    public var userInfo: [String: String]
    public var userText: String?

    public init(actionIdentifier: String, categoryIdentifier: String = "", userInfo: [String: String] = [:], userText: String? = nil) {
        self.actionIdentifier = actionIdentifier
        self.categoryIdentifier = categoryIdentifier
        self.userInfo = userInfo
        self.userText = userText
    }

    public var interactionId: InteractionID? {
        for key in [PushPayload.interactionKey, "interactionId"] {
            if let value = userInfo[key], let id = InteractionID(value) { return id }
        }
        return nil
    }
}

public enum NotificationIntent: Sendable, Equatable {
    case decision(Decision, optionId: String?)
    /// Open the app on this interaction (default tap, "More options", "View", secure approve).
    case open
    case dismiss
    case unknown
}

public enum NotificationActionParser {
    public static func parse(actionIdentifier: String) -> NotificationIntent {
        switch actionIdentifier {
        case NotificationActionID.systemDefaultTap: return .open
        case NotificationActionID.systemDismiss: return .dismiss
        default: break
        }
        if actionIdentifier.hasPrefix(NotificationActionID.optionPrefix) {
            let option = String(actionIdentifier.dropFirst(NotificationActionID.optionPrefix.count))
            return option.isEmpty ? .unknown : .decision(.select, optionId: option)
        }
        guard actionIdentifier.hasPrefix(NotificationActionID.prefix) else { return .unknown }
        switch String(actionIdentifier.dropFirst(NotificationActionID.prefix.count)) {
        case "approve": return .decision(.approve, optionId: nil)
        case "deny": return .decision(.deny, optionId: nil)
        case "report": return .decision(.report, optionId: nil)
        case "confirm": return .decision(.confirm, optionId: nil)
        case "decline": return .decision(.decline, optionId: nil)
        case "acknowledge": return .decision(.acknowledge, optionId: nil)
        case "reply": return .decision(.reply, optionId: nil)
        case "open", "review": return .open
        default: return .unknown
        }
    }
}

/// Kit-side mirrors of ViadereCore's notification specs (whose initializers are not public), constructible by
/// the app for fallbacks and tests. Convert to `UNNotificationAction` / `UNNotificationCategory` in the UI layer.
public struct NotificationActionModel: Sendable, Equatable {
    public var identifier: String
    public var title: String
    public var style: NotificationActionSpec.Style
    public var requiresAuthentication: Bool
    public var opensApp: Bool

    public init(identifier: String, title: String, style: NotificationActionSpec.Style = .normal,
                requiresAuthentication: Bool = true, opensApp: Bool = false) {
        self.identifier = identifier
        self.title = title
        self.style = style
        self.requiresAuthentication = requiresAuthentication
        self.opensApp = opensApp
    }

    public init(_ spec: NotificationActionSpec) {
        self.init(identifier: spec.identifier, title: spec.title, style: spec.style,
                  requiresAuthentication: spec.requiresAuthentication, opensApp: spec.opensApp)
    }
}

public struct NotificationCategoryModel: Sendable, Equatable {
    public var identifier: String
    public var actions: [NotificationActionModel]

    public init(identifier: String, actions: [NotificationActionModel]) {
        self.identifier = identifier
        self.actions = actions
    }

    public init(_ spec: NotificationCategorySpec) {
        self.init(identifier: spec.identifier, actions: spec.actions.map(NotificationActionModel.init))
    }
}
