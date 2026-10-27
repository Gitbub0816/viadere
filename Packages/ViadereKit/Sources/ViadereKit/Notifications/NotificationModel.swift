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
        case "open": return .open
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
