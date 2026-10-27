import Foundation
import UserNotifications
import ViadereCore
import ViadereKit

/// Turns ViadereCore's renderer-defined categories into `UNNotificationCategory` objects.
///
/// - Security approvals use `.authenticationRequired` and, when Face ID is needed, `.foreground`
///   (the action opens the app to the secure approval sheet instead of approving from the lock screen).
/// - `reply` and `message` use a text-input action.
enum NotificationCategories {
    static func action(_ model: NotificationActionModel) -> UNNotificationAction {
        var options: UNNotificationActionOptions = []
        if model.requiresAuthentication { options.insert(.authenticationRequired) }
        if model.opensApp { options.insert(.foreground) }
        if model.style == .destructive { options.insert(.destructive) }
        if model.style == .textInput {
            return UNTextInputNotificationAction(identifier: model.identifier, title: model.title, options: options,
                                                 textInputButtonTitle: "Send", textInputPlaceholder: "Reply")
        }
        return UNNotificationAction(identifier: model.identifier, title: model.title, options: options)
    }

    static func category(_ model: NotificationCategoryModel) -> UNNotificationCategory {
        UNNotificationCategory(
            identifier: model.identifier,
            actions: model.actions.map(action),
            intentIdentifiers: [],
            // Shown instead of the body when the user hides previews on the lock screen.
            hiddenPreviewsBodyPlaceholder: "Viadere needs your attention",
            options: [])
    }

    /// Registers the static categories, keeping any per-interaction `choose` categories the service extension added.
    static func registerStatic() async {
        let center = UNUserNotificationCenter.current()
        let existing = await center.notificationCategories()
        let statics = NotificationEnricher.staticCategorySpecs().map(category)
        let staticIds = Set(statics.map(\.identifier))
        let dynamic = existing.filter { !staticIds.contains($0.identifier) }
        center.setNotificationCategories(Set(statics).union(dynamic))
    }

    /// Removes the per-interaction `viadere.choose.<id>` categories, keeping only the static ones (sign-out).
    static func removeDynamic() async {
        let center = UNUserNotificationCenter.current()
        center.setNotificationCategories(Set(NotificationEnricher.staticCategorySpecs().map(category)))
    }

    /// Adds one category (the service extension registers `viadere.choose.<id>` before delivery).
    static func register(_ model: NotificationCategoryModel) async {
        let center = UNUserNotificationCenter.current()
        var categories = await center.notificationCategories()
        categories = categories.filter { $0.identifier != model.identifier }
        categories.insert(category(model))
        center.setNotificationCategories(categories)
    }

    static func level(_ level: NotificationRendering.InterruptionLevel) -> UNNotificationInterruptionLevel {
        switch level {
        case .passive: return .passive
        case .active: return .active
        case .timeSensitive: return .timeSensitive
        }
    }
}
