import SwiftUI
import UIKit
import UserNotifications
import UserNotificationsUI
import ViadereKit

/// Custom compact approval UI for sign-in and approval notifications (long-press / expand the banner).
///
/// It renders only the card the service extension prepared (`userInfo["viadere.card"]`), so it needs no
/// network and no credentials. Interaction inside the card is disabled: the notification's own action buttons
/// (and, for sensitive approvals, the secure sheet in the app) do the deciding.
final class NotificationViewController: UIViewController {
    private var host: UIHostingController<NotificationCardView>?

    private func present(_ view: NotificationCardView) {
        host?.willMove(toParent: nil)
        host?.view.removeFromSuperview()
        host?.removeFromParent()
        let controller = UIHostingController(rootView: view)
        controller.view.backgroundColor = .clear
        addChild(controller)
        controller.view.translatesAutoresizingMaskIntoConstraints = false
        self.view.addSubview(controller.view)
        NSLayoutConstraint.activate([
            controller.view.topAnchor.constraint(equalTo: self.view.topAnchor),
            controller.view.leadingAnchor.constraint(equalTo: self.view.leadingAnchor),
            controller.view.trailingAnchor.constraint(equalTo: self.view.trailingAnchor),
            controller.view.bottomAnchor.constraint(equalTo: self.view.bottomAnchor),
        ])
        controller.didMove(toParent: self)
        host = controller
        let width = max(self.view.bounds.width, 320)
        let fitted = controller.sizeThatFits(in: CGSize(width: width, height: .greatestFiniteMagnitude))
        preferredContentSize = CGSize(width: width, height: fitted.height)
    }
}

extension NotificationViewController: @preconcurrency UNNotificationContentExtension {
    func didReceive(_ notification: UNNotification) {
        let content = notification.request.content
        let card = (content.userInfo[NotificationCard.userInfoKey] as? String).flatMap { NotificationCard.decode(json: $0) }
        present(NotificationCardView(card: card, fallbackTitle: content.title, fallbackBody: content.body))
    }
}
