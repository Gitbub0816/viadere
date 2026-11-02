import Foundation
import UserNotifications
import ViadereKit

/// The local "Deny not sent yet. Open Viadere." notice (UX_COPY N-09, ADR-0022 §5.6). A Deny from a notification is attempted once inside the
/// action's background window; if it cannot be sent nothing is queued, this notice is posted and the request stays in the inbox. The business
/// sees `pending` until the request expires. Deliberately no actions and no business name: it must read correctly on a locked screen.
struct LocalSecurityNotices: LocalSecurityNoticePosting {
    func postDenyNotSent() async {
        let content = UNMutableNotificationContent()
        content.title = AuthDeliveryCopy.n09Title
        content.body = AuthDeliveryCopy.n09Body
        content.interruptionLevel = .active
        content.threadIdentifier = "viadere.general"
        // One notice at a time: a second failed Deny replaces it rather than stacking.
        let request = UNNotificationRequest(identifier: "viadere.deny.notsent", content: content, trigger: nil)
        try? await UNUserNotificationCenter.current().add(request)
    }
}
