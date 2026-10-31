import Foundation
import UserNotifications
import ViadereKit

/// Turns an opaque push into a rich, actionable notification.
///
/// The push carries only an interaction id (`iid`): no names, amounts or locations travel through APNs. This
/// extension fetches the interaction over the authenticated, device-signed API (using the shared Keychain
/// session), renders it with ViadereCore's `ChannelRenderer`, and registers the per-interaction `choose`
/// category before the notification is shown. If anything fails it falls back to a generic "Open Viadere" banner.
///
/// Brand Kits (WP-2.7): a non-security request may carry the business's approved logo as an attachment, taken only from the verified
/// local cache (`BrandKitStore`, re-hashed on read) under `BrandSurfacePolicy`; nothing is downloaded here, so branding can never delay
/// or replace the notification. Sign-in approvals, payment authorizations and security purposes never get one.
final class NotificationService: UNNotificationServiceExtension {
    private static let services = ViadereServices.live(configuration: ViadereRuntime.configuration)
    private var pending: PendingDelivery?
    private var task: Task<Void, Never>?

    override func didReceive(_ request: UNNotificationRequest, withContentHandler contentHandler: @escaping (UNNotificationContent) -> Void) {
        guard let mutable = request.content.mutableCopy() as? UNMutableNotificationContent else {
            contentHandler(request.content)
            return
        }
        guard let id = PushPayload.interactionId(from: request.content.userInfo) else {
            contentHandler(mutable)
            return
        }
        let delivery = PendingDelivery(content: mutable, handler: contentHandler)
        pending = delivery
        let enricher = Self.services.notificationEnricher
        let brandKits = Self.services.brandKits
        task = Task {
            let enriched = await enricher.enrich(interactionId: id)
            await delivery.deliver(enriched, logo: enriched.brandAttachment(from: brandKits)?.data)
        }
    }

    /// The system is about to kill the extension: show what we have (the generic banner) rather than nothing.
    override func serviceExtensionTimeWillExpire() {
        task?.cancel()
        pending?.deliverBestAttempt()
    }
}

/// Delivers exactly once, whichever of "enriched" or "time expired" happens first.
private final class PendingDelivery: @unchecked Sendable {
    private let lock = NSLock()
    private var delivered = false
    private let content: UNMutableNotificationContent
    private let handler: (UNNotificationContent) -> Void

    init(content: UNMutableNotificationContent, handler: @escaping (UNNotificationContent) -> Void) {
        self.content = content
        self.handler = handler
    }

    private func claim() -> Bool {
        lock.lock(); defer { lock.unlock() }
        if delivered { return false }
        delivered = true
        return true
    }

    func deliver(_ enriched: EnrichedNotification, logo: Data?) async {
        // The category must exist before the notification is presented.
        await NotificationCategories.register(enriched.category)
        guard claim() else { return }
        if let logo, let attachment = Self.attachment(logo) { content.attachments = [attachment] }
        content.title = enriched.title
        content.subtitle = enriched.subtitle
        content.body = enriched.body
        content.threadIdentifier = enriched.threadIdentifier
        content.categoryIdentifier = enriched.category.identifier
        content.interruptionLevel = NotificationCategories.level(enriched.interruptionLevel)
        content.relevanceScore = enriched.interruptionLevel == .timeSensitive ? 1.0 : (enriched.interruptionLevel == .passive ? 0.1 : 0.5)
        var userInfo = content.userInfo
        for (key, value) in enriched.userInfo { userInfo[key] = value }
        content.userInfo = userInfo
        handler(content)
    }

    /// A PNG attachment from verified bytes, via a uniquely named temporary file (the system moves it into its own store).
    private static func attachment(_ data: Data) -> UNNotificationAttachment? {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("viadere-brand-\(UUID().uuidString).png")
        do {
            try data.write(to: url, options: [.atomic])
            return try UNNotificationAttachment(identifier: "viadere.brand.logo", url: url,
                                                options: [UNNotificationAttachmentOptionsTypeHintKey: "public.png"])
        } catch {
            try? FileManager.default.removeItem(at: url)
            return nil
        }
    }

    func deliverBestAttempt() {
        guard claim() else { return }
        content.title = "Viadere"
        content.body = "Open Viadere to review a request."
        content.categoryIdentifier = "viadere.unknown"
        handler(content)
    }
}
