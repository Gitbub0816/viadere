import SwiftUI
import ViadereKit

/// App Clip: quick connect for `https://viadere.com/c/{code}` (QR, NFC, link). It shows the verified business and
/// purpose-scoped consent, creates a passkey account if needed, connects, then offers the full app.
@main
struct ViadereClipApp: App {
    @State private var flow = ClipFlowModel(services: ClipEnvironment.services)

    var body: some Scene {
        WindowGroup {
            ClipRootView(flow: flow)
                .onContinueUserActivity(NSUserActivityTypeBrowsingWeb) { activity in
                    guard let url = activity.webpageURL else { return }
                    Task { await flow.handle(url: url) }
                }
                .onOpenURL { url in Task { await flow.handle(url: url) } }
        }
    }
}

enum ClipEnvironment {
    /// Keychain items stay private to the clip (no shared group); passkey UI is available.
    static let services = ViadereServices.live(
        configuration: ViadereRuntime.configuration,
        passkeys: ApplePasskeyService(anchorProvider: { KeyWindow.current }),
        notificationPermission: UserNotificationPermissionService())
}
