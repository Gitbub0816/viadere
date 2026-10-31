import Foundation
import UIKit
import ViadereKit

/// The app's object graph. `services` is a plain `Sendable` value so background callbacks can use it directly;
/// everything UI-related lives on the main actor.
@MainActor
final class AppEnvironment {
    static let shared = AppEnvironment()

    /// Keychain-backed, Secure Enclave-keyed, certificate-pinned. See `ViadereServices.live`.
    nonisolated static let services: ViadereServices = ViadereServices.live(
        configuration: ViadereRuntime.configuration,
        passkeys: ApplePasskeyService(anchorProvider: { KeyWindow.current }),
        notificationPermission: UserNotificationPermissionService(),
        appLock: LocalAuthenticationAppLock(),
        residue: AppLocalResidueCleaner())

    let model: AppModel
    let privacyShield = PrivacyShield()
    let captureObserver = ScreenCaptureObserver()
    let liveActivities: LiveActivityManager
    let watchBridge: WatchBridge
    /// Verify (WP3): which verification request is open, and the client that talks to `/v1/verifications`.
    let verification = VerificationCenter()
    let verifyAPI: any VerifyAPI = LiveVerifyAPI.make(services: AppEnvironment.services)
    /// Customer profile (docs/PROFILES.md): which profile request is open, and the client for `/v1/profile`.
    let profile = ProfileCenter()
    let profileAPI: any ProfileAPI = LiveProfileAPI.make(services: AppEnvironment.services)
    /// Hosted Loops (WP-3.6): which instance is open and which consent prompt a start attempt needs.
    let loops = LoopCenter()

    /// Approve v2 (WP1): pairwise approval keys, the verified key directory, freeze. Closed (and says so) when the build pins no log key.
    let approve: ApproveController
    /// "Add business" by a business's link-session QR (WP-C1). Closed when the build pins no link-descriptor key.
    let link: LinkController

    private init() {
        approve = ApproveController(environment: ApproveEnvironment.live(services: Self.services))
        link = LinkController(flow: ApproveEnvironment.liveLinkFlow(services: Self.services))
        model = AppModel(services: Self.services, walletLibrary: PassKitWalletLibrary())
        liveActivities = LiveActivityManager(services: Self.services)
        watchBridge = WatchBridge(services: Self.services)
    }

    /// Applies the result of a notification action (opens the secure sheet, shows a toast, refreshes Home).
    func apply(_ outcome: NotificationOutcome) async {
        await model.apply(outcome)
    }
}
