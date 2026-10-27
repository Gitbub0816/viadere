import Observation
import UIKit

/// Tells sensitive screens when the display is being recorded or mirrored (`UIScreen.isCaptured`) and when a
/// screenshot was just taken, so they can show a notice, pause approvals or hide a redemption code.
@MainActor @Observable
final class ScreenCaptureObserver {
    private(set) var isCaptured = false
    /// Increments on every screenshot (`UIApplication.userDidTakeScreenshotNotification`). Observe with `onChange`.
    private(set) var screenshotCount = 0
    @ObservationIgnored private var token: NSObjectProtocol?
    @ObservationIgnored private var screenshotToken: NSObjectProtocol?

    init() {
        refresh()
        token = NotificationCenter.default.addObserver(forName: UIScreen.capturedDidChangeNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.refresh() }
        }
        screenshotToken = NotificationCenter.default.addObserver(forName: UIApplication.userDidTakeScreenshotNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.screenshotCount += 1 }
        }
    }

    func refresh() {
        let scene = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.first
        isCaptured = scene?.screen.isCaptured ?? false
    }
}
