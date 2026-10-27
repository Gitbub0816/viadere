import Observation
import UIKit

/// Tells the approval screen when the display is being recorded or mirrored (`UIScreen.isCaptured`), so it can
/// show a notice and pause approvals.
@MainActor @Observable
final class ScreenCaptureObserver {
    private(set) var isCaptured = false
    @ObservationIgnored private var token: NSObjectProtocol?

    init() {
        refresh()
        token = NotificationCenter.default.addObserver(forName: UIScreen.capturedDidChangeNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.refresh() }
        }
    }

    func refresh() {
        let scene = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }.first
        isCaptured = scene?.screen.isCaptured ?? false
    }
}
