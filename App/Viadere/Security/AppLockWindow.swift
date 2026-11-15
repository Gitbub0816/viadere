import SwiftUI
import UIKit
import ViadereKit

/// Presents the app lock in its **own window above everything**, including sheets, alerts, full-screen covers and
/// the keyboard of the main window. A SwiftUI overlay inside the main hierarchy sits *under* any sheet the content
/// presents; a window at `.alert + 1` cannot be covered by one, and while it is key nothing in the main window
/// receives touches or focus.
///
/// `AppModel.lock()` also tears down presented state and bumps `lockEpoch` (the content is keyed on it), so
/// nothing is left on screen or in the responder chain behind the lock.
@MainActor
final class AppLockWindowController {
    static let shared = AppLockWindowController()
    private var window: UIWindow?
    private var previousKeyWindow: UIWindow?

    var isPresented: Bool { window != nil }

    func update(locked: Bool, model: AppModel) {
        locked ? present(model: model) : dismiss()
    }

    private func present(model: AppModel) {
        guard window == nil, let scene = Self.activeScene() else { return }
        previousKeyWindow = scene.windows.first(where: \.isKeyWindow)
        let window = UIWindow(windowScene: scene)
        window.windowLevel = UIWindow.Level.alert + 1
        let host = UIHostingController(rootView: AppLockView(model: model))
        host.view.backgroundColor = .clear
        window.rootViewController = host
        window.accessibilityViewIsModal = true
        window.makeKeyAndVisible()
        self.window = window
        // Dismiss the keyboard and any first responder in the content window.
        previousKeyWindow?.endEditing(true)
    }

    private func dismiss() {
        guard let window else { return }
        window.isHidden = true
        window.rootViewController = nil
        self.window = nil
        previousKeyWindow?.makeKey()
        previousKeyWindow = nil
    }

    private static func activeScene() -> UIWindowScene? {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        return scenes.first(where: { $0.activationState == .foregroundActive })
            ?? scenes.first(where: { $0.activationState == .foregroundInactive })
            ?? scenes.first
    }
}
