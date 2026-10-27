import UIKit

/// The foreground key window (presentation anchor for the system passkey sheet). Lives in the app and App Clip
/// only: `UIApplication.shared` is unavailable to app extensions.
enum KeyWindow {
    @MainActor
    static var current: UIWindow? {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        let active = scenes.filter { $0.activationState == .foregroundActive }
        return (active.first ?? scenes.first)?.windows.first(where: \.isKeyWindow) ?? scenes.first?.windows.first
    }
}
