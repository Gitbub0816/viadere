import SwiftUI
import UIKit

/// Hides the app in the app switcher.
///
/// iOS snapshots the key window when the app resigns active. A plain full-screen cover (brand mark on the
/// background colour) is added **synchronously** from `willResignActiveNotification` and removed on
/// `didBecomeActive`, so approvals, amounts and messages never appear in the multitasking card.
@MainActor
final class PrivacyShield {
    private var cover: UIView?
    private var observers: [NSObjectProtocol] = []

    init() {
        let center = NotificationCenter.default
        observers.append(center.addObserver(forName: UIApplication.willResignActiveNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.show() }
        })
        observers.append(center.addObserver(forName: UIApplication.didBecomeActiveNotification, object: nil, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated { self?.hide() }
        })
    }

    private var keyWindow: UIWindow? {
        let scenes = UIApplication.shared.connectedScenes.compactMap { $0 as? UIWindowScene }
        return scenes.flatMap(\.windows).first(where: \.isKeyWindow) ?? scenes.first?.windows.first
    }

    private func show() {
        guard cover == nil, let window = keyWindow else { return }
        let view = UIView(frame: window.bounds)
        view.autoresizingMask = [.flexibleWidth, .flexibleHeight]
        view.backgroundColor = UIColor { traits in
            traits.userInterfaceStyle == .dark
                ? UIColor(red: 0.07, green: 0.07, blue: 0.067, alpha: 1)
                : UIColor(red: 0.961, green: 0.949, blue: 0.925, alpha: 1)
        }
        if let image = UIImage(named: "BrandMark") {
            let imageView = UIImageView(image: image)
            imageView.contentMode = .scaleAspectFit
            imageView.translatesAutoresizingMaskIntoConstraints = false
            view.addSubview(imageView)
            NSLayoutConstraint.activate([
                imageView.centerXAnchor.constraint(equalTo: view.centerXAnchor),
                imageView.centerYAnchor.constraint(equalTo: view.centerYAnchor),
                imageView.widthAnchor.constraint(equalToConstant: 120),
                imageView.heightAnchor.constraint(equalToConstant: 56),
            ])
        }
        view.isAccessibilityElement = false
        window.addSubview(view)
        cover = view
    }

    private func hide() {
        cover?.removeFromSuperview()
        cover = nil
    }
}
