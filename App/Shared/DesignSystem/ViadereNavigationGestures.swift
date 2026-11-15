//
//  ViadereNavigationGestures.swift
//  The system gestures people expect, kept working under Viadere's hand-built chrome (docs/APP-IA.md, "Gestures"):
//
//   • Swipe right from the left edge goes back. Viadere hides the system navigation bar and draws its own back button, and UIKit turns the
//     interactive pop gesture off whenever the bar is hidden. `ViadereBackButton` installs `ViadereSwipeBack` on its navigation controller,
//     so every pushed screen with a back button pops with the edge swipe again.
//   • Pull down closes a sheet (SwiftUI's own behavior; sheets keep it). Full-screen covers that are not security ceremonies (the QR
//     scanner) get the same pull with `.viaderePullDownToDismiss()`.
//   • A security sheet with an answer in progress is not pulled away by accident: `.interactiveDismissDisabled` while it is engaged, and
//     `ViadereSheetHandle` shows an explicit Close that confirms first.
//

#if os(iOS)
import SwiftUI
import UIKit

// MARK: - Edge swipe back

/// The delegate of every navigation controller's interactive pop gesture once a Viadere back button has appeared in it. It allows the swipe
/// whenever there is a screen to go back to and no transition is already running, regardless of the hidden navigation bar.
@MainActor
final class ViadereSwipeBack: NSObject, UIGestureRecognizerDelegate {
    static let shared = ViadereSwipeBack()

    /// Installs the delegate on `navigationController` (idempotent).
    func install(on navigationController: UINavigationController) {
        guard let recognizer = navigationController.interactivePopGestureRecognizer else { return }
        if recognizer.delegate !== self { recognizer.delegate = self }
        recognizer.isEnabled = true
    }

    func gestureRecognizerShouldBegin(_ gestureRecognizer: UIGestureRecognizer) -> Bool {
        // The recognizer lives on the navigation controller's root view, whose next responder is the controller itself.
        guard let navigationController = gestureRecognizer.view?.next as? UINavigationController else { return false }
        return navigationController.viewControllers.count > 1 && navigationController.transitionCoordinator == nil
    }
}

/// An invisible controller placed in a pushed screen: when it joins the hierarchy it finds its navigation controller and turns the edge
/// swipe back on. Costs nothing when there is no navigation controller (a sheet's root, a preview).
struct ViadereSwipeBackEnabler: UIViewControllerRepresentable {
    func makeUIViewController(context: Context) -> Controller { Controller() }
    func updateUIViewController(_ controller: Controller, context: Context) { controller.installIfPossible() }

    final class Controller: UIViewController {
        override func loadView() {
            let view = UIView(frame: .zero)
            view.isUserInteractionEnabled = false
            view.backgroundColor = .clear
            self.view = view
        }

        override func didMove(toParent parent: UIViewController?) {
            super.didMove(toParent: parent)
            installIfPossible()
        }

        override func viewDidAppear(_ animated: Bool) {
            super.viewDidAppear(animated)
            installIfPossible()
        }

        func installIfPossible() {
            if let navigationController = navigationController ?? findNavigationController() {
                ViadereSwipeBack.shared.install(on: navigationController)
            }
        }

        /// Walks the responder chain when the controller is not (yet) a child of the hosting controller.
        private func findNavigationController() -> UINavigationController? {
            var responder: UIResponder? = viewIfLoaded?.next
            while let current = responder {
                if let navigationController = current as? UINavigationController { return navigationController }
                if let controller = current as? UIViewController, let navigationController = controller.navigationController {
                    return navigationController
                }
                responder = current.next
            }
            return nil
        }
    }
}

extension View {
    /// Keeps the edge swipe back working on a screen that hides the navigation bar. `ViadereBackButton` already does this; use it on a
    /// pushed screen that has no back button of its own.
    public func viadereEdgeSwipeBack() -> some View {
        background(ViadereSwipeBackEnabler().frame(width: 0, height: 0).accessibilityHidden(true))
    }
}

// MARK: - Pull down to dismiss (full-screen covers)

/// A downward pull that closes a full-screen cover the way a sheet closes: the content follows the finger, and past a threshold (or with a
/// quick flick) it dismisses; otherwise it springs back. Never use it on a security ceremony.
struct ViaderePullDownToDismiss: ViewModifier {
    let isEnabled: Bool
    @Environment(\.dismiss) private var dismiss
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var offset: CGFloat = 0

    func body(content: Content) -> some View {
        content
            .offset(y: offset)
            .simultaneousGesture(
                DragGesture(minimumDistance: 24, coordinateSpace: .global)
                    .onChanged { value in
                        guard isEnabled, value.translation.height > 0,
                              abs(value.translation.height) > abs(value.translation.width) else { return }
                        offset = value.translation.height
                    }
                    .onEnded { value in
                        guard isEnabled else { return }
                        let pulledFar = value.translation.height > 140
                        let flicked = value.predictedEndTranslation.height > 320
                        if pulledFar || flicked {
                            dismiss()
                        } else {
                            withAnimation(reduceMotion ? nil : ViadereMotion.standard) { offset = 0 }
                        }
                    },
                including: isEnabled ? .all : .subviews)
            .accessibilityAction(.escape) { if isEnabled { dismiss() } }
    }
}

extension View {
    /// Pull down to close a full-screen cover (the scanner). VoiceOver's two-finger scrub closes it too.
    public func viaderePullDownToDismiss(_ isEnabled: Bool = true) -> some View {
        modifier(ViaderePullDownToDismiss(isEnabled: isEnabled))
    }
}
#endif
