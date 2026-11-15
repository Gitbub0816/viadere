#if canImport(UIKit) && canImport(SwiftUI) && canImport(CoreImage) && !os(watchOS)
import SwiftUI
import UIKit
import ViadereCore

/// UIKit "Verify with Viadere" button. Same hand-off and panel as `VerifyWithViadereButton` (the panel is the SwiftUI `VerifyPanelView`,
/// presented as a sheet from the nearest view controller).
///
///     let button = VerifyWithViadereUIButton(session: session)
///     button.onSendToPhone = { await myServer.sendVerificationToPhone() }   // optional
///     view.addSubview(button)
@MainActor
public final class VerifyWithViadereUIButton: UIButton {
    public var session: VerifyButtonSession { didSet { update() } }
    public var flow: VerifyButtonFlow = .verify { didSet { update() } }
    public var variant: VerifyButtonVariant = .filled { didSet { update() } }
    public var size: VerifyButtonSize = .medium { didSet { update() } }
    public var display: VerifyButtonDisplay = .label { didSet { update() } }
    /// Offer "Send to my phone" (see `VerifyPanelOption.sendToPhone`). `nil` hides the option.
    public var onSendToPhone: (@MainActor () async -> Void)?
    /// The session's code expired: fetch a new one from your server and assign `session`.
    public var onExpired: (@MainActor () -> Void)?

    public init(session: VerifyButtonSession, variant: VerifyButtonVariant = .filled, size: VerifyButtonSize = .medium, display: VerifyButtonDisplay = .label) {
        self.session = session
        self.variant = variant
        self.size = size
        self.display = display
        super.init(frame: .zero)
        addTarget(self, action: #selector(tapped), for: .primaryActionTriggered)
        registerForTraitChanges([UITraitUserInterfaceStyle.self]) { (button: VerifyWithViadereUIButton, _: UITraitCollection) in button.update() }
        update()
    }

    @available(*, unavailable)
    required init?(coder: NSCoder) { fatalError("init(coder:) is not supported") }

    public override var intrinsicContentSize: CGSize {
        let base = super.intrinsicContentSize
        let height = max(size.height, size.minimumHitTarget)
        return CGSize(width: display == .iconOnly ? height : max(base.width, height), height: height)
    }

    private func update() {
        let colors = VerifyButtonColors.of(variant, dark: traitCollection.userInterfaceStyle == .dark)
        var configuration = UIButton.Configuration.filled()
        configuration.cornerStyle = .capsule
        configuration.baseBackgroundColor = colors.background.map(Self.color) ?? .clear
        configuration.baseForegroundColor = Self.color(colors.foreground)
        configuration.background.strokeColor = Self.color(colors.border)
        configuration.background.strokeWidth = 1
        configuration.image = Self.markImage(height: size.fontSize * 0.95, color: Self.color(colors.foreground))
        configuration.imagePadding = size.fontSize * 0.55
        configuration.contentInsets = NSDirectionalEdgeInsets(top: 0, leading: display == .iconOnly ? 0 : size.height * 0.45, bottom: 0,
                                                              trailing: display == .iconOnly ? 0 : size.height * 0.45)
        if display == .label {
            var title = AttributedString(flow.label)
            title.font = UIFont.systemFont(ofSize: size.fontSize, weight: .semibold)
            configuration.attributedTitle = title
        } else {
            configuration.attributedTitle = nil
        }
        self.configuration = configuration
        accessibilityLabel = flow.label
        invalidateIntrinsicContentSize()
    }

    @objc private func tapped() {
        switch VerifyHandoffPlanner.onTap(device: VerifyDevice.current, session: session) {
        case .openInApp(let url):
            Task { @MainActor [weak self] in
                let opened = await VerifyAppOpener.openInApp(url)
                if VerifyHandoffPlanner.afterOpenInApp(opened: opened) == .showPanel { self?.presentPanel() }
            }
        case .showPanel: presentPanel()
        case .expired: onExpired?()
        case .handedOff: break
        }
    }

    private func presentPanel() {
        guard let presenter = nearestViewController() else { return }
        var host: UIViewController?
        let panel = VerifyPanelView(state: VerifyPanelState(session: session, sendToPhone: onSendToPhone != nil), flow: flow, onSendToPhone: onSendToPhone) {
            host?.dismiss(animated: true)
        }
        let controller = UIHostingController(rootView: panel)
        controller.modalPresentationStyle = .pageSheet
        host = controller
        presenter.present(controller, animated: true)
    }

    private func nearestViewController() -> UIViewController? {
        var responder: UIResponder? = self
        while let current = responder {
            if let controller = current as? UIViewController { return controller.presentedViewController ?? controller }
            responder = current.next
        }
        return nil
    }

    static func color(_ hex: UInt32) -> UIColor {
        UIColor(red: CGFloat((hex >> 16) & 0xFF) / 255, green: CGFloat((hex >> 8) & 0xFF) / 255, blue: CGFloat(hex & 0xFF) / 255, alpha: 1)
    }

    /// The mark drawn from the brand path data.
    static func markImage(height: CGFloat, color: UIColor) -> UIImage {
        let scale = height / VerifyButtonMark.viewBox.height
        let size = CGSize(width: VerifyButtonMark.viewBox.width * scale, height: height)
        return UIGraphicsImageRenderer(size: size).image { _ in
            func path(_ d: String) -> UIBezierPath {
                let bezier = UIBezierPath()
                for command in VerifyButtonMark.commands(d) ?? [] {
                    switch command {
                    case .move(let x, let y): bezier.move(to: CGPoint(x: x * scale, y: y * scale))
                    case .line(let x, let y): bezier.addLine(to: CGPoint(x: x * scale, y: y * scale))
                    case .curve(let x1, let y1, let x2, let y2, let x, let y):
                        bezier.addCurve(to: CGPoint(x: x * scale, y: y * scale), controlPoint1: CGPoint(x: x1 * scale, y: y1 * scale),
                                        controlPoint2: CGPoint(x: x2 * scale, y: y2 * scale))
                    case .close: bezier.close()
                    }
                }
                return bezier
            }
            color.withAlphaComponent(VerifyButtonMark.backFacesOpacity).setFill()
            path(VerifyButtonMark.backFaces).fill()
            color.setFill()
            VerifyButtonMark.frontFaces.forEach { path($0).fill() }
            let r = VerifyButtonMark.dot.radius * scale
            UIBezierPath(ovalIn: CGRect(x: VerifyButtonMark.dot.x * scale - r, y: VerifyButtonMark.dot.y * scale - r, width: r * 2, height: r * 2)).fill()
        }.withRenderingMode(.alwaysOriginal)
    }
}
#endif
