import PassKit
import SwiftUI
import UIKit
import ViadereCore
import ViadereKit

/// Apple's own "Add to Apple Wallet" button. This is stock UI on purpose: Apple requires `PKAddPassButton` for
/// adding passes, and the sheet it leads to (`PKAddPassesViewController`) is the only supported way to add one.
struct AddToWalletButton: UIViewRepresentable {
    let action: () -> Void
    @Environment(\.colorScheme) private var colorScheme

    func makeCoordinator() -> Coordinator { Coordinator(action: action) }

    func makeUIView(context: Context) -> PKAddPassButton {
        let button = PKAddPassButton(addPassButtonStyle: colorScheme == .dark ? .blackOutline : .black)
        button.addTarget(context.coordinator, action: #selector(Coordinator.tapped), for: .touchUpInside)
        return button
    }

    func updateUIView(_ button: PKAddPassButton, context: Context) {
        context.coordinator.action = action
        button.addPassButtonStyle = colorScheme == .dark ? .blackOutline : .black
    }

    final class Coordinator: NSObject {
        var action: () -> Void
        init(action: @escaping () -> Void) { self.action = action }
        @objc func tapped() { action() }
    }
}

/// Presents `PKAddPassesViewController` for a pass the server signed and `PKPass(data:)` validated.
@MainActor
final class WalletPresenter: NSObject, PKAddPassesViewControllerDelegate {
    private static var active: WalletPresenter?
    private var onFinished: (() -> Void)?

    /// Returns `false` if the pass can't be shown (PassKit refused it or no view controller is available).
    @discardableResult
    static func present(_ prepared: PreparedPass, onFinished: @escaping () -> Void) -> Bool {
        guard PKAddPassesViewController.canAddPasses(),
              let pass = try? PKPass(data: prepared.data),
              let controller = PKAddPassesViewController(pass: pass),
              let top = topViewController() else { return false }
        let presenter = WalletPresenter()
        presenter.onFinished = onFinished
        controller.delegate = presenter
        active = presenter
        top.present(controller, animated: true)
        return true
    }

    nonisolated func addPassesViewControllerDidFinish(_ controller: PKAddPassesViewController) {
        // PassKit calls its delegate on the main thread.
        MainActor.assumeIsolated {
            controller.dismiss(animated: true)
            onFinished?()
            Self.active = nil
        }
    }

    private static func topViewController() -> UIViewController? {
        var controller = KeyWindow.current?.rootViewController
        while let presented = controller?.presentedViewController { controller = presented }
        return controller
    }
}

/// The Wallet affordance for one pass: Apple's add button, an "In Wallet" state, or nothing when Wallet isn't available.
struct WalletPassAction: View {
    let pass: WalletPassMetadata
    let wallet: WalletPassCoordinator
    @Environment(\.scenePhase) private var scenePhase
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.xs) {
            switch wallet.state(for: pass) {
            case .unavailable:
                EmptyView()
            case .voided:
                ViadereBadge("No longer valid", kind: .danger)
            case .inWallet:
                HStack(spacing: ViadereSpace.s) {
                    ViadereBadge("In Wallet", kind: .success)
                    Spacer()
                    Button("Open in Wallet") { openInWallet() }
                        .buttonStyle(.viadere(.quiet, fullWidth: false))
                }
            case .notInWallet:
                AddToWalletButton { Task { await add() } }
                    .frame(height: 52)
                    .opacity(wallet.isPreparing.contains(pass.id) ? 0.5 : 1)
                    .disabled(wallet.isPreparing.contains(pass.id))
                    .accessibilityLabel(Text("Add to Apple Wallet"))
            }
            if let error { ViadereNotice(error, kind: .warning) }
        }
        .task { wallet.refresh([pass]) }
        .onChange(of: scenePhase) { _, phase in if phase == .active { wallet.refresh([pass]) } }
    }

    private func add() async {
        error = nil
        do {
            let prepared = try await wallet.prepare(pass)
            let shown = WalletPresenter.present(prepared) { wallet.refresh([pass]) }
            if !shown { error = WalletPassError.invalidPass.userMessage }
        } catch let failure as WalletPassError {
            error = failure.userMessage
        } catch {
            self.error = WalletPassError.invalidPass.userMessage
        }
    }

    private func openInWallet() {
        guard let url = PKPassLibrary().pass(withPassTypeIdentifier: pass.passTypeIdentifier, serialNumber: pass.serialNumber)?.passURL else { return }
        UIApplication.shared.open(url)
    }
}

#if DEBUG
#Preview("Wallet action") {
    PreviewHost { services in
        let model = AppModel(services: services, walletLibrary: MockWalletLibrary())
        WalletPassAction(pass: PreviewData.walletPass(PreviewData.loyaltyPassId, business: PreviewData.juniperCoffee, kind: .storeCard), wallet: model.wallet)
            .padding(ViadereSpace.screen)
    }
}
#endif
