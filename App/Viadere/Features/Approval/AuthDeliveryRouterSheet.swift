import SwiftUI
import ViadereKit

/// What `MainShell` presents for every tapped auth-delivery push and every inbox row (`AppModel.pendingAuthDelivery`). The name is kept from
/// when only links existed. It asks the display object once (no secret, nothing consumed), then shows the link screen, the code sheet, or
/// the one line a notice or a failure needs. Nothing here opens, redeems or prefetches anything.
struct LinkConfirmationSheet: View {
    private let deliveryId: UUID
    @State private var surface: AuthDeliverySurface?
    @Environment(\.dismiss) private var dismiss

    init(pending: PendingAuthDelivery) { deliveryId = pending.id }

    var body: some View {
        Group {
            switch surface {
            case nil:
                VStack(spacing: 0) {
                    ViadereSheetHandle(onClose: { dismiss() })
                    Spacer()
                    ViadereLoadingState("Loading")
                    Spacer()
                }
            case .link?:
                LinkConfirmationScreen(deliveryId: deliveryId)
            case .code?:
                CodeDeliverySheet(deliveryId: deliveryId)
            case let resolved?:
                VStack(spacing: ViadereSpace.l) {
                    ViadereSheetHandle(onClose: { dismiss() })
                    Spacer()
                    if let message = resolved.message {
                        ViadereOutcome(Self.outcomeKind(resolved), message).padding(.horizontal, ViadereSpace.screen)
                    }
                    Spacer()
                    VStack(spacing: ViadereSpace.s) {
                        if resolved == .none(.offline) {
                            Button(AuthDeliveryCopy.tryAgain) { Task { await resolve() } }.buttonStyle(.viadere(.secondary))
                        }
                        Button("Close") { dismiss() }.buttonStyle(.viadere(.quiet))
                    }
                    .padding(.horizontal, ViadereSpace.screen)
                    .padding(.bottom, ViadereSpace.m)
                }
            }
        }
        .background(ViadereColor.background)
        .viadereProtectedSurface()
        .privacySensitive()
        .task { if surface == nil { await resolve() } }
    }

    private func resolve() async {
        surface = nil
        surface = await AuthDeliverySurface.resolve(deliveryId: deliveryId, api: AppEnvironment.services.authDelivery)
    }

    /// A notice is information, not a stop; anything else here could not go through.
    private static func outcomeKind(_ surface: AuthDeliverySurface) -> ViadereOutcome.Kind {
        if case .notice = surface { return .neutral }
        return .caution
    }
}
