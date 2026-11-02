import SwiftUI
import UIKit
import ViadereKit

/// Opens a verified URL with the system, from the foreground, after the person tapped Continue. Never a web view, never `universalLinksOnly`
/// (a business's universal link may open the business's own app; ADR-0021 §4 item 3).
struct UIApplicationURLOpener: SystemURLOpening {
    @MainActor func open(_ url: URL) async -> Bool { await UIApplication.shared.open(url, options: [:]) }
}

/// The sign-in link screen (UX_COPY S-LINK-01 and the failure screens, ADR-0021 §4): the verified business, the full destination host, the
/// expiry, and two equal buttons with the safe action first. Opening the screen consumes nothing; only Continue asks for the URL, and
/// Continue stays off until the destination was verified (until Stage 6 delivers the tenant record, every business link fails closed).
struct LinkConfirmationSheet: View {
    @State private var model: LinkConfirmationViewModel
    @Environment(\.dismiss) private var dismiss

    init(pending: PendingAuthDelivery) {
        let services = AppEnvironment.services
        // Business-signed destinations are verified against an authority-signed tenant record (ADR-0031), which arrives in Stage 6: until
        // then `FailClosedDestinationVerifier` is the only verifier and nothing is ever opened.
        _model = State(initialValue: LinkConfirmationViewModel(
            deliveryId: pending.id, api: services.authDelivery, verifier: FailClosedDestinationVerifier(), opener: UIApplicationURLOpener()))
    }

    var body: some View {
        VStack(spacing: 0) {
            ViadereSheetHandle(onClose: { dismiss() })
            ScrollView {
                VStack(alignment: .leading, spacing: ViadereSpace.l) {
                    switch model.phase {
                    case .loading:
                        ProgressView().frame(maxWidth: .infinity)
                    case .reviewing, .opening:
                        question
                    default:
                        outcome
                    }
                }
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.top, ViadereSpace.m)
            }
            .scrollIndicators(.hidden)
            footer
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.vertical, ViadereSpace.m)
        }
        .background(ViadereColor.background)
        .viadereProtectedSurface()
        .privacySensitive()
        .task { await model.load() }
    }

    private var question: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.s) {
            Text(model.title).font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary).accessibilityAddTraits(.isHeader)
            if let body = model.body { Text(body).font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary) }
            hostRow
            if let note = model.unusualHostNote { ViadereNotice(note, kind: .warning) }
            if let expiry = model.expiryLine(formatter: { $0.formatted(date: .omitted, time: .shortened) }) {
                Text(expiry).font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
            }
            Text(model.footnote).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
        }
    }

    /// The full host, wrapping and never truncated, with its registrable domain in strong type.
    @ViewBuilder private var hostRow: some View {
        if let host = model.host {
            (Text(host.prefix).foregroundStyle(ViadereColor.textSecondary) + Text(host.strong).fontWeight(.bold).foregroundStyle(ViadereColor.textPrimary))
                .font(ViadereType.headline)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityLabel("Destination \(host.full)")
        }
    }

    @ViewBuilder private var outcome: some View {
        if model.phase != .loading, !model.title.isEmpty, model.display != nil {
            Text(model.title).font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary).accessibilityAddTraits(.isHeader)
        }
        if let message = model.message {
            Text(message).font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
        }
    }

    @ViewBuilder private var footer: some View {
        switch model.phase {
        case .reviewing, .opening:
            ViewThatFits(in: .horizontal) {
                HStack(spacing: ViadereSpace.s) { ForEach(model.buttons) { button($0) } }
                VStack(spacing: ViadereSpace.s) { ForEach(model.buttons) { button($0) } }
            }
        case .notOpened:
            Button(AuthDeliveryCopy.notMe) { Task { await model.thisWasntMe() } }
                .buttonStyle(.viadere(.secondary)).disabled(!model.canReport)
        default:
            VStack(spacing: ViadereSpace.s) {
                if model.offersTryAgain { Button(AuthDeliveryCopy.tryAgain) { Task { await model.tryAgain() } }.buttonStyle(.viadere(.secondary)) }
                Button("Close") { dismiss() }.buttonStyle(.viadere(.quiet))
            }
        }
    }

    private func button(_ spec: SafeActionButton) -> some View {
        Button(spec.title) {
            Task {
                if spec.role == .notMe { await model.thisWasntMe() } else { await model.proceed() }
            }
        }
        .buttonStyle(.viadere(.secondary))
        .frame(minHeight: 44)
        .disabled(!spec.isEnabled)
        .accessibilityLabel(spec.role == .proceed ? model.continueAccessibilityLabel : spec.title)
        .accessibilityInputLabels([spec.title])
    }
}

/// The `/h/` hand-off confirm (F-08): opening the link redeems nothing; Open does.
struct HandoffConfirmationSheet: View {
    let appModel: AppModel
    let confirmation: HandoffConfirmationViewModel
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        VStack(spacing: 0) {
            ViadereSheetHandle(onClose: { appModel.dismissHandoff(); dismiss() })
            VStack(alignment: .leading, spacing: ViadereSpace.l) {
                Text(confirmation.title).font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary).accessibilityAddTraits(.isHeader)
                if let body = confirmation.body { Text(body).font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary) }
                if let message = confirmation.message { Text(message).font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary) }
                Spacer(minLength: 0)
                if confirmation.buttons.isEmpty {
                    Button("Close") { appModel.dismissHandoff(); dismiss() }.buttonStyle(.viadere(.quiet))
                } else {
                    ViewThatFits(in: .horizontal) {
                        HStack(spacing: ViadereSpace.s) { ForEach(confirmation.buttons) { button($0) } }
                        VStack(spacing: ViadereSpace.s) { ForEach(confirmation.buttons) { button($0) } }
                    }
                }
            }
            .padding(.horizontal, ViadereSpace.screen)
            .padding(.vertical, ViadereSpace.m)
        }
        .background(ViadereColor.background)
        .viadereProtectedSurface()
    }

    private func button(_ spec: SafeActionButton) -> some View {
        Button(spec.title) {
            Task {
                if spec.role == .notMe { confirmation.thisWasntMe() } else { await appModel.confirmHandoff() }
            }
        }
        .buttonStyle(.viadere(.secondary))
        .frame(minHeight: 44)
        .disabled(!spec.isEnabled)
        .accessibilityInputLabels([spec.title])
    }
}
