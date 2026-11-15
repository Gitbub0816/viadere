import SwiftUI
import UIKit
import ViadereKit

/// Opens a verified URL with the system, from the foreground, after the person tapped Continue. Never a web view, never `universalLinksOnly`
/// (a business's universal link may open the business's own app; ADR-0021 §4 item 3).
struct UIApplicationURLOpener: SystemURLOpening {
    @MainActor func open(_ url: URL) async -> Bool { await UIApplication.shared.open(url, options: [:]) }
}

/// The sign-in link screen (shown by `LinkConfirmationSheet` once the delivery is known to be a link; UX_COPY S-LINK-01 and the failure screens, ADR-0021 §4): the verified business, the full destination host, the
/// expiry, and two equal buttons with the safe action first. Opening the screen consumes nothing; only Continue asks for the URL, and
/// Continue stays off until the destination was verified (until Stage 6 delivers the tenant record, every business link fails closed).
struct LinkConfirmationScreen: View {
    @State private var model: LinkConfirmationViewModel
    @Environment(\.dismiss) private var dismiss

    init(deliveryId: UUID) {
        let services = AppEnvironment.services
        // Business-signed destinations are verified against an authority-signed tenant record (ADR-0031). `services.destinationVerifier` is
        // `FailClosedDestinationVerifier` unless `authDeliveryFlags.destinationVerification` is on and the build pins authority keys
        // (`DestinationVerifiers.make`); the flag ships off, so nothing is ever opened until the owner enables it.
        _model = State(initialValue: LinkConfirmationViewModel(
            deliveryId: deliveryId, api: services.authDelivery, verifier: services.destinationVerifier, opener: UIApplicationURLOpener()))
    }

    var body: some View {
        VStack(spacing: 0) {
            ViadereSheetHandle(onClose: { dismiss() })
            ScrollView {
                VStack(alignment: .leading, spacing: ViadereSpace.l) {
                    switch model.phase {
                    case .loading:
                        ViadereLoading().frame(maxWidth: .infinity).padding(.vertical, ViadereSpace.xl)
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
            ViadereOutcome(outcomeKind, message)
        }
    }

    /// Success only when the destination was opened; a report is the person's own refusal; everything else stopped short.
    private var outcomeKind: ViadereOutcome.Kind {
        switch model.phase {
        case .opened: .success
        case .reported: .neutral
        default: .caution
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

