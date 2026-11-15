import SwiftUI
import UIKit
import ViadereKit

/// A delivered one-time code (UX_COPY C-OTP-01, C-OTP-02, C-OTP-04, C-TOTP-01; flows F5 and F6). The sheet opens on who sent it and when
/// it expires, with the code absent: only "Show code" asks the service for it (the one-time `open`). The code lives in the view model's
/// memory only, leaves the screen when it expires (device clock, checked every second), when the sheet closes and when the app goes to the
/// background, is hidden while the screen is recorded, and is copied only as a local-only pasteboard item that expires with the code.
/// Times are absolute ("Expires at …"), never a running countdown (UX_COPY §0 rule 10).
struct CodeDeliverySheet: View {
    @State private var model: CodeDeliveryViewModel
    @State private var capture = ScreenCaptureObserver()
    @State private var toast: String?
    @Environment(\.dismiss) private var dismiss
    @Environment(\.scenePhase) private var scenePhase

    init(deliveryId: UUID) {
        _model = State(initialValue: CodeDeliveryViewModel(deliveryId: deliveryId, api: AppEnvironment.services.authDelivery))
    }

    var body: some View {
        VStack(spacing: 0) {
            ViadereSheetHandle(onClose: { close() })
            ScrollView {
                VStack(alignment: .leading, spacing: ViadereSpace.l) {
                    switch model.phase {
                    case .loading:
                        ViadereLoadingState("Loading").frame(maxWidth: .infinity).padding(.vertical, ViadereSpace.xl)
                    case .ready, .revealing, .revealed:
                        codeCard
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
        .viadereToast($toast)
        .sensoryFeedback(.success, trigger: model.phase) { _, now in now == .revealed }
        .task { await model.load() }
        .task {
            // The expiry check: an expired code leaves the screen and memory within a second.
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                model.tick()
            }
        }
        .onChange(of: scenePhase) { _, phase in
            if phase == .background { close() }
        }
        .onDisappear { model.close() }
    }

    // MARK: Pieces

    private var codeCard: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.s) {
            Text(model.title).font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary).accessibilityAddTraits(.isHeader)
            if let label = model.kindLabel {
                Text(label).font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
            }
            codeArea.padding(.vertical, ViadereSpace.s)
            Text(model.useOnlyLine).font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
            Text(model.neverShareLine).font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
            if let expiry = model.expiryLine(formatter: { $0.formatted(date: .omitted, time: .shortened) }) {
                Text(expiry).font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
            }
        }
    }

    /// The code once revealed (large, monospaced, read digit by digit), or the one button that asks for it.
    @ViewBuilder private var codeArea: some View {
        if model.phase == .revealed {
            if capture.isCaptured {
                ViadereNotice("The code is hidden while the screen is being recorded.", kind: .warning)
            } else {
                Text(model.displayCode)
                    .font(.system(.largeTitle, design: .monospaced, weight: .semibold))
                    .foregroundStyle(ViadereColor.textPrimary)
                    .textSelection(.disabled)
                    .frame(maxWidth: .infinity, alignment: .center)
                    .padding(.vertical, ViadereSpace.m)
                    .accessibilityLabel(model.spokenCode)
                    .privacySensitive()
            }
        } else {
            Button(AuthDeliveryCopy.showCode) { Task { await model.reveal() } }
                .buttonStyle(.viadere(.secondary))
                .frame(minHeight: 44)
                .disabled(!model.canReveal)
        }
    }

    @ViewBuilder private var outcome: some View {
        if let message = model.message {
            ViadereOutcome(model.phase == .reported ? .neutral : .caution, message)
        }
    }

    /// This wasn't me first, Copy code second, equal (UX_COPY §0.2); stacked when they would not fit side by side.
    @ViewBuilder private var footer: some View {
        switch model.phase {
        case .ready, .revealing, .revealed:
            ViewThatFits(in: .horizontal) {
                HStack(spacing: ViadereSpace.s) { notMeButton; copyButton }
                VStack(spacing: ViadereSpace.s) { notMeButton; copyButton }
            }
        case .loading:
            EmptyView()
        default:
            VStack(spacing: ViadereSpace.s) {
                if model.offersTryAgain { Button(AuthDeliveryCopy.tryAgain) { Task { await model.tryAgain() } }.buttonStyle(.viadere(.secondary)) }
                Button("Close") { close() }.buttonStyle(.viadere(.quiet))
            }
        }
    }

    private var notMeButton: some View {
        Button(AuthDeliveryCopy.notMe) { Task { await model.thisWasntMe() } }
            .buttonStyle(.viadere(.secondary))
            .frame(minHeight: 44)
            .disabled(!model.canReport)
    }

    private var copyButton: some View {
        Button(AuthDeliveryCopy.copyCode) { copy() }
            .buttonStyle(.viadere(.secondary))
            .frame(minHeight: 44)
            .disabled(!model.canCopy || capture.isCaptured)
    }

    // MARK: Actions

    private func copy() {
        guard !capture.isCaptured, let request = model.copyRequest() else { return }
        SecurePasteboard.copy(request)
        toast = "Copied. It clears from the clipboard shortly."
    }

    private func close() {
        model.close()
        dismiss()
    }
}
