import SwiftUI
import ViadereCore
import ViadereKit

/// A short-lived, single-use code the business scans or reads. It exists only on screen: it disappears when the
/// countdown ends, when this view goes away, when the app backgrounds, and while the screen is being recorded.
struct RedemptionView: View {
    @Bindable var model: RedemptionViewModel
    let onClose: () -> Void
    @State private var capture = ScreenCaptureObserver()
    @State private var copied = false
    @Environment(\.scenePhase) private var scenePhase

    var body: some View {
        VStack(spacing: 0) {
            ViadereGrabber()
            ScrollView {
                VStack(alignment: .leading, spacing: ViadereSpace.l) {
                    header
                    content
                }
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.top, ViadereSpace.m)
                .padding(.bottom, ViadereSpace.l)
            }
            .scrollIndicators(.hidden)
            footer
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.top, ViadereSpace.s)
                .padding(.bottom, ViadereSpace.m)
        }
        .background(ViadereColor.background)
        .privacySensitive()
        .interactiveDismissDisabled(model.isBusy)
        .task {
            await model.start()
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                model.tick(Date())
            }
        }
        .onChange(of: capture.isCaptured, initial: true) { _, captured in model.isScreenBeingCaptured = captured }
        .onChange(of: capture.screenshotCount) { _, _ in model.noteScreenshot() }
        .onChange(of: scenePhase) { _, phase in if phase != .active { model.invalidate() } }
        .onDisappear { model.invalidate() }
        .sensoryFeedback(.success, trigger: model.phase == .active)
    }

    private var header: some View {
        HStack(spacing: ViadereSpace.s) {
            ViadereAvatar(name: model.businessName, size: 48, isVerified: model.entry.business.isVerified)
            VStack(alignment: .leading, spacing: 4) {
                Text(model.businessName).font(ViadereType.headline).foregroundStyle(ViadereColor.textPrimary)
                Text(model.rewardTitle).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
            }
            Spacer(minLength: 0)
            if model.phase == .active {
                ViadereCountdownRing(progress: model.fraction, label: model.countdownLabel, spokenLabel: model.spokenCountdown)
            }
        }
    }

    @ViewBuilder private var content: some View {
        switch model.phase {
        case .idle, .requesting:
            VStack(spacing: ViadereSpace.s) {
                ViadereLoading(height: 32)
                Text("Getting your code…").font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
            }
            .frame(maxWidth: .infinity, minHeight: 240)
        case .active:
            activeCode
        case .expired:
            message(symbol: "clock", title: "This code expired", text: "It only works for a couple of minutes. Nothing was used. Get a new one when you're at the counter.")
        case .refused(let text):
            message(symbol: "xmark.circle", title: "Not available", text: text)
        case .failed(let text):
            message(symbol: "wifi.exclamationmark", title: "Couldn't get a code", text: text)
        }
    }

    @ViewBuilder private var activeCode: some View {
        VStack(spacing: ViadereSpace.l) {
            if let payload = model.qrPayload, let display = model.displayCode {
                QRCodeView(payload: payload)
                Text(display)
                    .font(.system(size: 34, weight: .semibold, design: .monospaced))
                    .foregroundStyle(ViadereColor.textPrimary)
                    .tracking(2)
                    .accessibilityLabel(Text(model.spokenCode ?? ""))
                    .textSelection(.disabled)
                Text(model.spokenCountdown)
                    .font(ViadereType.subhead.weight(.medium))
                    .foregroundStyle(ViadereColor.accent)
                    .monospacedDigit()
            } else {
                ViadereNotice("Your screen is being recorded or mirrored, so the code is hidden. Stop recording to show it.", kind: .warning)
            }
            if model.screenshotTaken {
                ViadereNotice("A screenshot was taken. This code works once and expires soon, so don't share it.", kind: .warning)
            }
            Text("Show this at the counter. It works once.")
                .font(ViadereType.subhead)
                .foregroundStyle(ViadereColor.textSecondary)
        }
        .frame(maxWidth: .infinity)
    }

    private func message(symbol: String, title: String, text: String) -> some View {
        VStack(alignment: .leading, spacing: ViadereSpace.s) {
            Image(systemName: symbol).font(.system(size: 30, weight: .light)).foregroundStyle(ViadereColor.textTertiary).accessibilityHidden(true)
            Text(title).font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary)
            Text(text).font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary).fixedSize(horizontal: false, vertical: true)
        }
        .padding(.top, ViadereSpace.l)
    }

    @ViewBuilder private var footer: some View {
        switch model.phase {
        case .active:
            VStack(spacing: ViadereSpace.xs) {
                Button("Done") { model.invalidate(); onClose() }.buttonStyle(.viadere(.primary))
                if let code = model.codeForSecureCopy {
                    Button(copied ? "Copied" : "Copy code") {
                        SecurePasteboard.copy(code)
                        copied = true
                    }
                    .buttonStyle(.viadere(.quiet))
                }
            }
        case .expired, .failed:
            VStack(spacing: ViadereSpace.xs) {
                Button("Get a new code") { copied = false; Task { await model.start() } }.buttonStyle(.viadere(.primary))
                Button("Close", action: onClose).buttonStyle(.viadere(.quiet))
            }
        case .idle, .requesting:
            Button("Cancel", action: onClose).buttonStyle(.viadere(.quiet)).disabled(model.isBusy)
        case .refused:
            Button("Close", action: onClose).buttonStyle(.viadere(.secondary))
        }
    }
}

#if DEBUG
#Preview("Redemption") {
    PreviewHost { services in
        RedemptionPreview(services: services)
    }
}

private struct RedemptionPreview: View {
    let services: ViadereServices
    @State private var model: RedemptionViewModel?

    var body: some View {
        Group {
            if let model { RedemptionView(model: model) {} } else { ViadereLoading() }
        }
        .task {
            let rewards = RewardsViewModel(services: services)
            await rewards.load()
            if let entry = rewards.overview.rewards.first(where: { $0.eligibility.nextAction == .redeem }) { model = rewards.redemption(for: entry) }
        }
    }
}
#endif
