import SwiftUI
import UIKit
import ViadereCore
import ViadereKit

/// "Save your recovery codes": the recovery ID and ten single-use codes, shown **once** (after sign-up, after a recovery completes, after
/// "Generate new codes"). The codes live only in `RecoveryCodesViewModel`'s memory: this view never stores, logs or restores them.
///
/// - **Copy** goes through `SecurePasteboard` (local only, expires).
/// - **Save to Files** opens the system share sheet with the text (a stock control); the person chooses where it goes.
/// - **I saved these** must be ticked before Continue works.
/// - A screenshot or screen recording is noticed (the codes hide while the screen is captured), as for redemption codes.
struct RecoveryCodesView: View {
    @Bindable var model: RecoveryCodesViewModel
    var title = "Save your recovery codes"
    var continueTitle = "Continue"
    let onContinue: () -> Void
    @State private var capture = ScreenCaptureObserver()
    @State private var showingShare = false

    var body: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: ViadereSpace.l) {
                    ViadereMark.monochrome(ViadereColor.textTertiary).frame(height: 30).padding(.top, ViadereSpace.l)
                    VStack(alignment: .leading, spacing: ViadereSpace.s) {
                        Text(title)
                            .font(ViadereType.display)
                            .foregroundStyle(ViadereColor.textPrimary)
                            .fixedSize(horizontal: false, vertical: true)
                            .accessibilityAddTraits(.isHeader)
                        Text("If you ever lose every device, these are the only way back into your account. Each code works once, and Viadere can't show them again.")
                            .font(ViadereType.body)
                            .foregroundStyle(ViadereColor.textSecondary)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    codes
                    notices
                    Text("Keep them somewhere private, like a password manager or a printed page at home. Anyone with the ID and one code can start recovering your account.")
                        .font(ViadereType.footnote)
                        .foregroundStyle(ViadereColor.textTertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.bottom, ViadereSpace.l)
            }
            .scrollIndicators(.hidden)
            actions
        }
        .viadereScreenBackground()
        .privacySensitive()
        .onChange(of: capture.isCaptured, initial: true) { _, captured in model.isScreenBeingCaptured = captured }
        .onChange(of: capture.screenshotCount) { _, _ in model.noteScreenshot() }
        .sheet(isPresented: $showingShare) {
            if let text = model.exportText {
                ShareSheet(text: text) { showingShare = false }
                    .presentationDetents([.medium, .large])
            }
        }
    }

    // MARK: Codes

    @ViewBuilder private var codes: some View {
        if let visible = model.visibleCodes, let id = model.recoveryId {
            VStack(alignment: .leading, spacing: 0) {
                VStack(alignment: .leading, spacing: 4) {
                    Text("Recovery ID").font(ViadereType.footnote.weight(.medium)).foregroundStyle(ViadereColor.textSecondary)
                    Text(id)
                        .font(.system(size: 22, weight: .semibold, design: .monospaced))
                        .foregroundStyle(ViadereColor.textPrimary)
                        .textSelection(.disabled)
                        .accessibilityLabel(Text("Recovery ID " + id.filter { $0 != "-" }.map(String.init).joined(separator: " ")))
                }
                .padding(ViadereSpace.m)
                ViadereHairline()
                LazyVGrid(columns: [GridItem(.flexible(), alignment: .leading), GridItem(.flexible(), alignment: .leading)],
                          alignment: .leading, spacing: ViadereSpace.m) {
                    ForEach(Array(visible.enumerated()), id: \.offset) { index, code in
                        HStack(spacing: ViadereSpace.xs) {
                            Text("\(index + 1)")
                                .font(ViadereType.caption)
                                .foregroundStyle(ViadereColor.textTertiary)
                                .frame(width: 18, alignment: .trailing)
                            Text(code)
                                .font(.system(size: 17, weight: .medium, design: .monospaced))
                                .foregroundStyle(ViadereColor.textPrimary)
                                .textSelection(.disabled)
                        }
                        .accessibilityElement(children: .ignore)
                        .accessibilityLabel(Text("Code \(index + 1): " + code.filter { $0 != "-" }.map(String.init).joined(separator: " ")))
                    }
                }
                .padding(ViadereSpace.m)
            }
            .background(RoundedRectangle(cornerRadius: ViadereRadius.card, style: .continuous).fill(ViadereColor.surface))
            .overlay(RoundedRectangle(cornerRadius: ViadereRadius.card, style: .continuous).strokeBorder(ViadereColor.hairline, lineWidth: 1))
        } else if model.codes != nil {
            ViadereNotice("Your screen is being recorded or mirrored, so the codes are hidden. Stop recording to show them.", kind: .warning)
        } else {
            ViadereNotice("These codes are no longer on screen. You can generate a new set in Settings.", kind: .info)
        }
    }

    @ViewBuilder private var notices: some View {
        if model.screenshotTaken { ViadereNotice(RecoveryCodesViewModel.screenshotNotice, kind: .warning) }
        if model.hasCopied { ViadereNotice(RecoveryCodesViewModel.copyNotice, kind: .info) }
    }

    // MARK: Actions

    private var actions: some View {
        VStack(spacing: ViadereSpace.xs) {
            HStack(spacing: ViadereSpace.s) {
                Button(model.hasCopied ? "Copied" : "Copy") {
                    if let text = model.exportText {
                        SecurePasteboard.copy(text)
                        model.noteCopied()
                    }
                }
                .buttonStyle(.viadere(.secondary))
                Button("Save to Files") { showingShare = true }
                    .buttonStyle(.viadere(.secondary))
            }
            .disabled(model.codes == nil || model.isScreenBeingCaptured)
            Toggle(isOn: $model.confirmedSaved) {
                Text("I saved these").font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
            }
            .toggleStyle(.viadere)
            .padding(.vertical, ViadereSpace.xs)
            Button(continueTitle, action: onContinue)
                .buttonStyle(.viadere(.primary))
                .disabled(!model.canContinue)
        }
        .padding(.horizontal, ViadereSpace.screen)
        .padding(.top, ViadereSpace.s)
        .padding(.bottom, ViadereSpace.m)
        .background(ViadereColor.background)
    }
}

/// The stock share sheet. Copying is left to the app's own Copy button (local only, expiring), so the sheet's own "Copy" is excluded.
private struct ShareSheet: UIViewControllerRepresentable {
    let text: String
    let onDone: () -> Void

    func makeUIViewController(context: Context) -> UIActivityViewController {
        let controller = UIActivityViewController(activityItems: [text], applicationActivities: nil)
        controller.excludedActivityTypes = [.copyToPasteboard, .addToReadingList, .assignToContact, .postToFacebook, .postToTwitter, .postToWeibo]
        controller.completionWithItemsHandler = { _, _, _, _ in onDone() }
        return controller
    }

    func updateUIViewController(_ controller: UIActivityViewController, context: Context) {}
}

#if DEBUG
#Preview("Recovery codes") {
    let set = RecoveryCodeSet(
        recoveryId: "7K2M-Q9XD-4HBT",
        codes: (0..<10).map { _ in RecoveryCodeFormat.generateCode() }, issuedAt: Date())
    RecoveryCodesView(model: RecoveryCodesViewModel(codes: set)) {}
}
#endif
