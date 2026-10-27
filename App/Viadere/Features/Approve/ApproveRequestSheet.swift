import SwiftUI
import ViadereCore
import ViadereKit

/// An Approve v2 request: who is asking, what for, how much we trust what we are showing, then the decision. Everything on this screen was
/// verified on this phone (`ApproveRequestHandler`); the label under the business says what was checked.
struct ApproveRequestSheet: View {
    let prompt: ApprovalPrompt
    @Bindable var controller: ApproveController
    var capture: ScreenCaptureObserver
    @Environment(\.dismiss) private var dismiss
    @State private var confirmingReport = false
    @State private var understoodFatigue = false

    private var isBusy: Bool { controller.phase == .working }
    private var captured: Bool { capture.isCaptured }
    private var needsFatigueAck: Bool { prompt.showFatigueWarning && !understoodFatigue }

    var body: some View {
        VStack(spacing: 0) {
            ViadereGrabber()
            ScrollView {
                VStack(alignment: .leading, spacing: ViadereSpace.l) {
                    header
                    assuranceNotice
                    details
                    if prompt.showFatigueWarning { fatigueNotice }
                    if captured { ViadereNotice("Screen recording is on. Approving is paused; you can still decline.", kind: .warning) }
                    if let message = controller.message { ViadereNotice(message, kind: .danger) }
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
                .background(ViadereColor.background)
        }
        .background(ViadereColor.background)
        .privacySensitive()
        .interactiveDismissDisabled(isBusy)
        .onDisappear { controller.closePresented() }
        .confirmationDialog("Report this request?", isPresented: $confirmingReport, titleVisibility: .visible) {
            Button("Report as suspicious", role: .destructive) { Task { await answer(.report) } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("We decline it, tell \(prompt.business.safeName) you did not make it, and keep a record. Nothing is approved.")
        }
    }

    private var header: some View {
        HStack(spacing: ViadereSpace.s) {
            ViadereAvatar(name: prompt.business.safeName, size: 48, isVerified: prompt.business.isVerified)
            VStack(alignment: .leading, spacing: 2) {
                Text(prompt.business.safeName).font(ViadereType.headline).foregroundStyle(ViadereColor.textPrimary)
                Text(prompt.content.capability == .transactionApprove ? "Wants you to approve a payment" : "Wants you to confirm it is you")
                    .font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
            }
            Spacer(minLength: 0)
        }
        .accessibilityElement(children: .combine)
    }

    /// The plain statement of what was checked. A request the relay could read says so, and says that Viadere cannot vouch for it.
    @ViewBuilder private var assuranceNotice: some View {
        switch prompt.assurance {
        case .endToEndSigned:
            ViadereNotice("Checked on this phone: sent privately by \(prompt.business.safeName) and signed with a key it published. Viadere could not read or change it.", kind: .info)
        case .relayAsserted:
            ViadereNotice("Viadere passed this on and could read it. It is not signed by \(prompt.business.safeName). Only approve if you started this yourself.", kind: .warning)
        }
    }

    @ViewBuilder private var details: some View {
        switch prompt.content.details {
        case .transaction(let t):
            VStack(alignment: .leading, spacing: ViadereSpace.xs) {
                Text(MoneyFormatting.display(minor: t.amountMinor, currency: t.currency))
                    .font(ViadereType.display).foregroundStyle(ViadereColor.textPrimary)
                    .accessibilityLabel("Amount \(MoneyFormatting.display(minor: t.amountMinor, currency: t.currency))")
                ViadereRowGroup {
                    ViadereValueRow("To", UntrustedText.line(t.payeeDisplay, max: 80), emphasized: true)
                    ViadereHairline()
                    ViadereValueRow("Reference", UntrustedText.line(t.transactionReference, max: 64))
                    ViadereHairline()
                    ViadereValueRow("Expires", prompt.content.expiresAtDate.formatted(date: .omitted, time: .shortened))
                }
            }
        case .authentication(let a):
            VStack(alignment: .leading, spacing: ViadereSpace.xs) {
                Text(UntrustedText.line(a.actionDisplay, max: 120)).font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary)
                ViadereRowGroup {
                    if let reference = a.reference { ViadereValueRow("Reference", UntrustedText.line(reference, max: 64)); ViadereHairline() }
                    ViadereValueRow("Expires", prompt.content.expiresAtDate.formatted(date: .omitted, time: .shortened))
                }
            }
        }
    }

    private var fatigueNotice: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.s) {
            ViadereNotice("\(prompt.business.safeName) has asked \(prompt.requestsInWindow) times in the last hour. If you did not just start something with them, decline and report it.", kind: .warning)
            if !understoodFatigue {
                Button("I started this myself") { understoodFatigue = true }
                    .buttonStyle(.viadere(.secondary))
            }
        }
    }

    private var footer: some View {
        VStack(spacing: ViadereSpace.xs) {
            HStack(spacing: ViadereSpace.s) {
                Button("Decline") { Task { await answer(.deny) } }
                    .buttonStyle(.viadere(.destructive))
                    .disabled(isBusy)
                Button(prompt.key.assurance == .biometric ? "Approve with Face ID" : "Approve") { Task { await answer(.approve) } }
                    .buttonStyle(.viadere(.primary))
                    .disabled(isBusy || captured || needsFatigueAck)
            }
            Button("Report suspicious request") { confirmingReport = true }
                .buttonStyle(.viadere(.quiet))
                .disabled(isBusy)
        }
    }

    private func answer(_ decision: ApprovalDecision) async {
        if await controller.answer(prompt, decision) { dismiss() }
    }
}
