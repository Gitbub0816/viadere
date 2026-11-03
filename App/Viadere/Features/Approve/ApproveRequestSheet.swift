import SwiftUI
import UIKit
import ViadereCore
import ViadereKit

/// An Approve v2 request (ADR-0022, UX_COPY §3): who is asking, what for, how much we trust what we are showing, the number the person types
/// from the screen where they are signing in, then the decision. Everything on this screen was verified on this phone
/// (`ApproveRequestHandler`); the label under the business says what was checked.
///
/// The logic (number comparison, three wrong entries, the buttons and their order, every string) is `NumberMatchApprovalViewModel` in
/// ViadereKit and is unit-tested there; this file lays it out. Deny and Approve are one component: same style, same size, Deny first;
/// "This wasn't me" is a full-width secondary button in the pinned footer; there is no slider and no red.
struct ApproveRequestSheet: View {
    let prompt: ApprovalPrompt
    @Bindable var controller: ApproveController
    var capture: ScreenCaptureObserver
    @State private var model: NumberMatchApprovalViewModel
    @Environment(\.dismiss) private var dismiss
    @State private var confirmingLeave = false

    init(prompt: ApprovalPrompt, controller: ApproveController, capture: ScreenCaptureObserver) {
        self.prompt = prompt
        self.controller = controller
        self.capture = capture
        // R4-04: the number requirement comes from the verified prompts (signed policy), one screen per business group; the typed `match`, the
        // `deny_reason` and the wrong-entry count go inside the signed v2 result. R4-02: wrong entries persist per request in the approval store.
        let group = controller.numberMatchGroup(for: prompt)
        // S5-06: the counter is keyed by business and request id, and Approve stays off until the stored count is loaded (`.task` below).
        let recorder = controller.attemptRecorder(for: prompt)
        let model = NumberMatchApprovalViewModel(
            context: NumberMatchApprovalContext(group: group),
            answering: ApproveControllerAnswering(controller: controller, group: group, attempts: recorder),
            attempts: recorder)
        model.holdApproveUntilRestored()
        _model = State(initialValue: model)
    }

    private var isBusy: Bool { model.phase == .submitting || controller.phase == .working }
    private var finished: Bool {
        switch model.phase {
        case .entering, .submitting: return false
        default: return true
        }
    }

    var body: some View {
        // A security surface: Viadere's own look in every theme, never a business's Brand Kit (anti-spoofing, SECURITY.md §2.93).
        sheetBody.viadereProtectedSurface()
    }

    @ViewBuilder private var sheetBody: some View {
        VStack(spacing: 0) {
            ViadereSheetHandle(onClose: model.phase == .entering && model.wrongEntries > 0 && !isBusy ? { confirmingLeave = true } : nil)
            ScrollView {
                VStack(alignment: .leading, spacing: ViadereSpace.l) {
                    header
                    if finished { result } else {
                        assuranceNotice
                        details
                        if let group = model.groupLine { Text(group).font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary) }
                        if model.context.requirement != nil || model.context.requiresNumber { numberEntry }
                        if let fatigue = model.fatigueLine { fatigueNotice(fatigue) }
                        if let block = model.deviceBlockLine { ViadereNotice(block, kind: .info) }
                        if capture.isCaptured { ViadereNotice("Screen recording is on. Approving is paused; you can still deny.", kind: .warning) }
                        if let message = controller.message ?? model.notice { ViadereNotice(message, kind: .danger) }
                    }
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
        // After a wrong entry a swipe cannot dismiss: the handle asks "Leave this request?" (R4-02).
        .interactiveDismissDisabled(isBusy || model.confirmsBeforeLeaving)
        .task {
            if let recorder = controller.attemptRecorder(for: prompt) {
                model.restoreWrongEntries(await recorder.wrongEntries(requestIds: model.context.groupRequestIds))
            } else {
                model.restoreWrongEntries(0)
            }
        }
        .onChange(of: capture.isCaptured, initial: true) { _, captured in model.isScreenCaptured = captured }
        .onChange(of: model.announcement) { _, text in
            // A wrong entry is announced, not shown by colour alone (ADR-0022 §2.3).
            if let text { UIAccessibility.post(notification: .announcement, argument: text) }
        }
        .confirmationDialog("Leave this request?", isPresented: $confirmingLeave, titleVisibility: .visible) {
            Button("Leave", role: .destructive) { dismiss() }
            Button("Keep reviewing", role: .cancel) {}
        } message: {
            Text("Nothing is approved or denied. It stays in Alerts until it expires.")
        }
        .onDisappear { controller.closePresented() }
    }

    private var header: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.xs) {
            HStack(spacing: ViadereSpace.s) {
                ViadereAvatar(name: model.context.business, size: 48, isVerified: prompt.business.isVerified)
                Spacer(minLength: 0)
            }
            // Focus lands on the title when the sheet opens (ADR-0022 §2.3).
            Text(model.title).font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary).accessibilityAddTraits(.isHeader)
            Text(model.subtitle).font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
        }
        .accessibilityElement(children: .combine)
    }

    /// The plain statement of what was checked. A request the relay could read says so, and says that Viadere cannot vouch for it.
    @ViewBuilder private var assuranceNotice: some View {
        switch prompt.assurance {
        case .endToEndSigned:
            ViadereNotice("Checked on this phone: sent privately by \(model.context.business) and signed with a key it published. Viadere could not read or change it.", kind: .info)
        case .relayAsserted:
            ViadereNotice(model.relayLine ?? "", kind: .warning)
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
                    ViadereValueRow("Payee", UntrustedText.line(t.payeeDisplay, max: 80), emphasized: true)
                    ViadereHairline()
                    ViadereValueRow("Reference", UntrustedText.line(t.transactionReference, max: 64))
                    ViadereHairline()
                    ViadereValueRow("Expires at", prompt.content.expiresAtDate.formatted(date: .omitted, time: .shortened))
                }
            }
        case .authentication(let a):
            VStack(alignment: .leading, spacing: ViadereSpace.xs) {
                ViadereRowGroup {
                    ViadereValueRow("Sign-in", UntrustedText.line(a.actionDisplay, max: 60), emphasized: true)
                    ViadereHairline()
                    if let reference = a.reference { ViadereValueRow("Reference", UntrustedText.line(reference, max: 40)); ViadereHairline() }
                    ViadereValueRow("Requested at", prompt.request.createdAt.formatted(date: .omitted, time: .shortened))
                    ViadereHairline()
                    ViadereValueRow("Expires at", prompt.content.expiresAtDate.formatted(date: .omitted, time: .shortened))
                }
            }
        }
    }

    private var numberEntry: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.xs) {
            Text(model.fieldLabel).font(ViadereType.subhead.weight(.semibold)).foregroundStyle(ViadereColor.textPrimary)
            NumberEntryField(text: model.entry, accessibilityLabel: model.fieldLabel) { model.edit($0) }
                .frame(height: 56)
                .padding(.horizontal, ViadereSpace.s)
                .viadereSurface(radius: ViadereRadius.control)
            Text(model.helper).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
            Text(model.sameDeviceHint).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
        }
    }

    private func fatigueNotice(_ line: String) -> some View {
        VStack(alignment: .leading, spacing: ViadereSpace.s) {
            ViadereNotice(line, kind: .warning)
            if model.needsFatigueAcknowledgement {
                Button(AuthDeliveryCopy.startedMyself) { model.acknowledgeFatigue() }
                    .buttonStyle(.viadere(.secondary))
            }
        }
    }

    /// The outcome, shown only after the relay accepted the signed answer.
    @ViewBuilder private var result: some View {
        if let line = model.resultLine {
            Text(line).font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
        }
        if model.offersPause {
            Button(model.pauseTitle) { Task { _ = await model.pauseRequests() } }
                .buttonStyle(.viadere(.secondary))
        }
    }

    @ViewBuilder private var footer: some View {
        if finished {
            Button("Done") { controller.finishPresented(); dismiss() }
                .buttonStyle(.viadere(.secondary))
        } else {
            VStack(spacing: ViadereSpace.xs) {
                // One component: identical height, width, type and weight; Deny first in layout and reading order; side by side until the
                // text would truncate, then stacked with Deny on top (UX_COPY §0.2).
                ViewThatFits(in: .horizontal) {
                    HStack(spacing: ViadereSpace.s) { ForEach(model.buttons) { actionButton($0) } }
                    VStack(spacing: ViadereSpace.s) { ForEach(model.buttons) { actionButton($0) } }
                }
                // Full width, at least 44 pt, a button (not a link).
                Button(model.notMeButton.title) { Task { await model.reportNotMe() } }
                    .buttonStyle(.viadere(.secondary))
                    .frame(minHeight: 44)
                    .disabled(!model.notMeButton.isEnabled || isBusy)
                Text(model.denyLine).font(ViadereType.caption).foregroundStyle(ViadereColor.textSecondary).multilineTextAlignment(.center)
            }
        }
    }

    private func actionButton(_ spec: SafeActionButton) -> some View {
        Button(spec.title) {
            Task { spec.role == .deny ? await model.deny() : await model.approve() }
        }
        .buttonStyle(.viadere(.secondary))
        .frame(minHeight: 44)
        .disabled(!spec.isEnabled || isBusy)
        // Unique Voice Control names: "Deny", "Approve", "This wasn't me".
        .accessibilityInputLabels([spec.title])
    }
}
