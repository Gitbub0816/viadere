import SwiftUI
import ViadereCore
import ViadereKit

/// The most important screen: who is asking, what for, the facts, then the decision.
///
/// Laid out like the spec's example, "Someone is trying to spend $285.28 at Northfield Market in or near
/// Mesa, Arizona. Is this you?", with deny / approve (slide-to-approve for money and high-risk sign-ins).
/// Sensitive approvals are signed with a Secure Enclave key: Face ID appears when the slide completes,
/// with a prompt that names the business and amount.
struct ApprovalSheet: View {
    @Bindable var model: ApprovalViewModel
    var capture: ScreenCaptureObserver
    @Environment(\.dismiss) private var dismiss
    @State private var slideKey = UUID()
    @State private var confirmingReport = false
    @State private var replyText = ""
    @State private var multiSelection: Set<String> = []

    var body: some View {
        VStack(spacing: 0) {
            ViadereGrabber()
            ScrollView {
                VStack(alignment: .leading, spacing: ViadereSpace.l) {
                    header
                    mainContent
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
        .interactiveDismissDisabled(model.isBusy)
        .task {
            await model.load()
            // Drives the countdown and the expiry state.
            while !Task.isCancelled {
                try? await Task.sleep(for: .seconds(1))
                model.tick(Date())
            }
        }
        .onChange(of: capture.isCaptured, initial: true) { _, captured in model.isScreenBeingCaptured = captured }
        .onChange(of: model.contextRevision) { _, _ in
            // The request changed: nothing chosen or typed against the old details carries over.
            multiSelection = []
            replyText = ""
            slideKey = UUID()
        }
        .onChange(of: model.phase) { _, phase in
            if phase == .ready { slideKey = UUID() }
        }
        .task(id: model.phase) {
            if case .done = model.phase {
                try? await Task.sleep(for: .seconds(1.4))
                dismiss()
            }
        }
        .sensoryFeedback(.success, trigger: isDone)
        .sensoryFeedback(.warning, trigger: isFailed)
    }

    /// Approving is unavailable: the screen is being recorded, or the new-device cool-down pauses it. Denying never is.
    private var approveBlocked: Bool { model.approvalBlockedByCapture || model.approvalPausedByCoolDown }

    private var isDone: Bool { if case .done = model.phase { true } else { false } }
    private var isFailed: Bool { if case .failed = model.phase { true } else { false } }

    // MARK: Header

    private var header: some View {
        HStack(alignment: .center, spacing: ViadereSpace.s) {
            ViadereAvatar(name: model.envelope.business.safeName, size: 48, isVerified: model.envelope.business.isVerified)
            VStack(alignment: .leading, spacing: 4) {
                Text(model.envelope.business.safeName)
                    .font(ViadereType.headline)
                    .foregroundStyle(ViadereColor.textPrimary)
                HStack(spacing: ViadereSpace.xs) {
                    if model.envelope.business.isVerified { ViadereBadge("Verified", kind: .verified) }
                    Text(model.title)
                        .font(ViadereType.footnote)
                        .foregroundStyle(ViadereColor.textSecondary)
                }
            }
            Spacer(minLength: 0)
            if model.availability.isActionable, !isDone {
                ViadereCountdownRing(progress: model.remaining / model.totalLifetime,
                                     label: shortCountdown, spokenLabel: model.countdown)
            }
        }
    }

    private var shortCountdown: String {
        let seconds = Int(model.remaining)
        if seconds >= 3_600 { return "\(seconds / 3_600)h" }
        return String(format: "%d:%02d", seconds / 60, seconds % 60)
    }

    // MARK: Body

    @ViewBuilder private var mainContent: some View {
        if model.envelope.business.safeNameInfo.impersonatesViadere {
            ViadereNotice("This is a business using a name like Viadere. Viadere never asks you to approve anything under its own name.", kind: .danger)
        }
        if let behalf = model.onBehalfOf {
            ViadereNotice("You're responding on behalf of \(behalf). It's recorded in your household activity.", kind: .info)
        }
        if case .done(let decision, _) = model.phase {
            if case .acknowledge(let payload) = model.interaction.payload {
                AcknowledgmentReceipt(envelope: model.envelope, payload: payload, outcome: model.outcome,
                                      acknowledged: decision == .acknowledge, fallback: model.now)
            } else {
                ResultState(decision: decision, business: model.envelope.business.safeName)
            }
        } else {
            switch model.availability {
            case .actionable:
                if model.showsChangedNotice {
                    ViadereNotice("This request changed while you were looking at it. The details below are the current ones. Review them before deciding.", kind: .warning)
                }
                if model.approvalPausedByCoolDown {
                    ViadereNotice("\(model.coolDownMessage) \(model.coolDownStillAvailable)", kind: .info)
                }
                requestBody
            case .updateRequired:
                StateMessage(symbol: "arrow.down.app", title: "Update Viadere",
                             message: "Update Viadere to respond to this request. For your safety it can't be approved from this version, but you can still deny it.")
            case .expired:
                StateMessage(symbol: "clock", title: "This request expired",
                             message: "Nothing was approved. If you were trying to do something, start again with \(model.envelope.business.safeName).")
            case .alreadyHandled(let status):
                StateMessage(symbol: "checkmark.circle", title: "Already handled",
                             message: "This request was already \(Self.pastTense(status)). Nothing more to do.")
            case .unsupported:
                StateMessage(symbol: "arrow.down.app", title: "Update Viadere",
                             message: "This request needs a newer version of Viadere. For your safety it can't be shown here.")
            case .needsStrongerDevice:
                StateMessage(symbol: "faceid", title: "Needs Face ID",
                             message: "This request needs Face ID or Touch ID, which isn't set up on this iPhone. You can approve it on another trusted device.")
            case .notEnrolled:
                StateMessage(symbol: "iphone", title: "Set up this iPhone",
                             message: "Finish setting up this iPhone in Settings before approving requests.")
            }
        }
    }

    @ViewBuilder private var requestBody: some View {
        switch model.interaction.payload {
        case .authorize, .authenticate:
            securityBody
        case .confirm(let payload):
            Text(InteractionPresentation.confirmTitle(payload)).font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary)
            if let details = InteractionPresentation.confirmDetails(payload) { Text(details).font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary) }
            failureNotice
        case .choose(let payload):
            Text(InteractionPresentation.prompt(payload.prompt)).font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary)
            ViadereFlowLayout {
                ForEach(payload.options, id: \.id) { option in
                    ViadereChip(InteractionPresentation.optionLabel(option), isSelected: multiSelection.contains(option.id)) {
                        if payload.allowsMultiple {
                            if multiSelection.contains(option.id) { multiSelection.remove(option.id) } else { multiSelection.insert(option.id) }
                        } else {
                            Task { await model.submit(.select, selected: [option.id]) }
                        }
                    }
                    .disabled(model.isBusy)
                }
            }
            failureNotice
        case .acknowledge(let payload):
            AcknowledgmentBody(envelope: model.envelope, payload: payload, now: model.now)
            failureNotice
        case .reply(let payload):
            Text(InteractionPresentation.prompt(payload.prompt)).font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary)
            if !payload.suggestedReplies.isEmpty {
                ViadereFlowLayout {
                    ForEach(payload.suggestedReplies, id: \.self) { suggestion in
                        ViadereChip(InteractionPresentation.suggestedReply(suggestion)) { replyText = InteractionPresentation.suggestedReply(suggestion) }
                    }
                }
            }
            TextField("Your reply", text: $replyText, axis: .vertical)
                .lineLimit(1...5)
                .font(ViadereType.body)
                .padding(ViadereSpace.m)
                .background(RoundedRectangle(cornerRadius: ViadereRadius.control, style: .continuous).fill(ViadereColor.surface))
                .overlay(RoundedRectangle(cornerRadius: ViadereRadius.control, style: .continuous).strokeBorder(ViadereColor.hairline, lineWidth: 1))
            Text("\(max(0, payload.maxLength - replyText.count)) characters left")
                .font(ViadereType.footnote).foregroundStyle(ViadereColor.textTertiary)
            failureNotice
        case .status, .reward, .ticket, .message, .unknown:
            Text(model.headline).font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary)
            failureNotice
        }
    }

    private var securityBody: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.l) {
            Text(model.headline)
                .font(ViadereType.title)
                .foregroundStyle(ViadereColor.textPrimary)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityAddTraits(.isHeader)

            if !model.risks.isEmpty {
                ViadereFlowLayout {
                    ForEach(model.risks, id: \.code) { risk in
                        ViadereRiskChip(label: risk.label, severity: risk.severity.rawValue)
                    }
                }
            }

            ViadereRowGroup {
                ForEach(Array(model.details.enumerated()), id: \.element.id) { index, detail in
                    ViadereValueRow(detail.label, detail.value, emphasized: detail.emphasized)
                    if index < model.details.count - 1 { ViadereHairline() }
                }
            }

            if let effect = model.effect {
                HStack(alignment: .top, spacing: ViadereSpace.xs) {
                    Image(systemName: "arrow.turn.down.right").foregroundStyle(ViadereColor.textTertiary)
                    Text("If you approve: \(effect)")
                        .font(ViadereType.subhead)
                        .foregroundStyle(ViadereColor.textSecondary)
                }
                .accessibilityElement(children: .combine)
            }

            if capture.isCaptured {
                ViadereNotice("Your screen is being recorded or mirrored. Approving is paused until it stops. You can still deny.", kind: .warning)
            }
            if let label = model.verificationLabel {
                HStack(spacing: ViadereSpace.xs) {
                    Image(systemName: "faceid").foregroundStyle(ViadereColor.accent)
                    Text(label).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                }
                .accessibilityElement(children: .combine)
            }
            failureNotice
            if confirmingReport { reportConfirmation }
        }
    }

    @ViewBuilder private var failureNotice: some View {
        if case .failed(let error) = model.phase { ViadereNotice(error.userMessage, kind: .danger) }
    }

    private var reportConfirmation: some View {
        ViadereCard(padding: ViadereSpace.m) {
            VStack(alignment: .leading, spacing: ViadereSpace.s) {
                Text("Report this as suspicious?")
                    .font(ViadereType.headline).foregroundStyle(ViadereColor.textPrimary)
                Text("We'll deny it and tell \(model.envelope.business.safeName) it wasn't you.")
                    .font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                HStack(spacing: ViadereSpace.s) {
                    Button("Cancel") { confirmingReport = false }.buttonStyle(.viadere(.secondary))
                    Button("Report") {
                        confirmingReport = false
                        Task { await model.report() }
                    }
                    .buttonStyle(.viadere(.destructive))
                }
            }
        }
    }

    // MARK: Footer

    @ViewBuilder private var footer: some View {
        if model.isBusy {
            HStack(spacing: ViadereSpace.s) {
                ViadereLoading(height: 22)
                Text(model.plan?.requiresUserVerification == true ? "Confirming it's you…" : "Sending…")
                    .font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
            }
            .frame(maxWidth: .infinity, minHeight: 52)
        } else if isDone {
            Button("Close") { dismiss() }.buttonStyle(.viadere(.secondary))
        } else if case .updateRequired = model.availability {
            VStack(spacing: ViadereSpace.xs) {
                Button("Deny") { Task { await model.deny() } }.buttonStyle(.viadere(.destructive))
                Button("Close") { dismiss() }.buttonStyle(.viadere(.quiet))
            }
        } else if model.availability.isActionable {
            actionFooter
        } else {
            Button("Close") { dismiss() }.buttonStyle(.viadere(.secondary))
        }
    }

    @ViewBuilder private var actionFooter: some View {
        switch model.interaction.payload {
        case .authorize, .authenticate:
            VStack(spacing: ViadereSpace.xs) {
                if model.usesSlideToApprove {
                    ViadereSlideToConfirm(model.interaction.kind == .authenticate ? "Slide to sign in" : "Slide to approve",
                                          confirmedTitle: "Confirming…") {
                        Task { await model.approve() }
                    }
                    .id(slideKey)
                    .disabled(approveBlocked)
                    .opacity(approveBlocked ? 0.4 : 1)
                    Button("Deny") { Task { await model.deny() } }
                        .buttonStyle(.viadere(.destructive))
                } else {
                    ViadereApprovalButtons(
                        approveTitle: model.interaction.kind == .authenticate ? "Yes, it's me" : "Approve",
                        denyTitle: model.interaction.kind == .authenticate ? "No" : "Deny",
                        onApprove: { if !approveBlocked { Task { await model.approve() } } },
                        onDeny: { Task { await model.deny() } })
                    .opacity(approveBlocked ? 0.6 : 1)
                }
                Button("I don't recognize this") { withAnimation(ViadereMotion.standard) { confirmingReport.toggle() } }
                    .buttonStyle(.viadere(.quiet))
            }
        case .confirm:
            ViadereApprovalButtons(approveTitle: "Confirm", denyTitle: "Decline",
                                   onApprove: { if !approveBlocked { Task { await model.approve() } } }, onDeny: { Task { await model.deny() } })
                .opacity(approveBlocked ? 0.6 : 1)
        case .choose(let payload):
            if payload.allowsMultiple {
                Button("Send") { Task { await model.submit(.select, selected: Array(multiSelection)) } }
                    .buttonStyle(.viadere(.primary))
                    .disabled(multiSelection.isEmpty)
            } else {
                Button("Not now") { dismiss() }.buttonStyle(.viadere(.quiet))
            }
        case .acknowledge:
            VStack(spacing: ViadereSpace.xs) {
                Button("Acknowledge") { Task { await model.approve() } }.buttonStyle(.viadere(.primary))
                Button("Decline") { Task { await model.deny() } }.buttonStyle(.viadere(.quiet))
            }
        case .reply:
            Button("Send reply") { Task { await model.submit(.reply, reply: replyText) } }
                .buttonStyle(.viadere(.primary))
                .disabled(replyText.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
        case .status, .reward, .ticket, .message, .unknown:
            Button("Got it") { Task { await model.submit(.acknowledge) } }.buttonStyle(.viadere(.primary))
        }
    }

    static func pastTense(_ status: InteractionStatus) -> String {
        switch status {
        case .approved: "approved"
        case .denied: "denied"
        case .confirmed: "confirmed"
        case .declined: "declined"
        case .cancelled: "cancelled by the business"
        case .expired: "expired"
        case .reported: "reported"
        default: "handled"
        }
    }
}

private struct StateMessage: View {
    let symbol: String
    let title: String
    let message: String

    var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.s) {
            Image(systemName: symbol)
                .font(.system(size: 30, weight: .light))
                .foregroundStyle(ViadereColor.textTertiary)
                .accessibilityHidden(true)
            Text(title).font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary)
            Text(message).font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(.top, ViadereSpace.l)
    }
}

private struct ResultState: View {
    let decision: Decision
    let business: String

    private var title: String {
        switch decision {
        case .approve: "Approved"
        case .deny: "Denied"
        case .report: "Reported"
        case .confirm: "Confirmed"
        case .decline: "Declined"
        case .select, .reply: "Sent"
        case .acknowledge: "Done"
        }
    }

    private var symbol: String {
        switch decision {
        case .deny, .report, .decline: "xmark.circle"
        default: "checkmark.circle"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.s) {
            Image(systemName: symbol)
                .font(.system(size: 44, weight: .light))
                .foregroundStyle(decision == .approve || decision == .confirm ? ViadereColor.success : ViadereColor.textSecondary)
                .accessibilityHidden(true)
            Text(title).font(ViadereType.display).foregroundStyle(ViadereColor.textPrimary)
            Text("We let \(business) know.").font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
        }
        .padding(.top, ViadereSpace.xl)
        .accessibilityElement(children: .combine)
    }
}

#if DEBUG
#Preview("Approval · $285.28") {
    PreviewHost { services in
        ApprovalSheet(model: ApprovalViewModel(envelope: PreviewData.authorize(), services: services), capture: ScreenCaptureObserver())
    }
}

#Preview("Approval · sign-in") {
    PreviewHost { services in
        ApprovalSheet(model: ApprovalViewModel(envelope: PreviewData.authenticate(sensitivity: .standard), services: services), capture: ScreenCaptureObserver())
    }
}

#Preview("Approval · expired") {
    PreviewHost { services in
        ApprovalSheet(model: ApprovalViewModel(envelope: PreviewData.authorize(now: Date().addingTimeInterval(-900), expiresIn: 60), services: services),
                      capture: ScreenCaptureObserver())
    }
}

#Preview("Approval · choose") {
    PreviewHost { services in
        ApprovalSheet(model: ApprovalViewModel(envelope: PreviewData.choose(), services: services), capture: ScreenCaptureObserver())
    }
}
#endif
