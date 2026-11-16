import SwiftUI
import UIKit
import ViadereCore
import ViadereKit

// Device pairing (SECURITY.md §2.107, UX_COPY S-PAIR-01..08 with S-DEV-03..05). Built from the shared comparison pieces in
// `Approval/DeviceAddComparisonViews.swift` and the design system; facts above the decision, equal buttons with the safe actions first.

/// Trusted device: Settings → Trusted devices → Add another device. Shows the code the person types on the new device.
struct AddDeviceInviteView: View {
    let model: AddDeviceInviteViewModel
    var openRecovery: (() -> Void)?

    var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.l) {
            Text(PairingCopy.inviteTitle).font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary).accessibilityAddTraits(.isHeader)
            switch model.phase {
            case .idle:
                Text(PairingCopy.inviteBody).font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                Button(PairingCopy.inviteAction) { Task { await model.create() } }.buttonStyle(.viadere(.primary))
            case .creating:
                ViadereLoadingState(PairingCopy.inviteAction)
            case .showing(let code, _):
                Text(PairingCopy.inviteBody).font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                Text(code)
                    .font(.system(size: 32, weight: .semibold, design: .monospaced))
                    .foregroundStyle(ViadereColor.textPrimary)
                    .accessibilityLabel(code.map { String($0) }.filter { $0 != "-" }.joined(separator: ", "))
                if let line = model.expiryLine { Text(line).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary) }
                // The same code as a QR (`https://{link domain}/p/{code}`, SECURITY.md §2.107): only a new device's pairing entry reads it.
                if let link = DevicePairingLink.build(code: code) {
                    VStack(spacing: ViadereSpace.xs) {
                        QRCodeView(payload: link, size: 168, accessibilityText: PairingCopy.inviteQRAccessibility)
                        Text(PairingCopy.inviteQRLabel).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                            .multilineTextAlignment(.center)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    .frame(maxWidth: .infinity)
                }
            case .noTrustedDevice:
                ViadereNotice(PairingCopy.noTrustedDevice, kind: .info)
                if let openRecovery { Button(PairingCopy.recoveryAction, action: openRecovery).buttonStyle(.viadere(.secondary)) }
            case .failed(let message):
                ViadereNotice(message, kind: .danger)
                Button("Try again") { Task { await model.create() } }.buttonStyle(.viadere(.secondary))
            }
        }
        .padding(ViadereSpace.screen)
        .privacySensitive()
        .viadereProtectedSurface()
    }
}

/// Trusted device: the request, from the pairing notification or Alerts. It never receives or shows the code.
struct PairingApprovalView: View {
    let model: PairingApprovalViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.l) {
            Text(model.title).font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary).accessibilityAddTraits(.isHeader)
            if let refusal = model.refusal {
                Text(model.notice ?? refusal).font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
            } else if let result = model.resultLine {
                ViadereOutcome(model.phase == .added ? .success : (model.phase == .expired || model.phase == .ended ? .caution : .neutral), result)
            } else {
                // Facts first.
                VStack(alignment: .leading, spacing: ViadereSpace.xs) {
                    Text(model.nameRow).font(ViadereType.subhead).foregroundStyle(ViadereColor.textPrimary)
                    Text(model.platformRow).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                    Text(model.requestedRow).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                    Text(model.expiresRow).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                    Text(model.integrityRow).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                }
                if let warning = model.fatigueWarning { ViadereNotice(warning, kind: .warning) }
                // Then the decision.
                DeviceNumberEntry(label: model.fieldLabel, helper: model.helper, entry: model.entry) { model.edit($0) }
                if let notice = model.notice { ViadereNotice(notice, kind: .warning) }
                EqualSafeActionButtons(buttons: model.buttons) { role in
                    Task {
                        switch role {
                        case .deny: await model.deny()
                        case .notMe: await model.thisWasntMe()
                        default: await model.add()
                        }
                    }
                }
                Text(model.safeLine).font(ViadereType.footnote).foregroundStyle(ViadereColor.textTertiary)
            }
        }
        .padding(ViadereSpace.screen)
        .privacySensitive()
        .viadereProtectedSurface()
        .onChange(of: model.announcement) { _, text in
            if let text { UIAccessibility.post(notification: .announcement, argument: text) }
        }
    }
}

/// Alerts: the account's pending pairing requests (a D1 device only), each opening `PairingApprovalView`.
struct PairingRequestsSection: View {
    let model: PairingRequestsViewModel
    @State private var open: PairingApprovalViewModel?

    var body: some View {
        Group {
            if let line = model.alertsLine {
                ForEach(model.reviews, id: \.request.pairingId) { review in
                    Button { open = review } label: {
                        ViadereRow(line, subtitle: review.nameRow, leading: { ViadereIconTile(systemName: "iphone") }, trailing: { EmptyView() })
                    }
                    .buttonStyle(ViaderePressableStyle())
                }
            }
        }
        .task { await model.load() }
        .sheet(item: Binding(get: { open.map { PairingSheetItem($0) } }, set: { if $0 == nil { open = nil } })) { item in
            ScrollView { PairingApprovalView(model: item.model) }.viadereScreenBackground()
        }
    }
}

private struct PairingSheetItem: Identifiable {
    let model: PairingApprovalViewModel
    let id: DevicePairingID
    @MainActor init(_ model: PairingApprovalViewModel) { self.model = model; id = model.request.pairingId }
}

/// New device: onboarding → "I already use Viadere": enter the code, then show the comparison code and wait.
struct NewDevicePairingView: View {
    @Bindable var model: NewDevicePairingViewModel
    var onAdded: () -> Void
    @State private var code = ""
    @State private var scanning = false

    var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.l) {
            switch model.phase {
            case .enteringCode, .starting:
                Text(model.title).font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary).accessibilityAddTraits(.isHeader)
                Text(PairingCopy.codeEntryHelper).font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
                ViadereTextField(PairingCopy.codeFieldLabel, text: $code, prompt: "XXXX-XXXX-XXXX", message: model.notice, isError: model.notice != nil)
                    .textInputAutocapitalization(.characters)
                    .autocorrectionDisabled()
                    .onChange(of: code) { _, value in
                        model.edit(value)
                        if code != model.entry { code = model.entry }
                    }
                Button(PairingCopy.continueAction) { Task { await model.start(); await model.waitForResult() } }
                    .buttonStyle(.viadere(.primary))
                    .disabled(!model.canContinue)
                // The QR under the code on the other device. It only fills the field; Continue is still the person's tap.
                Button(PairingCopy.scanAction) { scanning = true }
                    .buttonStyle(.viadere(.secondary))
                    .disabled(model.phase != .enteringCode)
            case .showing:
                Text(AuthDeliveryCopy.newDeviceCodeTitle(code: "")).font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary)
                DeviceComparisonCode(display: model.displayCode ?? "", spoken: model.spokenCode ?? "")
                Text(AuthDeliveryCopy.newDeviceCodeDetail).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                ViadereLoadingState(PairingCopy.waiting)
                Button(PairingCopy.cancelAction) { Task { await model.cancel() } }.buttonStyle(.viadere(.secondary))
            case .added:
                ViadereOutcome(.success, PairingCopy.added)
                Button(PairingCopy.continueAction, action: onAdded).buttonStyle(.viadere(.primary))
            case .declined, .expired, .ended, .noTrustedDevice:
                ViadereOutcome(model.phase == .noTrustedDevice ? .neutral : .caution, model.resultLine ?? PairingCopy.cancelled)
            }
        }
        .padding(ViadereSpace.screen)
        .privacySensitive()
        .viadereProtectedSurface()
        .onChange(of: model.entry) { _, value in if code != value { code = value } }
        .fullScreenCover(isPresented: $scanning) {
            CodeScannerScreen { payload, symbology in
                // `ScannedCodePolicy` in the pairing context accepts only `https://{link domain}/p/{code}`; the view model checks again,
                // refuses it on an enrolled device, and fills the field.
                if case .rejected(let reason) = ScannedCodePolicy.evaluate(payload, symbology: symbology, context: .newDevicePairing) { return reason }
                scanning = false
                Task { _ = await model.scanned(payload, symbology: symbology) }
                return nil
            } onClose: { scanning = false }
            .viaderePullDownToDismiss()
        }
    }
}
