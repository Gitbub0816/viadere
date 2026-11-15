import SwiftUI
import UIKit
import ViadereKit

// Device-add comparison code (ADR-0033 §4.1, UX_COPY S-DEV-03..05). The key-log screens are not presented by anything yet (the authority side
// arrives in Stage 6; `AuthDeliveryFlags.shipping.deviceAddComparison` is false). The shared pieces below are also what device pairing uses
// (SECURITY.md §2.107, `DevicePairingViews.swift`), so both flows show the code and ask for it the same way.

/// The comparison code as the new device shows it: two groups of three, monospaced, read digit by digit by VoiceOver.
struct DeviceComparisonCode: View {
    let display: String
    let spoken: String

    var body: some View {
        Text(display)
            .font(.system(size: 44, weight: .semibold, design: .monospaced))
            .foregroundStyle(ViadereColor.textPrimary)
            .accessibilityLabel(spoken)
    }
}

/// The existing device's number field (paste and AutoFill refused by `NumberEntryField`), its label and helper.
struct DeviceNumberEntry: View {
    let label: String
    let helper: String
    let entry: String
    let onEdit: (String) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.s) {
            Text(label).font(ViadereType.subhead.weight(.semibold)).foregroundStyle(ViadereColor.textPrimary)
            NumberEntryField(text: entry, accessibilityLabel: label, onEdit: onEdit)
                .frame(height: 56)
                .padding(.horizontal, ViadereSpace.s)
                .viadereSurface(radius: ViadereRadius.control)
            Text(helper).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
        }
    }
}

/// Equal buttons (one style, one height), side by side until they would truncate, then stacked; the order is the model's (safe first).
struct EqualSafeActionButtons: View {
    let buttons: [SafeActionButton]
    let action: (SafeActionButton.Role) -> Void

    var body: some View {
        ViewThatFits(in: .horizontal) {
            HStack(spacing: ViadereSpace.s) { ForEach(buttons) { button($0) } }
            VStack(spacing: ViadereSpace.s) { ForEach(buttons) { button($0) } }
        }
    }

    private func button(_ spec: SafeActionButton) -> some View {
        Button(spec.title) { action(spec.role) }
            .buttonStyle(.viadere(.secondary))
            .frame(minHeight: 44)
            .disabled(!spec.isEnabled)
            .accessibilityInputLabels([spec.title])
    }
}

/// The NEW device: shows the comparison code, but only when the signed challenge lists exactly this device's keys.
struct NewDeviceCodeView: View {
    let model: NewDeviceComparisonViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.l) {
            switch model.phase {
            case .showing(let code):
                Text(AuthDeliveryCopy.newDeviceCodeTitle(code: "")).font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary)
                DeviceComparisonCode(display: DeviceAddCode.display(code), spoken: model.spokenCode ?? "")
                Text(AuthDeliveryCopy.newDeviceCodeDetail).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
            case .refused:
                // S-DEV-05: no code is shown at all.
                Text(AuthDeliveryCopy.deviceChallengeMismatch).font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
            case .unavailable:
                EmptyView()
            }
        }
        .padding(ViadereSpace.screen)
        .privacySensitive()
        .viadereProtectedSurface()
    }
}

/// The EXISTING device: asks for the number shown on the new device. It never receives or shows the code.
struct ExistingDeviceApprovalView: View {
    let model: ExistingDeviceApprovalViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.l) {
            Text(model.title).font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary).accessibilityAddTraits(.isHeader)
            if let refusal = model.refusal {
                Text(refusal).font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
            } else {
                Text(model.nameRow).font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                DeviceNumberEntry(label: model.fieldLabel, helper: model.helper, entry: model.entry) { model.edit($0) }
                if let notice = model.notice { ViadereNotice(notice, kind: .warning) }
                EqualSafeActionButtons(buttons: model.buttons) { role in
                    Task { role == .notMe ? await model.thisWasntMe() : await model.add() }
                }
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
