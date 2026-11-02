import SwiftUI
import UIKit
import ViadereKit

// Device-add comparison code (ADR-0033 §4.1, UX_COPY S-DEV-03..05). Not presented by anything yet: the authority side arrives in Stage 6, so
// `AuthDeliveryFlags.shipping.deviceAddComparison` is false and the view models start in `.unavailable`. The screens are here so Stage 6 only
// has to wire a verified challenge in.

/// The NEW device: shows the comparison code, but only when the signed challenge lists exactly this device's keys.
struct NewDeviceCodeView: View {
    let model: NewDeviceComparisonViewModel

    var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.l) {
            switch model.phase {
            case .showing(let code):
                Text(AuthDeliveryCopy.newDeviceCodeTitle(code: "")).font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary)
                // Two groups of three, monospaced, read digit by digit by VoiceOver.
                Text(DeviceAddCode.display(code))
                    .font(.system(size: 44, weight: .semibold, design: .monospaced))
                    .foregroundStyle(ViadereColor.textPrimary)
                    .accessibilityLabel(model.spokenCode ?? "")
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
                Text(model.fieldLabel).font(ViadereType.subhead.weight(.semibold)).foregroundStyle(ViadereColor.textPrimary)
                NumberEntryField(text: model.entry, accessibilityLabel: model.fieldLabel) { model.edit($0) }
                    .frame(height: 56)
                    .padding(.horizontal, ViadereSpace.s)
                    .viadereSurface(radius: ViadereRadius.control)
                Text(model.helper).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                if let notice = model.notice { ViadereNotice(notice, kind: .warning) }
                ViewThatFits(in: .horizontal) {
                    HStack(spacing: ViadereSpace.s) { ForEach(model.buttons) { button($0) } }
                    VStack(spacing: ViadereSpace.s) { ForEach(model.buttons) { button($0) } }
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

    private func button(_ spec: SafeActionButton) -> some View {
        Button(spec.title) {
            Task { spec.role == .notMe ? await model.thisWasntMe() : await model.add() }
        }
        .buttonStyle(.viadere(.secondary))
        .frame(minHeight: 44)
        .disabled(!spec.isEnabled)
        .accessibilityInputLabels([spec.title])
    }
}
