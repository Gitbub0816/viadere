import SwiftUI
import ViadereKit

/// The screen shown **before** the system passkey sheet when a device is added or set up again, so the sheet
/// (Face ID or passcode) is never a surprise. Presented over the current screen while `gate.pending` is set.
struct PasskeyExplanationView: View {
    let explanation: PasskeyExplanation
    let onContinue: () -> Void
    let onCancel: () -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: ViadereSpace.l) {
                    ViadereMark.monochrome(ViadereColor.textTertiary).frame(height: 32).padding(.top, ViadereSpace.xl)
                    Text(explanation.title)
                        .font(ViadereType.display)
                        .foregroundStyle(ViadereColor.textPrimary)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityAddTraits(.isHeader)
                    Text(explanation.message)
                        .font(ViadereType.body)
                        .foregroundStyle(ViadereColor.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                    ViadereRowGroup {
                        ForEach(Array(explanation.points.enumerated()), id: \.offset) { index, point in
                            HStack(alignment: .top, spacing: 14) {
                                ViadereIconTile(systemName: index == 0 ? "person.badge.key" : "lock")
                                Text(point)
                                    .font(ViadereType.subhead)
                                    .foregroundStyle(ViadereColor.textSecondary)
                                    .fixedSize(horizontal: false, vertical: true)
                                Spacer(minLength: 0)
                            }
                            .padding(.vertical, ViadereSpace.s)
                            .accessibilityElement(children: .combine)
                            if index < explanation.points.count - 1 { ViadereHairline(inset: 50) }
                        }
                    }
                }
                .padding(.horizontal, ViadereSpace.screen)
            }
            .scrollIndicators(.hidden)
            VStack(spacing: ViadereSpace.xs) {
                Button(explanation.continueTitle, action: onContinue).buttonStyle(.viadere(.primary))
                Button("Not now", action: onCancel).buttonStyle(.viadere(.quiet))
            }
            .padding(.horizontal, ViadereSpace.screen)
            .padding(.bottom, ViadereSpace.l)
            .padding(.top, ViadereSpace.s)
        }
        .frame(maxWidth: .infinity, maxHeight: .infinity)
        .viadereScreenBackground()
    }
}

extension View {
    /// Covers the screen with the passkey explanation while the gate has one pending.
    func passkeyExplanation(_ gate: PasskeyExplanationGate) -> some View {
        overlay {
            if let explanation = gate.pending {
                PasskeyExplanationView(explanation: explanation,
                                       onContinue: { gate.resolve(true) },
                                       onCancel: { gate.resolve(false) })
                    .transition(.opacity)
            }
        }
        .animation(ViadereMotion.gentle, value: gate.pending)
    }
}
