import SwiftUI
import ViadereCore
import ViadereKit

/// A verified business and exactly what connecting allows, purpose by purpose.
struct ConnectReview: View {
    @Bindable var vm: ConnectViewModel
    let profile: BusinessProfile
    /// Called by the primary button. The app connects straight away; the App Clip may first create an account.
    var onConnect: (() -> Void)?

    var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.l) {
            ViadereCard {
                VStack(alignment: .leading, spacing: ViadereSpace.m) {
                    HStack(spacing: ViadereSpace.m) {
                        ViadereAvatar(name: profile.safeName, size: 60, isVerified: true)
                        VStack(alignment: .leading, spacing: 6) {
                            Text(profile.safeName).font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary)
                            ViadereBadge("Verified business", kind: .verified)
                        }
                    }
                    ViadereHairline()
                    VStack(spacing: 0) {
                        if let handle = profile.handle { ViadereValueRow("Handle", handle.display) }
                        ViadereValueRow("Code", profile.code.display)
                        if let legal = profile.legalName { ViadereValueRow("Legal name", legal) }
                        if let host = profile.websiteURL?.host { ViadereValueRow("Website", host) }
                    }
                }
            }

            VStack(alignment: .leading, spacing: 0) {
                ViadereSectionHeader("What you're allowing")
                ViadereRowGroup {
                    let rows = PermissionCopy.rows(supported: profile.supportedPurposes,
                                                   granted: Dictionary(uniqueKeysWithValues: vm.optIns.map { ($0, true) }))
                    ForEach(Array(rows.enumerated()), id: \.element.id) { index, row in
                        PermissionToggleRow(row: row, isOn: Binding(
                            get: { row.isLocked ? true : (row.purpose.isGrantedByDefault ? true : vm.optIns.contains(row.purpose)) },
                            set: { _ in vm.toggleOptIn(row.purpose) }),
                            editable: !row.isLocked && !row.purpose.isGrantedByDefault)
                        if index < rows.count - 1 { ViadereHairline() }
                    }
                }
                Text("Security and account notices stay on while you're connected. Offers and rewards are off unless you choose. You can change any of this later.")
                    .font(ViadereType.footnote)
                    .foregroundStyle(ViadereColor.textTertiary)
                    .padding(.top, ViadereSpace.s)
            }

            VStack(spacing: ViadereSpace.xs) {
                Button("Connect to \(profile.safeName)") {
                    if let onConnect { onConnect() } else { Task { await vm.connect() } }
                }
                    .buttonStyle(.viadere(.primary))
                Button("Not now") { vm.backToEntry() }.buttonStyle(.viadere(.quiet))
            }
        }
    }
}

/// One permission: title, plain-language detail and a custom switch. Locked rows read "Always on".
struct PermissionToggleRow: View {
    let row: PermissionCopy.Row
    @Binding var isOn: Bool
    let editable: Bool

    var body: some View {
        Toggle(isOn: $isOn) {
            VStack(alignment: .leading, spacing: 2) {
                Text(row.title).font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                Text(row.isLocked ? "Always on while connected" : row.detail)
                    .font(ViadereType.footnote)
                    .foregroundStyle(ViadereColor.textSecondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .toggleStyle(.viadere)
        .disabled(!editable)
        .padding(.vertical, ViadereSpace.xxs)
    }
}

