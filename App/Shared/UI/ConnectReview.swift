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
                // One chip per purpose (not a column of switches): locked chips are always on while connected; offers and rewards are
                // the only ones to choose here, and they start off.
                let rows = PermissionCopy.rows(supported: profile.supportedPurposes,
                                               granted: Dictionary(uniqueKeysWithValues: vm.optIns.map { ($0, true) }))
                ViadereCard(padding: ViadereSpace.m) {
                    VStack(alignment: .leading, spacing: ViadereSpace.s) {
                        ViadereChipSet("What \(profile.safeName) can contact you about",
                                       chips: rows.map { row in
                                           ViadereChipSet<InteractionPurpose>.Chip(row.purpose, row.title,
                                                                                   isLocked: row.isLocked || row.purpose.isGrantedByDefault,
                                                                                   hint: row.detail)
                                       },
                                       isSelected: { purpose in purpose.isGrantedByDefault || !purpose.isRevocable || vm.optIns.contains(purpose) },
                                       toggle: { vm.toggleOptIn($0) })
                        ForEach(rows.filter { !$0.isLocked && !$0.purpose.isGrantedByDefault }) { row in
                            Text("\(row.title): \(row.detail)")
                                .font(ViadereType.footnote)
                                .foregroundStyle(ViadereColor.textSecondary)
                                .fixedSize(horizontal: false, vertical: true)
                        }
                    }
                }
                Text("Security, account notices, orders and support stay on while you're connected. Offers and rewards are off unless you choose. You can change any of this later.")
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
