import SwiftUI
import ViadereCore
import ViadereKit

/// A connected business: identity, what it may contact you about (purpose by purpose), history, disconnect.
struct BusinessDetailView: View {
    let relationship: Relationship
    let model: AppModel
    @State private var vm: BusinessDetailViewModel
    @State private var confirmingDisconnect = false
    @State private var copied = false
    @Environment(\.dismiss) private var dismiss

    init(relationship: Relationship, model: AppModel) {
        self.relationship = relationship
        self.model = model
        _vm = State(initialValue: BusinessDetailViewModel(relationship: relationship, services: model.services))
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: ViadereSpace.l) {
                ViadereBackButton { dismiss() }
                hero
                actions
                ApproveBusinessFreezeRow(controller: AppEnvironment.shared.approve, relationshipId: relationship.id, businessName: vm.business.safeName)
                BusinessRewardsEntry(business: vm.business, model: model)
                permissions
                history
                disconnect
            }
            .padding(.horizontal, ViadereSpace.screen)
            .padding(.bottom, ViadereSpace.xl)
        }
        .scrollIndicators(.hidden)
        .viadereScreenBackground()
        .toolbar(.hidden, for: .navigationBar)
        .task { await vm.load() }
        .onChange(of: vm.isDisconnected) { _, gone in
            guard gone else { return }
            Task { await model.home.load() }
            dismiss()
        }
    }

    // MARK: Pieces

    private var hero: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.m) {
            ViadereAvatar(name: vm.business.safeName, size: 72, isVerified: vm.business.isVerified)
            VStack(alignment: .leading, spacing: ViadereSpace.xs) {
                Text(vm.business.safeName).font(ViadereType.display).foregroundStyle(ViadereColor.textPrimary)
                HStack(spacing: ViadereSpace.xs) {
                    ViadereBadge(vm.business.isVerified ? "Verified business" : "Not verified", kind: vm.business.isVerified ? .verified : .danger)
                    if let category = vm.profile?.category.rawValue, category != "other" {
                        ViadereBadge(category.replacingOccurrences(of: "_", with: " ").capitalized)
                    }
                }
            }
            ViadereRowGroup {
                if let handle = vm.business.handle {
                    ViadereValueRow("Handle", handle.display)
                    ViadereHairline()
                }
                HStack {
                    ViadereValueRow("Code", vm.business.code.display)
                    Button(copied ? "Copied" : "Copy") {
                        SecurePasteboard.copy(vm.business.code.display)
                        copied = true
                    }
                    .buttonStyle(.viadere(.quiet, fullWidth: false))
                }
                ViadereHairline()
                ViadereValueRow("Connected", relationship.connectedAt.formatted(date: .abbreviated, time: .omitted))
            }
        }
    }

    private var actions: some View {
        Button {
            Task {
                if await model.messages.start(with: vm.business.id) != nil { model.selectedTab = .messages }
            }
        } label: {
            HStack(spacing: ViadereSpace.xs) {
                Image(systemName: "bubble.left")
                Text("Message \(vm.business.safeName)")
            }
        }
        .buttonStyle(.viadere(.secondary))
    }

    private var permissions: some View {
        VStack(alignment: .leading, spacing: 0) {
            ViadereSectionHeader("Permissions")
            ViadereRowGroup {
                ForEach(Array(vm.rows.enumerated()), id: \.element.id) { index, row in
                    PermissionToggleRow(
                        row: row,
                        isOn: Binding(get: { vm.consents[row.purpose] ?? row.isOn },
                                      set: { newValue in Task { await vm.setConsent(row.purpose, granted: newValue) } }),
                        editable: !row.isLocked)
                    if index < vm.rows.count - 1 { ViadereHairline() }
                }
            }
            if let error = vm.errorMessage {
                ViadereNotice(error, kind: .danger).padding(.top, ViadereSpace.s)
            }
            Text("Security and account notices can only stop by disconnecting.")
                .font(ViadereType.footnote)
                .foregroundStyle(ViadereColor.textTertiary)
                .padding(.top, ViadereSpace.s)
        }
    }

    @ViewBuilder private var history: some View {
        if !vm.history.isEmpty {
            VStack(alignment: .leading, spacing: 0) {
                ViadereSectionHeader("History")
                ViadereRowGroup {
                    ForEach(Array(vm.history.prefix(10).enumerated()), id: \.element.id) { index, envelope in
                        ViadereRow(InteractionPresentation.headline(envelope.interaction),
                                   subtitle: "\(statusLabel(envelope.status)) · \(InteractionPresentation.relative(envelope.interaction.createdAt, now: Date()))",
                                   leading: { EmptyView() }, trailing: { EmptyView() })
                        if index < min(vm.history.count, 10) - 1 { ViadereHairline() }
                    }
                }
            }
        }
    }

    private func statusLabel(_ status: InteractionStatus) -> String {
        switch status {
        case .pending: "Waiting"
        case .delivered: "Delivered"
        default: status.rawValue.capitalized
        }
    }

    private var disconnect: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.s) {
            if confirmingDisconnect {
                ViadereCard(padding: ViadereSpace.m) {
                    VStack(alignment: .leading, spacing: ViadereSpace.s) {
                        Text("Disconnect from \(vm.business.safeName)?")
                            .font(ViadereType.headline).foregroundStyle(ViadereColor.textPrimary)
                        Text("You'll stop receiving sign-in checks and notices from them. You can reconnect any time.")
                            .font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                        HStack(spacing: ViadereSpace.s) {
                            Button("Cancel") { confirmingDisconnect = false }.buttonStyle(.viadere(.secondary))
                            Button("Disconnect") { Task { await vm.disconnect() } }.buttonStyle(.viadere(.destructive))
                        }
                    }
                }
            } else {
                Button("Disconnect") { withAnimation(ViadereMotion.standard) { confirmingDisconnect = true } }
                    .buttonStyle(.viadere(.destructive))
            }
        }
        .padding(.top, ViadereSpace.m)
    }
}

#if DEBUG
#Preview("Business") {
    PreviewHost { services in
        BusinessDetailView(relationship: PreviewData.relationship(PreviewData.harborBank), model: AppModel(services: services))
    }
}

#Preview("Business · rewards") {
    PreviewHost { services in
        NavigationStack {
            BusinessDetailView(relationship: PreviewData.relationship(PreviewData.juniperCoffee), model: AppModel(services: services, walletLibrary: MockWalletLibrary()))
        }
    }
}
#endif
