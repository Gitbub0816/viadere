import SwiftUI
import ViadereCore
import ViadereKit

/// Settings for one business (spec C7.2; WP-1.5): identity, notifications (favorite, quiet levels), what it may contact you about (purpose
/// by purpose), history, block and disconnect. Quieting changes how notifications interrupt, never whether a request reaches Alerts, and
/// never applies to security checks or anything that needs an answer.
struct BusinessDetailView: View {
    let relationship: Relationship
    let model: AppModel
    @State private var vm: BusinessDetailViewModel
    @State private var prefs: BusinessPreferencesViewModel
    @State private var confirmingBlock = false
    @State private var confirmingDisconnect = false
    @State private var copied = false
    @State private var showingProfileAccess = false
    @Environment(\.dismiss) private var dismiss

    init(relationship: Relationship, model: AppModel) {
        self.relationship = relationship
        self.model = model
        _vm = State(initialValue: BusinessDetailViewModel(relationship: relationship, services: model.services))
        _prefs = State(initialValue: BusinessPreferencesViewModel(business: relationship.business,
                                                                  initial: model.businesses.entry(relationship.business.id)?.preferences,
                                                                  api: model.services.organizationAPI, clock: model.services.clock))
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: ViadereSpace.l) {
                ViadereBackButton { dismiss() }
                hero
                actions
                ApproveBusinessFreezeRow(controller: AppEnvironment.shared.approve, relationshipId: relationship.id, businessName: vm.business.safeName)
                BusinessRewardsEntry(business: vm.business, model: model)
                notifications
                permissions
                profileAccess
                history
                disconnect
                block
            }
            .padding(.horizontal, ViadereSpace.screen)
            .padding(.bottom, ViadereSpace.xl)
        }
        .scrollIndicators(.hidden)
        .viadereScreenBackground()
        .toolbar(.hidden, for: .navigationBar)
        .task {
            prefs.onSaved = { saved in model.businesses.apply(saved) }
            await vm.load()
            await prefs.load()
        }
        .onChange(of: vm.isDisconnected) { _, gone in
            guard gone else { return }
            Task {
                await model.home.load()
                await model.refreshOrganization()
            }
            dismiss()
        }
        .onChange(of: prefs.preferences.blocked) { _, blocked in
            guard blocked else { return }
            Task { await model.refreshOrganization() }
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

    /// Favorite and how loudly this business may interrupt (spec C7.2). Security requests and anything that needs an answer always come
    /// through at full priority, whatever is chosen here.
    private var notifications: some View {
        VStack(alignment: .leading, spacing: 0) {
            ViadereSectionHeader("Notifications")
            ViadereRowGroup {
                Toggle(isOn: Binding(get: { prefs.preferences.favorite }, set: { value in Task { await prefs.setFavorite(value) } })) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Favorite").font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                        Text("Shown first in Businesses and in the selector").font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                    }
                }
                .toggleStyle(.viadere)
                .padding(.vertical, ViadereSpace.s)
                .disabled(prefs.isSaving)
                ViadereHairline()
                VStack(alignment: .leading, spacing: ViadereSpace.xs) {
                    Text("Interruptions").font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                    ViadereFilterBar("Interruptions", selection: Binding(get: { prefs.effectiveMute }, set: { level in Task { await prefs.setMute(level) } }),
                                     options: [ViadereFilterBar<MuteLevel>.Option(MuteLevel.none, "Everything"), ViadereFilterBar<MuteLevel>.Option(.promotional, "Quiet offers"),
                                              ViadereFilterBar<MuteLevel>.Option(.allNonEssential, "Only what matters")])
                    Text(muteExplanation)
                        .font(ViadereType.footnote)
                        .foregroundStyle(ViadereColor.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                    if let until = prefs.preferences.muteUntil, prefs.effectiveMute != MuteLevel.none {
                        Text("Until \(until.formatted(date: .abbreviated, time: .shortened))")
                            .font(ViadereType.footnote)
                            .foregroundStyle(ViadereColor.textTertiary)
                    }
                }
                .padding(.vertical, ViadereSpace.s)
            }
            if let error = prefs.errorMessage {
                ViadereNotice(error, kind: .danger).padding(.top, ViadereSpace.s)
            }
        }
    }

    private var muteExplanation: String {
        switch prefs.effectiveMute {
        case .none: "Notifications from \(vm.business.safeName) arrive normally."
        case .promotional: "Offers and rewards arrive quietly. Everything still appears in Alerts and Benefits."
        case .allNonEssential: "Only security checks and requests that need your answer interrupt you. Everything still appears in Alerts."
        }
    }

    /// "What this business can see" (docs/PROFILES.md): the public name and any profile details shared with it.
    private var profileAccess: some View {
        VStack(alignment: .leading, spacing: 0) {
            ViadereSectionHeader("Profile")
            ViadereRowGroup {
                Button { showingProfileAccess = true } label: {
                    ViadereRow("What \(vm.business.safeName) can see", subtitle: "Your public name, and any details you choose") {
                        ViadereIconTile(systemName: "person.text.rectangle")
                    }
                }
                .buttonStyle(.plain)
            }
        }
        .sheet(isPresented: $showingProfileAccess) {
            BusinessProfileAccessView(api: AppEnvironment.shared.profileAPI, business: vm.business.id)
                .presentationDetents([.large])
                .presentationBackground(ViadereColor.background)
        }
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

    /// Block: ends the connection like Disconnect and also refuses new connections, links and SMS threads from this business until unblocked.
    private var block: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.s) {
            if confirmingBlock {
                ViadereCard(padding: ViadereSpace.m) {
                    VStack(alignment: .leading, spacing: ViadereSpace.s) {
                        Text("Block \(vm.business.safeName)?")
                            .font(ViadereType.headline).foregroundStyle(ViadereColor.textPrimary)
                        Text("You'll be disconnected, its waiting requests are cancelled, and it can't connect to you again until you unblock it in Businesses.")
                            .font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                        HStack(spacing: ViadereSpace.s) {
                            Button("Cancel") { confirmingBlock = false }.buttonStyle(.viadere(.secondary))
                            Button("Block") { Task { await prefs.block() } }.buttonStyle(.viadere(.destructive))
                        }
                    }
                }
            } else {
                Button("Block \(vm.business.safeName)") { withAnimation(ViadereMotion.standard) { confirmingBlock = true } }
                    .buttonStyle(.viadere(.quiet))
            }
        }
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
