import SwiftUI
import ViadereCore
import ViadereKit

/// Settings for one business (spec C7.2; WP-1.5; docs/APP-IA.md). In the order people look for things: how loudly it may interrupt (three
/// levels, with how long), what it may contact you about (one chip per purpose; security and account notices are locked on), approvals
/// and its own requests (deliberate state cards, never casual switches), privacy (what it can see, history), the connection's facts, then
/// disconnect and block. Quieting changes how notifications interrupt, never whether a request reaches Alerts, and never applies to
/// security checks or anything that needs an answer.
struct BusinessDetailView: View {
    let relationship: Relationship
    let model: AppModel
    @State private var vm: BusinessDetailViewModel
    @State private var prefs: BusinessPreferencesViewModel
    @State private var confirmingBlock = false
    @State private var confirmingDisconnect = false
    @State private var copied = false
    @State private var showingProfileAccess = false
    @State private var showingAllHistory = false
    @State private var duration: BusinessPreferencesViewModel.MuteDuration = .untilChanged
    @Environment(\.dismiss) private var dismiss

    init(relationship: Relationship, model: AppModel) {
        self.relationship = relationship
        self.model = model
        _vm = State(initialValue: BusinessDetailViewModel(relationship: relationship, services: model.services))
        _prefs = State(initialValue: BusinessPreferencesViewModel(business: relationship.business,
                                                                  initial: model.businesses.entry(relationship.business.id)?.preferences,
                                                                  api: model.services.organizationAPI, clock: model.services.clock))
    }

    private var name: String { vm.business.safeName }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                ViadereBackButton(name) { dismiss() }
                header
                notifications
                permissions
                ApproveBusinessFreezeRow(controller: AppEnvironment.shared.approve, relationshipId: relationship.id, businessName: name)
                BusinessLoopAuthorizationRow(business: vm.business, model: model)
                privacy
                about
                endConnection
            }
            .padding(.horizontal, ViadereSpace.screen)
            .padding(.bottom, ViadereSpace.xl)
        }
        .scrollIndicators(.hidden)
        .viadereScreenBackground()
        .toolbar(.hidden, for: .navigationBar)
        .task {
            prefs.onSaved = { saved in model.businesses.apply(saved) }
            duration = .closest(to: prefs.preferences.muteUntil, now: model.services.clock())
            await vm.load()
            await prefs.load()
            duration = .closest(to: prefs.preferences.muteUntil, now: model.services.clock())
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
        .sheet(isPresented: $showingProfileAccess) {
            BusinessProfileAccessView(api: AppEnvironment.shared.profileAPI, business: vm.business.id)
                .presentationDetents([.large])
                .presentationBackground(ViadereColor.background)
        }
    }

    // MARK: Header

    /// Who these settings are for, compact (the business page carries the full identity). The star sits with the name.
    private var header: some View {
        HStack(spacing: ViadereSpace.m) {
            ViadereAvatar(name: name, size: 56, isVerified: vm.business.isVerified)
            VStack(alignment: .leading, spacing: ViadereSpace.xxs) {
                Text(name)
                    .font(ViadereType.title)
                    .foregroundStyle(ViadereColor.textPrimary)
                    .accessibilityAddTraits(.isHeader)
                ViadereBadge(vm.business.isVerified ? "Verified business" : "Not verified", kind: vm.business.isVerified ? .verified : .danger)
            }
            .accessibilityElement(children: .combine)
            Spacer(minLength: 0)
            ViadereFavoriteButton(isFavorite: prefs.preferences.favorite, name: name) {
                Task { await prefs.setFavorite(!prefs.preferences.favorite) }
            }
            .disabled(prefs.isSaving)
        }
        .padding(.top, ViadereSpace.s)
    }

    // MARK: Notifications

    /// How loudly this business may interrupt: three levels instead of a switch, and how long a quieter level lasts.
    private var notifications: some View {
        let preset = InterruptionPreset(prefs.effectiveMute)
        return VStack(alignment: .leading, spacing: 0) {
            ViadereSectionHeader("Notifications")
            ViadereCard(padding: ViadereSpace.m) {
                VStack(alignment: .leading, spacing: ViadereSpace.s) {
                    ViadereLevelPicker("Interruptions from \(name)",
                                       selection: Binding(get: { preset }, set: { value in Task { await prefs.setMute(value.muteLevel, for: duration) } }),
                                       levels: InterruptionPreset.levels,
                                       caption: preset.explanation(business: name))
                    .disabled(prefs.isSaving)
                    if preset != .everything {
                        ViadereHairline()
                        ViadereInlineStepper("For", value: Binding(get: { duration }, set: { value in
                            duration = value
                            Task { await prefs.setMute(preset.muteLevel, for: value) }
                        }), values: BusinessPreferencesViewModel.MuteDuration.stepOrder) { durationText($0) }
                        .disabled(prefs.isSaving)
                        if let until = prefs.preferences.muteUntil {
                            Text("Back to Everything \(until.formatted(date: .abbreviated, time: .shortened)).")
                                .font(ViadereType.footnote)
                                .foregroundStyle(ViadereColor.textTertiary)
                        }
                    }
                }
            }
            if let error = prefs.errorMessage {
                ViadereNotice(error, kind: .danger).padding(.top, ViadereSpace.s)
            }
        }
    }

    private func durationText(_ duration: BusinessPreferencesViewModel.MuteDuration) -> String {
        switch duration {
        case .hour: "1 hour"
        case .day: "1 day"
        case .week: "1 week"
        case .untilChanged: "Until I change it"
        }
    }

    // MARK: Permissions

    /// What this business may contact you about: one chip per purpose instead of a column of switches. Security and account notices are
    /// locked on while connected (they stop only by disconnecting).
    private var permissions: some View {
        VStack(alignment: .leading, spacing: 0) {
            ViadereSectionHeader("\(name) can contact you about")
            ViadereCard(padding: ViadereSpace.m) {
                VStack(alignment: .leading, spacing: ViadereSpace.s) {
                    ViadereChipSet("What \(name) can contact you about",
                                   chips: vm.rows.map { row in
                                       ViadereChipSet<InteractionPurpose>.Chip(row.purpose, row.title, isLocked: row.isLocked, hint: row.detail)
                                   },
                                   isSelected: { purpose in vm.consents[purpose] ?? vm.rows.first { $0.purpose == purpose }?.isOn ?? false },
                                   toggle: { purpose in
                                       let current = vm.consents[purpose] ?? vm.rows.first { $0.purpose == purpose }?.isOn ?? false
                                       Task { await vm.setConsent(purpose, granted: !current) }
                                   })
                    Text(PermissionCopy.summary(currentRows) + ".")
                        .font(ViadereType.footnote.weight(.medium))
                        .foregroundStyle(ViadereColor.textPrimary)
                    Text("Security and account notices stay on while you're connected; they stop only if you disconnect.")
                        .font(ViadereType.footnote)
                        .foregroundStyle(ViadereColor.textSecondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            if let error = vm.errorMessage {
                ViadereNotice(error, kind: .danger).padding(.top, ViadereSpace.s)
            }
        }
    }

    /// The rows with the latest saved choices applied (the chips change before the server answers; a refusal rolls back).
    private var currentRows: [PermissionCopy.Row] {
        vm.rows.map { row in
            var row = row
            if let granted = vm.consents[row.purpose], !row.isLocked { row.isOn = granted }
            return row
        }
    }

    // MARK: Privacy

    private var privacy: some View {
        VStack(alignment: .leading, spacing: 0) {
            ViadereSectionHeader("Privacy")
            ViadereRowGroup {
                Button { showingProfileAccess = true } label: {
                    ViadereRow("What \(name) can see", subtitle: "Your public name, and any details you choose") {
                        ViadereIconTile(systemName: "person.text.rectangle")
                    }
                }
                .buttonStyle(.plain)
                if !vm.history.isEmpty {
                    ViadereHairline(inset: 50)
                    Button { withAnimation(ViadereMotion.standard) { showingAllHistory.toggle() } } label: {
                        ViadereRow("History", subtitle: historySubtitle) {
                            ViadereIconTile(systemName: "clock")
                        } trailing: {
                            Image(systemName: showingAllHistory ? "chevron.up" : "chevron.down")
                                .font(.system(size: 12, weight: .semibold))
                                .foregroundStyle(ViadereColor.textTertiary)
                                .accessibilityHidden(true)
                        }
                    }
                    .buttonStyle(.plain)
                    if showingAllHistory {
                        ForEach(vm.history.prefix(10), id: \.id) { envelope in
                            ViadereHairline(inset: 50)
                            ViadereRow(InteractionPresentation.headline(envelope.interaction),
                                       subtitle: "\(statusLabel(envelope.status)) · \(InteractionPresentation.relative(envelope.interaction.createdAt, now: Date()))",
                                       leading: { Color.clear.frame(width: 36, height: 1) }, trailing: { EmptyView() })
                        }
                    }
                }
            }
        }
    }

    private var historySubtitle: String {
        let count = min(vm.history.count, 10)
        return count == 1 ? "The last request from \(name)" : "The last \(count) requests from \(name)"
    }

    private func statusLabel(_ status: InteractionStatus) -> String {
        switch status {
        case .pending: "Waiting"
        case .delivered: "Delivered"
        default: status.rawValue.capitalized
        }
    }

    // MARK: About

    private var about: some View {
        VStack(alignment: .leading, spacing: 0) {
            ViadereSectionHeader("About this connection")
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
                if let category = vm.profile?.category.rawValue, category != "other" {
                    ViadereValueRow("Category", category.replacingOccurrences(of: "_", with: " ").capitalized)
                    ViadereHairline()
                }
                ViadereValueRow("Connected", relationship.connectedAt.formatted(date: .abbreviated, time: .omitted))
            }
        }
    }

    // MARK: End the connection

    private var endConnection: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.s) {
            ViadereSectionHeader("End the connection")
            if confirmingDisconnect {
                confirmCard(title: "Disconnect from \(name)?",
                            message: "You'll stop receiving sign-in checks and notices from them. You can reconnect any time.",
                            action: "Disconnect") { Task { await vm.disconnect() } } cancel: { confirmingDisconnect = false }
            } else {
                Button("Disconnect") { withAnimation(ViadereMotion.standard) { confirmingDisconnect = true } }
                    .buttonStyle(.viadere(.destructive))
            }
            // Block: ends the connection like Disconnect and also refuses new connections, links and SMS threads until unblocked.
            if confirmingBlock {
                confirmCard(title: "Block \(name)?",
                            message: "You'll be disconnected, its waiting requests are cancelled, and it can't connect to you again until you unblock it in Businesses.",
                            action: "Block") { Task { await prefs.block() } } cancel: { confirmingBlock = false }
            } else {
                Button("Block \(name)") { withAnimation(ViadereMotion.standard) { confirmingBlock = true } }
                    .buttonStyle(.viadere(.quiet))
            }
        }
    }

    private func confirmCard(title: String, message: String, action: String, onConfirm: @escaping () -> Void,
                             cancel: @escaping () -> Void) -> some View {
        ViadereCard(padding: ViadereSpace.m) {
            VStack(alignment: .leading, spacing: ViadereSpace.s) {
                Text(title).font(ViadereType.headline).foregroundStyle(ViadereColor.textPrimary)
                Text(message).font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                HStack(spacing: ViadereSpace.s) {
                    Button("Cancel", action: cancel).buttonStyle(.viadere(.secondary))
                    Button(action, action: onConfirm).buttonStyle(.viadere(.destructive))
                }
            }
        }
    }
}

#if DEBUG
#Preview("Business") {
    PreviewHost { services in
        NavigationStack {
            BusinessDetailView(relationship: PreviewData.relationship(PreviewData.harborBank), model: AppModel(services: services))
        }
    }
}
#endif

extension InterruptionPreset {
    /// The three levels as the level picker draws them (most to least).
    static var levels: [ViadereLevelPicker<InterruptionPreset>.Level] {
        allCases.map { ViadereLevelPicker<InterruptionPreset>.Level($0, $0.title, intensity: $0.intensity) }
    }
}
