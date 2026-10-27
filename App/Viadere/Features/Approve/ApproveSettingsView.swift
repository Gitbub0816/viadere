import SwiftUI
import ViadereCore
import ViadereKit

/// Settings → Approvals: pending requests, the pairwise keys held per business, the freeze switch, and any warning about a business's keys.
struct ApproveSettingsView: View {
    @Bindable var controller: ApproveController
    @Bindable var model: AppModel
    @State private var confirmingRemove: LocalApprovalKey?
    @State private var confirmingChange: PendingRootChange?
    @State private var enterCode = false
    @State private var typedCode = ""
    @State private var enrollment: PendingApproveEnrollment?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: ViadereSpace.l) {
                ViadereBackButton { dismiss() }
                ViadereHeader("Approvals", subtitle: "Payments and sign-ins you confirm with Face ID")
                if !controller.isAvailable {
                    ViadereNotice(ApproveText.notAvailable, kind: .info)
                } else {
                    if let message = controller.message { ViadereNotice(message, kind: .warning) }
                    freezeSection
                    alertsSection
                    waitingSection
                    keysSection
                    setupSection
                }
            }
            .padding(.horizontal, ViadereSpace.screen)
            .padding(.bottom, ViadereSpace.xl)
        }
        .scrollIndicators(.hidden)
        .viadereScreenBackground()
        .toolbar(.hidden, for: .navigationBar)
        .task {
            await controller.refresh()
            if let pending = model.pendingApproveEnrollment { enrollment = pending; model.pendingApproveEnrollment = nil }
        }
        .onChange(of: model.pendingApproveEnrollment) { _, pending in
            if let pending { enrollment = pending; model.pendingApproveEnrollment = nil }
        }
        .sheet(item: Binding(get: { enrollment.map { EnrollmentItem(code: $0.code, rootKid: $0.rootKid) } }, set: { if $0 == nil { enrollment = nil } })) { item in
            ApproveEnrollmentSheet(controller: controller, code: item.code, rootKid: item.rootKid)
                .presentationDetents([.large])
                .presentationBackground(ViadereColor.background)
        }
        .confirmationDialog("Remove this key?", isPresented: Binding(get: { confirmingRemove != nil }, set: { if !$0 { confirmingRemove = nil } }), titleVisibility: .visible) {
            Button("Remove", role: .destructive) { if let key = confirmingRemove { Task { await controller.revoke(key) } } }
            Button("Cancel", role: .cancel) {}
        } message: {
            Text("\(confirmingRemove?.businessName ?? "This business") will no longer be able to ask you to approve anything until you set it up again.")
        }
    }

    // MARK: Freeze

    private var freezeSection: some View {
        VStack(alignment: .leading, spacing: 0) {
            ViadereSectionHeader("Pause everything")
            ViadereRowGroup {
                Toggle(isOn: Binding(get: { controller.accountFrozen }, set: { value in Task { await controller.setAccountFrozen(value) } })) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Freeze approvals").font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                        Text("No business can ask you to approve anything. Turning this off again needs Face ID on a trusted device.")
                            .font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                    }
                }
                .toggleStyle(.viadere)
                .disabled(controller.phase == .working)
                .padding(.vertical, ViadereSpace.xxs)
            }
        }
    }

    // MARK: Warnings about a business's keys

    @ViewBuilder private var alertsSection: some View {
        let businesses = controller.keys.reduce(into: [BusinessID: String]()) { $0[$1.businessId] = $1.businessName }
        ForEach(businesses.keys.sorted { $0.description < $1.description }, id: \.self) { id in
            if let alert = controller.alerts[id.description] {
                VStack(alignment: .leading, spacing: ViadereSpace.s) {
                    switch alert {
                    case .rootChanged(let change):
                        ViadereNotice("\(businesses[id] ?? "A business") changed its signing key. This is normal when a company rotates keys, and it is also what an attack on its account looks like. Contact them another way to check before you continue.", kind: .warning)
                        ViadereRowGroup {
                            ViadereValueRow("Before", KeyIdentifier.displayFingerprint(change.pinnedKid))
                            ViadereHairline()
                            ViadereValueRow("Now", KeyIdentifier.displayFingerprint(change.newKid), emphasized: true)
                        }
                        Button("I checked. Trust the new key") { Task { await controller.acceptRootChange(businessId: id) } }
                            .buttonStyle(.viadere(.secondary))
                    case .rootConflict:
                        ViadereNotice("What \(businesses[id] ?? "this business") shows now does not match its history on this phone. Approvals with it are blocked. Do not continue; tell the business and Viadere.", kind: .danger)
                        Button("Forget this business's keys") { Task { await controller.acknowledgeConflict(businessId: id) } }
                            .buttonStyle(.viadere(.destructive))
                    }
                }
            }
        }
    }

    // MARK: Requests and keys

    @ViewBuilder private var waitingSection: some View {
        if !controller.prompts.isEmpty || !controller.rejected.isEmpty {
            VStack(alignment: .leading, spacing: 0) {
                ViadereSectionHeader("Waiting for you")
                ViadereRowGroup {
                    ForEach(controller.prompts) { prompt in
                        Button { controller.present(prompt) } label: {
                            ViadereRow(prompt.business.safeName, subtitle: prompt.promptReason) { ViadereAvatar(name: prompt.business.safeName, size: 36, isVerified: prompt.business.isVerified) }
                        }
                        .buttonStyle(.plain)
                        ViadereHairline(inset: 50)
                    }
                    ForEach(controller.rejected) { item in
                        ViadereRow(item.businessName, subtitle: "A request failed checks on this phone and was hidden") { ViadereIconTile(systemName: "exclamationmark.shield") }
                        Button("Dismiss") { controller.dismissRejected(item.id) }.buttonStyle(.viadere(.quiet, fullWidth: false))
                    }
                }
            }
        }
    }

    @ViewBuilder private var keysSection: some View {
        let active = controller.keys.filter { $0.status == .active || $0.status == .pendingConfirmation }
        if !active.isEmpty {
            VStack(alignment: .leading, spacing: 0) {
                ViadereSectionHeader("Your keys")
                ViadereRowGroup {
                    ForEach(active) { key in
                        HStack {
                            ViadereRow(key.businessName, subtitle: key.status == .active ? "Active" : "Waiting for the business to confirm") {
                                ViadereIconTile(systemName: "key.horizontal")
                            }
                            Button { confirmingRemove = key } label: { Image(systemName: "trash") }
                                .accessibilityLabel("Remove key for \(key.businessName)")
                                .buttonStyle(.plain)
                                .foregroundStyle(ViadereColor.danger)
                        }
                        if key.id != active.last?.id { ViadereHairline(inset: 50) }
                    }
                }
                Text("Each business has its own key. They cannot be matched with each other.")
                    .font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary).padding(.top, ViadereSpace.xs)
            }
        }
    }

    private var setupSection: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.s) {
            ViadereSectionHeader("Set up a business")
            ViadereEntryField(placeholder: "Setup code from the business", text: $typedCode, status: .none, hint: "Eight letters and numbers", monospaced: true)
            Button("Continue") { enrollment = PendingApproveEnrollment(code: typedCode, rootKid: nil); typedCode = "" }
                .buttonStyle(.viadere(.secondary))
                .disabled(typedCode.filter { $0.isLetter || $0.isNumber }.count < 8)
        }
    }
}

private struct EnrollmentItem: Identifiable, Equatable {
    var code: String
    var rootKid: String?
    var id: String { code + (rootKid ?? "") }
}

/// The per-business freeze switch shown on the business page.
struct ApproveBusinessFreezeRow: View {
    @Bindable var controller: ApproveController
    let relationshipId: RelationshipID
    let businessName: String

    var body: some View {
        if controller.isAvailable, controller.keys.contains(where: { $0.relationshipId == relationshipId && $0.status != .revoked }) {
            ViadereRowGroup {
                Toggle(isOn: Binding(get: { controller.isFrozen(relationship: relationshipId) }, set: { value in Task { await controller.setFrozen(value, relationship: relationshipId) } })) {
                    VStack(alignment: .leading, spacing: 2) {
                        Text("Pause approvals for \(businessName)").font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                        Text("It cannot ask you to approve anything until you turn this off.").font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                    }
                }
                .toggleStyle(.viadere)
                .disabled(controller.phase == .working)
                .padding(.vertical, ViadereSpace.xxs)
            }
        }
    }
}
