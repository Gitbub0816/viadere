import SwiftUI
import ViadereCore
import ViadereKit

/// Settings → Household: who can act for you (and who you can act for), always scoped, always expiring, always revocable.
struct HouseholdView: View {
    @Bindable var vm: HouseholdViewModel
    @State private var inviting = false
    @State private var accepting = false
    @State private var confirming: DelegationID?
    @State private var showPast = false

    var body: some View {
        SubScreen(title: "Household", subtitle: "Share limited access with people you trust. You decide what, where and until when.") {
            if let message = vm.errorMessage { ViadereNotice(message, kind: .danger) }
            VStack(spacing: ViadereSpace.xs) {
                Button("Invite someone") { vm.resetDraft(); inviting = true }.buttonStyle(.viadere(.primary))
                Button("I have an invitation code") { vm.resetAcceptance(); accepting = true }.buttonStyle(.viadere(.secondary))
            }
            if vm.phase == .loading {
                ViadereLoading().frame(maxWidth: .infinity).padding(.top, ViadereSpace.l)
            }
            if !vm.activeGiven.isEmpty { section("You've shared", grants: vm.activeGiven, endLabel: "End access") }
            if !vm.activeReceived.isEmpty { section("Shared with you", grants: vm.activeReceived, endLabel: "Stop acting for them") }
            if vm.phase == .loaded, vm.activeGiven.isEmpty, vm.activeReceived.isEmpty {
                Text("Nothing is shared right now.").font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary).padding(.top, ViadereSpace.s)
            }
            VStack(alignment: .leading, spacing: 0) {
                ViadereSectionHeader("Records")
                ViadereRowGroup {
                    NavigationLink {
                        HouseholdAuditView(vm: vm)
                    } label: {
                        ViadereRow("Household activity", subtitle: "Every grant, response and block", leading: { ViadereIconTile(systemName: "list.bullet.rectangle") })
                    }
                    .buttonStyle(.plain)
                }
            }
            if !vm.pastGrants.isEmpty {
                Button(showPast ? "Hide earlier" : "Show earlier · \(vm.pastGrants.count)") { withAnimation(ViadereMotion.standard) { showPast.toggle() } }
                    .buttonStyle(.viadere(.quiet, fullWidth: false))
                if showPast {
                    ViadereRowGroup {
                        ForEach(Array(vm.pastGrants.enumerated()), id: \.element.id) { index, grant in
                            grantRow(grant)
                            if index < vm.pastGrants.count - 1 { ViadereHairline(inset: 50) }
                        }
                    }
                }
            }
            Text("Delegates can see and respond to the access you share. They can never approve sign-ins or payments for you: those always need your own device. Sensitive access ends within 30 days.")
                .font(ViadereType.footnote)
                .foregroundStyle(ViadereColor.textTertiary)
        }
        .task { await vm.load() }
        .refreshable { await vm.load() }
        .sheet(isPresented: $inviting) {
            HouseholdInviteSheet(vm: vm) { inviting = false }
                .presentationDetents([.large])
                .presentationDragIndicator(.hidden)
                .presentationCornerRadius(ViadereRadius.sheet)
                .presentationBackground(ViadereColor.background)
        }
        .sheet(isPresented: $accepting) {
            AcceptInviteSheet(vm: vm) { accepting = false }
                .presentationDetents([.large])
                .presentationDragIndicator(.hidden)
                .presentationCornerRadius(ViadereRadius.sheet)
                .presentationBackground(ViadereColor.background)
        }
    }

    private func section(_ title: String, grants: [HouseholdGrant], endLabel: String) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            ViadereSectionHeader(title)
            ViadereRowGroup {
                ForEach(Array(grants.enumerated()), id: \.element.id) { index, grant in
                    VStack(alignment: .leading, spacing: ViadereSpace.xs) {
                        grantRow(grant)
                        if confirming == grant.id {
                            HStack(spacing: ViadereSpace.s) {
                                Button("Cancel") { confirming = nil }.buttonStyle(.viadere(.secondary))
                                Button(endLabel) { Task { await vm.revoke(grant); confirming = nil } }.buttonStyle(.viadere(.destructive))
                            }
                            .padding(.bottom, ViadereSpace.s)
                        } else {
                            Button(endLabel) { withAnimation(ViadereMotion.standard) { confirming = grant.id } }
                                .buttonStyle(.viadere(.quiet, fullWidth: false))
                        }
                    }
                    if index < grants.count - 1 { ViadereHairline() }
                }
            }
        }
    }

    private func grantRow(_ grant: HouseholdGrant) -> some View {
        ViadereRow(grant.counterpartName,
                   subtitle: "\(DelegationScopePolicy.roleTitle(grant.grant.role)) · \(vm.summary(grant))",
                   leading: { ViadereIconTile(systemName: "person.crop.circle") },
                   trailing: { badge(grant) })
    }

    @ViewBuilder private func badge(_ grant: HouseholdGrant) -> some View {
        switch grant.status {
        case .active: ViadereBadge("Active", kind: .success)
        case .pending: ViadereBadge("Invited", kind: .pending)
        case .expired: ViadereBadge("Expired", kind: .neutral)
        case .revoked: ViadereBadge("Ended", kind: .neutral)
        }
    }
}

// MARK: - Invite

/// Create a scoped, expiring invitation. Starts with nothing selected; sensitive scopes carry a warning and a Face ID step-up.
struct HouseholdInviteSheet: View {
    @Bindable var vm: HouseholdViewModel
    let onDone: () -> Void

    var body: some View {
        VStack(spacing: 0) {
            ViadereGrabber()
            if case .created(let invitation) = vm.creation {
                InviteCreated(invitation: invitation, name: vm.draft.delegateLabel, onDone: onDone)
            } else {
                form
            }
        }
        .background(ViadereColor.background)
        .privacySensitive()
        .interactiveDismissDisabled(vm.creation == .working)
    }

    private var form: some View {
        VStack(spacing: 0) {
            ScrollView {
                VStack(alignment: .leading, spacing: ViadereSpace.l) {
                    Text("Invite someone").font(ViadereType.display).foregroundStyle(ViadereColor.textPrimary)
                    ViadereTextField("Name", text: $vm.draft.delegateLabel, prompt: "Sam", message: "Only you see this. It helps you recognize them.")
                        .textContentType(.givenName)
                    role
                    access
                    businesses
                    lifetime
                    ForEach(vm.warnings) { warning in
                        ViadereNotice("\(warning.title). \(warning.message)", kind: warning.severity == .caution ? .warning : .info)
                    }
                    if case .failed(let message) = vm.creation { ViadereNotice(message, kind: .danger) }
                }
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.top, ViadereSpace.m)
                .padding(.bottom, ViadereSpace.l)
            }
            .scrollIndicators(.hidden)
            VStack(spacing: ViadereSpace.xs) {
                if let issue = vm.issues.first, vm.creation != .working {
                    Text(issue.message).font(ViadereType.footnote).foregroundStyle(ViadereColor.textTertiary)
                }
                Button(vm.creation == .working ? "Confirming…" : (vm.requiresStepUp ? "Continue with Face ID" : "Create invitation")) {
                    Task { await vm.createInvitation() }
                }
                .buttonStyle(.viadere(.primary))
                .disabled(!vm.canCreate)
                Button("Cancel", action: onDone).buttonStyle(.viadere(.quiet)).disabled(vm.creation == .working)
            }
            .padding(.horizontal, ViadereSpace.screen)
            .padding(.top, ViadereSpace.s)
            .padding(.bottom, ViadereSpace.m)
        }
    }

    private var role: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.xs) {
            Text("What they can do").font(ViadereType.footnote.weight(.medium)).foregroundStyle(ViadereColor.textSecondary)
            ViadereSegmented(selection: Binding(get: { vm.draft.role }, set: { vm.setRole($0) }),
                             options: [DelegationGrant.Role.viewer, .manager], title: DelegationScopePolicy.roleTitle)
            Text(DelegationScopePolicy.roleDetail(vm.draft.role)).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
        }
    }

    private var access: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Access").font(ViadereType.footnote.weight(.medium)).foregroundStyle(ViadereColor.textSecondary).padding(.bottom, ViadereSpace.xs)
            ViadereRowGroup {
                ForEach(Array(DelegationScopePolicy.delegablePurposes.enumerated()), id: \.element) { index, purpose in
                    Toggle(isOn: Binding(get: { vm.draft.purposes.contains(purpose) }, set: { _ in vm.togglePurpose(purpose) })) {
                        VStack(alignment: .leading, spacing: 2) {
                            HStack(spacing: ViadereSpace.xs) {
                                Text(PermissionCopy.title(purpose)).font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                                if DelegationScopePolicy.isSensitive(purpose) { ViadereBadge("Sensitive", kind: .verified) }
                            }
                            Text(PermissionCopy.detail(purpose)).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                        }
                    }
                    .toggleStyle(.viadere)
                    .padding(.vertical, ViadereSpace.xxs)
                    if index < DelegationScopePolicy.delegablePurposes.count - 1 { ViadereHairline() }
                }
            }
        }
    }

    private var businesses: some View {
        VStack(alignment: .leading, spacing: 0) {
            Text("Businesses").font(ViadereType.footnote.weight(.medium)).foregroundStyle(ViadereColor.textSecondary).padding(.bottom, ViadereSpace.xs)
            if vm.businesses.isEmpty {
                Text("Connect a business first.").font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
            } else {
                ViadereRowGroup {
                    ForEach(Array(vm.businesses.enumerated()), id: \.element.id) { index, business in
                        Toggle(isOn: Binding(get: { vm.draft.businessIds.contains(business.id) }, set: { _ in vm.toggleBusiness(business.id) })) {
                            HStack(spacing: ViadereSpace.s) {
                                ViadereAvatar(name: business.safeName, size: 32, isVerified: business.isVerified)
                                Text(business.safeName).font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary)
                            }
                        }
                        .toggleStyle(.viadere)
                        .padding(.vertical, ViadereSpace.xxs)
                        if index < vm.businesses.count - 1 { ViadereHairline() }
                    }
                }
            }
        }
    }

    private var lifetime: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.xs) {
            Text("Ends automatically").font(ViadereType.footnote.weight(.medium)).foregroundStyle(ViadereColor.textSecondary)
            ViadereSegmented(selection: Binding(get: { vm.selectedLifetimeDays }, set: { vm.setLifetime(days: $0) }),
                             options: vm.lifetimeChoices, title: { $0 == 365 ? "1 year" : "\($0) days" })
            Text("You can end access sooner at any time.").font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
        }
    }
}

private struct InviteCreated: View {
    let invitation: DelegationInvitation
    let name: String
    let onDone: () -> Void
    @State private var copied = false

    var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.l) {
            Image(systemName: "checkmark.circle").font(.system(size: 44, weight: .light)).foregroundStyle(ViadereColor.success).accessibilityHidden(true)
            Text("Invitation ready").font(ViadereType.display).foregroundStyle(ViadereColor.textPrimary)
            Text("Give this code to \(name.isEmpty ? "them" : name). They enter it in Viadere under Settings, Household. It works once and expires \(invitation.inviteExpiresAt.formatted(date: .abbreviated, time: .shortened)).")
                .font(ViadereType.body)
                .foregroundStyle(ViadereColor.textSecondary)
            ViadereCard(padding: ViadereSpace.l) {
                Text(invitation.code)
                    .font(.system(size: 32, weight: .semibold, design: .monospaced))
                    .tracking(2)
                    .foregroundStyle(ViadereColor.textPrimary)
                    .frame(maxWidth: .infinity)
                    .textSelection(.disabled)
            }
            Text("Access starts when they accept. Until then nothing is shared.")
                .font(ViadereType.footnote).foregroundStyle(ViadereColor.textTertiary)
            Spacer()
            Button("Done", action: onDone).buttonStyle(.viadere(.primary))
            Button(copied ? "Copied" : "Copy code") { SecurePasteboard.copy(invitation.code); copied = true }.buttonStyle(.viadere(.quiet))
        }
        .padding(.horizontal, ViadereSpace.screen)
        .padding(.top, ViadereSpace.l)
        .padding(.bottom, ViadereSpace.m)
    }
}

// MARK: - Accept

struct AcceptInviteSheet: View {
    @Bindable var vm: HouseholdViewModel
    let onDone: () -> Void
    @State private var code = ""

    var body: some View {
        VStack(spacing: 0) {
            ViadereGrabber()
            VStack(alignment: .leading, spacing: ViadereSpace.l) {
                content
                Spacer()
                footer
            }
            .padding(.horizontal, ViadereSpace.screen)
            .padding(.top, ViadereSpace.l)
            .padding(.bottom, ViadereSpace.m)
        }
        .background(ViadereColor.background)
        .privacySensitive()
    }

    @ViewBuilder private var content: some View {
        switch vm.acceptance {
        case .idle, .loadingPreview, .failed:
            Text("Invitation code").font(ViadereType.display).foregroundStyle(ViadereColor.textPrimary)
            Text("Enter the code someone shared with you. You'll see exactly what they're offering before you accept.")
                .font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
            ViadereTextField("Code", text: $code, prompt: "K7M2-9QXP")
                .textInputAutocapitalization(.characters)
                .autocorrectionDisabled()
                .onChange(of: code) { _, new in code = InvitationCodeInput.normalize(new) }
            if case .failed(let message) = vm.acceptance { ViadereNotice(message, kind: .danger) }
        case .preview(let preview), .accepting(let preview):
            Text("\(preview.grantorName) wants to share access").font(ViadereType.display).foregroundStyle(ViadereColor.textPrimary)
            ViadereRowGroup {
                ViadereValueRow("You can", DelegationScopePolicy.roleTitle(preview.role).replacingOccurrences(of: "Can ", with: ""))
                ViadereHairline()
                ViadereValueRow("Access", preview.purposes.map(PermissionCopy.title).joined(separator: ", "))
                ViadereHairline()
                ViadereValueRow("At", preview.businessNames.joined(separator: ", "))
                ViadereHairline()
                ViadereValueRow("Until", preview.expiresAt.formatted(date: .abbreviated, time: .omitted))
            }
            if !Set(preview.purposes).isDisjoint(with: DelegationScopePolicy.sensitivePurposes) {
                ViadereNotice("This includes sensitive access. You'll see security notices for \(preview.grantorName), but you can't approve sign-ins or payments for them.", kind: .warning)
            }
            Text("Everything you do for \(preview.grantorName) is labeled \"on behalf of\" and recorded in your household activity.")
                .font(ViadereType.footnote).foregroundStyle(ViadereColor.textTertiary)
        case .accepted(let name):
            Image(systemName: "checkmark.circle").font(.system(size: 44, weight: .light)).foregroundStyle(ViadereColor.success).accessibilityHidden(true)
            Text("You're set").font(ViadereType.display).foregroundStyle(ViadereColor.textPrimary)
            Text("You can now see updates from \(name)'s businesses, within what they shared.").font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
        }
    }

    @ViewBuilder private var footer: some View {
        switch vm.acceptance {
        case .idle, .failed:
            VStack(spacing: ViadereSpace.xs) {
                Button("Check code") { Task { await vm.previewInvitation(code: code) } }
                    .buttonStyle(.viadere(.primary)).disabled(!InvitationCodeInput.isComplete(code))
                Button("Cancel", action: onDone).buttonStyle(.viadere(.quiet))
            }
        case .loadingPreview:
            HStack(spacing: ViadereSpace.s) { ViadereLoading(height: 22); Text("Checking…").font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary) }
                .frame(maxWidth: .infinity, minHeight: 52)
        case .preview:
            VStack(spacing: ViadereSpace.xs) {
                Button("Accept") { Task { await vm.acceptInvitation(code: code) } }.buttonStyle(.viadere(.primary))
                Button("Decline", action: onDone).buttonStyle(.viadere(.quiet))
            }
        case .accepting:
            HStack(spacing: ViadereSpace.s) { ViadereLoading(height: 22); Text("Accepting…").font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary) }
                .frame(maxWidth: .infinity, minHeight: 52)
        case .accepted:
            Button("Done", action: onDone).buttonStyle(.viadere(.primary))
        }
    }
}

// MARK: - Audit trail

struct HouseholdAuditView: View {
    let vm: HouseholdViewModel

    var body: some View {
        SubScreen(title: "Household activity", subtitle: "Everything done with shared access, and anything that was blocked.", backTitle: "Household") {
            switch vm.auditPhase {
            case .idle, .loading:
                ViadereLoading().frame(maxWidth: .infinity).padding(.top, ViadereSpace.l)
            case .unavailable:
                ViadereEmptyState("Not available yet", message: "Household activity will appear here.")
            case .failed(let message):
                ViadereNotice(message, kind: .warning)
            case .loaded:
                if vm.audit.isEmpty {
                    ViadereEmptyState("Nothing yet", message: "When someone uses shared access, it's recorded here.")
                } else {
                    ViadereRowGroup {
                        ForEach(Array(vm.audit.enumerated()), id: \.element.id) { index, entry in
                            ViadereRow(DelegationScopePolicy.auditTitle(entry),
                                       subtitle: entry.occurredAt.formatted(date: .abbreviated, time: .shortened),
                                       leading: { ViadereIconTile(systemName: entry.onBehalfOfName != nil ? "person.2" : "person") },
                                       trailing: { entry.outcome == .denied ? AnyView(ViadereBadge("Blocked", kind: .danger)) : AnyView(EmptyView()) })
                            if index < vm.audit.count - 1 { ViadereHairline(inset: 50) }
                        }
                    }
                }
            }
        }
        .task { await vm.loadAudit() }
        .refreshable { await vm.loadAudit() }
    }
}

#if DEBUG
#Preview("Household") {
    PreviewHost { services in
        NavigationStack { HouseholdView(vm: HouseholdViewModel(services: services)) }
    }
}

#Preview("Household · invite") {
    PreviewHost { services in
        InvitePreview(services: services)
    }
}

#Preview("Household · accept") {
    PreviewHost { services in
        AcceptInviteSheet(vm: HouseholdViewModel(services: services)) {}
    }
}

#Preview("Household · activity") {
    PreviewHost { services in
        NavigationStack { HouseholdAuditView(vm: HouseholdViewModel(services: services)) }
    }
}

private struct InvitePreview: View {
    let services: ViadereServices
    @State private var vm: HouseholdViewModel

    init(services: ViadereServices) {
        self.services = services
        _vm = State(initialValue: HouseholdViewModel(services: services))
    }

    var body: some View {
        HouseholdInviteSheet(vm: vm) {}
            .task {
                await vm.load()
                vm.togglePurpose(.security)
            }
    }
}
#endif
