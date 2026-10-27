import SwiftUI
import ViadereCore
import ViadereKit

/// One business's program: membership (points, status, Wallet card) and its rewards.
struct BusinessRewardsView: View {
    let business: BusinessSummary
    let model: AppModel
    @State private var vm: BusinessRewardsViewModel
    @State private var selection: RewardSelection?
    @State private var joining = false

    init(business: BusinessSummary, model: AppModel) {
        self.business = business
        self.model = model
        _vm = State(initialValue: BusinessRewardsViewModel(business: business, services: model.services))
    }

    var body: some View {
        SubScreen(title: vm.program?.programName ?? "Rewards", subtitle: business.displayName, backTitle: "Back") {
            switch vm.phase {
            case .idle, .loading:
                ViadereLoading().frame(maxWidth: .infinity).padding(.top, ViadereSpace.xxl)
            case .noProgram:
                ViadereEmptyState("No rewards program", message: "\(business.displayName) doesn't offer a rewards program in Viadere.")
            case .failed(let message):
                ViadereNotice(message, kind: .warning)
            case .loaded:
                loaded
            }
        }
        .task { await vm.load() }
        .refreshable { await vm.load() }
        .sheet(isPresented: $joining) {
            LoyaltyEnrollSheet(vm: vm) { joining = false }
                .presentationDetents([.large])
                .presentationDragIndicator(.hidden)
                .presentationCornerRadius(ViadereRadius.sheet)
                .presentationBackground(ViadereColor.background)
        }
        .sheet(item: $selection) { selected in
            RewardDetailSheet(
                entryId: selected.id, lookup: { id in vm.rewards.first { $0.id == id } }, presentation: { vm.presentation(for: $0) },
                message: vm.message, busy: vm.busyRewardId != nil, wallet: model.wallet,
                onClaim: { await vm.claim($0) }, makeRedemption: { vm.redemption(for: $0) }, onRefresh: { await vm.load() })
                .presentationDetents([.large])
                .presentationDragIndicator(.hidden)
                .presentationCornerRadius(ViadereRadius.sheet)
                .presentationBackground(ViadereColor.background)
        }
    }

    @ViewBuilder private var loaded: some View {
        if let account = vm.account {
            LoyaltyAccountCard(account: account)
            walletCard(account)
            if let reference = account.memberReference {
                ViadereRowGroup {
                    ViadereValueRow("Member", reference)
                    ViadereHairline()
                    ViadereValueRow("Since", account.memberSince.formatted(date: .abbreviated, time: .omitted))
                }
            }
        } else if let program = vm.program {
            joinCard(program)
        }
        let sections = RewardSection.build(vm.rewards, presentation: vm.presentation(for:))
        ForEach(sections) { section in
            ViadereSectionHeader(section.title)
            ViadereRowGroup {
                ForEach(Array(section.entries.enumerated()), id: \.element.id) { index, entry in
                    Button { selection = RewardSelection(id: entry.id) } label: {
                        RewardRow(entry: entry, presentation: vm.presentation(for: entry))
                    }
                    .buttonStyle(.plain)
                    if index < section.entries.count - 1 { ViadereHairline(inset: 50) }
                }
            }
        }
        if let message = vm.message { ViadereNotice(message, kind: .warning) }
    }

    @ViewBuilder private func walletCard(_ account: LoyaltyAccount) -> some View {
        if let pass = account.walletPass {
            WalletPassAction(pass: pass, wallet: model.wallet)
        } else if model.wallet.canAddPasses {
            Button {
                Task { await vm.issueLoyaltyCard() }
            } label: {
                HStack(spacing: ViadereSpace.xs) {
                    Image(systemName: "wallet.pass")
                    Text("Create a Wallet card")
                }
            }
            .buttonStyle(.viadere(.secondary))
        }
    }

    private func joinCard(_ program: LoyaltyProgramOverview) -> some View {
        ViadereCard(padding: ViadereSpace.l) {
            VStack(alignment: .leading, spacing: ViadereSpace.s) {
                Text("Join \(program.programName)").font(ViadereType.title).foregroundStyle(ViadereColor.textPrimary)
                Text(program.summary).font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
                Button("Join") { joining = true }.buttonStyle(.viadere(.primary)).padding(.top, ViadereSpace.xs)
            }
        }
    }
}

/// Business detail's compact rewards entry: either "Join" or the membership summary, opening the full screen.
struct BusinessRewardsEntry: View {
    let business: BusinessSummary
    let model: AppModel
    @State private var vm: BusinessRewardsViewModel
    @State private var joining = false

    init(business: BusinessSummary, model: AppModel) {
        self.business = business
        self.model = model
        _vm = State(initialValue: BusinessRewardsViewModel(business: business, services: model.services))
    }

    var body: some View {
        Group {
            if vm.phase == .loaded, let program = vm.program {
                VStack(alignment: .leading, spacing: 0) {
                    ViadereSectionHeader("Rewards")
                    ViadereRowGroup {
                        if let account = vm.account {
                            NavigationLink {
                                BusinessRewardsView(business: business, model: model)
                            } label: {
                                ViadereRow(program.programName, subtitle: summary(account),
                                           leading: { ViadereIconTile(systemName: "star") })
                            }
                            .buttonStyle(.plain)
                        } else {
                            Button { joining = true } label: {
                                ViadereRow("Join \(program.programName)", subtitle: program.summary,
                                           leading: { ViadereIconTile(systemName: "star") })
                            }
                            .buttonStyle(.plain)
                        }
                    }
                }
            }
        }
        .task { await vm.load() }
        .sheet(isPresented: $joining) {
            LoyaltyEnrollSheet(vm: vm) { joining = false }
                .presentationDetents([.large])
                .presentationDragIndicator(.hidden)
                .presentationCornerRadius(ViadereRadius.sheet)
                .presentationBackground(ViadereColor.background)
        }
    }

    private func summary(_ account: LoyaltyAccount) -> String {
        var parts = [RewardCopy.points(account.pointsBalance)]
        if let status = account.statusName { parts.append(status) }
        let ready = vm.rewards.filter { $0.eligibility.state == .eligible }.count
        if ready > 0 { parts.append("\(ready) ready") }
        return parts.joined(separator: " · ")
    }
}

/// Join a program, optionally linking an existing membership. The person sees which terms version they accept.
struct LoyaltyEnrollSheet: View {
    let vm: BusinessRewardsViewModel
    let onDone: () -> Void
    @State private var reference = ""
    @State private var linking = false

    private var isWorking: Bool { vm.enrollment == .enrolling }

    var body: some View {
        VStack(spacing: 0) {
            ViadereGrabber()
            ScrollView {
                VStack(alignment: .leading, spacing: ViadereSpace.l) {
                    HStack(spacing: ViadereSpace.s) {
                        ViadereAvatar(name: vm.business.displayName, size: 48, isVerified: vm.business.isVerified)
                        VStack(alignment: .leading, spacing: 2) {
                            Text(vm.business.displayName).font(ViadereType.headline).foregroundStyle(ViadereColor.textPrimary)
                            if vm.business.isVerified { ViadereBadge("Verified", kind: .verified) }
                        }
                    }
                    Text("Join \(vm.program?.programName ?? "the program")")
                        .font(ViadereType.display)
                        .foregroundStyle(ViadereColor.textPrimary)
                        .fixedSize(horizontal: false, vertical: true)
                    Text(vm.program?.summary ?? "")
                        .font(ViadereType.body)
                        .foregroundStyle(ViadereColor.textSecondary)
                    ViadereRowGroup {
                        ViadereValueRow("Shared with \(vm.business.displayName)", "Your name and visits")
                        ViadereHairline()
                        ViadereValueRow("Program terms", vm.program?.termsVersion ?? "")
                    }
                    if linking {
                        ViadereTextField("Existing member number", text: $reference, prompt: "Optional",
                                         message: "We'll ask \(vm.business.displayName) to link your existing points.")
                            .textInputAutocapitalization(.characters)
                            .autocorrectionDisabled()
                    } else {
                        Button("I already have a membership") { withAnimation(ViadereMotion.standard) { linking = true } }
                            .buttonStyle(.viadere(.quiet, fullWidth: false))
                    }
                    if case .failed(let message) = vm.enrollment { ViadereNotice(message, kind: .danger) }
                }
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.top, ViadereSpace.m)
            }
            .scrollIndicators(.hidden)
            VStack(spacing: ViadereSpace.xs) {
                Button(isWorking ? "Joining…" : "Join") {
                    Task { if await vm.enroll(existingMemberReference: linking ? reference : nil) { onDone() } }
                }
                .buttonStyle(.viadere(.primary))
                .disabled(isWorking)
                Button("Not now", action: onDone).buttonStyle(.viadere(.quiet))
            }
            .padding(.horizontal, ViadereSpace.screen)
            .padding(.top, ViadereSpace.s)
            .padding(.bottom, ViadereSpace.m)
        }
        .background(ViadereColor.background)
        .privacySensitive()
    }
}

#if DEBUG
#Preview("Business rewards · member") {
    PreviewHost { services in
        NavigationStack { BusinessRewardsView(business: PreviewData.juniperCoffee, model: AppModel(services: services, walletLibrary: MockWalletLibrary())) }
    }
}

#Preview("Business rewards · join") {
    PreviewHost { services in
        NavigationStack { BusinessRewardsView(business: PreviewData.lumenTheater, model: AppModel(services: services, walletLibrary: MockWalletLibrary())) }
    }
}
#endif
