import SwiftUI
import ViadereCore
import ViadereKit

/// Identifies the reward whose detail sheet is open.
struct RewardSelection: Identifiable, Hashable {
    let id: RewardID
}

// MARK: - Aggregated rewards

/// Points and status first, then every reward across businesses, ordered by what the **server** says is usable.
struct RewardsView: View {
    let model: AppModel
    @State private var selection: RewardSelection?

    private var vm: RewardsViewModel { model.rewards }

    var body: some View {
        SubScreen(title: "Rewards", subtitle: "Points, perks and offers from your businesses", backTitle: "Home") {
            switch vm.phase {
            case .unavailable:
                ViadereEmptyState("Rewards are coming soon", message: "Your businesses haven't turned on rewards in Viadere yet.")
            case .failed(let message):
                ViadereNotice(message, kind: .warning)
                content
            default:
                content
            }
        }
        .task { await vm.load() }
        .refreshable { await vm.load() }
        .sheet(item: $selection) { selected in
            RewardDetailSheet(
                entryId: selected.id, lookup: { vm.entry($0) }, presentation: { vm.presentation(for: $0) },
                message: vm.message, busy: vm.busyRewardId != nil, wallet: model.wallet,
                onClaim: { await vm.claim($0) }, makeRedemption: { vm.redemption(for: $0) }, onRefresh: { await vm.load() })
                .presentationDetents([.large])
                .presentationDragIndicator(.hidden)
                .presentationCornerRadius(ViadereRadius.sheet)
                .presentationBackground(ViadereColor.background)
        }
    }

    @ViewBuilder private var content: some View {
        if vm.phase == .loading {
            ViadereLoading().frame(maxWidth: .infinity).padding(.top, ViadereSpace.xxl)
        } else if vm.accounts.isEmpty, vm.overview.rewards.isEmpty, vm.phase == .loaded {
            ViadereEmptyState("No rewards yet", message: "Join a business's program from its page and your points and perks show up here.")
        } else {
            if !vm.accounts.isEmpty {
                ViadereSectionHeader("Your memberships")
                VStack(spacing: ViadereSpace.s) {
                    ForEach(vm.accounts) { account in
                        NavigationLink {
                            BusinessRewardsView(business: account.business, model: model)
                        } label: {
                            LoyaltyAccountCard(account: account)
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
            ForEach(vm.sections) { section in
                ViadereSectionHeader(section.title)
                ViadereRowGroup {
                    ForEach(Array(section.entries.enumerated()), id: \.element.id) { index, entry in
                        Button { selection = RewardSelection(id: entry.id) } label: {
                            RewardRow(entry: entry, presentation: vm.presentation(for: entry), showsBusiness: true)
                        }
                        .buttonStyle(.plain)
                        if index < section.entries.count - 1 { ViadereHairline(inset: 50) }
                    }
                }
            }
            Text("Eligibility is decided by each business and checked again when you use a reward.")
                .font(ViadereType.footnote)
                .foregroundStyle(ViadereColor.textTertiary)
                .padding(.top, ViadereSpace.s)
        }
    }
}

// MARK: - Pieces

/// Points, status and progress for one membership.
struct LoyaltyAccountCard: View {
    let account: LoyaltyAccount

    private var progress: Double? {
        guard let toNext = account.pointsToNextStatus, toNext > 0 else { return nil }
        let total = Double(account.pointsBalance + toNext)
        return total > 0 ? Double(account.pointsBalance) / total : nil
    }

    var body: some View {
        ViadereCard(padding: ViadereSpace.l) {
            VStack(alignment: .leading, spacing: ViadereSpace.m) {
                HStack(spacing: ViadereSpace.s) {
                    ViadereAvatar(name: account.business.safeName, size: 36, isVerified: account.business.isVerified)
                    VStack(alignment: .leading, spacing: 0) {
                        Text(account.business.safeName)
                            .font(ViadereType.subhead.weight(.medium))
                            .foregroundStyle(ViadereColor.textPrimary)
                        Text(account.programName)
                            .font(ViadereType.footnote)
                            .foregroundStyle(ViadereColor.textSecondary)
                    }
                    Spacer()
                    if let status = account.statusName { ViadereBadge(status, kind: .verified) }
                }
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Text(account.pointsBalance.formatted(.number.grouping(.automatic)))
                        .font(ViadereType.display)
                        .foregroundStyle(ViadereColor.textPrimary)
                        .monospacedDigit()
                    Text("points").font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
                    Spacer()
                    ViadereChevron()
                }
                if let progress, let toNext = account.pointsToNextStatus {
                    VStack(alignment: .leading, spacing: ViadereSpace.xs) {
                        ViadereProgressBar(progress: progress, label: "Progress to \(account.nextStatusName ?? "next status")")
                        Text("\(RewardCopy.points(toNext)) to \(account.nextStatusName ?? "the next level")")
                            .font(ViadereType.footnote)
                            .foregroundStyle(ViadereColor.textSecondary)
                    }
                }
            }
        }
        .accessibilityElement(children: .combine)
    }
}

extension RewardKind {
    var symbol: String {
        switch self {
        case .coupon: "tag"
        case .perk: "star"
        case .offer: "gift"
        case .pointsReward: "sparkles"
        }
    }

    var title: String {
        switch self {
        case .coupon: "Coupon"
        case .perk: "Perk"
        case .offer: "Offer"
        case .pointsReward: "Points reward"
        }
    }
}

struct RewardRow: View {
    let entry: RewardEntry
    let presentation: RewardRowPresentation
    var showsBusiness = false

    private var subtitle: String {
        var parts: [String] = []
        if showsBusiness { parts.append(entry.business.safeName) }
        if let recurrence = entry.reward.recurrence { let text = RewardCopy.recurrence(recurrence); if !text.isEmpty { parts.append(text) } }
        parts.append(presentation.statusLine)
        return parts.joined(separator: " · ")
    }

    var body: some View {
        ViadereRow(entry.reward.title, subtitle: subtitle,
                   leading: { ViadereIconTile(systemName: entry.kind.symbol) },
                   trailing: { trailing })
    }

    @ViewBuilder private var trailing: some View {
        if presentation.tone == .available, let title = presentation.actionTitle {
            ViadereBadge(title == "Claim" ? "Claim" : "Ready", kind: .verified)
        } else {
            ViadereChevron()
        }
    }
}

// MARK: - Reward detail

/// One reward: what it is, the server's verdict, and the one action the server allows.
struct RewardDetailSheet: View {
    let entryId: RewardID
    let lookup: (RewardID) -> RewardEntry?
    let presentation: (RewardEntry) -> RewardRowPresentation
    let message: String?
    let busy: Bool
    let wallet: WalletPassCoordinator
    let onClaim: (RewardEntry) async -> Void
    let makeRedemption: (RewardEntry) -> RedemptionViewModel
    let onRefresh: () async -> Void
    @State private var redemption: RedemptionViewModel?
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        Group {
            if let redemption {
                RedemptionView(model: redemption) {
                    self.redemption = nil
                    Task { await onRefresh() }
                }
            } else if let entry = lookup(entryId) {
                detail(entry)
            } else {
                VStack { ViadereGrabber(); Spacer(); ViadereLoading(); Spacer() }
            }
        }
        .background(ViadereColor.background)
        .task { await onRefresh() }
    }

    private func detail(_ entry: RewardEntry) -> some View {
        let p = presentation(entry)
        return VStack(spacing: 0) {
            ViadereGrabber()
            ScrollView {
                VStack(alignment: .leading, spacing: ViadereSpace.l) {
                    HStack(spacing: ViadereSpace.s) {
                        ViadereAvatar(name: entry.business.safeName, size: 48, isVerified: entry.business.isVerified)
                        VStack(alignment: .leading, spacing: 4) {
                            Text(entry.business.safeName).font(ViadereType.headline).foregroundStyle(ViadereColor.textPrimary)
                            HStack(spacing: ViadereSpace.xs) {
                                if entry.business.isVerified { ViadereBadge("Verified", kind: .verified) }
                                Text(entry.kind.title).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                            }
                        }
                        Spacer(minLength: 0)
                    }
                    VStack(alignment: .leading, spacing: ViadereSpace.xs) {
                        Text(entry.reward.title)
                            .font(ViadereType.display)
                            .foregroundStyle(ViadereColor.textPrimary)
                            .fixedSize(horizontal: false, vertical: true)
                            .accessibilityAddTraits(.isHeader)
                        if let details = entry.reward.details {
                            Text(details).font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
                        }
                    }
                    statusLine(p)
                    facts(entry)
                    if let pass = entry.reward.walletPass { WalletPassAction(pass: pass, wallet: wallet) }
                    if let message { ViadereNotice(message, kind: message.hasPrefix("Claimed") ? .info : .warning) }
                    Text("Viadere never decides who qualifies. \(entry.business.safeName) does, and it's checked again when you use this.")
                        .font(ViadereType.footnote)
                        .foregroundStyle(ViadereColor.textTertiary)
                }
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.top, ViadereSpace.m)
                .padding(.bottom, ViadereSpace.l)
            }
            .scrollIndicators(.hidden)
            footer(entry, p)
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.top, ViadereSpace.s)
                .padding(.bottom, ViadereSpace.m)
        }
    }

    private func statusLine(_ p: RewardRowPresentation) -> some View {
        HStack(spacing: ViadereSpace.xs) {
            Circle()
                .fill(p.tone == .available ? ViadereColor.success : (p.tone == .waiting ? ViadereColor.accent : ViadereColor.textTertiary))
                .frame(width: 8, height: 8)
            Text(p.statusLine).font(ViadereType.subhead.weight(.medium)).foregroundStyle(ViadereColor.textPrimary)
        }
        .accessibilityElement(children: .combine)
    }

    private func facts(_ entry: RewardEntry) -> some View {
        ViadereRowGroup {
            if let recurrence = entry.reward.recurrence, !RewardCopy.recurrence(recurrence).isEmpty {
                ViadereValueRow("Repeats", RewardCopy.recurrence(recurrence))
                ViadereHairline()
            }
            if let cost = entry.pointsCost {
                ViadereValueRow("Costs", RewardCopy.points(cost))
                ViadereHairline()
            }
            if let until = entry.reward.validUntil {
                ViadereValueRow("Valid until", until.formatted(date: .abbreviated, time: .omitted))
                ViadereHairline()
            }
            ViadereValueRow("From", entry.business.safeName)
        }
    }

    @ViewBuilder private func footer(_ entry: RewardEntry, _ p: RewardRowPresentation) -> some View {
        if busy {
            HStack(spacing: ViadereSpace.s) {
                ViadereLoading(height: 22)
                Text("Checking with \(entry.business.safeName)…").font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
            }
            .frame(maxWidth: .infinity, minHeight: 52)
        } else if p.needsRefresh, p.tone == .available {
            HStack(spacing: ViadereSpace.s) {
                ViadereLoading(height: 22)
                Text("Checking it's still available…").font(ViadereType.subhead).foregroundStyle(ViadereColor.textSecondary)
            }
            .frame(maxWidth: .infinity, minHeight: 52)
        } else if let title = p.actionTitle {
            VStack(spacing: ViadereSpace.xs) {
                Button(title) {
                    switch p.action {
                    case .claim: Task { await onClaim(entry) }
                    case .redeem: redemption = makeRedemption(entry)
                    case .none: break
                    }
                }
                .buttonStyle(.viadere(.primary))
                Button("Not now") { dismiss() }.buttonStyle(.viadere(.quiet))
            }
        } else {
            Button("Close") { dismiss() }.buttonStyle(.viadere(.secondary))
        }
    }
}

#if DEBUG
#Preview("Rewards") {
    PreviewHost { services in
        NavigationStack { RewardsView(model: AppModel(services: services, walletLibrary: MockWalletLibrary())) }
    }
}

#Preview("Reward · free coffee on Tuesdays") {
    PreviewHost { services in
        RewardDetailPreview(services: services, title: "Free coffee on Tuesdays")
    }
}

#Preview("Reward · points shortfall") {
    PreviewHost { services in
        RewardDetailPreview(services: services, title: "Free bag of beans")
    }
}

private struct RewardDetailPreview: View {
    let services: ViadereServices
    let title: String
    @State private var model: AppModel?

    var body: some View {
        Group {
            if let model, let entry = model.rewards.overview.rewards.first(where: { $0.reward.title == title }) {
                RewardDetailSheet(
                    entryId: entry.id, lookup: { model.rewards.entry($0) }, presentation: { model.rewards.presentation(for: $0) },
                    message: nil, busy: false, wallet: model.wallet, onClaim: { await model.rewards.claim($0) },
                    makeRedemption: { model.rewards.redemption(for: $0) }, onRefresh: {})
            } else {
                ViadereLoading()
            }
        }
        .task {
            let created = AppModel(services: services, walletLibrary: MockWalletLibrary())
            await created.rewards.load()
            model = created
        }
    }
}
#endif
