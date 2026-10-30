import SwiftUI
import ViadereCore
import ViadereKit

/// Benefits (spec C6): coupons, rewards, loyalty and Wallet passes in their own destination, filtered by the business context and by
/// available / saved / eligible / redeemed / expired. Expiry and terms are on every row; eligibility is always the server's verdict.
struct BenefitsView: View {
    @Bindable var model: AppModel
    @State private var selection: RewardSelection?

    private var benefits: BenefitsViewModel { model.benefits }
    private var context: OrganizationContext { model.organization.effective }

    private static let filters: [(BenefitFilter?, String)] = [(.available, "Available"), (.saved, "Saved"), (.eligible, "Ready now"),
                                                             (.redeemed, "Used"), (.expired, "Expired")]

    var body: some View {
        NavigationStack {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    OrganizationContextHeader(model: model)
                    ViadereHeader("Benefits", subtitle: model.organization.selectedBusiness.map { "Coupons and rewards from \($0.safeName)" } ?? "Coupons, rewards and passes")
                    ViadereFilterBar("Benefit filters", selection: Binding(get: { benefits.filter }, set: { benefits.filter = $0 }),
                                     options: Self.filters.map { ViadereFilterBar<BenefitFilter?>.Option($0.0, $0.1, count: benefits.count($0.0, context: context)) })
                    content
                }
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.bottom, ViadereSpace.xl)
            }
            .scrollIndicators(.hidden)
            .viadereScreenBackground()
            .toolbar(.hidden, for: .navigationBar)
            .task {
                await benefits.load()
                await model.rewards.load()
            }
            .refreshable {
                await benefits.load()
                await model.rewards.load()
            }
            .sheet(item: $selection) { selected in
                RewardDetailSheet(
                    entryId: selected.id, lookup: { model.rewards.entry($0) }, presentation: { model.rewards.presentation(for: $0) },
                    message: model.rewards.message, busy: model.rewards.busyRewardId != nil, wallet: model.wallet,
                    onClaim: { await model.rewards.claim($0); await benefits.load() }, makeRedemption: { model.rewards.redemption(for: $0) },
                    onRefresh: { await model.rewards.load(); await benefits.load() })
                    .presentationDetents([.large])
                    .presentationDragIndicator(.hidden)
                    .presentationCornerRadius(ViadereRadius.sheet)
                    .presentationBackground(ViadereColor.background)
            }
        }
    }

    @ViewBuilder private var content: some View {
        let rewards = benefits.rewards(context: context)
        let accounts = benefits.accounts(context: context)
        if benefits.isLoading {
            ViadereLoading().frame(maxWidth: .infinity).padding(.top, ViadereSpace.xxl)
        } else if model.businesses.hasLoaded && model.businesses.active.isEmpty {
            ViadereEmptyState("No businesses yet", message: "Coupons and rewards from the businesses you connect to appear here.",
                              actionTitle: "Add a business") { model.addBusinessPresented = true }
                .padding(.top, ViadereSpace.xl)
        } else if rewards.isEmpty && accounts.isEmpty {
            ViadereEmptyState(emptyTitle, message: emptyMessage).padding(.top, ViadereSpace.xl)
        } else {
            if !accounts.isEmpty, benefits.filter == .available || benefits.filter == nil {
                ViadereSectionHeader("Memberships")
                VStack(spacing: ViadereSpace.s) {
                    ForEach(accounts) { account in
                        NavigationLink {
                            BusinessRewardsView(business: account.business, model: model)
                        } label: {
                            LoyaltyAccountCard(account: account)
                        }
                        .buttonStyle(.plain)
                    }
                }
            }
            if !rewards.isEmpty {
                ViadereSectionHeader(sectionTitle)
                ViadereRowGroup {
                    ForEach(Array(rewards.enumerated()), id: \.element.id) { index, entry in
                        Button { selection = RewardSelection(id: entry.id) } label: {
                            RewardRow(entry: entry, presentation: model.rewards.presentation(for: entry), showsBusiness: context == .all)
                        }
                        .buttonStyle(.plain)
                        if index < rewards.count - 1 { ViadereHairline(inset: 50) }
                    }
                }
            }
            Text("Eligibility is decided by each business and checked again when you use a reward.")
                .font(ViadereType.footnote)
                .foregroundStyle(ViadereColor.textTertiary)
                .padding(.top, ViadereSpace.s)
        }
        if let error = benefits.errorMessage {
            ViadereNotice(error, kind: .warning).padding(.top, ViadereSpace.m)
        }
    }

    private var sectionTitle: String { Self.filters.first { $0.0 == benefits.filter }?.1 ?? "Rewards" }

    private var emptyTitle: String {
        switch benefits.filter {
        case .saved?: "Nothing saved"
        case .redeemed?: "Nothing used yet"
        case .expired?: "Nothing expired"
        case .eligible?: "Nothing ready right now"
        default: model.organization.selectedBusiness.map { "No offers from \($0.safeName)" } ?? "No offers yet"
        }
    }

    private var emptyMessage: String {
        model.organization.selectedBusiness == nil
            ? "When a business you're connected to offers a coupon or a reward, it appears here."
            : "This business hasn't offered anything yet. Offers appear here when it does."
    }
}

#if DEBUG
#Preview("Benefits") {
    PreviewHost { services in
        BenefitsView(model: AppModel(services: services, walletLibrary: MockWalletLibrary()))
    }
}
#endif
