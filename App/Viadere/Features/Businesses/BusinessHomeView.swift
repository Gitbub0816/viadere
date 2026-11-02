import SwiftUI
import ViadereCore
import ViadereKit

/// A business home (spec C3, C6.2; WP-1.6, WP-2.6): Viadere's standard modules in the order the business chose, always starting with the
/// verified profile. The page renders at once in Viadere's neutral style with the default order, then adopts the business's order and its
/// verified Brand Kit when they arrive; nothing waits for either. An approved kit themes the business's whole space (owner decision):
/// the header band in the kit's color with the hash-checked logo, the brand-tinted page and cards, accents and the business's own actions,
/// all re-resolved over the person's appearance theme (`BrandStyle`). The name, verified badge and handle, wording, navigation and every
/// security surface (approvals, verification requests) stay Viadere's (`.viadereProtectedSurface()`). Modules with nothing to show are
/// left out rather than drawn as empty placeholders (C8.3).
struct BusinessHomeView: View {
    let entry: ConnectedBusiness
    let model: AppModel
    @State private var home: BusinessHomeViewModel
    @State private var decoration: BusinessHomeDecoration
    @State private var loops: LoopCatalogViewModel
    @State private var rewards: BusinessRewardsViewModel
    @Environment(\.dismiss) private var dismiss

    init(entry: ConnectedBusiness, model: AppModel) {
        self.entry = entry
        self.model = model
        _home = State(initialValue: BusinessHomeViewModel(business: entry.business, api: model.services.organizationAPI))
        _rewards = State(initialValue: BusinessRewardsViewModel(business: entry.business, services: model.services))
        _loops = State(initialValue: BusinessLoopsSection.makeCatalog(business: entry.business, model: model))
        // From the verified local cache only: instant, and neutral when there is nothing verified.
        _decoration = State(initialValue: BusinessHomeDecoration.make(business: entry.business, brand: model.services.brandKits))
    }

    private var brand: BrandStyle { BrandStyle(decoration.style) }

    private var business: BusinessSummary { entry.business }
    private var scope: OrganizationContext { .business(business.id) }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: ViadereSpace.l) {
                ViadereBackButton("Businesses") { dismiss() }
                ForEach(home.modules, id: \.module) { module in
                    moduleView(module.module)
                }
                if !home.modules.contains(where: { $0.module == "loops" }) {
                    BusinessLoopsSection(business: business, model: model, catalog: loops)
                }
                ViadereRowGroup {
                    NavigationLink {
                        BusinessDetailView(relationship: entry.relationship, model: model)
                    } label: {
                        ViadereRow("Settings for \(business.safeName)", subtitle: "Notifications, permissions, block or disconnect",
                                   leading: { ViadereIconTile(systemName: "slider.horizontal.3") })
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, ViadereSpace.screen)
            .padding(.bottom, ViadereSpace.xl)
        }
        .scrollIndicators(.hidden)
        .viadereScreenBackground()
        .environment(\.brandStyle, brand)
        .toolbar(.hidden, for: .navigationBar)
        .task {
            await home.load()
            await model.alerts.ensureLoaded(scope)
        }
        // The page loads the Loop list (the section is empty until it has loaded, so it cannot start its own task); again when consent changes.
        .task(id: model.loopConsent.status) { await loops.load() }
        .task { await rewards.load() }
        .task {
            // Separate task: branding never delays the page or its modules.
            guard let store = model.services.brandKits, business.isVerified else { return }
            await store.refresh(business.id)
            decoration = BusinessHomeDecoration.make(business: business, brand: store)
        }
    }

    @ViewBuilder private func moduleView(_ id: String) -> some View {
        switch id {
        case "profile": profile
        case "message": message
        case "approvals": requests(title: "Waiting for you", matching: { $0.category == .approval || ($0.category == .request) })
            .viadereProtectedSurface()
        case "verification_requests": requests(title: "Verification requests", matching: { $0.category == .verification })
            .viadereProtectedSurface()
        case "offers": offers
        case "rewards": BusinessRewardsEntry(business: business, model: model, vm: rewards)
        case "recent_activity": recentActivity
        case "loops": BusinessLoopsSection(business: business, model: model, catalog: loops)
        default: EmptyView()
        }
    }

    // MARK: Modules

    private var profile: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.m) {
            brandBand
            VStack(alignment: .leading, spacing: ViadereSpace.xs) {
                Text(business.safeName)
                    .font(ViadereType.display)
                    .foregroundStyle(ViadereColor.textPrimary)
                    .accessibilityAddTraits(.isHeader)
                HStack(spacing: ViadereSpace.xs) {
                    ViadereBadge(business.isVerified ? "Verified business" : "Not verified", kind: business.isVerified ? .verified : .danger)
                    if let category = entry.category?.rawValue, category != "other" {
                        ViadereBadge(category.replacingOccurrences(of: "_", with: " ").capitalized)
                    }
                }
                Text(business.handle?.display ?? business.code.display)
                    .font(ViadereType.subhead)
                    .foregroundStyle(ViadereColor.textSecondary)
            }
        }
        .accessibilityElement(children: .combine)
    }

    /// The header band in the kit's primary color (`BusinessHomeDecoration.headerBand`), holding the verified logo or, without one, the
    /// business's monogram in the band's own ink. Decoration only: the identity below is drawn in the theme's protected colors.
    @ViewBuilder private var brandBand: some View {
        if brand.isBranded {
            let shape = RoundedRectangle(cornerRadius: brand.cornerRadius, style: .continuous)
            HStack(spacing: ViadereSpace.m) {
                if decoration.logo != nil {
                    BrandLogo(data: decoration.logo, name: business.safeName, isVerified: business.isVerified, size: 72,
                              accessibilityLabel: decoration.logoAccessibilityLabel)
                } else {
                    BrandMonogram(name: business.safeName, ink: brand.onPrimary, size: 72)
                }
                Spacer(minLength: 0)
            }
            .padding(ViadereSpace.l)
            .frame(maxWidth: .infinity, minHeight: 120, alignment: .leading)
            .background(shape.fill(brand.primary))
            .overlay(shape.strokeBorder(brand.accent, lineWidth: brand.borderWidth))
            .brandFrameBackground(brand)
            .accessibilityHidden(decoration.logo == nil)
        } else {
            ViadereAvatar(name: business.safeName, size: 72, isVerified: business.isVerified)
        }
    }

    private var message: some View {
        Button {
            Task {
                if await model.messages.start(with: business.id) != nil { model.selectedTab = .messages }
            }
        } label: {
            HStack(spacing: ViadereSpace.xs) {
                Image(systemName: "bubble.left")
                Text("Message \(business.safeName)")
            }
        }
        // The business's own action: its brand fill in a branded space, Viadere's secondary button otherwise.
        .buttonStyle(.brand(brand))
    }

    @ViewBuilder private func requests(title: String, matching: (AlertEntry) -> Bool) -> some View {
        let items = model.alerts.needsYou(context: scope).filter(matching)
        if !items.isEmpty {
            VStack(alignment: .leading, spacing: ViadereSpace.s) {
                ViadereSectionHeader(title)
                ForEach(items) { item in
                    AlertCard(entry: item, canAct: model.alerts.canAct(item), now: model.services.clock()) {
                        Task { await AlertOpener.open(item, model: model) }
                    }
                }
            }
        }
    }

    @ViewBuilder private var offers: some View {
        let offers = model.benefits.overview.rewards.filter { $0.business.id == business.id && BenefitRules.matches($0, filter: .available) }
        if !offers.isEmpty {
            VStack(alignment: .leading, spacing: 0) {
                ViadereSectionHeader("Offers")
                ViadereRowGroup {
                    ForEach(Array(BenefitRules.sorted(offers).prefix(5).enumerated()), id: \.element.id) { index, entry in
                        RewardRow(entry: entry, presentation: model.rewards.presentation(for: entry))
                        if index < min(offers.count, 5) - 1 { ViadereHairline(inset: 50) }
                    }
                }
            }
        }
    }

    @ViewBuilder private var recentActivity: some View {
        let items = Array(model.alerts.history(context: scope).prefix(5))
        if !items.isEmpty {
            VStack(alignment: .leading, spacing: 0) {
                ViadereSectionHeader("Recent activity")
                ViadereRowGroup {
                    ForEach(Array(items.enumerated()), id: \.element.id) { index, item in
                        AlertHistoryRow(entry: item, status: model.alerts.displayStatus(item), now: model.services.clock())
                        if index < items.count - 1 { ViadereHairline(inset: 50) }
                    }
                }
            }
        }
    }
}
