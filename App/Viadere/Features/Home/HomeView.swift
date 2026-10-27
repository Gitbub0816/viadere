import SwiftUI
import ViadereCore
import ViadereKit

/// The calm home: what needs you first (and unmistakably), then what's in progress, then recent businesses.
struct HomeView: View {
    @Bindable var model: AppModel
    @State private var path = NavigationPath()

    private var home: HomeViewModel { model.home }

    var body: some View {
        NavigationStack(path: $path) {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    topBar
                    if home.content.isEmpty, home.phase != .loading {
                        ViadereEmptyState(
                            "You're all set",
                            message: "When a business needs you, it appears here. Usually you'll just get a notification.",
                            actionTitle: "Connect a business") { model.selectedTab = .connect }
                            .padding(.top, ViadereSpace.xxl)
                    } else {
                        pendingSection
                        statusSection
                        rewardsSection
                        recentSection
                    }
                    if case .failed(let message) = home.phase {
                        ViadereNotice(message, kind: .warning).padding(.top, ViadereSpace.l)
                    }
                }
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.bottom, ViadereSpace.xl)
            }
            .task {
                await home.load()
                await model.rewards.load()
            }
            .refreshable { await home.load() }
            .scrollIndicators(.hidden)
            .viadereScreenBackground()
            .toolbar(.hidden, for: .navigationBar)
            .navigationDestination(for: Relationship.self) { relationship in
                BusinessDetailView(relationship: relationship, model: model)
            }
            .navigationDestination(for: HomeRoute.self) { route in
                switch route {
                case .rewards: RewardsView(model: model)
                }
            }
        }
    }

    private var topBar: some View {
        HStack {
            ViadereLockup(.horizontal, ribbonHeight: 24)
            Spacer()
            ViadereIconButton(systemName: "plus", label: "Connect a business") { model.selectedTab = .connect }
        }
        .padding(.top, ViadereSpace.m)
        .padding(.bottom, ViadereSpace.s)
    }

    // MARK: Sections

    @ViewBuilder private var pendingSection: some View {
        if !home.content.pending.isEmpty {
            ViadereSectionHeader(home.content.pending.count == 1 ? "Needs you" : "Needs you · \(home.content.pending.count)")
            VStack(spacing: ViadereSpace.s) {
                ForEach(home.content.pending) { envelope in
                    PendingActionCard(envelope: envelope) {
                        Task { await model.openInteraction(envelope.id) }
                    }
                }
            }
        } else if !home.content.isEmpty {
            Text("Nothing needs you right now.")
                .font(ViadereType.body)
                .foregroundStyle(ViadereColor.textSecondary)
                .padding(.top, ViadereSpace.l)
        }
    }

    @ViewBuilder private var statusSection: some View {
        if !home.content.statuses.isEmpty {
            ViadereSectionHeader("In progress")
            ViadereRowGroup {
                ForEach(Array(home.content.statuses.enumerated()), id: \.element.id) { index, envelope in
                    StatusRow(envelope: envelope)
                    if index < home.content.statuses.count - 1 { ViadereHairline(inset: 50) }
                }
            }
        }
    }

    /// One quiet row; it only appears once the server has rewards to show.
    @ViewBuilder private var rewardsSection: some View {
        if model.rewards.phase == .loaded, !model.rewards.accounts.isEmpty || !model.rewards.overview.rewards.isEmpty {
            let ready = model.rewards.availableCount
            ViadereSectionHeader("Rewards")
            ViadereRowGroup {
                Button { path.append(HomeRoute.rewards) } label: {
                    ViadereRow("Rewards", subtitle: ready == 0 ? "Points, perks and offers" : (ready == 1 ? "1 ready to use" : "\(ready) ready to use"),
                               leading: { ViadereIconTile(systemName: "star") })
                }
                .buttonStyle(.plain)
            }
        }
    }

    @ViewBuilder private var recentSection: some View {
        if !home.content.recent.isEmpty {
            ViadereSectionHeader("Your businesses", actionTitle: "Add") { model.selectedTab = .connect }
            ViadereRowGroup {
                ForEach(Array(home.content.recent.enumerated()), id: \.element.id) { index, relationship in
                    Button {
                        path.append(relationship)
                    } label: {
                        ViadereRow(relationship.business.safeName,
                                   subtitle: relationship.business.handle?.display ?? relationship.business.code.display) {
                            ViadereAvatar(name: relationship.business.safeName, size: 36, isVerified: relationship.business.isVerified)
                        }
                    }
                    .buttonStyle(.plain)
                    if index < home.content.recent.count - 1 { ViadereHairline(inset: 50) }
                }
            }
        }
    }
}

enum HomeRoute: Hashable { case rewards }

/// A request waiting on the person. Prominent by design: champagne edge, large headline, live countdown.
struct PendingActionCard: View {
    let envelope: InteractionEnvelope
    let action: () -> Void

    var body: some View {
        Button(action: action) {
            VStack(alignment: .leading, spacing: ViadereSpace.s) {
                HStack(spacing: ViadereSpace.s) {
                    ViadereAvatar(name: envelope.business.safeName, size: 36, isVerified: envelope.business.isVerified)
                    VStack(alignment: .leading, spacing: 0) {
                        Text(envelope.business.safeName)
                            .font(ViadereType.subhead.weight(.medium))
                            .foregroundStyle(ViadereColor.textPrimary)
                        Text(InteractionPresentation.kindLabel(envelope.interaction))
                            .font(ViadereType.footnote)
                            .foregroundStyle(ViadereColor.textSecondary)
                    }
                    Spacer()
                    TimelineView(.periodic(from: .now, by: 1)) { context in
                        Text(InteractionPresentation.countdown(until: envelope.interaction.expiresAt, now: context.date))
                            .font(ViadereType.caption)
                            .monospacedDigit()
                            .foregroundStyle(ViadereColor.accent)
                    }
                }
                Text(InteractionPresentation.headline(envelope.interaction))
                    .font(ViadereType.title)
                    .foregroundStyle(ViadereColor.textPrimary)
                    .multilineTextAlignment(.leading)
                    .fixedSize(horizontal: false, vertical: true)
                HStack {
                    Text(envelope.interaction.kind.isSecuritySensitive ? "Review" : "Respond")
                        .font(ViadereType.subhead.weight(.semibold))
                    Image(systemName: "arrow.right").font(.system(size: 13, weight: .semibold))
                }
                .foregroundStyle(ViadereColor.accent)
            }
            .padding(ViadereSpace.l)
            .frame(maxWidth: .infinity, alignment: .leading)
            .viadereSurface()
            .overlay(alignment: .leading) {
                Capsule().fill(ViadereColor.accent).frame(width: 3).padding(.vertical, ViadereSpace.l)
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
        .accessibilityHint(Text("Opens the request"))
    }
}

struct StatusRow: View {
    let envelope: InteractionEnvelope

    private var subtitle: String {
        if case .status(let payload) = envelope.interaction.payload, let body = UntrustedText.optionalLine(payload.body, max: 120) { return body }
        return envelope.business.safeName
    }

    var body: some View {
        ViadereRow(InteractionPresentation.headline(envelope.interaction), subtitle: subtitle,
                   leading: { ViadereAvatar(name: envelope.business.safeName, size: 36) },
                   trailing: { EmptyView() })
    }
}

#if DEBUG
#Preview("Home") {
    PreviewHost { services in
        HomeView(model: AppModel(services: services, walletLibrary: MockWalletLibrary()))
    }
}
#endif
