import SwiftUI
import ViadereCore
import ViadereKit

/// Where the Businesses tab can go.
enum BusinessesRoute: Hashable {
    case business(BusinessID)
    case loopDirectory
    case yourLoops
}

/// Businesses (spec C2, C3, C8; docs/APP-IA.md): Discover (the Loop directory and Your Loops) when Loops are available, then one directory of
/// the customer's connections, favorites first, searchable on the device, with a prominent Add business. Fifty businesses are one list and a
/// search field, never fifty tabs. Opening a business shows its neutral Viadere home; it does not change the business context (only the
/// selector does). Ended connections can be unblocked or reconnected from here.
struct BusinessesView: View {
    @Bindable var model: AppModel
    @State private var path: [BusinessesRoute] = []
    @State private var unblocking: ConnectedBusiness? = nil

    private var directory: BusinessesViewModel { model.businesses }

    var body: some View {
        NavigationStack(path: $path) {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    OrganizationContextHeader(model: model)
                    ViadereHeader("Businesses", subtitle: subtitle) {
                        Button {
                            model.addBusinessPresented = true
                        } label: {
                            HStack(spacing: 6) {
                                Image(systemName: "plus")
                                Text("Add")
                            }
                        }
                        .buttonStyle(.viadere(.primary, fullWidth: false))
                        .accessibilityLabel(Text("Add business"))
                    }
                    if directory.directory.count > 3 {
                        ViadereSearchField("Search your businesses", text: Binding(get: { directory.query }, set: { directory.query = $0 }))
                            .padding(.bottom, ViadereSpace.s)
                    }
                    if directory.query.isEmpty { discover }
                    content
                }
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.bottom, ViadereSpace.xl)
            }
            .scrollIndicators(.hidden)
            .scrollDismissesKeyboard(.interactively)
            .viadereScreenBackground()
            .toolbar(.hidden, for: .navigationBar)
            .task { await directory.load() }
            .refreshable { await directory.load() }
            .navigationDestination(for: BusinessesRoute.self) { route in
                switch route {
                case .business(let id):
                    if let entry = directory.entry(id), entry.isActive {
                        BusinessHomeView(entry: entry, model: model)
                    } else {
                        SubScreen(title: "Not available", subtitle: "You're no longer connected to this business.", backTitle: "Businesses") { EmptyView() }
                    }
                case .loopDirectory: LoopDirectorySlot(model: model)
                case .yourLoops: YourLoopsSlot(model: model)
                }
            }
            .confirmationDialog(unblocking.map { "Unblock \($0.business.safeName)?" } ?? "Unblock?",
                                isPresented: Binding(get: { unblocking != nil }, set: { if !$0 { unblocking = nil } }), titleVisibility: .visible) {
                Button("Unblock") {
                    guard let entry = unblocking else { return }
                    Task { await directory.unblock(entry.business.id) }
                }
                Button("Cancel", role: .cancel) {}
            } message: {
                Text("It can connect to you again, but only if you choose to reconnect. Nothing is reconnected now.")
            }
            .task(id: model.businessToOpen) {
                // A business link opens its page when connected; otherwise the connect flow reviews it first.
                guard let handle = model.businessToOpen else { return }
                await directory.load()
                if let entry = directory.active.first(where: { $0.business.handle == handle }) {
                    model.businessToOpen = nil
                    path = [.business(entry.business.id)]
                } else {
                    model.addBusinessPresented = true
                }
            }
        }
    }

    private var subtitle: String {
        let count = directory.active.count
        return count == 0 ? "Connect with a QR code, handle or code" : (count == 1 ? "1 connected business" : "\(count) connected businesses")
    }

    @ViewBuilder private var content: some View {
        let results = directory.results
        let active = results.filter(\.isActive)
        let ended = results.filter { !$0.isActive }
        if directory.isLoading {
            ViadereLoading().frame(maxWidth: .infinity).padding(.top, ViadereSpace.xxl)
        } else if directory.directory.isEmpty {
            ViadereEmptyState("No businesses yet",
                              message: "Add a business with its QR code, its @handle or its code. Verified businesses only.",
                              actionTitle: "Add a business") { model.addBusinessPresented = true }
                .padding(.top, ViadereSpace.xl)
        } else if results.isEmpty {
            Text("No business matches \u{201C}\(directory.query)\u{201D}.")
                .font(ViadereType.body)
                .foregroundStyle(ViadereColor.textSecondary)
                .padding(.top, ViadereSpace.m)
        } else {
            let favorites = active.filter(\.preferences.favorite)
            let others = active.filter { !$0.preferences.favorite }
            if !favorites.isEmpty { section("Favorites", favorites) }
            if !others.isEmpty { section(favorites.isEmpty ? "Connected" : "Everyone else", others) }
            if !ended.isEmpty {
                ViadereSectionHeader("No longer connected")
                ViadereRowGroup {
                    ForEach(Array(ended.enumerated()), id: \.element.id) { index, entry in
                        HStack(spacing: ViadereSpace.xs) {
                            ViadereBusinessCard(name: entry.business.safeName,
                                                subtitle: entry.preferences.blocked ? "Blocked" : "Disconnected",
                                                isVerified: entry.business.isVerified)
                            if entry.preferences.blocked {
                                Button("Unblock") { unblocking = entry }
                                    .buttonStyle(.viadere(.quiet, fullWidth: false))
                                    .accessibilityLabel(Text("Unblock \(entry.business.safeName)"))
                            } else {
                                Button("Reconnect") { model.reconnect(entry.business) }
                                    .buttonStyle(.viadere(.quiet, fullWidth: false))
                                    .accessibilityLabel(Text("Reconnect to \(entry.business.safeName)"))
                            }
                        }
                        if index < ended.count - 1 { ViadereHairline(inset: 58) }
                    }
                }
            }
        }
        if let error = directory.errorMessage {
            ViadereNotice(error, kind: .warning).padding(.top, ViadereSpace.m)
        }
    }

    private func section(_ title: String, _ entries: [ConnectedBusiness]) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            ViadereSectionHeader(title)
            ViadereRowGroup {
                ForEach(Array(entries.enumerated()), id: \.element.id) { index, entry in
                    HStack(spacing: 0) {
                        Button { path.append(.business(entry.business.id)) } label: {
                            ViadereBusinessCard(name: entry.business.safeName, subtitle: detail(entry), isVerified: entry.business.isVerified,
                                                badge: badge(entry))
                        }
                        .buttonStyle(.plain)
                        ViadereFavoriteButton(isFavorite: entry.preferences.favorite, name: entry.business.safeName) {
                            Task { await directory.setFavorite(entry.business.id, !entry.preferences.favorite) }
                        }
                    }
                    if index < entries.count - 1 { ViadereHairline(inset: 58) }
                }
            }
        }
    }

    /// Discover (reserved for Loops, docs/APP-IA.md): the Loop directory and the Loops the customer added. Shown only while Loops are
    /// offered at all; each business's own Loops stay on its page.
    @ViewBuilder private var discover: some View {
        if model.services.loopsAPI != nil {
            VStack(alignment: .leading, spacing: 0) {
                ViadereSectionHeader("Discover")
                HStack(spacing: ViadereSpace.s) {
                    discoverTile("Loop directory", subtitle: "Find requests and tools", symbol: "square.grid.2x2", route: .loopDirectory)
                    discoverTile("Your Loops", subtitle: "The ones you've added", symbol: "square.stack", route: .yourLoops)
                }
            }
        }
    }

    private func discoverTile(_ title: String, subtitle: String, symbol: String, route: BusinessesRoute) -> some View {
        Button { path.append(route) } label: {
            VStack(alignment: .leading, spacing: ViadereSpace.s) {
                ViadereIconTile(systemName: symbol)
                VStack(alignment: .leading, spacing: 2) {
                    Text(title).font(ViadereType.headline).foregroundStyle(ViadereColor.textPrimary)
                    Text(subtitle).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                }
            }
            .padding(ViadereSpace.m)
            .frame(maxWidth: .infinity, alignment: .leading)
            .viadereSurface(radius: ViadereRadius.control + 4)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .accessibilityElement(children: .combine)
    }

    private func detail(_ entry: ConnectedBusiness) -> String {
        var parts: [String] = [entry.business.handle?.display ?? entry.business.code.display]
        if entry.preferences.effectiveMute(at: model.services.clock()) != MuteLevel.none { parts.append("Quieted") }
        return parts.joined(separator: " · ")
    }

    private func badge(_ entry: ConnectedBusiness) -> String? {
        let count = model.alerts.needsYou(context: .business(entry.business.id)).count
        return count == 0 ? nil : (count == 1 ? "1 needs you" : "\(count) need you")
    }
}

#if DEBUG
#Preview("Businesses") {
    PreviewHost { services in
        BusinessesView(model: AppModel(services: services, walletLibrary: MockWalletLibrary()))
    }
}
#endif
