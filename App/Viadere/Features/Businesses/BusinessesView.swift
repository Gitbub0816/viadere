import SwiftUI
import ViadereCore
import ViadereKit

/// Businesses (spec C2, C3, C8): one directory of the customer's connections, favorites first, searchable on the device, with a prominent
/// Add business. Fifty businesses are one list and a search field, never fifty tabs. Opening a business shows its neutral Viadere home; it
/// does not change the business context (only the selector does).
struct BusinessesView: View {
    @Bindable var model: AppModel
    @State private var path: [BusinessID] = []

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
                    content
                    ViadereSectionHeader("Also in Viadere")
                    ViadereRowGroup {
                        NavigationLink {
                            AuthenticatorView(backTitle: "Businesses")
                        } label: {
                            ViadereRow("Authenticator", subtitle: "Passkeys and one-time codes", leading: { ViadereIconTile(systemName: "key.viewfinder") })
                        }
                        .buttonStyle(.plain)
                    }
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
            .navigationDestination(for: BusinessID.self) { id in
                if let entry = directory.entry(id) {
                    BusinessHomeView(entry: entry, model: model)
                } else {
                    ViadereEmptyState("Not available", message: "You're no longer connected to this business.")
                }
            }
            .task(id: model.businessToOpen) {
                // A business link opens its page when connected; otherwise the connect flow reviews it first.
                guard let handle = model.businessToOpen else { return }
                await directory.load()
                if let entry = directory.active.first(where: { $0.business.handle == handle }) {
                    model.businessToOpen = nil
                    path = [entry.business.id]
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
                        ViadereBusinessCard(name: entry.business.safeName,
                                            subtitle: entry.preferences.blocked ? "Blocked" : "Disconnected",
                                            isVerified: entry.business.isVerified)
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
                        Button { path.append(entry.business.id) } label: {
                            ViadereBusinessCard(name: entry.business.safeName, subtitle: detail(entry), isVerified: entry.business.isVerified,
                                                badge: badge(entry))
                        }
                        .buttonStyle(.plain)
                        Button {
                            Task { await directory.setFavorite(entry.business.id, !entry.preferences.favorite) }
                        } label: {
                            Image(systemName: entry.preferences.favorite ? "star.fill" : "star")
                                .font(.system(size: 17, weight: .medium))
                                .foregroundStyle(entry.preferences.favorite ? ViadereColor.accent : ViadereColor.textTertiary)
                                .frame(width: 44, height: 44)
                                .contentShape(Rectangle())
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel(Text(entry.preferences.favorite ? "Remove \(entry.business.safeName) from favorites" : "Add \(entry.business.safeName) to favorites"))
                    }
                    if index < entries.count - 1 { ViadereHairline(inset: 58) }
                }
            }
        }
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
