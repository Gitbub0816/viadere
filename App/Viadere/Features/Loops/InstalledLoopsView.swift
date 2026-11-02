import SwiftUI
import ViadereCore
import ViadereKit

/// Your Loops (SECURITY.md §2.98 "Installed Loops"): every Loop the customer added, with or without a connection. Open starts (or resumes)
/// it; the Loop's page shows its permissions again and removes it (its open requests are cancelled).
struct InstalledLoopsView: View {
    let model: AppModel
    var backTitle: String?
    @Environment(\.dismiss) private var dismiss

    private var library: LoopLibraryViewModel { model.loopLibrary }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                if let backTitle { ViadereBackButton(backTitle) { dismiss() } }
                ViadereHeader("Your Loops", subtitle: "Loops you added. Each one says who built it and what it can do.")
                InstalledLoopsList(model: model)
                ViadereSectionHeader("Find more")
                ViadereRowGroup {
                    NavigationLink {
                        LoopDirectoryView(model: model, backTitle: "Your Loops")
                    } label: {
                        ViadereRow("Browse Loops", subtitle: "Reviewed by Viadere", leading: { ViadereIconTile(systemName: "square.grid.2x2") })
                    }
                    .buttonStyle(.plain)
                }
            }
            .padding(.horizontal, ViadereSpace.screen)
            .padding(.bottom, ViadereSpace.xl)
        }
        .scrollIndicators(.hidden)
        .viadereScreenBackground()
        .toolbar(.hidden, for: .navigationBar)
        .task { await library.load() }
        .refreshable { await library.load() }
    }
}

/// The list itself, reused by Settings → Requests built by businesses.
struct InstalledLoopsList: View {
    let model: AppModel
    var showsEmptyState = true

    private var library: LoopLibraryViewModel { model.loopLibrary }

    var body: some View {
        if library.loops.isEmpty {
            if library.isLoading && !library.hasLoaded {
                ViadereLoading()
            } else if showsEmptyState {
                ViadereEmptyState("No Loops yet", message: "Add Loops from the directory, a business's page or a link a business shares.")
            }
        } else {
            ViadereRowGroup {
                ForEach(Array(library.loops.enumerated()), id: \.element.loopId) { index, loop in
                    VStack(alignment: .leading, spacing: 0) {
                    HStack(spacing: ViadereSpace.xs) {
                        NavigationLink {
                            LoopDetailView(model: model, loopId: loop.loopId, source: .directory, backTitle: "Your Loops")
                        } label: {
                            ViadereRow(LoopLibraryViewModel.title(loop), subtitle: LoopLibraryViewModel.subtitle(loop),
                                       leading: { LoopIcon(business: loop.business, brand: model.services.brandKits, size: 40) },
                                       trailing: { EmptyView() })
                        }
                        .buttonStyle(.plain)
                        .accessibilityLabel(Text("\(LoopLibraryViewModel.title(loop)). \(LoopLibraryViewModel.subtitle(loop))"))
                        if loop.isStartable || !loop.openInstances.isEmpty {
                            Button(loop.openInstances.isEmpty ? "Open" : "Resume") {
                                Task { await AppEnvironment.shared.loops.startInstalled(loop, model: model) }
                            }
                            .buttonStyle(.viadere(.secondary, fullWidth: false))
                            .accessibilityLabel(Text("\(loop.openInstances.isEmpty ? "Open" : "Resume") \(LoopLibraryViewModel.title(loop))"))
                        }
                    }
                    // This Loop's own alerts in Alerts (F-4): one chip per Loop, off unless the customer turned it on. Never the business's
                    // other alerts, offers or messages.
                    HStack {
                        ViadereToggleChip("Alerts", isOn: loop.alertsEnabled, hint: LoopAlertsCopy.detail(business: loop.business.safeName)) {
                            Task { await library.setAlerts(loop.loopId, enabled: !loop.alertsEnabled) }
                        }
                        Text(LoopAlertsCopy.state(enabled: loop.alertsEnabled))
                            .font(ViadereType.footnote)
                            .foregroundStyle(ViadereColor.textTertiary)
                            .lineLimit(2)
                        Spacer(minLength: 0)
                    }
                    .padding(.leading, 54)
                    .padding(.bottom, ViadereSpace.xs)
                    }
                    if index < library.loops.count - 1 { ViadereHairline(inset: 54) }
                }
            }
        }
        if let error = library.errorMessage { ViadereNotice(error, kind: .warning) }
    }
}
