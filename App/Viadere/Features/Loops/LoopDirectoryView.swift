import SwiftUI
import ViadereCore
import ViadereKit

/// The Loop directory (SECURITY.md §2.98 "Installed Loops"): featured Loops, categories and search over reviewed names and descriptions,
/// each under "Built by {verified name}". Opening one shows its install sheet (`LoopDetailView`). It has no navigation stack of its own:
/// the host pushes it (or wraps it in `LoopDirectoryScreen` to present it as a sheet).
struct LoopDirectoryView: View {
    let model: AppModel
    var backTitle: String?
    @State private var directory: LoopDirectoryViewModel
    @State private var searchTask: Task<Void, Never>?
    @Environment(\.dismiss) private var dismiss

    init(model: AppModel, backTitle: String? = nil) {
        self.model = model
        self.backTitle = backTitle
        let consent = model.loopConsent
        _directory = State(initialValue: LoopDirectoryViewModel(api: model.services.loopsAPI, consent: { consent.status }))
    }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 0) {
                if let backTitle { ViadereBackButton(backTitle) { dismiss() } }
                ViadereHeader("Loops", subtitle: "Small apps businesses build for Viadere. Viadere reviews every one before you can add it.")
                if !directory.isAvailable {
                    ViadereNotice("Loops aren't available right now. Everything else in Viadere works as usual.", kind: .info)
                } else {
                    ViadereSearchField("Search Loops", text: Binding(get: { directory.query }, set: { newValue in
                        directory.query = newValue
                        scheduleSearch()
                    }))
                    .padding(.bottom, ViadereSpace.s)
                    categories
                    yourLoopsLink
                    content
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
    }

    /// Debounced: one request per pause in typing (the server also rate-limits directory reads).
    private func scheduleSearch() {
        searchTask?.cancel()
        searchTask = Task {
            try? await Task.sleep(for: .milliseconds(350))
            guard !Task.isCancelled else { return }
            await directory.load()
        }
    }

    @ViewBuilder private var categories: some View {
        if !directory.categories.isEmpty {
            ScrollView(.horizontal) {
                HStack(spacing: ViadereSpace.xs) {
                    ViadereChip("All", isSelected: directory.category == nil) { Task { await directory.select(nil) } }
                    ForEach(directory.categories, id: \.rawValue) { category in
                        ViadereChip(category.title, isSelected: directory.category == category) { Task { await directory.select(category) } }
                    }
                }
                .padding(.vertical, ViadereSpace.xxs)
            }
            .scrollIndicators(.hidden)
            .padding(.bottom, ViadereSpace.xs)
            .accessibilityElement(children: .contain)
            .accessibilityLabel(Text("Categories"))
        }
    }

    @ViewBuilder private var yourLoopsLink: some View {
        if !model.loopLibrary.loops.isEmpty {
            ViadereRowGroup {
                NavigationLink {
                    InstalledLoopsView(model: model, backTitle: "Loops")
                } label: {
                    ViadereRow("Your Loops", subtitle: model.loopLibrary.loops.count == 1 ? "1 added" : "\(model.loopLibrary.loops.count) added",
                               leading: { ViadereIconTile(systemName: "square.stack") })
                }
                .buttonStyle(.plain)
            }
            .padding(.top, ViadereSpace.xs)
        }
    }

    @ViewBuilder private var content: some View {
        if directory.page == nil, directory.isLoading {
            ViadereLoading()
        } else if let error = directory.errorMessage {
            ViadereNotice(error, kind: .warning)
        } else if directory.isEmpty {
            ViadereEmptyState(directory.isFiltering ? "No matches" : "No Loops yet",
                              message: directory.isFiltering ? "Try another word or category." : "Loops businesses publish appear here after Viadere reviews them.")
        } else {
            if !directory.featured.isEmpty {
                ViadereSectionHeader("Featured")
                entryGroup(directory.featured)
            }
            if !directory.entries.isEmpty {
                ViadereSectionHeader(directory.isFiltering ? "Results" : "All Loops")
                entryGroup(directory.entries)
            }
        }
    }

    private func entryGroup(_ entries: [LoopDirectoryEntry]) -> some View {
        ViadereRowGroup {
            ForEach(Array(entries.enumerated()), id: \.element.loopId) { index, entry in
                NavigationLink {
                    LoopDetailView(model: model, loopId: entry.loopId, source: .directory, backTitle: "Loops")
                } label: {
                    LoopEntryRow(entry: entry, brand: model.services.brandKits)
                }
                .buttonStyle(.plain)
                if index < entries.count - 1 { ViadereHairline(inset: 62) }
            }
        }
    }
}

/// `LoopDirectoryView` with its own navigation stack, for presenting it as a sheet.
struct LoopDirectoryScreen: View {
    let model: AppModel

    var body: some View {
        NavigationStack { LoopDirectoryView(model: model) }
    }
}

/// One directory row: the business's icon, the reviewed title, "Built by {verified name}", and Added when installed.
struct LoopEntryRow: View {
    let entry: LoopDirectoryEntry
    let brand: BrandKitStore?

    var body: some View {
        ViadereRow(LoopDirectoryViewModel.title(entry), subtitle: subtitle,
                   leading: { LoopIcon(business: entry.business, brand: brand, size: 40) },
                   trailing: {
                       HStack(spacing: ViadereSpace.xs) {
                           if entry.installed { ViadereBadge("Added", kind: .success) }
                           ViadereChevron()
                       }
                   })
        .accessibilityLabel(Text("\(LoopDirectoryViewModel.title(entry)). Built by \(entry.business.safeName), a business on Viadere\(entry.installed ? ". Added" : "")"))
    }

    private var subtitle: String {
        if let summary = LoopDirectoryViewModel.summary(entry) { return "\(LoopDirectoryViewModel.attribution(entry.business)) · \(summary)" }
        return LoopDirectoryViewModel.attribution(entry.business)
    }
}

/// A Loop's icon: the business's approved Brand Kit logo (else mark) from its verified brand manifest, else Viadere's monogram. Decoration
/// only; the verified name is always written next to it.
struct LoopIcon: View {
    let business: BusinessSummary
    let brand: BrandKitStore?
    var size: CGFloat = 44
    @State private var decoration: BusinessHomeDecoration?

    var body: some View {
        BrandLogo(data: decoration?.logo, name: business.safeName, isVerified: business.isVerified, size: size)
            .accessibilityHidden(true)
            .task(id: business.id) {
                guard let brand, business.isVerified else { return }
                decoration = BusinessHomeDecoration.make(business: business, brand: brand)
                // Never awaited by anything else: the row renders at once with the monogram.
                await brand.refresh(business.id)
                decoration = BusinessHomeDecoration.make(business: business, brand: brand)
            }
    }
}

/// A business's Loops for its page when the customer is **not** connected (search result, install link, profile): every visible published
/// Loop of that business, each opening its install sheet. The page owns and loads `directory` (`makeDirectory`), like
/// `BusinessLoopsSection`: SwiftUI never runs a `.task` on a view that is empty until it has loaded.
struct BusinessLoopDirectorySection: View {
    let business: BusinessSummary
    let model: AppModel
    let directory: LoopDirectoryViewModel

    static func makeDirectory(business: BusinessSummary, model: AppModel) -> LoopDirectoryViewModel {
        let consent = model.loopConsent
        return LoopDirectoryViewModel(api: model.services.loopsAPI, business: business.id, consent: { consent.status })
    }

    var body: some View {
        if !directory.entries.isEmpty {
            VStack(alignment: .leading, spacing: 0) {
                ViadereSectionHeader("Loops")
                ViadereRowGroup {
                    ForEach(Array(directory.entries.enumerated()), id: \.element.loopId) { index, entry in
                        NavigationLink {
                            LoopDetailView(model: model, loopId: entry.loopId, source: .businessPage, backTitle: business.safeName)
                        } label: {
                            LoopEntryRow(entry: entry, brand: model.services.brandKits)
                        }
                        .buttonStyle(.plain)
                        if index < directory.entries.count - 1 { ViadereHairline(inset: 62) }
                    }
                }
            }
        }
    }
}
