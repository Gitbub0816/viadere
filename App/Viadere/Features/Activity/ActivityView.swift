import SwiftUI
import ViadereCore
import ViadereKit

/// Orders, deliveries, appointments, trips and tickets: calm, grouped by business, newest relevance first.
/// Built from `status`, `ticket` and `confirm` interactions. Nothing here asks for attention unless a business
/// is actually waiting on you.
struct ActivityView: View {
    @Bindable var model: AppModel
    @State private var path: [String] = []
    @State private var showEarlier = false

    private var vm: ActivityViewModel { model.activity }

    var body: some View {
        NavigationStack(path: $path) {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    ViadereHeader("Activity", subtitle: subtitle)
                    filters
                    feed
                    if case .failed(let message) = vm.phase {
                        ViadereNotice(message, kind: .warning).padding(.top, ViadereSpace.l)
                    }
                }
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.bottom, ViadereSpace.xl)
            }
            .scrollIndicators(.hidden)
            .viadereScreenBackground()
            .toolbar(.hidden, for: .navigationBar)
            .task { await vm.load() }
            .refreshable { await vm.load() }
            .navigationDestination(for: String.self) { id in
                ActivityDetailView(itemId: id, model: model)
            }
        }
    }

    private var subtitle: String {
        let n = vm.needsYouCount
        return n == 0 ? "Everything is on track" : (n == 1 ? "1 thing needs you" : "\(n) things need you")
    }

    private var filters: some View {
        ScrollView(.horizontal) {
            HStack(spacing: ViadereSpace.xs) {
                ForEach(ActivityCategory.Filter.allCases, id: \.self) { filter in
                    ViadereChip(filter.title, isSelected: vm.filter == filter) { withAnimation(ViadereMotion.quick) { vm.filter = filter } }
                }
            }
            .padding(.vertical, ViadereSpace.xs)
        }
        .scrollIndicators(.hidden)
    }

    @ViewBuilder private var feed: some View {
        let current = vm.visible.filtered(.all, includePast: false)
        let earlier = vm.visible.allItems.filter { $0.phase == .past }
        if vm.phase == .loading {
            ViadereLoading().frame(maxWidth: .infinity).padding(.top, ViadereSpace.xxl)
        } else if current.isEmpty && earlier.isEmpty {
            ViadereEmptyState(ActivityPresentation.emptyTitle, message: ActivityPresentation.emptyMessage)
                .padding(.top, ViadereSpace.xxl)
        } else {
            ForEach(current.groups) { group in
                ActivityGroupSection(group: group, model: model) { path.append($0.id) }
            }
            if !earlier.isEmpty {
                Button(showEarlier ? "Hide earlier" : "Show earlier · \(earlier.count)") {
                    withAnimation(ViadereMotion.standard) { showEarlier.toggle() }
                }
                .buttonStyle(.viadere(.quiet, fullWidth: false))
                .padding(.top, ViadereSpace.m)
                if showEarlier {
                    ViadereRowGroup {
                        ForEach(Array(earlier.enumerated()), id: \.element.id) { index, item in
                            Button { path.append(item.id) } label: { ActivityRow(item: item, now: model.services.clock()) }
                                .buttonStyle(.plain)
                            if index < earlier.count - 1 { ViadereHairline(inset: 50) }
                        }
                    }
                }
            }
        }
    }
}

/// One business's items. Items waiting on the person carry their quick actions right under the row.
struct ActivityGroupSection: View {
    let group: ActivityGroup
    let model: AppModel
    let open: (ActivityItem) -> Void

    var body: some View {
        VStack(alignment: .leading, spacing: 0) {
            ViadereSectionHeader(group.business.displayName)
            ViadereRowGroup {
                ForEach(Array(group.items.enumerated()), id: \.element.id) { index, item in
                    VStack(alignment: .leading, spacing: 0) {
                        Button { open(item) } label: { ActivityRow(item: item, now: model.services.clock()) }
                            .buttonStyle(.plain)
                        if item.phase == .needsYou, !item.actions.isEmpty {
                            ActivityActionBar(item: item, model: model)
                                .padding(.leading, 50)
                                .padding(.bottom, ViadereSpace.s)
                        }
                    }
                    if index < group.items.count - 1 { ViadereHairline(inset: 50) }
                }
            }
        }
    }
}

struct ActivityRow: View {
    let item: ActivityItem
    let now: Date

    var body: some View {
        ViadereRow(item.title, subtitle: ActivityPresentation.rowSubtitle(item, now: now),
                   leading: { ViadereIconTile(systemName: item.category.symbol) },
                   trailing: { trailing })
    }

    @ViewBuilder private var trailing: some View {
        if item.phase == .needsYou {
            ViadereBadge("Needs you", kind: .verified)
        } else if item.isAlert {
            ViadereBadge("Update", kind: .danger)
        } else {
            ViadereChevron()
        }
    }
}

/// The answers a business is waiting on: confirm / cancel / check in, reschedule times, or "Review" for anything that
/// must open the secure approval sheet. Labels come from the business's own requested actions.
struct ActivityActionBar: View {
    let item: ActivityItem
    let model: AppModel

    var body: some View {
        VStack(alignment: .leading, spacing: ViadereSpace.xs) {
            ViadereFlowLayout {
                ForEach(item.actions) { action in
                    ViadereChip(action.label, isSelected: action.isPrimary) { Task { await run(action) } }
                        .disabled(model.activity.busyActionId != nil)
                        .opacity(model.activity.busyActionId == action.id ? 0.5 : 1)
                }
            }
            if let message = model.activity.message {
                Text(message).font(ViadereType.footnote).foregroundStyle(ViadereColor.danger)
            }
        }
    }

    private func run(_ action: ActivityAction) async {
        switch await model.activity.perform(action, in: item) {
        case .needsSecureSheet(let id): await model.openInteraction(id)
        case .done:
            await model.home.load()
            model.toast = "Sent to \(item.business.displayName)."
        case .cancelled, .failed: break
        }
    }
}

#if DEBUG
#Preview("Activity") {
    PreviewHost { services in
        ActivityView(model: AppModel(services: services, walletLibrary: MockWalletLibrary()))
    }
}
#endif
