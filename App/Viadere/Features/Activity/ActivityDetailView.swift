import SwiftUI
import ViadereCore
import ViadereKit

/// One order, delivery, appointment, trip or event: status, the facts, tickets and the actions the business sent.
struct ActivityDetailView: View {
    let itemId: String
    let model: AppModel
    @Environment(\.dismiss) private var dismiss

    private var vm: ActivityViewModel { model.activity }
    private var item: ActivityItem? { vm.content.allItems.first { $0.id == itemId } }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: ViadereSpace.l) {
                ViadereBackButton("Activity") { dismiss() }
                if let item {
                    hero(item)
                    facts(item)
                    if let note = item.venueNote { venue(note) }
                    if let pass = vm.pass(for: item) { passCard(pass) }
                    actions(item)
                    support(item)
                } else {
                    ViadereEmptyState("All done", message: "This is no longer in progress.")
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
    }

    // MARK: Pieces

    private func hero(_ item: ActivityItem) -> some View {
        VStack(alignment: .leading, spacing: ViadereSpace.m) {
            HStack(spacing: ViadereSpace.s) {
                ViadereAvatar(name: item.business.safeName, size: 48, isVerified: item.business.isVerified)
                VStack(alignment: .leading, spacing: 4) {
                    Text(item.business.safeName).font(ViadereType.headline).foregroundStyle(ViadereColor.textPrimary)
                    HStack(spacing: ViadereSpace.xs) {
                        if item.business.isVerified { ViadereBadge("Verified", kind: .verified) }
                        Text(item.category.title).font(ViadereType.footnote).foregroundStyle(ViadereColor.textSecondary)
                    }
                }
            }
            Text(item.title)
                .font(ViadereType.display)
                .foregroundStyle(ViadereColor.textPrimary)
                .fixedSize(horizontal: false, vertical: true)
                .accessibilityAddTraits(.isHeader)
            if let status = item.statusText {
                Text(status)
                    .font(ViadereType.subhead.weight(.medium))
                    .foregroundStyle(item.isAlert ? ViadereColor.danger : ViadereColor.textSecondary)
            }
            if let progress = item.progress { ViadereProgressBar(progress: progress) }
            if let subtitle = item.subtitle, item.venueNote == nil {
                Text(subtitle).font(ViadereType.body).foregroundStyle(ViadereColor.textSecondary)
            }
        }
    }

    @ViewBuilder private func facts(_ item: ActivityItem) -> some View {
        let rows = ActivityPresentation.details(item, now: model.services.clock())
        if !rows.isEmpty {
            ViadereRowGroup {
                ForEach(Array(rows.enumerated()), id: \.element.id) { index, row in
                    ViadereValueRow(row.label, row.value, emphasized: row.emphasized)
                    if index < rows.count - 1 { ViadereHairline() }
                }
            }
        }
    }

    private func venue(_ note: String) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            ViadereSectionHeader("Venue and schedule")
            ViadereCard(padding: ViadereSpace.m) {
                Text(note).font(ViadereType.body).foregroundStyle(ViadereColor.textPrimary).fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func passCard(_ pass: WalletPassMetadata) -> some View {
        VStack(alignment: .leading, spacing: ViadereSpace.xs) {
            ViadereSectionHeader(pass.kind == .boardingPass ? "Boarding pass" : (pass.kind == .eventTicket ? "Ticket" : "Pass"))
            WalletPassAction(pass: pass, wallet: model.wallet)
        }
    }

    @ViewBuilder private func actions(_ item: ActivityItem) -> some View {
        if !item.actions.isEmpty {
            VStack(alignment: .leading, spacing: ViadereSpace.s) {
                ViadereSectionHeader("Needs you")
                ViadereCard(padding: ViadereSpace.m) {
                    VStack(alignment: .leading, spacing: ViadereSpace.s) {
                        ActivityActionBar(item: item, model: model)
                        if ActivityPresentation.needsSecureNote(item) {
                            Text(ActivityPresentation.secureSheetNote)
                                .font(ViadereType.footnote)
                                .foregroundStyle(ViadereColor.textSecondary)
                        }
                    }
                }
            }
        }
    }

    @ViewBuilder private func support(_ item: ActivityItem) -> some View {
        VStack(spacing: ViadereSpace.xs) {
            if vm.canAskToReschedule(item) {
                Button {
                    Task {
                        if await model.messages.start(with: item.business.id) != nil { model.selectedTab = .messages }
                    }
                } label: {
                    HStack(spacing: ViadereSpace.xs) { Image(systemName: "calendar.badge.clock"); Text("Ask to reschedule") }
                }
                .buttonStyle(.viadere(.secondary))
            }
            Button {
                Task {
                    if await model.messages.start(with: item.business.id) != nil { model.selectedTab = .messages }
                }
            } label: {
                HStack(spacing: ViadereSpace.xs) { Image(systemName: "bubble.left"); Text("Message \(item.business.safeName)") }
            }
            .buttonStyle(.viadere(.quiet))
        }
    }
}

#if DEBUG
#Preview("Activity · appointment") {
    PreviewHost { services in
        ActivityDetailPreview(services: services, category: .appointment)
    }
}

#Preview("Activity · flight") {
    PreviewHost { services in
        ActivityDetailPreview(services: services, category: .travel)
    }
}

#Preview("Activity · event") {
    PreviewHost { services in
        ActivityDetailPreview(services: services, category: .event)
    }
}

private struct ActivityDetailPreview: View {
    let services: ViadereServices
    let category: ActivityCategory
    @State private var model: AppModel?

    var body: some View {
        Group {
            if let model, let id = model.activity.content.allItems.first(where: { $0.category == category })?.id {
                ActivityDetailView(itemId: id, model: model)
            } else {
                ViadereLoading()
            }
        }
        .task {
            let created = AppModel(services: services, walletLibrary: MockWalletLibrary())
            await created.activity.load()
            model = created
        }
    }
}
#endif
