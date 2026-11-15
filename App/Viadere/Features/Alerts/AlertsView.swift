import SwiftUI
import ViadereCore
import ViadereKit

/// Alerts (spec C5): the durable inbox. "Needs you" holds what waits on the person (security first, then the soonest to expire); "History"
/// holds everything else, including the orders, trips and bookings that used to be the Activity tab. The server list is the source of
/// truth; a push only points here. Expired items never show an action, and nothing is actionable while offline.
///
/// Sign-in links, one-time codes and security notices (auth deliveries) are not in the Alerts read model: they come from their own inbox
/// (`AuthDeliveryInboxViewModel`) and sit at the top of "Needs you". A row opens the same sheet as the push (`pendingAuthDelivery`), which
/// fetches the display object only; nothing is opened or consumed from this list.
struct AlertsView: View {
    @Bindable var model: AppModel
    @State private var path: [String] = []
    @State private var inbox: AuthDeliveryInboxViewModel

    init(model: AppModel) {
        self.model = model
        _inbox = State(initialValue: AuthDeliveryInboxViewModel(api: model.services.authDelivery, clock: model.services.clock))
    }

    private var alerts: AlertsViewModel { model.alerts }
    private var context: OrganizationContext { model.organization.effective }

    var body: some View {
        NavigationStack(path: $path) {
            ScrollView {
                VStack(alignment: .leading, spacing: 0) {
                    OrganizationContextHeader(model: model)
                    ViadereHeader("Alerts", subtitle: subtitle) {
                        ViadereIconButton(systemName: "viewfinder", label: "Scan a code") { model.scannerPresented = true }
                    }
                    securityNotice
                    ViadereSegmented(selection: Binding(get: { alerts.segment }, set: { alerts.segment = $0 }), options: AlertsSegment.allCases) {
                        $0 == .needsYou ? "Needs you" : "History"
                    }
                    .padding(.bottom, ViadereSpace.s)
                    // A first load that failed has its own state below (with a retry); the notice is for a failed refresh and offline.
                    if alerts.isOffline || (alerts.errorMessage != nil && !alerts.isEmpty) {
                        ViadereNotice(alerts.errorMessage ?? "You're offline.", kind: alerts.isOffline ? .info : .warning)
                            .padding(.bottom, ViadereSpace.s)
                            .transition(.opacity)
                    }
                    switch alerts.segment {
                    case .needsYou: needsYou
                    case .history: history
                    }
                }
                .padding(.horizontal, ViadereSpace.screen)
                .padding(.bottom, ViadereSpace.xl)
                .viadereAnimation(ViadereMotion.gentle, value: model.securityNotices.notices.count)
                .viadereAnimation(ViadereMotion.gentle, value: alerts.isOffline)
            }
            .scrollIndicators(.hidden)
            .viadereScreenBackground()
            .toolbar(.hidden, for: .navigationBar)
            .refreshable {
                await model.refreshOrganization()
                await refreshInbox()
            }
            .task { await refreshInbox() }
            // A delivery sheet closed (opened, reported, expired, or just looked at): the list follows the server.
            .onChange(of: model.pendingAuthDelivery) { _, now in
                if now == nil { Task { await refreshInbox() } }
            }
            .task(id: context) {
                await alerts.ensureLoaded(context)
                model.services.homeWidget?.publish(alerts: alerts, benefits: model.benefits)
                // Rows on screen for a moment count as seen (per account; the server keeps the mark).
                try? await Task.sleep(for: .seconds(1.5))
                await alerts.markSeen(alerts.visible(context: context))
            }
            .task { await model.activity.load() }
            .navigationDestination(for: String.self) { id in
                ActivityDetailView(itemId: id, model: model)
            }
        }
    }

    private func refreshInbox() async {
        await inbox.refresh()
        model.services.homeWidget?.publish(deliveries: inbox)
    }

    private var subtitle: String {
        let count = alerts.needsYou(context: context).count + inbox.rows(business: context.businessFilter).count
        let scope = model.organization.selectedBusiness.map { " from \($0.safeName)" } ?? ""
        return count == 0 ? "Nothing needs you\(scope)" : (count == 1 ? "1 thing needs you\(scope)" : "\(count) things need you\(scope)")
    }

    /// Viadere's own account notices stay on top in All (they are about the account, not a business).
    @ViewBuilder private var securityNotice: some View {
        if context == .all, let notice = model.securityNotices.current {
            SecurityNoticeBanner(vm: model.securityNotices, notice: notice) { model.reviewDevices() }
                .padding(.bottom, ViadereSpace.m)
                .transition(.opacity)
        } else if context == .all, let message = model.securityNotices.message {
            // The outcome of "Cancel recovery" / "Cancel" stays visible after its notice is gone.
            ViadereNotice(message, kind: .info).padding(.bottom, ViadereSpace.s).transition(.opacity)
        }
        if let notice = model.home.coolDownNotice {
            ViadereNotice("\(notice) \(CoolDownPolicy.stillAvailable)", kind: .info).padding(.bottom, ViadereSpace.s)
        }
    }

    // MARK: Needs you

    /// Pending sign-in links, codes and notices for this context, newest first; expired ones leave by the device clock.
    @ViewBuilder private var deliveries: some View {
        let rows = inbox.rows(business: context.businessFilter)
        if !rows.isEmpty {
            ViadereRowGroup {
                ForEach(Array(rows.enumerated()), id: \.element.id) { index, row in
                    Button { model.pendingAuthDelivery = PendingAuthDelivery(id: row.id) } label: {
                        ViadereRow(row.line, subtitle: AuthDeliveryCopy.expiresAt(row.expiresAt.formatted(date: .omitted, time: .shortened))) {
                            ViadereIconTile(systemName: row.symbol)
                        }
                    }
                    .buttonStyle(.viaderePressable)
                    .disabled(!inbox.canOpen(row))
                    if index < rows.count - 1 { ViadereHairline(inset: 50) }
                }
            }
            .padding(.bottom, ViadereSpace.s)
        }
    }

    @ViewBuilder private var needsYou: some View {
        deliveries
        let items = alerts.needsYou(context: context)
        let state = ScreenLoadState.resolve(isLoading: alerts.isLoading, isEmpty: alerts.isEmpty,
                                            errorMessage: alerts.isOffline ? nil : alerts.errorMessage)
        if state == .loading {
            ViadereSkeleton(.cards(2), label: "Loading alerts")
        } else if case .failed(let message) = state {
            ViadereErrorState("Couldn't load alerts", message: message) { await alerts.refresh() }
                .padding(.top, ViadereSpace.m)
        } else if items.isEmpty {
            if inbox.rows(business: context.businessFilter).isEmpty { emptyNeedsYou.padding(.top, ViadereSpace.xl) }
        } else {
            VStack(spacing: ViadereSpace.s) {
                ForEach(Array(items.enumerated()), id: \.element.id) { index, entry in
                    AlertCard(entry: entry, canAct: alerts.canAct(entry), now: model.services.clock(),
                              brand: BrandStyle(AlertBrandStyle.make(entry, brand: model.services.brandKits))) {
                        Task { await AlertOpener.open(entry, model: model) }
                    }
                    .viadereEntrance(index)
                }
            }
        }
    }

    @ViewBuilder private var emptyNeedsYou: some View {
        if model.businesses.hasLoaded && model.businesses.active.isEmpty {
            ViadereEmptyState("No businesses yet",
                              message: "Add a business with its QR code, handle or code. When it needs you, the request appears here.",
                              actionTitle: "Add a business") { model.addBusinessPresented = true }
        } else if let business = model.organization.selectedBusiness {
            ViadereEmptyState("Nothing from \(business.safeName)", message: "When \(business.safeName) needs you, it appears here. Usually you'll also get a notification.")
        } else {
            ViadereEmptyState("You're all set", message: "When a business needs you, it appears here. Usually you'll also get a notification.")
        }
    }

    // MARK: History

    @ViewBuilder private var history: some View {
        let filterOptions: [ViadereFilterBar<AlertStatusFilter?>.Option] = [
            .init(nil, "All"), .init(.completed, "Done"), .init(.expired, "Expired"),
        ]
        ViadereFilterBar("History filters", selection: Binding(get: { alerts.historyFilter }, set: { alerts.historyFilter = $0 }), options: filterOptions)
        let items = alerts.history(context: context)
        if items.isEmpty {
            Text(model.organization.selectedBusiness.map { "No earlier alerts from \($0.safeName)." } ?? "No earlier alerts.")
                .font(ViadereType.body)
                .foregroundStyle(ViadereColor.textSecondary)
                .padding(.top, ViadereSpace.m)
        } else {
            ViadereRowGroup {
                ForEach(Array(items.prefix(100).enumerated()), id: \.element.id) { index, entry in
                    Button { Task { await AlertOpener.open(entry, model: model) } } label: {
                        AlertHistoryRow(entry: entry, status: alerts.displayStatus(entry), now: model.services.clock())
                    }
                    .buttonStyle(.viaderePressable)
                    .disabled(entry.target?.kind != .interaction)
                    if index < min(items.count, 100) - 1 { ViadereHairline(inset: 50) }
                }
            }
            if alerts.hasMore[context] == true {
                Button("Show earlier") { Task { await alerts.loadMore(context) } }
                    .buttonStyle(.viadere(.quiet, fullWidth: false))
                    .padding(.top, ViadereSpace.s)
            }
        }
        activityTimeline
    }

    /// Orders, deliveries, trips and bookings (the former Activity tab), narrowed by the same context.
    @ViewBuilder private var activityTimeline: some View {
        let groups = model.activity.visible.filtered(.all, includePast: false).groups.filter { group in
            context.businessFilter == nil || group.business.id == context.businessFilter
        }
        if !groups.isEmpty {
            ViadereSectionHeader("Orders, trips and bookings")
            ForEach(groups) { group in
                ActivityGroupSection(group: group, model: model) { path.append($0.id) }
            }
        }
    }
}

/// A request waiting on the person: issuer first (verified name and badge), what it asks, the live deadline, one clear way in. The action
/// is disabled, with the reason in words, when the request expired or the phone is offline.
struct AlertCard: View {
    let entry: AlertEntry
    let canAct: Bool
    let now: Date
    /// The business's kit for this card (`AlertBrandStyle`: informational updates only; neutral for every request, approval,
    /// verification and security item). Draws an accent strip beside the neutral content.
    var brand: BrandStyle = .neutral
    let open: () -> Void

    var body: some View {
        Button(action: open) {
            VStack(alignment: .leading, spacing: ViadereSpace.s) {
                HStack(spacing: ViadereSpace.s) {
                    ViadereAvatar(name: AlertPresentation.issuer(entry), size: 36, isVerified: entry.business?.isVerified ?? false)
                    VStack(alignment: .leading, spacing: 0) {
                        HStack(spacing: 6) {
                            Text(AlertPresentation.issuer(entry))
                                .font(ViadereType.subhead.weight(.medium))
                                .foregroundStyle(ViadereColor.textPrimary)
                            if entry.unread {
                                Circle().fill(ViadereColor.accent).frame(width: 7, height: 7).accessibilityHidden(true)
                            }
                        }
                        Text(AlertPresentation.kindLabel(entry))
                            .font(ViadereType.footnote)
                            .foregroundStyle(ViadereColor.textSecondary)
                    }
                    Spacer(minLength: ViadereSpace.xs)
                    if let expiry = entry.expiresAt {
                        TimelineView(.periodic(from: .now, by: 1)) { context in
                            Text(InteractionPresentation.countdown(until: expiry, now: context.date))
                                .font(ViadereType.caption)
                                .monospacedDigit()
                                .foregroundStyle(ViadereColor.accent)
                        }
                    }
                }
                Text(AlertPresentation.title(entry))
                    .font(ViadereType.title)
                    .foregroundStyle(ViadereColor.textPrimary)
                    .multilineTextAlignment(.leading)
                    .fixedSize(horizontal: false, vertical: true)
                HStack(spacing: 6) {
                    Text(canAct ? (entry.purpose == .security ? "Review" : "Respond") : unavailableReason)
                        .font(ViadereType.subhead.weight(.semibold))
                    if canAct { Image(systemName: "arrow.right").font(.system(size: 13, weight: .semibold)) }
                }
                .foregroundStyle(canAct ? ViadereColor.accent : ViadereColor.textSecondary)
            }
            .padding(ViadereSpace.l)
            .frame(maxWidth: .infinity, alignment: .leading)
            .viadereSurface()
            .overlay(alignment: .leading) {
                // The leading strip: the business's kit color on its informational updates, else Viadere's accent while actionable.
                if brand.isBranded {
                    Capsule().fill(brand.primary).frame(width: 4).padding(.vertical, ViadereSpace.l).accessibilityHidden(true)
                } else if canAct {
                    Capsule().fill(ViadereColor.accent).frame(width: 3).padding(.vertical, ViadereSpace.l)
                }
            }
            .contentShape(Rectangle())
        }
        .buttonStyle(.viaderePressable)
        .disabled(!canAct && entry.source != .securityNotice)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(Text("\(AlertPresentation.kindLabel(entry)) from \(AlertPresentation.issuer(entry))\(entry.business?.isVerified == true ? ", verified business" : ""). \(AlertPresentation.title(entry))\(entry.unread ? ". New" : "")"))
        .accessibilityHint(Text(canAct ? "Opens the request" : unavailableReason))
    }

    private var unavailableReason: String {
        if let expiry = entry.expiresAt, expiry <= now { return "Expired" }
        if entry.business?.isVerified == false { return "This business can't send requests right now" }
        if entry.target == nil { return "Answer on the device that received it" }
        return "Available when you're back online"
    }
}

struct AlertHistoryRow: View {
    let entry: AlertEntry
    let status: AlertStatus
    let now: Date

    var body: some View {
        ViadereRow(AlertPresentation.title(entry),
                   subtitle: "\(AlertPresentation.issuer(entry)) · \(AlertPresentation.statusLabel(status)) · \(InteractionPresentation.relative(entry.updatedAt, now: now))",
                   leading: { ViadereAvatar(name: AlertPresentation.issuer(entry), size: 36, isVerified: entry.business?.isVerified ?? false) },
                   trailing: {
                       if entry.unread {
                           Circle().fill(ViadereColor.accent).frame(width: 7, height: 7).accessibilityLabel(Text("New"))
                       }
                   })
    }
}

#if DEBUG
#Preview("Alerts") {
    PreviewHost { services in
        AlertsView(model: AppModel(services: services, walletLibrary: MockWalletLibrary()))
    }
}
#endif
