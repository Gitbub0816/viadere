import SwiftUI
import ViadereCore
import ViadereKit

extension AppTab {
    var title: String {
        switch self {
        case .messages: "Messages"
        case .alerts: "Alerts"
        case .benefits: "Benefits"
        case .businesses: "Businesses"
        }
    }

    var symbol: String {
        switch self {
        case .messages: "bubble.left"
        case .alerts: "bell"
        case .benefits: "tag"
        case .businesses: "building.2"
        }
    }
}

/// The stable bar (spec C1; plan 4.8 variant A): Messages, Alerts, Benefits, Businesses on a hand-built bar, each tab with its own
/// `NavigationStack` (system bar hidden). The business selector at the top of every tab filters Messages, Alerts and Benefits the same way;
/// Settings and Add business open as sheets from it. The bar never grows with the number of businesses.
struct MainShell: View {
    @Bindable var model: AppModel

    var body: some View {
        VStack(spacing: 0) {
            Group {
                switch model.selectedTab {
                case .messages: MessagesView(model: model)
                case .alerts: AlertsView(model: model)
                case .benefits: BenefitsView(model: model)
                case .businesses: BusinessesView(model: model)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            ViadereTabBar(selection: $model.selectedTab, items: AppTab.allCases.map { tab in
                ViadereTabBar<AppTab>.Item(tab: tab, title: tab.title, symbol: tab.symbol, badge: badge(for: tab))
            })
        }
        .viadereScreenBackground()
        .viadereDocumentVerification()
        .sheet(item: Binding(get: { AppEnvironment.shared.verification.presented.map(PresentedVerification.init) },
                             set: { value in
                                 AppEnvironment.shared.verification.presented = value?.id
                                 // The verification sheet always names its own recipient; the context was frozen while it was open.
                                 if value == nil { model.organization.endSensitiveFlow() }
                             })) { presented in
            VerificationSheetHost(id: presented.id)
                .presentationDetents([.large])
                .presentationBackground(ViadereColor.background)
        }
        .sheet(isPresented: $model.settingsPresented) {
            SettingsView(model: model)
                .presentationDetents([.large])
                .presentationCornerRadius(ViadereRadius.sheet)
                .presentationBackground(ViadereColor.background)
        }
        .sheet(isPresented: $model.addBusinessPresented, onDismiss: {
            Task { await model.businesses.load() }
        }) {
            ConnectView(model: model)
                .presentationDetents([.large])
                .presentationCornerRadius(ViadereRadius.sheet)
                .presentationBackground(ViadereColor.background)
        }
        .task { await model.messages.load() }
        .onChange(of: model.home.content, initial: true) { _, content in
            // Keep the watch's pending list and any running Live Activities in step with the pending requests.
            let environment = AppEnvironment.shared
            environment.watchBridge.push(content)
            Task { await environment.liveActivities.sync(content.statuses) }
        }
        .onChange(of: model.activity.liveCandidates) { _, candidates in
            // Only statuses `LiveActivityPolicy` allows (ongoing orders, deliveries, flights, appointments; never marketing).
            Task { await AppEnvironment.shared.liveActivities.sync(candidates) }
        }
    }

    /// Alerts: what is actionable now (the server's read model, re-checked by the device clock). Messages: unread. Never both for one event.
    private func badge(for tab: AppTab) -> Int {
        switch tab {
        case .alerts: model.alerts.badgeCount()
        case .messages: model.messages.unreadTotal
        default: 0
        }
    }
}

/// `Identifiable` wrapper so a request id can drive `.sheet(item:)`.
struct PresentedVerification: Identifiable {
    let id: VerificationRequestID
}

/// Builds the verification view model once per presentation.
struct VerificationSheetHost: View {
    @State private var model: VerificationViewModel

    init(id: VerificationRequestID) {
        let environment = AppEnvironment.shared
        _model = State(initialValue: VerificationViewModel(
            id: id, api: environment.verifyAPI, wallet: PassKitWalletIdentity(), document: DocumentVerificationLauncher.shared,
            lock: AppEnvironment.services.appLock))
    }

    var body: some View { VerificationRequestSheet(model: model) }
}
