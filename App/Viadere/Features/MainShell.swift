import SwiftUI
import ViadereKit

extension AppTab {
    var title: String {
        switch self {
        case .home: "Home"
        case .activity: "Activity"
        case .connect: "Connect"
        case .messages: "Messages"
        case .settings: "Settings"
        }
    }

    var symbol: String {
        switch self {
        case .home: "house"
        case .activity: "clock"
        case .connect: "plus.circle"
        case .messages: "bubble.left"
        case .settings: "slider.horizontal.3"
        }
    }
}

/// Four tabs on a hand-built bar. Each tab keeps its own `NavigationStack` (system bar hidden).
struct MainShell: View {
    @Bindable var model: AppModel

    var body: some View {
        VStack(spacing: 0) {
            Group {
                switch model.selectedTab {
                case .home: HomeView(model: model)
                case .activity: ActivityView(model: model)
                case .connect: ConnectView(model: model)
                case .messages: MessagesView(model: model)
                case .settings: SettingsView(model: model)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            ViadereTabBar(selection: $model.selectedTab, items: AppTab.allCases.map { tab in
                ViadereTabBar<AppTab>.Item(tab: tab, title: tab.title, symbol: tab.symbol, badge: badge(for: tab))
            })
        }
        .viadereScreenBackground()
        .task { await model.messages.load() }
        .onChange(of: model.home.content, initial: true) { _, content in
            // Keep the watch's pending list and any running Live Activities in step with Home.
            let environment = AppEnvironment.shared
            environment.watchBridge.push(content)
            Task { await environment.liveActivities.sync(content.statuses) }
        }
        .onChange(of: model.activity.liveCandidates) { _, candidates in
            // Only statuses `LiveActivityPolicy` allows (ongoing orders, deliveries, flights, appointments; never marketing).
            Task { await AppEnvironment.shared.liveActivities.sync(candidates) }
        }
    }

    private func badge(for tab: AppTab) -> Int {
        switch tab {
        case .home: model.home.content.pending.count
        case .activity: model.activity.needsYouCount
        case .messages: model.messages.unreadTotal
        default: 0
        }
    }
}
