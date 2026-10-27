import SwiftUI
import ViadereKit

extension AppTab {
    var title: String {
        switch self {
        case .home: "Home"
        case .connect: "Connect"
        case .messages: "Messages"
        case .settings: "Settings"
        }
    }

    var symbol: String {
        switch self {
        case .home: "house"
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
    }

    private func badge(for tab: AppTab) -> Int {
        switch tab {
        case .home: model.home.content.pending.count
        case .messages: model.messages.unreadTotal
        default: 0
        }
    }
}
