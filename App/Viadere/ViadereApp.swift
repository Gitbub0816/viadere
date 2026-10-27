import SwiftUI
import ViadereKit

@main
struct ViadereApp: App {
    @UIApplicationDelegateAdaptor(AppDelegate.self) private var delegate
    @Environment(\.scenePhase) private var scenePhase

    var body: some Scene {
        WindowGroup {
            RootView(model: AppEnvironment.shared.model, capture: AppEnvironment.shared.captureObserver)
                .onOpenURL { url in
                    Task { await AppEnvironment.shared.model.open(url: url) }
                }
                .onContinueUserActivity(NSUserActivityTypeBrowsingWeb) { activity in
                    guard let url = activity.webpageURL else { return }
                    Task { await AppEnvironment.shared.model.open(url: url) }
                }
        }
        .onChange(of: scenePhase) { _, phase in
            let model = AppEnvironment.shared.model
            switch phase {
            case .background: model.sceneDidEnterBackground()
            case .active: Task { await model.sceneWillEnterForeground() }
            default: break
            }
        }
    }
}
