import SwiftUI
import ViadereCore
import ViadereKit

// INTEGRATION SLOTS (docs/APP-IA.md, "Reserved places").
//
// These are the destinations the IA reserves for work that lands separately. Each is reached from its final place in the hierarchy
// already, so wiring one is a one-line change: replace the body with the real view and keep the type (or change the one call site named
// below). They are deliberately plain until then.

/// You → Appearance. Owner: the appearance/themes work (an appearance picker view: light, dark, system and themes).
/// Call site: `SettingsView.screen(_:)`, `case .appearance`.
struct AppearanceSettingsSlot: View {
    let model: AppModel

    var body: some View {
        SubScreen(title: "Appearance", subtitle: "Light, dark and theme") {
            // INTEGRATION SLOT (themes): replace with the appearance picker.
            ViadereEmptyState("Appearance", message: "Viadere follows your iPhone's light and dark setting.")
        }
    }
}

/// Businesses → Discover → Loop directory. Owner: the Loops work (a directory of Loops to add, "Your Loops").
/// Call site: `BusinessesView.discover`.
struct LoopDirectorySlot: View {
    let model: AppModel

    var body: some View {
        SubScreen(title: "Loop directory", subtitle: "Requests and tools businesses build on Viadere", backTitle: "Businesses") {
            // INTEGRATION SLOT (loops): replace with the Loop directory.
            ViadereEmptyState("Coming soon", message: "Loops your businesses offer appear on their pages under Requests.")
        }
    }
}

/// Businesses → Discover → Your Loops. Owner: the Loops work.
/// Call site: `BusinessesView.discover`.
struct YourLoopsSlot: View {
    let model: AppModel

    var body: some View {
        SubScreen(title: "Your Loops", subtitle: "The Loops you've added", backTitle: "Businesses") {
            // INTEGRATION SLOT (loops): replace with "Your Loops".
            ViadereEmptyState("No Loops yet", message: "When you add a Loop from a business, it appears here.")
        }
    }
}
