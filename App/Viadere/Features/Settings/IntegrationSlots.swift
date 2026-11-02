import SwiftUI
import ViadereCore
import ViadereKit

// INTEGRATION SLOTS (docs/APP-IA.md, "Reserved places").
//
// These are the destinations the IA reserves for work that lands separately. Each is reached from its final place in the hierarchy
// already, so wiring one is a one-line change: replace the body with the real view and keep the type (or change the one call site named
// below). They are deliberately plain until then.

/// You → Appearance: the appearance picker (`AppearanceSettingsView`).
/// Call site: `SettingsView.screen(_:)`, `case .appearance`.
struct AppearanceSettingsSlot: View {
    let model: AppModel

    var body: some View {
        // Wired: the themes picker (pairings, day/night themes, Increase Contrast), persisted per device in the app group.
        AppearanceSettingsView(model: ViadereThemeRuntime.model)
    }
}

/// Businesses → Discover → Loop directory. Owner: the Loops work (a directory of Loops to add, "Your Loops").
/// Call site: `BusinessesView.discover`.
struct LoopDirectorySlot: View {
    let model: AppModel

    var body: some View {
        // Wired: the Loop directory (browse, search, categories, featured; reviewed listings only).
        LoopDirectoryView(model: model, backTitle: "Businesses")
    }
}

/// Businesses → Discover → Your Loops. Owner: the Loops work.
/// Call site: `BusinessesView.discover`.
struct YourLoopsSlot: View {
    let model: AppModel

    var body: some View {
        // Wired: the Loops this person installed, with their open requests and uninstall.
        InstalledLoopsView(model: model, backTitle: "Businesses")
    }
}
