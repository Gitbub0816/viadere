import SwiftUI
import ViadereCore
import ViadereKit

/// Which Loop instance is open, and the consent prompts the Loop entry points need (business page, Alerts, `viadere.loop` notifications).
/// `MainShell` presents the sheets.
@MainActor
@Observable
final class LoopCenter {
    struct Presented: Identifiable, Equatable {
        let id: LoopInstanceID
        /// The instance as just returned by `POST /v1/loops/instances` (saves a round trip); `nil` = fetch it.
        let initial: LoopInstanceView?

        static func == (a: Presented, b: Presented) -> Bool { a.id == b.id }
    }

    /// The consent step a start attempt needs first.
    enum ConsentPrompt: Identifiable, Equatable {
        case enableLoops
        case authorize(BusinessSummary)

        var id: String {
            switch self {
            case .enableLoops: "enable"
            case .authorize(let business): "authorize.\(business.id)"
            }
        }
    }

    var presented: Presented?
    var consentPrompt: ConsentPrompt?

    func present(_ id: LoopInstanceID, initial: LoopInstanceView? = nil) {
        presented = Presented(id: id, initial: initial)
    }

    /// Starts `summary` from a business page: both consents first (on the device too), then the instance sheet.
    func start(_ summary: LoopSummary, business: BusinessSummary, catalog: LoopCatalogViewModel, model: AppModel) async {
        switch await catalog.start(summary) {
        case .started(let view):
            model.organization.open(itemFrom: business.id)
            present(view.id, initial: view)
        case .needsConsent(let decision):
            switch decision {
            case .needsGlobalConsent: consentPrompt = .enableLoops
            case .needsBusinessAuthorization: consentPrompt = .authorize(business)
            case .unavailable, .allowed: model.toast = "This isn't available right now."
            }
        case .failed(let message):
            model.toast = message
        }
    }

    /// A `viadere.loop` notification (opaque: no business, no content).
    func handle(_ route: LoopNotificationRoute, model: AppModel) async {
        switch route {
        case .instance(let id):
            present(id)
        case .alerts:
            model.selectedTab = .alerts
            await model.alerts.refresh()
        }
    }
}
