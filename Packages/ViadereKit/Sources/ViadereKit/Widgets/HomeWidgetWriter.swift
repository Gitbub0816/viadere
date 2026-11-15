import Foundation
import ViadereCore

/// The app's side of the Home Screen widget: turns what the app already loaded into a `WidgetSnapshot` (numbers and times only) and
/// asks WidgetKit to redraw only when what the widget shows changed.
///
/// Two sources feed it, each at its own pace: the Alerts read model and the benefits overview (after `AppModel.refreshOrganization`), and
/// the deliveries inbox (after the Alerts screen refreshes it). The writer keeps the last expiries of each and writes them together, so
/// neither source erases the other's count. It never sees a business name, a request type, an amount, a code or message text: it reads
/// expiries and counts from the view models and nothing else.
@MainActor
public final class HomeWidgetWriter {
    private let store: WidgetSnapshotStore
    private let reload: @MainActor @Sendable () -> Void
    private let clock: @Sendable () -> Date
    private var alertExpiries: [Date?] = []
    private var deliveryExpiries: [Date] = []
    private var benefitsAvailable: Int?

    /// - Parameters:
    ///   - store: the app group store (`WidgetSnapshotStore(persistence: UserDefaultsWidgetSnapshotPersistence(suiteName: …))`).
    ///   - reload: the App passes `{ WidgetCenter.shared.reloadTimelines(ofKind: WidgetSnapshot.kind) }`.
    /// `nonisolated` so the app can build it inside its (nonisolated) services graph; it only stores its arguments.
    public nonisolated init(store: WidgetSnapshotStore, clock: @escaping @Sendable () -> Date = { Date() },
                            reload: @escaping @MainActor @Sendable () -> Void) {
        self.store = store
        self.clock = clock
        self.reload = reload
    }

    /// After the Alerts and benefits refresh. `benefits` is optional: without it the widget shows no benefits line.
    public func publish(alerts: AlertsViewModel, benefits: BenefitsViewModel? = nil) {
        alertExpiries = alerts.waitingExpiries()
        benefitsAvailable = benefits.map { $0.count(.available, context: .all) }
        write()
    }

    /// After the deliveries inbox refreshes (links and codes that wait; notices ask for nothing).
    public func publish(deliveries: AuthDeliveryInboxViewModel) {
        deliveryExpiries = deliveries.waitingExpiries()
        write()
    }

    /// Sign-out, account deletion, revocation: the widget goes back to its neutral face.
    public func clear() {
        alertExpiries = []
        deliveryExpiries = []
        benefitsAvailable = nil
        if store.clear() { reload() }
    }

    private func write() {
        let waiting = alertExpiries + deliveryExpiries.map { Optional($0) }
        if store.write(waiting: waiting, benefitsAvailable: benefitsAvailable, now: clock()) { reload() }
    }
}
