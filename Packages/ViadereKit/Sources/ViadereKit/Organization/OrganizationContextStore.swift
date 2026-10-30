import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

/// The customer's business context (spec C1, C3.5, C9.7; plan 4.8): **All** by default or one connected business, persisted locally for
/// convenience and sent to the server only as a filter. A push or deep link for another business shows it temporarily ("Showing {name}"
/// with "Back to all") without rewriting the saved choice, and nothing changes the context while an approval or verification is open.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class OrganizationContextStore {
    public private(set) var state: OrganizationContextState
    /// Active connections by id (the selector's options; a context naming anything else is refused).
    public private(set) var businesses: [BusinessID: BusinessSummary] = [:]
    /// Selector order: favorites first, then recent activity (`BusinessDirectoryRules`).
    public private(set) var order: [BusinessID] = []
    private let preferences: any PreferencesStore

    public init(preferences: any PreferencesStore) {
        self.preferences = preferences
        let saved = preferences.string(.organizationContext).flatMap { try? ViadereJSON.decode(OrganizationContext.self, from: Data($0.utf8)) }
        state = OrganizationContextState(saved: saved ?? .default)
    }

    public var effective: OrganizationContext { state.effective }
    public var saved: OrganizationContext { state.saved }
    public var isSensitiveFlowOpen: Bool { state.sensitiveFlowOpen }
    public var connected: Set<BusinessID> { Set(businesses.keys) }

    /// The business the lists are narrowed to, if any.
    public var selectedBusiness: BusinessSummary? { effective.businessFilter.flatMap { businesses[$0] } }
    /// The business shown temporarily because a push or link for it was opened.
    public var temporaryBusiness: BusinessSummary? { state.temporary.flatMap { businesses[$0] } }

    /// Selector label.
    public var title: String { selectedBusiness?.displayName ?? "All businesses" }
    /// What the single adjustable selector element announces (plan 4.8 accessibility).
    public var accessibilityValue: String { selectedBusiness.map { "Showing \($0.displayName)" } ?? "Showing all businesses" }

    /// The selector's options in order: All, then the connected businesses.
    public var options: [OrganizationContext] { [.all] + order.map(OrganizationContext.business) }

    public func summary(for id: BusinessID) -> BusinessSummary? { businesses[id] }

    // MARK: Changes

    /// An explicit choice in the selector. Persisted.
    @discardableResult
    public func select(_ context: OrganizationContext) -> OrganizationContextState.ChangeResult {
        let result = state.select(context, connected: connected)
        if result == .changed { persist() }
        return result
    }

    /// The selector's VoiceOver increment / decrement: moves through All and the businesses in order.
    @discardableResult
    public func adjust(by delta: Int) -> OrganizationContextState.ChangeResult {
        let all = options
        guard !all.isEmpty else { return .unchanged }
        let current = all.firstIndex(of: saved) ?? 0
        let next = min(max(current + delta, 0), all.count - 1)
        guard next != current else { return .unchanged }
        return select(all[next])
    }

    /// A push, deep link, approval or verification for `business` was opened while browsing something else.
    @discardableResult
    public func open(itemFrom business: BusinessID) -> OrganizationContextState.ChangeResult { state.open(itemFrom: business, connected: connected) }

    /// "Back to all" on the temporary banner.
    @discardableResult
    public func returnToSaved() -> OrganizationContextState.ChangeResult { state.returnToSaved() }

    public func beginSensitiveFlow() { state.beginSensitiveFlow() }
    public func endSensitiveFlow() { state.endSensitiveFlow() }

    /// The Businesses directory was (re)loaded: the selector offers exactly the active connections. A saved context naming a business that
    /// is no longer connected falls back to All.
    public func update(directory: [ConnectedBusiness]) {
        let active = BusinessDirectoryRules.ordered(directory).filter(\.isActive)
        let previous = Set(businesses.keys)
        businesses = Dictionary(active.map { ($0.business.id, $0.business) }, uniquingKeysWith: { a, _ in a })
        order = active.map(\.business.id)
        var gone = previous.subtracting(businesses.keys)
        if let savedBusiness = saved.businessFilter, businesses[savedBusiness] == nil { gone.insert(savedBusiness) }
        if let temporary = state.temporary, businesses[temporary] == nil { gone.insert(temporary) }
        for id in gone { state.businessDisconnected(id) }
        persist()
    }

    /// Sign-out or a wiped device: back to All, nothing remembered.
    public func reset() {
        state = OrganizationContextState(saved: .default)
        businesses = [:]
        order = []
        preferences.setString(nil, for: .organizationContext)
    }

    private func persist() {
        if saved == .all {
            preferences.setString(nil, for: .organizationContext)
        } else if let data = try? ViadereJSON.encode(saved) {
            preferences.setString(String(decoding: data, as: UTF8.self), for: .organizationContext)
        }
    }
}
