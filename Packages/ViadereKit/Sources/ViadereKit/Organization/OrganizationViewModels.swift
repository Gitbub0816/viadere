import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

private func message(for error: any Error, _ fallback: String) -> String { (error as? APIError)?.userMessage ?? fallback }

// MARK: - Benefits (spec C6)

/// Coupons, rewards and loyalty in one place, filtered by the business context and by available / saved / redeemed / expired / eligible.
/// Loaded once across businesses and filtered locally, so switching context or filter is instant; eligibility always comes from the server.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class BenefitsViewModel {
    public var filter: BenefitFilter? = .available
    public private(set) var overview = RewardsOverview()
    public private(set) var isLoading = false
    public private(set) var errorMessage: String?
    private let api: (any OrganizationAPI)?

    public init(api: (any OrganizationAPI)?, initial: RewardsOverview = RewardsOverview()) {
        self.api = api
        overview = initial
    }

    public func rewards(context: OrganizationContext) -> [RewardEntry] {
        BenefitRules.sorted(overview.rewards.filter { entry in
            (context.businessFilter == nil || entry.business.id == context.businessFilter) && BenefitRules.matches(entry, filter: filter)
        })
    }

    public func accounts(context: OrganizationContext) -> [LoyaltyAccount] {
        overview.accounts.filter { context.businessFilter == nil || $0.business.id == context.businessFilter }
    }

    /// The count the filter chip shows for each filter in `context`.
    public func count(_ filter: BenefitFilter?, context: OrganizationContext) -> Int {
        overview.rewards.filter { (context.businessFilter == nil || $0.business.id == context.businessFilter) && BenefitRules.matches($0, filter: filter) }.count
    }

    public func load() async {
        guard let api else { return }
        isLoading = overview.rewards.isEmpty && overview.accounts.isEmpty
        defer { isLoading = false }
        do {
            overview = try await api.benefits(filter: nil, business: nil)
            errorMessage = nil
        } catch {
            errorMessage = message(for: error, "Couldn't load your benefits.")
        }
    }

    public func reset() { overview = RewardsOverview() }
}

// MARK: - Businesses directory (spec C3, C8)

/// The connected businesses: favorites first, then recent activity; local search over names and handles (the customer's own connections
/// only). Fifty businesses are one list with search, never fifty tabs.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class BusinessesViewModel {
    public var query = ""
    public private(set) var directory: [ConnectedBusiness] = []
    public private(set) var isLoading = false
    public private(set) var hasLoaded = false
    public private(set) var errorMessage: String?
    private let api: (any OrganizationAPI)?
    /// Called with every successful load (the context store's selector options follow it).
    public var onChange: (([ConnectedBusiness]) -> Void)?

    public init(api: (any OrganizationAPI)?, initial: [ConnectedBusiness] = []) {
        self.api = api
        directory = BusinessDirectoryRules.ordered(initial)
    }

    public var active: [ConnectedBusiness] { directory.filter(\.isActive) }
    public var favorites: [ConnectedBusiness] { active.filter(\.preferences.favorite) }

    /// The directory rows for the current search: active connections first (favorites on top), ended ones after them.
    public var results: [ConnectedBusiness] { directory.filter { BusinessDirectoryRules.matches($0.business, query: query) } }

    public func entry(_ id: BusinessID) -> ConnectedBusiness? { directory.first { $0.business.id == id } }

    public func load() async {
        guard let api else { return }
        isLoading = directory.isEmpty
        defer { isLoading = false }
        do {
            directory = BusinessDirectoryRules.ordered(try await api.businesses())
            hasLoaded = true
            errorMessage = nil
            onChange?(directory)
        } catch {
            errorMessage = message(for: error, "Couldn't load your businesses.")
        }
    }

    /// Optimistic favorite toggle, rolled back when the server refuses.
    public func setFavorite(_ id: BusinessID, _ favorite: Bool) async {
        guard let api, let index = directory.firstIndex(where: { $0.business.id == id }) else { return }
        let previous = directory[index].preferences
        directory[index].preferences.favorite = favorite
        directory = BusinessDirectoryRules.ordered(directory)
        do {
            let saved = try await api.updatePreferences(business: id, BusinessPreferencesUpdate(favorite: favorite))
            apply(saved)
        } catch {
            if let i = directory.firstIndex(where: { $0.business.id == id }) { directory[i].preferences = previous }
            directory = BusinessDirectoryRules.ordered(directory)
            errorMessage = message(for: error, "Couldn't save that change.")
        }
    }

    /// Reflects preferences saved elsewhere (the business settings screen).
    public func apply(_ preferences: BusinessPreferences) {
        guard let index = directory.firstIndex(where: { $0.business.id == preferences.businessId }) else { return }
        directory[index].preferences = preferences
        if preferences.blocked { directory[index].status = .disconnected }
        directory = BusinessDirectoryRules.ordered(directory)
        onChange?(directory)
    }

    public func reset() {
        directory = []
        hasLoaded = false
        query = ""
    }
}

// MARK: - Per-business settings (spec C7.2, WP-1.5)

@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class BusinessPreferencesViewModel {
    public let business: BusinessSummary
    public private(set) var preferences: BusinessPreferences
    public private(set) var isSaving = false
    public private(set) var errorMessage: String?
    private let api: (any OrganizationAPI)?
    private let clock: @Sendable () -> Date
    /// Called after every successful save.
    public var onSaved: ((BusinessPreferences) -> Void)?

    public init(business: BusinessSummary, initial: BusinessPreferences? = nil, api: (any OrganizationAPI)?, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.business = business
        preferences = initial ?? BusinessPreferences(businessId: business.id)
        self.api = api
        self.clock = clock
    }

    /// The mute in force now (a timed mute that ended reads as none).
    public var effectiveMute: MuteLevel { preferences.effectiveMute(at: clock()) }

    /// Timed mutes the screen offers.
    public enum MuteDuration: String, CaseIterable, Sendable {
        case hour, day, week, untilChanged = "until_changed"
        public var title: String {
            switch self {
            case .hour: "For 1 hour"
            case .day: "For 1 day"
            case .week: "For 1 week"
            case .untilChanged: "Until I change it"
            }
        }
        func end(from now: Date) -> Date? {
            switch self {
            case .hour: now.addingTimeInterval(3_600)
            case .day: now.addingTimeInterval(86_400)
            case .week: now.addingTimeInterval(7 * 86_400)
            case .untilChanged: nil
            }
        }
    }

    public func load() async {
        guard let api else { return }
        do {
            preferences = try await api.preferences(business: business.id)
            errorMessage = nil
        } catch {
            errorMessage = message(for: error, "Couldn't load these settings.")
        }
    }

    public func setMute(_ level: MuteLevel, for duration: MuteDuration = .untilChanged) async {
        await save(BusinessPreferencesUpdate(muteLevel: level, muteUntil: level == MuteLevel.none ? nil : duration.end(from: clock())))
    }

    public func setFavorite(_ favorite: Bool) async { await save(BusinessPreferencesUpdate(favorite: favorite)) }

    /// Ends the connection and refuses new ones from this business until unblocked (the screen confirms first).
    public func block() async { await save(BusinessPreferencesUpdate(blocked: true)) }
    public func unblock() async { await save(BusinessPreferencesUpdate(blocked: false)) }

    private func save(_ update: BusinessPreferencesUpdate) async {
        guard let api, !isSaving else { return }
        isSaving = true
        defer { isSaving = false }
        do {
            preferences = try await api.updatePreferences(business: business.id, update)
            errorMessage = nil
            onSaved?(preferences)
        } catch {
            errorMessage = message(for: error, "Couldn't save that change.")
        }
    }
}

// MARK: - Business home (spec C6.2, WP-1.6)

/// A business home composed from Viadere's standard modules. It renders **immediately** with Viadere's default layout (no network, no
/// branding) and adopts the business's published order when it arrives; whatever the server sends goes through `SurfaceLayout.renderable`.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class BusinessHomeViewModel {
    public let business: BusinessSummary
    public private(set) var modules: [SurfaceModule] = SurfaceLayout.renderable(SurfaceLayout.defaultBusinessHome.wireModules)
    public private(set) var version = 0
    private let api: (any OrganizationAPI)?

    public init(business: BusinessSummary, api: (any OrganizationAPI)?) {
        self.business = business
        self.api = api
    }

    public func load() async {
        guard let api, let view = try? await api.surface(business: business.id), view.business.id == business.id else { return }
        modules = SurfaceLayout.renderable(view.modules)
        version = view.version
    }
}
