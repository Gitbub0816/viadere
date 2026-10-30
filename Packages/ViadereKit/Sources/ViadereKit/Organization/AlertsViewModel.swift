import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

/// The Alerts destination (spec C5; plan 4.8): "Needs you" and "History" (Activity lives under Alerts), filtered by the business context.
///
/// The server's list is the source of truth; pushes are hints. The cache is bounded, synced incrementally with `since`, and **never** makes
/// anything actionable on its own: every action re-checks the expiry with the device clock and is disabled while offline. Context switches
/// filter the cache locally (instant), and fetch the selected business's first page once so its older items appear too.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class AlertsViewModel {
    public var segment: AlertsSegment = .needsYou
    /// History filter (`nil` = everything that is not waiting for you).
    public var historyFilter: AlertStatusFilter?
    public var unreadOnly = false
    public private(set) var isLoading = false
    /// The last refresh failed for lack of a connection: cached items stay visible, actions are disabled.
    public private(set) var isOffline = false
    public private(set) var errorMessage: String?
    /// Whether an older page exists for the context last paged.
    public private(set) var hasMore: [OrganizationContext: Bool] = [:]

    public static let cacheLimit = 1_000
    private var cache: [String: AlertEntry] = [:]
    private var syncToken: String?
    private var cursors: [OrganizationContext: String] = [:]
    private var loadedContexts: Set<OrganizationContext> = []
    private var pushes = SeenEventSet(capacity: 512)
    private let api: (any OrganizationAPI)?
    private let clock: @Sendable () -> Date

    public init(api: (any OrganizationAPI)?, clock: @escaping @Sendable () -> Date = { Date() }, initial: [AlertEntry] = []) {
        self.api = api
        self.clock = clock
        for entry in initial { cache[entry.alertId] = entry }
    }

    public var now: Date { clock() }
    public var isEmpty: Bool { cache.isEmpty }
    public var all: [AlertEntry] { Array(cache.values) }

    // MARK: What the screen shows

    /// Waiting for the customer: pending by the device clock, newest-urgent first (deterministic: urgency, then soonest expiry, then newest).
    public func needsYou(context: OrganizationContext) -> [AlertEntry] {
        let now = clock()
        return cache.values.filter { entry in
            AlertRules.matches(entry.item, context: context, status: .pending, now: now) && (entry.actionRequired || entry.source == .securityNotice)
                && (!unreadOnly || entry.unread)
        }.sorted(by: Self.urgentFirst)
    }

    /// Everything else, newest first, optionally narrowed by status.
    public func history(context: OrganizationContext) -> [AlertEntry] {
        let now = clock()
        let pending = Set(needsYou(context: context).map(\.alertId))
        return cache.values.filter { entry in
            guard !pending.contains(entry.alertId), AlertRules.matches(entry.item, context: context, status: nil, now: now) else { return false }
            if let historyFilter, !AlertRules.matches(entry.item, context: context, status: historyFilter, now: now) { return false }
            return !unreadOnly || entry.unread
        }.sorted { $0.createdAt != $1.createdAt ? $0.createdAt > $1.createdAt : $0.alertId < $1.alertId }
    }

    public func visible(context: OrganizationContext) -> [AlertEntry] {
        segment == .needsYou ? needsYou(context: context) : history(context: context)
    }

    /// The Alerts badge: what is actionable now (the server's verdict re-checked by the device clock), never informational items.
    public func badgeCount(context: OrganizationContext = .all) -> Int {
        let now = clock()
        return cache.values.filter { AlertRules.matches($0.item, context: context, status: .pending, now: now) && $0.isActionable(at: now) }.count
    }

    /// Whether the item may show its action now: never offline, never expired or finished, never from a business that is not verified.
    public func canAct(_ entry: AlertEntry) -> Bool { !isOffline && entry.isActionable(at: clock()) }

    /// The status to show (a pending item past its expiry reads "Expired" even before the next sync).
    public func displayStatus(_ entry: AlertEntry) -> AlertStatus { AlertRules.displayStatus(entry.item, now: clock()) }

    static func urgentFirst(_ a: AlertEntry, _ b: AlertEntry) -> Bool {
        func rank(_ u: AlertUrgency) -> Int {
            switch u {
            case .critical: 0
            case .timeSensitive: 1
            case .normal: 2
            case .unknown: 3
            }
        }
        if a.purpose == .security, b.purpose != .security { return true }
        if b.purpose == .security, a.purpose != .security { return false }
        if rank(a.urgency) != rank(b.urgency) { return rank(a.urgency) < rank(b.urgency) }
        let ae = a.expiresAt ?? .distantFuture, be = b.expiresAt ?? .distantFuture
        if ae != be { return ae < be }
        if a.createdAt != b.createdAt { return a.createdAt > b.createdAt }
        return a.alertId < b.alertId
    }

    // MARK: Loading

    /// First load: the newest page across all businesses. Later calls sync incrementally (`since`).
    public func refresh() async {
        guard let api else { return }
        isLoading = cache.isEmpty
        defer { isLoading = false }
        do {
            if let token = syncToken {
                var page = try await api.alerts(AlertQuery(since: SyncToken.decode(token), limit: AlertQuery.maxLimit))
                merge(page.items)
                // A burst of changes larger than one page: keep following the cursor.
                var guardPages = 0
                while let cursor = page.nextCursor.flatMap(AlertCursor.init(encoded:)), guardPages < 10 {
                    page = try await api.alerts(AlertQuery(cursor: cursor, since: SyncToken.decode(token), limit: AlertQuery.maxLimit))
                    merge(page.items)
                    guardPages += 1
                }
                syncToken = page.syncToken
            } else {
                let page = try await api.alerts(AlertQuery(limit: AlertQuery.maxLimit))
                merge(page.items)
                syncToken = page.syncToken
                cursors[.all] = page.nextCursor
                hasMore[.all] = page.nextCursor != nil
                loadedContexts.insert(.all)
            }
            isOffline = false
            errorMessage = nil
        } catch {
            note(error)
        }
    }

    /// The selected business's first page, once (its older items may not be in the All page).
    public func ensureLoaded(_ context: OrganizationContext) async {
        guard let api, !loadedContexts.contains(context), let business = context.businessFilter else { return }
        do {
            let page = try await api.alerts(AlertQuery(businessId: business, limit: AlertQuery.maxLimit))
            merge(page.items)
            cursors[context] = page.nextCursor
            hasMore[context] = page.nextCursor != nil
            loadedContexts.insert(context)
            isOffline = false
        } catch {
            note(error)
        }
    }

    /// The next older page for `context`.
    public func loadMore(_ context: OrganizationContext) async {
        guard let api, let raw = cursors[context], let cursor = AlertCursor(encoded: raw) else { return }
        do {
            let page = try await api.alerts(AlertQuery(businessId: context.businessFilter, cursor: cursor, limit: AlertQuery.maxLimit))
            merge(page.items)
            cursors[context] = page.nextCursor
            hasMore[context] = page.nextCursor != nil
        } catch {
            note(error)
        }
    }

    /// Marks rows seen (optimistically; a failure only means they show as unread again next time).
    public func markSeen(_ entries: [AlertEntry]) async {
        let ids = entries.filter(\.unread).map(\.alertId)
        guard !ids.isEmpty else { return }
        for id in ids { cache[id]?.unread = false }
        for chunk in stride(from: 0, to: ids.count, by: AlertSeenRequest.maxIds) {
            try? await api?.markAlertsSeen(Array(ids[chunk..<min(chunk + AlertSeenRequest.maxIds, ids.count)]))
        }
    }

    // MARK: Pushes (best effort; deduped by server event id)

    /// Whether a push for `eventId` should be presented: not if the same event was already shown, nor if the list already knows the item is
    /// finished. The list, not the push, stays the source of truth: a refresh follows either way.
    public func shouldPresentPush(eventId: String) -> Bool {
        if let known = cache.values.first(where: { $0.eventId == eventId }), displayStatus(known) != .pending { return false }
        return pushes.insert(eventId)
    }

    /// An item was answered or dismissed elsewhere in the app: reflect it at once (the next sync confirms it).
    public func markHandled(alertId: String, status: AlertStatus = .completed) {
        guard var entry = cache[alertId] else { return }
        entry.status = status
        entry.actionable = false
        entry.updatedAt = clock()
        cache[alertId] = entry
    }

    /// A business ended: its rows leave the cache.
    public func forget(business: BusinessID) {
        cache = cache.filter { $0.value.business?.id != business }
        loadedContexts.remove(.business(business))
        cursors[.business(business)] = nil
    }

    /// Sign-out: nothing survives.
    public func reset() {
        cache = [:]
        syncToken = nil
        cursors = [:]
        loadedContexts = []
        hasMore = [:]
        pushes = SeenEventSet(capacity: 512)
        isOffline = false
        errorMessage = nil
    }

    func merge(_ items: [AlertEntry]) {
        for item in items { cache[item.alertId] = item }
        guard cache.count > Self.cacheLimit else { return }
        // Evict the oldest finished items first, then the oldest of anything; pending items are evicted last.
        let now = clock()
        let ordered = cache.values.sorted { a, b in
            let ap = AlertRules.displayStatus(a.item, now: now) == .pending, bp = AlertRules.displayStatus(b.item, now: now) == .pending
            if ap != bp { return !ap }
            return a.createdAt < b.createdAt
        }
        for entry in ordered.prefix(cache.count - Self.cacheLimit) { cache[entry.alertId] = nil }
    }

    private func note(_ error: any Error) {
        if let api = error as? APIError, case .transport = api {
            isOffline = true
            errorMessage = "You're offline. Showing what was last loaded."
        } else if (error as? URLError) != nil {
            isOffline = true
            errorMessage = "You're offline. Showing what was last loaded."
        } else {
            errorMessage = (error as? APIError)?.userMessage ?? "Couldn't load your alerts."
        }
    }
}
