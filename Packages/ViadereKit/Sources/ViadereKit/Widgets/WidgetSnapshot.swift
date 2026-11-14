import Foundation
import ViadereCore

// Home Screen widgets (small and medium; Core's `widget_small` / `widget_medium` templates name the sizes).
//
// A widget is drawn outside the app, can sit on a screen a stranger sees, and is rendered by a process that holds no session and no
// keys. So the only thing the app shares with it is **numbers**: how many requests wait (and until when each stops waiting), and
// optionally how many benefits are available. No business name, no request type, no amount, code, message text or identifier ever
// enters the snapshot; the type has no field that could hold one, and the tests pin its encoded keys.

/// What the app writes to the app group for the widget. Numbers and times only.
public struct WidgetSnapshot: Codable, Sendable, Equatable {
    /// The WidgetKit kind of the requests widget.
    public static let kind = "com.viadere.widget.requests"
    public static let maxCount = 99
    /// A snapshot older than this says nothing reliable any more (the app has not run): the widget falls back to its neutral face.
    public static let staleAfter: TimeInterval = 24 * 3_600

    /// When each waiting request stops waiting (its expiry), soonest first. At most `maxCount`.
    public var waitingUntil: [Date]
    /// Waiting requests without an expiry.
    public var waitingOpenEnded: Int
    /// Benefits available now; `nil` when the app does not know (the line is omitted).
    public var benefitsAvailable: Int?
    public var updatedAt: Date

    /// - Parameter waiting: one element per waiting request: its expiry, or `nil` when it has none. Already-expired ones are dropped.
    public init(waiting: [Date?], benefitsAvailable: Int? = nil, now: Date) {
        let dated = waiting.compactMap { $0 }.filter { $0 > now }.sorted()
        waitingUntil = Array(dated.prefix(Self.maxCount))
        waitingOpenEnded = min(max(0, waiting.filter { $0 == nil }.count), Self.maxCount)
        self.benefitsAvailable = benefitsAvailable.map { min(max(0, $0), Self.maxCount) }
        updatedAt = now
    }

    /// How many requests wait at `date`.
    public func waitingCount(at date: Date) -> Int {
        min(Self.maxCount, waitingOpenEnded + waitingUntil.filter { $0 > date }.count)
    }

    public func isStale(at date: Date) -> Bool { date.timeIntervalSince(updatedAt) >= Self.staleAfter || date < updatedAt.addingTimeInterval(-300) }

    /// Equal for the widget's purposes (the write time alone is not a change).
    func sameContent(as other: WidgetSnapshot) -> Bool {
        waitingUntil == other.waitingUntil && waitingOpenEnded == other.waitingOpenEnded && benefitsAvailable == other.benefitsAvailable
    }

    enum CodingKeys: String, CodingKey { case waitingUntil = "u", waitingOpenEnded = "o", benefitsAvailable = "b", updatedAt = "t" }
}

/// Where the snapshot is kept: the app group's defaults (`group.com.viadere.shared`), which the widget extension reads.
public protocol WidgetSnapshotPersistence: Sendable {
    func load() -> Data?
    func save(_ data: Data?)
}

public final class UserDefaultsWidgetSnapshotPersistence: WidgetSnapshotPersistence, @unchecked Sendable {
    public static let key = "com.viadere.widget.snapshot.v1"
    private let defaults: UserDefaults

    /// - Parameter suiteName: the app group id; `.standard` when it is empty or unavailable.
    public init(suiteName: String?) {
        defaults = suiteName.flatMap { $0.isEmpty ? nil : UserDefaults(suiteName: $0) } ?? .standard
    }

    public func load() -> Data? { defaults.data(forKey: Self.key) }
    public func save(_ data: Data?) {
        if let data { defaults.set(data, forKey: Self.key) } else { defaults.removeObject(forKey: Self.key) }
    }
}

public final class InMemoryWidgetSnapshotPersistence: WidgetSnapshotPersistence, @unchecked Sendable {
    private let lock = NSLock()
    private var data: Data?
    public init(_ data: Data? = nil) { self.data = data }
    public func load() -> Data? { lock.withLock { data } }
    public func save(_ data: Data?) { lock.withLock { self.data = data } }
}

/// Reads and writes the snapshot. The app writes (and clears on sign-out); the widget only reads.
public struct WidgetSnapshotStore: Sendable {
    private let persistence: any WidgetSnapshotPersistence

    public init(persistence: any WidgetSnapshotPersistence) { self.persistence = persistence }

    /// `nil` when nothing was written (signed out, first launch) or what is stored cannot be read.
    public func read() -> WidgetSnapshot? {
        guard let data = persistence.load(), data.count <= 16_384, let snapshot = try? JSONDecoder().decode(WidgetSnapshot.self, from: data),
              snapshot.waitingUntil.count <= WidgetSnapshot.maxCount, (0...WidgetSnapshot.maxCount).contains(snapshot.waitingOpenEnded),
              snapshot.benefitsAvailable.map({ (0...WidgetSnapshot.maxCount).contains($0) }) ?? true else { return nil }
        return snapshot
    }

    /// Writes the snapshot. Returns whether what the widget shows changed (the caller then reloads the widget's timeline).
    @discardableResult
    public func write(waiting: [Date?], benefitsAvailable: Int? = nil, now: Date) -> Bool {
        let next = WidgetSnapshot(waiting: waiting, benefitsAvailable: benefitsAvailable, now: now)
        // Nothing new and written within the hour: no write, no reload. (The hourly rewrite keeps a used app's snapshot from going stale.)
        if let previous = read(), previous.sameContent(as: next), !previous.isStale(at: now), now.timeIntervalSince(previous.updatedAt) < 3_600 {
            return false
        }
        guard let data = try? JSONEncoder().encode(next) else { return false }
        persistence.save(data)
        return true
    }

    /// Sign-out: the widget goes back to its neutral face. Returns whether there was something to clear.
    @discardableResult
    public func clear() -> Bool {
        let had = persistence.load() != nil
        persistence.save(nil)
        return had
    }
}

/// One moment of the widget, as plain data and Viadere's own words.
public struct WidgetEntryContent: Sendable, Equatable {
    public enum State: Sendable, Equatable {
        /// Nothing is known (signed out, never opened, or the snapshot is too old): the mark and "Open Viadere".
        case neutral
        /// The app knows that nothing waits.
        case clear
        case waiting(Int)
    }

    public var date: Date
    public var state: State
    /// The large figure (`nil` unless something waits).
    public var count: String?
    public var headline: String
    /// The medium size's second line; `nil` when there is nothing to add.
    public var benefitsLine: String?
    public var accessibilityLabel: String

    public init(date: Date, snapshot: WidgetSnapshot?) {
        self.date = date
        guard let snapshot, !snapshot.isStale(at: date) else {
            state = .neutral
            count = nil
            headline = "Open Viadere"
            benefitsLine = nil
            accessibilityLabel = "Viadere. Open Viadere."
            return
        }
        let waiting = snapshot.waitingCount(at: date)
        if waiting == 0 {
            state = .clear
            count = nil
            headline = "Nothing needs you"
        } else {
            state = .waiting(waiting)
            count = waiting >= WidgetSnapshot.maxCount ? "\(WidgetSnapshot.maxCount)+" : "\(waiting)"
            headline = waiting == 1 ? "request waiting" : "requests waiting"
        }
        if let benefits = snapshot.benefitsAvailable, benefits > 0 {
            benefitsLine = benefits == 1 ? "1 benefit available" : "\(benefits >= WidgetSnapshot.maxCount ? "\(WidgetSnapshot.maxCount)+" : "\(benefits)") benefits available"
        } else {
            benefitsLine = nil
        }
        var spoken = ["Viadere", waiting == 0 ? "Nothing needs you" : (waiting == 1 ? "1 request waiting" : "\(waiting) requests waiting")]
        if let benefitsLine { spoken.append(benefitsLine) }
        accessibilityLabel = spoken.joined(separator: ". ") + "."
    }

    /// What the widget gallery and a redacted render show: the layout with no figure.
    public static func placeholder(date: Date) -> WidgetEntryContent { WidgetEntryContent(date: date, snapshot: nil) }
}

/// The widget's timeline: the count now, a new entry each time a waiting request expires (so the figure never overstates what waits,
/// even if the app is not opened), and the neutral face once the snapshot is too old to trust.
public enum WidgetTimelineModel {
    public static let maxEntries = 24

    public static func entries(snapshot: WidgetSnapshot?, now: Date) -> [WidgetEntryContent] {
        guard let snapshot, !snapshot.isStale(at: now) else { return [WidgetEntryContent(date: now, snapshot: nil)] }
        let staleAt = snapshot.updatedAt.addingTimeInterval(WidgetSnapshot.staleAfter)
        var dates = [now]
        // Each expiry is a moment the count drops; identical moments collapse.
        for expiry in snapshot.waitingUntil where expiry > now && expiry < staleAt && dates.last != expiry { dates.append(expiry) }
        dates = Array(dates.prefix(maxEntries - 1))
        var entries = dates.map { WidgetEntryContent(date: $0, snapshot: snapshot) }
        entries.append(WidgetEntryContent(date: staleAt, snapshot: nil))
        return entries
    }
}

extension AlertsViewModel {
    /// For the widget snapshot: one element per alert that is actionable now (the same rule as the Alerts badge), carrying only its expiry.
    public func waitingExpiries() -> [Date?] {
        let now = self.now
        return all.filter { AlertRules.matches($0.item, context: .all, status: .pending, now: now) && $0.isActionable(at: now) }.map(\.expiresAt)
    }
}
