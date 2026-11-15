import Foundation
import ViadereCore

// MARK: - Display copy (describes the rule; never decides eligibility)

public enum RewardCopy {
    /// "Every Tuesday", "Weekdays", "Mon, Wed and Fri". Describes the business's rule for the person to read.
    public static func recurrence(_ recurrence: RewardRecurrence) -> String {
        let days = Set(recurrence.weekdays.filter { (1...7).contains($0) }).sorted()
        guard !days.isEmpty else { return "" }
        let long = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        let short = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        let text: String
        if days == [1, 2, 3, 4, 5] {
            text = "Weekdays"
        } else if days == [6, 7] {
            text = "Weekends"
        } else if days.count == 7 {
            text = "Every day"
        } else if days.count == 1 {
            text = "Every \(long[days[0] - 1])"
        } else {
            let names = days.map { short[$0 - 1] }
            text = names.dropLast().joined(separator: ", ") + " and " + (names.last ?? "")
        }
        return recurrence.perDayLimit > 1 ? "\(text) · up to \(recurrence.perDayLimit) a day" : text
    }

    public static func points(_ value: Int) -> String {
        let formatted = value.formatted(.number.grouping(.automatic))
        return value == 1 ? "1 point" : "\(formatted) points"
    }
}

/// How one reward row reads: a status line and whether to offer the primary action.
public struct RewardRowPresentation: Equatable, Sendable {
    public enum Tone: Sendable, Equatable { case available, waiting, finished }

    public var statusLine: String
    public var tone: Tone
    /// The server's action when (and only when) the server says the reward is eligible and the check is fresh.
    public var action: RewardEligibility.Action
    /// The verdict is old enough that the screen should refresh before offering the action.
    public var needsRefresh: Bool

    /// A verdict older than this is re-fetched before its action is offered. This is freshness, not eligibility.
    public static let freshness: TimeInterval = 300

    /// - Parameter fetchedAt: when *this device* received the verdict (device clock to device clock, so a skewed
    ///   clock can't hide or show actions; the server re-checks every claim and redemption regardless).
    public init(_ entry: RewardEntry, now: Date, fetchedAt: Date, timeZone: TimeZone = .current) {
        let e = entry.eligibility
        needsRefresh = now.timeIntervalSince(fetchedAt) > Self.freshness
        switch e.state {
        case .eligible:
            tone = .available
            if let until = entry.reward.validUntil { statusLine = "Available · until \(Self.day(until, timeZone))" } else { statusLine = "Available now" }
            action = e.nextAction
        case .notToday:
            tone = .waiting
            statusLine = e.nextEligibleAt.map { "Next available \(Self.day($0, timeZone))" } ?? "Not available today"
            action = .none
        case .limitReached:
            tone = .waiting
            statusLine = e.nextEligibleAt.map { "Used for now · back \(Self.day($0, timeZone))" } ?? "Used for now"
            action = .none
        case .notYetValid:
            tone = .waiting
            statusLine = (e.nextEligibleAt ?? entry.reward.validFrom).map { "Starts \(Self.day($0, timeZone))" } ?? "Not active yet"
            action = .none
        case .insufficientPoints:
            tone = .waiting
            statusLine = e.pointsShortfall.map { "\(RewardCopy.points($0)) to go" } ?? "Not enough points yet"
            action = .none
        case .redeemed:
            tone = .finished
            statusLine = entry.reward.redeemedAt.map { "Redeemed \(Self.day($0, timeZone))" } ?? "Redeemed"
            action = .none
        case .expired:
            tone = .finished
            statusLine = "Expired"
            action = .none
        case .revoked:
            tone = .finished
            statusLine = "No longer available"
            action = .none
        case .unavailable:
            tone = .waiting
            statusLine = "Not available right now"
            action = .none
        }
        // Even a server-eligible verdict never shows an action while it is stale.
        if needsRefresh { action = .none }
    }

    static func day(_ date: Date, _ zone: TimeZone) -> String {
        var style = Date.FormatStyle(date: .abbreviated, time: .omitted)
        style.timeZone = zone
        return date.formatted(style)
    }

    public var actionTitle: String? {
        switch action {
        case .claim: "Claim"
        case .redeem: "Use now"
        case .none: nil
        }
    }
}
