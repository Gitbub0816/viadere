import Foundation
import ViadereCore

/// Everything the eligibility verdict depends on, gathered by `RewardsService`. Pure data: the evaluator below never touches
/// the database, the device clock or anything the client sent.
struct RewardFacts {
    var kind: RewardKind
    var revoked: Bool
    var validFrom: Date?
    var validUntil: Date?
    /// ISO weekdays (1 = Monday) on which the reward applies; empty = every day.
    var weekdays: [Int]
    /// IANA zone whose midnight starts a "day" for recurrence and per-day limits.
    var timeZone: TimeZone
    var perDayLimit: Int?
    var pointsCost: Int?
    var claimedAt: Date?
    /// The consumer has consumed a redemption and the reward allows only one.
    var lifetimeRedeemed: Bool
    /// Redemptions that currently count against the limit in the current window (issued and unexpired, or consumed).
    var usageInWindow: Int
    /// The earliest expiry among unexpired issued codes in the window (a lifetime limit frees up then).
    var earliestHeldCodeExpiry: Date?
    /// Points balance, `nil` when the consumer has no account at the business.
    var pointsBalance: Int?
}

/// Eligibility is computed **only** here. Recurrence ("Tuesdays") is evaluated in the business's time zone, so a customer
/// travelling or a phone set to another zone changes nothing; DST days (23 or 25 hours) are handled by the calendar.
enum RewardEligibilityEvaluator {
    /// How far ahead `nextEligibleAt` looks for the next allowed day.
    static let lookaheadDays = 14

    static func calendar(_ zone: TimeZone) -> Calendar {
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = zone
        return calendar
    }

    /// ISO weekday: 1 = Monday … 7 = Sunday.
    static func isoWeekday(_ date: Date, in zone: TimeZone) -> Int {
        let weekday = calendar(zone).component(.weekday, from: date)
        return weekday == 1 ? 7 : weekday - 1
    }

    /// `2026-10-27` in the business's zone: the key per-day limits are counted under.
    static func dayKey(_ date: Date, in zone: TimeZone) -> String {
        let c = calendar(zone).dateComponents([.year, .month, .day], from: date)
        return String(format: "%04d-%02d-%02d", c.year ?? 0, c.month ?? 0, c.day ?? 0)
    }

    static func startOfNextDay(after date: Date, in zone: TimeZone) -> Date? {
        let cal = calendar(zone)
        return cal.date(byAdding: .day, value: 1, to: cal.startOfDay(for: date))
    }

    /// The start of the first allowed local day strictly after `date`'s day, within the lookahead and before `validUntil`.
    static func nextAllowedDayStart(after date: Date, weekdays: [Int], zone: TimeZone, validUntil: Date?) -> Date? {
        let cal = calendar(zone)
        var cursor = cal.startOfDay(for: date)
        for _ in 0..<lookaheadDays {
            guard let next = cal.date(byAdding: .day, value: 1, to: cursor) else { return nil }
            cursor = next
            if let validUntil, cursor >= validUntil { return nil }
            if weekdays.isEmpty || weekdays.contains(isoWeekday(cursor, in: zone)) { return cursor }
        }
        return nil
    }

    /// The first moment at or after `date` on which the weekday rule allows redemption.
    static func firstAllowedMoment(onOrAfter date: Date, weekdays: [Int], zone: TimeZone, validUntil: Date?) -> Date? {
        if weekdays.isEmpty || weekdays.contains(isoWeekday(date, in: zone)) { return date }
        return nextAllowedDayStart(after: date, weekdays: weekdays, zone: zone, validUntil: validUntil)
    }

    /// Which limit window a redemption belongs to, and how many fit in it. `nil` = unlimited.
    /// - Recurring rewards (and any reward with an explicit per-day limit): that many per local day.
    /// - Other points rewards: unlimited (the balance is the limit).
    /// - Coupons, offers and perks: once per consumer.
    static func limit(kind: RewardKind, recurring: Bool, perDayLimit: Int?) -> (scope: Scope, max: Int)? {
        if recurring || perDayLimit != nil { return (.day, max(1, perDayLimit ?? 1)) }
        if kind == .pointsReward { return nil }
        return (.lifetime, 1)
    }

    enum Scope { case day, lifetime }

    static func windowKey(for facts: RewardFacts, now: Date) -> String {
        switch limit(kind: facts.kind, recurring: !facts.weekdays.isEmpty, perDayLimit: facts.perDayLimit)?.scope {
        case .day?: dayKey(now, in: facts.timeZone)
        case .lifetime?: "once"
        case nil: "open"
        }
    }

    /// Coupons and offers are saved to the account first; perks and points rewards go straight to a code.
    static func requiresClaim(_ kind: RewardKind) -> Bool { kind == .coupon || kind == .offer }

    static func evaluate(_ facts: RewardFacts, now: Date) -> RewardEligibility {
        func verdict(_ state: RewardEligibility.State, action: RewardEligibility.Action = .none, next: Date? = nil,
                     shortfall: Int? = nil) -> RewardEligibility {
            RewardEligibility(state: state, nextAction: action, checkedAt: now, nextEligibleAt: next, pointsShortfall: shortfall)
        }
        let zone = facts.timeZone
        let rule = limit(kind: facts.kind, recurring: !facts.weekdays.isEmpty, perDayLimit: facts.perDayLimit)

        if facts.revoked { return verdict(.revoked) }
        if facts.lifetimeRedeemed { return verdict(.redeemed) }
        if let until = facts.validUntil, now >= until { return verdict(.expired) }
        if let from = facts.validFrom, now < from {
            return verdict(.notYetValid, next: firstAllowedMoment(onOrAfter: from, weekdays: facts.weekdays, zone: zone, validUntil: facts.validUntil))
        }
        if !facts.weekdays.isEmpty, !facts.weekdays.contains(isoWeekday(now, in: zone)) {
            return verdict(.notToday, next: nextAllowedDayStart(after: now, weekdays: facts.weekdays, zone: zone, validUntil: facts.validUntil))
        }
        if let rule, facts.usageInWindow >= rule.max {
            switch rule.scope {
            case .day:
                return verdict(.limitReached, next: nextAllowedDayStart(after: now, weekdays: facts.weekdays, zone: zone, validUntil: facts.validUntil))
            case .lifetime:
                return verdict(.limitReached, next: facts.earliestHeldCodeExpiry)
            }
        }
        if facts.kind == .pointsReward, let cost = facts.pointsCost {
            let balance = facts.pointsBalance ?? 0
            if balance < cost { return verdict(.insufficientPoints, shortfall: cost - balance) }
        }
        if requiresClaim(facts.kind), facts.claimedAt == nil { return verdict(.eligible, action: .claim) }
        return verdict(.eligible, action: .redeem)
    }
}
