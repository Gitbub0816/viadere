import Foundation

/// Age-threshold arithmetic on calendar dates (AGE-001). Used **inside the process** to turn a validated birthdate (or an issuer's
/// `age_in_years`) into the yes/no the capability discloses; the birthdate itself is never stored or returned.
public enum AgeThreshold {
    /// A calendar date (proleptic Gregorian, no time zone).
    public struct Day: Sendable, Hashable, Comparable {
        public var year: Int
        public var month: Int
        public var day: Int

        public init?(year: Int, month: Int, day: Int) {
            guard (1900...9999).contains(year), (1...12).contains(month), day >= 1, day <= Self.daysIn(month: month, year: year) else { return nil }
            self.year = year
            self.month = month
            self.day = day
        }

        /// Strict `YYYY-MM-DD` (ISO 8601 full-date, as ISO 18013-5 `full-date` and the provider's `date_of_birth`).
        public init?(isoDate string: String) {
            let parts = string.split(separator: "-", omittingEmptySubsequences: false)
            guard parts.count == 3, parts[0].count == 4, parts[1].count == 2, parts[2].count == 2,
                  parts.allSatisfy({ $0.allSatisfy { $0.isASCII && $0.isNumber } }),
                  let year = Int(parts[0]), let month = Int(parts[1]), let day = Int(parts[2]) else { return nil }
            self.init(year: year, month: month, day: day)
        }

        /// The UTC calendar day of `date`.
        public init(utc date: Date) {
            var calendar = Calendar(identifier: .gregorian)
            calendar.timeZone = TimeZone(identifier: "UTC")!
            let c = calendar.dateComponents([.year, .month, .day], from: date)
            year = c.year!
            month = c.month!
            day = c.day!
        }

        /// The **earliest calendar date anywhere on Earth** at `date`: the date at UTC−12. A threshold check uses this "today" so a person
        /// is never reported as having reached an age while it is still the day before their birthday in some time zone (the conservative
        /// reading; counsel to confirm for each regulated use). Viadere does not know the person's or the venue's time zone.
        public init(earliestLocal date: Date) {
            self.init(utc: date.addingTimeInterval(-12 * 3600))
        }

        static func isLeap(_ year: Int) -> Bool { (year % 4 == 0 && year % 100 != 0) || year % 400 == 0 }
        static func daysIn(month: Int, year: Int) -> Int {
            switch month {
            case 2: isLeap(year) ? 29 : 28
            case 4, 6, 9, 11: 30
            default: 31
            }
        }

        public static func < (lhs: Day, rhs: Day) -> Bool { (lhs.year, lhs.month, lhs.day) < (rhs.year, rhs.month, rhs.day) }
    }

    /// Whether someone born on `birth` is at least `years` old on `today`. A 29 February birthday reaches the age on 1 March in a
    /// non-leap year (the conservative reading). A birth date in the future never meets any threshold.
    public static func meets(birth: Day, years: Int, today: Day) -> Bool {
        guard years >= 0, birth <= today else { return false }
        let targetYear = birth.year + years
        var month = birth.month
        var day = birth.day
        if month == 2, day == 29, !Day.isLeap(targetYear) {
            month = 3
            day = 1
        }
        guard let target = Day(year: min(targetYear, 9999), month: month, day: day) else { return false }
        return target <= today
    }

    /// `meets` for an ISO date string; `nil` when the string is not a strict full-date.
    public static func meets(birthDate: String, years: Int, now: Date) -> Bool? {
        guard let birth = Day(isoDate: birthDate) else { return nil }
        return meets(birth: birth, years: years, today: Day(earliestLocal: now))
    }
}
