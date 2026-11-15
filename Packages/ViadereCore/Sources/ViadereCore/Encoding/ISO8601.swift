import Foundation

/// Deterministic ISO-8601 date formatting used for every Viadere wire date.
///
/// Output is always UTC with millisecond precision: `2026-10-27T14:03:09.120Z`.
/// Parsing accepts an optional fractional part (any number of digits, truncated to
/// milliseconds) and either `Z` or a `±HH:MM` offset.
public enum ViadereDate {
    /// Formats `date` as `YYYY-MM-DDTHH:MM:SS.sssZ` (UTC, milliseconds, truncated toward the past).
    public static func format(_ date: Date) -> String {
        let totalMillis = millis(date)
        var days = totalMillis >= 0 ? totalMillis / 86_400_000 : (totalMillis - 86_399_999) / 86_400_000
        let msOfDay = totalMillis - days * 86_400_000
        let hour = msOfDay / 3_600_000
        let minute = (msOfDay / 60_000) % 60
        let second = (msOfDay / 1000) % 60
        let milli = msOfDay % 1000
        // Civil-from-days (Howard Hinnant), epoch 1970-01-01.
        days += 719_468
        let era = (days >= 0 ? days : days - 146_096) / 146_097
        let doe = days - era * 146_097
        let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365
        var year = yoe + era * 400
        let doy = doe - (365 * yoe + yoe / 4 - yoe / 100)
        let mp = (5 * doy + 2) / 153
        let day = doy - (153 * mp + 2) / 5 + 1
        let month = mp < 10 ? mp + 3 : mp - 9
        if month <= 2 { year += 1 }
        return pad(year, 4) + "-" + pad(month, 2) + "-" + pad(day, 2) + "T"
            + pad(hour, 2) + ":" + pad(minute, 2) + ":" + pad(second, 2) + "." + pad(milli, 3) + "Z"
    }

    /// Parses an ISO-8601 timestamp (see type documentation). Returns `nil` when malformed.
    public static func parse(_ string: String) -> Date? {
        let chars = Array(string.utf8)
        var i = 0
        func number(_ count: Int) -> Int64? {
            guard i + count <= chars.count else { return nil }
            var value: Int64 = 0
            for _ in 0..<count {
                let c = chars[i]
                guard c >= 48, c <= 57 else { return nil }
                value = value * 10 + Int64(c - 48)
                i += 1
            }
            return value
        }
        func expect(_ c: UInt8) -> Bool {
            guard i < chars.count, chars[i] == c else { return false }
            i += 1
            return true
        }
        guard let year = number(4), expect(45), let month = number(2), expect(45), let day = number(2) else { return nil }
        guard i < chars.count, chars[i] == 84 || chars[i] == 116 else { return nil }
        i += 1
        guard let hour = number(2), expect(58), let minute = number(2), expect(58), let second = number(2) else { return nil }
        guard (1...12).contains(month), (1...31).contains(day), hour < 24, minute < 60, second < 61 else { return nil }
        var millis: Int64 = 0
        if i < chars.count, chars[i] == 46 {
            i += 1
            var digits = 0
            while i < chars.count, chars[i] >= 48, chars[i] <= 57 {
                if digits < 3 { millis = millis * 10 + Int64(chars[i] - 48) }
                digits += 1
                i += 1
            }
            guard digits > 0 else { return nil }
            if digits < 3 { for _ in digits..<3 { millis *= 10 } }
        }
        var offsetSeconds: Int64 = 0
        guard i < chars.count else { return nil }
        if chars[i] == 90 || chars[i] == 122 {
            i += 1
        } else if chars[i] == 43 || chars[i] == 45 {
            let sign: Int64 = chars[i] == 43 ? 1 : -1
            i += 1
            guard let oh = number(2), expect(58), let om = number(2), oh < 24, om < 60 else { return nil }
            offsetSeconds = sign * (oh * 3600 + om * 60)
        } else {
            return nil
        }
        guard i == chars.count else { return nil }
        // Days-from-civil (Howard Hinnant).
        let y = month <= 2 ? year - 1 : year
        let era = (y >= 0 ? y : y - 399) / 400
        let yoe = y - era * 400
        let mp = month > 2 ? month - 3 : month + 9
        let doy = (153 * mp + 2) / 5 + day - 1
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy
        let days = era * 146_097 + doe - 719_468
        let seconds = days * 86_400 + hour * 3600 + minute * 60 + min(second, 59) - offsetSeconds
        return Date(timeIntervalSince1970: TimeInterval(seconds) + TimeInterval(millis) / 1000)
    }

    /// Truncates a date to whole milliseconds (what survives a wire round trip).
    public static func truncatedToMilliseconds(_ date: Date) -> Date {
        Date(timeIntervalSince1970: TimeInterval(millis(date)) / 1000)
    }

    /// Unix seconds (floor).
    public static func unixSeconds(_ date: Date) -> Int64 {
        Int64(floor(date.timeIntervalSince1970))
    }

    static func millis(_ date: Date) -> Int64 {
        Int64(floor(date.timeIntervalSince1970 * 1000 + 1e-6))
    }

    private static func pad(_ value: Int64, _ width: Int) -> String {
        let s = String(value)
        return s.count >= width ? s : String(repeating: "0", count: width - s.count) + s
    }
}
