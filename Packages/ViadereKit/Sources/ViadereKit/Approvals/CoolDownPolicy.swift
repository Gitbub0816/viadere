import Foundation
import ViadereCore

/// The new-device cool-down, as the client explains and pre-checks it (the server enforces it).
///
/// A device enrolled while the account already has another trusted device cannot approve **high or critical** requests until
/// `Device.approvalsLockedUntil` (24 hours), unless another trusted device confirms it (`POST /v1/devices/{id}/confirm`).
/// Deny, decline and report always work: they are the safe directions.
public enum CoolDownPolicy {
    /// Decisions that are never paused.
    public static let alwaysAllowed: Set<Decision> = [.deny, .report, .decline]

    /// Whether `decision` on `interaction` is one the cool-down pauses (same rule as the server).
    public static func restricts(_ decision: Decision, on interaction: Interaction) -> Bool {
        interaction.effectiveSensitivity >= .high && !alwaysAllowed.contains(decision)
    }

    /// Whether the device is inside its cool-down at `now`.
    public static func isActive(until lockedUntil: Date?, now: Date) -> Bool {
        lockedUntil.map { now < $0 } ?? false
    }

    /// True when `decision` on `interaction` must wait for the cool-down to end.
    public static func pauses(_ decision: Decision, on interaction: Interaction, until lockedUntil: Date?, now: Date) -> Bool {
        isActive(until: lockedUntil, now: now) && restricts(decision, on: interaction)
    }

    /// "3:42 PM" today, "tomorrow at 3:42 PM", otherwise "Oct 28 at 3:42 PM".
    public static func timeText(_ date: Date, now: Date, calendar: Calendar = .current, locale: Locale = .current) -> String {
        let time = DateFormatter()
        time.locale = locale
        time.timeZone = calendar.timeZone
        time.dateStyle = .none
        time.timeStyle = .short
        let clock = time.string(from: date)
        if calendar.isDate(date, inSameDayAs: now) { return clock }
        if let tomorrow = calendar.date(byAdding: .day, value: 1, to: now), calendar.isDate(date, inSameDayAs: tomorrow) {
            return "tomorrow at \(clock)"
        }
        let day = DateFormatter()
        day.locale = locale
        day.timeZone = calendar.timeZone
        day.setLocalizedDateFormatFromTemplate("MMMd")
        return "\(day.string(from: date)) at \(clock)"
    }

    /// The calm explanation shown on Home and in the approval sheet.
    public static func message(until lockedUntil: Date?, now: Date, calendar: Calendar = .current, locale: Locale = .current) -> String {
        guard let lockedUntil, lockedUntil > now else {
            return "For your security, this iPhone can't approve high-risk requests yet. Confirm it from your other device."
        }
        return "For your security, this iPhone can approve high-risk requests after \(timeText(lockedUntil, now: now, calendar: calendar, locale: locale)), or confirm it from your other device."
    }

    /// What remains possible meanwhile.
    public static let stillAvailable = "You can still deny or report any request."
}

extension ViadereServices {
    /// This device's new-device cool-down end, or `nil` when it is trusted (or the server can't be asked right now).
    public func approvalsLockedUntil() async -> Date? {
        guard let record = try? await records.load(), let devices = try? await api.devices() else { return nil }
        guard let lockedUntil = devices.first(where: { $0.id == record.deviceId })?.approvalsLockedUntil else { return nil }
        return CoolDownPolicy.isActive(until: lockedUntil, now: clock()) ? lockedUntil : nil
    }
}
