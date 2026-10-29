import Foundation
import ViadereCore

/// Which approvals a device that is not approved yet may make, as the client explains and pre-checks it (the server decides, §2.5a).
///
/// Only a **D1** device (`Device.trustTier`) approves **high or critical** requests. A new device of an existing account, or any device
/// after a recovery, is D0 until one of the account's trusted devices approves it (`POST /v1/devices/{id}/confirm`); for Approve v2 the
/// business can also set it up again. **Waiting never changes that.** Deny, decline and report always work: they are the safe directions.
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
        // Newer ICU puts a narrow no-break space before AM/PM; plain spaces read the same and compare simply.
        let clock = time.string(from: date).replacingOccurrences(of: "\u{202F}", with: " ").replacingOccurrences(of: "\u{00A0}", with: " ")
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

    /// The calm explanation shown on Home, in Settings and in the approval sheet. It never promises a time: trust comes from an approval.
    public static let notApprovedMessage =
        "For your security, this iPhone can't approve high-risk requests until one of your trusted devices approves it. A business can also set it up again for its own requests."

    /// Kept for callers that pass the window's end; the answer no longer depends on it.
    public static func message(until lockedUntil: Date?, now: Date, calendar: Calendar = .current, locale: Locale = .current) -> String {
        notApprovedMessage
    }

    /// What remains possible meanwhile.
    public static let stillAvailable = "You can still deny or report any request."
}

extension ViadereServices {
    /// This device's new-device window end, or `nil` when there is none (or the server can't be asked right now).
    public func approvalsLockedUntil() async -> Date? {
        guard let record = try? await records.load(), let devices = try? await api.devices() else { return nil }
        guard let lockedUntil = devices.first(where: { $0.id == record.deviceId })?.approvalsLockedUntil else { return nil }
        return CoolDownPolicy.isActive(until: lockedUntil, now: clock()) ? lockedUntil : nil
    }

    /// Whether the server says this device may approve high-risk requests (D1); `nil` when it can't be asked right now.
    public func thisDeviceApprovesHighRisk() async -> Bool? {
        guard let record = try? await records.load(), let devices = try? await api.devices(),
              let device = devices.first(where: { $0.id == record.deviceId }) else { return nil }
        return device.approvesHighRisk(at: clock())
    }
}
