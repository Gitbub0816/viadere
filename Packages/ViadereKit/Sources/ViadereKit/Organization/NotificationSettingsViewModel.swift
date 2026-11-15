import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

/// You → Notifications, account-wide (SECURITY.md §2.96 "Notification level and quiet hours"): the default level a business without its own
/// level inherits, and optional quiet hours. The server stores and enforces both where pushes are decided; this model only edits them.
///
/// * **Default level** reuses the three named levels (`InterruptionPreset`): Everything / Balanced / Only what matters.
/// * **Quiet hours** are a daily window in the device's time zone. During it only security-critical items (sign-in approvals, payments,
///   verification, account security notices) interrupt; everything else arrives quietly and still appears in Alerts.
/// * **Never a security silence.** Nothing here can quiet a security item; the screen says so in plain words (`securityNote`).
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class NotificationSettingsViewModel {
    public private(set) var settings: NotificationSettings
    public private(set) var hasLoaded = false
    public private(set) var isSaving = false
    public private(set) var errorMessage: String?

    private let api: (any OrganizationAPI)?
    private let timeZone: @Sendable () -> TimeZone

    /// 10 PM to 7 AM: what turning quiet hours on starts with.
    public static let defaultStartMinute = 22 * 60
    public static let defaultEndMinute = 7 * 60

    /// Shown under the settings: what always comes through.
    public static let securityNote = "Sign-in approvals, payments and verification requests always come through, whatever you choose here."

    public init(api: (any OrganizationAPI)?, initial: NotificationSettings = .default, timeZone: @escaping @Sendable () -> TimeZone = { .current }) {
        self.api = api
        settings = initial
        self.timeZone = timeZone
    }

    // MARK: Level

    /// The default level as one of the three named levels.
    public var preset: InterruptionPreset { InterruptionPreset(settings.defaultLevel) }

    public var levelCaption: String {
        switch preset {
        case .everything: "Businesses you haven't set up yourself notify you normally."
        case .balanced: "Offers and rewards from those businesses arrive quietly. Everything still appears in Alerts and Benefits."
        case .essentials: "Those businesses only interrupt for security checks and requests that need your answer. Everything still appears in Alerts."
        }
    }

    /// Chooses the default level. Optimistic; rolled back when the server refuses.
    public func setPreset(_ preset: InterruptionPreset) async {
        await save(NotificationSettingsUpdate(defaultLevel: preset.muteLevel, quietHours: settings.quietHours))
    }

    // MARK: Quiet hours

    public var quietHoursEnabled: Bool { settings.quietHours != nil }
    public var startMinute: Int { settings.quietHours?.startMinute ?? Self.defaultStartMinute }
    public var endMinute: Int { settings.quietHours?.endMinute ?? Self.defaultEndMinute }

    /// Turns quiet hours on (10 PM to 7 AM in the device's time zone) or off.
    public func setQuietHours(enabled: Bool) async {
        guard enabled != quietHoursEnabled else { return }
        let window = enabled ? QuietHours(startMinute: Self.defaultStartMinute, endMinute: Self.defaultEndMinute, timeZone: timeZone().identifier) : nil
        await save(NotificationSettingsUpdate(defaultLevel: settings.defaultLevel, quietHours: window))
    }

    /// Changes the window. Ignored when quiet hours are off, when start equals end, or when a time is outside a day.
    public func setQuietHours(startMinute: Int, endMinute: Int) async {
        guard quietHoursEnabled else { return }
        let window = QuietHours(startMinute: startMinute, endMinute: endMinute, timeZone: timeZone().identifier)
        guard window.isValid else {
            errorMessage = "Choose a start and end time that differ."
            return
        }
        guard window != settings.quietHours else { return }
        await save(NotificationSettingsUpdate(defaultLevel: settings.defaultLevel, quietHours: window))
    }

    /// Follows the device when it moves to another time zone, so "10 PM" stays 10 PM where the customer is. Cheap: a no-op unless the
    /// window's zone differs from the device's.
    public func syncTimeZone() async {
        guard let window = settings.quietHours, window.timeZone != timeZone().identifier else { return }
        await save(NotificationSettingsUpdate(defaultLevel: settings.defaultLevel,
                                              quietHours: QuietHours(startMinute: window.startMinute, endMinute: window.endMinute, timeZone: timeZone().identifier)))
    }

    /// "Off", or "10:00 PM to 7:00 AM".
    public var quietHoursSummary: String {
        guard let window = settings.quietHours else { return "Off" }
        return "\(Self.timeLabel(minute: window.startMinute)) to \(Self.timeLabel(minute: window.endMinute))"
    }

    /// The sentence under the quiet hours controls.
    public var quietHoursCaption: String {
        quietHoursEnabled
            ? "Between these times everything arrives quietly except security. It all still appears in Alerts."
            : "Pick a time of day when only security should interrupt you."
    }

    /// The row on You → Notifications: the level and, when set, the quiet window.
    public var rowSummary: String {
        guard quietHoursEnabled else { return preset.title }
        return "\(preset.title) · Quiet \(quietHoursSummary)"
    }

    /// Whether quiet hours are in force at `now`.
    public func isQuiet(at now: Date) -> Bool { settings.quietHours?.contains(now) ?? false }

    /// "10:00 PM" for a minute of the day, in the device's locale (a fixed reference day; no time zone shift).
    public static func timeLabel(minute: Int, locale: Locale = .current) -> String {
        let clamped = min(max(minute, 0), QuietHours.minutesPerDay - 1)
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = TimeZone(identifier: "UTC") ?? .gmt
        let date = calendar.date(from: DateComponents(year: 2001, month: 1, day: 1, hour: clamped / 60, minute: clamped % 60)) ?? Date(timeIntervalSince1970: 0)
        var style = Date.FormatStyle(date: .omitted, time: .shortened)
        style.timeZone = calendar.timeZone
        style.locale = locale
        return date.formatted(style)
    }

    /// The minute of the day of a date picked on the device (`DatePicker` hour and minute), in `calendar`'s zone.
    public static func minute(of date: Date, calendar: Calendar = .current) -> Int {
        let parts = calendar.dateComponents([.hour, .minute], from: date)
        return (parts.hour ?? 0) * 60 + (parts.minute ?? 0)
    }

    /// A date today (in `calendar`) at a minute of the day, for a `DatePicker`'s binding.
    public static func date(minute: Int, calendar: Calendar = .current, reference: Date = Date()) -> Date {
        let clamped = min(max(minute, 0), QuietHours.minutesPerDay - 1)
        return calendar.date(bySettingHour: clamped / 60, minute: clamped % 60, second: 0, of: reference) ?? reference
    }

    // MARK: Load / save

    public func load() async {
        guard let api else { return }
        do {
            settings = try await api.notificationSettings()
            hasLoaded = true
            errorMessage = nil
        } catch {
            errorMessage = (error as? APIError)?.userMessage ?? "Couldn't load these settings."
        }
    }

    public func reset() {
        settings = .default
        hasLoaded = false
        isSaving = false
        errorMessage = nil
    }

    private func save(_ update: NotificationSettingsUpdate) async {
        guard let api, !isSaving else { return }
        let previous = settings
        isSaving = true
        defer { isSaving = false }
        settings = NotificationSettings(defaultLevel: update.defaultLevel, quietHours: update.quietHours, updatedAt: previous.updatedAt)
        do {
            settings = try await api.updateNotificationSettings(update)
            errorMessage = nil
        } catch {
            settings = previous
            errorMessage = (error as? APIError)?.userMessage ?? "Couldn't save that change."
        }
    }
}
