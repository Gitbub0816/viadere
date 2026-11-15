import Foundation

// MARK: - Account-wide notification settings (SECURITY.md §2.96 "Notification level and quiet hours")
//
// Two account-wide controls on top of the per-business level (`BusinessPreferences.muteLevel`):
//
// * **Default level.** Everything / Balanced / Only what matters (the same three `MuteLevel`s). A business the customer never set a level
//   for inherits it; a business with its own level keeps that level.
// * **Quiet hours.** An optional daily window (start, end, IANA time zone) in which a notification arrives *quietly* (passive, no sound)
//   unless it is security-critical. Quiet hours change how a push interrupts, never whether an item exists: everything stays in Alerts.
//
// Neither control can silence a security push: sign-in approvals, payment authorizations, verification requests, Approve v2 requests and
// account security notices break through every level and every quiet window (`NotificationPolicy.isSecurityCritical`).

/// A daily quiet window in the customer's own time zone. `startMinute`/`endMinute` are minutes after local midnight (0..<1440); a window
/// whose end is earlier than its start crosses midnight (22:00 to 07:00).
public struct QuietHours: Codable, Sendable, Hashable {
    public var startMinute: Int
    public var endMinute: Int
    /// An IANA time zone identifier ("America/Toronto"). The window follows daylight-saving changes of that zone.
    public var timeZone: String

    public static let minutesPerDay = 1_440
    public static let maxTimeZoneLength = 64

    public init(startMinute: Int, endMinute: Int, timeZone: String) {
        self.startMinute = startMinute
        self.endMinute = endMinute
        self.timeZone = timeZone
    }

    /// Valid: both minutes inside a day, different from each other (an empty or whole-day window is not a window), and a known time zone.
    public var isValid: Bool {
        (0..<Self.minutesPerDay).contains(startMinute) && (0..<Self.minutesPerDay).contains(endMinute) && startMinute != endMinute
            && timeZone.utf8.count <= Self.maxTimeZoneLength && TimeZone(identifier: timeZone) != nil
    }

    /// Whether `date` falls inside the window. An unknown time zone or an invalid window is never "quiet" (fail open: the customer
    /// is notified normally rather than silently missing something).
    public func contains(_ date: Date) -> Bool {
        guard isValid, let zone = TimeZone(identifier: timeZone) else { return false }
        var calendar = Calendar(identifier: .gregorian)
        calendar.timeZone = zone
        let parts = calendar.dateComponents([.hour, .minute], from: date)
        let minute = (parts.hour ?? 0) * 60 + (parts.minute ?? 0)
        if startMinute < endMinute { return minute >= startMinute && minute < endMinute }
        return minute >= startMinute || minute < endMinute
    }
}

/// `GET /v1/notifications/settings`: the account-wide notification settings. A new account has the default level `none` (Everything) and
/// no quiet hours.
public struct NotificationSettings: Codable, Sendable, Hashable {
    /// The level a business without its own level inherits (`none` = Everything, `promotional` = Balanced, `allNonEssential` = Only what matters).
    public var defaultLevel: MuteLevel
    public var quietHours: QuietHours?
    public var updatedAt: Date?

    public init(defaultLevel: MuteLevel = .none, quietHours: QuietHours? = nil, updatedAt: Date? = nil) {
        self.defaultLevel = defaultLevel
        self.quietHours = quietHours
        self.updatedAt = updatedAt
    }

    public static let `default` = NotificationSettings()
}

/// `PUT /v1/notifications/settings`: replaces the settings (idempotent). `quietHours: null` or absent turns quiet hours off.
public struct NotificationSettingsUpdate: Codable, Sendable, Hashable {
    public var defaultLevel: MuteLevel
    public var quietHours: QuietHours?

    public init(defaultLevel: MuteLevel, quietHours: QuietHours?) {
        self.defaultLevel = defaultLevel
        self.quietHours = quietHours
    }

    /// `nil` when valid, else the field that is wrong.
    public var invalidField: String? { quietHours.map { $0.isValid ? nil : "quietHours" } ?? nil }
}

extension APIRoutes {
    public static let notificationSettingsGet = Endpoint<EmptyBody, NotificationSettings>(
        "notifications.settings.get", .GET, "/v1/notifications/settings", auth: .deviceSignedBearer)
    /// `422` for an invalid quiet window (minutes outside a day, equal start and end, unknown time zone).
    public static let notificationSettingsPut = Endpoint<NotificationSettingsUpdate, NotificationSettings>(
        "notifications.settings.put", .PUT, "/v1/notifications/settings", auth: .deviceSignedBearer)

    /// Appended to `APIRoutes.all`.
    public static let notificationSettingsEndpoints: [AnyEndpoint] = [notificationSettingsGet.descriptor, notificationSettingsPut.descriptor]
}

/// Where a push for an interaction lands: normally, or quietly (passive, no sound, normal priority). Quiet is never "not delivered".
public enum NotificationPolicy {
    public enum Interruption: String, Sendable, Hashable {
        case normal
        case quiet
    }

    /// Items that break through every level and quiet window: sign-in and payment approvals (keyed on the server-known kind, never only
    /// on the purpose a business declared) and the non-revocable `security` purpose. Approve v2 requests, verification requests and account
    /// security notices are always sent at their own level and never pass through this policy.
    public static func isSecurityCritical(kind: InteractionKind?, purpose: InteractionPurpose) -> Bool {
        if kind?.isRestrictionExempt == true { return true }
        return purpose == .security
    }

    /// The level that applies to a business: its own when the customer set one (and a timed one has not ended), else the account default.
    public static func effectiveLevel(business: BusinessPreferences?, accountDefault: MuteLevel, at now: Date) -> MuteLevel {
        guard let business, business.hasOwnLevel else { return accountDefault }
        if let until = business.muteUntil, until <= now { return accountDefault }
        return business.muteLevel
    }

    /// The interruption for one notification: security-critical items are always normal; otherwise the level's `MutePolicy` and then quiet
    /// hours may make it quiet.
    public static func interruption(kind: InteractionKind?, purpose: InteractionPurpose, actionRequired: Bool, level: MuteLevel,
                                    quietHours: QuietHours?, at now: Date) -> Interruption {
        if isSecurityCritical(kind: kind, purpose: purpose) { return .normal }
        if MutePolicy.silences(level, purpose: purpose, actionRequired: actionRequired) { return .quiet }
        if let quietHours, quietHours.contains(now) { return .quiet }
        return .normal
    }
}
