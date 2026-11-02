import Foundation
import ViadereCore

/// How loudly a business may interrupt, as three named levels instead of switches (docs/APP-IA.md). Each level is one `MuteLevel`; the
/// server's rules are unchanged: security checks and anything that needs an answer always come through, whatever is chosen.
public enum InterruptionPreset: String, CaseIterable, Sendable, Hashable, Identifiable {
    /// Everything arrives normally (`MuteLevel.none`).
    case everything
    /// Offers and rewards arrive quietly (`MuteLevel.promotional`).
    case balanced
    /// Only what needs you interrupts (`MuteLevel.allNonEssential`).
    case essentials

    public var id: String { rawValue }

    public init(_ level: MuteLevel) {
        switch level {
        case .none: self = .everything
        case .promotional: self = .balanced
        case .allNonEssential: self = .essentials
        }
    }

    public var muteLevel: MuteLevel {
        switch self {
        case .everything: .none
        case .balanced: .promotional
        case .essentials: .allNonEssential
        }
    }

    public var title: String {
        switch self {
        case .everything: "Everything"
        case .balanced: "Balanced"
        case .essentials: "Only what matters"
        }
    }

    /// 1–3: how much gets through, for the level meter.
    public var intensity: Int {
        switch self {
        case .everything: 3
        case .balanced: 2
        case .essentials: 1
        }
    }

    public func explanation(business: String) -> String {
        switch self {
        case .everything: "Notifications from \(business) arrive normally."
        case .balanced: "Offers and rewards arrive quietly. Everything still appears in Alerts and Benefits."
        case .essentials: "Only security checks and requests that need your answer interrupt you. Everything still appears in Alerts."
        }
    }

    /// The short form used in summaries ("Balanced", "Quiet until 6 PM").
    public func summary(until: Date?, now: Date, calendar: Calendar = .current) -> String {
        guard self != .everything, let until else { return title }
        if calendar.isDate(until, inSameDayAs: now) {
            return "\(title) until \(until.formatted(date: .omitted, time: .shortened))"
        }
        return "\(title) until \(until.formatted(.dateTime.month(.abbreviated).day()))"
    }
}

extension BusinessPreferencesViewModel.MuteDuration {
    /// Shortest first: the order the inline stepper walks.
    public static var stepOrder: [Self] { [.hour, .day, .week, .untilChanged] }

    /// The next or previous duration in `stepOrder` (clamped at the ends).
    public func stepped(by delta: Int) -> Self {
        let order = Self.stepOrder
        guard let index = order.firstIndex(of: self) else { return self }
        return order[min(max(index + delta, 0), order.count - 1)]
    }

    /// The duration that best describes a saved mute end (`nil` end: until changed).
    public static func closest(to until: Date?, now: Date) -> Self {
        guard let until else { return .untilChanged }
        let remaining = until.timeIntervalSince(now)
        if remaining <= 3_600 { return .hour }
        if remaining <= 86_400 { return .day }
        return .week
    }
}

extension PermissionCopy {
    /// One line that says what a business may contact you about, for the business page and its settings row:
    /// "Orders, support and offers" / "Only security and account notices".
    public static func summary(_ rows: [Row]) -> String {
        let optional = rows.filter { !$0.isLocked && $0.isOn }.map { shortTitle($0.purpose) }
        guard !optional.isEmpty else { return "Only security and account notices" }
        if optional.count == 1 { return optional[0].prefix(1).uppercased() + optional[0].dropFirst() + " and essentials" }
        let joined = optional.dropLast().joined(separator: ", ") + " and " + optional.last!
        return joined.prefix(1).uppercased() + joined.dropFirst()
    }

    /// The lowercase noun used inside sentences and chips.
    public static func shortTitle(_ purpose: InteractionPurpose) -> String {
        switch purpose {
        case .security: "security"
        case .accountService: "account notices"
        case .transactional: "orders"
        case .support: "support"
        case .marketing: "offers"
        case .rewards: "rewards"
        }
    }
}
