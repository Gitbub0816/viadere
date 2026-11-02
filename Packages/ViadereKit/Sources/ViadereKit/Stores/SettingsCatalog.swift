import Foundation
import ViadereCore

/// The groups of the You tab (docs/APP-IA.md), in the order they appear.
public enum SettingsGroup: String, CaseIterable, Sendable, Hashable {
    case account, security, notifications, privacy, records, appearance

    public var title: String {
        switch self {
        case .account: "Account"
        case .security: "Security"
        case .notifications: "Notifications"
        case .privacy: "Privacy and sharing"
        case .records: "Records"
        case .appearance: "Appearance"
        }
    }
}

/// Every place in the You tab, as data: the screen hierarchy, the rows' titles and icons, and the on-device search all read this, so a
/// setting is never reachable by search but missing from the list (or the other way round).
public enum SettingsDestination: String, CaseIterable, Sendable, Hashable, Identifiable {
    // Account
    case profile, household, phones, sessions
    // Security
    case appLock, approvals, devices, authenticator, recovery
    // Notifications
    case notifications, lockScreenDetails, businessNotifications, loops
    // Privacy and sharing
    case profileReceipts, consents, verifications
    // Records
    case acknowledgments, dataExport
    // Appearance
    case appearance

    public var id: String { rawValue }

    public var group: SettingsGroup {
        switch self {
        case .profile, .household, .phones, .sessions: .account
        case .appLock, .approvals, .devices, .authenticator, .recovery: .security
        case .notifications, .lockScreenDetails, .businessNotifications, .loops: .notifications
        case .profileReceipts, .consents, .verifications: .privacy
        case .acknowledgments, .dataExport: .records
        case .appearance: .appearance
        }
    }

    public var title: String {
        switch self {
        case .profile: "Profile"
        case .household: "Household"
        case .phones: "Linked phones"
        case .sessions: "Signed-in sessions"
        case .appLock: "App lock"
        case .approvals: "Approvals"
        case .devices: "Trusted devices"
        case .authenticator: "Authenticator"
        case .recovery: "Recovery codes"
        case .notifications: "Notifications"
        case .lockScreenDetails: "Details on the lock screen"
        case .businessNotifications: "Business by business"
        case .loops: "Requests built by businesses"
        case .profileReceipts: "Sharing history"
        case .consents: "Consent history"
        case .verifications: "Verification history"
        case .acknowledgments: "Acknowledgments"
        case .dataExport: "Download my data"
        case .appearance: "Appearance"
        }
    }

    /// The row's quiet second line when no live summary is available.
    public var detail: String {
        switch self {
        case .profile: "Your public name and what you share"
        case .household: "Share limited access with people you trust"
        case .phones: "Numbers that can reach your businesses by text"
        case .sessions: "Where your account is signed in"
        case .appLock: "Require Face ID or your passcode to open Viadere"
        case .approvals: "Payments and sign-ins you confirm"
        case .devices: "The devices that can approve requests"
        case .authenticator: "Passkeys and one-time codes"
        case .recovery: "The way back in if you lose every device"
        case .notifications: "How and when Viadere interrupts you"
        case .lockScreenDetails: "What approval notifications show"
        case .businessNotifications: "How loudly each business may interrupt"
        case .loops: "Short requests a business builds"
        case .profileReceipts: "Profile details you shared or stopped sharing"
        case .consents: "What you've allowed, and when"
        case .verifications: "Age and ID checks, and what was shared"
        case .acknowledgments: "Policies and estimates you've read"
        case .dataExport: "A copy only this iPhone can open"
        case .appearance: "Light, dark and theme"
        }
    }

    /// An SF Symbol name (never shield imagery: the brand avoids it).
    public var symbol: String {
        switch self {
        case .profile: "person.text.rectangle"
        case .household: "person.2"
        case .phones: "phone"
        case .sessions: "person.crop.circle"
        case .appLock: "faceid"
        case .approvals: "checkmark.seal"
        case .devices: "iphone.gen3"
        case .authenticator: "key.viewfinder"
        case .recovery: "list.number"
        case .notifications: "bell"
        case .lockScreenDetails: "lock.rectangle"
        case .businessNotifications: "building.2"
        case .loops: "square.stack"
        case .profileReceipts: "clock.arrow.circlepath"
        case .consents: "checklist"
        case .verifications: "person.badge.key"
        case .acknowledgments: "doc.text"
        case .dataExport: "square.and.arrow.down"
        case .appearance: "circle.lefthalf.filled"
        }
    }

    /// Words people use for this setting that its title does not contain.
    public var keywords: [String] {
        switch self {
        case .profile: ["name", "public name", "details", "address", "birthday", "email"]
        case .household: ["family", "delegate", "partner", "parent", "share access", "manager", "viewer"]
        case .phones: ["phone number", "sms", "text message", "mobile"]
        case .sessions: ["sign out", "signed in", "web", "browser", "log out"]
        case .appLock: ["face id", "touch id", "passcode", "lock", "privacy", "biometric"]
        case .approvals: ["freeze", "pause", "payments", "sign-in", "keys", "mfa", "authorize"]
        case .devices: ["iphone", "ipad", "watch", "remove device", "trusted", "new device"]
        case .authenticator: ["passkeys", "passwords", "otp", "totp", "2fa", "codes", "autofill"]
        case .recovery: ["lost phone", "recover", "backup codes", "passkey", "account recovery"]
        case .notifications: ["alerts", "sounds", "focus", "interrupt", "quiet", "mute"]
        case .lockScreenDetails: ["preview", "amount", "lock screen", "privacy", "rich notifications"]
        case .businessNotifications: ["mute", "quiet", "silence", "offers", "per business"]
        case .loops: ["loops", "built by", "forms", "business requests"]
        case .profileReceipts: ["shared", "receipts", "stopped sharing"]
        case .consents: ["permissions", "marketing", "opt in", "opt out", "allowed"]
        case .verifications: ["age", "id", "identity", "document", "verify"]
        case .acknowledgments: ["policies", "estimates", "terms", "read"]
        case .dataExport: ["export", "download", "copy", "gdpr", "data"]
        case .appearance: ["dark mode", "light mode", "theme", "colors", "colours", "look"]
        }
    }

    /// Where a search result for this item leads. Items that live inside another screen open that screen.
    public var screen: SettingsDestination? {
        switch self {
        case .appLock: nil // an inline control on the You page itself
        case .lockScreenDetails, .businessNotifications: .notifications
        default: self
        }
    }
}

/// What this account and server offer; rows for features the server does not offer are hidden rather than shown broken.
public struct SettingsAvailability: Sendable, Hashable {
    public var recovery: Bool
    public var phones: Bool
    public var sessions: Bool
    public var household: Bool
    public var acknowledgments: Bool
    public var loops: Bool

    public init(recovery: Bool = true, phones: Bool = true, sessions: Bool = true, household: Bool = true, acknowledgments: Bool = true,
                loops: Bool = true) {
        self.recovery = recovery
        self.phones = phones
        self.sessions = sessions
        self.household = household
        self.acknowledgments = acknowledgments
        self.loops = loops
    }

    public static let everything = SettingsAvailability()

    public func allows(_ destination: SettingsDestination) -> Bool {
        switch destination {
        case .recovery: recovery
        case .phones: phones
        case .sessions: sessions
        case .household: household
        case .acknowledgments: acknowledgments
        case .loops: loops
        default: true
        }
    }
}

/// The You tab's structure and its on-device search (nothing leaves the phone).
public enum SettingsCatalog {
    /// The rows of `group` on the You page, in order. Items that live inside another screen are not repeated as rows.
    public static func rows(in group: SettingsGroup, available: SettingsAvailability = .everything) -> [SettingsDestination] {
        SettingsDestination.allCases.filter { $0.group == group && available.allows($0) && $0.isTopLevel }
    }

    /// Ranked matches for `query`: every word must match the title, detail or a keyword; title matches rank first. Case and accents are
    /// ignored. An empty query matches nothing (the page shows its groups instead).
    public static func search(_ query: String, available: SettingsAvailability = .everything) -> [SettingsDestination] {
        let words = normalize(query).split(whereSeparator: \.isWhitespace).map(String.init)
        guard !words.isEmpty else { return [] }
        var scored: [(SettingsDestination, Int, Int)] = []
        for (index, item) in SettingsDestination.allCases.enumerated() where available.allows(item) {
            let title = normalize(item.title)
            let detail = normalize(item.detail)
            let keywords = item.keywords.map(normalize)
            var score = 0
            var matchedAll = true
            for word in words {
                if title.hasPrefix(word) || title.split(separator: " ").contains(where: { $0.hasPrefix(word) }) { score += 3 }
                else if title.contains(word) { score += 2 }
                else if keywords.contains(where: { $0.contains(word) }) || detail.contains(word) { score += 1 }
                else { matchedAll = false; break }
            }
            if matchedAll { scored.append((item, score, index)) }
        }
        return scored.sorted { $0.1 != $1.1 ? $0.1 > $1.1 : $0.2 < $1.2 }.map(\.0)
    }

    static func normalize(_ text: String) -> String {
        text.folding(options: [.caseInsensitive, .diacriticInsensitive], locale: nil)
            .replacingOccurrences(of: "-", with: " ")
            .trimmingCharacters(in: .whitespacesAndNewlines)
    }
}

extension SettingsDestination {
    /// Whether the item is its own row on the You page (inline controls and items inside the Notifications screen are not).
    public var isTopLevel: Bool {
        switch self {
        case .lockScreenDetails, .businessNotifications: false
        default: true
        }
    }
}

// MARK: - Summaries

/// One calm line that says how well the account is protected, shown at the top of Security. Never alarming for the normal state; the
/// weakest fact wins the headline.
public struct SecurityPosture: Sendable, Equatable {
    public enum Level: Sendable, Equatable { case strong, good, needsAttention }

    public var level: Level
    public var headline: String
    public var detail: String

    /// - Parameters:
    ///   - assurance: this device's strongest approval method (`nil` while loading).
    ///   - recoveryRemaining: unused recovery codes (`nil` when the server does not offer recovery or has not answered).
    public static func summarize(assurance: DecisionAssurance?, appLock: Bool, activeDevices: Int, recoveryRemaining: Int?,
                                 approvalsFrozen: Bool) -> SecurityPosture {
        var facts: [String] = []
        switch assurance {
        case .biometric?: facts.append("Face ID approvals")
        case .devicePasscode?: facts.append("Passcode approvals")
        case .none?: facts.append("Basic approvals only")
        case nil: break
        }
        facts.append(appLock ? "App lock on" : "App lock off")
        facts.append(activeDevices == 1 ? "1 trusted device" : "\(activeDevices) trusted devices")
        let detail = facts.joined(separator: " · ")
        if approvalsFrozen {
            return SecurityPosture(level: .needsAttention, headline: "Approvals are frozen", detail: "No business can ask you to approve anything. " + detail)
        }
        if recoveryRemaining == 0 {
            return SecurityPosture(level: .needsAttention, headline: "Create recovery codes", detail: "You have no way back in if you lose this iPhone. " + detail)
        }
        if assurance == DecisionAssurance.none {
            return SecurityPosture(level: .needsAttention, headline: "Turn on Face ID or a passcode", detail: detail)
        }
        if assurance == .biometric, appLock {
            return SecurityPosture(level: .strong, headline: "Well protected", detail: detail)
        }
        return SecurityPosture(level: .good, headline: "Protected", detail: detail)
    }
}
