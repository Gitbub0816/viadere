import Foundation
import Observation
import ViadereCore

/// Which side of a pairing is shown: the system's light/dark appearance, or one side always.
public enum AppearanceFollow: String, Sendable, Hashable, Codable, CaseIterable {
    case system
    case alwaysLight = "always_light"
    case alwaysDark = "always_dark"

    public var title: String {
        switch self {
        case .system: "With the system"
        case .alwaysLight: "Always day"
        case .alwaysDark: "Always night"
        }
    }
}

/// The person's appearance choice on this device: a day (light-side) theme, a night (dark-side) theme, and which one to show when.
/// Combination modes are just pairings, e.g. Folio by day and Nightfall by night, following the system.
public struct AppearanceSelection: Sendable, Hashable, Codable {
    public var light: AppearanceTheme.ID
    public var dark: AppearanceTheme.ID
    public var follow: AppearanceFollow
    /// With the system's Increase Contrast on, show Beacon / Lantern instead (default on).
    public var honorsIncreaseContrast: Bool

    public init(light: AppearanceTheme.ID, dark: AppearanceTheme.ID, follow: AppearanceFollow = .system, honorsIncreaseContrast: Bool = true) {
        // A theme can only sit on its own side; anything else falls back to the signature theme of that side.
        self.light = AppearanceTheme.theme(light).side == .light ? light : .daybreak
        self.dark = AppearanceTheme.theme(dark).side == .dark ? dark : .nightfall
        self.follow = follow
        self.honorsIncreaseContrast = honorsIncreaseContrast
    }

    public static let `default` = AppearanceSelection(light: .daybreak, dark: .nightfall)

    enum CodingKeys: String, CodingKey {
        case light, dark, follow
        case honorsIncreaseContrast = "honors_increase_contrast"
    }

    /// Lenient: unknown or misplaced values (an older or newer build wrote them) fall back to the defaults instead of failing.
    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let light = (try? c.decode(String.self, forKey: .light)).flatMap(AppearanceTheme.ID.init(rawValue:)) ?? .daybreak
        let dark = (try? c.decode(String.self, forKey: .dark)).flatMap(AppearanceTheme.ID.init(rawValue:)) ?? .nightfall
        let follow = (try? c.decode(String.self, forKey: .follow)).flatMap(AppearanceFollow.init(rawValue:)) ?? .system
        let contrast = (try? c.decode(Bool.self, forKey: .honorsIncreaseContrast)) ?? true
        self.init(light: light, dark: dark, follow: follow, honorsIncreaseContrast: contrast)
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(light.rawValue, forKey: .light)
        try c.encode(dark.rawValue, forKey: .dark)
        try c.encode(follow.rawValue, forKey: .follow)
        try c.encode(honorsIncreaseContrast, forKey: .honorsIncreaseContrast)
    }

    /// The side forced by `follow`, or `nil` when the system decides.
    public var lockedSide: ThemeSide? {
        switch follow {
        case .system: nil
        case .alwaysLight: .light
        case .alwaysDark: .dark
        }
    }

    /// The side shown for a system appearance.
    public func side(systemIsDark: Bool) -> ThemeSide { lockedSide ?? (systemIsDark ? .dark : .light) }

    /// The theme drawn on `side`, with Increase Contrast applied.
    public func theme(for side: ThemeSide, increaseContrast: Bool = false) -> AppearanceTheme {
        if increaseContrast && honorsIncreaseContrast { return .highContrast(side) }
        return .theme(side == .light ? light : dark)
    }

    /// The theme on screen now.
    public func resolvedTheme(systemIsDark: Bool, increaseContrast: Bool = false) -> AppearanceTheme {
        theme(for: side(systemIsDark: systemIsDark), increaseContrast: increaseContrast)
    }

    /// The named pairing this selection matches, if any.
    public var pairing: AppearancePairing? { AppearancePairing.all.first { $0.light == light && $0.dark == dark } }

    /// Stable small integer for this exact choice (used as a render key so every view re-resolves its colors after a change).
    public var renderKey: Int {
        let l = AppearanceTheme.ID.allCases.firstIndex(of: light) ?? 0
        let d = AppearanceTheme.ID.allCases.firstIndex(of: dark) ?? 0
        let f = AppearanceFollow.allCases.firstIndex(of: follow) ?? 0
        return 1 + l + 16 * d + 256 * f + (honorsIncreaseContrast ? 1024 : 0)
    }

    /// Inverse of `renderKey` (`nil` for 0 or an unknown key).
    public init?(renderKey: Int) {
        guard renderKey > 0 else { return nil }
        let k = renderKey - 1
        let ids = AppearanceTheme.ID.allCases, follows = AppearanceFollow.allCases
        let (l, d, f) = (k % 16, (k / 16) % 16, (k / 256) % 4)
        guard l < ids.count, d < ids.count, f < follows.count else { return nil }
        self.init(light: ids[l], dark: ids[d], follow: follows[f], honorsIncreaseContrast: k & 1024 != 0)
    }
}

/// A named day/night combination shown as one card in the picker.
public struct AppearancePairing: Sendable, Hashable, Identifiable {
    public var id: String
    public var name: String
    public var tagline: String
    public var light: AppearanceTheme.ID
    public var dark: AppearanceTheme.ID

    public var selection: AppearanceSelection { AppearanceSelection(light: light, dark: dark) }

    public static let signature = AppearancePairing(id: "signature", name: "Signature", tagline: "Daybreak by day, Nightfall by night",
                                                    light: .daybreak, dark: .nightfall)
    public static let readingRoom = AppearancePairing(id: "reading_room", name: "Reading Room", tagline: "Folio by day, Nightfall by night",
                                                      light: .folio, dark: .nightfall)
    public static let eclipse = AppearancePairing(id: "eclipse", name: "Eclipse", tagline: "Daybreak by day, true black by night",
                                                  light: .daybreak, dark: .midnight)
    public static let lamplight = AppearancePairing(id: "lamplight", name: "Lamplight", tagline: "Folio by day, Midnight by night",
                                                    light: .folio, dark: .midnight)
    public static let hearth = AppearancePairing(id: "hearth", name: "Hearth", tagline: "Sage by day, Ember by night",
                                                 light: .sage, dark: .ember)
    public static let clearView = AppearancePairing(id: "clear_view", name: "Clear View", tagline: "Beacon by day, Lantern by night",
                                                    light: .beacon, dark: .lantern)

    public static let all: [AppearancePairing] = [.signature, .readingRoom, .eclipse, .lamplight, .hearth, .clearView]
}

/// Where the choice is kept: the app group's defaults, so the notification extensions, widgets and Live Activities draw the same theme.
public protocol AppearancePersistence: Sendable {
    func load() -> Data?
    func save(_ data: Data)
}

public final class UserDefaultsAppearancePersistence: AppearancePersistence, @unchecked Sendable {
    public static let key = "com.viadere.appearance.v1"
    private let defaults: UserDefaults

    /// - Parameter suiteName: the app group id; `.standard` when it is empty or unavailable.
    public init(suiteName: String?) {
        defaults = suiteName.flatMap { $0.isEmpty ? nil : UserDefaults(suiteName: $0) } ?? .standard
    }

    public func load() -> Data? { defaults.data(forKey: Self.key) }
    public func save(_ data: Data) { defaults.set(data, forKey: Self.key) }
}

public final class InMemoryAppearancePersistence: AppearancePersistence, @unchecked Sendable {
    private let lock = NSLock()
    private var data: Data?
    public init(_ data: Data? = nil) { self.data = data }
    public func load() -> Data? { lock.withLock { data } }
    public func save(_ data: Data) { lock.withLock { self.data = data } }
}

/// The observable appearance choice (Settings → Appearance). Changes apply at once (`onChange`, the app's theme runtime) and persist.
@MainActor
@Observable
public final class AppearanceModel {
    public private(set) var selection: AppearanceSelection
    @ObservationIgnored private let persistence: any AppearancePersistence
    @ObservationIgnored public var onChange: ((AppearanceSelection) -> Void)?

    public init(persistence: any AppearancePersistence) {
        self.persistence = persistence
        selection = Self.read(persistence)
    }

    /// The stored choice, for processes without a model (extensions); the default when nothing or something unreadable is stored.
    public nonisolated static func read(_ persistence: any AppearancePersistence) -> AppearanceSelection {
        guard let data = persistence.load(), let value = try? JSONDecoder().decode(AppearanceSelection.self, from: data) else { return .default }
        return value
    }

    public func select(_ selection: AppearanceSelection) {
        guard selection != self.selection else { return }
        self.selection = selection
        if let data = try? JSONEncoder().encode(selection) { persistence.save(data) }
        onChange?(selection)
    }

    /// Picks a named pairing, keeping the person's follow and contrast settings.
    public func select(_ pairing: AppearancePairing) {
        select(AppearanceSelection(light: pairing.light, dark: pairing.dark, follow: selection.follow,
                                   honorsIncreaseContrast: selection.honorsIncreaseContrast))
    }

    public func setTheme(_ id: AppearanceTheme.ID) {
        var next = selection
        if AppearanceTheme.theme(id).side == .light { next.light = id } else { next.dark = id }
        select(next)
    }

    public func setFollow(_ follow: AppearanceFollow) {
        var next = selection
        next.follow = follow
        select(next)
    }

    public func setHonorsIncreaseContrast(_ value: Bool) {
        var next = selection
        next.honorsIncreaseContrast = value
        select(next)
    }
}
