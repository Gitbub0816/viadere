import Foundation
import ViadereCore

/// One color token: an sRGB color and the opacity it is drawn at (hairlines and soft fills are translucent).
public struct ThemeSwatch: Sendable, Hashable {
    public var color: BrandColor
    public var opacity: Double

    public init(_ hex: String, opacity: Double = 1) {
        color = BrandColor(hex)!
        self.opacity = opacity
    }

    public init(color: BrandColor, opacity: Double = 1) {
        self.color = color
        self.opacity = opacity
    }

    /// `0xRRGGBB`.
    public var rgbValue: UInt32 {
        let c = color.rgb
        return (UInt32(c.red) << 16) | (UInt32(c.green) << 8) | UInt32(c.blue)
    }

    /// The opaque color this swatch produces over `background` (source-over, per sRGB channel, as the screen blends it).
    public func composited(over background: BrandColor) -> BrandColor {
        guard opacity < 1 else { return color }
        let (f, b) = (color.rgb, background.rgb)
        func channel(_ fg: UInt8, _ bg: UInt8) -> UInt8 { UInt8((Double(fg) * opacity + Double(bg) * (1 - opacity)).rounded()) }
        return BrandColor(Hex.encode([channel(f.red, b.red), channel(f.green, b.green), channel(f.blue, b.blue)]))!
    }
}

/// How strictly a theme is held to WCAG: `standard` = AA everywhere, `high` = AAA text (7:1) and 4.5:1 for meaningful non-text.
public enum ThemeContrastLevel: String, Sendable, Hashable, Codable {
    case standard, high

    public var minimums: ContrastMinimums { self == .high ? .aaa : .aa }
}

/// Which system appearance a theme is drawn for.
public enum ThemeSide: String, Sendable, Hashable, Codable, CaseIterable {
    case light, dark

    public var brandAppearance: BrandAppearance { self == .light ? .light : .dark }
}

/// Every color role of the design system (`ViadereColor` in the app). A screen reads roles, never hex values.
public enum ThemeRole: String, Sendable, Hashable, CaseIterable {
    case background, surface, surfaceRaised, track
    case textPrimary, textSecondary, textTertiary
    case accent, accentSoft
    case primaryFill, onPrimary
    case danger, success, warning
    case hairline, switchOn, knob
}

/// A complete palette. Grounds: `background` (screens), `surface` (cards, rows), `surfaceRaised` (selected pills, sheets). Text levels:
/// `textPrimary` and `textSecondary` meet the theme's text minimum on every ground and on `track`; `textTertiary` is for incidental text
/// (placeholders, timestamps, captions next to a primary label) and meets 3:1 (4.5:1 in high contrast). `accent` is champagne in every
/// Viadere theme: links, focus, the verified badge (text minimum on every ground and on `accentSoft`).
public struct ThemePalette: Sendable, Hashable {
    public var background: ThemeSwatch
    public var surface: ThemeSwatch
    public var surfaceRaised: ThemeSwatch
    public var track: ThemeSwatch
    public var textPrimary: ThemeSwatch
    public var textSecondary: ThemeSwatch
    public var textTertiary: ThemeSwatch
    public var accent: ThemeSwatch
    public var accentSoft: ThemeSwatch
    public var primaryFill: ThemeSwatch
    public var onPrimary: ThemeSwatch
    public var danger: ThemeSwatch
    public var success: ThemeSwatch
    public var warning: ThemeSwatch
    public var hairline: ThemeSwatch
    public var switchOn: ThemeSwatch
    public var knob: ThemeSwatch
    /// Card shadow opacity (soft shadows on light themes only; `0` on dark ones).
    public var shadowOpacity: Double

    public subscript(role: ThemeRole) -> ThemeSwatch {
        switch role {
        case .background: background
        case .surface: surface
        case .surfaceRaised: surfaceRaised
        case .track: track
        case .textPrimary: textPrimary
        case .textSecondary: textSecondary
        case .textTertiary: textTertiary
        case .accent: accent
        case .accentSoft: accentSoft
        case .primaryFill: primaryFill
        case .onPrimary: onPrimary
        case .danger: danger
        case .success: success
        case .warning: warning
        case .hairline: hairline
        case .switchOn: switchOn
        case .knob: knob
        }
    }

    /// Opacity of the tinted fills behind danger / success text (badges, destructive buttons); part of the palette contract.
    public static let dangerTintOpacity = 0.08
    public static let successTintOpacity = 0.10
}
