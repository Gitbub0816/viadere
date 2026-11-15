import Foundation
import ViadereCore

/// A named appearance theme: one full palette for one side (light or dark) of the system appearance. Every theme stays Viadere: charcoal
/// ink or ivory paper, champagne accents, no saturated chrome. `AppearanceThemeAudit` holds each one to WCAG AA (AAA for high contrast).
public struct AppearanceTheme: Sendable, Hashable, Identifiable {
    public enum ID: String, Sendable, Hashable, Codable, CaseIterable {
        // Light side
        case daybreak, folio, sage, beacon
        // Dark side
        case nightfall, midnight, ember, lantern
    }

    public var id: ID
    public var name: String
    /// One calm line for the picker card.
    public var tagline: String
    public var side: ThemeSide
    public var contrast: ThemeContrastLevel
    public var palette: ThemePalette

    public var isDark: Bool { side == .dark }
}

extension AppearanceTheme {
    public static func theme(_ id: ID) -> AppearanceTheme {
        switch id {
        case .daybreak: daybreak
        case .folio: folio
        case .sage: sage
        case .beacon: beacon
        case .nightfall: nightfall
        case .midnight: midnight
        case .ember: ember
        case .lantern: lantern
        }
    }

    public static var all: [AppearanceTheme] { ID.allCases.map(theme) }
    public static func all(_ side: ThemeSide) -> [AppearanceTheme] { all.filter { $0.side == side } }

    /// The high-contrast theme of the same side (used when the system's Increase Contrast is on).
    public static func highContrast(_ side: ThemeSide) -> AppearanceTheme { side == .light ? beacon : lantern }

    /// Ivory paper, charcoal ink, deep champagne: the signature light theme.
    public static let daybreak = AppearanceTheme(
        id: .daybreak, name: "Daybreak", tagline: "Ivory and charcoal, as Viadere was drawn", side: .light, contrast: .standard,
        palette: ThemePalette(
            background: .init("#F5F2EC"), surface: .init("#FCFBF8"), surfaceRaised: .init("#FFFFFF"), track: .init("#EAE6DF"),
            textPrimary: .init("#1F1E1C"), textSecondary: .init("#625E57"), textTertiary: .init("#7B756C"),
            accent: .init("#7A6440"), accentSoft: .init("#C2AE8E", opacity: 0.16),
            primaryFill: .init("#1F1E1C"), onPrimary: .init("#F5F2EC"),
            danger: .init("#9E3B28"), success: .init("#3F6A4C"), warning: .init("#7F5512"),
            hairline: .init("#1F1E1C", opacity: 0.10), switchOn: .init("#1F1E1C"), knob: .init("#FFFFFF"), shadowOpacity: 0.045))

    /// Warm paper and sepia ink with less blue and less glare: for long reading and evening light.
    public static let folio = AppearanceTheme(
        id: .folio, name: "Folio", tagline: "Warm paper and sepia ink, low glare", side: .light, contrast: .standard,
        palette: ThemePalette(
            background: .init("#F1E9DA"), surface: .init("#F7F1E5"), surfaceRaised: .init("#FBF7EE"), track: .init("#E6DCC9"),
            textPrimary: .init("#2E2519"), textSecondary: .init("#63543F"), textTertiary: .init("#796950"),
            accent: .init("#74552B"), accentSoft: .init("#B08A55", opacity: 0.16),
            primaryFill: .init("#3A2E20"), onPrimary: .init("#F7F1E5"),
            danger: .init("#963823"), success: .init("#43623A"), warning: .init("#7C5016"),
            hairline: .init("#2E2519", opacity: 0.12), switchOn: .init("#3A2E20"), knob: .init("#FFFDF8"), shadowOpacity: 0.04))

    /// Ivory with a breath of green, olive-gold accents: quiet, and a little playful.
    public static let sage = AppearanceTheme(
        id: .sage, name: "Sage", tagline: "Soft green ivory with olive gold", side: .light, contrast: .standard,
        palette: ThemePalette(
            background: .init("#EEF0EA"), surface: .init("#F7F8F4"), surfaceRaised: .init("#FFFFFF"), track: .init("#E1E5DB"),
            textPrimary: .init("#1D231F"), textSecondary: .init("#56605A"), textTertiary: .init("#717A73"),
            accent: .init("#5E6A2E"), accentSoft: .init("#9AA66A", opacity: 0.18),
            primaryFill: .init("#26322B"), onPrimary: .init("#F2F4EE"),
            danger: .init("#9E3B28"), success: .init("#2F6A45"), warning: .init("#7A5512"),
            hairline: .init("#1D231F", opacity: 0.10), switchOn: .init("#26322B"), knob: .init("#FFFFFF"), shadowOpacity: 0.045))

    /// Accessibility light: black on white, firm hairlines, AAA text everywhere.
    public static let beacon = AppearanceTheme(
        id: .beacon, name: "Beacon", tagline: "Black on white, every line firm", side: .light, contrast: .high,
        palette: ThemePalette(
            background: .init("#FFFFFF"), surface: .init("#F7F5F1"), surfaceRaised: .init("#FFFFFF"), track: .init("#E4E0D8"),
            textPrimary: .init("#000000"), textSecondary: .init("#2B2926"), textTertiary: .init("#45423D"),
            accent: .init("#564526"), accentSoft: .init("#564526", opacity: 0.10),
            primaryFill: .init("#000000"), onPrimary: .init("#FFFFFF"),
            danger: .init("#8A1D0C"), success: .init("#1B4A28"), warning: .init("#5E3B00"),
            hairline: .init("#000000", opacity: 0.55), switchOn: .init("#000000"), knob: .init("#FFFFFF"), shadowOpacity: 0))

    /// Warm charcoal and ivory type with champagne accents: the signature dark theme.
    public static let nightfall = AppearanceTheme(
        id: .nightfall, name: "Nightfall", tagline: "Warm charcoal with champagne light", side: .dark, contrast: .standard,
        palette: ThemePalette(
            background: .init("#121211"), surface: .init("#1C1B1A"), surfaceRaised: .init("#262523"), track: .init("#2A2927"),
            textPrimary: .init("#F3F0EA"), textSecondary: .init("#A8A399"), textTertiary: .init("#86817A"),
            accent: .init("#CDB993"), accentSoft: .init("#CDB993", opacity: 0.14),
            primaryFill: .init("#F3F0EA"), onPrimary: .init("#1F1E1C"),
            danger: .init("#E5866E"), success: .init("#8DBB98"), warning: .init("#DDAE62"),
            hairline: .init("#F3F0EA", opacity: 0.12), switchOn: .init("#CDB993"), knob: .init("#F5F2EC"), shadowOpacity: 0))

    /// True black for OLED screens, champagne for every accent and primary action.
    public static let midnight = AppearanceTheme(
        id: .midnight, name: "Midnight", tagline: "True black, champagne accents", side: .dark, contrast: .standard,
        palette: ThemePalette(
            background: .init("#000000"), surface: .init("#0C0C0B"), surfaceRaised: .init("#171615"), track: .init("#1F1E1C"),
            textPrimary: .init("#EDE8DF"), textSecondary: .init("#A39D93"), textTertiary: .init("#7E7972"),
            accent: .init("#D4BE94"), accentSoft: .init("#D4BE94", opacity: 0.16),
            primaryFill: .init("#D4BE94"), onPrimary: .init("#000000"),
            danger: .init("#E8836C"), success: .init("#8CC09A"), warning: .init("#E0B062"),
            hairline: .init("#EDE8DF", opacity: 0.11), switchOn: .init("#D4BE94"), knob: .init("#F5F2EC"), shadowOpacity: 0))

    /// Deep umber with copper accents, like the last light of a fire.
    public static let ember = AppearanceTheme(
        id: .ember, name: "Ember", tagline: "Deep umber with copper glow", side: .dark, contrast: .standard,
        palette: ThemePalette(
            background: .init("#16110E"), surface: .init("#201915"), surfaceRaised: .init("#2B221D"), track: .init("#322822"),
            textPrimary: .init("#F4ECE4"), textSecondary: .init("#B7AA9E"), textTertiary: .init("#908377"),
            accent: .init("#E3A678"), accentSoft: .init("#E3A678", opacity: 0.14),
            primaryFill: .init("#F4ECE4"), onPrimary: .init("#201915"),
            danger: .init("#F08C74"), success: .init("#9CC4A0"), warning: .init("#E8BC6A"),
            hairline: .init("#F4ECE4", opacity: 0.12), switchOn: .init("#E3A678"), knob: .init("#F5F2EC"), shadowOpacity: 0))

    /// Accessibility dark: white on black, bright champagne, AAA text everywhere.
    public static let lantern = AppearanceTheme(
        id: .lantern, name: "Lantern", tagline: "White on black, bright and steady", side: .dark, contrast: .high,
        palette: ThemePalette(
            background: .init("#000000"), surface: .init("#0E0E0D"), surfaceRaised: .init("#1A1918"), track: .init("#2B2A27"),
            textPrimary: .init("#FFFFFF"), textSecondary: .init("#E8E3DA"), textTertiary: .init("#CBC5BA"),
            accent: .init("#F0DDB4"), accentSoft: .init("#F0DDB4", opacity: 0.18),
            primaryFill: .init("#FFFFFF"), onPrimary: .init("#000000"),
            danger: .init("#FFA28E"), success: .init("#A8E2B6"), warning: .init("#FFD27A"),
            hairline: .init("#FFFFFF", opacity: 0.60), switchOn: .init("#9C845C"), knob: .init("#FFFFFF"), shadowOpacity: 0))
}
