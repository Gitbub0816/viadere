import Foundation

/// Semantic roles a Brand Kit may color. There is no role for attribution, verified badges, risk chips, confirmation panels, danger or
/// critical text: those always use `ProtectedPalette` (spec B2.4, A6a.2).
public enum BrandTokenRole: String, Sendable, Codable, CaseIterable, Hashable {
    case primary, secondary, accent, surface
}

public enum BrandAppearance: String, Sendable, Codable, CaseIterable, Hashable {
    case light, dark
}

/// WCAG 2.x contrast computed in **integer** arithmetic so every platform (iOS, the web renderer, a future Android client) reaches the
/// same decision for the same colors: sRGB channels are linearized through a fixed table (`linear[c] = round(1e7 · lin(c/255))`),
/// relative luminance is `Y = 2126·R + 7152·G + 722·B` in units of 1e-11, and `ratio ≥ k/10` is tested as
/// `10·(Y_light + 5e9) ≥ k·(Y_dark + 5e9)`.
public enum ContrastPolicy {
    /// Minimum ratio ×10 for text and for icons/controls (WCAG AA: 4.5 and 3.0).
    public static let textMinimumTimes10: Int64 = 45
    public static let nonTextMinimumTimes10: Int64 = 30

    static let linear: [Int64] = [
        0, 3035, 6071, 9106, 12141, 15176, 18212, 21247, 24282, 27317, 30353, 33465, 36765, 40247, 43914, 47770,
        51815, 56054, 60488, 65121, 69954, 74990, 80232, 85681, 91341, 97212, 103298, 109601, 116122, 122865, 129830, 137021,
        144438, 152085, 159963, 168074, 176420, 185002, 193824, 202886, 212190, 221739, 231534, 241576, 251869, 262412, 273209, 284260,
        295568, 307134, 318960, 331048, 343398, 356013, 368895, 382044, 395462, 409152, 423114, 437350, 451862, 466651, 481718, 497066,
        512695, 528606, 544803, 561285, 578054, 595112, 612461, 630100, 648033, 666259, 684782, 703601, 722719, 742136, 761854, 781874,
        802198, 822827, 843762, 865005, 886556, 908417, 930590, 953075, 975873, 998987, 1022417, 1046165, 1070231, 1094617, 1119324, 1144354,
        1169707, 1195384, 1221388, 1247718, 1274377, 1301365, 1328683, 1356333, 1384316, 1412633, 1441285, 1470273, 1499598, 1529262, 1559265, 1589608,
        1620294, 1651322, 1682694, 1714411, 1746474, 1778884, 1811642, 1844750, 1878208, 1912017, 1946178, 1980693, 2015563, 2050787, 2086369, 2122308,
        2158605, 2195262, 2232280, 2269659, 2307400, 2345506, 2383976, 2422811, 2462013, 2501583, 2541521, 2581829, 2622507, 2663556, 2704978, 2746773,
        2788943, 2831487, 2874408, 2917706, 2961383, 3005438, 3049873, 3094689, 3139887, 3185468, 3231432, 3277781, 3324515, 3371636, 3419144, 3467041,
        3515326, 3564001, 3613068, 3662526, 3712377, 3762621, 3813260, 3864294, 3915725, 3967552, 4019778, 4072402, 4125426, 4178851, 4232677, 4286905,
        4341536, 4396572, 4452012, 4507858, 4564110, 4620770, 4677838, 4735315, 4793202, 4851499, 4910208, 4969330, 5028865, 5088813, 5149177, 5209956,
        5271151, 5332764, 5394795, 5457245, 5520114, 5583404, 5647115, 5711248, 5775804, 5840784, 5906188, 5972018, 6038273, 6104956, 6172066, 6239604,
        6307571, 6375969, 6444797, 6514056, 6583748, 6653873, 6724432, 6795425, 6866853, 6938718, 7011019, 7083758, 7156935, 7230551, 7304607, 7379104,
        7454042, 7529422, 7605245, 7681511, 7758222, 7835378, 7912979, 7991027, 8069523, 8148466, 8227858, 8307699, 8387990, 8468732, 8549926, 8631572,
        8713671, 8796224, 8879231, 8962694, 9046612, 9130987, 9215819, 9301109, 9386857, 9473065, 9559734, 9646862, 9734453, 9822506, 9911021, 10000000,
    ]

    /// Relative luminance in units of 1e-11 (0 ... 1e11).
    public static func luminance(_ color: BrandColor) -> Int64 {
        let c = color.rgb
        return 2126 * linear[Int(c.red)] + 7152 * linear[Int(c.green)] + 722 * linear[Int(c.blue)]
    }

    static let offset: Int64 = 5_000_000_000

    /// Whether the contrast between `a` and `b` is at least `minimumTimes10 / 10`.
    public static func meets(_ a: BrandColor, _ b: BrandColor, minimumTimes10: Int64) -> Bool {
        let (la, lb) = (luminance(a), luminance(b))
        let (light, dark) = la >= lb ? (la, lb) : (lb, la)
        return 10 * (light + offset) >= minimumTimes10 * (dark + offset)
    }

    /// Contrast ratio ×100, rounded down (for Studio warnings: "3.12:1").
    public static func ratioTimes100(_ a: BrandColor, _ b: BrandColor) -> Int64 {
        let (la, lb) = (luminance(a), luminance(b))
        let (light, dark) = la >= lb ? (la, lb) : (lb, la)
        return (light + offset) * 100 / (dark + offset)
    }

    /// The Viadere foreground (charcoal or ivory) with the higher contrast on `background` (`on_primary: "auto"`).
    public static func bestForeground(on background: BrandColor) -> BrandColor {
        ratioTimes100(NeutralPalette.charcoal, background) >= ratioTimes100(NeutralPalette.ivory, background) ? NeutralPalette.charcoal : NeutralPalette.ivory
    }
}

/// Viadere's own colors (`App/Shared/DesignSystem/ViadereDesignSystem.swift`).
public enum NeutralPalette {
    public static let charcoal = BrandColor("#1F1E1C")!
    public static let ivory = BrandColor("#F5F2EC")!

    public static func palette(_ appearance: BrandAppearance) -> ResolvedPalette {
        switch appearance {
        case .light:
            ResolvedPalette(primary: charcoal, onPrimary: ivory, secondary: BrandColor("#6B675F")!, accent: BrandColor("#8C7550")!,
                            surface: BrandColor("#FCFBF8")!, onSurface: charcoal)
        case .dark:
            ResolvedPalette(primary: BrandColor("#F3F0EA")!, onPrimary: charcoal, secondary: BrandColor("#A29D94")!, accent: BrandColor("#CDB993")!,
                            surface: BrandColor("#1C1B1A")!, onSurface: BrandColor("#F3F0EA")!)
        }
    }
}

/// The palette for **protected** presentation nodes (attribution bar, verified badge, confirmation panel, risk chips, outcome status,
/// notices). Always neutral: no Brand Kit input reaches it.
public enum ProtectedPalette {
    public static func palette(_ appearance: BrandAppearance) -> ResolvedPalette { NeutralPalette.palette(appearance) }
}

/// Concrete colors per role after clamping. Renderers use these, never raw tokens.
public struct ResolvedPalette: Sendable, Hashable, Codable {
    public var primary: BrandColor
    public var onPrimary: BrandColor
    public var secondary: BrandColor
    public var accent: BrandColor
    public var surface: BrandColor
    public var onSurface: BrandColor

    enum CodingKeys: String, CodingKey {
        case primary, secondary, accent, surface
        case onPrimary = "on_primary"
        case onSurface = "on_surface"
    }
}

/// Result of applying a kit's tokens: the palettes and which roles Viadere replaced with neutral ones (shown as Studio warnings).
public struct BrandStyleResolution: Sendable, Hashable, Codable {
    public var light: ResolvedPalette
    public var dark: ResolvedPalette
    /// Roles replaced in light / dark appearance, in `BrandTokenRole` order.
    public var overriddenLight: [BrandTokenRole]
    public var overriddenDark: [BrandTokenRole]

    enum CodingKeys: String, CodingKey {
        case light, dark
        case overriddenLight = "overridden_light"
        case overriddenDark = "overridden_dark"
    }

    public func palette(_ appearance: BrandAppearance) -> ResolvedPalette { appearance == .light ? light : dark }

    public static let neutral = ContrastPolicy.resolve(nil)
}

extension ContrastPolicy {
    /// Applies `tokens` over the neutral palette and **clamps** every role that fails its contrast minimum back to neutral (spec B2.4:
    /// Viadere may override for accessibility and legibility). Brand tokens set the light surface only; dark mode keeps Viadere's dark
    /// surface and takes the brand colors that are legible on it.
    public static func resolve(_ tokens: BrandTokens?) -> BrandStyleResolution {
        let neutralLight = NeutralPalette.palette(.light)
        let neutralDark = NeutralPalette.palette(.dark)
        guard let tokens else {
            return BrandStyleResolution(light: neutralLight, dark: neutralDark, overriddenLight: [], overriddenDark: [])
        }
        func apply(_ neutral: ResolvedPalette, brandSurface: Bool) -> (ResolvedPalette, [BrandTokenRole]) {
            var p = neutral
            var overridden = Set<BrandTokenRole>()
            if brandSurface, let surface = tokens.surface {
                let on = bestForeground(on: surface)
                if meets(on, surface, minimumTimes10: textMinimumTimes10) { p.surface = surface; p.onSurface = on } else { overridden.insert(.surface) }
            }
            let primary = tokens.primary
            let onPrimary = bestForeground(on: primary)
            if meets(onPrimary, primary, minimumTimes10: textMinimumTimes10) && meets(primary, p.surface, minimumTimes10: nonTextMinimumTimes10) {
                p.primary = primary
                p.onPrimary = onPrimary
            } else {
                overridden.insert(.primary)
            }
            if let secondary = tokens.secondary {
                if meets(secondary, p.surface, minimumTimes10: textMinimumTimes10) { p.secondary = secondary } else { overridden.insert(.secondary) }
            }
            if let accent = tokens.accent {
                if meets(accent, p.surface, minimumTimes10: nonTextMinimumTimes10) { p.accent = accent } else { overridden.insert(.accent) }
            }
            return (p, BrandTokenRole.allCases.filter(overridden.contains))
        }
        let light = apply(neutralLight, brandSurface: true)
        let dark = apply(neutralDark, brandSurface: false)
        return BrandStyleResolution(light: light.0, dark: dark.0, overriddenLight: light.1, overriddenDark: dark.1)
    }
}
