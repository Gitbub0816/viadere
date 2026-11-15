import Foundation

/// Contrast minimums (×10) a palette is held to: WCAG AA (4.5 text, 3.0 non-text) or the high-contrast level (7.0 text, AAA; 4.5 non-text).
public struct ContrastMinimums: Sendable, Hashable {
    public var text: Int64
    public var nonText: Int64

    public init(text: Int64, nonText: Int64) {
        self.text = text
        self.nonText = nonText
    }

    public static let aa = ContrastMinimums(text: ContrastPolicy.textMinimumTimes10, nonText: ContrastPolicy.nonTextMinimumTimes10)
    public static let aaa = ContrastMinimums(text: 70, nonText: 45)
}

/// The base a Brand Kit is applied over: an appearance theme's own (neutral) palette, the two foregrounds that theme writes text in, and
/// whether brand **surfaces** may replace the theme's (light themes only; dark themes keep their own surface and tint it instead).
public struct ThemedBrandBase: Sendable, Hashable {
    public var palette: ResolvedPalette
    /// Candidate text colors on brand fills (the theme's ink and its paper); the one with the higher contrast is used (`on_primary: "auto"`).
    public var foregrounds: [BrandColor]
    public var acceptsBrandSurface: Bool
    public var minimums: ContrastMinimums
    /// Whether this base is dark (brand colors that are too dark for it are lightened, never darkened).
    public var isDark: Bool
    /// Theme rules (on by default): brand colors must also read on the theme's own surface (a branded space draws them on tinted theme
    /// cards too), and a brand surface is accepted only if the theme's ink, secondary text, accent and primary stay legible on it (so every
    /// fallback color is legible wherever it lands). Off only for the classic neutral bases, which reproduce `resolve(_:)` exactly.
    public var strict: Bool
    /// Further grounds brand colors are drawn on under theme rules (the theme's page background).
    public var grounds: [BrandColor]

    public init(palette: ResolvedPalette, foregrounds: [BrandColor], acceptsBrandSurface: Bool, minimums: ContrastMinimums, isDark: Bool,
                strict: Bool = true, grounds: [BrandColor] = []) {
        self.grounds = grounds
        self.palette = palette
        self.foregrounds = foregrounds
        self.acceptsBrandSurface = acceptsBrandSurface
        self.minimums = minimums
        self.isDark = isDark
        self.strict = strict
    }

    /// The classic neutral bases `ContrastPolicy.resolve(_:)` uses.
    public static func neutral(_ appearance: BrandAppearance) -> ThemedBrandBase {
        ThemedBrandBase(palette: NeutralPalette.palette(appearance), foregrounds: [NeutralPalette.charcoal, NeutralPalette.ivory],
                        acceptsBrandSurface: appearance == .light, minimums: .aa, isDark: appearance == .dark, strict: false)
    }
}

/// A brand palette resolved over one theme, with the roles Viadere replaced and the roles it **derived** (a lighter or darker variant of
/// the brand color, so a deep brand color still reads on a black theme). Same integer arithmetic as `ContrastPolicy`.
public struct ThemedBrandResolution: Sendable, Hashable {
    public var palette: ResolvedPalette
    public var overridden: [BrandTokenRole]
    public var derived: [BrandTokenRole]
}

extension ContrastPolicy {
    /// The foreground among `candidates` with the highest contrast on `background`.
    public static func bestForeground(on background: BrandColor, among candidates: [BrandColor]) -> BrandColor {
        candidates.max { ratioTimes100($0, background) < ratioTimes100($1, background) } ?? bestForeground(on: background)
    }

    /// `a` mixed toward `b` by `step / steps`, per sRGB channel, rounded half up (integer math, the same on every platform).
    public static func mix(_ a: BrandColor, toward b: BrandColor, step: Int, of steps: Int) -> BrandColor {
        let (x, y) = (a.rgb, b.rgb)
        func channel(_ p: UInt8, _ q: UInt8) -> UInt8 {
            UInt8((Int(p) * (steps - step) + Int(q) * step + steps / 2) / steps)
        }
        let r = channel(x.red, y.red), g = channel(x.green, y.green), bl = channel(x.blue, y.blue)
        return BrandColor(Hex.encode([r, g, bl]))!
    }

    /// The largest share (in twentieths) a brand color may be moved toward white or black before it stops being that brand's color and
    /// Viadere's neutral token is used instead.
    public static let maximumDerivationSteps = 12

    /// `color`, or the nearest lighter (on a dark base) / darker (on a light base) variant that passes `accepts`; `nil` when none within
    /// `maximumDerivationSteps` does (the role then falls back to neutral).
    public static func derive(_ color: BrandColor, lighten: Bool, accepts: (BrandColor) -> Bool) -> (color: BrandColor, derived: Bool)? {
        if accepts(color) { return (color, false) }
        let target = BrandColor(lighten ? "#FFFFFF" : "#000000")!
        for step in 1...maximumDerivationSteps {
            let candidate = mix(color, toward: target, step: step, of: 20)
            if accepts(candidate) { return (candidate, true) }
        }
        return nil
    }

    /// Applies `tokens` over a theme's base palette with the same rules as `resolve(_:)` (every role that fails its minimum falls back to
    /// the base), except that a brand color too dark or too light for the base may first be **derived** (`derive`), so a kit keeps its hue in
    /// every theme. With `ThemedBrandBase.neutral(...)` and `derive: false` it equals `resolve(_:)` for that appearance.
    public static func resolve(_ tokens: BrandTokens?, over base: ThemedBrandBase, derive allowDerive: Bool = true) -> ThemedBrandResolution {
        var p = base.palette
        guard let tokens else { return ThemedBrandResolution(palette: p, overridden: [], derived: []) }
        var overridden = Set<BrandTokenRole>()
        var derived = Set<BrandTokenRole>()
        let minimums = base.minimums
        func pick(_ color: BrandColor, role: BrandTokenRole, accepts: (BrandColor) -> Bool) -> BrandColor? {
            if allowDerive {
                guard let result = derive(color, lighten: base.isDark, accepts: accepts) else { return nil }
                if result.derived { derived.insert(role) }
                return result.color
            }
            return accepts(color) ? color : nil
        }
        if base.acceptsBrandSurface, let surface = tokens.surface {
            let on = base.strict ? base.palette.onSurface : bestForeground(on: surface, among: base.foregrounds)
            let fallbacksRead = !base.strict || (meets(base.palette.secondary, surface, minimumTimes10: minimums.text)
                && meets(base.palette.accent, surface, minimumTimes10: minimums.nonText)
                && meets(base.palette.primary, surface, minimumTimes10: minimums.nonText))
            if fallbacksRead, meets(on, surface, minimumTimes10: minimums.text) {
                p.surface = surface
                p.onSurface = on
            } else {
                overridden.insert(.surface)
            }
        }
        let surface = p.surface
        // Under theme rules every brand color must also read on the theme's own surface.
        let grounds = base.strict ? Array(Set([surface, base.palette.surface] + base.grounds)) : [surface]
        func reads(_ color: BrandColor, _ minimum: Int64) -> Bool { grounds.allSatisfy { meets(color, $0, minimumTimes10: minimum) } }
        if let primary = pick(tokens.primary, role: .primary, accepts: { candidate in
            meets(bestForeground(on: candidate, among: base.foregrounds), candidate, minimumTimes10: minimums.text)
                && reads(candidate, minimums.nonText)
        }) {
            p.primary = primary
            p.onPrimary = bestForeground(on: primary, among: base.foregrounds)
        } else {
            overridden.insert(.primary)
        }
        if let secondary = tokens.secondary {
            if let value = pick(secondary, role: .secondary, accepts: { reads($0, minimums.text) }) {
                p.secondary = value
            } else {
                overridden.insert(.secondary)
            }
        }
        if let accent = tokens.accent {
            if let value = pick(accent, role: .accent, accepts: { reads($0, minimums.nonText) }) {
                p.accent = value
            } else {
                overridden.insert(.accent)
            }
        }
        derived.subtract(overridden)
        return ThemedBrandResolution(palette: p, overridden: BrandTokenRole.allCases.filter(overridden.contains),
                                     derived: BrandTokenRole.allCases.filter(derived.contains))
    }
}

extension BrandStyleResolution {
    /// The brand intent behind a clamped resolution (what a Loop tree carries): each role the kit set and the clamp kept, light first, else
    /// dark. `nil` when no brand color survived at all. Used to re-resolve a kit over an appearance theme.
    public var keptTokens: BrandTokens? {
        let neutralLight = NeutralPalette.palette(.light)
        let neutralDark = NeutralPalette.palette(.dark)
        func kept(_ role: BrandTokenRole, _ value: (ResolvedPalette) -> BrandColor) -> BrandColor? {
            if !overriddenLight.contains(role), value(light) != value(neutralLight) { return value(light) }
            if !overriddenDark.contains(role), value(dark) != value(neutralDark) { return value(dark) }
            return nil
        }
        guard let primary = kept(.primary, \.primary) else { return nil }
        let surface = !overriddenLight.contains(.surface) && light.surface != neutralLight.surface ? light.surface : nil
        return BrandTokens(primary: primary, secondary: kept(.secondary, \.secondary), accent: kept(.accent, \.accent), surface: surface)
    }
}

extension ResolvedPalette {
    /// A palette from explicit colors (an appearance theme's own roles, as a Brand Kit base).
    public static func make(primary: BrandColor, onPrimary: BrandColor, secondary: BrandColor, accent: BrandColor, surface: BrandColor,
                            onSurface: BrandColor) -> ResolvedPalette {
        ResolvedPalette(primary: primary, onPrimary: onPrimary, secondary: secondary, accent: accent, surface: surface, onSurface: onSurface)
    }
}
