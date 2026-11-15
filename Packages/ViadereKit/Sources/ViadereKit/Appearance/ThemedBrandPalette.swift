import Foundation
import ViadereCore

/// A business's Brand Kit resolved over one appearance theme (WP-2.6; SECURITY.md §2.93): the kit's tokens are applied over the theme's
/// own palette by `ContrastPolicy.resolve(_:over:)` (clamped against that theme's grounds, with lighter/darker **derived** variants so a deep
/// brand color still reads on a black theme), plus two tints for the business's whole space:
/// * `canvas`: the theme background with a breath of the brand color (page background of the business's space);
/// * `card`: the theme surface with the same breath (cards and rows in that space).
/// Both are accepted only if the theme's own text, secondary text and accent still meet the theme's minimums on them; otherwise the theme's
/// untinted grounds are used. High-contrast themes are never tinted.
///
/// Protected elements (verified badge, business name, risk chips, approve/deny, attribution) never read this type: they use the theme
/// palette directly (`ThemedBrandPalette.protected(for:)`), whatever the kit.
public struct ThemedBrandPalette: Sendable, Hashable {
    public var themeId: AppearanceTheme.ID
    public var isBranded: Bool
    public var primary: BrandColor
    public var onPrimary: BrandColor
    public var secondary: BrandColor
    public var accent: BrandColor
    public var surface: BrandColor
    public var onSurface: BrandColor
    public var canvas: BrandColor
    public var card: BrandColor
    /// Roles Viadere replaced with the theme's own color (failed contrast even after derivation).
    public var overridden: [BrandTokenRole]
    /// Roles drawn as a lighter or darker variant of the brand color.
    public var derived: [BrandTokenRole]

    /// Twentieths of brand color mixed into the canvas / card (light, dark themes).
    static let tintSteps = (light: 2, dark: 3)

    /// The theme as a Brand Kit base.
    public static func base(_ theme: AppearanceTheme) -> ThemedBrandBase {
        let p = theme.palette
        let palette = ResolvedPalette.make(primary: p.primaryFill.color, onPrimary: p.onPrimary.color, secondary: p.textSecondary.color,
                                      accent: p.accent.color, surface: p.surface.color, onSurface: p.textPrimary.color)
        return ThemedBrandBase(palette: palette, foregrounds: [p.textPrimary.color, p.background.color], acceptsBrandSurface: !theme.isDark,
                               minimums: theme.contrast.minimums, isDark: theme.isDark, grounds: [p.background.color, p.surfaceRaised.color])
    }

    /// The protected palette in `theme`: the theme's own colors, never a kit's.
    public static func protected(for theme: AppearanceTheme) -> ThemedBrandPalette { resolve(nil, theme: theme) }

    public static func resolve(_ tokens: BrandTokens?, theme: AppearanceTheme) -> ThemedBrandPalette {
        let p = theme.palette
        var canvas = p.background.color
        var card = p.surface.color
        var base = base(theme)
        if let tokens, theme.contrast == .standard {
            // Tint first (the theme's own text decides how far), then clamp the kit against the tinted grounds as well, so its accent is
            // derived to read on the space it is drawn in.
            let steps = theme.isDark ? tintSteps.dark : tintSteps.light
            canvas = tint(p.background.color, with: tokens.primary, maxSteps: steps, theme: theme)
            card = tint(p.surface.color, with: tokens.primary, maxSteps: steps, theme: theme)
            base.grounds += [canvas, card]
        }
        let result = ContrastPolicy.resolve(tokens, over: base)
        if result.overridden.contains(.primary) {
            // No brand color survived for the fill: the space keeps the theme's own grounds.
            canvas = p.background.color
            card = p.surface.color
        }
        return ThemedBrandPalette(themeId: theme.id, isBranded: tokens != nil, primary: result.palette.primary, onPrimary: result.palette.onPrimary,
                                  secondary: result.palette.secondary, accent: result.palette.accent, surface: result.palette.surface,
                                  onSurface: result.palette.onSurface, canvas: canvas, card: card, overridden: result.overridden,
                                  derived: result.derived)
    }

    /// `ground` with up to `maxSteps` twentieths of `brand`, the strongest tint on which the theme's text levels and accent still pass.
    static func tint(_ ground: BrandColor, with brand: BrandColor, maxSteps: Int, theme: AppearanceTheme) -> BrandColor {
        let p = theme.palette
        let minimums = theme.contrast.minimums
        for step in stride(from: maxSteps, through: 1, by: -1) {
            let candidate = ContrastPolicy.mix(ground, toward: brand, step: step, of: 20)
            let legible = [p.textPrimary.color, p.textSecondary.color, p.accent.color, p.danger.color, p.success.color]
                .allSatisfy { ContrastPolicy.meets($0, candidate, minimumTimes10: minimums.text) }
                && ContrastPolicy.meets(p.textTertiary.color, candidate, minimumTimes10: theme.contrast == .high ? 45 : 30)
            if legible { return candidate }
        }
        return ground
    }
}

extension BrandAppearanceStyle {
    /// The kit's colors to re-resolve per theme: the kit's own tokens when known, else what survived the classic clamp (Loop trees).
    public var themeTokens: BrandTokens? {
        guard source == .brandKit else { return nil }
        return tokens ?? palette.keptTokens
    }

    /// This style in `theme`. Neutral styles give the theme's own palette.
    public func palette(in theme: AppearanceTheme) -> ThemedBrandPalette { ThemedBrandPalette.resolve(themeTokens, theme: theme) }
}
