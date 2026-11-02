import Foundation
import ViadereCore

/// The contrast contract every appearance theme meets, as checks over `ContrastPolicy`'s integer WCAG arithmetic (the same numbers the
/// Brand Kit clamp uses). Text minimum = 4.5:1 (7:1 for high contrast), non-text = 3:1 (4.5:1 for high contrast).
public enum AppearanceThemeAudit {
    public struct Check: Sendable, Hashable, CustomStringConvertible {
        public var theme: AppearanceTheme.ID
        public var name: String
        public var ratioTimes100: Int64
        public var minimumTimes10: Int64
        /// `ContrastPolicy.meets` (exact); `ratioTimes100` is rounded down and only for the message.
        public var passes: Bool
        public var description: String {
            "\(theme.rawValue) \(name): \(Double(ratioTimes100) / 100):1 < \(Double(minimumTimes10) / 10):1"
        }
    }

    public static func checks(_ theme: AppearanceTheme) -> [Check] {
        let p = theme.palette
        let m = theme.contrast.minimums
        let high = theme.contrast == .high
        var out: [Check] = []
        func add(_ name: String, _ a: BrandColor, _ b: BrandColor, _ minimum: Int64) {
            out.append(Check(theme: theme.id, name: name, ratioTimes100: ContrastPolicy.ratioTimes100(a, b), minimumTimes10: minimum,
                             passes: ContrastPolicy.meets(a, b, minimumTimes10: minimum)))
        }
        let grounds: [(String, BrandColor)] = [("background", p.background.color), ("surface", p.surface.color),
                                               ("surfaceRaised", p.surfaceRaised.color)]
        for (ground, color) in grounds {
            add("textPrimary on \(ground)", p.textPrimary.color, color, m.text)
            add("textSecondary on \(ground)", p.textSecondary.color, color, m.text)
            add("textTertiary on \(ground)", p.textTertiary.color, color, high ? 45 : 30)
            add("accent on \(ground)", p.accent.color, color, m.text)
            add("danger on \(ground)", p.danger.color, color, m.text)
            add("success on \(ground)", p.success.color, color, m.text)
            add("warning on \(ground)", p.warning.color, color, m.text)
        }
        // Segmented controls and switch tracks carry labels.
        add("textPrimary on track", p.textPrimary.color, p.track.color, m.text)
        add("textSecondary on track", p.textSecondary.color, p.track.color, m.text)
        // Primary buttons.
        add("onPrimary on primaryFill", p.onPrimary.color, p.primaryFill.color, m.text)
        add("primaryFill on background", p.primaryFill.color, p.background.color, m.nonText)
        add("primaryFill on surface", p.primaryFill.color, p.surface.color, m.nonText)
        // Badges and tinted buttons: the text on its own tint over a surface.
        add("accent on accentSoft", p.accent.color, p.accentSoft.composited(over: p.surface.color), m.text)
        add("danger on danger tint", p.danger.color,
            ThemeSwatch(color: p.danger.color, opacity: ThemePalette.dangerTintOpacity).composited(over: p.surface.color), m.text)
        add("success on success tint", p.success.color,
            ThemeSwatch(color: p.success.color, opacity: ThemePalette.successTintOpacity).composited(over: p.surface.color), m.text)
        // Switches: the on state against its ground, the knob against the on fill (WCAG 1.4.11 has no AAA level: 3:1).
        add("switchOn on background", p.switchOn.color, p.background.color, m.nonText)
        add("switchOn on surface", p.switchOn.color, p.surface.color, m.nonText)
        // The focus ring / text-field border is the accent.
        add("accent (focus) on surface", p.accent.color, p.surface.color, m.nonText)
        if high {
            // The knob against the on fill (WCAG 1.4.11 has no AAA level: 3:1). Standard themes rely on the knob's position and shadow.
            add("knob on switchOn", p.knob.color, p.switchOn.color, 30)
            // High contrast: hairlines are real borders (WCAG 1.4.11) and outline the switch knob.
            add("hairline on surface", p.hairline.composited(over: p.surface.color), p.surface.color, 30)
            add("hairline on background", p.hairline.composited(over: p.background.color), p.background.color, 30)
            // The knob stands out from the off track by itself, or by its hairline outline.
            let knobOutline = p.hairline.composited(over: p.knob.color)
            let knobVisible = ContrastPolicy.meets(p.knob.color, p.track.color, minimumTimes10: 30) ? p.track.color : knobOutline
            add("knob on track (or its outline)", knobVisible, p.knob.color, 30)
        }
        return out
    }

    public static func failures(_ theme: AppearanceTheme) -> [Check] { checks(theme).filter { !$0.passes } }

    /// Checks of a Brand Kit resolved over `theme`: every brand role the kit got (not replaced) meets the theme's minimums on the grounds
    /// it is drawn on, and the tinted canvas / card keep the theme's own text legible.
    public static func brandFailures(_ brand: ThemedBrandPalette, theme: AppearanceTheme) -> [Check] {
        let p = theme.palette
        let m = theme.contrast.minimums
        var out: [Check] = []
        func add(_ name: String, _ a: BrandColor, _ b: BrandColor, _ minimum: Int64) {
            if !ContrastPolicy.meets(a, b, minimumTimes10: minimum) {
                out.append(Check(theme: theme.id, name: "brand " + name, ratioTimes100: ContrastPolicy.ratioTimes100(a, b), minimumTimes10: minimum,
                                 passes: false))
            }
        }
        add("onPrimary on primary", brand.onPrimary, brand.primary, m.text)
        add("primary on surface", brand.primary, brand.surface, m.nonText)
        add("accent on card", brand.accent, brand.card, m.nonText)
        add("accent on canvas", brand.accent, brand.canvas, m.nonText)
        add("onSurface on surface", brand.onSurface, brand.surface, m.text)
        add("secondary on surface", brand.secondary, brand.surface, m.text)
        add("accent on surface", brand.accent, brand.surface, m.nonText)
        for (ground, color) in [("canvas", brand.canvas), ("card", brand.card)] {
            add("textPrimary on \(ground)", p.textPrimary.color, color, m.text)
            add("textSecondary on \(ground)", p.textSecondary.color, color, m.text)
            add("accent on \(ground)", p.accent.color, color, m.text)
            add("danger on \(ground)", p.danger.color, color, m.text)
        }
        return out
    }
}
