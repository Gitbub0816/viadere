import Foundation
import ViadereCore

/// What the top of a business page draws (owner decision: an approved kit themes the business's whole space). Branded: a band in the
/// kit's primary color (or its derived variant for the theme), with the verified logo or a monogram in the band's own ink, on the
/// brand-tinted canvas. Neutral: no band, Viadere's monogram avatar on the theme background. The business name, verified badge and handle
/// are drawn below the band in the theme's protected colors, never from this type.
public struct BrandHeaderBand: Sendable, Hashable {
    public var isBranded: Bool
    public var fill: BrandColor
    /// Monogram / glyph color on `fill` (text minimum of the theme).
    public var ink: BrandColor
    public var accent: BrandColor
    public var canvas: BrandColor
    /// Verified logo bytes are shown; otherwise the monogram in `ink`.
    public var showsLogo: Bool
}

extension BusinessHomeDecoration {
    /// The header band in `theme`.
    public func headerBand(in theme: AppearanceTheme) -> BrandHeaderBand {
        let palette = style.palette(in: theme)
        guard palette.isBranded else {
            return BrandHeaderBand(isBranded: false, fill: theme.palette.surfaceRaised.color, ink: theme.palette.textPrimary.color,
                                   accent: theme.palette.accent.color, canvas: theme.palette.background.color, showsLogo: false)
        }
        return BrandHeaderBand(isBranded: true, fill: palette.primary, ink: palette.onPrimary, accent: palette.accent, canvas: palette.canvas,
                               showsLogo: logo != nil)
    }
}

/// Brand styling of an alert card (owner decision: alert accents follow the business's kit). Only **informational** business items
/// (`AlertCategory.update`) with a purpose `BrandSurfacePolicy` allows are styled; approvals, requests (which include sign-in and
/// authorization), verification, link confirmations, security notices and unknown categories always render neutral.
public enum AlertBrandStyle {
    public static func allowsBranding(_ entry: AlertEntry) -> Bool {
        guard entry.category == .update, let business = entry.business, business.isVerified else { return false }
        return BrandSurfacePolicy.allowsBranding(purpose: entry.purpose, kind: .status)
    }

    public static func make(_ entry: AlertEntry, brand: BrandKitStore?) -> BrandAppearanceStyle {
        guard allowsBranding(entry), let business = entry.business, let brand else { return .neutral }
        return brand.resolution(for: business.id, surface: .interaction(purpose: entry.purpose, kind: .status)).style
    }
}
