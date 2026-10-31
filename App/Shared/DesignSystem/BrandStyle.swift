import SwiftUI
import ViadereCore
import ViadereKit

// MARK: - Brand Kit style (WP-2.6)
//
// Maps a verified, contrast-clamped `BrandAppearanceStyle` (ViadereKit) to design-system colors and shapes. Rules:
// * Only the roles a kit may color exist here (primary, on-primary, secondary, accent, surface); there is no API for text, labels,
//   badges, risk chips, attribution, confirmation or outcome colors: those use `ViadereColor` / `BrandStyle.protected*`, always neutral.
// * Light and dark come from the clamped palettes (`ContrastPolicy`), so a token that fails contrast is already Viadere's own.
// * Frames are drawn behind content, never over it, and are decorative (hidden from accessibility).

extension BrandColor {
    /// `0xRRGGBB`.
    var rgbValue: UInt32 {
        let c = rgb
        return (UInt32(c.red) << 16) | (UInt32(c.green) << 8) | UInt32(c.blue)
    }
}

extension Color {
    /// A dynamic color from a light and a dark brand color (already clamped).
    init(brandLight light: BrandColor, dark: BrandColor) {
        self.init(viadereLight: light.rgbValue, dark: dark.rgbValue)
    }

    /// A dynamic color with optional brand values; a `nil` side uses `fallback`'s Viadere hex for that appearance.
    init(brandLight light: BrandColor?, dark: BrandColor?, fallbackLight: UInt32, fallbackDark: UInt32) {
        self.init(viadereLight: light?.rgbValue ?? fallbackLight, dark: dark?.rgbValue ?? fallbackDark)
    }
}

public struct BrandStyle: Equatable {
    public let style: BrandAppearanceStyle

    public init(_ style: BrandAppearanceStyle = .neutral) { self.style = style }

    public static let neutral = BrandStyle()

    public var isBranded: Bool { style.source == .brandKit }

    private var light: ResolvedPalette { style.palette.light }
    private var dark: ResolvedPalette { style.palette.dark }

    /// Fills of branded, non-protected elements (page accents, the branded header band, secondary buttons on the business home).
    public var primary: Color { isBranded ? Color(brandLight: light.primary, dark: dark.primary) : ViadereColor.primaryFill }
    public var onPrimary: Color { isBranded ? Color(brandLight: light.onPrimary, dark: dark.onPrimary) : ViadereColor.onPrimary }
    public var secondary: Color { isBranded ? Color(brandLight: light.secondary, dark: dark.secondary) : ViadereColor.textSecondary }
    public var accent: Color { isBranded ? Color(brandLight: light.accent, dark: dark.accent) : ViadereColor.accent }
    public var surface: Color { isBranded ? Color(brandLight: light.surface, dark: dark.surface) : ViadereColor.surface }
    public var onSurface: Color { isBranded ? Color(brandLight: light.onSurface, dark: dark.onSurface) : ViadereColor.textPrimary }

    public var cornerRadius: CGFloat {
        switch style.radius {
        case .none: 0
        case .small: ViadereRadius.chip
        case .medium: ViadereRadius.card
        case .large: ViadereRadius.sheet
        }
    }

    public var borderWidth: CGFloat {
        switch style.border {
        case .none: 0
        case .hairline: 1
        case .regular: 2
        }
    }

    // Protected elements: always Viadere's neutral colors, whatever the kit.
    public static let protectedText = ViadereColor.textPrimary
    public static let protectedSecondaryText = ViadereColor.textSecondary
    public static let protectedSurface = ViadereColor.surface
    public static let protectedAccent = ViadereColor.accent
}

private struct BrandStyleKey: EnvironmentKey {
    static let defaultValue = BrandStyle.neutral
}

extension EnvironmentValues {
    /// The business home's Brand Kit style; neutral everywhere else.
    public var brandStyle: BrandStyle {
        get { self[BrandStyleKey.self] }
        set { self[BrandStyleKey.self] = newValue }
    }
}

// MARK: - Frames

/// A Viadere-authored decorative frame from the registry (`FrameRegistry`); unknown ids draw nothing. Always behind content.
public struct BrandFrame: View {
    let id: String?
    let style: BrandStyle

    public init(id: String?, style: BrandStyle) {
        self.id = id
        self.style = style
    }

    public var body: some View {
        Group {
            switch id {
            case "viadere.frame.hairline.v1":
                RoundedRectangle(cornerRadius: style.cornerRadius, style: .continuous)
                    .strokeBorder(style.accent.opacity(0.55), lineWidth: 1)
            case "viadere.frame.snow.v1":
                Canvas { context, size in
                    // A light, deterministic scatter along the top edge only.
                    for i in 0..<18 {
                        let x = size.width * CGFloat((i * 37) % 100) / 100
                        let y = CGFloat((i * 13) % 28) + 6
                        let r = CGFloat(1 + (i % 3))
                        context.fill(Path(ellipseIn: CGRect(x: x, y: y, width: r * 2, height: r * 2)), with: .color(style.accent.opacity(0.35)))
                    }
                }
            default:
                EmptyView()
            }
        }
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }
}

extension View {
    /// Draws the business's frame **behind** this view (never over it).
    public func brandFrameBackground(_ style: BrandStyle) -> some View {
        background(BrandFrame(id: style.style.frameId, style: style))
    }
}

// MARK: - Pieces

/// The verified logo of a business (bytes already hash-checked by `BrandKitStore`), or Viadere's monogram avatar. The name and the
/// verified badge are drawn by the caller in neutral colors; the logo never replaces them.
public struct BrandLogo: View {
    let data: Data?
    let name: String
    let isVerified: Bool
    let size: CGFloat
    let accessibilityLabel: String?

    public init(data: Data?, name: String, isVerified: Bool, size: CGFloat = 72, accessibilityLabel: String? = nil) {
        self.data = data
        self.name = name
        self.isVerified = isVerified
        self.size = size
        self.accessibilityLabel = accessibilityLabel
    }

    public var body: some View {
        #if canImport(UIKit) && !os(watchOS)
        if let data, let image = UIImage(data: data) {
            Image(uiImage: image)
                .resizable()
                .interpolation(.high)
                .scaledToFit()
                .frame(width: size, height: size)
                .clipShape(RoundedRectangle(cornerRadius: size * 0.22, style: .continuous))
                .overlay(RoundedRectangle(cornerRadius: size * 0.22, style: .continuous).strokeBorder(ViadereColor.hairline, lineWidth: 1))
                .accessibilityLabel(Text(accessibilityLabel ?? name))
        } else {
            ViadereAvatar(name: name, size: size, isVerified: isVerified)
        }
        #else
        ViadereAvatar(name: name, size: size, isVerified: isVerified)
        #endif
    }
}

/// The thin brand accent line on a message card (C4.4): decoration only, next to (never over) the sender's name and badge.
public struct BrandAccentLine: View {
    let decoration: MessageCardDecoration?

    public init(_ decoration: MessageCardDecoration?) { self.decoration = decoration }

    public var body: some View {
        if let decoration, decoration.accentLight != nil || decoration.accentDark != nil {
            Capsule()
                .fill(Color(brandLight: decoration.accentLight, dark: decoration.accentDark, fallbackLight: 0x8C7550, fallbackDark: 0xCDB993))
                .frame(width: 3)
                .accessibilityHidden(true)
        }
    }
}
