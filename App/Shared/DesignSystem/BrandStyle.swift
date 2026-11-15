import SwiftUI
import ViadereCore
import ViadereKit

// MARK: - Brand Kit style (WP-2.6)
//
// Maps a verified Brand Kit (`BrandAppearanceStyle`, ViadereKit) to design-system colors and shapes, **per appearance theme**: the kit's
// tokens are re-resolved over the theme on screen (`ThemedBrandPalette`: `ContrastPolicy` clamp, lighter/darker derived variants, tinted
// canvas and cards), so a business's space follows Daybreak, Folio, Midnight, Lantern and the rest. Rules:
// * Only the roles a kit may color exist here (primary, on-primary, secondary, accent, surface, and the canvas/card tints of its space);
//   there is no API for the business name, verified badge, risk chips, attribution, approve/deny, confirmation or outcome colors: those use
//   `ViadereColor` / `BrandStyle.protected*`, always the theme's own.
// * Security surfaces set `.viadereProtectedSurface()` (neutral style for everything inside), whatever space they appear in.
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

    /// A light / dark brand color pair (already clamped); a `nil` side draws the current theme's accent.
    static func brandAccent(light: BrandColor?, dark: BrandColor?) -> Color {
        Color.viadereDynamic { theme in
            guard let color = theme.isDark ? dark : light else { return theme.palette.accent }
            return ThemeSwatch(color: color)
        }
    }
}

public struct BrandStyle: Equatable, Sendable {
    public let style: BrandAppearanceStyle

    public init(_ style: BrandAppearanceStyle = .neutral) { self.style = style }

    public static let neutral = BrandStyle()

    public var isBranded: Bool { style.source == .brandKit }

    /// The kit's tokens to resolve per theme (`nil` = neutral).
    private var tokens: BrandTokens? { style.themeTokens }

    /// One role of the kit in the current theme.
    private func role(_ pick: @escaping @Sendable (ThemedBrandPalette) -> BrandColor) -> Color {
        let tokens = tokens
        return Color.viadereDynamic { theme in ThemeSwatch(color: pick(ViadereThemeRuntime.shared.brand(tokens, theme: theme))) }
    }

    /// Fills of branded, non-protected elements: the header band, the business space's own actions.
    public var primary: Color { isBranded ? role({ $0.primary }) : ViadereColor.primaryFill }
    public var onPrimary: Color { isBranded ? role({ $0.onPrimary }) : ViadereColor.onPrimary }
    public var secondary: Color { isBranded ? role({ $0.secondary }) : ViadereColor.textSecondary }
    /// Icons, section rules and accent lines in the business space.
    public var accent: Color { isBranded ? role({ $0.accent }) : ViadereColor.accent }
    public var surface: Color { isBranded ? role({ $0.surface }) : ViadereColor.surface }
    public var onSurface: Color { isBranded ? role({ $0.onSurface }) : ViadereColor.textPrimary }
    /// The business space's page ground: the theme background with a breath of the brand color (untinted in high contrast).
    public var canvas: Color { isBranded ? role({ $0.canvas }) : ViadereColor.background }
    /// Cards and rows in the business space.
    public var card: Color { isBranded ? role({ $0.card }) : ViadereColor.surface }

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
    /// The Brand Kit style of the business space being shown (its page, thread, offers); neutral everywhere else and inside every
    /// `.viadereProtectedSurface()`.
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
                .fill(Color.brandAccent(light: decoration.accentLight, dark: decoration.accentDark))
                .frame(width: 3)
                .accessibilityHidden(true)
        }
    }
}

/// A business's monogram drawn in the band's own ink (no logo yet, or none): initials only, never a verified mark (the badge is drawn
/// by the caller in protected colors).
public struct BrandMonogram: View {
    let name: String
    let ink: Color
    let size: CGFloat

    public init(name: String, ink: Color, size: CGFloat = 72) {
        self.name = name
        self.ink = ink
        self.size = size
    }

    private var initials: String {
        let words = name.split(whereSeparator: { $0 == " " || $0 == "-" }).prefix(2)
        return words.compactMap(\.first).map { String($0).uppercased() }.joined()
    }

    public var body: some View {
        let shape = RoundedRectangle(cornerRadius: size * 0.22, style: .continuous)
        Text(initials)
            .font(.system(size: size * 0.36, weight: .semibold, design: .default))
            .foregroundStyle(ink)
            .frame(width: size, height: size)
            .overlay(shape.strokeBorder(ink.opacity(0.5), lineWidth: 1.5))
            .accessibilityHidden(true)
    }
}

/// The business's own (non-security) actions inside its space: the kit's primary fill and ink; Viadere's secondary button when neutral.
public struct BrandButtonStyle: ButtonStyle {
    let brand: BrandStyle

    public init(_ brand: BrandStyle) { self.brand = brand }

    @ViewBuilder
    public func makeBody(configuration: Configuration) -> some View {
        if brand.isBranded {
            let shape = RoundedRectangle(cornerRadius: ViadereRadius.button, style: .continuous)
            configuration.label
                .font(ViadereType.headline)
                .foregroundStyle(brand.onPrimary)
                .lineLimit(1)
                .padding(.horizontal, 22)
                .frame(maxWidth: .infinity, minHeight: 52)
                .background { shape.fill(brand.primary).opacity(configuration.isPressed ? 0.86 : 1) }
                .contentShape(shape)
                .scaleEffect(configuration.isPressed ? 0.985 : 1)
                .animation(ViadereMotion.quick, value: configuration.isPressed)
        } else {
            ViadereButtonStyle(.secondary).makeBody(configuration: configuration)
        }
    }
}

extension ButtonStyle where Self == BrandButtonStyle {
    /// `.buttonStyle(.brand(style))`: never on an approval, sign-in, payment or verification action.
    public static func brand(_ style: BrandStyle) -> BrandButtonStyle { BrandButtonStyle(style) }
}
