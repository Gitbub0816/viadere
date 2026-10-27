//
//  ViadereMark.swift
//  Viadere brand: the "via" ribbon mark, wordmark, lockups and brand palette.
//
//  GENERATED from the same Bézier data as Design/svg/*.svg (see Design/README.md).
//  Self-contained: SwiftUI only. Drop this file into the app target.
//
//  Usage:
//      ViadereMark()                              // adapts: primary on light, light ribbon in dark mode
//      ViadereMark(style: .primary)               // charcoal → ivory → champagne
//      ViadereMark(style: .onDark)                // tuned for black / charcoal backgrounds
//      ViadereMark.monochrome(.white)             // single colour (twist kept with opacity)
//      ViadereMarkShape()                         // plain silhouette Shape (masks, clips, outlines)
//      ViadereWordmark(size: 28)                  // "via" semibold + "dere" light
//      ViadereLockup(.horizontal, ribbonHeight: 32)
//
//  The mark scales from any frame and always keeps its aspect ratio
//  (321.71 × 146, ribbon 321.71 × 100 plus the dot).
//

import SwiftUI

// MARK: - Brand palette

/// Viadere core palette. Semantic, appearance-aware colours live in the asset catalog
/// (`Colors/*.colorset`) and in `ViadereDesignSystem.swift` (`ViadereColor`).
public enum ViadereBrand {
    public static let charcoal      = Color(viadereHex: 0x1F1E1C)   // primary dark, text, mark (light bg)
    public static let graphite      = Color(viadereHex: 0x4A4844)   // secondary dark
    public static let silver        = Color(viadereHex: 0xC9C4BB)   // neutral mid-tone, ribbon highlight
    public static let ivory         = Color(viadereHex: 0xF5F2EC)   // primary light, backgrounds
    public static let champagne     = Color(viadereHex: 0xC2AE8E)   // accent / ribbon end
    public static let champagneDeep = Color(viadereHex: 0x8C7550)   // accent text on ivory (AA)
    public static let black         = Color(viadereHex: 0x121211)   // dark-mode background

    /// Width ÷ height of the full mark (ribbon + dot).
    public static let markAspectRatio: CGFloat = 2.2
    /// Width ÷ height of the ribbon alone (the dot excluded).
    public static let ribbonAspectRatio: CGFloat = 3.22
}

extension Color {
    /// sRGB colour from a 0xRRGGBB literal.
    init(viadereHex hex: UInt32, opacity: Double = 1) {
        self.init(.sRGB,
                  red: Double((hex >> 16) & 0xFF) / 255,
                  green: Double((hex >> 8) & 0xFF) / 255,
                  blue: Double(hex & 0xFF) / 255,
                  opacity: opacity)
    }
}

// MARK: - Geometry (view-box units)

/// Cubic Bézier outlines of the mark in a 321.71 × 146 view box (y down).
/// Each path is `[x0, y0, c1x, c1y, c2x, c2y, x, y, …]`: a start point followed by cubic segments.
enum ViadereMarkGeometry {
    static let width: CGFloat = 321.71
    static let height: CGFloat = 146
    /// Ribbon occupies y = ribbonTop … ribbonTop + 100.
    static let ribbonTop: CGFloat = 46

    /// Full ribbon outline (back face shows through the twist lenses).
    static let silhouette: [CGFloat] = [
        0, 46, 31.34, 46, 52.61, 53.08, 58.62, 61.38, 68.66, 75.25, 78.7, 89.12,
        88.74, 102.99, 97.57, 90.82, 106.39, 78.66, 115.22, 66.49, 130.87, 44.9, 156.4, 45.68,
        170.7, 68.18, 176.91, 77.94, 183.11, 87.69, 189.31, 97.44, 198.07, 85.47, 206.83, 73.5,
        215.59, 61.52, 231.34, 40, 256.71, 40.99, 270.74, 63.66, 287.73, 91.11, 304.72, 118.55,
        321.71, 146, 290.37, 146, 271.7, 141.91, 268.73, 137.12, 259.42, 122.07, 250.1, 107.02,
        240.79, 91.98, 231.72, 104.38, 222.64, 116.77, 213.57, 129.17, 198.67, 149.53, 174.45, 148.74,
        160.91, 127.45, 154.3, 117.06, 147.7, 106.67, 141.09, 96.28, 132.77, 107.75, 124.45, 119.22,
        116.14, 130.69, 101.32, 151.11, 76.1, 151.1, 61.31, 130.67, 40.87, 102.44, 20.44, 74.22,
        0, 46
    ]

    /// Front faces, left to right: the "v" stroke, the "i" arch, the "a" arch.
    static let fronts: [[CGFloat]] = [
        [
            0, 46, 31.34, 46, 52.61, 53.08, 58.62, 61.38, 68.66, 75.25, 78.7, 89.12,
            88.74, 102.99, 101.18, 120.16, 102.65, 139.14, 118.23, 127.81, 117.53, 128.77, 116.83, 129.73,
            116.14, 130.69, 101.32, 151.11, 76.1, 151.1, 61.31, 130.67, 40.87, 102.44, 20.44, 74.22,
            0, 46
        ],
        [
            113.12, 69.37, 113.82, 68.41, 114.52, 67.45, 115.22, 66.49, 130.87, 44.9, 156.4, 45.68,
            170.7, 68.18, 176.91, 77.94, 183.11, 87.69, 189.31, 97.44, 200.84, 115.58, 199.82, 137.73,
            215.67, 126.3, 214.97, 127.26, 214.27, 128.22, 213.57, 129.17, 198.67, 149.53, 174.45, 148.74,
            160.91, 127.45, 154.3, 117.06, 147.7, 106.67, 141.09, 96.28, 129.64, 78.27, 128.81, 57.95,
            113.12, 69.37
        ],
        [
            213.49, 64.4, 214.19, 63.44, 214.89, 62.48, 215.59, 61.52, 231.34, 40, 256.71, 40.99,
            270.74, 63.66, 287.73, 91.11, 304.72, 118.55, 321.71, 146, 290.37, 146, 271.7, 141.91,
            268.73, 137.12, 259.42, 122.07, 250.1, 107.02, 240.79, 91.98, 229.56, 73.83, 229.23, 53.05,
            213.49, 64.4
        ]
    ]

    /// Back faces seen through the twist (between the front faces).
    static let lenses: [[CGFloat]] = [
        [
            88.74, 102.99, 101.18, 120.16, 102.65, 139.14, 118.23, 127.81, 125.85, 117.3, 133.47, 106.79,
            141.09, 96.28, 129.64, 78.27, 128.81, 57.95, 113.12, 69.37, 105, 80.58, 96.87, 91.78,
            88.74, 102.99
        ],
        [
            189.31, 97.44, 200.84, 115.58, 199.82, 137.73, 215.67, 126.3, 224.05, 114.86, 232.42, 103.42,
            240.79, 91.98, 229.56, 73.83, 229.23, 53.05, 213.49, 64.4, 205.43, 75.41, 197.37, 86.43,
            189.31, 97.44
        ]
    ]

    /// Gradient axis of each lens: [x1, y1, x2, y2] (trough end → crest end).
    static let lensAxes: [[CGFloat]] = [
        [88.74, 102.99, 113.12, 69.37],
        [189.31, 97.44, 213.49, 64.4]
    ]

    /// The dot (identity) above the "i" rise.
    static let dotCenter = CGPoint(x: 155.21, y: 20.5)
    static let dotRadius: CGFloat = 20.5
}

/// Draws one outline from `ViadereMarkGeometry`, aspect-fitted and centred in the rect.
struct ViadereMarkPath: Shape {
    let data: [CGFloat]

    func path(in rect: CGRect) -> Path {
        let t = ViadereMarkTransform(rect)
        var path = Path()
        guard data.count >= 8 else { return path }
        path.move(to: t.point(data[0], data[1]))
        var i = 2
        while i + 5 < data.count {
            path.addCurve(to: t.point(data[i + 4], data[i + 5]),
                          control1: t.point(data[i], data[i + 1]),
                          control2: t.point(data[i + 2], data[i + 3]))
            i += 6
        }
        path.closeSubpath()
        return path
    }
}

struct ViadereMarkDot: Shape {
    func path(in rect: CGRect) -> Path {
        let t = ViadereMarkTransform(rect)
        let c = t.point(ViadereMarkGeometry.dotCenter.x, ViadereMarkGeometry.dotCenter.y)
        let r = ViadereMarkGeometry.dotRadius * t.scale
        return Path(ellipseIn: CGRect(x: c.x - r, y: c.y - r, width: r * 2, height: r * 2))
    }
}

/// The full mark silhouette (ribbon + dot) as a single Shape. Useful for masks, clips and outlines.
public struct ViadereMarkShape: Shape {
    public init() {}
    public func path(in rect: CGRect) -> Path {
        var path = ViadereMarkPath(data: ViadereMarkGeometry.silhouette).path(in: rect)
        path.addPath(ViadereMarkDot().path(in: rect))
        return path
    }
}

struct ViadereMarkTransform {
    let scale: CGFloat
    let origin: CGPoint

    init(_ rect: CGRect) {
        let w = ViadereMarkGeometry.width, h = ViadereMarkGeometry.height
        let s = max(0, min(rect.width / w, rect.height / h))
        scale = s
        origin = CGPoint(x: rect.minX + (rect.width - w * s) / 2,
                         y: rect.minY + (rect.height - h * s) / 2)
    }

    func point(_ x: CGFloat, _ y: CGFloat) -> CGPoint {
        CGPoint(x: origin.x + x * scale, y: origin.y + y * scale)
    }
}

// MARK: - Styles

public enum ViadereMarkStyle {
    /// `.primary` in light mode, `.onDark` in dark mode.
    case automatic
    /// Charcoal → ivory → champagne, for ivory / white backgrounds.
    case primary
    /// Ivory → champagne ribbon with a light dot, for black / charcoal backgrounds.
    case onDark
    /// One flat colour; the twist is kept by drawing the back faces at reduced opacity.
    case monochrome(Color)
}

struct ViadereMarkTheme {
    let base: Color
    let fronts: [Gradient]
    let lenses: [Gradient]
    let dot: Gradient

    static let primary = ViadereMarkTheme(
            base: Color(viadereHex: 0x5E5A54),
            fronts: [
                Gradient(stops: [.init(color: Color(viadereHex: 0x41403D), location: 0), .init(color: Color(viadereHex: 0x2A2927), location: 0.45), .init(color: Color(viadereHex: 0x1C1B19), location: 1)]),
                Gradient(stops: [.init(color: Color(viadereHex: 0xD8D1C5), location: 0), .init(color: Color(viadereHex: 0xBDB5A8), location: 0.3), .init(color: Color(viadereHex: 0x5C5954), location: 0.62), .init(color: Color(viadereHex: 0x22211F), location: 1)]),
                Gradient(stops: [.init(color: Color(viadereHex: 0xD5C9B4), location: 0), .init(color: Color(viadereHex: 0xBEAE93), location: 0.5), .init(color: Color(viadereHex: 0x958268), location: 1)])
            ],
            lenses: [
                Gradient(stops: [.init(color: Color(viadereHex: 0x2B2A27), location: 0), .init(color: Color(viadereHex: 0x7A756D), location: 0.45), .init(color: Color(viadereHex: 0xCEC6B9), location: 1)]),
                Gradient(stops: [.init(color: Color(viadereHex: 0x8F897F), location: 0), .init(color: Color(viadereHex: 0xCFC8BC), location: 0.5), .init(color: Color(viadereHex: 0xE9E2D6), location: 1)])
            ],
            dot: Gradient(colors: [Color(viadereHex: 0x4A4845), Color(viadereHex: 0x1C1B19)])
        )

    static let onDark = ViadereMarkTheme(
            base: Color(viadereHex: 0x8D877D),
            fronts: [
                Gradient(stops: [.init(color: Color(viadereHex: 0xD9D4CB), location: 0), .init(color: Color(viadereHex: 0x9A948A), location: 1)]),
                Gradient(stops: [.init(color: Color(viadereHex: 0xF5F1EA), location: 0), .init(color: Color(viadereHex: 0xDCD6CC), location: 0.55), .init(color: Color(viadereHex: 0xA49D92), location: 1)]),
                Gradient(stops: [.init(color: Color(viadereHex: 0xECE3D3), location: 0), .init(color: Color(viadereHex: 0xD7C9B0), location: 0.5), .init(color: Color(viadereHex: 0xAD9978), location: 1)])
            ],
            lenses: [
                Gradient(stops: [.init(color: Color(viadereHex: 0x4B4843), location: 0), .init(color: Color(viadereHex: 0x8C867C), location: 0.5), .init(color: Color(viadereHex: 0xC9C2B6), location: 1)]),
                Gradient(stops: [.init(color: Color(viadereHex: 0x5E584F), location: 0), .init(color: Color(viadereHex: 0xA39A8B), location: 0.5), .init(color: Color(viadereHex: 0xD3C8B4), location: 1)])
            ],
            dot: Gradient(colors: [Color(viadereHex: 0xFFFDF8), Color(viadereHex: 0xD3CCC0)])
        )
}

// MARK: - Mark view

public struct ViadereMark: View {
    private let style: ViadereMarkStyle
    @Environment(\.colorScheme) private var colorScheme

    public init(style: ViadereMarkStyle = .automatic) {
        self.style = style
    }

    /// Single-colour mark, e.g. `ViadereMark.monochrome(.white)`.
    public static func monochrome(_ color: Color) -> ViadereMark {
        ViadereMark(style: .monochrome(color))
    }

    public var body: some View {
        GeometryReader { proxy in
            let scale = min(proxy.size.width / ViadereMarkGeometry.width,
                            proxy.size.height / ViadereMarkGeometry.height)
            layers(scale: scale)
        }
        .aspectRatio(ViadereBrand.markAspectRatio, contentMode: .fit)
        .accessibilityElement()
        .accessibilityLabel(Text("Viadere"))
        .accessibilityAddTraits(.isImage)
    }

    @ViewBuilder
    private func layers(scale: CGFloat) -> some View {
        switch style {
        case .monochrome(let color):
            ZStack {
                ViadereMarkPath(data: ViadereMarkGeometry.silhouette).fill(color.opacity(0.62))
                ForEach(0..<ViadereMarkGeometry.fronts.count, id: \.self) { i in
                    ViadereMarkPath(data: ViadereMarkGeometry.fronts[i]).fill(color)
                }
                ViadereMarkDot().fill(color)
            }
        case .primary:
            themed(.primary, scale: scale)
        case .onDark:
            themed(.onDark, scale: scale)
        case .automatic:
            themed(colorScheme == .dark ? .onDark : .primary, scale: scale)
        }
    }

    private func themed(_ theme: ViadereMarkTheme, scale: CGFloat) -> some View {
        let w = ViadereMarkGeometry.width, h = ViadereMarkGeometry.height
        let top = UnitPoint(x: 0.5, y: ViadereMarkGeometry.ribbonTop / h)
        let bottom = UnitPoint(x: 0.5, y: (ViadereMarkGeometry.ribbonTop + 100) / h)
        let c = ViadereMarkGeometry.dotCenter, r = ViadereMarkGeometry.dotRadius
        // Radial highlight sits up and to the left of the dot's centre.
        let dotHighlight = UnitPoint(x: (c.x - r + 0.72 * r) / w, y: (c.y - r + 0.64 * r) / h)
        return ZStack {
            ViadereMarkPath(data: ViadereMarkGeometry.silhouette).fill(theme.base)
            ForEach(0..<ViadereMarkGeometry.lenses.count, id: \.self) { i in
                let a = ViadereMarkGeometry.lensAxes[i]
                ViadereMarkPath(data: ViadereMarkGeometry.lenses[i]).fill(
                    LinearGradient(gradient: theme.lenses[i],
                                   startPoint: UnitPoint(x: a[0] / w, y: a[1] / h),
                                   endPoint: UnitPoint(x: a[2] / w, y: a[3] / h)))
            }
            ForEach(0..<ViadereMarkGeometry.fronts.count, id: \.self) { i in
                ViadereMarkPath(data: ViadereMarkGeometry.fronts[i]).fill(
                    LinearGradient(gradient: theme.fronts[i], startPoint: top, endPoint: bottom))
            }
            ViadereMarkDot().fill(
                RadialGradient(gradient: theme.dot, center: dotHighlight,
                               startRadius: 0, endRadius: 1.44 * r * scale))
        }
    }
}

// MARK: - Wordmark

/// Lowercase `viadere`: "via" semibold, "dere" light.
/// Uses the bundled Outfit font (App/Resources/Fonts, SIL OFL 1.1; register the files under
/// `UIAppFonts` in Info.plist). If the font is not registered, SwiftUI falls back to the system font.
/// For pixel-exact artwork use the `Wordmark` / `LockupHorizontal` vector image sets instead.
public struct ViadereWordmark: View {
    public enum Typeface {
        /// Outfit (the brand face, outlined in the SVG/PDF artwork).
        case outfit
        /// SF Pro Rounded, no bundled font required.
        case sfRounded
    }

    private let size: CGFloat
    private let typeface: Typeface
    private let viaColor: Color?
    private let dereColor: Color?
    @Environment(\.colorScheme) private var colorScheme

    public init(size: CGFloat = 28, typeface: Typeface = .outfit, viaColor: Color? = nil, dereColor: Color? = nil) {
        self.size = size
        self.typeface = typeface
        self.viaColor = viaColor
        self.dereColor = dereColor
    }

    public var body: some View {
        let dark = colorScheme == .dark
        let via = viaColor ?? (dark ? Color(viadereHex: 0xF3EFE8) : Color(viadereHex: 0x1F1E1C))
        let dere = dereColor ?? (dark ? Color(viadereHex: 0xB9B2A7) : Color(viadereHex: 0x3E3C39))
        return (Text("via").font(font(heavy: true)).foregroundStyle(via)
              + Text("dere").font(font(heavy: false)).foregroundStyle(dere))
            .kerning(-0.008 * size)
            .lineLimit(1)
            .fixedSize()
            .accessibilityLabel(Text("Viadere"))
    }

    private func font(heavy: Bool) -> Font {
        switch typeface {
        case .outfit:
            return .custom(heavy ? "Outfit-SemiBold" : "Outfit-Light", fixedSize: size)
        case .sfRounded:
            return .system(size: size, weight: heavy ? .semibold : .light, design: .rounded)
        }
    }

    /// Width of the outlined wordmark in ems (Outfit), for layout maths.
    static let emWidth: CGFloat = 3.39
    /// x-height of Outfit SemiBold in ems.
    static let xHeight: CGFloat = 0.48
}

// MARK: - Lockups

/// Mark + wordmark with the brand-guide proportions.
/// Horizontal: wordmark x-height = 0.73 × ribbon height, gap = 0.26 × ribbon height, baseline 0.1 × ribbon height above the ribbon bottom.
/// Stacked: wordmark ≈ 1.36 × ribbon width, centred under the mark.
public struct ViadereLockup: View {
    public enum Layout { case horizontal, stacked }

    private let layout: Layout
    private let ribbonHeight: CGFloat
    private let markStyle: ViadereMarkStyle
    private let typeface: ViadereWordmark.Typeface

    public init(_ layout: Layout = .horizontal, ribbonHeight: CGFloat = 32,
                markStyle: ViadereMarkStyle = .automatic, typeface: ViadereWordmark.Typeface = .outfit) {
        self.layout = layout
        self.ribbonHeight = ribbonHeight
        self.markStyle = markStyle
        self.typeface = typeface
    }

    private var markHeight: CGFloat { ribbonHeight * ViadereMarkGeometry.height / 100 }

    public var body: some View {
        switch layout {
        case .horizontal:
            let fontSize = 0.73 * ribbonHeight / ViadereWordmark.xHeight
            HStack(alignment: .bottom, spacing: ribbonHeight * 0.26) {
                ViadereMark(style: markStyle).frame(height: markHeight)
                ViadereWordmark(size: fontSize, typeface: typeface)
                    .alignmentGuide(.bottom) { d in d[.lastTextBaseline] + ribbonHeight * 0.10 }
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(Text("Viadere"))
        case .stacked:
            let ribbonWidth = ribbonHeight * ViadereBrand.ribbonAspectRatio
            let fontSize = 1.36 * ribbonWidth / ViadereWordmark.emWidth
            VStack(spacing: ribbonHeight * 0.36) {
                ViadereMark(style: markStyle).frame(height: markHeight)
                ViadereWordmark(size: fontSize, typeface: typeface)
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(Text("Viadere"))
        }
    }
}

#if DEBUG
struct ViadereMark_Previews: PreviewProvider {
    static var previews: some View {
        VStack(spacing: 32) {
            ViadereMark(style: .primary).frame(height: 120)
            ViadereMark.monochrome(ViadereBrand.charcoal).frame(height: 44)
            ViadereLockup(.horizontal, ribbonHeight: 36, markStyle: .primary)
            ViadereLockup(.stacked, ribbonHeight: 40, markStyle: .primary)
        }
        .padding(32)
        .background(ViadereBrand.ivory)
        .previewDisplayName("Light")

        VStack(spacing: 32) {
            ViadereMark(style: .onDark).frame(height: 120)
            ViadereMark.monochrome(ViadereBrand.ivory).frame(height: 44)
            ViadereLockup(.horizontal, ribbonHeight: 36, markStyle: .onDark)
        }
        .padding(32)
        .background(ViadereBrand.black)
        .environment(\.colorScheme, .dark)
        .previewDisplayName("Dark")
    }
}
#endif
