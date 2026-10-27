"""Generates App/Shared/DesignSystem/ViadereMark.swift from the same geometry used for the SVGs
(port of swift.js). The Swift template below is emitted verbatim; ``@@name@@`` marks the generated values."""
import re

import brand as B
import geom as G
from brand import THEMES


def n(v):
    """Round to 2 decimals and print like JS `toFixed(2)` with trailing zeros stripped."""
    r = G.js_round(v * 100) / 100
    if r == 0:
        r = 0.0
    return re.sub(r'\.?0+$', '', f'{r:.2f}', count=1) or '0'


def flat(segs):
    a = [segs[0][0][0], segs[0][0][1]]
    for c in segs:
        a += [c[1][0], c[1][1], c[2][0], c[2][1], c[3][0], c[3][1]]
    return a


def arr(a, indent='        '):
    lines = [indent + ', '.join(n(v) for v in a[i:i + 12]) for i in range(0, len(a), 12)]
    return '[\n' + ',\n'.join(lines) + '\n' + indent[4:] + ']'


def hexc(h):
    return '0x' + h.replace('#', '').upper()


def stops(s):
    return 'Gradient(stops: [' + ', '.join(f'.init(color: Color(viadereHex: {hexc(c)}), location: {G.js_str(o)})' for o, c in s) + '])'


def theme(t):
    return f"""ViadereMarkTheme(
            base: Color(viadereHex: {hexc(t['base'])}),
            fronts: [
                {(',' + chr(10) + ' ' * 16).join(stops(s) for s in t['front'])}
            ],
            lenses: [
                {(',' + chr(10) + ' ' * 16).join(stops(s) for s in t['lens'])}
            ],
            dot: Gradient(colors: [Color(viadereHex: {hexc(t['dot'][0])}), Color(viadereHex: {hexc(t['dot'][1])})])
        )"""


def source():
    m = B.mark('primary', 'sw')
    g = m['g']
    wmEm = B.wordmark(1000, {'via': '#000', 'dere': '#000'})['width'] / 1000
    xh = B.glyphs[600]['xHeight'] / 1000
    v = {
        'W': n(m['W']), 'H': n(m['H']),
        'hex_charcoal': hexc(B.PAL['charcoal']), 'hex_graphite': hexc(B.PAL['graphite']), 'hex_silver': hexc(B.PAL['silver']),
        'hex_ivory': hexc(B.PAL['ivory']), 'hex_champagne': hexc(B.PAL['champagne']),
        'hex_champagneDeep': hexc(B.PAL['champagneDeep']), 'hex_black': hexc(B.PAL['black']),
        'aspect': n(m['W'] / m['H']), 'ribbon_aspect': n(m['W'] / 100),
        'ribbonTop': n(g['ribbonTop']),
        'silhouette': arr(flat(g['sil'])),
        'fronts': ',\n'.join('        ' + arr(flat(fr), '            ') for fr in g['front']),
        'lenses': ',\n'.join('        ' + arr(flat(bk), '            ') for bk in g['back']),
        'lensAxes': ',\n'.join('        [' + ', '.join(n(x) for x in (a[0][0], a[0][1], a[1][0], a[1][1])) + ']' for a in g['lensAxis']),
        'dotCx': n(g['dot']['cx']), 'dotCy': n(g['dot']['cy']), 'dotR': n(g['dot']['r']),
        'theme_primary': theme(THEMES['primary']), 'theme_dark': theme(THEMES['dark']),
        'word_dark_via': hexc(B.WORD['dark']['via']), 'word_light_via': hexc(B.WORD['light']['via']),
        'word_dark_dere': hexc(B.WORD['dark']['dere']), 'word_light_dere': hexc(B.WORD['light']['dere']),
        'emWidth': n(wmEm), 'xHeight': n(xh),
        'clearSpace': n(2 * g['dot']['r'] / 100),
    }
    return re.sub(r'@@(\w+)@@', lambda mo: v[mo.group(1)], TEMPLATE)


def write():
    src = source()
    B.write(B.OUT_SWIFT, src)
    return src


TEMPLATE = r"""//
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
//  (@@W@@ × @@H@@, ribbon @@W@@ × 100 plus the dot).
//

import SwiftUI

// MARK: - Brand palette

/// Viadere core palette. Semantic, appearance-aware colours live in the asset catalog
/// (`Colors/*.colorset`) and in `ViadereDesignSystem.swift` (`ViadereColor`).
public enum ViadereBrand {
    public static let charcoal      = Color(viadereHex: @@hex_charcoal@@)   // primary dark, text, mark (light bg)
    public static let graphite      = Color(viadereHex: @@hex_graphite@@)   // secondary dark
    public static let silver        = Color(viadereHex: @@hex_silver@@)   // neutral mid-tone, ribbon highlight
    public static let ivory         = Color(viadereHex: @@hex_ivory@@)   // primary light, backgrounds
    public static let champagne     = Color(viadereHex: @@hex_champagne@@)   // accent / ribbon end
    public static let champagneDeep = Color(viadereHex: @@hex_champagneDeep@@)   // accent text on ivory (AA)
    public static let black         = Color(viadereHex: @@hex_black@@)   // dark-mode background

    /// Width ÷ height of the full mark (ribbon + dot).
    public static let markAspectRatio: CGFloat = @@aspect@@
    /// Width ÷ height of the ribbon alone (the dot excluded).
    public static let ribbonAspectRatio: CGFloat = @@ribbon_aspect@@
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

/// Cubic Bézier outlines of the mark in a @@W@@ × @@H@@ view box (y down).
/// Each path is `[x0, y0, c1x, c1y, c2x, c2y, x, y, …]`: a start point followed by cubic segments.
enum ViadereMarkGeometry {
    static let width: CGFloat = @@W@@
    static let height: CGFloat = @@H@@
    /// Ribbon occupies y = ribbonTop … ribbonTop + 100.
    static let ribbonTop: CGFloat = @@ribbonTop@@

    /// Full ribbon outline (back face shows through the twist lenses).
    static let silhouette: [CGFloat] = @@silhouette@@

    /// Front faces, left to right: the "v" stroke, the "i" arch, the "a" arch.
    static let fronts: [[CGFloat]] = [
@@fronts@@
    ]

    /// Back faces seen through the twist (between the front faces).
    static let lenses: [[CGFloat]] = [
@@lenses@@
    ]

    /// Gradient axis of each lens: [x1, y1, x2, y2] (trough end → crest end).
    static let lensAxes: [[CGFloat]] = [
@@lensAxes@@
    ]

    /// The dot (identity) above the "i" rise.
    static let dotCenter = CGPoint(x: @@dotCx@@, y: @@dotCy@@)
    static let dotRadius: CGFloat = @@dotR@@
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

    static let primary = @@theme_primary@@

    static let onDark = @@theme_dark@@
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
        let via = viaColor ?? (dark ? Color(viadereHex: @@word_dark_via@@) : Color(viadereHex: @@word_light_via@@))
        let dere = dereColor ?? (dark ? Color(viadereHex: @@word_dark_dere@@) : Color(viadereHex: @@word_light_dere@@))
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
    static let emWidth: CGFloat = @@emWidth@@
    /// x-height of Outfit SemiBold in ems.
    static let xHeight: CGFloat = @@xHeight@@
}

// MARK: - Lockups

/// Mark + wordmark with the brand-guide proportions. Clear space (one dot diameter) is NOT
/// included in the view; add `.padding(ViadereLockup.clearSpace(ribbonHeight:))` around it.
/// Horizontal: wordmark x-height = 0.66 × ribbon height, gap = 0.26 × ribbon height, baseline 0.1 × ribbon height above the ribbon bottom.
/// Stacked: wordmark ≈ 1.24 × ribbon width, centred under the mark.
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

    /// Minimum clear space around a lockup or mark: one dot diameter.
    public static func clearSpace(ribbonHeight: CGFloat) -> CGFloat { ribbonHeight * @@clearSpace@@ }

    private var markHeight: CGFloat { ribbonHeight * ViadereMarkGeometry.height / 100 }

    public var body: some View {
        switch layout {
        case .horizontal:
            let fontSize = 0.66 * ribbonHeight / ViadereWordmark.xHeight
            HStack(alignment: .bottom, spacing: ribbonHeight * 0.26) {
                ViadereMark(style: markStyle).frame(height: markHeight)
                ViadereWordmark(size: fontSize, typeface: typeface)
                    .alignmentGuide(.bottom) { d in d[.lastTextBaseline] + ribbonHeight * 0.10 }
            }
            .accessibilityElement(children: .ignore)
            .accessibilityLabel(Text("Viadere"))
        case .stacked:
            let ribbonWidth = ribbonHeight * ViadereBrand.ribbonAspectRatio
            let fontSize = 1.24 * ribbonWidth / ViadereWordmark.emWidth
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
"""
