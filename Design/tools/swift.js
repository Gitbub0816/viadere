// Generates Design/swift/ViadereMark.swift from the same geometry used for the SVGs.
const fs = require('fs');
const B = require('./build.js');
const { THEMES } = require('./mark');
const m = B.mark('primary', 'sw'); const g = m.g;
const n = (v) => { const r = Math.round(v * 100) / 100; return (Object.is(r, -0) ? 0 : r).toFixed(2).replace(/\.?0+$/, '') || '0'; };
const flat = (segs) => { const a = [segs[0][0][0], segs[0][0][1]]; for (const c of segs) a.push(c[1][0], c[1][1], c[2][0], c[2][1], c[3][0], c[3][1]); return a; };
const arr = (a, indent = '        ') => {
  const lines = []; for (let i = 0; i < a.length; i += 12) lines.push(indent + a.slice(i, i + 12).map(n).join(', '));
  return '[\n' + lines.join(',\n') + '\n' + indent.slice(4) + ']';
};
const hex = (h) => '0x' + h.replace('#', '').toUpperCase();
const stops = (s) => `Gradient(stops: [${s.map(([o, c]) => `.init(color: Color(viadereHex: ${hex(c)}), location: ${o})`).join(', ')}])`;
const theme = (t) => `ViadereMarkTheme(
            base: Color(viadereHex: ${hex(t.base)}),
            fronts: [
                ${t.front.map(stops).join(',\n                ')}
            ],
            lenses: [
                ${t.lens.map(stops).join(',\n                ')}
            ],
            dot: Gradient(colors: [Color(viadereHex: ${hex(t.dot[0])}), Color(viadereHex: ${hex(t.dot[1])})])
        )`;
const wmEm = B.wordmark(1000, { via: '#000', dere: '#000' }).width / 1000;
const xh = B.glyphs[600].xHeight / 1000;

const src = `//
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
//  (${n(m.W)} × ${n(m.H)}, ribbon ${n(m.W)} × 100 plus the dot).
//

import SwiftUI

// MARK: - Brand palette

/// Viadere core palette. Semantic, appearance-aware colours live in the asset catalog
/// (\`Colors/*.colorset\`) and in \`ViadereDesignSystem.swift\` (\`ViadereColor\`).
public enum ViadereBrand {
    public static let charcoal      = Color(viadereHex: ${hex(B.PAL.charcoal)})   // primary dark, text, mark (light bg)
    public static let graphite      = Color(viadereHex: ${hex(B.PAL.graphite)})   // secondary dark
    public static let silver        = Color(viadereHex: ${hex(B.PAL.silver)})   // neutral mid-tone, ribbon highlight
    public static let ivory         = Color(viadereHex: ${hex(B.PAL.ivory)})   // primary light, backgrounds
    public static let champagne     = Color(viadereHex: ${hex(B.PAL.champagne)})   // accent / ribbon end
    public static let champagneDeep = Color(viadereHex: ${hex(B.PAL.champagneDeep)})   // accent text on ivory (AA)
    public static let black         = Color(viadereHex: ${hex(B.PAL.black)})   // dark-mode background

    /// Width ÷ height of the full mark (ribbon + dot).
    public static let markAspectRatio: CGFloat = ${n(m.W / m.H)}
    /// Width ÷ height of the ribbon alone (the dot excluded).
    public static let ribbonAspectRatio: CGFloat = ${n(m.W / 100)}
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

/// Cubic Bézier outlines of the mark in a ${n(m.W)} × ${n(m.H)} view box (y down).
/// Each path is \`[x0, y0, c1x, c1y, c2x, c2y, x, y, …]\`: a start point followed by cubic segments.
enum ViadereMarkGeometry {
    static let width: CGFloat = ${n(m.W)}
    static let height: CGFloat = ${n(m.H)}
    /// Ribbon occupies y = ribbonTop … ribbonTop + 100.
    static let ribbonTop: CGFloat = ${n(g.ribbonTop)}

    /// Full ribbon outline (back face shows through the twist lenses).
    static let silhouette: [CGFloat] = ${arr(flat(g.sil))}

    /// Front faces, left to right: the "v" stroke, the "i" arch, the "a" arch.
    static let fronts: [[CGFloat]] = [
${g.front.map(fr => '        ' + arr(flat(fr), '            ')).join(',\n')}
    ]

    /// Back faces seen through the twist (between the front faces).
    static let lenses: [[CGFloat]] = [
${g.back.map(bk => '        ' + arr(flat(bk), '            ')).join(',\n')}
    ]

    /// Gradient axis of each lens: [x1, y1, x2, y2] (trough end → crest end).
    static let lensAxes: [[CGFloat]] = [
${g.lensAxis.map(a => `        [${[a[0][0], a[0][1], a[1][0], a[1][1]].map(n).join(', ')}]`).join(',\n')}
    ]

    /// The dot (identity) above the "i" rise.
    static let dotCenter = CGPoint(x: ${n(g.dot.cx)}, y: ${n(g.dot.cy)})
    static let dotRadius: CGFloat = ${n(g.dot.r)}
}

/// Draws one outline from \`ViadereMarkGeometry\`, aspect-fitted and centred in the rect.
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
    /// \`.primary\` in light mode, \`.onDark\` in dark mode.
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

    static let primary = ${theme(THEMES.primary)}

    static let onDark = ${theme(THEMES.dark)}
}

// MARK: - Mark view

public struct ViadereMark: View {
    private let style: ViadereMarkStyle
    @Environment(\\.colorScheme) private var colorScheme

    public init(style: ViadereMarkStyle = .automatic) {
        self.style = style
    }

    /// Single-colour mark, e.g. \`ViadereMark.monochrome(.white)\`.
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
                ForEach(0..<ViadereMarkGeometry.fronts.count, id: \\.self) { i in
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
            ForEach(0..<ViadereMarkGeometry.lenses.count, id: \\.self) { i in
                let a = ViadereMarkGeometry.lensAxes[i]
                ViadereMarkPath(data: ViadereMarkGeometry.lenses[i]).fill(
                    LinearGradient(gradient: theme.lenses[i],
                                   startPoint: UnitPoint(x: a[0] / w, y: a[1] / h),
                                   endPoint: UnitPoint(x: a[2] / w, y: a[3] / h)))
            }
            ForEach(0..<ViadereMarkGeometry.fronts.count, id: \\.self) { i in
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

/// Lowercase \`viadere\`: "via" semibold, "dere" light.
/// Uses the bundled Outfit font (App/Resources/Fonts, SIL OFL 1.1; register the files under
/// \`UIAppFonts\` in Info.plist). If the font is not registered, SwiftUI falls back to the system font.
/// For pixel-exact artwork use the \`Wordmark\` / \`LockupHorizontal\` vector image sets instead.
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
    @Environment(\\.colorScheme) private var colorScheme

    public init(size: CGFloat = 28, typeface: Typeface = .outfit, viaColor: Color? = nil, dereColor: Color? = nil) {
        self.size = size
        self.typeface = typeface
        self.viaColor = viaColor
        self.dereColor = dereColor
    }

    public var body: some View {
        let dark = colorScheme == .dark
        let via = viaColor ?? (dark ? Color(viadereHex: ${hex(B.WORD.dark.via)}) : Color(viadereHex: ${hex(B.WORD.light.via)}))
        let dere = dereColor ?? (dark ? Color(viadereHex: ${hex(B.WORD.dark.dere)}) : Color(viadereHex: ${hex(B.WORD.light.dere)}))
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
    static let emWidth: CGFloat = ${n(wmEm)}
    /// x-height of Outfit SemiBold in ems.
    static let xHeight: CGFloat = ${n(xh)}
}

// MARK: - Lockups

/// Mark + wordmark with the brand-guide proportions. Clear space (one dot diameter) is NOT
/// included in the view; add \`.padding(ViadereLockup.clearSpace(ribbonHeight:))\` around it.
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
    public static func clearSpace(ribbonHeight: CGFloat) -> CGFloat { ribbonHeight * ${n(2 * g.dot.r / 100)} }

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
        .environment(\\.colorScheme, .dark)
        .previewDisplayName("Dark")
    }
}
#endif
`;
fs.writeFileSync('/home/user/viadere/Design/swift/ViadereMark.swift', src);
console.log('swift ok', src.length);
