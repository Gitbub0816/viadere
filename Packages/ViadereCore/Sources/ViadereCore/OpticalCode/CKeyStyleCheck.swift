import Foundation

// CKey style safety: a Swift port of `structural_problem` and `safety_problem` (strict policy) in the CKey reference core
// (https://github.com/clearkeysolutions/ckey, ported at tag v0.1.0-build.85, `src/core_internal.inc`; unchanged in v0.1.0-build.127). `CKeyStyleTests` checks every verdict, and the
// reference's own message, against a table made by the reference build (`docs/protocol/vectors/ckey-style-v1.json`).
//
// Not ported: the adaptive and override policies (a refused style is never repaired or drawn anyway), the centre logo and its
// error-correction load, and certification (the reference's modelled photo sweep).
//
// Portions Copyright (c) 2026 ClearKey Solutions, LLC, MIT License (see `docs/THIRD-PARTY-NOTICES.md`).

/// The values of a custom CKey style, as plain data. It draws nothing by itself: `CKeyStyle(validating:)` is the only way to a style a
/// renderer accepts.
public struct CKeyStyleSpec: Sendable, Hashable, Codable {
    public enum ModuleShape: String, Sendable, Codable, CaseIterable, Hashable { case rounded, square, circle, diamond }
    public enum RingStyle: String, Sendable, Codable, CaseIterable, Hashable { case joined, dots }
    public enum RayCap: String, Sendable, Codable, CaseIterable, Hashable { case round, flat }

    public static let maxAccents = 4

    /// Centre of the background, and its edge (a radial vignette when they differ).
    public var background: BrandColor
    public var backgroundEdge: BrandColor
    /// The marks, and the shade of a metallic sheen across the symbol (flat ink when equal).
    public var ink: BrandColor
    public var inkShade: BrandColor
    /// Colours for a share of the payload marks. Keys, frame and finders always use the main ink.
    public var accents: [BrandColor]
    /// 0 to 100: the share of payload marks drawn in accents.
    public var accentPercent: Int
    public var modules: ModuleShape
    public var rings: RingStyle
    public var rays: RayCap
    /// Material amounts in percent (0 to 100): embossed highlight, drop shadow, background grain.
    public var bevel: Int
    public var shadow: Int
    public var texture: Int

    public init(background: BrandColor, backgroundEdge: BrandColor? = nil, ink: BrandColor, inkShade: BrandColor? = nil, accents: [BrandColor] = [],
                accentPercent: Int = 0, modules: ModuleShape = .rounded, rings: RingStyle = .joined, rays: RayCap = .round, bevel: Int = 0, shadow: Int = 0,
                texture: Int = 0) {
        self.background = background
        self.backgroundEdge = backgroundEdge ?? background
        self.ink = ink
        self.inkShade = inkShade ?? ink
        self.accents = accents
        self.accentPercent = accentPercent
        self.modules = modules
        self.rings = rings
        self.rays = rays
        self.bevel = bevel
        self.shadow = shadow
        self.texture = texture
    }

    enum CodingKeys: String, CodingKey {
        case background, ink, accents, modules, rings, rays, bevel, shadow, texture
        case backgroundEdge = "background_edge"
        case inkShade = "ink_shade"
        case accentPercent = "accent_percent"
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        let background = try c.decode(BrandColor.self, forKey: .background)
        let ink = try c.decode(BrandColor.self, forKey: .ink)
        self.init(background: background, backgroundEdge: try c.decodeIfPresent(BrandColor.self, forKey: .backgroundEdge), ink: ink,
                  inkShade: try c.decodeIfPresent(BrandColor.self, forKey: .inkShade), accents: try c.decodeIfPresent([BrandColor].self, forKey: .accents) ?? [],
                  accentPercent: try c.decodeIfPresent(Int.self, forKey: .accentPercent) ?? 0,
                  modules: try c.decodeIfPresent(ModuleShape.self, forKey: .modules) ?? .rounded, rings: try c.decodeIfPresent(RingStyle.self, forKey: .rings) ?? .joined,
                  rays: try c.decodeIfPresent(RayCap.self, forKey: .rays) ?? .round, bevel: try c.decodeIfPresent(Int.self, forKey: .bevel) ?? 0,
                  shadow: try c.decodeIfPresent(Int.self, forKey: .shadow) ?? 0, texture: try c.decodeIfPresent(Int.self, forKey: .texture) ?? 0)
    }

    /// The reference's two presets as specs (for editors and tests). `concept` is Viadere's own look.
    public static let plain = CKeyStyleSpec(background: BrandColor("#FFFFFF")!, ink: BrandColor("#000000")!)
    public static let concept = CKeyStyleSpec(background: BrandColor("#14161E")!, backgroundEdge: BrandColor("#07080C")!, ink: BrandColor("#F6EEE0")!,
                                              inkShade: BrandColor("#C8B69A")!, accents: [BrandColor("#A9B896")!, BrandColor("#9EA1A6")!], accentPercent: 18,
                                              bevel: 60, shadow: 50, texture: 40)
}

/// The reference's style check. A pure function of the style: no symbol is needed because no logo is drawn.
public enum CKeyStyleCheck {
    /// Below this ratio a mark is near-invisible: refused.
    public static let hardContrast = 1.5
    /// Below this ratio the reference only warns and asks for certification (its photo sweep), which is not ported.
    public static let adviseContrast = 3.0

    /// What cannot be drawn, or reliably breaks a code.
    public enum Refusal: Error, Sendable, Equatable {
        /// More than four accents, or an accent share outside 0...100.
        case accentLimits
        /// Bevel, shadow or texture outside 0...100 percent.
        case effectRange
        /// A mark colour too close to a background colour (lowercase `#rrggbb`).
        case tooFaint(ink: String, background: String, ratio: Double)
        /// Some marks lighter than the background and some darker.
        case mixedPolarity

        /// The reference's own sentence.
        public var message: String {
            switch self {
            case .accentLimits: "accents: at most 4 colours and 100%"
            case .effectRange: "bevel, shadow, and texture must be 0..1"
            case .tooFaint(let ink, let background, let ratio):
                "ink \(ink) on background \(background) is \(String(format: "%.1f", ratio)):1, too faint to read (minimum \(String(format: "%.1f", hardContrast)):1)"
            case .mixedPolarity: "all inks must be lighter than the background, or all darker"
            }
        }
    }

    /// What the reference accepts but does not vouch for without certification.
    public enum Advice: Sendable, Equatable {
        case lowContrast(ink: String, background: String, ratio: Double)
        case strongShadowOnLight
        case strongBevelOnLight

        public var message: String {
            switch self {
            case .lowContrast(let ink, let background, let ratio): "ink \(ink) on background \(background) is only \(String(format: "%.1f", ratio)):1"
            case .strongShadowOnLight: "strong shadow on dark-on-light marks"
            case .strongBevelOnLight: "strong bevel on dark-on-light marks"
            }
        }
    }

    public enum Verdict: Sendable, Equatable {
        /// Every rule passes; the lowest contrast of any mark colour against any background colour.
        case ok(minimumContrast: Double)
        case advice(Advice, minimumContrast: Double)
        case refused(Refusal)

        /// The message `ckey_check_scalable_style` reports for this verdict (strict policy, no logo).
        public var referenceMessage: String {
            switch self {
            case .ok(let contrast): "style OK: contrast >= \(String(format: "%.1f", contrast)):1; logo uses 0% of block correction"
            case .advice(let advice, _): "style OK, but \(advice.message); certify it to check that it scans"
            case .refused(let refusal): refusal.message
            }
        }
    }

    static func rgb(_ color: BrandColor) -> CKeyStyle.RGB {
        let c = color.rgb
        return CKeyStyle.RGB(r: c.red, g: c.green, b: c.blue)
    }

    /// WCAG relative luminance, in floating point exactly as the reference computes it (the reader decodes luminance).
    static func relativeLuminance(_ c: CKeyStyle.RGB) -> Double {
        func channel(_ v: UInt8) -> Double {
            let x = Double(v) / 255.0
            return x <= 0.04045 ? x / 12.92 : pow((x + 0.055) / 1.055, 2.4)
        }
        return 0.2126 * channel(c.r) + 0.7152 * channel(c.g) + 0.0722 * channel(c.b)
    }

    static func contrastRatio(_ a: CKeyStyle.RGB, _ b: CKeyStyle.RGB) -> Double {
        let la = relativeLuminance(a), lb = relativeLuminance(b)
        return (max(la, lb) + 0.05) / (min(la, lb) + 0.05)
    }

    public static func contrastRatio(_ a: BrandColor, _ b: BrandColor) -> Double { contrastRatio(rgb(a), rgb(b)) }

    /// Whether every mark is lighter than the background (`true`), darker (`false`), or the style has no single answer (`nil`).
    public static func isLightOnDark(_ spec: CKeyStyleSpec) -> Bool? {
        var sides = Set<Bool>()
        for background in [spec.background, spec.backgroundEdge] {
            for ink in inks(spec) { sides.insert(relativeLuminance(rgb(ink)) > relativeLuminance(rgb(background))) }
        }
        return sides.count == 1 ? sides.first : nil
    }

    static func inks(_ spec: CKeyStyleSpec) -> [BrandColor] {
        [spec.ink, spec.inkShade] + (spec.accentPercent > 0 ? spec.accents : [])
    }

    /// The reference's verdict for `spec`: values a renderer cannot draw first, then the scan-safety rules.
    public static func evaluate(_ spec: CKeyStyleSpec) -> Verdict {
        // Shapes and caps are closed Swift enums, so the reference's "unknown module shape" family cannot occur.
        if spec.accents.count > CKeyStyleSpec.maxAccents || !(0...100).contains(spec.accentPercent) { return .refused(.accentLimits) }
        for amount in [spec.bevel, spec.shadow, spec.texture] where !(0...100).contains(amount) { return .refused(.effectRange) }

        var minimum = 1e9
        var polarity = 0
        var problem: Refusal?
        var advice: Advice?
        for background in [spec.background, spec.backgroundEdge].map(rgb) {
            for ink in inks(spec).map(rgb) {
                let ratio = contrastRatio(ink, background)
                minimum = min(minimum, ratio)
                if ratio < hardContrast && problem == nil {
                    problem = .tooFaint(ink: ink.hex, background: background.hex, ratio: ratio)
                } else if ratio < adviseContrast && advice == nil {
                    advice = .lowContrast(ink: ink.hex, background: background.hex, ratio: ratio)
                }
                let side = relativeLuminance(ink) > relativeLuminance(background) ? 1 : -1
                if polarity != 0 && side != polarity && problem == nil { problem = .mixedPolarity }
                polarity = side
            }
        }
        if polarity < 0 && spec.shadow > 40 && advice == nil { advice = .strongShadowOnLight }
        if polarity < 0 && spec.bevel > 50 && advice == nil { advice = .strongBevelOnLight }
        if let problem { return .refused(problem) }
        if let advice { return .advice(advice, minimumContrast: minimum) }
        return .ok(minimumContrast: minimum)
    }
}

extension CKeyStyle {
    /// A custom style, or the reference's refusal. A style the reference only warns about is returned: a caller that cannot certify it
    /// (`BusinessCodeStyle`) must treat that warning as a refusal.
    public init(validating spec: CKeyStyleSpec) throws {
        if case .refused(let refusal) = CKeyStyleCheck.evaluate(spec) { throw refusal }
        self.init(background: CKeyStyleCheck.rgb(spec.background), backgroundEdge: CKeyStyleCheck.rgb(spec.backgroundEdge), ink: CKeyStyleCheck.rgb(spec.ink),
                  inkShade: CKeyStyleCheck.rgb(spec.inkShade), accents: spec.accents.map(CKeyStyleCheck.rgb), accentPercent: UInt32(spec.accentPercent),
                  bevel: Double(spec.bevel) / 100.0, shadow: Double(spec.shadow) / 100.0, texture: Double(spec.texture) / 100.0,
                  modules: spec.modules, rings: spec.rings, rays: spec.rays)
    }
}
