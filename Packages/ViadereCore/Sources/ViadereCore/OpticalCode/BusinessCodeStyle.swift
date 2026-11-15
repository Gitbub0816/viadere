import Foundation

// Who may style a code, and how far (docs/SECURITY.md §2.105, normative).
//
// Two types that do not convert into each other:
//
// * `ViadereCodeStyle`: Viadere's own looks, for Viadere's own surfaces (sign-in, approvals, Verify). It has no initializer that takes a
//   colour, a business or stored data.
// * `BusinessCodeStyle`: what a business chose for **its** connect and install codes. It exists only after validation, and a security
//   surface has no parameter that accepts one.
//
// A code's look never carries trust: the app shows the verified business after the scan, whatever the code looked like.

/// Viadere's own code looks. Security surfaces take this type and nothing else.
public struct ViadereCodeStyle: Sendable, Equatable {
    public let ckey: CKeyStyle

    private init(_ ckey: CKeyStyle) { self.ckey = ckey }

    /// The Viadere code: CKey's "concept" preset.
    public static let concept = ViadereCodeStyle(.concept)
    /// Black on white, for print.
    public static let plain = ViadereCodeStyle(.plain)
}

/// Colours of a QR code. ISO/IEC 18004 codes are dark modules on a light field; phone cameras are only required to read that polarity.
public enum QRCodeColorPolicy {
    /// WCAG contrast the two colours must reach (×10): the existing text minimum, 4.5:1.
    public static let minimumContrastTimes10: Int64 = ContrastPolicy.textMinimumTimes10
    /// Minimum difference in relative luminance between the light and the dark colour, in `ContrastPolicy.luminance` units (1e-11):
    /// 0.40, the "symbol contrast" (light reflectance minus dark reflectance) of grade 2 in ISO/IEC 15415, the print-quality standard
    /// ISO/IEC 18004 refers to. A ratio alone would accept black on a mid grey (4.5:1 at a difference of 0.18), which cameras read badly.
    public static let minimumLuminanceDifference: Int64 = 40_000_000_000
    /// Quiet zone in modules on every side (ISO/IEC 18004 requires 4). Not configurable.
    public static let quietZoneModules = 4

    public static let defaultDark = BrandColor("#1F1E1C")!
    public static let defaultLight = BrandColor("#FFFFFF")!

    public enum Refusal: Error, Sendable, Equatable {
        /// The "dark" colour is not darker than the "light" one.
        case inverted
        /// Contrast ×100 below the minimum.
        case lowContrast(ratioTimes100: Int64)
        /// The light colour is not light enough for the dark one (reflectance difference under 0.40).
        case lowLuminanceDifference
    }

    public static func check(dark: BrandColor, light: BrandColor) -> Refusal? {
        let (ld, ll) = (ContrastPolicy.luminance(dark), ContrastPolicy.luminance(light))
        guard ld < ll else { return .inverted }
        guard ContrastPolicy.meets(dark, light, minimumTimes10: minimumContrastTimes10) else {
            return .lowContrast(ratioTimes100: ContrastPolicy.ratioTimes100(dark, light))
        }
        guard ll - ld >= minimumLuminanceDifference else { return .lowLuminanceDifference }
        return nil
    }
}

/// The code style a business stores for its own connect and install codes. Every value of this type has passed validation, including one
/// decoded from storage.
public struct BusinessCodeStyle: Sendable, Equatable, Codable {
    public static let currentVersion = 1

    public enum Symbology: String, Sendable, Codable, CaseIterable { case ckey, qr }
    public enum CKeyPreset: String, Sendable, Codable, CaseIterable { case concept, plain }

    public enum Choice: Sendable, Equatable {
        case ckeyPreset(CKeyPreset)
        case ckeyCustom(CKeyStyleSpec)
        case qr(dark: BrandColor, light: BrandColor)
    }

    /// Material amounts (percent) a custom style may use: those of the "concept" preset, the only amounts the reference reports as read
    /// back from a browser rendering.
    public static let maxBevel = 60, maxShadow = 50, maxTexture = 40

    public enum Refusal: Error, Sendable, Equatable {
        /// The reference refuses the style.
        case unsafe(CKeyStyleCheck.Refusal)
        /// The reference accepts the style only with certification, which Viadere cannot run: refused.
        case uncertified(CKeyStyleCheck.Advice)
        case materialsTooStrong
        /// A custom style with exactly the colours of the Viadere code. Choose the preset instead.
        case reservedForViadere
        case qr(QRCodeColorPolicy.Refusal)
        case unsupportedVersion

        /// A sentence for the business console.
        public var message: String {
            switch self {
            case .unsafe(.tooFaint(let ink, let background, let ratio)):
                "\(ink.uppercased()) on \(background.uppercased()) has a contrast of \(String(format: "%.1f", ratio)):1. A scanner cannot tell them apart; marks need at least 3:1 against the background."
            case .unsafe(.mixedPolarity):
                "Every mark colour must be lighter than both background colours, or every one darker. Mixing the two cannot be scanned."
            case .unsafe(.accentLimits): "Use at most 4 accent colours and an accent share from 0 to 100."
            case .unsafe(.effectRange): "Bevel, shadow and texture go from 0 to 100."
            case .uncertified(.lowContrast(let ink, let background, let ratio)):
                "\(ink.uppercased()) on \(background.uppercased()) has a contrast of \(String(format: "%.1f", ratio)):1. Marks need at least 3:1 against both background colours."
            case .uncertified(.strongShadowOnLight): "Dark marks on a light background can use a shadow of at most 40."
            case .uncertified(.strongBevelOnLight): "Dark marks on a light background can use a bevel of at most 50."
            case .materialsTooStrong: "Use a bevel of at most \(BusinessCodeStyle.maxBevel), a shadow of at most \(BusinessCodeStyle.maxShadow) and a texture of at most \(BusinessCodeStyle.maxTexture)."
            case .reservedForViadere: "Those are exactly the colours of the Viadere code. Choose the Viadere preset, or change a colour."
            case .qr(.inverted): "A QR code needs dark squares on a light background. Phone cameras often cannot read the reverse."
            case .qr(.lowContrast(let ratio)):
                "Those QR colours have a contrast of \(ratio / 100).\(String(format: "%02d", Int(ratio % 100))):1. A QR code needs at least 4.5:1."
            case .qr(.lowLuminanceDifference): "The light colour is too dark for a QR code. Use a lighter background."
            case .unsupportedVersion: "This style was saved by a newer version of Viadere."
            }
        }
    }

    public let choice: Choice

    /// The default: the Viadere code.
    public static let standard = BusinessCodeStyle(preset: .concept)

    public init(preset: CKeyPreset) { choice = .ckeyPreset(preset) }

    /// A custom CKey style: the reference's check must pass **without** a warning, materials stay within the concept preset's amounts, and
    /// the colours may not be exactly the Viadere code's.
    public init(custom spec: CKeyStyleSpec) throws {
        if let refusal = Self.refusal(for: spec) { throw refusal }
        choice = .ckeyCustom(spec)
    }

    public init(qrDark dark: BrandColor, light: BrandColor) throws {
        if let refusal = QRCodeColorPolicy.check(dark: dark, light: light) { throw Refusal.qr(refusal) }
        choice = .qr(dark: dark, light: light)
    }

    public static func refusal(for spec: CKeyStyleSpec) -> Refusal? {
        switch CKeyStyleCheck.evaluate(spec) {
        case .refused(let refusal): return .unsafe(refusal)
        case .advice(let advice, _): return .uncertified(advice)
        case .ok: break
        }
        if spec.bevel > maxBevel || spec.shadow > maxShadow || spec.texture > maxTexture { return .materialsTooStrong }
        let concept = CKeyStyleSpec.concept
        if spec.background == concept.background && spec.backgroundEdge == concept.backgroundEdge && spec.ink == concept.ink && spec.inkShade == concept.inkShade {
            return .reservedForViadere
        }
        return nil
    }

    public var symbology: Symbology {
        switch choice {
        case .ckeyPreset, .ckeyCustom: .ckey
        case .qr: .qr
        }
    }

    /// The CKey style to draw, when the symbology is CKey.
    public var ckeyStyle: CKeyStyle? {
        switch choice {
        case .ckeyPreset(.concept): .concept
        case .ckeyPreset(.plain): .plain
        case .ckeyCustom(let spec): try? CKeyStyle(validating: spec)
        case .qr: nil
        }
    }

    /// The QR colours to draw, when the symbology is QR.
    public var qrColors: (dark: BrandColor, light: BrandColor)? {
        if case .qr(let dark, let light) = choice { return (dark, light) }
        return nil
    }

    // MARK: Suggestions from a Brand Kit

    /// A custom CKey style suggested from a business's approved tokens: the first of a few candidates that passes validation, else black on
    /// white. A suggestion is a form default and nothing more; what is saved goes through `init(custom:)` again.
    public static func suggestedCustom(from tokens: BrandTokens?) -> CKeyStyleSpec {
        guard let tokens else { return .plain }
        let white = BrandColor("#FFFFFF")!
        let surface = tokens.surface ?? white
        var candidates: [CKeyStyleSpec] = []
        for (background, ink) in [(surface, tokens.primary), (tokens.primary, surface), (white, tokens.primary), (tokens.primary, white)] {
            var spec = CKeyStyleSpec(background: background, ink: ink)
            let accents = [tokens.accent, tokens.secondary].compactMap { $0 }.filter { accent in
                var trial = spec
                trial.accents = [accent]
                trial.accentPercent = 15
                return refusal(for: trial) == nil
            }
            if !accents.isEmpty {
                spec.accents = accents
                spec.accentPercent = 15
            }
            candidates.append(spec)
        }
        return candidates.first { refusal(for: $0) == nil } ?? .plain
    }

    /// QR colours suggested from tokens: the primary on white when that passes, else Viadere's default.
    public static func suggestedQR(from tokens: BrandTokens?) -> (dark: BrandColor, light: BrandColor) {
        if let primary = tokens?.primary, QRCodeColorPolicy.check(dark: primary, light: QRCodeColorPolicy.defaultLight) == nil {
            return (primary, QRCodeColorPolicy.defaultLight)
        }
        return (QRCodeColorPolicy.defaultDark, QRCodeColorPolicy.defaultLight)
    }

    // MARK: Codable (versioned; decoding validates)

    enum CodingKeys: String, CodingKey { case v, symbology, preset, custom, dark, light }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        guard try c.decode(Int.self, forKey: .v) == Self.currentVersion else { throw Refusal.unsupportedVersion }
        switch try c.decode(Symbology.self, forKey: .symbology) {
        case .ckey:
            if let spec = try c.decodeIfPresent(CKeyStyleSpec.self, forKey: .custom) {
                guard !c.contains(.preset) else { throw DecodingError.dataCorruptedError(forKey: .preset, in: c, debugDescription: "preset and custom") }
                try self.init(custom: spec)
            } else {
                self.init(preset: try c.decode(CKeyPreset.self, forKey: .preset))
            }
        case .qr:
            try self.init(qrDark: try c.decode(BrandColor.self, forKey: .dark), light: try c.decode(BrandColor.self, forKey: .light))
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(Self.currentVersion, forKey: .v)
        try c.encode(symbology, forKey: .symbology)
        switch choice {
        case .ckeyPreset(let preset): try c.encode(preset, forKey: .preset)
        case .ckeyCustom(let spec): try c.encode(spec, forKey: .custom)
        case .qr(let dark, let light):
            try c.encode(dark, forKey: .dark)
            try c.encode(light, forKey: .light)
        }
    }
}
