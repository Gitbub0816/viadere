import Foundation

// CKey SVG renderer: a Swift port of `ckey_render_scalable_styled_svg` in the CKey reference core
// (https://github.com/clearkeysolutions/ckey, ported at tag v0.1.0-build.85, `src/api_render.inc`; unchanged in and checked against
// v0.1.0-build.127, the current Stable-Release). For the two certified presets it produces the reference's output byte for byte (`CKeySymbolTests`), and for custom styles as well (`CKeyStyleTests`). A style's members stay internal:
// outside this module a style is one of the presets or comes from `CKeyStyle(validating:)`, which runs the port of the reference's
// scan-safety check (`CKeyStyleCheck.swift`). The centre logo of the reference is not ported: it spends error correction.
//
// Portions Copyright (c) 2026 ClearKey Solutions, LLC, MIT License (see `docs/THIRD-PARTY-NOTICES.md`).

/// How a CKey is painted. Styling never changes where a reader samples.
public struct CKeyStyle: Sendable, Equatable {
    struct RGB: Sendable, Equatable {
        let r: UInt8, g: UInt8, b: UInt8
        var hex: String { String(format: "#%02x%02x%02x", Int(r), Int(g), Int(b)) }
    }

    let background: RGB, backgroundEdge: RGB
    let ink: RGB, inkShade: RGB
    let accents: [RGB]
    let accentPercent: UInt32
    let bevel: Double, shadow: Double, texture: Double
    let modules: CKeyStyleSpec.ModuleShape, rings: CKeyStyleSpec.RingStyle, rays: CKeyStyleSpec.RayCap

    init(background: RGB, backgroundEdge: RGB, ink: RGB, inkShade: RGB, accents: [RGB], accentPercent: UInt32, bevel: Double, shadow: Double,
         texture: Double, modules: CKeyStyleSpec.ModuleShape = .rounded, rings: CKeyStyleSpec.RingStyle = .joined, rays: CKeyStyleSpec.RayCap = .round) {
        self.background = background
        self.backgroundEdge = backgroundEdge
        self.ink = ink
        self.inkShade = inkShade
        self.accents = accents
        self.accentPercent = accentPercent
        self.bevel = bevel
        self.shadow = shadow
        self.texture = texture
        self.modules = modules
        self.rings = rings
        self.rays = rays
    }

    /// Black on white.
    public static let plain = CKeyStyle(background: RGB(r: 0xFF, g: 0xFF, b: 0xFF), backgroundEdge: RGB(r: 0xFF, g: 0xFF, b: 0xFF),
                                        ink: RGB(r: 0, g: 0, b: 0), inkShade: RGB(r: 0, g: 0, b: 0), accents: [], accentPercent: 0,
                                        bevel: 0, shadow: 0, texture: 0)
    /// CKey's "concept" preset: cream metallic ink on a dark vignette, with a few muted accent marks.
    public static let concept = CKeyStyle(background: RGB(r: 0x14, g: 0x16, b: 0x1E), backgroundEdge: RGB(r: 0x07, g: 0x08, b: 0x0C),
                                          ink: RGB(r: 0xF6, g: 0xEE, b: 0xE0), inkShade: RGB(r: 0xC8, g: 0xB6, b: 0x9A),
                                          accents: [RGB(r: 0xA9, g: 0xB8, b: 0x96), RGB(r: 0x9E, g: 0xA1, b: 0xA6)], accentPercent: 18,
                                          bevel: 0.6, shadow: 0.5, texture: 0.4)

    /// Deterministic accent choice per site (decorative).
    func accent(of id: UInt32) -> Int? {
        guard !accents.isEmpty, accentPercent > 0 else { return nil }
        let h = CKeyMath.siteHash(id ^ 0x4143_4345)  // "ACCE"
        return h % 100 < accentPercent ? Int((h / 100) % UInt32(accents.count)) : nil
    }
}

extension CKeySymbol {
    /// The symbol as a standalone SVG document on the 31-unit canvas (quiet margin included), `31 * scale` pixels wide.
    ///
    /// - Parameter label: the accessible name; the reference's own label when `nil`. It is XML-escaped here.
    public func svg(style: CKeyStyle = .concept, scale: Int = 16, label: String? = nil) -> String {
        precondition((1...512).contains(scale), "scale is 1 to 512")
        let L = CKeyLayout.standard(version)
        let p = L.pitch, dot = L.dot
        let center = CKeyLayout.center, tau = CKeyLayout.tau
        let f = Self.fixed4
        let dotStroke = f(2 * dot), capStyle = style.rays == .flat ? "butt" : "round"
        let sheen = style.ink != style.inkShade, vignette = style.background != style.backgroundEdge
        let depth = style.bevel > 0 || style.shadow > 0
        let ink = sheen ? "url(#ckey-ink)" : style.ink.hex
        let name = label.map(Self.xmlEscape) ?? "CKey scalable symbol profile 0 version \(version)"

        var o = "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"\(31 * scale)\" height=\"\(31 * scale)\" viewBox=\"-1 -1 31 31\" role=\"img\" aria-label=\"\(name)\">"
        var c = ""  // Cartesian modules, drawn after the polar marks
        o.reserveCapacity(L.nodes.count * 60)
        c.reserveCapacity(L.nodes.count * 50)

        // Materials.
        if sheen || vignette || depth || style.texture > 0 {
            o += "<defs>"
            if sheen {
                o += "<linearGradient id=\"ckey-ink\" gradientUnits=\"userSpaceOnUse\" x1=\"0\" y1=\"0\" x2=\"29\" y2=\"29\"><stop offset=\"0\" stop-color=\"\(style.ink.hex)\"/><stop offset=\"0.55\" stop-color=\"\(style.inkShade.hex)\"/><stop offset=\"1\" stop-color=\"\(style.ink.hex)\"/></linearGradient>"
            }
            if vignette {
                o += "<radialGradient id=\"ckey-bg\" gradientUnits=\"userSpaceOnUse\" cx=\"14.5\" cy=\"14.5\" r=\"21\"><stop offset=\"0\" stop-color=\"\(style.background.hex)\"/><stop offset=\"1\" stop-color=\"\(style.backgroundEdge.hex)\"/></radialGradient>"
            }
            if style.texture > 0 {
                o += "<filter id=\"ckey-grain\" x=\"0\" y=\"0\" width=\"100%\" height=\"100%\"><feTurbulence type=\"fractalNoise\" baseFrequency=\"1.7\" numOctaves=\"2\" seed=\"7\"/><feColorMatrix type=\"saturate\" values=\"0\"/></filter>"
            }
            if depth {
                o += "<filter id=\"ckey-depth\" x=\"-2%\" y=\"-2%\" width=\"104%\" height=\"104%\" color-interpolation-filters=\"sRGB\">"
                var base = "SourceGraphic"
                if style.shadow > 0 {
                    o += "<feDropShadow dx=\"0.05\" dy=\"0.09\" stdDeviation=\"0.07\" flood-color=\"#000000\" flood-opacity=\"\(f(0.75 * style.shadow))\" result=\"shadowed\"/>"
                    base = "shadowed"
                }
                if style.bevel > 0 {
                    o += "<feGaussianBlur in=\"SourceAlpha\" stdDeviation=\"0.045\" result=\"bump\"/><feSpecularLighting in=\"bump\" surfaceScale=\"3\" specularConstant=\"\(f(1.1 * style.bevel))\" specularExponent=\"16\" lighting-color=\"#ffffff\" result=\"spec\"><feDistantLight azimuth=\"225\" elevation=\"40\"/></feSpecularLighting>"
                    o += "<feComposite in=\"spec\" in2=\"SourceAlpha\" operator=\"in\" result=\"shine\"/><feComposite in=\"shine\" in2=\"\(base)\" operator=\"arithmetic\" k1=\"0\" k2=\"1\" k3=\"1\" k4=\"0\"/>"
                }
                o += "</filter>"
            }
            o += "</defs>"
        }
        o += "<rect x=\"-1\" y=\"-1\" width=\"31\" height=\"31\" fill=\"\(vignette ? "url(#ckey-bg)" : style.background.hex)\"/>"
        if style.texture > 0 {
            o += "<rect x=\"-1\" y=\"-1\" width=\"31\" height=\"31\" filter=\"url(#ckey-grain)\" opacity=\"\(f(0.18 * style.texture))\"/>"
        }
        o += "<g fill=\"\(ink)\" stroke=\"\(ink)\"\(depth ? " filter=\"url(#ckey-depth)\"" : "")>"
        o += "<g class=\"ckey-frame\"><rect x=\"0.5\" y=\"0.5\" width=\"28\" height=\"28\" rx=\"3.5\" fill=\"none\" stroke-width=\"0.65\"/></g>"

        // Corner finders: one inset arc per corner; only the top-left arc is interrupted (the orientation signature).
        o += "<g class=\"ckey-finders\">"
        let inset = 4.0, radius = 2.3, thickness = 0.8, splitGap = 0.95
        let transforms = ["", "translate(29.000000 0) scale(-1 1)", "translate(29.000000 29.000000) scale(-1 -1)", "translate(0 29.000000) scale(1 -1)"]
        for (corner, transform) in transforms.enumerated() {
            o += "<g transform=\"\(transform)\" fill=\"none\" stroke-linecap=\"round\">"
            if corner == 0 {
                let halfGap = (splitGap + thickness) / (2.0 * radius)
                let middle = 5.0 * tau / 8.0
                let a1 = middle - halfGap, a2 = middle + halfGap
                o += "<path d=\"M \(f(inset - radius)) \(f(inset)) A \(f(radius)) \(f(radius)) 0 0 1 \(f(inset + radius * cos(a1))) \(f(inset + radius * sin(a1)))"
                o += " M \(f(inset + radius * cos(a2))) \(f(inset + radius * sin(a2))) A \(f(radius)) \(f(radius)) 0 0 1 \(f(inset)) \(f(inset - radius))\" stroke-width=\"\(f(thickness))\"/>"
            } else {
                o += "<path d=\"M \(f(inset - radius)) \(f(inset)) A \(f(radius)) \(f(radius)) 0 0 1 \(f(inset)) \(f(inset - radius))\" stroke-width=\"\(f(thickness))\"/>"
            }
            o += "</g>"
        }

        // Calibration keys.
        o += "</g><g class=\"ckey-grid-key\">"
        for r in 0..<2 {
            for cc in 0..<2 { o += Self.module((Double(L.col0 + cc) + 0.5) * p, (Double(L.row0 + r) + 0.5) * p, p, shape: style.modules, fill: nil) }
        }
        o += "</g><g class=\"ckey-polar-keys\">"
        for (slot, fraction) in [(0, 1.0), (L.rayKeyHalf, 0.5), (L.rayKeyThree, 0.75)] {
            let a = tau * Double(slot) / Double(L.dialSlots), r0 = CKeyLayout.dialInner, r1 = r0 + L.keyRay * fraction
            o += "<path d=\"M \(f(center + r0 * sin(a))) \(f(center - r0 * cos(a))) L \(f(center + r1 * sin(a))) \(f(center - r1 * cos(a)))\" fill=\"none\" stroke-width=\"\(f(0.44 * p))\" stroke-linecap=\"\(capStyle)\"/>"
        }
        let rk = L.ringRadius(L.rings - 1), k = L.ringKeySlot, slots = Double(L.dialSlots)
        for slot in [0, 2, 6] {
            let a = tau * Double(k + slot) / slots
            o += "<circle cx=\"\(f(center + rk * sin(a)))\" cy=\"\(f(center - rk * cos(a)))\" r=\"\(f(dot))\" stroke=\"none\"/>"
        }
        // The Ring Key keeps its dot, gap and run pattern in every style: it is a key.
        o += Self.ringRun(radius: rk, from: Double(k) + 7.5, to: Double(k) + 15.5, slots: slots, dot: dot, strokeWidth: dotStroke)

        // Data: dial rays in placement order, then ring runs, then the Cartesian modules.
        o += "</g><g class=\"ckey-data-polar\">"
        let stride = L.dialSlots
        var ringBits = [Bool](repeating: false, count: L.rings * stride)
        var ringAccent = [Int?](repeating: nil, count: L.rings * stride)
        for (i, n) in L.nodes.enumerated() {
            let bit = siteValue(i, layout: L)
            let accent = style.accent(of: n.id)
            switch n.kind {
            case .cartesian:
                if bit { c += Self.module(n.x, n.y, p, shape: style.modules, fill: accent.map { style.accents[$0].hex }) }
            case .dial:
                let a = tau * Double(n.slot) / Double(L.dialSlots), r0 = CKeyLayout.dialInner, r1 = r0 + (bit ? L.longRay : L.shortRay)
                o += "<path d=\"M \(f(center + r0 * sin(a))) \(f(center - r0 * cos(a))) L \(f(center + r1 * sin(a))) \(f(center - r1 * cos(a)))\" fill=\"none\" stroke-width=\"\(f(L.rayWidth))\" stroke-linecap=\"\(capStyle)\"/>"
            case .ring:
                ringBits[n.ring * stride + n.slot] = bit
                ringAccent[n.ring * stride + n.slot] = accent
            }
        }
        for ring in 0..<L.rings {
            let radius = L.ringRadius(ring)
            var slot = 0
            while slot < stride {
                let at = ring * stride + slot
                if !ringBits[at] { slot += 1; continue }
                var end = slot + 1
                if style.rings == .joined { while end < stride, ringBits[ring * stride + end] { end += 1 } }
                let colour = ringAccent[at].map { style.accents[$0].hex }
                if end - slot == 1 {
                    let a = tau * Double(slot) / slots
                    o += "<circle cx=\"\(f(center + radius * sin(a)))\" cy=\"\(f(center - radius * cos(a)))\" r=\"\(f(dot))\" stroke=\"none\"\(colour.map { " fill=\"\($0)\"" } ?? "")/>"
                } else {
                    let run = Self.ringRun(radius: radius, from: Double(slot) - 0.5, to: Double(end) - 0.5, slots: slots, dot: dot, strokeWidth: dotStroke)
                    o += colour.map { "<g stroke=\"\($0)\">\(run)</g>" } ?? run
                }
                slot = end
            }
        }
        o += "</g><g class=\"ckey-data-cartesian\">"
        o += c
        o += "</g></g></svg>"
        return o
    }

    /// A data or key module centered at (cx, cy), in the style's shape.
    private static func module(_ cx: Double, _ cy: Double, _ p: Double, shape: CKeyStyleSpec.ModuleShape, fill: String?) -> String {
        let h = 0.34 * p, f = fixed4
        let paint = fill.map { " fill=\"\($0)\"" } ?? ""
        switch shape {
        case .circle:
            return "<circle cx=\"\(f(cx))\" cy=\"\(f(cy))\" r=\"\(f(h))\" stroke=\"none\"\(paint)/>"
        case .diamond:
            let d = 0.40 * p  // inscribed radius 0.28p covers the sample support
            return "<polygon points=\"\(f(cx)),\(f(cy - d)) \(f(cx + d)),\(f(cy)) \(f(cx)),\(f(cy + d)) \(f(cx - d)),\(f(cy))\" stroke=\"none\"\(paint)/>"
        case .rounded, .square:
            return "<rect x=\"\(f(cx - h))\" y=\"\(f(cy - h))\" width=\"\(f(2 * h))\" height=\"\(f(2 * h))\" rx=\"\(f(shape == .square ? 0.0 : 0.16 * p))\" stroke=\"none\"\(paint)/>"
        }
    }

    /// A run of adjacent ring sites as one round-capped arc. Caps add a dot diameter, so the centerline is shortened by a dot radius at
    /// each end; a run over half a turn sets the large-arc flag.
    private static func ringRun(radius: Double, from: Double, to: Double, slots: Double, dot: Double, strokeWidth: String) -> String {
        let center = CKeyLayout.center, tau = CKeyLayout.tau, f = fixed4
        let cap = dot / radius
        let a0 = tau * from / slots + cap, a1 = tau * to / slots - cap
        return "<path d=\"M \(f(center + radius * sin(a0))) \(f(center - radius * cos(a0))) A \(f(radius)) \(f(radius)) 0 \(a1 - a0 > tau / 2 ? 1 : 0) 1 \(f(center + radius * sin(a1))) \(f(center - radius * cos(a1)))\" fill=\"none\" stroke-width=\"\(strokeWidth)\" stroke-linecap=\"round\"/>"
    }

    /// `%.4f`, as the reference prints every coordinate.
    static func fixed4(_ value: Double) -> String { String(format: "%.4f", value) }

    static func xmlEscape(_ text: String) -> String {
        var out = ""
        for ch in text.unicodeScalars {
            switch ch {
            case "&": out += "&amp;"
            case "<": out += "&lt;"
            case ">": out += "&gt;"
            case "\"": out += "&quot;"
            case "'": out += "&#39;"
            default:
                // Control characters have no place in an accessible name (and most are not legal XML).
                if ch.value >= 0x20 && ch.value != 0x7F { out.unicodeScalars.append(ch) }
            }
        }
        return out
    }
}
