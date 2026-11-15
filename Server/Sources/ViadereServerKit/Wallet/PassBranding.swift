import Fluent
import Foundation
import ViadereCore

/// The business's approved Brand Kit on its signed Wallet passes (G18, docs/WALLET.md, docs/SECURITY.md §2.93 "Surfaces").
///
/// * **Only what customers already see.** The kit comes from `BrandKitService.buildPublishable`: approved snapshots only (never a draft or an
///   edit under review), images still `ready`, of **this** business only, and nothing for a suspended or banned business or while the
///   `brand_kits` switch is on. The kit is the schedule's default (else the first published one): a pass is long-lived, so it does not rotate.
/// * **Contrast.** `backgroundColor` is the kit's primary, `foregroundColor` the Viadere neutral with the better contrast on it; both must meet
///   WCAG AA for text (`ContrastPolicy`, 4.5:1) or the pass keeps Viadere's colors. `labelColor` is the kit's accent only when it meets the same
///   ratio, else the foreground. A strip image is kept only when the foreground still meets 4.5:1 on the strip's average color (the primary
///   fields are drawn over it).
/// * **Images.** The stored assets were re-encoded by `BrandImagePipeline` at upload; here they are decoded again by the same codec, cropped or
///   fitted to Apple's sizes and encoded as fresh PNGs: icon 29×29 pt (from `mark`), logo up to 160×50 pt (from `logo`, else `mark`), strip
///   375×123 pt (store card), 375×144 pt (coupon), 375×98 pt (event ticket) (from `background`), each at @1x, @2x and @3x. Boarding and
///   generic passes get no strip (Wallet does not show one). Every file is listed in the signed `manifest.json` like any other.
struct PassBranding {
    let db: any Database
    let ctx: ServerContext
    let runtime: BrandKitRuntime?

    struct Colors: Equatable {
        var background: BrandColor
        var foreground: BrandColor
        var label: BrandColor
    }

    struct Style {
        var colors: Colors?
        var images: [ZipArchive.Entry] = []
        var kitId: String?
    }

    static let scales = [1, 2, 3]

    /// Rendered variants by `sha256|name|box`: the content hash keys it, so an entry can never be another image's. Bounded; cleared when full.
    private static let cache = VariantCache()

    final class VariantCache: @unchecked Sendable {
        private let lock = NSLock()
        private var entries: [String: [ZipArchive.Entry]] = [:]
        static let limit = 64
        func get(_ key: String) -> [ZipArchive.Entry]? { lock.withLock { entries[key] } }
        func put(_ key: String, _ value: [ZipArchive.Entry]) {
            lock.withLock {
                if entries.count >= Self.limit { entries.removeAll() }
                entries[key] = value
            }
        }
    }

    /// Kit colors that pass the contrast rule, or `nil` (Viadere's pass colors).
    static func colors(_ tokens: BrandTokens) -> Colors? {
        let background = tokens.primary
        let foreground = ContrastPolicy.bestForeground(on: background)
        guard ContrastPolicy.meets(foreground, background, minimumTimes10: ContrastPolicy.textMinimumTimes10) else { return nil }
        var label = foreground
        if let accent = tokens.accent, ContrastPolicy.meets(accent, background, minimumTimes10: ContrastPolicy.textMinimumTimes10) { label = accent }
        return Colors(background: background, foreground: foreground, label: label)
    }

    static func rgb(_ color: BrandColor) -> String {
        let c = color.rgb
        return "rgb(\(c.red), \(c.green), \(c.blue))"
    }

    static func stripSize(_ kind: WalletPassKind) -> (width: Int, height: Int)? {
        switch kind {
        case .storeCard: (375, 123)
        case .coupon: (375, 144)
        case .eventTicket: (375, 98)
        case .boardingPass, .generic: nil
        }
    }

    /// The style for a pass of `businessId`, or an empty style (Viadere's look). Never throws into the pass build: branding must not stop a pass.
    func style(businessId: UUID, kind: WalletPassKind) async -> Style {
        do {
            guard let business = try await BusinessRecord.find(businessId, on: db), business.isVerified, !BrandKitService.isBanned(business),
                  !(await PlatformFlags(db: db, ctx: ctx).brandKitsStopped(businessId: businessId)) else { return Style() }
            let (kits, schedule) = try await BrandKitService(db: db, ctx: ctx).buildPublishable(businessId: businessId)
            guard let kit = kits.first(where: { $0.kitId == schedule.defaultKit }) ?? kits.first else { return Style() }
            var style = Style(colors: Self.colors(kit.tokens), kitId: kit.kitId)
            guard let runtime, runtime.store != nil else { return style }
            let assets = BrandAssetService(db: db, ctx: ctx, runtime: runtime)
            /// The approved, `ready` asset of this business in `slot` (its bytes hash-checked by `bytes(of:)`), rendered as `name` variants.
            func render(_ slots: [BrandAssetSlot], _ name: String, box: (Int, Int), fit: Bool, square: Bool = false) async throws -> [ZipArchive.Entry] {
                for slot in slots {
                    guard let ref = kit.assets[slot], ref.fits(slot),
                          let row = try await BrandAssetRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$sha256 == ref.sha256)
                              .filter(\.$slot == slot.rawValue).filter(\.$state == BrandKitService.AssetState.ready.rawValue).first() else { continue }
                    let key = "\(ref.sha256)|\(name)|\(box.0)x\(box.1)"
                    if let cached = Self.cache.get(key) { return cached }
                    guard let data = try await assets.bytes(of: row), case .success(let decoded) = BrandImagePipeline.decodePNG([UInt8](data)) else { continue }
                    let entries = Self.variants(name, square ? Self.squareCrop(decoded) : decoded, box: box, fit: fit)
                    Self.cache.put(key, entries)
                    return entries
                }
                return []
            }
            style.images += try await render([.mark], "icon", box: (29, 29), fit: false, square: true)
            style.images += try await render([.logo, .mark], "logo", box: (160, 50), fit: true)
            if let size = Self.stripSize(kind) {
                let foreground = style.colors?.foreground ?? NeutralPalette.ivory
                let base = style.colors?.background ?? NeutralPalette.charcoal
                let strip = try await render([.background], "strip", box: size, fit: false)
                if let first = strip.first, case .success(let small) = BrandImagePipeline.decodePNG([UInt8](first.data)),
                   ContrastPolicy.meets(foreground, Self.average(small, over: base), minimumTimes10: ContrastPolicy.textMinimumTimes10) {
                    style.images += strip
                }
            }
            return style
        } catch {
            ctx.logger.warning("pass branding skipped", metadata: ["type": "\(type(of: error))"])
            return Style()
        }
    }

    // MARK: Pixels

    /// `name.png`, `name@2x.png`, `name@3x.png`: `fit` scales inside the box keeping the aspect ratio; otherwise the image is center-cropped to
    /// the box's aspect ratio and scaled to it exactly.
    static func variants(_ name: String, _ source: BrandImagePipeline.Pixels, box: (Int, Int), fit: Bool) -> [ZipArchive.Entry] {
        let cropped = fit ? source : crop(source, toAspect: box)
        return scales.compactMap { scale -> ZipArchive.Entry? in
            let target: (width: Int, height: Int)
            if fit {
                let factor = min(Double(box.0 * scale) / Double(cropped.width), Double(box.1 * scale) / Double(cropped.height))
                target = (max(1, Int((Double(cropped.width) * factor).rounded(.down))), max(1, Int((Double(cropped.height) * factor).rounded(.down))))
            } else {
                target = (box.0 * scale, box.1 * scale)
            }
            guard let png = BrandImagePipeline.encodePNG(cropped.resized(to: target)) else { return nil }
            return ZipArchive.Entry(name: scale == 1 ? "\(name).png" : "\(name)@\(scale)x.png", data: png)
        }
    }

    static func squareCrop(_ p: BrandImagePipeline.Pixels) -> BrandImagePipeline.Pixels { crop(p, toAspect: (1, 1)) }

    /// The largest centered region of `p` with the aspect ratio `w:h`.
    static func crop(_ p: BrandImagePipeline.Pixels, toAspect aspect: (Int, Int)) -> BrandImagePipeline.Pixels {
        var width = p.width, height = p.width * aspect.1 / max(1, aspect.0)
        if height > p.height { height = p.height; width = p.height * aspect.0 / max(1, aspect.1) }
        width = max(1, min(width, p.width)); height = max(1, min(height, p.height))
        guard width != p.width || height != p.height else { return p }
        let x0 = (p.width - width) / 2, y0 = (p.height - height) / 2
        var out = [UInt8](repeating: 0, count: width * height * 4)
        for y in 0..<height {
            let from = ((y0 + y) * p.width + x0) * 4
            out.replaceSubrange((y * width * 4)..<((y + 1) * width * 4), with: p.rgba[from..<(from + width * 4)])
        }
        return BrandImagePipeline.Pixels(width: width, height: height, rgba: out)
    }

    /// The average color of `p` composited over `base`.
    static func average(_ p: BrandImagePipeline.Pixels, over base: BrandColor) -> BrandColor {
        let b = base.rgb
        var sum = (0, 0, 0)
        let count = max(1, p.width * p.height)
        for i in stride(from: 0, to: p.rgba.count, by: 4) {
            let a = Int(p.rgba[i + 3])
            sum.0 += (Int(p.rgba[i]) * a + Int(b.red) * (255 - a)) / 255
            sum.1 += (Int(p.rgba[i + 1]) * a + Int(b.green) * (255 - a)) / 255
            sum.2 += (Int(p.rgba[i + 2]) * a + Int(b.blue) * (255 - a)) / 255
        }
        func hex(_ v: Int) -> String { let s = String(min(255, v / count), radix: 16, uppercase: true); return s.count == 1 ? "0" + s : s }
        return BrandColor("#" + hex(sum.0) + hex(sum.1) + hex(sum.2)) ?? base
    }
}
