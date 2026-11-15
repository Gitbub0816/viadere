import Crypto
import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// G18: the approved Brand Kit on the signed Wallet pass (colors, icon, logo, strip), contrast enforced, approved kits of the pass's own
/// business only, every image in the signed manifest.
final class WalletBrandingTests: XCTestCase {
    static let system = AuditActor(kind: .system, id: "test")
    static let reviewer = AuditActor(kind: .operator_, id: "operator-test")
    static let viadereColors = ["rgb(31, 31, 31)", "rgb(247, 243, 235)", "rgb(201, 169, 110)"]

    static func solidPNG(width: Int, height: Int, rgb: (UInt8, UInt8, UInt8)) -> Data {
        var rgba = [UInt8]()
        rgba.reserveCapacity(width * height * 4)
        for _ in 0..<(width * height) { rgba += [rgb.0, rgb.1, rgb.2, 255] }
        return BrandImagePipeline.encodePNG(.init(width: width, height: height, rgba: rgba))!
    }

    struct Scene {
        var business: TestBusiness
        var consumer: TestConsumer
        var kit: BrandKitRecord?
    }

    /// A verified business with a loyalty program, an enrolled customer, and (optionally) a kit with logo, mark and background images.
    static func scene(_ h: TestHarness, name: String = "Juniper Coffee", handle: String = "junipercoffee", primary: String = "#2F5D50", accent: String? = "#F7E3A1",
                      background: (UInt8, UInt8, UInt8) = (0x10, 0x20, 0x18), approve: Bool = true, withKit: Bool = true) async throws -> Scene {
        let business = try await h.makeBusiness(name: name, handle: handle)
        try await h.saveProgram(business)
        let consumer = try await h.readyConsumer()
        _ = try await h.connect(consumer, to: business)
        _ = try await h.enroll(consumer, business)
        guard withKit else { return Scene(business: business, consumer: consumer, kit: nil) }
        let assets = BrandAssetService(db: h.db, ctx: h.ctx, runtime: h.app.brandKits)
        let id = business.record.id!
        let logo = try await assets.ingest(businessId: id, data: Data(BrandAssetPipelineTests.png(width: 300, height: 100, opaque: true)), declaredContentType: "image/png", slot: .logo, actor: system)
        let mark = try await assets.ingest(businessId: id, data: solidPNG(width: 120, height: 100, rgb: (0xE0, 0x40, 0x30)), declaredContentType: "image/png", slot: .mark, actor: system)
        let strip = try await assets.ingest(businessId: id, data: solidPNG(width: 750, height: 300, rgb: background), declaredContentType: "image/png", slot: .background, actor: system)
        let service = BrandKitService(db: h.db, ctx: h.ctx)
        let kit = try await service.save(businessId: id, kitId: nil, draft: .init(kitKey: "everyday", name: "Everyday",
            tokens: BrandTokens(primary: BrandColor(primary)!, accent: accent.flatMap(BrandColor.init)), frameId: nil,
            assets: [.logo: logo.id!, .mark: mark.id!, .background: strip.id!]), actor: system)
        if approve {
            for asset in [logo, mark, strip] { try await service.reviewAsset(id: asset.id!, approve: true, actor: reviewer, reason: nil) }
            try await service.approveKit(id: kit.id!, actor: reviewer, note: nil)
        }
        return Scene(business: business, consumer: consumer, kit: try await BrandKitRecord.find(kit.id!, on: h.db))
    }

    static func pass(_ h: TestHarness, _ s: Scene, kind: WalletPassKind = .storeCard) async throws -> PKPassContents {
        let issued = try await h.signedPost(s.consumer, "/v1/wallet/passes", WalletPassIssueRequest(kind: kind, businessId: s.business.id))
        XCTAssertEqual(issued.status, .created, issued.text)
        let metadata = try issued.json(WalletPassMetadata.self)
        let download = try await h.signed(s.consumer, .GET, "/v1/wallet/passes/\(metadata.id)")
        XCTAssertEqual(download.status, .ok, download.text)
        return try PKPassContents(download.body)
    }

    static func colors(_ p: PKPassContents) -> [String] {
        [p.passJSON["backgroundColor"] as? String ?? "", p.passJSON["foregroundColor"] as? String ?? "", p.passJSON["labelColor"] as? String ?? ""]
    }

    static func size(_ png: Data?) -> (Int, Int)? {
        guard let png, case .success(let s) = PNGStructure.parse([UInt8](png)) else { return nil }
        return (s.width, s.height)
    }

    /// Apple's manifest over every file but itself and the signature, and the signature over exactly that manifest.
    static func assertSigned(_ h: TestHarness, _ p: PKPassContents, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertEqual(Set(p.manifest.keys), Set(p.files.keys).subtracting(["manifest.json", "signature"]), file: file, line: line)
        for (name, hash) in p.manifest { XCTAssertEqual(hash, p.sha1(name), name, file: file, line: line) }
        XCTAssertEqual(p.files["signature"], FakePassSigner.prefix + Data(SHA256.hash(data: p.files["manifest.json"] ?? Data())), file: file, line: line)
        XCTAssertEqual(h.signer.signedManifests.last, p.files["manifest.json"], file: file, line: line)
    }

    func testAnApprovedKitStylesThePassAndTheSignedManifestCoversItsImages() async throws {
        try await withHarness { h in
            let s = try await Self.scene(h)
            let p = try await Self.pass(h, s)
            // Colors: the kit's primary, the better Viadere neutral on it, and the accent (it meets 4.5:1 on the primary).
            XCTAssertEqual(Self.colors(p), ["rgb(47, 93, 80)", PassBranding.rgb(ContrastPolicy.bestForeground(on: BrandColor("#2F5D50")!)), "rgb(247, 227, 161)"])
            // Images at Apple's sizes, @1x/@2x/@3x, freshly encoded PNGs.
            for (name, w, h0) in [("icon", 29, 29), ("strip", 375, 123)] {
                for scale in [1, 2, 3] {
                    let file = scale == 1 ? "\(name).png" : "\(name)@\(scale)x.png"
                    let dims = try XCTUnwrap(Self.size(p.files[file]), file)
                    XCTAssertEqual(dims.0, w * scale, file); XCTAssertEqual(dims.1, h0 * scale, file)
                }
            }
            for scale in [1, 2, 3] {
                let dims = try XCTUnwrap(Self.size(p.files[scale == 1 ? "logo.png" : "logo@\(scale)x.png"]))
                XCTAssertLessThanOrEqual(dims.0, 160 * scale); XCTAssertLessThanOrEqual(dims.1, 50 * scale)
                XCTAssertTrue(dims.0 == 150 * scale || dims.1 == 50 * scale, "fitted to the box: \(dims)")
            }
            // The brand icon replaced Viadere's champagne one.
            XCTAssertNotEqual(p.files["icon.png"], PKPassBuilder.icons().first?.data)
            Self.assertSigned(h, p)
            for name in ["icon.png", "logo.png", "logo@2x.png", "strip@3x.png"] { XCTAssertNotNil(p.manifest[name], name) }
            // Boarding and generic passes carry no strip (Wallet shows none), coupons a 375×144 one.
            XCTAssertNil(PassBranding.stripSize(.boardingPass))
            XCTAssertEqual(PassBranding.stripSize(.coupon)?.height, 144)
            XCTAssertEqual(PassBranding.stripSize(.eventTicket)?.height, 98)
        }
    }

    func testUnapprovedAndOtherTenantsKitsAreNeverUsed() async throws {
        try await withHarness { h in
            // Business B has an approved kit; business A's kit is still waiting for review.
            let b = try await Self.scene(h, name: "Birch Bakery", handle: "birchbakery", primary: "#123B6D")
            let a = try await Self.scene(h, approve: false)
            let passA = try await Self.pass(h, a)
            XCTAssertEqual(Self.colors(passA), Self.viadereColors, "an unapproved kit never reaches a pass")
            XCTAssertNil(passA.files["logo.png"])
            XCTAssertNil(passA.files["strip.png"])
            XCTAssertEqual(passA.files["icon.png"], PKPassBuilder.icons().first?.data)
            Self.assertSigned(h, passA)
            // B's own pass is branded with B's kit; nothing of B appears on A's.
            let passB = try await Self.pass(h, b)
            XCTAssertEqual(Self.colors(passB).first, "rgb(18, 59, 109)")
            XCTAssertFalse(Self.colors(passA).contains("rgb(18, 59, 109)"))
            // An edit under review does not change the approved colors on B's pass; a takedown removes the branding at once.
            let service = BrandKitService(db: h.db, ctx: h.ctx)
            try await service.save(businessId: b.business.record.id!, kitId: b.kit!.id!, draft: .init(kitKey: "everyday", name: "Everyday",
                tokens: BrandTokens(primary: BrandColor("#8C2F39")!), frameId: nil, assets: [:]), actor: Self.system)
            let edited = try await Self.pass(h, b)
            XCTAssertEqual(Self.colors(edited).first, "rgb(18, 59, 109)")
            try await service.takeDownKit(id: b.kit!.id!, actor: Self.reviewer, reason: "Imitates another brand")
            let down = try await Self.pass(h, b)
            XCTAssertEqual(Self.colors(down), Self.viadereColors)
            XCTAssertNil(down.files["logo.png"])
            // A suspended business's pass is not branded either (the style refuses it before reading any kit).
            let style = await PassBranding(db: h.db, ctx: h.ctx, runtime: h.app.brandKits).style(businessId: UUID(), kind: .storeCard)
            XCTAssertNil(style.colors)
            XCTAssertTrue(style.images.isEmpty)
        }
    }

    func testLowContrastKitsFallBackToViadereColorsAndALowContrastStripIsDropped() async throws {
        try await withHarness { h in
            // Mid grey: neither charcoal nor ivory reaches 4.5:1 on it.
            let grey = try await Self.scene(h, primary: "#808080")
            XCTAssertNil(PassBranding.colors(BrandTokens(primary: BrandColor("#808080")!)))
            let p = try await Self.pass(h, grey)
            XCTAssertEqual(Self.colors(p), Self.viadereColors)
            Self.assertSigned(h, p)
            // An accent that fails on the primary falls back to the foreground for labels.
            let colors = try XCTUnwrap(PassBranding.colors(BrandTokens(primary: BrandColor("#2F5D50")!, accent: BrandColor("#3A6B5D")!)))
            XCTAssertEqual(colors.label, colors.foreground)
            // A dark primary with a near-white strip: ivory text over the strip would be unreadable, so the strip is left out.
            let light = try await Self.scene(h, name: "Larch Lane", handle: "larchlane", background: (0xF4, 0xF4, 0xF0))
            let q = try await Self.pass(h, light)
            XCTAssertEqual(Self.colors(q).first, "rgb(47, 93, 80)")
            XCTAssertNil(q.files["strip.png"])
            XCTAssertNotNil(q.files["logo.png"])
            Self.assertSigned(h, q)
        }
    }
}
