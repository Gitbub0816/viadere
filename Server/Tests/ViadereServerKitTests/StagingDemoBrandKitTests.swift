import Crypto
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// The staging "Atlas Demo" Brand Kit as a phone sees it, end to end: `staging-demo --seed-brand-kit`, an operator approves the logo and
/// the kit, then a connected customer fetches `GET /v1/businesses/{id}/brand` and the logo from the asset host, and the device-side checks
/// run on what came back (pinned-key verification in the wire form the app build pins, selection, the contrast clamp, the asset hash).
/// Staging showed the Atlas page exactly like an unbranded one.
///
/// The device half that lives in ViadereKit (`BrandKitStore`, `BusinessHomeDecoration`) runs on a capture of these responses in
/// `Packages/ViadereKit/Tests/ViadereKitTests/AtlasBrandFixture.swift`; set `VIADERE_CAPTURE_BRAND_FIXTURE=/path/file.json` to re-capture.
final class StagingDemoBrandKitTests: XCTestCase {
    static let assetHost = "assets.viadere-cdn.example"
    /// A fixed `brand-manifest` key so a capture verifies against a pin that can be written into the Kit fixture (test-only key).
    static let manifestKey = try! SoftwareP256SigningKey(rawRepresentation: Data(SHA256.hash(data: Data("staging-demo-brand-fixture".utf8))))

    func testSeededBrandKitReachesADeviceAfterReview() async throws {
        try await withHarness({
            $0.brandKits.assetDomain = LinkDomain(Self.assetHost)
            $0.brandKits.manifestKey = Self.manifestKey
        }) { h in
            let demo = try StagingDemo(db: h.db, ctx: h.ctx, environment: .staging)
            let atlas = try await demo.ensureBusiness().id!
            let seed = try await demo.seedBrandKit(businessId: atlas, runtime: h.app.brandKits)
            let (op, account) = try await h.makeOperator()
            try await eq(try await h.dashReauth(op, account).status, .ok)
            try await eq(try await h.formPost("/operator/brand/assets/\(seed.asset.id!.uuidString.lowercased())/approve", op).status, .seeOther)
            try await eq(try await h.formPost("/operator/brand/kits/\(seed.kit.id!.uuidString.lowercased())/approve", op).status, .seeOther)

            // The phone connects to Atlas Demo and opens its page.
            let consumer = try await h.readyConsumer()
            let connected = try await h.signedPost(consumer, APIRoutes.relationshipConnect.template,
                                                   ConnectRequest(businessId: BusinessID(atlas), source: .handle, optInPurposes: []))
            XCTAssertTrue([.ok, .created].contains(connected.status), connected.text)
            let directory = try await h.signed(consumer, .GET, APIRoutes.relationshipsList.template).json([Relationship].self)
            let entry = try XCTUnwrap(directory.first { $0.business.id == BusinessID(atlas) })
            XCTAssertTrue(entry.business.isVerified, "the page only asks for branding of a verified business")

            let path = APIRoutes.businessBrandGet.template.replacingOccurrences(of: "{businessId}", with: BusinessID(atlas).description)
            let fetched = try await h.signed(consumer, .GET, path)
            XCTAssertEqual(fetched.status, .ok, fetched.text)
            let response = try fetched.json(BrandManifestResponse.self)
            XCTAssertEqual(response.status, .branded)
            XCTAssertEqual(response.businessId, BusinessID(atlas))
            XCTAssertEqual(response.assetHost, Self.assetHost)

            // The pin exactly as `ViadereServer brand-manifest-key` prints it and the app build carries it (`kid:publicKey`).
            let kid = KeyIdentifier.make(try Self.manifestKey.publicKey.signingKey())
            let pinLine = "\(kid):\(Self.manifestKey.publicKey.base64URL)"
            let point = try XCTUnwrap(Base64URL.decode(Self.manifestKey.publicKey.base64URL))
            XCTAssertEqual(try KeyIdentifier.make(p256X963: point), kid, "the app derives the same kid from the printed key")
            let pinned = [PinnedManifestKey(kid: kid, publicKey: try DevicePublicKey(bytes: point))]
            let manifest = try BrandManifest.verify(try XCTUnwrap(response.manifest), expectedBusiness: BusinessID(atlas), keys: pinned,
                                                    now: h.clock.now())
            let selection = BrandKitSelector.select(manifest: manifest, now: h.clock.now(), selectionSeed: response.selectionSeedData)
            XCTAssertEqual(selection.kitId, StagingDemo.kitKey)
            let kit = try XCTUnwrap(manifest.kit(StagingDemo.kitKey))
            XCTAssertEqual(kit.tokens.primary, StagingDemo.kitTokens.primary)
            let clamped = ContrastPolicy.resolve(kit.tokens)
            XCTAssertEqual(clamped.overriddenLight, [], "the deep teal survives the clamp on ivory")
            XCTAssertEqual(clamped.light.primary, StagingDemo.kitTokens.primary)

            // The logo from the asset host, checked by hash like the app does.
            let logoRef = try XCTUnwrap(kit.assets[.logo], "the approved logo is in the manifest")
            let logoURL = try XCTUnwrap(logoRef.url(assetHost: try XCTUnwrap(response.assetHost)))
            let logo = try await h.request(.GET, logoURL.path, headers: [AssetHostMiddleware.header: Self.assetHost])
            XCTAssertEqual(logo.status, .ok)
            XCTAssertEqual(logo.body.count, logoRef.bytes)
            XCTAssertEqual(Hex.encode(Data(SHA256.hash(data: logo.body))), logoRef.sha256)

            // `staging-demo --status` reports what devices get: the live manifest and its kid (to compare with the build pin), and the
            // asset host the logo comes from.
            let status = try await demo.status(businessId: atlas)
            XCTAssertEqual(status.manifest?.status, "active")
            XCTAssertEqual(status.manifest?.kid, kid)
            XCTAssertEqual(status.brandReach, .branded(kid: kid, assetHost: Self.assetHost))

            if let out = ProcessInfo.processInfo.environment["VIADERE_CAPTURE_BRAND_FIXTURE"] {
                let fixture: [String: String] = [
                    "pin": pinLine, "business_id": BusinessID(atlas).description, "now": String(Int64(h.clock.now().timeIntervalSince1970)),
                    "response": String(decoding: try ViadereJSON.encode(response), as: UTF8.self), "etag": fetched.headers.first(name: .eTag) ?? "",
                    "logo": Base64URL.encode(logo.body), "display_name": entry.business.displayName,
                ]
                try JSONEncoder.sortedKeys.encode(fixture).write(to: URL(fileURLWithPath: out))
            }
        }
    }

    /// Without `ASSET_DOMAIN` the kit still reaches devices, but no logo can: `--status` says so, and the device-side tests
    /// (`AtlasBrandKitDeviceTests.headerBandCarriesTheBrand`) require the page to look branded anyway.
    func testStatusSaysWhenNoLogoCanReachDevices() async throws {
        try await withHarness({ $0.brandKits.manifestKey = Self.manifestKey }) { h in
            let demo = try StagingDemo(db: h.db, ctx: h.ctx, environment: .staging)
            let atlas = try await demo.ensureBusiness().id!
            let before = try await demo.status(businessId: atlas)
            XCTAssertEqual(before.brandReach, .notPublished)
            let seed = try await demo.seedBrandKit(businessId: atlas, runtime: h.app.brandKits)
            let (op, account) = try await h.makeOperator()
            try await eq(try await h.dashReauth(op, account).status, .ok)
            try await eq(try await h.formPost("/operator/brand/assets/\(seed.asset.id!.uuidString.lowercased())/approve", op).status, .seeOther)
            try await eq(try await h.formPost("/operator/brand/kits/\(seed.kit.id!.uuidString.lowercased())/approve", op).status, .seeOther)
            let kid = KeyIdentifier.make(try Self.manifestKey.publicKey.signingKey())
            let after = try await demo.status(businessId: atlas)
            XCTAssertEqual(after.brandReach, .branded(kid: kid, assetHost: nil))
        }
    }
}
