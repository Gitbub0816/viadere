import Crypto
import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Phase 2 server tests (plan 5.4 D3 rows "Malicious asset uploads" (serving and tenancy half), "Misleading branded approvals" (server
/// half), "Stale cache"; WP-2.1, WP-2.3, WP-2.4, WP-2.5, WP-2.7, WP-2.8, the `brand_kits` kill switch and the healthcare ban).
final class BrandKitServerTests: XCTestCase {
    static let system = AuditActor(kind: .system, id: "test")
    static let operatorActor = AuditActor(kind: .operator_, id: "operator-test")

    /// A verified business with a connected customer, one approved logo and one approved kit (with a live manifest).
    struct World {
        var h: TestHarness
        var business: TestBusiness
        var customer: TestConsumer
        var relationship: Relationship
        var logo: BrandAssetRecord
        var kit: BrandKitRecord
    }

    static func world(_ h: TestHarness, name: String = "Corner Shop", handle: String = "cornershop", publish: Bool = true) async throws -> World {
        let business = try await h.makeBusiness(name: name, handle: handle)
        let customer = try await h.readyConsumer(name: "Alice")
        let relationship = try await h.connect(customer, to: business, optIn: [.marketing])
        let logo = try await BrandAssetService(db: h.db, ctx: h.ctx, runtime: h.app.brandKits)
            .ingest(businessId: business.record.id!, data: Data(BrandAssetPipelineTests.png(width: 64, height: 64)), declaredContentType: "image/png", slot: .logo, actor: system)
        let service = BrandKitService(db: h.db, ctx: h.ctx)
        let kit = try await service.save(businessId: business.record.id!, kitId: nil, draft: .init(kitKey: "everyday", name: "Everyday",
            tokens: BrandTokens(primary: BrandColor("#2F5D50")!, accent: BrandColor("#B5683A")!), frameId: nil, assets: [.logo: logo.id!]), actor: system)
        if publish {
            try await service.reviewAsset(id: logo.id!, approve: true, actor: operatorActor, reason: nil)
            try await service.approveKit(id: kit.id!, actor: operatorActor, note: nil)
        }
        return World(h: h, business: business, customer: customer, relationship: relationship,
                     logo: try await BrandAssetRecord.find(logo.id!, on: h.db)!, kit: try await BrandKitRecord.find(kit.id!, on: h.db)!)
    }

    static func brand(_ h: TestHarness, _ consumer: TestConsumer, _ business: BusinessID, headers: [String: String] = [:]) async throws -> HTTPResult {
        let path = "/v1/businesses/\(business)/brand"
        var all = try await h.signedHeaders(consumer, .GET, path, body: Data())
        for (name, value) in headers { all[name] = value }
        return try await h.request(.GET, path, headers: all)
    }

    static func pinnedKeys(_ h: TestHarness) throws -> [PinnedManifestKey] {
        let key = h.ctx.config.brandKits.manifestKey!
        return [PinnedManifestKey(kid: KeyIdentifier.make(try key.publicKey.signingKey()), publicKey: key.publicKey)]
    }

    // MARK: Serving the manifest (WP-2.3)

    func testConnectedCustomerGetsAVerifiableManifestAndOthersGet404() async throws {
        try await withHarness { h in
            let w = try await Self.world(h)
            let response = try await Self.brand(h, w.customer, w.business.id)
            XCTAssertEqual(response.status, .ok, response.text)
            let view = try response.json(BrandManifestResponse.self)
            XCTAssertEqual(view.status, .branded)
            let manifest = try BrandManifest.verify(view.manifest, expectedBusiness: w.business.id, keys: try Self.pinnedKeys(h), now: h.clock.now())
            XCTAssertEqual(manifest.kits.map(\.kitId), ["everyday"])
            XCTAssertEqual(manifest.kits.first?.assets[.logo]?.sha256, w.logo.sha256)
            XCTAssertEqual(view.manifestHash, try manifest.manifestHash())
            XCTAssertEqual(view.selectionSeedData?.count, 32)
            // The manifest of business A verifies only as business A's (a device showing B renders neutral).
            XCTAssertThrowsError(try BrandManifest.verify(view.manifest, expectedBusiness: BusinessID(), keys: try Self.pinnedKeys(h), now: h.clock.now()))

            // A customer with no relationship, one who left, an unknown business and a malformed id: 404, never an existence oracle.
            let stranger = try await h.readyConsumer(name: "Mallory")
            try await eq(try await Self.brand(h, stranger, w.business.id).status, .notFound)
            try await eq(try await Self.brand(h, w.customer, BusinessID()).status, .notFound)
            let malformed = try await h.signed(w.customer, .GET, "/v1/businesses/not-a-uuid/brand")
            XCTAssertNotEqual(malformed.status, .ok)
            let left = try await h.signed(w.customer, .DELETE, "/v1/relationships/\(w.relationship.id)")
            XCTAssertTrue([.ok, .noContent].contains(left.status), left.text)
            try await eq(try await Self.brand(h, w.customer, w.business.id).status, .notFound)
            // Unauthenticated: refused.
            try await eq(try await h.request(.GET, "/v1/businesses/\(w.business.id)/brand").status, .unauthorized)
        }
    }

    func testTamperedManifestFailsDeviceVerification() async throws {
        try await withHarness { h in
            let w = try await Self.world(h)
            let view = try await Self.brand(h, w.customer, w.business.id).json(BrandManifestResponse.self)
            let parts = try XCTUnwrap(view.manifest).split(separator: ".").map(String.init)
            var payload = try XCTUnwrap(Base64URL.decode(parts[1]))
            let text = String(decoding: payload, as: UTF8.self).replacingOccurrences(of: "#2F5D50", with: "#000001")
            payload = Data(text.utf8)
            let forged = parts[0] + "." + Base64URL.encode(payload) + "." + parts[2]
            XCTAssertThrowsError(try BrandManifest.verify(forged, expectedBusiness: w.business.id, keys: try Self.pinnedKeys(h), now: h.clock.now()))
            // Another key (a look-alike server) is not trusted.
            let other = SoftwareP256SigningKey()
            XCTAssertThrowsError(try BrandManifest.verify(view.manifest, expectedBusiness: w.business.id,
                                                          keys: [PinnedManifestKey(kid: KeyIdentifier.make(try other.publicKey.signingKey()), publicKey: other.publicKey)], now: h.clock.now()))
        }
    }

    func testOnlyApprovedKitsAndImagesArePublishedAndEditsKeepTheApprovedVersionLive() async throws {
        try await withHarness { h in
            let w = try await Self.world(h, publish: false)
            // Nothing approved yet: neutral.
            var view = try await Self.brand(h, w.customer, w.business.id).json(BrandManifestResponse.self)
            XCTAssertEqual(view.status, .neutral)
            XCTAssertNil(view.manifest)
            let service = BrandKitService(db: h.db, ctx: h.ctx)
            // A kit cannot be approved while its image is unreviewed.
            do { try await service.approveKit(id: w.kit.id!, actor: Self.operatorActor, note: nil); XCTFail("approved with an unreviewed image") } catch {}
            try await service.reviewAsset(id: w.logo.id!, approve: true, actor: Self.operatorActor, reason: nil)
            try await service.approveKit(id: w.kit.id!, actor: Self.operatorActor, note: nil)
            view = try await Self.brand(h, w.customer, w.business.id).json(BrandManifestResponse.self)
            XCTAssertEqual(view.status, .branded)
            // An edit goes back to review; customers keep the approved colors until it is approved.
            try await service.save(businessId: w.business.record.id!, kitId: w.kit.id!, draft: .init(kitKey: "everyday", name: "Everyday",
                tokens: BrandTokens(primary: BrandColor("#8C2F39")!), frameId: nil, assets: [:]), actor: Self.system)
            let manifest = try BrandManifest.verify(try await Self.brand(h, w.customer, w.business.id).json(BrandManifestResponse.self).manifest,
                                                    expectedBusiness: w.business.id, keys: try Self.pinnedKeys(h), now: h.clock.now())
            XCTAssertEqual(manifest.kits.first?.tokens.primary.hex, "#2F5D50")
            // Takedown removes it at once: a withdrawal, then neutral.
            try await service.takeDownKit(id: w.kit.id!, actor: Self.operatorActor, reason: "Impersonates another brand")
            view = try await Self.brand(h, w.customer, w.business.id).json(BrandManifestResponse.self)
            XCTAssertEqual(view.status, .neutral)
            let actions = Set(try await AuditEventRecord.query(on: h.db).all().map(\.action))
            for action in ["brandkit.asset_uploaded", "brandkit.kit_saved", "brandkit.asset_approved", "brandkit.kit_approved", "brandkit.manifest_published",
                           "brandkit.kit_taken_down", "brandkit.manifest_withdrawn"] {
                XCTAssertTrue(actions.contains(action), action)
            }
        }
    }

    func testTokensWithHostileValuesAreRefusedAndAForeignAssetCannotBeReferenced() async throws {
        try await withHarness { h in
            let w = try await Self.world(h)
            let other = try await h.makeBusiness(name: "Other Shop", handle: "othershop")
            let service = BrandKitService(db: h.db, ctx: h.ctx)
            // Business B cannot place business A's image in its kit (cross-tenant reference).
            do {
                try await service.save(businessId: other.record.id!, kitId: nil, draft: .init(kitKey: "stolen", name: "Stolen", tokens: BrandTokens(primary: BrandColor("#2F5D50")!),
                                                                                              frameId: nil, assets: [.logo: w.logo.id!]), actor: Self.system)
                XCTFail("foreign asset accepted")
            } catch let error as APIError { XCTAssertEqual(error.status, .unprocessableEntity) }
            // Names that claim Viadere or attribution, unknown frames and bad identifiers are refused by Core's rules.
            for (key, name, frame) in [("ok", "Verified by Viadere", nil as String?), ("ok2", "Spring", "evil.frame"), ("Bad Key!", "Spring", nil)] {
                do {
                    try await service.save(businessId: w.business.record.id!, kitId: nil, draft: .init(kitKey: key, name: name, tokens: BrandTokens(primary: BrandColor("#2F5D50")!),
                                                                                                    frameId: frame, assets: [:]), actor: Self.system)
                    XCTFail("\(key) \(name) accepted")
                } catch let error as APIError { XCTAssertEqual(error.status, .unprocessableEntity, "\(name)") }
            }
            // A kit's identifier cannot change through an edit.
            do {
                try await service.save(businessId: w.business.record.id!, kitId: w.kit.id!, draft: .init(kitKey: "renamed", name: "Everyday",
                    tokens: BrandTokens(primary: BrandColor("#2F5D50")!), frameId: nil, assets: [:]), actor: Self.system)
                XCTFail("kit id changed")
            } catch {}
        }
    }

    // MARK: Kill switch and healthcare ban

    func testKillSwitchServesNeutralAndStopsAssetsGlobalAndPerBusiness() async throws {
        try await withHarness { h in
            let w = try await Self.world(h)
            let flags = PlatformFlags(db: h.db, ctx: h.ctx)
            let operatorId = UUID()
            for scope in [nil, w.business.record.id!] as [UUID?] {
                try await flags.set(.brandKits, businessId: scope, value: "on", reason: "Emergency takedown drill", actor: .operatorUser(operatorId))
                let view = try await Self.brand(h, w.customer, w.business.id).json(BrandManifestResponse.self)
                XCTAssertEqual(view, .neutral(w.business.id))
                try await eq(try await h.request(.GET, "/b/\(w.logo.sha256).png").status, .notFound)
                try await flags.clear(.brandKits, businessId: scope, reason: "Drill finished, back on", actor: .operatorUser(operatorId))
                try await eq(try await Self.brand(h, w.customer, w.business.id).json(BrandManifestResponse.self).status, .branded)
                try await eq(try await h.request(.GET, "/b/\(w.logo.sha256).png").status, .ok)
            }
            XCTAssertGreaterThan(h.ctx.metrics.value(.brandManifestWithheld), 0)
            XCTAssertGreaterThan(h.ctx.metrics.value(.brandManifestServed), 0)
        }
    }

    func testHealthcareBusinessesGetNoBrandKitFeature() async throws {
        try await withHarness { h in
            let w = try await Self.world(h)
            w.business.record.category = "healthcare"
            try await w.business.record.update(on: h.db)
            try await eq(try await Self.brand(h, w.customer, w.business.id).json(BrandManifestResponse.self).status, .neutral)
            try await eq(try await h.request(.GET, "/b/\(w.logo.sha256).png").status, .notFound)
            do {
                _ = try await BrandAssetService(db: h.db, ctx: h.ctx, runtime: h.app.brandKits).ingest(businessId: w.business.record.id!,
                    data: Data(BrandAssetPipelineTests.png()), declaredContentType: "image/png", slot: .mark, actor: Self.system)
                XCTFail("healthcare upload accepted")
            } catch let error as APIError { XCTAssertEqual(error.status, .forbidden) }
            do {
                try await BrandKitService(db: h.db, ctx: h.ctx).approveKit(id: w.kit.id!, actor: Self.operatorActor, note: nil)
                XCTFail("healthcare kit approved")
            } catch {}
        }
    }

    // MARK: Asset serving (WP-2.1)

    func testAssetsAreServedOnlyWhenApprovedWithSafeHeadersAndNoCookies() async throws {
        try await withHarness { h in
            let w = try await Self.world(h, publish: false)
            // Pending review: not public.
            try await eq(try await h.request(.GET, "/b/\(w.logo.sha256).png").status, .notFound)
            try await BrandKitService(db: h.db, ctx: h.ctx).reviewAsset(id: w.logo.id!, approve: true, actor: Self.operatorActor, reason: nil)
            let served = try await h.request(.GET, "/b/\(w.logo.sha256).png")
            XCTAssertEqual(served.status, .ok)
            XCTAssertEqual(served.headers.first(name: .contentType), "image/png")
            XCTAssertEqual(served.headers.first(name: "X-Content-Type-Options"), "nosniff")
            XCTAssertEqual(served.headers.first(name: "Cross-Origin-Resource-Policy"), "cross-origin")
            XCTAssertEqual(served.headers.first(name: "Content-Security-Policy"), "default-src 'none'; sandbox")
            XCTAssertTrue(served.headers.first(name: .cacheControl)?.contains("immutable") == true)
            XCTAssertNil(served.headers.first(name: .setCookie))
            XCTAssertEqual(Hex.encode(Data(SHA256.hash(data: served.body))), w.logo.sha256)
            // Query strings, upper-case or partial names and other extensions: 404.
            for path in ["/b/\(w.logo.sha256).png?x=1", "/b/\(w.logo.sha256.uppercased()).png", "/b/\(w.logo.sha256).svg", "/b/\(w.logo.sha256.prefix(10)).png", "/b/..%2F.png"] {
                try await eq(try await h.request(.GET, path).status, .notFound, path)
            }
            // Takedown stops serving.
            try await BrandKitService(db: h.db, ctx: h.ctx).takeDownAsset(id: w.logo.id!, actor: Self.operatorActor, reason: "Trademark complaint received")
            try await eq(try await h.request(.GET, "/b/\(w.logo.sha256).png").status, .notFound)
        }
    }

    func testTheAssetHostAnswersOnlyAssetsAndTheAPIHostServesNoAssets() async throws {
        try await withHarness({ $0.brandKits.assetDomain = LinkDomain("assets.viadere-cdn.example") }) { h in
            let w = try await Self.world(h)
            let asset = ["Host": "assets.viadere-cdn.example"]
            let ok = try await h.request(.GET, "/b/\(w.logo.sha256).png", headers: asset)
            XCTAssertEqual(ok.status, .ok)
            XCTAssertNil(ok.headers.first(name: .setCookie))
            // AASA, the API, the console and the link routes do not exist on the asset host.
            for path in ["/.well-known/apple-app-site-association", "/apple-app-site-association", "/v1/directory/search?q=a", "/dashboard/login", "/healthz",
                         "/b/\(w.logo.sha256).png?v=2"] {
                let response = try await h.request(.GET, path, headers: asset)
                XCTAssertEqual(response.status, .notFound, path)
                XCTAssertNil(response.headers.first(name: .setCookie), path)
                XCTAssertTrue(response.body.isEmpty, path)
            }
            try await eq(try await h.request(.POST, "/b/\(w.logo.sha256).png", headers: asset).status, .notFound)
            // The API host does not serve assets once an asset host exists.
            try await eq(try await h.request(.GET, "/b/\(w.logo.sha256).png", headers: ["Host": "viadere.com"]).status, .notFound)
            // The AASA file is unaffected on the API host.
            let aasa = try await h.request(.GET, "/.well-known/apple-app-site-association", headers: ["Host": "viadere.com"])
            XCTAssertEqual(aasa.status, .ok, aasa.text)
            // The manifest tells devices where assets live.
            try await eq(try await Self.brand(h, w.customer, w.business.id).json(BrandManifestResponse.self).assetHost, "assets.viadere-cdn.example")
        }
    }

    func testAssetDomainMustBeAHostOfItsOwn() throws {
        var config = ServerConfig.testing()
        for bad in ["viadere.com"] {
            XCTAssertThrowsError(try config.validateAssetDomain(LinkDomain(bad), strict: false), bad)
        }
        XCTAssertThrowsError(try config.validateAssetDomain(LinkDomain("assets.viadere.com"), strict: true))
        XCTAssertNoThrow(try config.validateAssetDomain(LinkDomain("assets.viadere.com"), strict: false))
        XCTAssertNoThrow(try config.validateAssetDomain(LinkDomain("assets.viadere-cdn.example"), strict: true))
        XCTAssertThrowsError(try config.applyBrandKitEnvironment(["ASSET_DOMAIN": "https://assets.example.com/x"], production: false))
        XCTAssertThrowsError(try config.applyBrandKitEnvironment(["BRAND_MANIFEST_SIGNING_KEY": "not-a-key"], production: false))
        XCTAssertThrowsError(try config.applyBrandKitEnvironment(["BRAND_SELECTION_KEY": Base64URL.encode(Data(repeating: 1, count: 8))], production: false))
        XCTAssertThrowsError(try config.applyBrandKitEnvironment(["BRAND_ASSET_DIRECTORY": "/tmp/x"], production: true))
        // A Key Vault key without the vault, or next to a software key, refuses the boot.
        XCTAssertThrowsError(try config.applyBrandKitEnvironment(["AZURE_KEY_VAULT_BRAND_MANIFEST_KEY": "brand-manifest"], production: false))
        // Strict environments without a key simply have Brand Kits off.
        try config.applyBrandKitEnvironment([:], production: true)
        XCTAssertNil(config.brandKits.manifestKey)
        XCTAssertNil(config.brandKits.selectionKey)
        let raw = Base64URL.encode(P256.Signing.PrivateKey().rawRepresentation)
        try config.applyBrandKitEnvironment(["BRAND_MANIFEST_SIGNING_KEY": raw, "ASSET_DOMAIN": "assets.viadere-cdn.example"], production: true)
        XCTAssertNotNil(config.brandKits.manifestKey)
        XCTAssertEqual(config.brandKits.assetDomain?.host, "assets.viadere-cdn.example")
    }

    func testBrandSigningKeyMustDifferFromTheOtherSigningKeys() async throws {
        var config = ServerConfig.testing()
        config.brandKits.manifestKey = config.approve.linkDescriptorKey
        do { try await BrandKitRegistration.resolveSigningKey(config: &config, kms: nil); XCTFail("shared key accepted") } catch {}
        // On Azure the key comes from Key Vault (LocalKMS stands in here) and its public key is loaded at boot.
        let kms = LocalKMS()
        kms.createSigningKey("brand-manifest")
        var azure = ServerConfig.testing()
        azure.brandKits.keyVaultManifestKey = "brand-manifest"
        try await BrandKitRegistration.resolveSigningKey(config: &azure, kms: kms)
        let loaded = try XCTUnwrap(azure.brandKits.manifestKey)
        let expected = DevicePublicKey(try await kms.publicKey(keyRef: "brand-manifest"))
        XCTAssertEqual(loaded.publicKey, expected)
        var missing = ServerConfig.testing()
        missing.brandKits.keyVaultManifestKey = "absent-key"
        do { try await BrandKitRegistration.resolveSigningKey(config: &missing, kms: kms); XCTFail("missing key accepted") } catch {}
        // The worker never signs manifests.
        var worker = ServerConfig.testing()
        worker.role = .worker
        try await BrandKitRegistration.resolveSigningKey(config: &worker, kms: nil)
        XCTAssertTrue(worker.brandKits.manifestKey is UnavailableSigningKey)
    }

    // MARK: Scheduling, pinning, seeds (WP-2.4)

    func testOverlappingEqualPriorityWindowsAreRefusedAtPublish() async throws {
        try await withHarness { h in
            let w = try await Self.world(h)
            let service = BrandKitService(db: h.db, ctx: h.ctx)
            let a = BrandScheduleWindow(kit: "everyday", startsAt: LocalDateTime("2027-03-01T00:00")!, endsAt: LocalDateTime("2027-04-01T00:00")!, priority: 5)
            let b = BrandScheduleWindow(kit: "everyday", startsAt: LocalDateTime("2027-03-15T00:00")!, endsAt: nil, priority: 5)
            do {
                try await service.saveSchedule(businessId: w.business.record.id!, schedule: BrandSchedule(timezone: "America/Phoenix", windows: [a, b]), actor: Self.system)
                XCTFail("overlap accepted")
            } catch let error as APIError {
                XCTAssertEqual(error.status, .unprocessableEntity)
                XCTAssertTrue(error.details?.values.contains("ambiguous_overlap") == true)
            }
            do {
                try await service.saveSchedule(businessId: w.business.record.id!, schedule: BrandSchedule(timezone: "Not/AZone", windows: [a]), actor: Self.system)
                XCTFail("bad zone accepted")
            } catch {}
            do {
                try await service.saveSchedule(businessId: w.business.record.id!, schedule: BrandSchedule(timezone: "UTC", defaultKit: "ghost"), actor: Self.system)
                XCTFail("unknown kit accepted")
            } catch {}
        }
    }

    func testAPinnedInteractionKeepsItsKitWhenTheScheduleChangesAndSecurityRequestsAreNeverPinned() async throws {
        try await withHarness { h in
            let w = try await Self.world(h)
            let service = BrandKitService(db: h.db, ctx: h.ctx)
            let business = w.business.record.id!
            // A second approved kit, active through a window right now (the clock is 2027-01-15T08:00Z).
            let winter = try await service.save(businessId: business, kitId: nil, draft: .init(kitKey: "winter", name: "Winter",
                tokens: BrandTokens(primary: BrandColor("#1D3557")!), frameId: nil, assets: [:]), actor: Self.system)
            try await service.approveKit(id: winter.id!, actor: Self.operatorActor, note: nil)
            let now = LocalDateTime.localDay(of: h.clock.now(), in: TimeZone(identifier: "UTC")!)
            let window = BrandScheduleWindow(kit: "winter", startsAt: LocalDateTime("\(now)T00:00")!, endsAt: nil, priority: 10)
            try await service.saveSchedule(businessId: business, schedule: BrandSchedule(timezone: "UTC", defaultKit: "everyday", windows: [window]), actor: Self.system)

            let confirm = try await h.issue(w.business, relationship: w.relationship, payload: .confirm(ConfirmPayload(title: "Confirm pickup")), purpose: .transactional)
            XCTAssertEqual(confirm.status, .created, confirm.text)
            let confirmId = try confirm.json(Interaction.self).id
            let signIn = try await h.issue(w.business, relationship: w.relationship,
                payload: .authenticate(AuthenticatePayload(service: "Online account", device: "Safari", attemptedAt: h.clock.now())), purpose: .security)
            XCTAssertEqual(signIn.status, .created, signIn.text)
            let signInId = try signIn.json(Interaction.self).id

            // The schedule changes: the window is removed and everyday becomes the only choice.
            try await service.saveSchedule(businessId: business, schedule: BrandSchedule(timezone: "UTC", defaultKit: "everyday"), actor: Self.system)
            let view = try await Self.brand(h, w.customer, w.business.id).json(BrandManifestResponse.self)
            XCTAssertEqual(view.pins, [BrandKitPin(interactionId: confirmId.description.lowercased(), kitId: "winter")])
            XCTAssertFalse(view.pins.contains { $0.interactionId == signInId.description.lowercased() })
            let manifest = try BrandManifest.verify(view.manifest, expectedBusiness: w.business.id, keys: try Self.pinnedKeys(h), now: h.clock.now())
            XCTAssertEqual(BrandKitSelector.select(manifest: manifest, now: h.clock.now(), pinnedKit: "winter").kitId, "winter")
            XCTAssertEqual(BrandKitSelector.select(manifest: manifest, now: h.clock.now(), selectionSeed: view.selectionSeedData).kitId, "everyday")
            // A pin never leaks to another customer.
            let bob = try await h.readyConsumer(name: "Bob")
            _ = try await h.connect(bob, to: w.business)
            try await isTrue(try await Self.brand(h, bob, w.business.id).json(BrandManifestResponse.self).pins.isEmpty)
        }
    }

    func testRandomPoolSeedIsStablePerCustomerAndBusinessAndUnlinkableAcrossBusinesses() async throws {
        try await withHarness { h in
            let w = try await Self.world(h)
            let w2 = try await Self.world(h, name: "Second Shop", handle: "secondshop")
            _ = try await h.connect(w.customer, to: w2.business)
            let seedA1 = try await Self.brand(h, w.customer, w.business.id).json(BrandManifestResponse.self).selectionSeed
            let seedA2 = try await Self.brand(h, w.customer, w.business.id).json(BrandManifestResponse.self).selectionSeed
            let seedB = try await Self.brand(h, w.customer, w2.business.id).json(BrandManifestResponse.self).selectionSeed
            let other = try await Self.brand(h, w2.customer, w2.business.id).json(BrandManifestResponse.self).selectionSeed
            XCTAssertNotNil(seedA1)
            XCTAssertEqual(seedA1, seedA2)
            XCTAssertNotEqual(seedA1, seedB)
            XCTAssertNotEqual(seedB, other)
            XCTAssertEqual(seedA1, Base64URL.encode(BrandSelectionSeed.derive(key: h.ctx.config.brandKits.selectionKey!, consumer: w.customer.id, business: w.business.id)))
        }
    }

    // MARK: Stale cache (D3.T7, server half)

    func testManifestsAreReissuedBeforeExpiryAndAnExpiredOneIsNeverServed() async throws {
        try await withHarness { h in
            let w = try await Self.world(h)
            let first = try await Self.brand(h, w.customer, w.business.id)
            let etag = try XCTUnwrap(first.headers.first(name: .eTag))
            let notModified = try await Self.brand(h, w.customer, w.business.id, headers: ["If-None-Match": etag])
            XCTAssertEqual(notModified.status, .notModified)
            let v1 = try BrandManifest.verify(try first.json(BrandManifestResponse.self).manifest, expectedBusiness: w.business.id, keys: try Self.pinnedKeys(h), now: h.clock.now())
            // Eight days later (less than seven days left): re-issued with a new version and lifetime.
            h.clock.advance(by: 8 * 86400)
            let service = BrandKitService(db: h.db, ctx: h.ctx)
            let reissued = try await XCTUnwrapAsync(await service.current(businessId: w.business.record.id!))
            let v2 = try BrandManifest.verify(reissued.jws, expectedBusiness: w.business.id, keys: try Self.pinnedKeys(h), now: h.clock.now())
            XCTAssertGreaterThan(v2.manifestVersion, v1.manifestVersion)
            XCTAssertGreaterThan(v2.notAfter, v1.notAfter)
            // The manifest a device cached first is past its lifetime later: it no longer verifies (neutral on the device).
            XCTAssertThrowsError(try BrandManifest.verify(try first.json(BrandManifestResponse.self).manifest, expectedBusiness: w.business.id,
                                                          keys: try Self.pinnedKeys(h), now: h.clock.now().addingTimeInterval(7 * 86400)))
        }
    }

    func testAnExpiredManifestIsNeverServedWhenItCannotBeReissued() async throws {
        try await withHarness({ $0.brandKits.manifestKey = nil }) { h in
            let business = try await h.makeBusiness(name: "Corner Shop", handle: "cornershop")
            let row = BrandManifestRecord()
            row.id = UUID()
            row.businessId = business.record.id!
            row.version = 1
            row.status = "active"
            row.jws = "a.b.c"
            row.notAfter = h.clock.now().addingTimeInterval(-1)
            row.createdAt = h.clock.now()
            try await row.create(on: h.db)
            let service = BrandKitService(db: h.db, ctx: h.ctx)
            try await isNil(try await service.current(businessId: business.record.id!))
            row.notAfter = h.clock.now().addingTimeInterval(3600)
            try await row.update(on: h.db)
            // Inside its lifetime it is still served (the device re-checks `not_after` itself).
            try await notNil(try await service.current(businessId: business.record.id!))
            // Without a signing key the consumer route is neutral in any case.
            let customer = try await h.readyConsumer()
            _ = try await h.connect(customer, to: business)
            try await eq(try await Self.brand(h, customer, business.id).json(BrandManifestResponse.self).status, .neutral)
        }
    }

    // MARK: Upload path through the console (WP-2.2 tenancy, WP-2.5)

    static func multipart(_ fields: [(String, String)], file: (name: String, filename: String, type: String, data: Data)?) -> (Data, String) {
        let boundary = "viadere-test-\(UUID().uuidString)"
        var body = Data()
        for (name, value) in fields { body += Data("--\(boundary)\r\nContent-Disposition: form-data; name=\"\(name)\"\r\n\r\n\(value)\r\n".utf8) }
        if let file {
            body += Data("--\(boundary)\r\nContent-Disposition: form-data; name=\"\(file.name)\"; filename=\"\(file.filename)\"\r\nContent-Type: \(file.type)\r\n\r\n".utf8)
            body += file.data + Data("\r\n".utf8)
        }
        body += Data("--\(boundary)--\r\n".utf8)
        return (body, "multipart/form-data; boundary=\(boundary)")
    }

    func upload(_ h: TestHarness, _ session: DashSession?, slot: String = "logo", type: String = "image/png", data: Data, csrf: String? = nil) async throws -> HTTPResult {
        var fields = [("slot", slot)]
        if let session { fields.append(("_csrf", csrf ?? h.csrf(session))) }
        let (body, contentType) = Self.multipart(fields, file: ("file", "logo.png", type, data))
        var headers = h.cookieHeaders(session)
        headers["Origin"] = h.origin
        return try await h.request(.POST, ConsoleBrandStudio.uploadPath, headers: headers, body: body, contentType: contentType)
    }

    func testConsoleUploadNeedsAuthenticationPermissionFreshPasskeyAndStaysInTheTenant() async throws {
        try await withHarness { h in
            let (owner, ownerAccount, businessId) = try await h.verifiedOwner()
            let png = Data(BrandAssetPipelineTests.png())
            // Unauthenticated and without CSRF: refused, nothing stored.
            let anonymous = try await upload(h, nil, data: png)
            XCTAssertNotEqual(anonymous.status, .ok)
            XCTAssertNotEqual(anonymous.headers.first(name: .location), ConsoleBrandStudio.path + "?m=uploaded")
            try await eq(try await BrandAssetRecord.query(on: h.db).count(), 0)
            let forged = try await upload(h, owner, data: png, csrf: "forged")
            XCTAssertEqual(forged.status, .forbidden)
            // Re-authenticated owner: accepted, pending review, not public.
            try await h.dashReauth(owner, ownerAccount)
            let ok = try await upload(h, owner, data: png)
            XCTAssertEqual(ok.status, .seeOther, ok.text)
            let asset = try await XCTUnwrapAsync(await BrandAssetRecord.query(on: h.db).filter(\.$businessId == businessId).first())
            XCTAssertEqual(asset.state, "pending_review")
            try await eq(try await h.request(.GET, "/b/\(asset.sha256).png").status, .notFound)
            // A hostile file through the console: refused with its reason, audited, counted.
            let svg = try await upload(h, owner, type: "image/png", data: Data("<svg onload=alert(1)>".utf8))
            XCTAssertEqual(svg.status, .unprocessableEntity)
            XCTAssertEqual(h.ctx.metrics.brandRejectionCount(.svgRefused), 1)
            try await isTrue(try await AuditEventRecord.query(on: h.db).filter(\.$action == "brandkit.asset_rejected").count() > 0)
            // The owner sees its image; a member of another organization cannot see it, its kit preview or its image route.
            try await eq(try await h.get(owner, "/dashboard/brand/assets/\(asset.id!.uuidString.lowercased())/image"), .ok)
            let (outsider, outsiderAccount, _) = try await h.verifiedOwner(email: "rival@example.com", org: "Rival Roasters", handle: "rivalroasters")
            try await h.dashReauth(outsider, outsiderAccount)
            try await eq(try await h.get(outsider, "/dashboard/brand/assets/\(asset.id!.uuidString.lowercased())/image"), .notFound)
            let kit = try await BrandKitService(db: h.db, ctx: h.ctx).save(businessId: businessId, kitId: nil, draft: .init(kitKey: "everyday", name: "Everyday",
                tokens: BrandTokens(primary: BrandColor("#2F5D50")!), frameId: nil, assets: [.logo: asset.id!]), actor: Self.system)
            for path in ["/dashboard/brand/kits/\(kit.id!.uuidString.lowercased())", "/dashboard/brand/preview/\(kit.id!.uuidString.lowercased())"] {
                try await eq(try await h.get(outsider, path), .notFound, path)
            }
            let hijack = try await h.formPost("/dashboard/brand/kits/\(kit.id!.uuidString.lowercased())", outsider, [("name", "Mine"), ("primary", "#000000")])
            XCTAssertEqual(hijack.status, .notFound, hijack.text)
            // A role without manageBrandKits cannot change anything.
            let (operatorMember, operatorAccount) = try await h.addMember(owner: owner, role: .messagingOperator, email: "ops@acme.example")
            try await h.dashReauth(operatorMember, operatorAccount)
            try await eq(try await upload(h, operatorMember, data: png).status, .forbidden)
            try await eq(try await h.formPost("/dashboard/brand/kits", operatorMember, [("kit_id", "x"), ("name", "X"), ("primary", "#000000")]).status, .forbidden)
        }
    }

    func testStudioSavesKitsAndSchedulesAndRendersASandboxedPreview() async throws {
        try await withHarness { h in
            let (owner, account, businessId) = try await h.verifiedOwner()
            try await h.dashReauth(owner, account)
            // Unknown fields (a smuggled label, a URL) are simply not read; the stored tokens are Core's closed schema.
            let created = try await h.formPost("/dashboard/brand/kits", owner, [("kit_id", "spring"), ("name", "Spring"), ("primary", "#fff5d6"),
                ("use_accent", "1"), ("accent", "#B5683A"), ("radius", "large"), ("button_label", "Approve now"), ("logo_url", "https://evil.example/x.png")])
            XCTAssertEqual(created.status, .seeOther, created.text)
            let kit = try await XCTUnwrapAsync(await BrandKitRecord.query(on: h.db).filter(\.$businessId == businessId).first())
            XCTAssertEqual(kit.tokensJSON, ##"{"accent":"#B5683A","on_primary":"auto","primary":"#FFF5D6","radius":"large"}"##)
            XCTAssertEqual(kit.status, "pending_review")
            let bad = try await h.formPost("/dashboard/brand/kits", owner, [("kit_id", "x"), ("name", "X"), ("primary", "red;background:url(x)")])
            XCTAssertEqual(bad.status, .unprocessableEntity)
            // The kit page warns in text about the low-contrast primary.
            let page = try await h.page("/dashboard/brand/kits/\(kit.id!.uuidString.lowercased())", owner)
            XCTAssertEqual(page.status, .ok)
            XCTAssertTrue(page.text.contains("Contrast warnings"))
            XCTAssertTrue(page.text.contains("Primary #FFF5D6"))
            XCTAssertTrue(page.headers.first(name: "Content-Security-Policy")?.contains("frame-src 'self'") == true)
            XCTAssertTrue(page.text.contains("sandbox=\"\""))
            // The preview: its own CSP (no script source, sandbox, framable only by the console), and an approval card that stays neutral.
            let preview = try await h.page("/dashboard/brand/preview/\(kit.id!.uuidString.lowercased())", owner)
            XCTAssertEqual(preview.status, .ok)
            let csp = try XCTUnwrap(preview.headers.first(name: "Content-Security-Policy"))
            XCTAssertTrue(csp.contains("sandbox"))
            XCTAssertTrue(csp.contains("frame-ancestors 'self'"))
            XCTAssertTrue(csp.contains("img-src data:"))
            XCTAssertFalse(csp.contains("script-src"))
            XCTAssertFalse(preview.text.contains("<script"))
            XCTAssertEqual(preview.headers.first(name: "X-Frame-Options"), "SAMEORIGIN")
            XCTAssertTrue(preview.text.contains("Preview, not exactly what customers see"))
            XCTAssertTrue(preview.text.contains("Approvals always use Viadere's own style"))
            // The approval card uses the protected neutral palette, never the kit's primary.
            XCTAssertTrue(preview.text.contains("--qp:\(ProtectedPalette.palette(.light).primary.hex)"))
            // Schedule through the form: an overlap is refused, a valid one is stored.
            let overlap = try await h.formPost("/dashboard/brand/schedule", owner, [("timezone", "America/Phoenix"), ("w0_kit", "spring"), ("w0_start", "2027-03-01T00:00"),
                ("w0_priority", "5"), ("w1_kit", "spring"), ("w1_start", "2027-03-10T00:00"), ("w1_priority", "5")])
            XCTAssertEqual(overlap.status, .unprocessableEntity, overlap.text)
            let saved = try await h.formPost("/dashboard/brand/schedule", owner, [("timezone", "America/Phoenix"), ("default_kit", "spring"), ("w0_kit", "spring"),
                ("w0_start", "2027-03-01T00:00"), ("w0_end", "2027-04-01T00:00"), ("w0_priority", "5"), ("pool_spring", "3")])
            XCTAssertEqual(saved.status, .seeOther, saved.text)
            let schedule = try await XCTUnwrapAsync(await BrandKitService(db: h.db, ctx: h.ctx).schedule(businessId: businessId))
            XCTAssertEqual(schedule.timezone, "America/Phoenix")
            XCTAssertEqual(schedule.randomPool, [BrandPoolEntry(kit: "spring", weight: 3)])
            // The studio home renders for the owner.
            let studio = try await h.page("/dashboard/brand", owner)
            XCTAssertEqual(studio.status, .ok, studio.text)
            XCTAssertTrue(studio.text.contains("Brand Kits"))
        }
    }

    // MARK: Operator review (WP-2.8)

    func testOperatorReviewQueueNeedsFreshPasskeyAndReasons() async throws {
        try await withHarness { h in
            let w = try await Self.world(h, publish: false)
            let (session, account) = try await h.makeOperator()
            let queue = try await h.page("/operator/brand", session)
            XCTAssertEqual(queue.status, .ok, queue.text)
            XCTAssertTrue(queue.text.contains("Everyday"))
            // Business sessions cannot reach the operator queue.
            let (owner, _, _) = try await h.verifiedOwner()
            let crossRealm = try await h.page("/operator/brand", owner)
            XCTAssertNotEqual(crossRealm.status, .ok)
            let asset = w.logo.id!.uuidString.lowercased(), kit = w.kit.id!.uuidString.lowercased()
            // A rejection without a reason is refused; with one it is recorded.
            try await h.dashReauth(session, account)
            try await eq(try await h.formPost("/operator/brand/assets/\(asset)/reject", session, [("reason", "")]).status, .unprocessableEntity)
            try await eq(try await h.formPost("/operator/brand/assets/\(asset)/approve", session).status, .seeOther)
            try await eq(try await h.formPost("/operator/brand/kits/\(kit)/approve", session).status, .seeOther)
            try await eq(try await Self.brand(h, w.customer, w.business.id).json(BrandManifestResponse.self).status, .branded)
            try await eq(try await h.formPost("/operator/brand/kits/\(kit)/takedown", session, [("reason", "Imitates a bank's logo")]).status, .seeOther)
            try await eq(try await Self.brand(h, w.customer, w.business.id).json(BrandManifestResponse.self).status, .neutral)
            // The kill switch from the queue page.
            try await eq(try await h.formPost("/operator/brand/switch", session, [("action", "on"), ("reason", "Incident drill for branding")]).status, .seeOther)
            try await isTrue(await PlatformFlags(db: h.db, ctx: h.ctx).brandKitsStopped(businessId: w.business.record.id!))
            XCTAssertGreaterThan(h.ctx.metrics.value(.brandTakedown), 0)
        }
    }

    // MARK: Surfaces (WP-2.7, server policy)

    func testNotificationAttachmentIsTheApprovedLogoAndNeverOnSecurityRequests() async throws {
        try await withHarness({ $0.brandKits.assetDomain = LinkDomain("assets.viadere-cdn.example") }) { h in
            let w = try await Self.world(h)
            let resolver = BrandAttachmentResolver(db: h.db, ctx: h.ctx)
            let url = try await resolver.attachmentURL(businessId: w.business.record.id!, consumerId: w.customer.id.uuid, purpose: .marketing, kind: .message)
            XCTAssertEqual(url?.absoluteString, "https://assets.viadere-cdn.example/b/\(w.logo.sha256).png")
            for (purpose, kind) in [(InteractionPurpose.security, InteractionKind.authenticate), (.transactional, .authorize), (.accountService, .status), (.marketing, .unknown("new"))] {
                try await isNil(try await resolver.attachmentURL(businessId: w.business.record.id!, consumerId: w.customer.id.uuid, purpose: purpose, kind: kind), "\(purpose) \(kind)")
            }
        }
    }
}
