import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

/// Serves the captured Atlas responses like the staging API and asset host do.
actor AtlasFixtureServer: BrandKitAPI, BrandAssetFetcher {
    private(set) var manifestCalls = 0
    private(set) var assetURLs: [URL] = []

    func brandManifest(business: BusinessID, ifNoneMatch: String?) async throws -> BrandManifestFetch {
        manifestCalls += 1
        guard business == AtlasBrandFixture.businessId else { throw APIError.server(status: 404, code: .notFound, message: "Not found.") }
        if ifNoneMatch == AtlasBrandFixture.etag { return .notModified }
        return .fetched(AtlasBrandFixture.response, etag: AtlasBrandFixture.etag)
    }

    func fetch(_ url: URL, maxBytes: Int) async throws -> Data {
        assetURLs.append(url)
        let logo = AtlasBrandFixture.logo
        guard url.host == AtlasBrandFixture.assetHost, url.lastPathComponent == "\(MockBrandKitAPI.ref(for: logo).sha256).png" else {
            throw BrandKitError.assetStatus(404)
        }
        return logo
    }
}

/// The device half of the staging Atlas Demo Brand Kit (see `StagingDemoBrandKitTests` on the server): the captured, operator-approved
/// manifest goes through the build pin parser, `BrandKitStore`, `BusinessHomeDecoration` and the themed brand palette exactly as the app
/// runs them. Staging showed the Atlas page exactly like an unbranded one.
@Suite("Atlas Demo Brand Kit on a device (captured from the server)")
struct AtlasBrandKitDeviceTests {
    static let business = BusinessSummary(id: AtlasBrandFixture.businessId, displayName: AtlasBrandFixture.displayName, handle: nil,
                                          code: BusinessCode.generate(), verificationStatus: .verified)

    static func store(_ server: AtlasFixtureServer, cache: any BrandKitCache = InMemoryBrandKitCache()) -> BrandKitStore {
        let keys = ManifestKeyPins.parse(AtlasBrandFixture.pin)
        return BrandKitStore(api: server, assets: server, cache: cache, keys: keys, apiHost: "viadere-api.cksites.dev",
                             clock: { AtlasBrandFixture.now.addingTimeInterval(60) })
    }

    @Test("the build pin line parses to the key the server signed with")
    func pinParses() {
        let keys = ManifestKeyPins.parse(AtlasBrandFixture.pin)
        #expect(keys.count == 1)
        let manifest = try? BrandManifest.verify(AtlasBrandFixture.response.manifest ?? "", expectedBusiness: AtlasBrandFixture.businessId,
                                                 keys: keys, now: AtlasBrandFixture.now)
        #expect(manifest?.kits.map(\.kitId) == ["atlas"])
    }

    @Test("the store verifies the manifest, selects the atlas kit and caches the hash-checked logo")
    func storeResolvesAtlas() async {
        let server = AtlasFixtureServer()
        let store = Self.store(server)
        #expect(!store.resolution(for: Self.business.id).isBranded, "nothing before the first refresh")
        let resolution = await store.refresh(Self.business.id)
        #expect(resolution.isBranded)
        #expect(resolution.kit?.kitId == "atlas")
        #expect(resolution.style.source == .brandKit)
        #expect(resolution.style.tokens?.primary == BrandColor("#227470"))
        #expect(await server.assetURLs.count == 1)
    }

    @Test("the business page decoration is branded: logo, teal header, tinted space in every theme; identity stays neutral")
    func decorationIsVisiblyBranded() async {
        let server = AtlasFixtureServer()
        let store = Self.store(server)
        _ = await store.refresh(Self.business.id)
        let decoration = BusinessHomeDecoration.make(business: Self.business, brand: store)
        #expect(decoration.style.source == .brandKit)
        #expect(decoration.logo == AtlasBrandFixture.logo)
        #expect(decoration.logoSlot == .logo)
        #expect(decoration.name == "Atlas Demo" && decoration.isVerified)
        for theme in AppearanceTheme.all {
            let palette = decoration.style.palette(in: theme)
            #expect(palette.isBranded)
            #expect(AppearanceThemeAudit.brandFailures(palette, theme: theme).isEmpty, "\(theme.id)")
            // Visibly different from the unbranded page: the header is the brand's teal (or its lighter variant), not the page ground.
            let neutral = ThemedBrandPalette.protected(for: theme)
            #expect(palette.primary != neutral.primary, "\(theme.id): the header band must not fall back to Viadere's own fill")
            #expect(ContrastPolicy.ratioTimes100(palette.primary, theme.palette.background.color) >= 150,
                    "\(theme.id): the teal band must stand out from the page")
        }
    }

    @Test("an app restart renders the kit from the app-group cache at once, before any network")
    func coldStartFromCache() async {
        let cache = InMemoryBrandKitCache()
        _ = await Self.store(AtlasFixtureServer(), cache: cache).refresh(Self.business.id)
        let offline = AtlasFixtureServer()
        let restarted = BrandKitStore(api: nil, assets: nil, cache: cache, keys: ManifestKeyPins.parse(AtlasBrandFixture.pin),
                                      clock: { AtlasBrandFixture.now.addingTimeInterval(3600) })
        let decoration = BusinessHomeDecoration.make(business: Self.business, brand: restarted)
        #expect(decoration.style.source == .brandKit)
        #expect(decoration.logo == AtlasBrandFixture.logo)
        #expect(await offline.manifestCalls == 0)
    }

    // MARK: What the page draws (the staging bug)

    /// Staging served the kit and the device verified it, yet the page looked unbranded: the page drew only the kit's *surface* (Atlas'
    /// ivory #FAF7F0 on Viadere's ivory #F5F2EC page) with a hairline, never the teal, and without an asset host the band held Viadere's
    /// own monogram. The header band must carry the kit's primary in every theme, logo or not.
    @Test("the header band is the Atlas teal in every theme, with or without the logo")
    func headerBandCarriesTheBrand() async {
        for withLogo in [true, false] {
            let store: BrandKitStore
            if withLogo {
                store = Self.store(AtlasFixtureServer())
            } else {
                // Staging without ASSET_DOMAIN: the manifest arrives without an asset host, so no logo can be fetched.
                var response = AtlasBrandFixture.response
                response.assetHost = nil
                let api = MockBrandKitAPI()
                await api.serve(response, etag: "\"no-assets\"")
                store = BrandKitStore(api: api, assets: api, cache: InMemoryBrandKitCache(), keys: ManifestKeyPins.parse(AtlasBrandFixture.pin),
                                      clock: { AtlasBrandFixture.now.addingTimeInterval(60) })
            }
            _ = await store.refresh(Self.business.id)
            let decoration = BusinessHomeDecoration.make(business: Self.business, brand: store)
            #expect((decoration.logo != nil) == withLogo)
            for theme in AppearanceTheme.all {
                let band = decoration.headerBand(in: theme)
                #expect(band.isBranded, "\(theme.id)")
                #expect(band.showsLogo == withLogo)
                #expect(band.fill != theme.palette.background.color && band.fill != theme.palette.surface.color)
                // Visibly not the page: at least 1.5:1 against the canvas, and the monogram ink readable on it.
                #expect(ContrastPolicy.ratioTimes100(band.fill, band.canvas) >= 150, "\(theme.id): \(band.fill.hex) on \(band.canvas.hex)")
                #expect(ContrastPolicy.meets(band.ink, band.fill, minimumTimes10: theme.contrast.minimums.text), "\(theme.id)")
                if theme.contrast == .standard && !theme.isDark {
                    #expect(band.fill == BrandColor("#227470"), "\(theme.id): the teal itself on light themes")
                }
            }
            // An unbranded business keeps Viadere's own header.
            let neutral = BusinessHomeDecoration.make(business: Self.business, brand: nil)
            #expect(!neutral.headerBand(in: .daybreak).isBranded)
        }
    }

    @Test("the conversation with Atlas takes the kit's style; the sender line stays protected")
    func threadIsBranded() async {
        let store = Self.store(AtlasFixtureServer())
        _ = await store.refresh(Self.business.id)
        let card = MessageCardDecoration.make(business: Self.business, brand: store)
        #expect(card.style.source == .brandKit)
        #expect(card.identityPalette == .neutral)
        #expect(card.senderName == "Atlas Demo")
        #expect(MessageCardDecoration.make(business: Self.business, brand: nil).style == .neutral)
    }

    static func alert(_ category: AlertCategory, purpose: InteractionPurpose, verified: Bool = true) -> AlertEntry {
        var summary = business
        summary.verificationStatus = verified ? .verified : .pending
        return AlertEntry(alertId: "interaction:\(UUID().uuidString.lowercased())", eventId: "e", source: .interaction, business: summary,
                          purpose: purpose, category: category, urgency: .normal, status: .pending, title: "Your order is ready", expiresAt: nil,
                          actionRequired: false, actionable: false, unread: true, createdAt: AtlasBrandFixture.now, updatedAt: AtlasBrandFixture.now,
                          target: nil)
    }

    @Test("alert accents: informational updates are branded; approvals, requests, verification and security never are")
    func alertAccents() async {
        let store = Self.store(AtlasFixtureServer())
        _ = await store.refresh(Self.business.id)
        #expect(AlertBrandStyle.make(Self.alert(.update, purpose: .transactional), brand: store).source == .brandKit)
        #expect(AlertBrandStyle.make(Self.alert(.update, purpose: .rewards), brand: store).source == .brandKit)
        for category in [AlertCategory.approval, .request, .verification, .linkConfirmation, .securityNotice, .unknown] {
            #expect(AlertBrandStyle.make(Self.alert(category, purpose: .transactional), brand: store) == .neutral, "\(category)")
        }
        for purpose in [InteractionPurpose.security, .accountService] {
            #expect(AlertBrandStyle.make(Self.alert(.update, purpose: purpose), brand: store) == .neutral, "\(purpose)")
        }
        #expect(AlertBrandStyle.make(Self.alert(.update, purpose: .transactional, verified: false), brand: store) == .neutral)
    }
}
