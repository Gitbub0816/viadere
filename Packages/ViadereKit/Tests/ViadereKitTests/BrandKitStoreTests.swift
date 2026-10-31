import Crypto
import Foundation
import Testing
import ViadereCore
@testable import ViadereKit

/// Fixtures for the Brand Kit tests (WP-2.6, WP-2.7; D3 "Misleading branded approvals", "Stale cache").
enum BK {
    /// 2026-11-15T12:00:00Z
    static let now = Date(timeIntervalSince1970: 1_794_744_000)
    static let business = PreviewData.northfield.id
    static let other = PreviewData.harborBank.id
    static let logo = MockBrandKitAPI.pngBytes("northfield-logo")
    static let mark = MockBrandKitAPI.pngBytes("northfield-mark")
    static let art = MockBrandKitAPI.pngBytes("northfield-art")

    static var keys: [PinnedManifestKey] { [MockBrandKitAPI.pinnedKey] }
    static let rogue = try! SoftwareP256SigningKey(rawRepresentation: Data(SHA256.hash(data: Data("rogue-brand".utf8))))

    /// Hostile tokens: ivory primary on ivory, white accent, near-invisible secondary, a surface that defeats both foregrounds.
    static let hostile = BrandTokens(primary: BrandColor("#F5F2EC")!, secondary: BrandColor("#F0F0F0")!, accent: BrandColor("#FFFFFF")!,
                                     surface: BrandColor("#777777")!, radius: .none, border: .none, typeScale: .large)
    static let good = BrandTokens(primary: BrandColor("#2F5D50")!, secondary: BrandColor("#4A4A48")!, accent: BrandColor("#B5683A")!,
                                  surface: BrandColor("#FFFDF7")!, radius: .large, border: .hairline, typeScale: .standard)

    static func manifest(business: BusinessID = BK.business, tokens: BrandTokens = BK.good, defaultKit: String = "everyday",
                         issued: Date = BK.now.addingTimeInterval(-3600), lifetime: Int64 = 14 * 86400, version: Int64 = 3) -> BrandManifest {
        let issuedAt = Int64(issued.timeIntervalSince1970)
        return BrandManifest(businessId: business, manifestVersion: version, kits: [
            BrandKit(kitId: "everyday", name: "Everyday", tokens: tokens, frameId: "viadere.frame.hairline.v1",
                     assets: [.logo: MockBrandKitAPI.ref(for: logo, width: 512, height: 512), .mark: MockBrandKitAPI.ref(for: mark),
                              .art: MockBrandKitAPI.ref(for: art, width: 1200, height: 800)]),
            BrandKit(kitId: "holiday", name: "Holiday", tokens: BrandTokens(primary: BrandColor("#1D3557")!, accent: BrandColor("#9C2F2F")!)),
        ], schedule: BrandSchedule(timezone: "America/New_York", defaultKit: defaultKit), issuedAt: issuedAt, notAfter: issuedAt + lifetime,
           kid: MockBrandKitAPI.kid)
    }

    final class Clock: @unchecked Sendable {
        private let lock = NSLock()
        private var value: Date
        init(_ value: Date = BK.now) { self.value = value }
        var now: Date { lock.lock(); defer { lock.unlock() }; return value }
        func advance(_ seconds: TimeInterval) { lock.lock(); value = value.addingTimeInterval(seconds); lock.unlock() }
    }

    static func store(api: (any BrandKitAPI)?, assets: (any BrandAssetFetcher)? = nil, cache: any BrandKitCache = InMemoryBrandKitCache(),
                      keys: [PinnedManifestKey] = BK.keys, clock: Clock = Clock(), apiHost: String? = "api.viadere.com",
                      timeout: Duration = .seconds(5)) -> BrandKitStore {
        BrandKitStore(api: api, assets: assets, cache: cache, keys: keys, apiHost: apiHost, clock: { clock.now }, fetchTimeout: timeout)
    }

    static func served(_ manifest: BrandManifest = BK.manifest(), key: SoftwareP256SigningKey = MockBrandKitAPI.signingKey,
                       pins: [BrandKitPin] = [], assetHost: String = MockBrandKitAPI.assetHost, etag: String = "\"e1\"") async throws -> MockBrandKitAPI {
        let api = MockBrandKitAPI()
        await api.serve(try await MockBrandKitAPI.response(manifest, key: key, pins: pins, assetHost: assetHost), etag: etag)
        for data in [logo, mark, art] { await api.serveAsset(data, sha256: MockBrandKitAPI.ref(for: data).sha256) }
        return api
    }

    static func tempDirectory() -> URL {
        let url = FileManager.default.temporaryDirectory.appendingPathComponent("brandkit-\(UUID().uuidString)", isDirectory: true)
        try? FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
        return url
    }
}

/// A brand API that never answers (and ignores cancellation): the "hung server" of the timing test.
struct HungBrandKitAPI: BrandKitAPI, BrandAssetFetcher {
    func brandManifest(business: BusinessID, ifNoneMatch: String?) async throws -> BrandManifestFetch {
        await withCheckedContinuation { (_: CheckedContinuation<Void, Never>) in }
        return .notModified
    }
    func fetch(_ url: URL, maxBytes: Int) async throws -> Data {
        await withCheckedContinuation { (_: CheckedContinuation<Void, Never>) in }
        return Data()
    }
}

@Suite("Brand Kit store: verification and cache")
struct BrandKitStoreTests {
    @Test func verifiedManifestSelectsTheDefaultKitWithClampedStyle() async throws {
        let api = try await BK.served()
        let store = BK.store(api: api, assets: api)
        #expect(store.resolution(for: BK.business).isBranded == false)
        let resolved = await store.refresh(BK.business)
        #expect(resolved.kit?.kitId == "everyday")
        #expect(resolved.selection.reason == .defaultKit)
        #expect(resolved.style.source == .brandKit)
        #expect(resolved.style.frameId == "viadere.frame.hairline.v1")
        #expect(resolved.style.palette == ContrastPolicy.resolve(BK.good))
        #expect(store.resolution(for: BK.business).kit?.kitId == "everyday")
        // Per business: nothing leaks to another business.
        #expect(store.resolution(for: BK.other).isBranded == false)
    }

    @Test func manifestSignedByAnUnpinnedKeyRendersNeutralAndIsNotCached() async throws {
        let api = try await BK.served(key: BK.rogue)
        let cache = InMemoryBrandKitCache()
        let store = BK.store(api: api, assets: api, cache: cache)
        #expect(await store.refresh(BK.business).isBranded == false)
        #expect(cache.record(for: BK.business) == nil)
        #expect(await api.assetCalls == 0)
    }

    @Test func noPinnedKeysMeansNeutral() async throws {
        let api = try await BK.served()
        let store = BK.store(api: api, assets: api, keys: [])
        #expect(await store.refresh(BK.business).isBranded == false)
    }

    @Test func manifestOfAnotherBusinessIsRefused() async throws {
        // The server answers for Harbor Bank with Northfield's (validly signed) manifest: it must not style Harbor Bank.
        let api = MockBrandKitAPI()
        var response = try await MockBrandKitAPI.response(BK.manifest(business: BK.business))
        response.businessId = BK.other
        await api.serve(response)
        let store = BK.store(api: api, assets: api)
        #expect(await store.refresh(BK.other).isBranded == false)
    }

    @Test func expiredManifestFallsBackToNeutralWithoutARefetch() async throws {
        let clock = BK.Clock()
        let api = try await BK.served(BK.manifest(lifetime: 2 * 86400))
        let cache = InMemoryBrandKitCache()
        let store = BK.store(api: api, assets: api, cache: cache, clock: clock)
        #expect(await store.refresh(BK.business).isBranded)
        clock.advance(2 * 86400)
        #expect(store.resolution(for: BK.business).isBranded == false)
        #expect(cache.record(for: BK.business) == nil)
        #expect(await api.manifestCalls == 1)
    }

    @Test func notModifiedWithAnExpiredCachedManifestIsNeutral() async throws {
        let clock = BK.Clock()
        let api = try await BK.served(BK.manifest(lifetime: 86400), etag: "\"same\"")
        let cache = InMemoryBrandKitCache()
        let store = BK.store(api: api, assets: api, cache: cache, clock: clock)
        #expect(await store.refresh(BK.business).isBranded)
        clock.advance(86400 + 1)
        // The server says 304 (same ETag) but the cached manifest is past not_after: it is not trusted.
        #expect(await store.refresh(BK.business).isBranded == false)
        #expect(await api.lastIfNoneMatch == .some("\"same\""))
    }

    @Test func conditionalRefreshSendsTheETagAndKeepsTheKit() async throws {
        let api = try await BK.served(etag: "\"v3\"")
        let store = BK.store(api: api, assets: api)
        _ = await store.refresh(BK.business)
        #expect(await api.lastIfNoneMatch == .some(nil))
        let again = await store.refresh(BK.business)
        #expect(await api.lastIfNoneMatch == .some("\"v3\""))
        #expect(again.kit?.kitId == "everyday")
    }

    @Test func tamperedCacheOnDiskIsReverifiedAndDropped() async throws {
        let directory = BK.tempDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let api = try await BK.served()
        let first = BK.store(api: api, assets: api, cache: FileBrandKitCache(directory: directory))
        #expect(await first.refresh(BK.business).isBranded)

        // A fresh process (the notification extension) reads the cache without the network.
        let reader = BK.store(api: nil, cache: FileBrandKitCache(directory: directory))
        #expect(reader.resolution(for: BK.business).kit?.kitId == "everyday")

        // Someone rewrites the cached manifest payload to the hostile tokens (signature no longer matches).
        let cache = FileBrandKitCache(directory: directory)
        var record = try #require(cache.record(for: BK.business))
        let hostile = try await MockBrandKitAPI.response(BK.manifest(tokens: BK.hostile), key: BK.rogue)
        record.response.manifest = hostile.manifest
        cache.store(record, for: BK.business)
        let tampered = BK.store(api: nil, cache: FileBrandKitCache(directory: directory))
        #expect(tampered.resolution(for: BK.business).isBranded == false)
        #expect(FileBrandKitCache(directory: directory).record(for: BK.business) == nil)
    }

    @Test func cachedManifestUnderARetiredKeyIsNeutral() async throws {
        let cache = InMemoryBrandKitCache()
        let api = try await BK.served()
        _ = await BK.store(api: api, assets: api, cache: cache).refresh(BK.business)
        let rotated = BK.store(api: nil, cache: cache, keys: [PinnedManifestKey(kid: "other", publicKey: BK.rogue.publicKey)])
        #expect(rotated.resolution(for: BK.business).isBranded == false)
    }

    @Test func neutralAnswerWithdrawsTheKitAndPurgesTheCache() async throws {
        let api = try await BK.served()
        let cache = InMemoryBrandKitCache()
        let store = BK.store(api: api, assets: api, cache: cache)
        #expect(await store.refresh(BK.business).isBranded)
        await api.serve(.neutral(BK.business), etag: "\"n\"")
        #expect(await store.refresh(BK.business).isBranded == false)
        #expect(store.resolution(for: BK.business).isBranded == false)
        #expect(cache.record(for: BK.business) == nil)
    }

    @Test func notFoundForgetsTheBusiness() async throws {
        let api = try await BK.served()
        let cache = InMemoryBrandKitCache()
        let store = BK.store(api: api, assets: api, cache: cache)
        #expect(await store.refresh(BK.business).isBranded)
        // Disconnected (or no longer verified): the server answers 404 and everything about the business is dropped.
        await api.stopServing(BK.business)
        #expect(await store.refresh(BK.business).isBranded == false)
        #expect(store.resolution(for: BK.business).isBranded == false)
        #expect(cache.record(for: BK.business) == nil)
    }

    @Test func offlineKeepsTheStillValidVerifiedKit() async throws {
        let api = try await BK.served()
        let store = BK.store(api: api, assets: api)
        #expect(await store.refresh(BK.business).isBranded)
        await api.setFailing(true)
        #expect(await store.refresh(BK.business).isBranded)
    }

    @Test func pinnedKitWinsForItsInteractionAndAMissingPinnedKitIsNeutral() async throws {
        let pinned = InteractionID()
        let dangling = InteractionID()
        let api = try await BK.served(pins: [BrandKitPin(interactionId: pinned.description, kitId: "holiday"),
                                             BrandKitPin(interactionId: dangling.description, kitId: "removed")])
        let store = BK.store(api: api, assets: api)
        _ = await store.refresh(BK.business)
        let surface = BrandSurface.interaction(purpose: .transactional, kind: .confirm)
        #expect(store.resolution(for: BK.business, surface: surface, interactionId: pinned).kit?.kitId == "holiday")
        #expect(store.resolution(for: BK.business, surface: surface, interactionId: dangling).isBranded == false)
        #expect(store.resolution(for: BK.business, surface: surface).kit?.kitId == "everyday")
    }
}

@Suite("Brand Kit store: assets")
struct BrandKitAssetTests {
    @Test func assetsAreStoredOnlyAfterTheirHashMatches() async throws {
        let api = try await BK.served()
        let cache = InMemoryBrandKitCache()
        // The asset host serves the wrong bytes for the logo.
        await api.serveAsset(MockBrandKitAPI.pngBytes("swapped"), sha256: MockBrandKitAPI.ref(for: BK.logo).sha256)
        let store = BK.store(api: api, assets: api, cache: cache)
        let resolved = await store.refresh(BK.business)
        let logoRef = try #require(resolved.kit?.assets[.logo])
        let markRef = try #require(resolved.kit?.assets[.mark])
        #expect(cache.asset(sha256: logoRef.sha256) == nil)
        #expect(store.verifiedAsset(logoRef) == nil)
        #expect(store.verifiedAsset(markRef) == BK.mark)
    }

    @Test func tamperedCachedAssetIsDeletedNotShown() async throws {
        let api = try await BK.served()
        let cache = InMemoryBrandKitCache()
        let store = BK.store(api: api, assets: api, cache: cache)
        let resolved = await store.refresh(BK.business)
        let ref = try #require(resolved.kit?.assets[.logo])
        #expect(store.verifiedAsset(ref) == BK.logo)
        cache.overwriteAsset(MockBrandKitAPI.pngBytes("evil"), sha256: ref.sha256)
        #expect(store.verifiedAsset(ref) == nil)
        #expect(cache.asset(sha256: ref.sha256) == nil)
    }

    @Test func assetsAreNeverFetchedFromTheAPIHost() async throws {
        let api = try await BK.served(assetHost: "api.viadere.com")
        let store = BK.store(api: api, assets: api, apiHost: "api.viadere.com")
        #expect(await store.refresh(BK.business).isBranded)
        #expect(await api.assetCalls == 0)
    }

    @Test func assetBytesMustBeAPNGOfTheDeclaredSize() {
        let ref = MockBrandKitAPI.ref(for: BK.logo)
        #expect(BrandAssetVerifier.isValid(BK.logo, for: ref))
        #expect(!BrandAssetVerifier.isValid(BK.logo + Data([0]), for: ref))
        let notPNG = Data("GIF89a-not-a-png".utf8)
        #expect(!BrandAssetVerifier.isValid(notPNG, for: MockBrandKitAPI.ref(for: notPNG)))
    }

    @Test func fileCacheEvictsLeastRecentlyUsedAssetsUnderItsBudget() throws {
        let directory = BK.tempDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let cache = FileBrandKitCache(directory: directory, byteBudget: 2_500)
        let blobs = (0..<3).map { Data(repeating: UInt8($0), count: 1_000) }
        let names = blobs.map { SHA256.hash(data: $0).map { String(format: "%02x", $0) }.joined() }
        cache.storeAsset(blobs[0], sha256: names[0])
        Thread.sleep(forTimeInterval: 1.1)
        cache.storeAsset(blobs[1], sha256: names[1])
        Thread.sleep(forTimeInterval: 1.1)
        _ = cache.asset(sha256: names[0]) // touch: now the most recently used
        Thread.sleep(forTimeInterval: 1.1)
        cache.storeAsset(blobs[2], sha256: names[2])
        #expect(cache.usedBytes <= 2_500)
        #expect(cache.asset(sha256: names[1]) == nil)
        #expect(cache.asset(sha256: names[0]) == blobs[0])
        #expect(cache.asset(sha256: names[2]) == blobs[2])
    }

    @Test func fileCacheRefusesNamesThatAreNotHashes() {
        let directory = BK.tempDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let cache = FileBrandKitCache(directory: directory)
        cache.storeAsset(Data("x".utf8), sha256: "../../escape")
        cache.storeAsset(Data("x".utf8), sha256: String(repeating: "A", count: 64))
        #expect(cache.usedBytes == 0)
        #expect(!FileManager.default.fileExists(atPath: directory.deletingLastPathComponent().appendingPathComponent("escape.png").path))
    }

    @Test func signOutRemovesEverything() async throws {
        let directory = BK.tempDirectory()
        defer { try? FileManager.default.removeItem(at: directory) }
        let api = try await BK.served()
        let store = BK.store(api: api, assets: api, cache: FileBrandKitCache(directory: directory))
        #expect(await store.refresh(BK.business).isBranded)
        store.removeAll()
        #expect(store.resolution(for: BK.business).isBranded == false)
        #expect(FileBrandKitCache(directory: directory).usedBytes == 0)
    }
}

@Suite("Brand Kits never delay or dress up security flows")
struct BrandKitSecurityTests {
    @Test func aHungBrandServerDelaysNothing() async throws {
        let store = BK.store(api: HungBrandKitAPI(), assets: HungBrandKitAPI(), timeout: .milliseconds(300))
        let refresh = Task { await store.refresh(BK.business) }
        let started = ContinuousClock.now
        // Every read answers at once while the fetch hangs.
        for surface in [BrandSurface.approval, .signIn, .security, .businessHome, .messageCard, .interaction(purpose: .security, kind: .authenticate)] {
            #expect(store.resolution(for: BK.business, surface: surface).isBranded == false)
        }
        #expect(store.notificationAttachment(business: BK.business, interactionId: nil, purpose: .transactional, kind: .confirm) == nil)
        #expect(ContinuousClock.now - started < .milliseconds(100))
        // And the refresh itself gives up instead of hanging.
        let result = await refresh.value
        #expect(result.isBranded == false)
        #expect(ContinuousClock.now - started < .seconds(3))
    }

    @Test func protectedSurfacesAreNeutralWhateverTheKit() async throws {
        let api = try await BK.served(BK.manifest(tokens: BK.hostile))
        let store = BK.store(api: api, assets: api)
        #expect(await store.refresh(BK.business).isBranded)
        for surface in [BrandSurface.approval, .signIn, .security, .verification, .profileRequest,
                        .interaction(purpose: .security, kind: .confirm), .interaction(purpose: .accountService, kind: .acknowledge),
                        .interaction(purpose: .transactional, kind: .authenticate), .interaction(purpose: .transactional, kind: .authorize),
                        .interaction(purpose: .marketing, kind: .unknown("future_kind"))] {
            let resolved = store.resolution(for: BK.business, surface: surface)
            #expect(resolved.isBranded == false)
            #expect(resolved.style == .neutral)
        }
    }

    @Test func notificationAttachmentIsTheApprovedLogoAndNeverOnSecurityRequests() async throws {
        let api = try await BK.served()
        let store = BK.store(api: api, assets: api)
        _ = await store.refresh(BK.business)
        let attachment = try #require(store.notificationAttachment(business: BK.business, interactionId: nil, purpose: .transactional, kind: .confirm))
        #expect(attachment.slot == .logo)
        #expect(attachment.data == BK.logo)
        #expect(store.notificationAttachment(business: BK.business, interactionId: nil, purpose: .security, kind: .confirm) == nil)
        #expect(store.notificationAttachment(business: BK.business, interactionId: nil, purpose: .transactional, kind: .authenticate) == nil)
        #expect(store.notificationAttachment(business: BK.business, interactionId: nil, purpose: .transactional, kind: .authorize) == nil)
    }

    @Test func liveActivityAccentIsOnlyAKeptAccentToken() async throws {
        let good = try await BK.served()
        let store = BK.store(api: good, assets: good)
        _ = await store.refresh(BK.business)
        let accent = store.liveActivityAccent(business: BK.business, interactionId: nil, purpose: .transactional, kind: .status)
        #expect(accent.light == BK.good.accent)
        let denied = store.liveActivityAccent(business: BK.business, interactionId: nil, purpose: .security, kind: .authorize)
        #expect(denied.light == nil && denied.dark == nil)

        let hostile = try await BK.served(BK.manifest(tokens: BK.hostile))
        let hostileStore = BK.store(api: hostile, assets: hostile)
        _ = await hostileStore.refresh(BK.business)
        let clamped = hostileStore.liveActivityAccent(business: BK.business, interactionId: nil, purpose: .transactional, kind: .status)
        #expect(clamped.light == nil)
    }

    @Test @MainActor func hostileTokensCannotChangeTheApprovalSheet() async throws {
        let mockAPI = MockViadereAPI(seed: false)
        let services = await ViadereServices.mock(api: mockAPI)
        for envelope in [PreviewData.authorize(), PreviewData.authenticate()] {
            await mockAPI.add(envelope)
            let business = envelope.business.id
            let api = try await BK.served(BK.manifest(business: business, tokens: BK.hostile))
            let store = BK.store(api: api, assets: api)
            #expect(await store.refresh(business).isBranded)
            let model = ApprovalViewModel(envelope: envelope, services: services)
            let branded = ApprovalSheetSnapshot.make(model, brand: store)
            let neutral = ApprovalSheetSnapshot.make(model, brand: nil)
            #expect(branded == neutral)
            #expect(branded.style == .neutral)
            #expect(branded.businessName == envelope.business.safeName)
            #expect(branded.isVerified == envelope.business.isVerified)
        }
    }

    @Test func messageCardKeepsTheSenderIdentity() async throws {
        let api = try await BK.served(BK.manifest(tokens: BK.hostile))
        let store = BK.store(api: api, assets: api)
        _ = await store.refresh(BK.business)
        let decoration = MessageCardDecoration.make(business: PreviewData.northfield, brand: store)
        #expect(decoration.senderName == PreviewData.northfield.safeName)
        #expect(decoration.isVerified == PreviewData.northfield.isVerified)
        #expect(decoration.identityPalette == .neutral)
        // The hostile accent failed the clamp: no line at all rather than an invisible or look-alike one.
        #expect(decoration.accentLight == nil)

        let good = try await BK.served()
        let goodStore = BK.store(api: good, assets: good)
        _ = await goodStore.refresh(BK.business)
        #expect(MessageCardDecoration.make(business: PreviewData.northfield, brand: goodStore).accentLight == BK.good.accent)
    }

    @Test func businessHomeUsesTheVerifiedLogoAndNeutralIdentity() async throws {
        let api = try await BK.served()
        let store = BK.store(api: api, assets: api)
        _ = await store.refresh(BK.business)
        let home = BusinessHomeDecoration.make(business: PreviewData.northfield, brand: store)
        #expect(home.logo == BK.logo)
        #expect(home.logoSlot == .logo)
        #expect(home.name == PreviewData.northfield.safeName)
        #expect(home.logoAccessibilityLabel == "Logo of \(PreviewData.northfield.safeName)")
        #expect(home.style.source == .brandKit)
        #expect(home.style.protectedPalette == .neutral)
        #expect(BusinessHomeDecoration.make(business: PreviewData.harborBank, brand: store).style == .neutral)
    }

    @Test func walletPassAccentIsTheClampedPrimary() async throws {
        let api = try await BK.served()
        let store = BK.store(api: api, assets: api)
        _ = await store.refresh(BK.business)
        #expect(WalletPassBrandAccent.make(business: BK.business, brand: store).light == BK.good.primary)
        let hostile = try await BK.served(BK.manifest(tokens: BK.hostile))
        let hostileStore = BK.store(api: hostile, assets: hostile)
        _ = await hostileStore.refresh(BK.business)
        #expect(WalletPassBrandAccent.make(business: BK.business, brand: hostileStore).light == nil)
        #expect(WalletPassBrandAccent.make(business: nil, brand: store).light == nil)
    }
}

@Suite("Manifest key pins and conditional requests")
struct ManifestKeyPinTests {
    static let key = MockBrandKitAPI.signingKey.publicKey

    static func pinned(_ key: SoftwareP256SigningKey) -> PinnedManifestKey {
        PinnedManifestKey(kid: try! KeyIdentifier.make(p256X963: key.publicKey.x963), publicKey: key.publicKey)
    }

    @Test func parsesKidAndKeyPairsAllOrNothing() throws {
        let encoded = Base64URL.encode(Self.key.x963)
        let kid = try KeyIdentifier.make(p256X963: Self.key.x963)
        #expect(ManifestKeyPins.parse("\(kid):\(encoded)") == [PinnedManifestKey(kid: kid, publicKey: Self.key)])
        #expect(ManifestKeyPins.parse(encoded).first?.kid == kid)
        #expect(ManifestKeyPins.parse("wrong-kid:\(encoded)").isEmpty)
        #expect(ManifestKeyPins.parse("\(kid):\(encoded),garbage").isEmpty)
        #expect(ManifestKeyPins.parse("\(encoded),\(encoded)").isEmpty)
        #expect(ManifestKeyPins.parse("$(VIADERE_BRAND_MANIFEST_KEYS)").isEmpty)
        #expect(ManifestKeyPins.parse("").isEmpty)
        #expect(ManifestKeyPins.parse(nil).isEmpty)
        let two = ManifestKeyPins.parse("\(encoded), \(Base64URL.encode(BK.rogue.publicKey.x963))")
        #expect(two.count == 2)
    }

    @Test func configurationReadsBothPinSets() {
        let brand = Base64URL.encode(Self.key.x963)
        let loop = Base64URL.encode(BK.rogue.publicKey.x963)
        let config = ViadereConfiguration.resolve(info: ["ViadereBrandManifestKeys": brand, "ViadereLoopPublicationKeys": loop], allowLocalHTTP: false)
        #expect(config.brandManifestKeys.map(\.publicKey) == [Self.key])
        #expect(config.loopPublicationKeys == [Self.pinned(BK.rogue)])
        #expect(ViadereConfiguration.resolve(info: [:], allowLocalHTTP: false).brandManifestKeys.isEmpty)
    }

    @Test func servedLoopKeysCanOnlyNarrowThePins() {
        let pinned = [Self.pinned(MockBrandKitAPI.signingKey)]
        let foreign = LoopPublicationKeySet.Key(kid: "x", publicKey: Base64URL.encode(BK.rogue.publicKey.x963))
        let own = LoopPublicationKeySet.Key(kid: pinned[0].kid, publicKey: Base64URL.encode(MockBrandKitAPI.signingKey.publicKey.x963))
        #expect(ManifestKeyPins.effectiveLoopKeys(pinned: pinned, served: nil) == pinned)
        #expect(ManifestKeyPins.effectiveLoopKeys(pinned: pinned, served: LoopPublicationKeySet(keys: [foreign])).isEmpty)
        #expect(ManifestKeyPins.effectiveLoopKeys(pinned: pinned, served: LoopPublicationKeySet(keys: [own, foreign])) == pinned)
    }

    @Test func conditionalGetSendsIfNoneMatchAndMaps304() async throws {
        let env = try await ClientEnv()
        let transport = FakeTransport { request, index in
            index == 0 ? HTTPResponse(status: 200, headers: ["ETag": "\"abc\"", "content-type": "application/json"],
                                      body: Data(#"{"businessId":"\#(BK.business)","status":"neutral","pins":[]}"#.utf8))
                : HTTPResponse(status: 304)
        }
        let (client, _) = env.client(transport: transport)
        let api = LiveBrandKitAPI(client: client)
        let first = try await api.brandManifest(business: BK.business, ifNoneMatch: nil)
        #expect(first == .fetched(.neutral(BK.business), etag: "\"abc\""))
        #expect(transport.requests[0].headers["If-None-Match"] == nil)
        #expect(try await api.brandManifest(business: BK.business, ifNoneMatch: "\"abc\"") == .notModified)
        #expect(transport.requests[1].headers["If-None-Match"] == "\"abc\"")
        #expect(transport.requests[1].headers["Authorization"] == "Bearer tok-1")
        _ = try SignedRequestHeaders(headers: transport.requests[1].headers)
    }

    @Test func extraHeadersCannotReplaceAuthentication() async throws {
        let env = try await ClientEnv()
        let transport = FakeTransport { _, _ in json("[]") }
        let signer = DeviceRequestSigner(records: env.records, keys: env.keys)
        let executor = RequestExecutor(baseURL: URL(string: "http://localhost:8080")!, transport: transport, signer: signer)
        _ = try await executor.run(APIRoutes.devicesList.descriptor, pathAndQuery: "/v1/devices", body: nil, bearer: "tok-1",
                                   extraHeaders: ["Authorization": "Bearer evil", "If-None-Match": "\"x\"", "X-Other": "1"])
        let request = try #require(transport.requests.first)
        #expect(request.headers["Authorization"] == "Bearer tok-1")
        #expect(request.headers["If-None-Match"] == "\"x\"")
        #expect(request.headers["X-Other"] == nil)
    }
}
