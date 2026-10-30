import Crypto
import Foundation
import Testing
@testable import ViadereCore

/// WP-2.3 and WP-2.4 Core tests: token schema, contrast clamp, frames, manifest signing, selection, pinning, overlap, DST, asset policy.
@Suite("Brand Kits")
struct BrandKitTests {
    // MARK: Tokens

    @Test func tokensWithExtraKeysTextOrURLValuesAreRejected() {
        let good: JSONValue = .object(["primary": .string("#2F5D50"), "on_primary": .string("auto"), "radius": .string("large")])
        #expect(BrandTokens.parse(good).issues.isEmpty)
        #expect(BrandTokens.parse(good).tokens?.jsonValue == good)
        let hostile: [(String, JSONValue)] = [
            ("button_label", .string("Approve")), ("font", .string("Comic Sans")), ("logo_url", .string("https://x.example/l.png")),
            ("verified_badge", .string("#000000")), ("attribution", .string("hidden")), ("css", .string("display:none")),
        ]
        for (key, value) in hostile {
            guard case .object(var o) = good else { return }
            o[key] = value
            #expect(BrandTokens.parse(.object(o)).issues.contains { $0.code == ContractIssue.unknownMember }, "\(key)")
            #expect(BrandTokens.parse(.object(o)).tokens == nil)
        }
        for bad in ["red", "#fff", "#2F5D50; background:url(javascript:alert(1))", "rgba(0,0,0,0)", "url(https://x)", "#GGGGGG", "2F5D50", "#2F5D5000"] {
            #expect(BrandTokens.parse(.object(["primary": .string(bad)])).issues.contains { $0.code == "invalid_color" }, "\(bad)")
        }
        #expect(BrandTokens.parse(.object(["primary": .string("#2F5D50"), "on_primary": .string("#FFFFFF")])).issues.map(\.code) == [ContractIssue.invalidValue])
        #expect(BrandTokens.parse(.object(["primary": .string("#2F5D50"), "radius": .string("pill")])).issues.map(\.code) == [ContractIssue.invalidValue])
        #expect(BrandTokens.parse(.object(["secondary": .string("#2F5D50")])).issues.map(\.code) == [ContractIssue.missingMember])
        #expect(BrandTokens.parse(.object(["primary": .integer(0x2F5D50)])).issues.contains { $0.code == "invalid_color" || $0.code == ContractIssue.wrongType })
    }

    // MARK: Contrast

    @Test func contrastMathMatchesWCAG() {
        let black = BrandColor("#000000")!, white = BrandColor("#FFFFFF")!
        #expect(ContrastPolicy.luminance(black) == 0)
        #expect(ContrastPolicy.luminance(white) == 100_000_000_000)
        #expect(ContrastPolicy.ratioTimes100(black, white) == 2100)
        #expect(ContrastPolicy.ratioTimes100(white, black) == 2100)
        // #777777 on white is the classic 4.48:1 that fails AA; #767676 passes at 4.54:1.
        #expect(!ContrastPolicy.meets(BrandColor("#777777")!, white, minimumTimes10: 45))
        #expect(ContrastPolicy.meets(BrandColor("#767676")!, white, minimumTimes10: 45))
        #expect(ContrastPolicy.ratioTimes100(BrandColor("#767676")!, white) == 454)
        #expect(ContrastPolicy.bestForeground(on: BrandColor("#1D3557")!) == NeutralPalette.ivory)
        #expect(ContrastPolicy.bestForeground(on: BrandColor("#F7E9A0")!) == NeutralPalette.charcoal)
        // The neutral palette itself satisfies its own rules.
        #expect(ContrastPolicy.resolve(BrandTokens(primary: NeutralPalette.charcoal)).overriddenLight.isEmpty)
    }

    @Test func lowContrastTokensAreReplacedByNeutralOnes() {
        let pale = BrandTokens(primary: BrandColor("#FFF5D6")!, secondary: BrandColor("#D9D9D9")!, accent: BrandColor("#FDFDFD")!, surface: BrandColor("#808080")!)
        let r = ContrastPolicy.resolve(pale)
        #expect(r.overriddenLight == [.primary, .secondary, .accent, .surface])
        #expect(r.light == NeutralPalette.palette(.light))
        let good = ContrastPolicy.resolve(FX.springTokens)
        #expect(good.overriddenLight.isEmpty)
        #expect(good.light.primary == FX.springTokens.primary)
        #expect(good.light.onPrimary == NeutralPalette.ivory)
        #expect(good.light.surface == FX.springTokens.surface)
        // Dark mode keeps Viadere's dark surface; a dark brand primary that is invisible on it is replaced there only.
        #expect(good.dark.surface == NeutralPalette.palette(.dark).surface)
        #expect(good.overriddenDark.contains(.primary))
        #expect(good.dark.primary == NeutralPalette.palette(.dark).primary)
        // Every resolved palette meets the minimums.
        for resolution in [r, good, ContrastPolicy.resolve(nil)] {
            for p in [resolution.light, resolution.dark] {
                #expect(ContrastPolicy.meets(p.onPrimary, p.primary, minimumTimes10: 45))
                #expect(ContrastPolicy.meets(p.onSurface, p.surface, minimumTimes10: 45))
                #expect(ContrastPolicy.meets(p.secondary, p.surface, minimumTimes10: 45))
                #expect(ContrastPolicy.meets(p.accent, p.surface, minimumTimes10: 30))
            }
        }
    }

    // MARK: Frames

    @Test func framesAreViadereOwnedAndSeasonal() {
        let registry = FrameRegistry.v1
        #expect(registry.resolve("viadere.frame.hairline.v1", at: FX.now) == "viadere.frame.hairline.v1")
        #expect(registry.resolve("viadere.frame.snow.v1", at: FX.now) == nil)
        #expect(registry.resolve("viadere.frame.snow.v1", at: Date(timeIntervalSince1970: 1_796_083_200)) == "viadere.frame.snow.v1")
        #expect(registry.resolve("viadere.frame.snow.v1", at: Date(timeIntervalSince1970: 1_803_859_200)) == nil)
        #expect(registry.resolve("acme.frame.custom", at: FX.now) == nil)
        #expect(registry.resolve(nil, at: FX.now) == nil)
    }

    // MARK: Manifest

    @Test func manifestValidatesSignsAndVerifies() async throws {
        let manifest = FX.brandManifest()
        #expect(manifest.validationIssues().isEmpty, "\(manifest.validationIssues())")
        let parsed = BrandManifest.parse(manifest.jsonValue)
        #expect(parsed.issues.isEmpty)
        #expect(parsed.manifest == manifest)
        #expect(try manifest.manifestHash().hasPrefix("sha256:"))
        let jws = try await manifest.sign(with: FX.brandKey)
        #expect(try BrandManifest.verify(jws, expectedBusiness: FX.business, keys: FX.brandPinned, now: FX.now) == manifest)
    }

    @Test func tamperedOrMisdirectedManifestsFailDeviceVerification() async throws {
        let manifest = FX.brandManifest()
        let jws = try await manifest.sign(with: FX.brandKey)
        // Served for another business (A's manifest to a user looking at B).
        #expect(throws: ManifestVerificationError.headerPayloadMismatch) {
            try BrandManifest.verify(jws, expectedBusiness: FX.otherBusiness, keys: FX.brandPinned, now: FX.now)
        }
        // Signed by a key that is not pinned, or a publication-manifest key (domain separation by typ and key set).
        let rogue = try await manifest.sign(with: FX.key("rogue"))
        #expect(throws: ManifestVerificationError.badSignature) { try BrandManifest.verify(rogue, expectedBusiness: FX.business, keys: FX.brandPinned, now: FX.now) }
        #expect(throws: ManifestVerificationError.unknownKey) { try BrandManifest.verify(jws, expectedBusiness: FX.business, keys: FX.pinned, now: FX.now) }
        // A publication manifest never verifies as a brand manifest.
        let publication = try await FX.manifest(for: FX.pickup, key: FX.brandKey, kid: FX.brandKid)
        #expect(throws: ManifestVerificationError.wrongType) { try BrandManifest.verify(publication, expectedBusiness: FX.business, keys: FX.brandPinned, now: FX.now) }
        // Payload swapped: different tokens under the original signature.
        let parts = jws.split(separator: ".").map(String.init)
        let payload = String(decoding: Base64URL.decode(parts[1])!, as: UTF8.self).replacingOccurrences(of: "#8C2F39", with: "#FFFFFF")
        #expect(throws: ManifestVerificationError.badSignature) {
            try BrandManifest.verify(parts[0] + "." + Base64URL.encode(Data(payload.utf8)) + "." + parts[2], expectedBusiness: FX.business, keys: FX.brandPinned, now: FX.now)
        }
        // Stale (stale cache D3.T7): expired manifests are refused, so the device renders neutral.
        #expect(throws: ManifestVerificationError.expired) {
            try BrandManifest.verify(jws, expectedBusiness: FX.business, keys: FX.brandPinned, now: FX.now.addingTimeInterval(31 * 86400))
        }
        #expect(throws: ManifestVerificationError.missing) { try BrandManifest.verify(nil, expectedBusiness: FX.business, keys: FX.brandPinned, now: FX.now) }
        // A manifest with unknown members does not verify even if signed.
        guard case .object(var o) = manifest.jsonValue else { return }
        o["script"] = .string("alert(1)")
        let smuggled = try await ManifestJWS.sign(payload: o, type: BrandManifest.jwsType, kid: FX.brandKid, with: FX.brandKey)
        #expect(throws: ManifestVerificationError.malformed("schema")) { try BrandManifest.verify(smuggled, expectedBusiness: FX.business, keys: FX.brandPinned, now: FX.now) }
    }

    @Test func manifestPublishRules() {
        var m = FX.brandManifest()
        m.kits[0].frameId = "acme.frame.custom"
        m.kits[1].name = "Built by Viadere"
        m.kits[2].assets[.logo] = BrandAssetRef(sha256: String(repeating: "cd", count: 32), width: 4000, height: 4000, bytes: 10)
        m.schedule.defaultKit = "missing"
        m.schedule.randomPool = [BrandPoolEntry(kit: "spring", weight: 0)]
        let codes = Set(m.validationIssues().map(\.code))
        #expect(codes.isSuperset(of: ["unknown_frame", "invalid_text", "invalid_asset", "unknown_kit", ContractIssue.invalidValue]))
        var tz = FX.brandManifest(timezone: "Mars/Olympus_Mons")
        #expect(tz.validationIssues().map(\.code) == [ContractIssue.invalidValue])
        tz.notAfter = tz.issuedAt + 400 * 86400
        tz.schedule.timezone = "UTC"
        #expect(tz.validationIssues().map(\.code) == ["invalid_lifetime"])
    }

    // MARK: Schedule, overlap, selection

    func w(_ kit: String, _ start: String, _ end: String?, _ priority: Int) -> BrandScheduleWindow {
        BrandScheduleWindow(kit: kit, startsAt: LocalDateTime(start)!, endsAt: end.map { LocalDateTime($0)! }, priority: priority)
    }

    @Test func overlappingEqualPriorityWindowsAreRejectedAtPublish() {
        let overlapping = FX.brandManifest(windows: [w("spring", "2026-11-01T00:00", "2026-11-30T00:00", 10), w("winter", "2026-11-20T00:00", "2026-12-31T00:00", 10)])
        #expect(overlapping.validationIssues().map(\.code) == ["ambiguous_overlap"])
        // Open-ended windows overlap everything after their start.
        let open = FX.brandManifest(windows: [w("spring", "2026-11-01T00:00", nil, 5), w("winter", "2027-01-01T00:00", "2027-02-01T00:00", 5)])
        #expect(open.validationIssues().map(\.code) == ["ambiguous_overlap"])
        // Different priorities may overlap; touching windows ([a, b) and [b, c)) do not overlap.
        #expect(FX.brandManifest(windows: [w("spring", "2026-11-01T00:00", "2026-11-30T00:00", 10), w("winter", "2026-11-20T00:00", "2026-12-31T00:00", 20)]).validationIssues().isEmpty)
        #expect(FX.brandManifest(windows: [w("spring", "2026-11-01T00:00", "2026-11-20T00:00", 10), w("winter", "2026-11-20T00:00", "2026-12-31T00:00", 10)]).validationIssues().isEmpty)
        #expect(FX.brandManifest(windows: [w("spring", "2026-11-20T00:00", "2026-11-20T00:00", 1)]).validationIssues().map(\.code) == ["empty_window"])
    }

    @Test func selectionOrder() {
        let m = FX.brandManifest(windows: [w("spring", "2026-11-01T00:00", "2026-11-30T00:00", 10), w("winter", "2026-11-10T00:00", "2026-11-20T00:00", 20)])
        #expect(BrandKitSelector.select(manifest: m, now: FX.now) == BrandKitSelection(kitId: "winter", reason: .window))
        #expect(BrandKitSelector.select(manifest: m, now: FX.now.addingTimeInterval(6 * 86400)) == BrandKitSelection(kitId: "spring", reason: .window))
        #expect(BrandKitSelector.select(manifest: m, now: FX.now.addingTimeInterval(20 * 86400)) == BrandKitSelection(kitId: "everyday", reason: .defaultKit))
        #expect(BrandKitSelector.select(manifest: FX.brandManifest(defaultKit: nil), now: FX.now) == .neutral)
        #expect(BrandKitSelector.select(manifest: nil, now: FX.now) == .neutral)
        // Expired manifest → neutral.
        #expect(BrandKitSelector.select(manifest: m, now: FX.now.addingTimeInterval(30 * 86400)) == .neutral)
        // Equal-priority active windows (only possible in an unvalidated manifest) never pick an arbitrary brand.
        let ambiguous = FX.brandManifest(windows: [w("spring", "2026-11-01T00:00", nil, 10), w("winter", "2026-11-01T00:00", nil, 10)])
        #expect(BrandKitSelector.select(manifest: ambiguous, now: FX.now) == BrandKitSelection(kitId: "everyday", reason: .defaultKit))
    }

    @Test func pinnedInteractionKeepsItsKitWhenTheWindowChanges() {
        let m = FX.brandManifest(windows: [w("winter", "2026-11-10T00:00", "2026-11-20T00:00", 20)])
        let atStart = BrandKitSelector.select(manifest: m, now: FX.now)
        #expect(atStart.kitId == "winter")
        // The window ends mid-flow; the pinned instance keeps "winter".
        let later = FX.now.addingTimeInterval(10 * 86400)
        #expect(BrandKitSelector.select(manifest: m, now: later).kitId == "everyday")
        #expect(BrandKitSelector.select(manifest: m, now: later, pinnedKit: "winter") == BrandKitSelection(kitId: "winter", reason: .pinned))
        // A pinned kit that was deleted renders neutral (never a different brand mid-flow).
        #expect(BrandKitSelector.select(manifest: m, now: later, pinnedKit: "deleted") == .neutral)
    }

    @Test func randomPoolIsStablePerDayAndNotLinkableAcrossBusinesses() {
        let pool = [BrandPoolEntry(kit: "spring", weight: 1), BrandPoolEntry(kit: "winter", weight: 1), BrandPoolEntry(kit: "everyday", weight: 1)]
        let m = FX.brandManifest(pool: pool)
        let key = SymmetricKey(data: Data(repeating: 7, count: 32))
        let seed = BrandSelectionSeed.derive(key: key, consumer: FX.consumer, business: FX.business)
        let morning = BrandKitSelector.select(manifest: m, now: FX.now, selectionSeed: seed)
        #expect(morning.reason == .randomPool)
        // Same local day, other device (same seed from the server) → same kit.
        #expect(BrandKitSelector.select(manifest: m, now: FX.now.addingTimeInterval(3 * 3600), selectionSeed: seed) == morning)
        // Seeds differ per business and per consumer, and do not reveal the consumer.
        let otherBusiness = BrandSelectionSeed.derive(key: key, consumer: FX.consumer, business: FX.otherBusiness)
        let otherConsumer = BrandSelectionSeed.derive(key: key, consumer: ConsumerID(), business: FX.business)
        #expect(seed != otherBusiness && seed != otherConsumer)
        #expect(!seed.contains(Data(FX.consumer.description.utf8)))
        // Over many days every pool kit is chosen (the pick varies by day).
        var chosen = Set<String>()
        for day in 0..<29 { chosen.insert(BrandKitSelector.select(manifest: m, now: FX.now.addingTimeInterval(Double(day) * 86400), selectionSeed: seed).kitId ?? "") }
        #expect(chosen == ["spring", "winter", "everyday"])
        // Without a seed the pool is skipped (default).
        #expect(BrandKitSelector.select(manifest: m, now: FX.now).reason == .defaultKit)
    }

    // MARK: Time zones and DST (fixed IANA fixtures)

    @Test func localTimesResolveDeterministicallyAcrossDST() throws {
        let ny = try #require(TimeZone(identifier: "America/New_York"))
        // Ordinary time: 2026-11-15 07:00 EST = 12:00Z.
        #expect(LocalDateTime("2026-11-15T07:00")!.instant(in: ny) == 1_794_744_000)
        // Spring forward 2026-03-08: 02:30 does not exist → shifted forward by the gap to 03:30 EDT = 07:30Z.
        #expect(LocalDateTime("2026-03-08T02:30")!.instant(in: ny) == 1_772_955_000)
        #expect(LocalDateTime("2026-03-08T03:30")!.instant(in: ny) == 1_772_955_000)
        // Fall back 2026-11-01: 01:30 happens twice → the earlier instant (EDT, 05:30Z).
        #expect(LocalDateTime("2026-11-01T01:30")!.instant(in: ny) == 1_793_511_000)
        // Phoenix has no DST.
        let phx = try #require(TimeZone(identifier: "America/Phoenix"))
        #expect(LocalDateTime("2026-07-01T12:00")!.instant(in: phx) == 1_782_932_400)
        // Berlin spring forward 2026-03-29 02:30 → 03:30 CEST = 01:30Z.
        let berlin = try #require(TimeZone(identifier: "Europe/Berlin"))
        #expect(LocalDateTime("2026-03-29T02:30")!.instant(in: berlin) == 1_774_747_800)
        #expect(LocalDateTime.localDay(of: Date(timeIntervalSince1970: 1_794_744_000), in: ny) == "2026-11-15")
        #expect(LocalDateTime.localDay(of: Date(timeIntervalSince1970: 1_794_718_799), in: ny) == "2026-11-14")
        for bad in ["2026-02-30T10:00", "2026-11-15T24:00", "2026-11-15 10:00", "2026-11-15T10:00:00", "2026-11-15T10:00Z", ""] {
            #expect(LocalDateTime(bad) == nil, "\(bad)")
        }
    }

    @Test func windowAcrossTheFallBackHourEndsOnce() {
        // A window ending at 01:30 on fall-back day ends at the first 01:30 (earlier instant), never an hour late.
        let m = FX.brandManifest(windows: [w("winter", "2026-10-31T00:00", "2026-11-01T01:30", 10)])
        #expect(BrandKitSelector.select(manifest: m, now: Date(timeIntervalSince1970: 1_793_510_999)).kitId == "winter")
        #expect(BrandKitSelector.select(manifest: m, now: Date(timeIntervalSince1970: 1_793_511_000)).kitId == "everyday")
    }

    // MARK: Asset policy (ADR-0017, D3.T5 at policy level)

    @Test func onlyPNGAndJPEGAreAcceptedAndSVGIsRefused() {
        let png = Data([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A, 0, 0, 0, 13])
        let jpeg = Data([0xFF, 0xD8, 0xFF, 0xE0, 0, 16])
        #expect(BrandAssetPolicy.precheck(declaredContentType: "image/png", byteCount: 1000, prefix: png) == .success(.png))
        #expect(BrandAssetPolicy.precheck(declaredContentType: "image/jpeg; charset=binary", byteCount: 1000, prefix: jpeg) == .success(.jpeg))
        let cases: [(String, Data, BrandAssetPolicy.Rejection)] = [
            ("image/svg+xml", Data("<svg xmlns='http://www.w3.org/2000/svg'><script>alert(1)</script></svg>".utf8), .svgRefused),
            ("image/png", Data("\u{FEFF}  <?xml version='1.0'?><svg>".utf8), .svgRefused),
            ("image/png", Data("<!DOCTYPE html><html><script>".utf8), .markupRefused),
            ("image/png", Data("<html><body>".utf8), .markupRefused),
            ("image/jpeg", png, .contentTypeMismatch),
            ("image/png", jpeg, .contentTypeMismatch),
            ("text/html", png, .contentTypeMismatch),
            ("image/gif", Data("GIF89a".utf8), .unsupportedFormat),
            ("image/webp", Data("RIFF\u{0}\u{0}\u{0}\u{0}WEBPVP8 ".utf8), .unsupportedFormat),
            ("application/pdf", Data("%PDF-1.7".utf8), .unsupportedFormat),
            ("image/svg+xml", Data([1, 2, 3]), .svgRefused),
            ("image/png", Data([1, 2, 3]), .unsupportedFormat),
        ]
        for (type, prefix, rejection) in cases {
            #expect(BrandAssetPolicy.precheck(declaredContentType: type, byteCount: 1000, prefix: prefix) == .failure(rejection), "\(type)")
        }
        #expect(BrandAssetPolicy.precheck(declaredContentType: "image/png", byteCount: BrandAssetPolicy.maxUploadBytes + 1, prefix: png) == .failure(.tooLarge))
        #expect(BrandAssetPolicy.precheck(declaredContentType: "image/png", byteCount: 0, prefix: Data()) == .failure(.empty))
    }

    @Test func dimensionGuardRunsBeforeAllocation() {
        #expect(BrandAssetPolicy.checkSourceDimensions(width: 4000, height: 4000) == nil)
        #expect(BrandAssetPolicy.checkSourceDimensions(width: 8192, height: 8192) == .dimensionsTooLarge)
        #expect(BrandAssetPolicy.checkSourceDimensions(width: 100_000, height: 1) == .dimensionsTooLarge)
        #expect(BrandAssetPolicy.checkSourceDimensions(width: Int.max, height: Int.max) == .dimensionsTooLarge)
        #expect(BrandAssetPolicy.checkSourceDimensions(width: 0, height: 10) == .dimensionsInvalid)
        #expect(BrandAssetPolicy.targetSize(width: 2000, height: 1000, slot: .logo) == (512, 256))
        #expect(BrandAssetPolicy.targetSize(width: 300, height: 200, slot: .logo) == (300, 200))
    }

    @Test func assetReferencesAreContentAddressedOnTheAssetDomain() {
        let ref = BrandAssetRef(sha256: String(repeating: "ab", count: 32), width: 512, height: 512, bytes: 18432)
        #expect(ref.url(assetHost: "assets.viadere.example")?.absoluteString == "https://assets.viadere.example/b/\(ref.sha256).png")
        #expect(ref.url(assetHost: "assets.viadere.example/evil") == nil)
        #expect(ref.url(assetHost: "user@assets.viadere.example") == nil)
        #expect(BrandAssetRef(sha256: "../../etc/passwd", width: 1, height: 1, bytes: 1).url(assetHost: "assets.viadere.example") == nil)
        #expect(ref.fits(.logo) && !ref.fits(.mark))
    }
}
