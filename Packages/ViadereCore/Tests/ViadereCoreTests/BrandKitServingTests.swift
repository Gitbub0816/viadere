import Foundation
import Testing
@testable import ViadereCore

/// Phase 2 serving contract (WP-2.3, WP-2.4, WP-2.7): the consumer route and DTO, the stored schedule form, and the surface policy that keeps
/// business art off security requests.
@Suite("Brand Kits serving and surfaces")
struct BrandKitServingTests {
    // MARK: Route and DTO

    @Test func brandRouteIsDeviceSignedAndInTheCatalog() throws {
        #expect(APIRoutes.businessBrandGet.template == "/v1/businesses/{businessId}/brand")
        #expect(APIRoutes.businessBrandGet.method == .GET)
        #expect(APIRoutes.businessBrandGet.auth == .deviceSignedBearer)
        #expect(APIRoutes.all.contains(APIRoutes.businessBrandGet.descriptor))
        #expect(try APIRoutes.businessBrandGet.path(["businessId": FX.business.description]) == "/v1/businesses/\(FX.business.description)/brand")
    }

    @Test func responseRoundTripsAndNeutralCarriesNothing() throws {
        let seed = Base64URL.encode(Data(repeating: 7, count: 32))
        let full = BrandManifestResponse(businessId: FX.business, status: .branded, manifest: "a.b.c", manifestHash: "sha256:" + String(repeating: "0", count: 64),
                                         selectionSeed: seed, pins: [BrandKitPin(interactionId: UUID().uuidString.lowercased(), kitId: "spring")], assetHost: "assets.viadere.example")
        let data = try JSONEncoder().encode(full)
        #expect(try JSONDecoder().decode(BrandManifestResponse.self, from: data) == full)
        let text = String(decoding: data, as: UTF8.self)
        for key in ["businessId", "status", "manifest", "manifestHash", "selectionSeed", "pins", "assetHost", "interactionId", "kitId"] { #expect(text.contains("\"\(key)\"")) }
        #expect(full.selectionSeedData?.count == 32)
        let neutral = BrandManifestResponse.neutral(FX.business)
        #expect(neutral.status == .neutral && neutral.manifest == nil && neutral.pins.isEmpty && neutral.selectionSeed == nil)
        // A malformed seed is ignored rather than trusted.
        var bad = full
        bad.selectionSeed = Base64URL.encode(Data(repeating: 1, count: 8))
        #expect(bad.selectionSeedData == nil)
    }

    // MARK: Schedule storage form

    @Test func scheduleRoundTripsAndRefusesUnknownMembers() throws {
        let start = LocalDateTime("2026-12-01T00:00")!, end = LocalDateTime("2027-01-01T00:00")!
        let schedule = BrandSchedule(timezone: "America/Phoenix", defaultKit: "everyday",
                                     windows: [BrandScheduleWindow(kit: "winter", startsAt: start, endsAt: end, priority: 10)],
                                     randomPool: [BrandPoolEntry(kit: "spring", weight: 3)])
        let parsed = BrandSchedule.parse(schedule.jsonValue)
        #expect(parsed.issues.isEmpty)
        #expect(parsed.schedule == schedule)
        guard case .object(var o) = schedule.jsonValue else { Issue.record("not an object"); return }
        o["css"] = .string("body{display:none}")
        #expect(BrandSchedule.parse(.object(o)).issues.map(\.code) == [ContractIssue.unknownMember])
        #expect(BrandSchedule.parse(.object(o)).schedule == nil)
        // A manifest still serializes the same canonical schedule member after the refactor.
        let manifest = FX.brandManifest(windows: schedule.windows, defaultKit: "everyday")
        guard case .object(let m) = manifest.jsonValue else { Issue.record("not an object"); return }
        #expect(m["schedule"] == manifest.schedule.jsonValue)
        #expect(BrandManifest.parse(manifest.jsonValue).issues.isEmpty)
    }

    @Test func scheduleValidationRefusesOverlapUnknownKitsAndBadZones() {
        let a = BrandScheduleWindow(kit: "spring", startsAt: LocalDateTime("2027-03-01T00:00")!, endsAt: LocalDateTime("2027-04-01T00:00")!, priority: 5)
        let b = BrandScheduleWindow(kit: "winter", startsAt: LocalDateTime("2027-03-15T00:00")!, endsAt: nil, priority: 5)
        let kits: Set<String> = ["spring", "winter", "everyday"]
        #expect(BrandSchedule(timezone: "Europe/Zurich", windows: [a, b]).validationIssues(kitIds: kits).map(\.code) == ["ambiguous_overlap"])
        var c = b
        c.priority = 6
        #expect(BrandSchedule(timezone: "Europe/Zurich", windows: [a, c]).validationIssues(kitIds: kits).isEmpty)
        #expect(BrandSchedule(timezone: "Europe/Zurich", defaultKit: "gone", windows: [a]).validationIssues(kitIds: kits).map(\.code) == ["unknown_kit"])
        #expect(BrandSchedule(timezone: "Mars/Olympus", windows: [a]).validationIssues(kitIds: kits).map(\.code) == [ContractIssue.invalidValue])
        // Fall-back day in New York: 01:30 happens twice; a window 01:30..01:59 local is not empty (earlier instant rule).
        let dst = BrandScheduleWindow(kit: "spring", startsAt: LocalDateTime("2026-11-01T01:30")!, endsAt: LocalDateTime("2026-11-01T01:59")!, priority: 1)
        #expect(BrandSchedule(timezone: "America/New_York", windows: [dst]).validationIssues(kitIds: kits).isEmpty)
    }

    @Test func kitValidationMatchesTheManifestRules() {
        let ok = BrandKit(kitId: "spring", name: "Spring", tokens: FX.springTokens, frameId: "viadere.frame.hairline.v1")
        #expect(ok.validationIssues().isEmpty)
        #expect(BrandKit(kitId: "Spring!", name: "Spring", tokens: FX.springTokens).validationIssues().map(\.code) == ["invalid_identifier"])
        #expect(BrandKit(kitId: "s", name: "Verified by Viadere", tokens: FX.springTokens).validationIssues().map(\.code) == ["invalid_text"])
        #expect(BrandKit(kitId: "s", name: "Spring", tokens: FX.springTokens, frameId: "evil.frame").validationIssues().map(\.code) == ["unknown_frame"])
        let huge = BrandAssetRef(sha256: String(repeating: "ab", count: 32), width: 4096, height: 4096, bytes: 10)
        #expect(BrandKit(kitId: "s", name: "Spring", tokens: FX.springTokens, assets: [.logo: huge]).validationIssues().map(\.code) == ["invalid_asset"])
        // The snow frame is registered; it is unavailable after its window closes.
        let snow = BrandKit(kitId: "s", name: "Winter", tokens: FX.springTokens, frameId: "viadere.frame.snow.v1")
        #expect(snow.validationIssues(frameAt: Date(timeIntervalSince1970: 1_810_000_000)).map(\.code) == ["frame_unavailable"])
    }

    // MARK: Surfaces (WP-2.7)

    static let logo = BrandAssetRef(sha256: String(repeating: "cd", count: 32), width: 512, height: 512, bytes: 20_000)
    static let art = BrandAssetRef(sha256: String(repeating: "ef", count: 32), width: 1600, height: 900, bytes: 400_000)

    @Test func securityRequestsNeverCarryBusinessArtOrAccent() {
        let kit = BrandKit(kitId: "spring", name: "Spring", tokens: FX.springTokens, assets: [.logo: Self.logo, .art: Self.art, .background: Self.art])
        for purpose in InteractionPurpose.allCases {
            for kind in InteractionKind.known + [.unknown("future_kind")] {
                let allowed = BrandSurfacePolicy.allowsBranding(purpose: purpose, kind: kind)
                let expected = purpose != .security && purpose != .accountService && kind != .authenticate && kind != .authorize && InteractionKind.known.contains(kind)
                #expect(allowed == expected, "\(purpose) \(kind)")
                let attachment = BrandSurfacePolicy.notificationAttachment(kit: kit, purpose: purpose, kind: kind)
                #expect((attachment != nil) == expected)
                // Only the approved logo is ever attached, never background or art.
                if let attachment { #expect(attachment.slot == .logo && attachment.asset == Self.logo) }
                #expect((BrandSurfacePolicy.liveActivityAccent(kit: kit, purpose: purpose, kind: kind, appearance: .light) != nil) == expected)
            }
        }
    }

    @Test func attachmentFallsBackToMarkAndRefusesArtOnly() {
        let mark = BrandAssetRef(sha256: String(repeating: "12", count: 32), width: 256, height: 256, bytes: 9000)
        let markOnly = BrandKit(kitId: "k", name: "K", tokens: FX.springTokens, assets: [.mark: mark, .art: Self.art])
        #expect(BrandSurfacePolicy.notificationAttachment(kit: markOnly, purpose: .marketing, kind: .message)?.slot == .mark)
        let artOnly = BrandKit(kitId: "k", name: "K", tokens: FX.springTokens, assets: [.art: Self.art, .background: Self.art])
        #expect(BrandSurfacePolicy.notificationAttachment(kit: artOnly, purpose: .marketing, kind: .message) == nil)
        // A logo reference that does not fit its slot (a hostile manifest) is never attached.
        let oversized = BrandKit(kitId: "k", name: "K", tokens: FX.springTokens, assets: [.logo: Self.art])
        #expect(BrandSurfacePolicy.notificationAttachment(kit: oversized, purpose: .marketing, kind: .message) == nil)
        #expect(BrandSurfacePolicy.notificationAttachment(kit: nil, purpose: .marketing, kind: .message) == nil)
    }

    @Test func liveActivityAccentIsOnlyTheClampedAccentToken() {
        let kit = BrandKit(kitId: "k", name: "K", tokens: FX.springTokens)
        #expect(BrandSurfacePolicy.liveActivityAccent(kit: kit, purpose: .transactional, kind: .status, appearance: .light) == FX.springTokens.accent)
        // An accent that fails contrast against the surface is dropped (Viadere's accent is used).
        let pale = BrandKit(kitId: "k", name: "K", tokens: BrandTokens(primary: BrandColor("#2F5D50")!, accent: BrandColor("#FDFDFD")!))
        #expect(BrandSurfacePolicy.liveActivityAccent(kit: pale, purpose: .transactional, kind: .status, appearance: .light) == nil)
        // No accent token: nothing to apply (the primary color is never used as an activity accent).
        let primaryOnly = BrandKit(kitId: "k", name: "K", tokens: BrandTokens(primary: BrandColor("#2F5D50")!))
        #expect(BrandSurfacePolicy.liveActivityAccent(kit: primaryOnly, purpose: .transactional, kind: .status, appearance: .light) == nil)
    }
}
