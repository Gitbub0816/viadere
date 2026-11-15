@preconcurrency import Crypto
import Fluent
import Foundation
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Business code styles (docs/SECURITY.md §2.105) and stored campaigns (§2.106).
final class CodeStyleCampaignTests: XCTestCase {
    // MARK: Helpers

    /// These tests make many requests from one test address; the limits themselves are covered elsewhere.
    static func relaxed(_ config: inout ServerConfig) {
        config.rateLimits.authCeremony = .perMinute(10_000, burst: 10_000)
        config.rateLimits.globalIP = .perMinute(100_000, burst: 100_000)
        config.rateLimits.dashboardAuth = .perMinute(10_000, burst: 10_000)
        config.rateLimits.directory = .perMinute(10_000, burst: 10_000)
        config.rateLimits.dashboardAction = .perMinute(10_000, burst: 10_000)
    }

    private func businessCode(_ h: TestHarness, _ businessId: UUID) async throws -> BusinessCode {
        let record = try await XCTUnwrapAsync(await BusinessCodeRecord.query(on: h.db).filter(\.$businessId == businessId).first())
        return try XCTUnwrap(BusinessCode(parsing: record.canonical))
    }

    /// The `<svg>…</svg>` inside the element marked `data-code="<which>"`.
    private func svg(in html: String, code which: String) throws -> String {
        let marker = try XCTUnwrap(html.range(of: "data-code=\"\(which)\""), "no \(which) code on the page")
        let start = try XCTUnwrap(html.range(of: "<svg", range: marker.upperBound..<html.endIndex))
        let end = try XCTUnwrap(html.range(of: "</svg>", range: start.lowerBound..<html.endIndex))
        return String(html[start.lowerBound..<end.upperBound])
    }

    private func signedLink(_ html: String) throws -> String {
        let regex = try NSRegularExpression(pattern: "https://viadere\\.com/c/[0-9A-Z]{6}\\?ctx=[A-Za-z0-9_-]+&amp;sig=[A-Za-z0-9_-]{43}")
        let range = try XCTUnwrap(regex.firstMatch(in: html, range: NSRange(html.startIndex..., in: html))?.range)
        return String(html[Range(range, in: html)!]).replacingOccurrences(of: "&amp;", with: "&")
    }

    private func createCampaign(_ h: TestHarness, _ owner: DashSession, _ id: String, name: String? = nil, action: String? = nil, days: Int = 30) async throws -> (link: String, record: CampaignRecord) {
        var form = [("campaign", id), ("days", String(days))]
        if let name { form.append(("name", name)) }
        if let action { form.append(("action", action)) }
        let result = try await h.formPost("/dashboard/campaigns", owner, form)
        XCTAssertEqual(result.status, .ok, result.text)
        let record = try await XCTUnwrapAsync(await CampaignRecord.query(on: h.db).filter(\.$publicId == id).first())
        return (try signedLink(result.text), record)
    }

    private func customForm(background: String, ink: String, extra: [(String, String)] = []) -> [(String, String)] {
        [("look", "custom"), ("background", background), ("ink", ink), ("modules", "rounded"), ("rings", "joined"), ("rays", "round")] + extra
    }

    // MARK: G1: styles

    func testTheDefaultIsTheViadereCodeWithAPlainQRCodeBesideIt() async throws {
        try await withHarness(Self.relaxed) { h in
            let (owner, _, _) = try await h.verifiedOwner()
            let result = try await h.formPost("/dashboard/campaigns", owner, [("campaign", "spring"), ("days", "30")])
            XCTAssertEqual(result.status, .ok, result.text)
            let link = try signedLink(result.text)
            XCTAssertTrue(result.text.contains("data-code=\"primary\" data-symbology=\"ckey\""))
            let primary = try svg(in: result.text, code: "primary")
            XCTAssertEqual(primary, try CKeySymbol.encode(link, level: .medium).svg(style: .concept, label: "Viadere code for your Viadere connect link"))
            let qr = try svg(in: result.text, code: "qr")
            let expected = try QRCode.encode(link, errorCorrection: .medium)
            XCTAssertEqual(DashboardPagesTests.modules(fromSVG: qr, size: expected.size, border: 4), expected.modules)
            // Both download as SVG attachments, under a CSP that runs nothing.
            for (which, start) in [("primary", "<svg"), ("qr", "<svg")] {
                let download = try await h.formPost("/dashboard/campaigns/download", owner, [("campaign", "spring"), ("code", which)])
                XCTAssertEqual(download.status, .ok, which)
                XCTAssertEqual(download.headers.first(name: .contentType), "image/svg+xml")
                XCTAssertTrue(download.headers.first(name: .contentDisposition)?.hasPrefix("attachment") == true)
                XCTAssertTrue(download.headers.first(name: "Content-Security-Policy")?.contains("sandbox") == true)
                XCTAssertTrue(download.text.hasPrefix(start))
                XCTAssertFalse(download.text.contains("<script"))
            }
            let plainDownload = try await h.formPost("/dashboard/campaigns/download", owner, [("campaign", "spring"), ("code", "qr")])
            XCTAssertEqual(DashboardPagesTests.modules(fromSVG: plainDownload.text, size: expected.size, border: 4), expected.modules)
        }
    }

    func testThePayloadIsTheSameUnderEveryStyle() async throws {
        try await withHarness(Self.relaxed) { h in
            let (owner, account, businessId) = try await h.verifiedOwner()
            try await h.dashReauth(owner, account)
            let (link, _) = try await createCampaign(h, owner, "spring")
            let expectedQR = try QRCode.encode(link, errorCorrection: .medium)
            let forms: [[(String, String)]] = [[("look", "concept")], [("look", "plain")],
                                              customForm(background: "#FFF8E7", ink: "#2F1B0C", extra: [("modules", "circle"), ("rings", "dots"), ("rays", "flat")]),
                                              [("look", "qr"), ("qr_dark", "#1B3A5C"), ("qr_light", "#FFFFFF")]]
            for form in forms {
                let saved = try await h.formPost(ConsoleCodeStyle.savePath, owner, form)
                XCTAssertEqual(saved.status, .seeOther, "\(form) \(saved.text)")
                let style = try await BusinessCodeStyleService(db: h.db, ctx: h.ctx).effective(businessId: businessId)
                let page = try await h.page("/dashboard/campaigns/\(try await CampaignService(db: h.db, ctx: h.ctx).list(businessId: businessId)[0].id!.uuidString.lowercased())", owner)
                XCTAssertEqual(page.status, .ok)
                XCTAssertEqual(try signedLink(page.text), link, "the link never changes with the style")
                let primary = try svg(in: page.text, code: "primary")
                if let ckey = style.ckeyStyle {
                    // The marks are the symbol of the same link; only the paint differs.
                    XCTAssertEqual(primary, try CKeySymbol.encode(link, level: .medium).svg(style: ckey, label: "Viadere code for your Viadere connect link"))
                } else {
                    XCTAssertEqual(DashboardPagesTests.modules(fromSVG: primary, size: expectedQR.size, border: 4), expectedQR.modules)
                    XCTAssertTrue(primary.contains("#1B3A5C"))
                }
                XCTAssertEqual(DashboardPagesTests.modules(fromSVG: try svg(in: page.text, code: "qr"), size: expectedQR.size, border: 4), expectedQR.modules)
            }
            try await eq(try await AuditEventRecord.query(on: h.db).filter(\.$action == "brandkit.code_style_saved").count(), forms.count)
        }
    }

    func testUnsafeStylesAreRefusedWithTheirReasonAndNothingIsStored() async throws {
        try await withHarness(Self.relaxed) { h in
            let (owner, account, businessId) = try await h.verifiedOwner()
            try await h.dashReauth(owner, account)
            let refusals: [([(String, String)], String)] = [
                (customForm(background: "#808080", ink: "#8C8C8C"), "contrast of 1.2:1"),
                (customForm(background: "#FFFFFF", ink: "#A0A0A0"), "at least 3:1"),
                (customForm(background: "#777777", ink: "#FFFFFF", extra: [("use_accent1", "1"), ("accent1", "#000000"), ("accent_percent", "20")]), "Mixing the two"),
                (customForm(background: "#14161E", ink: "#F6EEE0", extra: [("use_edge", "1"), ("background_edge", "#07080C"), ("use_shade", "1"), ("ink_shade", "#C8B69A")]), "colours of the Viadere code"),
                (customForm(background: "#FFFFFF", ink: "#000000", extra: [("shadow", "45")]), "shadow of at most 40"),
                (customForm(background: "#FFFFFF", ink: "#949494"), "#949494 is too close to the middle"),
                (customForm(background: "#000000", ink: "#A0A0A0"), "#A0A0A0 is too close to the middle"),
                (customForm(background: "#000000", ink: "#FFFFFF", extra: [("bevel", "90")]), "bevel of at most 60"),
                ([("look", "qr"), ("qr_dark", "#FFFFFF"), ("qr_light", "#000000")], "dark squares on a light background"),
                ([("look", "qr"), ("qr_dark", "#000000"), ("qr_light", "#A0A0A0")], "light colour is too dark"),
                ([("look", "qr"), ("qr_dark", "#999999"), ("qr_light", "#FFFFFF")], "at least 4.5:1"),
                (customForm(background: "red;background:url(x)", ink: "#000000"), "#RRGGBB"),
                (customForm(background: "#FFFFFF", ink: "#00000"), "#RRGGBB"),
                ([("look", "qr"), ("qr_dark", "\"><script>alert(1)</script>"), ("qr_light", "#FFFFFF")], "#RRGGBB"),
                (customForm(background: "#FFFFFF", ink: "#000000", extra: [("modules", "star")]), "listed options"),
                ([("look", "logo")], "Choose a code style"),
            ]
            for (form, reason) in refusals {
                for path in [ConsoleCodeStyle.savePath, ConsoleCodeStyle.previewPath] {
                    let response = try await h.formPost(path, owner, form)
                    XCTAssertEqual(response.status, .unprocessableEntity, "\(path) \(form)")
                    XCTAssertTrue(response.text.contains(reason), "\(path) \(form): expected “\(reason)”")
                    XCTAssertTrue(response.text.contains("Your saved style is unchanged."))
                    XCTAssertFalse(response.text.contains("<script>alert(1)</script>"), "submitted text is escaped")
                }
            }
            try await eq(try await BusinessCodeStyleRecord.query(on: h.db).filter(\.$businessId == businessId).count(), 0)
            try await eq(try await AuditEventRecord.query(on: h.db).filter(\.$action == "brandkit.code_style_saved").count(), 0)
            // A preview of an acceptable style draws it and stores nothing.
            let preview = try await h.formPost(ConsoleCodeStyle.previewPath, owner, customForm(background: "#FFF8E7", ink: "#2F1B0C"))
            XCTAssertEqual(preview.status, .ok, preview.text)
            XCTAssertTrue(preview.text.contains("Nothing is saved until you choose Save."))
            XCTAssertTrue(preview.text.contains("fill=\"#2f1b0c\"") || preview.text.contains("#2f1b0c"))
            try await eq(try await BusinessCodeStyleRecord.query(on: h.db).count(), 0)
        }
    }

    func testAStoredStyleRoundTripsAndARowThatNoLongerValidatesIsNeverDrawn() async throws {
        try await withHarness(Self.relaxed) { h in
            let (owner, account, businessId) = try await h.verifiedOwner()
            try await h.dashReauth(owner, account)
            let form = customForm(background: "#FFF8E7", ink: "#2F1B0C", extra: [("use_accent1", "1"), ("accent1", "#5A1E0C"), ("accent_percent", "20"),
                                                                                     ("modules", "diamond"), ("rings", "dots"), ("rays", "flat"), ("bevel", "20"), ("shadow", "10"), ("texture", "30"),
                                                                                     ("label", "<b>smuggled</b>"), ("logo_url", "https://evil.example/x.png")])
            let saved = try await h.formPost(ConsoleCodeStyle.savePath, owner, form)
            XCTAssertEqual(saved.status, .seeOther, saved.text)
            let row = try await XCTUnwrapAsync(await BusinessCodeStyleRecord.query(on: h.db).filter(\.$businessId == businessId).first())
            XCTAssertFalse(row.styleJSON.contains("smuggled"))
            XCTAssertFalse(row.styleJSON.contains("evil"))
            let stored = try JSONDecoder().decode(BusinessCodeStyle.self, from: Data(row.styleJSON.utf8))
            let expected = try BusinessCodeStyle(custom: CKeyStyleSpec(background: BrandColor("#FFF8E7")!, ink: BrandColor("#2F1B0C")!, accents: [BrandColor("#5A1E0C")!],
                                                                       accentPercent: 20, modules: .diamond, rings: .dots, rays: .flat, bevel: 20, shadow: 10, texture: 30))
            XCTAssertEqual(stored, expected)
            // The editor shows the stored values back.
            let studio = try await h.page(ConsoleBrandStudio.path, owner)
            XCTAssertEqual(studio.status, .ok)
            XCTAssertTrue(studio.text.contains("value=\"#fff8e7\""))
            XCTAssertTrue(studio.text.contains("value=\"#5a1e0c\""))
            let audit = try await XCTUnwrapAsync(await AuditEventRecord.query(on: h.db).filter(\.$action == "brandkit.code_style_saved").first())
            XCTAssertEqual(audit.businessId, businessId)
            XCTAssertTrue(audit.metadataJSON.contains("custom"))
            // A row written under other rules (here: tampered to a faint colour) is ignored; the default is drawn.
            row.styleJSON = row.styleJSON.replacingOccurrences(of: "#2F1B0C", with: "#FFF7E6")
            try await row.update(on: h.db)
            try await eq(try await BusinessCodeStyleService(db: h.db, ctx: h.ctx).effective(businessId: businessId), .standard)
            row.styleJSON = #"{"v":2,"symbology":"ckey","preset":"plain"}"#
            try await row.update(on: h.db)
            try await eq(try await BusinessCodeStyleService(db: h.db, ctx: h.ctx).effective(businessId: businessId), .standard)
        }
    }

    func testOnlyEditorsWithAFreshPasskeyChangeTheStyleAndOnlyTheirOwn() async throws {
        try await withHarness(Self.relaxed) { h in
            let (owner, ownerAccount, businessId) = try await h.verifiedOwner()
            let qr = [("look", "qr"), ("qr_dark", "#1B3A5C"), ("qr_light", "#FFFFFF")]
            // A viewer (auditor) sees the card read-only and cannot preview or save.
            let (auditor, auditorAccount) = try await h.addMember(owner: owner, role: .auditor, email: "audit@acme.example")
            try await h.dashReauth(auditor, auditorAccount)
            let page = try await h.page(ConsoleBrandStudio.path, auditor)
            XCTAssertEqual(page.status, .ok)
            XCTAssertTrue(page.text.contains("id=\"code-style\""))
            XCTAssertFalse(page.text.contains("Save code style"))
            try await eq(try await h.formPost(ConsoleCodeStyle.savePath, auditor, qr).status, .forbidden)
            try await eq(try await h.formPost(ConsoleCodeStyle.previewPath, auditor, qr).status, .forbidden)
            // Another organization's owner writes only its own row.
            let (rival, rivalAccount, rivalId) = try await h.verifiedOwner(email: "rival@example.com", org: "Rival Roasters", handle: "rivalroasters")
            try await h.dashReauth(rival, rivalAccount)
            try await h.dashReauth(owner, ownerAccount)
            try await eq(try await h.formPost(ConsoleCodeStyle.savePath, owner, qr).status, .seeOther)
            try await eq(try await h.formPost(ConsoleCodeStyle.savePath, rival, [("look", "plain"), ("business_id", businessId.uuidString)]).status, .seeOther)
            let service = BusinessCodeStyleService(db: h.db, ctx: h.ctx)
            try await eq(try await service.stored(businessId: businessId), try BusinessCodeStyle(qrDark: BrandColor("#1B3A5C")!, light: BrandColor("#FFFFFF")!))
            try await eq(try await service.stored(businessId: rivalId), BusinessCodeStyle(preset: .plain))
            // The rival's console never shows the owner's colours.
            let rivalPage = try await h.page(ConsoleBrandStudio.path, rival)
            XCTAssertFalse(rivalPage.text.lowercased().contains("#1b3a5c"))
        }
    }

    func testSuggestionsFromTheApprovedBrandKitAreFormDefaultsThatPassTheValidator() async throws {
        try await withHarness(Self.relaxed) { h in
            let (owner, _, businessId) = try await h.verifiedOwner()
            let kit = try await BrandKitService(db: h.db, ctx: h.ctx).save(businessId: businessId, kitId: nil, draft: .init(kitKey: "everyday", name: "Everyday",
                tokens: BrandTokens(primary: BrandColor("#2F5D50")!, surface: BrandColor("#FBF7EF")!), frameId: nil, assets: [:]), actor: AuditActor(kind: .system))
            // Not approved yet: no suggestion is taken from it.
            let unapproved = try await BusinessCodeStyleService(db: h.db, ctx: h.ctx).approvedTokens(businessId: businessId)
            XCTAssertNil(unapproved)
            try await BrandKitService(db: h.db, ctx: h.ctx).approveKit(id: kit.id!, actor: BrandKitServerTests.operatorActor, note: nil)
            let tokens = try await BusinessCodeStyleService(db: h.db, ctx: h.ctx).approvedTokens(businessId: businessId)
            let suggested = BusinessCodeStyle.suggestedCustom(from: tokens)
            XCTAssertNil(BusinessCodeStyle.refusal(for: suggested))
            let page = try await h.page(ConsoleBrandStudio.path, owner)
            XCTAssertTrue(page.text.contains("value=\"\(suggested.ink.hex.lowercased())\""), "the suggestion fills the form")
            // Nothing is stored by a suggestion.
            try await eq(try await BusinessCodeStyleRecord.query(on: h.db).count(), 0)
        }
    }

    // MARK: G2: campaigns

    func testCampaignsAreStoredListedArchivedAndEscaped() async throws {
        try await withHarness(Self.relaxed) { h in
            let (owner, _, businessId) = try await h.verifiedOwner()
            let hostile = "<script>alert(1)</script>\"onmouseover=x"
            let (_, record) = try await createCampaign(h, owner, "autumn-mailer", name: hostile, action: "open_benefits")
            XCTAssertEqual(record.businessId, businessId)
            XCTAssertEqual(record.name, hostile)
            XCTAssertEqual(record.action, "open_benefits")
            XCTAssertNotNil(record.expiresAt)
            XCTAssertNotNil(record.createdBy)
            let list = try await h.page("/dashboard/campaigns", owner)
            XCTAssertEqual(list.status, .ok)
            XCTAssertFalse(list.text.contains("<script>alert(1)</script>"))
            XCTAssertTrue(list.text.contains("&lt;script&gt;alert(1)&lt;/script&gt;"))
            XCTAssertTrue(list.text.contains("Active"))
            // The same identifier cannot be created twice; an action off the closed list is refused.
            try await eq(try await h.formPost("/dashboard/campaigns", owner, [("campaign", "autumn-mailer"), ("days", "30")]).status, .unprocessableEntity)
            let offList = try await h.formPost("/dashboard/campaigns", owner, [("campaign", "pay"), ("action", "pay_now"), ("days", "30")])
            XCTAssertEqual(offList.status, .unprocessableEntity)
            XCTAssertTrue(offList.text.contains("Choose one of the listed actions."))
            try await eq(try await CampaignRecord.query(on: h.db).count(), 1)
            // Archive.
            let id = record.id!.uuidString.lowercased()
            try await eq(try await h.formPost("/dashboard/campaigns/\(id)/archive", owner).status, .seeOther)
            let archived = try await XCTUnwrapAsync(await CampaignRecord.find(record.id, on: h.db))
            XCTAssertNotNil(archived.archivedAt)
            try await isTrue(try await h.page("/dashboard/campaigns", owner).text.contains("Archived"))
            try await isTrue(try await AuditEventRecord.query(on: h.db).filter(\.$action == "campaign.archived").count() == 1)
            // Another organization can neither open nor archive it.
            let (rival, _, _) = try await h.verifiedOwner(email: "rival@example.com", org: "Rival Roasters", handle: "rivalroasters")
            try await eq(try await h.page("/dashboard/campaigns/\(id)", rival).status, .notFound)
            try await eq(try await h.formPost("/dashboard/campaigns/\(id)/archive", rival).status, .notFound)
            try await eq(try await h.formPost("/dashboard/campaigns/download", rival, [("campaign", "autumn-mailer"), ("code", "qr")]).status, .notFound)
            try await isTrue(!(try await h.page("/dashboard/campaigns", rival).text.contains("autumn-mailer")))
        }
    }

    func testOnlyAVerifiedLiveCampaignContextOfThisBusinessIsCredited() async throws {
        try await withHarness(Self.relaxed) { h in
            let (owner, _, businessId) = try await h.verifiedOwner()
            let (rivalOwner, _, rivalId) = try await h.verifiedOwner(email: "rival@example.com", org: "Rival Roasters", handle: "rivalroasters")
            let (link, record) = try await createCampaign(h, owner, "spring", action: "enroll_rewards")
            let code = try await businessCode(h, businessId)
            let rivalCode = try await businessCode(h, rivalId)
            func connect(_ business: UUID, _ link: String?, name: String) async throws -> RelationshipRecord {
                let consumer = try await h.readyConsumer(name: name)
                let response = try await h.signedPost(consumer, "/v1/relationships", ConnectRequest(businessId: BusinessID(business), source: .qr, link: link))
                XCTAssertEqual(response.status, .created, response.text)
                return try await XCTUnwrapAsync(await RelationshipRecord.query(on: h.db).filter(\.$consumerId == consumer.id.uuid).first())
            }
            // The signed, live link: credited, and the audit event names the campaign.
            let credited = try await connect(businessId, link, name: "Ada")
            XCTAssertEqual(credited.campaignId, record.id)
            let connected = try await AuditEventRecord.query(on: h.db).filter(\.$action == "relationship.connected").filter(\.$consumerId == credited.consumerId).first()
            XCTAssertTrue(connected?.metadataJSON.contains("\"campaign\":\"spring\"") == true, connected?.metadataJSON ?? "")
            // A context altered under its signature and the plain link: connected, not credited.
            let sigStart = link.range(of: "&sig=")!
            let ctxStart = link.range(of: "?ctx=")!
            var context = Array(link[ctxStart.upperBound..<sigStart.lowerBound])
            context[2] = context[2] == "A" ? "B" : "A"
            let tampered = String(link[..<ctxStart.upperBound]) + String(context) + String(link[sigStart.lowerBound...])
            try await isTrue(try await connect(businessId, tampered, name: "Bea").campaignId == nil)
            // A context without a signature is not a valid link: refused, nothing created.
            let ctxOnly = String(link[..<sigStart.lowerBound])
            let unsigned = try await h.signedPost(try await h.readyConsumer(name: "Cy"), "/v1/relationships", ConnectRequest(businessId: BusinessID(businessId), source: .qr, link: ctxOnly))
            XCTAssertEqual(unsigned.status, .unprocessableEntity)
            try await isTrue(try await connect(businessId, ConnectLink(code: code).urlString, name: "Di").campaignId == nil)
            try await isTrue(try await connect(businessId, nil, name: "Ed").campaignId == nil)
            // A context signed by a key Viadere does not hold.
            let foreign = try ConnectLink(code: code, context: ConnectContext(campaign: "spring", issuedAt: h.clock.now(), expiresAt: h.clock.now().addingTimeInterval(3600)),
                                          key: .init(size: .bits256)).urlString
            try await isTrue(try await connect(businessId, foreign, name: "Flo").campaignId == nil)
            // The owner's signed link presented for another business is refused outright; a genuine context for the rival naming the
            // owner's campaign identifier credits nothing to either.
            let mismatch = try await h.signedPost(try await h.readyConsumer(name: "Gus"), "/v1/relationships", ConnectRequest(businessId: BusinessID(rivalId), source: .qr, link: link))
            XCTAssertEqual(mismatch.status, .unprocessableEntity)
            let crossTenant = try h.ctx.connectKeys.link(code: rivalCode, context: ConnectContext(campaign: "spring", issuedAt: h.clock.now(), expiresAt: h.clock.now().addingTimeInterval(3600)),
                                                         domain: h.ctx.config.linkDomain).urlString
            try await isTrue(try await connect(rivalId, crossTenant, name: "Hal").campaignId == nil)
            // Counts are per tenant.
            try await eq(try await CampaignService(db: h.db, ctx: h.ctx).connectCounts(businessId: businessId), [record.id!: 1])
            try await eq(try await CampaignService(db: h.db, ctx: h.ctx).connectCounts(businessId: rivalId), [:])
            try await isTrue(!(try await h.page("/dashboard", rivalOwner).text.contains("Connections by campaign")))
            let overview = try await h.page("/dashboard", owner)
            XCTAssertTrue(overview.text.contains("Connections by campaign"), overview.text)
            XCTAssertTrue(overview.text.contains("1 connections came through a campaign link"))
            // Archived and expired campaigns stop crediting; their link still connects.
            let id = record.id!.uuidString.lowercased()
            try await eq(try await h.formPost("/dashboard/campaigns/\(id)/archive", owner).status, .seeOther)
            try await isTrue(try await connect(businessId, link, name: "Ivy").campaignId == nil)
            let (summer, summerRecord) = try await createCampaign(h, owner, "summer", days: 30)
            h.clock.advance(by: 31 * 86_400)
            try await isTrue(try await connect(businessId, summer, name: "Jo").campaignId == nil)
            try await eq(try await CampaignService(db: h.db, ctx: h.ctx).connectCounts(businessId: businessId), [record.id!: 1])
            XCTAssertNotNil(summerRecord.id)
        }
    }

    func testActionsAreAClosedListAndNeverChangeConsent() async throws {
        try await withHarness(Self.relaxed) { h in
            let (owner, _, businessId) = try await h.verifiedOwner()
            let (link, _) = try await createCampaign(h, owner, "rewards", action: "enroll_rewards")
            let code = try await businessCode(h, businessId)
            // The directory passes the verified, listed action of a live campaign on.
            let resolved = try await h.post("/v1/directory/resolve", DirectoryResolveRequest(input: link)).json(DirectoryResolveResponse.self)
            XCTAssertEqual(resolved.context?.action, "enroll_rewards")
            XCTAssertEqual(CampaignAction(verified: resolved.context), .enrollRewards)
            // A server-signed context with an action off the list, or one that differs from the stored campaign, is passed on without it.
            for (campaign, action) in [("rewards", "pay_now"), ("rewards", "open_messages"), ("unknown", "open_benefits")] {
                let forged = try h.ctx.connectKeys.link(code: code, context: ConnectContext(campaign: campaign, action: action, issuedAt: h.clock.now(),
                                                                                            expiresAt: h.clock.now().addingTimeInterval(3600)), domain: h.ctx.config.linkDomain).urlString
                let response = try await h.post("/v1/directory/resolve", DirectoryResolveRequest(input: forged)).json(DirectoryResolveResponse.self)
                XCTAssertNil(response.context?.action, "\(campaign) \(action)")
            }
            // Connecting through the rewards link with no opt-in grants exactly what connecting without it grants.
            func consents(_ link: String?, _ name: String) async throws -> [String: Bool] {
                let consumer = try await h.readyConsumer(name: name)
                let response = try await h.signedPost(consumer, "/v1/relationships", ConnectRequest(businessId: BusinessID(businessId), source: .qr, link: link))
                XCTAssertEqual(response.status, .created, response.text)
                let rows = try await ConsentGrantRecord.query(on: h.db).filter(\.$consumerId == consumer.id.uuid).all()
                return Dictionary(uniqueKeysWithValues: rows.map { ($0.purpose, $0.granted) })
            }
            let withAction = try await consents(link, "Ada")
            let without = try await consents(nil, "Bea")
            XCTAssertEqual(withAction, without)
            XCTAssertEqual(withAction["rewards"], false)
        }
    }
}
