import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Decode-proof input for business code styles (docs/SECURITY.md §2.105): saves each style below through the Brand Studio editor, renders the
/// campaign page as the console serves it, and writes the page (with its CSP), the page's two codes as standalone SVG files and the campaign
/// link to `$STYLED_CODES_DIR` with a `manifest.json`. A browser screenshots the codes and the reference reader decodes them. Skipped unless
/// `STYLED_CODES_DIR` is set, so it never runs in the normal suite.
final class StyledCodeDump: XCTestCase {
    struct Entry: Codable { var name: String; var symbology: String; var link: String; var page: String; var primary: String; var qr: String; var note: String }

    /// Styles to prove. Two custom CKeys sit at the mark limits and near the 3:1 floor, one dark on light and one light on dark; one QR sits
    /// at its 4.5:1 floor.
    static let styles: [(name: String, note: String, form: [(String, String)])] = [
        ("concept", "Viadere preset", [("look", "concept")]),
        ("plain", "black on white preset", [("look", "plain")]),
        ("cream-circles", "custom, accent, circles, dots, flat rays", [("look", "custom"), ("background", "#FFF8E7"), ("ink", "#2F1B0C"), ("use_accent1", "1"), ("accent1", "#5A1E0C"),
                                                                        ("accent_percent", "25"), ("modules", "circle"), ("rings", "dots"), ("rays", "flat")]),
        ("navy-materials", "custom light on dark, vignette, sheen, materials at the cap", [("look", "custom"), ("background", "#0F2A44"), ("use_edge", "1"), ("background_edge", "#0A1D30"),
                                                                                           ("ink", "#F2E6C9"), ("use_shade", "1"), ("ink_shade", "#E9DCBC"), ("use_accent1", "1"), ("accent1", "#DDE8D2"),
                                                                                           ("accent_percent", "18"), ("modules", "diamond"), ("bevel", "60"), ("shadow", "50"), ("texture", "40")]),
        ("green-squares", "custom dark on light, square modules", [("look", "custom"), ("background", "#E8F1EC"), ("ink", "#163D2E"), ("modules", "square")]),
        ("floor-dark-marks", "custom at both floors: luma 56 marks, #383838 on #878787 is 3.28:1", [("look", "custom"), ("background", "#878787"), ("ink", "#383838")]),
        ("floor-light-marks", "custom at both floors: luma 216 marks, #D8D8D8 on #787878 is 3.09:1", [("look", "custom"), ("background", "#787878"), ("ink", "#D8D8D8")]),
        ("floor-accent-vignette", "custom with a vignette, an accent at the luma floor, shadow and bevel at their dark-on-light caps", [("look", "custom"), ("background", "#FFFFFF"), ("use_edge", "1"), ("background_edge", "#F2F2F2"),
                                                                                                  ("ink", "#4A2E14"), ("use_accent1", "1"), ("accent1", "#383838"), ("accent_percent", "40"), ("shadow", "40"), ("bevel", "50")]),
        ("qr-navy", "QR in brand colours", [("look", "qr"), ("qr_dark", "#1B3A5C"), ("qr_light", "#FFFFFF")]),
        ("qr-floor", "QR at the 4.5:1 floor: #767676 on #FFFFFF", [("look", "qr"), ("qr_dark", "#767676"), ("qr_light", "#FFFFFF")]),
        ("qr-tinted", "QR on a tinted field: #2F1B0C on #F3E3C3", [("look", "qr"), ("qr_dark", "#2F1B0C"), ("qr_light", "#F3E3C3")]),
    ]

    private func svg(in html: String, code which: String) throws -> String {
        let marker = try XCTUnwrap(html.range(of: "data-code=\"\(which)\""))
        let start = try XCTUnwrap(html.range(of: "<svg", range: marker.upperBound..<html.endIndex))
        let end = try XCTUnwrap(html.range(of: "</svg>", range: start.lowerBound..<html.endIndex))
        return String(html[start.lowerBound..<end.upperBound])
    }

    func testDumpStyledCodes() async throws {
        guard let dir = ProcessInfo.processInfo.environment["STYLED_CODES_DIR"] else { throw XCTSkip("STYLED_CODES_DIR not set") }
        let root = URL(fileURLWithPath: dir, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try await withHarness(CodeStyleCampaignTests.relaxed) { h in
            let (owner, account, businessId) = try await h.verifiedOwner()
            try await h.dashReauth(owner, account)
            let created = try await h.formPost("/dashboard/campaigns", owner, [("campaign", "spring-flyer"), ("name", "Spring flyer"), ("action", "open_benefits"), ("days", "90")])
            XCTAssertEqual(created.status, .ok, created.text)
            let campaign = try await XCTUnwrapAsync(await CampaignRecord.query(on: h.db).filter(\.$businessId == businessId).first())
            var entries: [Entry] = []
            for style in Self.styles {
                let saved = try await h.formPost(ConsoleCodeStyle.savePath, owner, style.form)
                XCTAssertEqual(saved.status, .seeOther, "\(style.name): \(saved.text.prefix(2000))")
                let page = try await h.page("/dashboard/campaigns/\(campaign.id!.uuidString.lowercased())", owner)
                XCTAssertEqual(page.status, .ok)
                let link = try XCTUnwrap(page.text.range(of: "https://viadere.io/c/[^<\"]+", options: .regularExpression).map { String(page.text[$0]).replacingOccurrences(of: "&amp;", with: "&") })
                let symbology = page.text.contains("data-symbology=\"ckey\"") ? "ckey" : "qr"
                let files = (page: "\(style.name).html", primary: "\(style.name)-primary.svg", qr: "\(style.name)-qr.svg")
                try page.body.write(to: root.appendingPathComponent(files.page))
                try Data(try svg(in: page.text, code: "primary").utf8).write(to: root.appendingPathComponent(files.primary))
                try Data(try svg(in: page.text, code: "qr").utf8).write(to: root.appendingPathComponent(files.qr))
                try Data((page.headers.first(name: "Content-Security-Policy") ?? "").utf8).write(to: root.appendingPathComponent("csp.txt"))
                entries.append(Entry(name: style.name, symbology: symbology, link: link, page: files.page, primary: files.primary, qr: files.qr, note: style.note))
            }
            let encoder = JSONEncoder()
            encoder.outputFormatting = [.prettyPrinted, .sortedKeys, .withoutEscapingSlashes]
            try encoder.encode(entries).write(to: root.appendingPathComponent("manifest.json"))
        }
    }
}
