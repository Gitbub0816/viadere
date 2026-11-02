import Fluent
import Foundation
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// Rendering harness input: boots the app, seeds a busy business (several Brand Kits, many API keys and webhooks, Loop drafts, a published and
/// listed Loop, team members) and an operator, crawls every console page reachable by link, and writes each response (body and the headers the
/// browser must see) to `$CONSOLE_DUMP_DIR`, with a `manifest.json`. `Server/Tests/browser/test_console_render.py` serves that directory with the
/// real CSP and screenshots every page. Skipped unless `CONSOLE_DUMP_DIR` is set, so it never runs in the normal suite.
final class ConsoleRenderDump: XCTestCase {
    struct Entry: Codable { var path: String; var status: Int; var realm: String; var file: String; var contentType: String; var headers: [String: String] }

    func testDumpEveryConsolePage() async throws {
        guard let dir = ProcessInfo.processInfo.environment["CONSOLE_DUMP_DIR"] else { throw XCTSkip("CONSOLE_DUMP_DIR not set") }
        let root = URL(fileURLWithPath: dir, isDirectory: true)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: true)
        try await withHarness { h in
            let (owner, account, businessId) = try await h.verifiedOwner(org: "Acme Roasters and Provisions of Greater Phoenix")
            try await h.dashReauth(owner, account)

            // Brand: an asset and three kits (so the studio shows several preview frames).
            let png = Data(BrandAssetPipelineTests.png())
            let (body, type) = BrandKitServerTests.multipart([("slot", "logo"), ("_csrf", h.csrf(owner))], file: ("file", "logo.png", "image/png", png))
            var uploadHeaders = h.cookieHeaders(owner)
            uploadHeaders["Origin"] = h.origin
            _ = try await h.request(.POST, ConsoleBrandStudio.uploadPath, headers: uploadHeaders, body: body, contentType: type)
            for (key, name, color) in [("everyday", "Everyday", "#2F5D50"), ("spring", "Spring promotion with a rather long name", "#B5683A"), ("night", "Late night", "#1F2A44")] {
                _ = try await h.formPost("/dashboard/brand/kits", owner, [("kit_id", key), ("name", name), ("primary", color), ("use_accent", "1"), ("accent", "#C2AE8E"), ("radius", "large")])
            }
            _ = try await h.formPost("/dashboard/brand/schedule", owner, [("timezone", "America/Phoenix"), ("default_kit", "everyday"), ("w0_kit", "spring"),
                ("w0_start", "2027-03-01T00:00"), ("w0_end", "2027-04-01T00:00"), ("w0_priority", "5"), ("pool_spring", "3")])

            // Developers: many keys and webhooks with long names and URLs.
            for i in 1...9 {
                _ = try await h.formPost("/dashboard/api-keys", owner, [("name", "integration-key-number-\(i)-for-the-point-of-sale-system"), ("mode", i % 3 == 0 ? "live" : "test"),
                    ("scopes[]", "interactions:write"), ("scopes[]", "interactions:read")])
            }
            for i in 1...5 {
                _ = try await h.formPost("/dashboard/webhooks", owner, [("url", "https://hooks-\(i).acme-roasters-integration.example.com/viadere/webhooks/v1/receive/endpoint"), ("events[]", "message.received")])
            }
            _ = try await h.addMember(owner: owner, role: .developer, email: "dev@example.com", name: "Dana Developer")
            _ = try await h.addMember(owner: owner, role: .support, email: "support@example.com", name: "Sam Support")

            // Loops: a published, listed Loop, a second one, and Studio drafts.
            let business = try await h.testBusiness(businessId)
            let world = try await LoopWorld.build(h, business: business, tag: "acme")
            let publication = try await world.publish()
            _ = try await world.publish(LoopFixtures.pickup(title: "Order a cake", key: "cake"))
            try await LoopInstallService(db: h.db, ctx: h.ctx).setListing(publicationId: publication.id!, category: .foodAndDrink, listed: true, featured: true,
                                                                          operatorId: world.reviewer1, reason: "Checked for the directory.")
            for _ in 0..<2 { _ = try await LoopStudioTests.createDraft(h, owner, template: "pickup_time") }

            let (op, opAccount) = try await h.makeOperator()
            try await h.dashReauth(op, opAccount)

            var manifest: [Entry] = []
            var seen = Set<String>()
            func crawl(_ start: String, session: DashSession, realm: String) async throws {
                var queue = [start]
                while let path = queue.first, seen.count < 400 {
                    queue.removeFirst()
                    guard seen.insert(realm + path).inserted else { continue }
                    let result = try await h.page(path, session)
                    let name = String(manifest.count) + "-" + realm + ".bin"
                    try result.body.write(to: root.appendingPathComponent(name))
                    var headers: [String: String] = [:]
                    for n in ["Content-Security-Policy", "Referrer-Policy", "X-Frame-Options", "Cache-Control"] { if let v = result.headers.first(name: n) { headers[n] = v } }
                    manifest.append(Entry(path: path, status: Int(result.status.code), realm: realm, file: name,
                                          contentType: result.headers.first(name: .contentType) ?? "text/html", headers: headers))
                    guard result.status == .ok, (result.headers.first(name: .contentType) ?? "").contains("html") else { continue }
                    let text = result.text
                    let regex = try NSRegularExpression(pattern: "(?:href|src)=\"(/(?:dashboard|operator)[^\"#]*)\"")
                    let ns = text as NSString
                    for m in regex.matches(in: text, range: NSRange(location: 0, length: ns.length)) {
                        let link = ns.substring(with: m.range(at: 1)).replacingOccurrences(of: "&amp;", with: "&")
                        let clean = link.split(separator: "?").first.map(String.init) ?? link
                        guard clean.hasPrefix("/" + realm), !clean.contains("logout"), !clean.contains("/auth/") else { continue }
                        if link.contains("sort=") || link.contains("page=") { continue }
                        queue.append(link.contains("?m=") ? clean : link)
                    }
                }
            }
            try await crawl("/dashboard", session: owner, realm: "dashboard")
            try await crawl("/operator", session: op, realm: "operator")
            try ViadereJSON.encode(manifest).write(to: root.appendingPathComponent("manifest.json"))
            print("CONSOLE_DUMP pages=\(manifest.count)")
        }
    }
}
