@preconcurrency import Crypto
import Foundation
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// The embeddable "Verify with Viadere" button (`Server/Public/verify-button/v1/`, `docs/VERIFY-BUTTON.md`): served like the connect button
/// (immutable, SRI-ready, allow-listed) and statically free of everything a strict CSP or a privacy review would object to. Behaviour
/// (rendering, panel, hand-off, QR correctness) is tested in a real headless browser: `Server/Tests/browser/test_verify_button.py`.
final class VerifyButtonTests: XCTestCase {
    var repo: URL { URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent() }
    var publicDir: URL { repo.appendingPathComponent("Server/Public/verify-button/v1") }

    func sri(_ file: String) throws -> String {
        "sha384-" + Data(SHA384.hash(data: try Data(contentsOf: publicDir.appendingPathComponent(file)))).base64EncodedString()
    }

    // MARK: Serving

    func testFilesAreServedImmutableWithCORSForSRIAndNoSniffing() async throws {
        try await withHarness { h in
            for (file, type) in [("viadere-verify.js", "text/javascript"), ("viadere-verify.css", "text/css")] {
                let r = try await h.request(.GET, "/verify-button/v1/\(file)")
                XCTAssertEqual(r.status, .ok, file)
                XCTAssertTrue(r.headers.first(name: .contentType)?.hasPrefix(type) == true)
                XCTAssertEqual(r.headers.first(name: .cacheControl), "public, max-age=31536000, immutable")
                XCTAssertEqual(r.headers.first(name: .accessControlAllowOrigin), "*")
                XCTAssertNil(r.headers.first(name: .accessControlAllowCredentials))
                XCTAssertEqual(r.headers.first(name: "X-Content-Type-Options"), "nosniff")
                XCTAssertEqual(r.headers.first(name: "Content-Security-Policy"), "default-src 'none'")
                XCTAssertNil(r.headers.first(name: .setCookie))
                XCTAssertEqual(r.body, try Data(contentsOf: publicDir.appendingPathComponent(file)))
                let etag = try XCTUnwrap(r.headers.first(name: .eTag))
                let cached = try await h.request(.GET, "/verify-button/v1/\(file)", headers: ["If-None-Match": etag])
                XCTAssertEqual(cached.status, .notModified)
            }
        }
    }

    func testOnlyAllowListedFilesAreReadAndTraversalIsImpossible() async throws {
        try await withHarness { h in
            for path in ["/verify-button/v1/../../Package.swift", "/verify-button/v1/%2e%2e%2fPackage.swift", "/verify-button/v1/example.html",
                         "/verify-button/v1/viadere-connect.js", "/verify-button/v2/viadere-verify.js", "/verify-button/viadere-verify.js",
                         "/verify-button/v1/viadere-verify.JS", "/verify-button/v1/.env"] {
                let r = try await h.request(.GET, path)
                XCTAssertTrue([.notFound, .badRequest].contains(r.status), "\(path) → \(r.status)")
            }
        }
    }

    func testIntegrityManifestMatchesTheFilesAndTheGuidePinsThem() async throws {
        try await withHarness { h in
            let r = try await h.request(.GET, "/verify-button/v1/integrity.json")
            XCTAssertEqual(r.status, .ok)
            let manifest = try JSONDecoder().decode([String: String].self, from: r.body)
            XCTAssertEqual(manifest, ["viadere-verify.js": try sri("viadere-verify.js"), "viadere-verify.css": try sri("viadere-verify.css")])
        }
        let guide = try String(contentsOf: repo.appendingPathComponent("docs/VERIFY-BUTTON.md"), encoding: .utf8)
        XCTAssertTrue(guide.contains(try sri("viadere-verify.js")), "docs/VERIFY-BUTTON.md must pin the current viadere-verify.js hash (and a change ships under /v2/)")
        XCTAssertTrue(guide.contains(try sri("viadere-verify.css")), "…and the current viadere-verify.css hash")
        XCTAssertTrue(guide.contains("https://viadere.com/verify-button/v1/viadere-verify.js"))
        let example = try String(contentsOf: repo.appendingPathComponent("docs/examples/verify-button.html"), encoding: .utf8)
        XCTAssertTrue(example.contains(try sri("viadere-verify.js")) && example.contains(try sri("viadere-verify.css")), "the example page pins the hashes too")
        XCTAssertFalse(example.contains("<script>"), "the example needs no inline script")
        XCTAssertFalse(example.contains("style="), "…and no inline style")
    }

    // MARK: Static properties

    /// The executable part of the script (comments removed).
    func code(of file: String) throws -> String {
        var text = try String(contentsOf: publicDir.appendingPathComponent(file), encoding: .utf8)
        text = text.replacingOccurrences(of: "/\\*[\\s\\S]*?\\*/", with: "", options: .regularExpression)
        return text.split(separator: "\n", omittingEmptySubsequences: false).filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("//") }.joined(separator: "\n")
    }

    func testTheScriptMakesNoRequestsTouchesNoStorageAndInjectsNoMarkup() throws {
        let js = try code(of: "viadere-verify.js")
        for forbidden in ["fetch(", "XMLHttpRequest", "sendBeacon", "WebSocket", "EventSource", "localStorage", "sessionStorage", "indexedDB", "document.cookie",
                          "iframe", "eval(", "new Function", "document.write", "import(", "importScripts", "innerHTML", "outerHTML", "insertAdjacentHTML",
                          "<script", "'style'", "\"style\"", ".style.", "onclick", "onerror", "setTimeout(", "setInterval(", "window.open", "postMessage",
                          "location.href =", "location.assign", "attachShadow", "adoptedStyleSheets"] {
            XCTAssertFalse(js.contains(forbidden), "viadere-verify.js must not use \(forbidden)")
        }
        // The only absolute URL in code is the SVG namespace; session links are matched by a strict pattern of the two Viadere link domains.
        let urls = js.matches(of: /https?:\/\/[^\s'"<>)]+/).map { String($0.output) }
        XCTAssertEqual(Set(urls), ["http://www.w3.org/2000/svg"], "\(urls)")
        XCTAssertTrue(js.contains(#"var LINK = /^https:\/\/(viadere\.com|viadere\.cksites\.dev)\/v\/([A-HJ-NP-Z2-9]{8})$/;"#))
        XCTAssertTrue(js.contains("noopener noreferrer"))
        XCTAssertTrue(js.contains("referrerpolicy"))
        XCTAssertLessThan(try Data(contentsOf: publicDir.appendingPathComponent("viadere-verify.js")).count, 32 * 1024)
    }

    func testTheLinkPatternAgreesWithTheCodeAlphabet() throws {
        // The script's character class is exactly the Approve alphabet (no I, O, 0, 1) that `VerificationSessionCode` generates.
        let allowed = Set("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
        for _ in 0..<200 { XCTAssertTrue(VerificationSessionCode.generate().allSatisfy { allowed.contains($0) }) }
        let classMembers = Set("ABCDEFGH" + "JKLMN" + "PQRSTUVWXYZ" + "23456789")
        XCTAssertEqual(classMembers, allowed)
    }

    func testTheStylesheetUsesTheBrandPaletteAndNoExternalResources() throws {
        let css = try String(contentsOf: publicDir.appendingPathComponent("viadere-verify.css"), encoding: .utf8)
        XCTAssertFalse(css.contains("url("))
        XCTAssertFalse(css.contains("@import"))
        XCTAssertFalse(css.contains("expression("))
        // Design/README.md palette and semantic tokens only.
        let allowed: Set<String> = ["#1F1E1C", "#F5F2EC", "#4A4844", "#8C7550", "#F3F0EA", "#C9C4BB", "#FCFBF8", "#1C1B1A", "#FFFFFF", "#6B675F", "#A29D94",
                                    "#CDB993", "#262523"]
        for match in css.matches(of: /#[0-9A-Fa-f]{6}\b/) { XCTAssertTrue(allowed.contains(String(match.output).uppercased()), "\(match.output) is not a brand colour") }
        XCTAssertTrue(css.contains("prefers-color-scheme:dark"))
        XCTAssertTrue(css.contains("forced-colors:active"))
        XCTAssertTrue(css.contains("prefers-reduced-motion:reduce"))
        XCTAssertTrue(css.contains("min-height:44px"), "44 pt minimum touch target")
    }

    func testTheMarkInTheButtonIsTheBrandMark() throws {
        let js = try String(contentsOf: publicDir.appendingPathComponent("viadere-verify.js"), encoding: .utf8)
        let svg = try String(contentsOf: repo.appendingPathComponent("Design/svg/viadere-mark-mono-dark.svg"), encoding: .utf8)
        let paths = svg.matches(of: /d="([^"]+)"/).map { String($0.output.1) }
        XCTAssertEqual(paths.count, 4)
        for path in paths { XCTAssertTrue(js.contains(path), "button mark must be the brand artwork") }
        XCTAssertTrue(js.contains("cx: '155.21', cy: '20.5', r: '20.5'"))
    }
}
