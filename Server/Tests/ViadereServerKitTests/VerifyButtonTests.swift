@preconcurrency import Crypto
import Foundation
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// The embeddable "Verify with Viadere" button (`Server/Public/verify-button/{v1,v2}/`, `docs/VERIFY-BUTTON.md`): served like the connect
/// button (immutable, SRI-ready, allow-listed) and statically free of everything a strict CSP or a privacy review would object to.
/// `v1` (QR code first) is published and must never change by a byte; `v2` shows the Viadere code (CKey) first. Behaviour (rendering,
/// panel, hand-off, QR and CKey correctness) is tested in a real headless browser: `Server/Tests/browser/test_verify_button.py` and
/// `test_verify_button_v2.py`.
final class VerifyButtonTests: XCTestCase {
    var repo: URL { URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent() }
    let versions = ["v1", "v2"]
    let files = [("viadere-verify.js", "text/javascript"), ("viadere-verify.css", "text/css")]

    func publicDir(_ version: String) -> URL { repo.appendingPathComponent("Server/Public/verify-button/\(version)") }

    func sri(_ version: String, _ file: String) throws -> String {
        "sha384-" + Data(SHA384.hash(data: try Data(contentsOf: publicDir(version).appendingPathComponent(file)))).base64EncodedString()
    }

    // MARK: Serving

    func testFilesAreServedImmutableWithCORSForSRIAndNoSniffing() async throws {
        try await withHarness { h in
            for version in versions {
                for (file, type) in files {
                    let path = "/verify-button/\(version)/\(file)"
                    let r = try await h.request(.GET, path)
                    XCTAssertEqual(r.status, .ok, path)
                    XCTAssertTrue(r.headers.first(name: .contentType)?.hasPrefix(type) == true)
                    XCTAssertEqual(r.headers.first(name: .cacheControl), "public, max-age=31536000, immutable")
                    XCTAssertEqual(r.headers.first(name: .accessControlAllowOrigin), "*")
                    XCTAssertNil(r.headers.first(name: .accessControlAllowCredentials))
                    XCTAssertEqual(r.headers.first(name: "X-Content-Type-Options"), "nosniff")
                    XCTAssertEqual(r.headers.first(name: "Content-Security-Policy"), "default-src 'none'")
                    XCTAssertNil(r.headers.first(name: .setCookie))
                    XCTAssertEqual(r.body, try Data(contentsOf: publicDir(version).appendingPathComponent(file)), "\(path) serves that version's own file")
                    let etag = try XCTUnwrap(r.headers.first(name: .eTag))
                    let cached = try await h.request(.GET, path, headers: ["If-None-Match": etag])
                    XCTAssertEqual(cached.status, .notModified)
                }
            }
            let v1 = try await h.request(.GET, "/verify-button/v1/viadere-verify.js")
            let v2 = try await h.request(.GET, "/verify-button/v2/viadere-verify.js")
            XCTAssertNotEqual(v1.body, v2.body)
            XCTAssertNotEqual(v1.headers.first(name: .eTag), v2.headers.first(name: .eTag))
        }
    }

    func testOnlyAllowListedFilesAreReadAndTraversalIsImpossible() async throws {
        try await withHarness { h in
            var paths = ["/verify-button/v3/viadere-verify.js", "/verify-button/v0/viadere-verify.js", "/verify-button/V2/viadere-verify.js",
                         "/verify-button/viadere-verify.js", "/verify-button/v2/../v1/Package.swift"]
            for version in versions {
                paths += ["/verify-button/\(version)/../../Package.swift", "/verify-button/\(version)/%2e%2e%2fPackage.swift", "/verify-button/\(version)/example.html",
                          "/verify-button/\(version)/viadere-connect.js", "/verify-button/\(version)/viadere-verify.JS", "/verify-button/\(version)/.env"]
            }
            for path in paths {
                let r = try await h.request(.GET, path)
                XCTAssertTrue([.notFound, .badRequest].contains(r.status), "\(path) → \(r.status)")
            }
        }
    }

    /// `v1` is published: integrators pin these hashes with Subresource Integrity, so the files can never change. A change ships as a new
    /// version directory. If this test fails, restore the `v1` files; do not update the hashes.
    func testVersion1IsFrozen() throws {
        XCTAssertEqual(try sri("v1", "viadere-verify.js"), "sha384-vT7Sg9sIvngk1wVF56Jez/Zj9uoaJRKxrxbv76xNd8qG7oQqjvm/blG5iyeezM+Y")
        XCTAssertEqual(try sri("v1", "viadere-verify.css"), "sha384-7B8nwhugpRQh8Dv3bHED/l1CVZzyssS+AABdibXE3TEPHKXRjPLLq4v2VxPDYhDP")
        XCTAssertEqual(try Data(contentsOf: publicDir("v1").appendingPathComponent("viadere-verify.js")).count, 23_517)
        XCTAssertEqual(try Data(contentsOf: publicDir("v1").appendingPathComponent("viadere-verify.css")).count, 7_925)
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: publicDir("v1").path).sorted(), ["viadere-verify.css", "viadere-verify.js"])
        XCTAssertEqual(try FileManager.default.contentsOfDirectory(atPath: publicDir("v2").path).sorted(), ["viadere-verify.css", "viadere-verify.js"])
    }

    func testIntegrityManifestMatchesTheFilesAndTheGuidePinsThem() async throws {
        let guide = try String(contentsOf: repo.appendingPathComponent("docs/VERIFY-BUTTON.md"), encoding: .utf8)
        try await withHarness { h in
            for version in versions {
                let r = try await h.request(.GET, "/verify-button/\(version)/integrity.json")
                XCTAssertEqual(r.status, .ok)
                XCTAssertEqual(r.headers.first(name: .cacheControl), "public, max-age=300")
                let manifest = try JSONDecoder().decode([String: String].self, from: r.body)
                XCTAssertEqual(manifest, ["viadere-verify.js": try sri(version, "viadere-verify.js"), "viadere-verify.css": try sri(version, "viadere-verify.css")])
            }
        }
        for version in versions {
            XCTAssertTrue(guide.contains(try sri(version, "viadere-verify.js")), "docs/VERIFY-BUTTON.md must pin the \(version) viadere-verify.js hash (a change ships under a new version)")
            XCTAssertTrue(guide.contains(try sri(version, "viadere-verify.css")), "…and the \(version) viadere-verify.css hash")
            XCTAssertTrue(guide.contains("https://viadere.io/verify-button/\(version)/viadere-verify.js"))
            XCTAssertTrue(guide.contains("https://viadere.io/verify-button/\(version)/viadere-verify.css"))
        }
        // One complete example page per version, each pinning that version's files and nothing else.
        for (version, page) in [("v2", "docs/examples/verify-button.html"), ("v1", "docs/examples/verify-button-v1.html")] {
            let example = try String(contentsOf: repo.appendingPathComponent(page), encoding: .utf8)
            for (file, _) in files {
                XCTAssertTrue(example.contains("https://viadere.io/verify-button/\(version)/\(file)\""), "\(page) loads \(version)/\(file)")
                XCTAssertTrue(example.contains("integrity=\"\(try sri(version, file))\""), "\(page) pins the \(version) hash of \(file)")
            }
            let other = version == "v1" ? "v2" : "v1"
            XCTAssertFalse(example.contains("/verify-button/\(other)/"), "\(page) does not mix versions")
            XCTAssertFalse(example.contains("<script>"), "the example needs no inline script")
            XCTAssertFalse(example.contains("style="), "…and no inline style")
        }
    }

    // MARK: Static properties

    /// The executable part of the script (comments removed).
    func code(of file: String, version: String) throws -> String {
        var text = try String(contentsOf: publicDir(version).appendingPathComponent(file), encoding: .utf8)
        text = text.replacingOccurrences(of: "/\\*[\\s\\S]*?\\*/", with: "", options: .regularExpression)
        return text.split(separator: "\n", omittingEmptySubsequences: false).filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("//") }.joined(separator: "\n")
    }

    func testTheScriptMakesNoRequestsTouchesNoStorageAndInjectsNoMarkup() throws {
        // v1: the button, the panel and a QR encoder. v2 adds the CKey Profile 0 encoder and the "concept" renderer (about 21 KB,
        // unminified and commented so that it can be reviewed against the Swift port line by line), the CKey licence notice (1 KB) and
        // the switch between the codes (2 KB): 48 KB in all. The cap of 50 KB makes further growth a deliberate decision. Served
        // compressed the file is about a third of that.
        let caps = ["v1": 32 * 1024, "v2": 50 * 1024]
        for version in versions {
            let js = try code(of: "viadere-verify.js", version: version)
            for forbidden in ["fetch(", "XMLHttpRequest", "sendBeacon", "WebSocket", "EventSource", "localStorage", "sessionStorage", "indexedDB", "document.cookie",
                              "iframe", "eval(", "new Function", "document.write", "import(", "importScripts", "innerHTML", "outerHTML", "insertAdjacentHTML",
                              "<script", "'style'", "\"style\"", ".style.", "onclick", "onerror", "setTimeout(", "setInterval(", "window.open", "postMessage",
                              "location.href =", "location.assign", "attachShadow", "adoptedStyleSheets",
                              // Also never needed, and listed since v2 so that the larger file cannot grow them unnoticed.
                              "requestAnimationFrame", "requestIdleCallback", "setAttributeNS", "createContextualFragment", "DOMParser", "srcdoc",
                              "javascript:", "data:", "blob:", "navigator.clipboard", "Worker(", "crypto.", "<svg", "cssText", "insertRule"] {
                XCTAssertFalse(js.contains(forbidden), "\(version)/viadere-verify.js must not use \(forbidden)")
            }
            // The only absolute URL in code is the SVG namespace; session links are matched by a strict pattern of the two Viadere link domains.
            let urls = js.matches(of: /https?:\/\/[^\s'"<>)]+/).map { String($0.output) }
            XCTAssertEqual(Set(urls), ["http://www.w3.org/2000/svg"], "\(version): \(urls)")
            // v1 is frozen with the placeholder production host and the retired staging host it was published with (testVersion1IsFrozen);
            // v2 matches viadere.io and staging.viadere.io exactly (no other subdomain of viadere.io).
            let hosts = version == "v1" ? #"viadere\.com|viadere\.cksites\.dev"# : #"viadere\.io|staging\.viadere\.io"#
            XCTAssertTrue(js.contains(#"var LINK = /^https:\/\/("# + hosts + #")\/v\/([A-HJ-NP-Z2-9]{8})$/;"#), version)
            XCTAssertTrue(js.contains("noopener noreferrer"))
            XCTAssertTrue(js.contains("referrerpolicy"))
            XCTAssertLessThan(try Data(contentsOf: publicDir(version).appendingPathComponent("viadere-verify.js")).count, try XCTUnwrap(caps[version]), version)
        }
    }

    /// The Viadere app's scanner accepts a CKey only when its payload is exactly the https session link (`ScannedCodePolicy`), so both codes
    /// are made from the validated link and nothing else; and the only references inside the drawing are to its own gradients and filters.
    func testVersion2EncodesExactlyTheValidatedLinkInBothCodes() throws {
        let js = try code(of: "viadere-verify.js", version: "v2")
        XCTAssertEqual(js.matches(of: /ckEncode\(([^)]*)\)/).map { String($0.output.1) }.sorted(),
                       ["data, level, version", "data, level, version", "data, level, version", "session.link"],
                       "one definition, two static test hooks, and the panel's call with the validated link")
        XCTAssertEqual(js.matches(of: /qrSVG\(([^)]*)\)/).map { String($0.output.1) }.sorted(), ["session.link", "text"])
        XCTAssertTrue(js.contains("return match ? { link: match[0], code: match[2] } : null;"), "session.link is the whole match of the strict pattern")
        let references = Set(js.matches(of: /url\(#[^)]*\)/).map { String($0.output) })
        XCTAssertEqual(references, ["url(#ckey-ink' + sfx + ')", "url(#ckey-bg' + sfx + ')", "url(#ckey-grain' + sfx + ')", "url(#ckey-depth' + sfx + ')"])
        XCTAssertTrue(js.contains("'Use your phone’s camera instead'") && js.contains("'Back to the Viadere code'"), "the QR code stays one control away")
        XCTAssertTrue(js.contains("(forced-colors: active)"), "forced colours get the QR code")
        let whole = try String(contentsOf: publicDir("v2").appendingPathComponent("viadere-verify.js"), encoding: .utf8)
        XCTAssertTrue(whole.contains("Copyright (c) 2026 ClearKey Solutions, LLC. MIT License:") && whole.contains("The above copyright notice and this permission notice shall be included"),
                      "the port keeps the CKey copyright and permission notice in the shipped file")
        let notices = try String(contentsOf: repo.appendingPathComponent("docs/THIRD-PARTY-NOTICES.md"), encoding: .utf8)
        XCTAssertTrue(notices.contains("Server/Public/verify-button/v2/viadere-verify.js"))
    }

    func testTheLinkPatternAgreesWithTheCodeAlphabet() throws {
        // The script's character class is exactly the Approve alphabet (no I, O, 0, 1) that `VerificationSessionCode` generates.
        let allowed = Set("ABCDEFGHJKLMNPQRSTUVWXYZ23456789")
        for _ in 0..<200 { XCTAssertTrue(VerificationSessionCode.generate().allSatisfy { allowed.contains($0) }) }
        let classMembers = Set("ABCDEFGH" + "JKLMN" + "PQRSTUVWXYZ" + "23456789")
        XCTAssertEqual(classMembers, allowed)
    }

    func testTheStylesheetUsesTheBrandPaletteAndNoExternalResources() throws {
        for version in versions {
            let css = try String(contentsOf: publicDir(version).appendingPathComponent("viadere-verify.css"), encoding: .utf8)
            XCTAssertFalse(css.contains("url("))
            XCTAssertFalse(css.contains("@import"))
            XCTAssertFalse(css.contains("expression("))
            // Design/README.md palette and semantic tokens only. (The Viadere code's own colours in v2 are the CKey "concept" preset's,
            // fixed in the script as SVG attributes because a certified preset must be drawn as specified; the stylesheet has none.)
            let allowed: Set<String> = ["#1F1E1C", "#F5F2EC", "#4A4844", "#8C7550", "#F3F0EA", "#C9C4BB", "#FCFBF8", "#1C1B1A", "#FFFFFF", "#6B675F", "#A29D94",
                                        "#CDB993", "#262523"]
            for match in css.matches(of: /#[0-9A-Fa-f]{6}\b/) { XCTAssertTrue(allowed.contains(String(match.output).uppercased()), "\(version): \(match.output) is not a brand colour") }
            XCTAssertTrue(css.contains("prefers-color-scheme:dark"))
            XCTAssertTrue(css.contains("forced-colors:active"))
            XCTAssertTrue(css.contains("prefers-reduced-motion:reduce"))
            XCTAssertTrue(css.contains("min-height:44px"), "44 pt minimum touch target")
        }
        let v2 = try String(contentsOf: publicDir("v2").appendingPathComponent("viadere-verify.css"), encoding: .utf8)
        XCTAssertTrue(v2.contains(".vdv-switch{display:block;width:100%;min-height:44px"), "the switch between the codes is a full-size target")
        XCTAssertTrue(v2.contains(".vdv-qr-frame,.vdv-ckey-frame{forced-color-adjust:none}"))
    }

    func testTheMarkInTheButtonIsTheBrandMark() throws {
        let svg = try String(contentsOf: repo.appendingPathComponent("Design/svg/viadere-mark-mono-dark.svg"), encoding: .utf8)
        let paths = svg.matches(of: /d="([^"]+)"/).map { String($0.output.1) }
        XCTAssertEqual(paths.count, 4)
        for version in versions {
            let js = try String(contentsOf: publicDir(version).appendingPathComponent("viadere-verify.js"), encoding: .utf8)
            for path in paths { XCTAssertTrue(js.contains(path), "\(version): button mark must be the brand artwork") }
            XCTAssertTrue(js.contains("cx: '155.21', cy: '20.5', r: '20.5'"))
        }
    }
}
