@preconcurrency import Crypto
import Foundation
import ViadereCore
import XCTest
@testable import ViadereServerKit

final class ConnectButtonTests: XCTestCase {
    var publicDir: URL {
        URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Public/connect-button/v1")
    }

    func sri(_ file: String) throws -> String {
        let data = try Data(contentsOf: publicDir.appendingPathComponent(file))
        return "sha384-" + Data(SHA384.hash(data: data)).base64EncodedString()
    }

    // MARK: Serving

    func testFilesAreServedImmutableWithCORSForSRIAndNoSniffing() async throws {
        try await withHarness { h in
            for (file, type) in [("viadere-connect.js", "text/javascript"), ("viadere-connect.css", "text/css")] {
                let r = try await h.request(.GET, "/connect-button/v1/\(file)")
                XCTAssertEqual(r.status, .ok, file)
                XCTAssertTrue(r.headers.first(name: .contentType)?.hasPrefix(type) == true)
                XCTAssertEqual(r.headers.first(name: .cacheControl), "public, max-age=31536000, immutable")
                XCTAssertEqual(r.headers.first(name: .accessControlAllowOrigin), "*", "cross-origin SRI needs CORS")
                XCTAssertNil(r.headers.first(name: .accessControlAllowCredentials))
                XCTAssertEqual(r.headers.first(name: "Cross-Origin-Resource-Policy"), "cross-origin")
                XCTAssertEqual(r.headers.first(name: "X-Content-Type-Options"), "nosniff")
                XCTAssertEqual(r.headers.first(name: "Content-Security-Policy"), "default-src 'none'")
                XCTAssertNil(r.headers.first(name: .setCookie))
                XCTAssertEqual(r.body, try Data(contentsOf: publicDir.appendingPathComponent(file)))
                // Conditional requests.
                let etag = try XCTUnwrap(r.headers.first(name: .eTag))
                let cached = try await h.request(.GET, "/connect-button/v1/\(file)", headers: ["If-None-Match": etag])
                XCTAssertEqual(cached.status, .notModified)
                XCTAssertTrue(cached.body.isEmpty)
            }
        }
    }

    func testOnlyAllowListedFilesAreReadAndTraversalIsImpossible() async throws {
        try await withHarness { h in
            for path in ["/connect-button/v1/../../Package.swift", "/connect-button/v1/%2e%2e%2fPackage.swift", "/connect-button/v1/..%2fv1%2fviadere-connect.js",
                         "/connect-button/v1/example.html", "/connect-button/v1/.env", "/connect-button/v1/viadere-connect.js.map", "/connect-button/v2/viadere-connect.js",
                         "/connect-button/viadere-connect.js", "/connect-button/v1/viadere-connect.JS"] {
                let r = try await h.request(.GET, path)
                XCTAssertTrue([.notFound, .badRequest].contains(r.status), "\(path) → \(r.status)")
            }
        }
    }

    func testIntegrityManifestMatchesTheFilesOnDisk() async throws {
        try await withHarness { h in
            let r = try await h.request(.GET, "/connect-button/v1/integrity.json")
            XCTAssertEqual(r.status, .ok)
            let manifest = try JSONDecoder().decode([String: String].self, from: r.body)
            XCTAssertEqual(manifest["viadere-connect.js"], try sri("viadere-connect.js"))
            XCTAssertEqual(manifest["viadere-connect.css"], try sri("viadere-connect.css"))
            XCTAssertEqual(manifest.count, 2)
            XCTAssertEqual(r.headers.first(name: .accessControlAllowOrigin), "*")
        }
    }

    func testTheIntegrationGuidePinsTheCurrentHashes() throws {
        let docs = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("docs/BUSINESS-INTEGRATION.md")
        let text = try String(contentsOf: docs, encoding: .utf8)
        XCTAssertTrue(text.contains(try sri("viadere-connect.js")), "docs/BUSINESS-INTEGRATION.md must contain the current viadere-connect.js SRI hash — update it when the file changes (and ship a new /vN/ path)")
        XCTAssertTrue(text.contains(try sri("viadere-connect.css")), "…and the current viadere-connect.css hash")
        XCTAssertTrue(text.contains("https://viadere.com/connect-button/v1/viadere-connect.js"))
        XCTAssertTrue(text.contains("class=\"vd-connect\""))
    }

    // MARK: Static properties of the embeddable files

    /// The executable part of the script (comments removed), so documentation can mention what the code does *not* do.
    func code(of file: String) throws -> String {
        var text = try String(contentsOf: publicDir.appendingPathComponent(file), encoding: .utf8)
        text = text.replacingOccurrences(of: "/\\*[\\s\\S]*?\\*/", with: "", options: .regularExpression)
        text = text.split(separator: "\n", omittingEmptySubsequences: false).filter { !$0.trimmingCharacters(in: .whitespaces).hasPrefix("//") }.joined(separator: "\n")
        return text
    }

    func testTheScriptMakesNoNetworkRequestsAndTouchesNoStorage() throws {
        let js = try code(of: "viadere-connect.js")
        for forbidden in ["fetch(", "XMLHttpRequest", "sendBeacon", "WebSocket", "EventSource", "localStorage", "sessionStorage", "indexedDB", "document.cookie", "iframe",
                          "eval(", "new Function", "document.write", "import(", "importScripts", "navigator.", "<script", "onerror", "onclick"] {
            XCTAssertFalse(js.contains(forbidden), "viadere-connect.js must not use \(forbidden)")
        }
        // The only URLs it may contain: the connect origin, and the SVG namespace.
        let urls = js.matches(of: /https?:\/\/[^\s'"<>)]+/).map { String($0.output) }
        XCTAssertFalse(urls.isEmpty)
        XCTAssertTrue(urls.allSatisfy { $0 == "https://viadere.com/c/" || $0 == "http://www.w3.org/2000/svg" }, "\(urls)")
        XCTAssertLessThan(try Data(contentsOf: publicDir.appendingPathComponent("viadere-connect.js")).count, 6 * 1024, "tiny")
        XCTAssertTrue(js.contains("referrerpolicy"))
        XCTAssertTrue(js.contains("noopener noreferrer"))
    }

    func testTheStylesheetHasNoExternalResources() throws {
        let css = try String(contentsOf: publicDir.appendingPathComponent("viadere-connect.css"), encoding: .utf8)
        XCTAssertFalse(css.contains("url("))
        XCTAssertFalse(css.contains("@import"))
        XCTAssertFalse(css.contains("expression("))
        // Brand palette only (Design/README.md).
        let allowed: Set<String> = ["#1F1E1C", "#F5F2EC", "#4A4844", "#8C7550", "#F3F0EA", "#C9C4BB"]
        for match in css.matches(of: /#[0-9A-Fa-f]{6}\b/) { XCTAssertTrue(allowed.contains(String(match.output).uppercased()), "\(match.output) is not a brand colour") }
        XCTAssertTrue(css.contains("prefers-color-scheme:dark"))
        XCTAssertTrue(css.contains("min-height:44px"), "44pt minimum touch target")
    }

    func testTheMarkInTheButtonIsTheBrandMark() throws {
        let js = try String(contentsOf: publicDir.appendingPathComponent("viadere-connect.js"), encoding: .utf8)
        let svg = try String(contentsOf: URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .appendingPathComponent("Design/svg/viadere-mark-mono-dark.svg"), encoding: .utf8)
        let paths = svg.matches(of: /d="([^"]+)"/).map { String($0.output.1) }
        XCTAssertEqual(paths.count, 4)
        for path in paths { XCTAssertTrue(js.contains(path), "button mark must be the brand artwork") }
        XCTAssertTrue(js.contains("cx=\"155.21\" cy=\"20.5\" r=\"20.5\""))
        XCTAssertTrue(DashboardUI.markSVG.contains(paths[0]), "dashboard uses the same artwork")
    }

    // Behaviour (rendering, normalisation, hostile input) is tested in a real headless browser: Server/Tests/browser/test_connect_button.py.
}
