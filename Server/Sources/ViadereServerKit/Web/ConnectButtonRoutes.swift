@preconcurrency import Crypto
import Foundation
import Vapor
import ViadereCore

/// A versioned set of embeddable, dependency-free files under `Server/Public/{name}/{version}/` (the "Connect with Viadere" and
/// "Verify with Viadere" buttons).
///
/// * **Immutable per URL.** Files live under a versioned path and are served with
///   `Cache-Control: public, max-age=31536000, immutable`, so an integrator can pin them with Subresource
///   Integrity. A change to a file ships under a new version path (`v2/`), never in place.
/// * **SRI-ready.** `Access-Control-Allow-Origin: *` (no credentials) lets `<script integrity=… crossorigin>` work
///   cross-origin; `GET /{name}/{version}/integrity.json` publishes the current `sha384` of every file.
/// * Only an allow-listed set of file names is ever read (no path traversal), and responses carry
///   `nosniff` and a locked-down CSP.
struct EmbedAssets: Sendable {
    let name: String
    let version: String
    let files: [String: String]

    func directoryCandidates(_ app: Application) -> [String] {
        var candidates = [app.directory.publicDirectory + "\(name)/\(version)/"]
        // Development and test builds run from the package directory.
        let source = URL(fileURLWithPath: #filePath).deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
            .deletingLastPathComponent().appendingPathComponent("Public/\(name)/\(version)/").path
        candidates.append(source)
        return candidates
    }

    func load(_ file: String, app: Application) -> Data? {
        guard files[file] != nil else { return nil }
        for directory in directoryCandidates(app) {
            if let data = FileManager.default.contents(atPath: directory + file) { return data }
        }
        return nil
    }

    static func sri(_ data: Data) -> String { "sha384-" + Data(SHA384.hash(data: data)).base64EncodedString() }

    func register(_ app: Application) {
        let assets = self
        let limiter = IPRateLimitMiddleware(name: "web") { $0.rateLimits.directory }
        let group = app.routes.grouped(limiter)
        @Sendable func common(_ response: Response) {
            response.headers.replaceOrAdd(name: .accessControlAllowOrigin, value: "*")
            response.headers.replaceOrAdd(name: "Cross-Origin-Resource-Policy", value: "cross-origin")
            response.headers.replaceOrAdd(name: "Content-Security-Policy", value: "default-src 'none'")
            response.headers.replaceOrAdd(name: .cacheControl, value: "public, max-age=31536000, immutable")
            response.headers.remove(name: "Pragma")
        }
        group.get(.constant(name), .constant(version), "integrity.json") { req -> Response in
            var map: [String: String] = [:]
            for file in assets.files.keys.sorted() { if let data = assets.load(file, app: req.application) { map[file] = Self.sri(data) } }
            let data = try JSONSerialization.data(withJSONObject: map, options: [.sortedKeys, .withoutEscapingSlashes])
            let response = Response(status: .ok, body: .init(data: data))
            response.headers.contentType = .json
            common(response)
            // The manifest itself must be fresh enough to notice a deployment.
            response.headers.replaceOrAdd(name: .cacheControl, value: "public, max-age=300")
            return response
        }
        group.get(.constant(name), .constant(version), ":file") { req -> Response in
            guard let file = req.parameters.get("file"), let type = assets.files[file], let data = assets.load(file, app: req.application) else { throw APIError.notFound }
            let etag = "\"" + SecureToken.sha256Hex(data).prefix(32) + "\""
            if req.headers.first(name: .ifNoneMatch) == etag {
                let response = Response(status: .notModified)
                response.headers.replaceOrAdd(name: .eTag, value: etag)
                common(response)
                return response
            }
            let response = Response(status: .ok, body: .init(data: data))
            response.headers.replaceOrAdd(name: .contentType, value: type)
            response.headers.replaceOrAdd(name: .eTag, value: etag)
            common(response)
            return response
        }
    }
}

/// Serves the embeddable "Connect with Viadere" button (`Server/Public/connect-button/v1/`).
enum ConnectButtonRoutes {
    static let version = "v1"
    static let assets = EmbedAssets(name: "connect-button", version: version, files: [
        "viadere-connect.js": "text/javascript; charset=utf-8",
        "viadere-connect.css": "text/css; charset=utf-8",
    ])

    static func register(_ app: Application) { assets.register(app) }
}

/// Serves the embeddable "Verify with Viadere" button (`Server/Public/verify-button/v1/`, `docs/VERIFY-BUTTON.md`): the same immutable,
/// SRI-ready, allow-listed serving as the connect button.
enum VerifyButtonRoutes {
    static let version = "v1"
    static let assets = EmbedAssets(name: "verify-button", version: version, files: [
        "viadere-verify.js": "text/javascript; charset=utf-8",
        "viadere-verify.css": "text/css; charset=utf-8",
    ])

    static func register(_ app: Application) { assets.register(app) }
}
