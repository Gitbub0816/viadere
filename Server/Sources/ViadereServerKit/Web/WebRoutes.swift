@preconcurrency import Crypto
import Fluent
import Foundation
import Vapor
import ViadereCore

/// Minimal server-rendered fallback pages. No scripts, no external resources; the only inline asset is one
/// stylesheet pinned by SHA-256 in the CSP. Dynamic text is HTML-escaped.
enum WebRoutes {
    static let css = """
    :root{color-scheme:light dark;--bg:#f6f2ea;--fg:#26241f;--accent:#b79c6a;--card:#fffdf8}
    @media(prefers-color-scheme:dark){:root{--bg:#1d1c1a;--fg:#f1ece1;--card:#272522}}
    body{margin:0;background:var(--bg);color:var(--fg);font:17px/1.5 -apple-system,system-ui,sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center}
    main{max-width:28rem;margin:1rem;padding:2rem;background:var(--card);border-radius:16px;border:1px solid var(--accent)}
    h1{font-size:1.4rem;margin:.2rem 0 1rem}p{margin:.6rem 0}.muted{opacity:.7;font-size:.9rem}.btn{display:inline-block;margin-top:1rem;padding:.7rem 1.2rem;border-radius:999px;background:var(--fg);color:var(--bg);text-decoration:none}
    code{font:1.1rem ui-monospace,monospace;letter-spacing:.08em}
    """

    static var csp: String {
        let hash = Data(SHA256.hash(data: Data(css.utf8))).base64EncodedString()
        return "default-src 'none'; style-src 'sha256-\(hash)'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
    }

    static func register(_ routes: any RoutesBuilder) {
        routes.get("healthz") { req -> Response in
            // Leaks nothing: no version, no dependency state.
            let response = Response(status: .ok, body: .init(string: "{\"status\":\"ok\"}"))
            response.headers.contentType = .json
            return response
        }
        routes.get("readyz") { req -> Response in
            do { _ = try await BusinessRecord.query(on: req.db).limit(1).all() } catch {
                let response = Response(status: .serviceUnavailable, body: .init(string: "{\"status\":\"unavailable\"}"))
                response.headers.contentType = .json
                return response
            }
            let response = Response(status: .ok, body: .init(string: "{\"status\":\"ok\"}"))
            response.headers.contentType = .json
            return response
        }
        routes.get(".well-known", "apple-app-site-association") { req -> Response in
            let ctx = req.ctx
            let appID = "\(ctx.config.appleTeamID).\(ctx.config.appBundleID)"
            let clipID = "\(ctx.config.appleTeamID).\(ctx.config.appClipBundleID)"
            let json: [String: Any] = [
                // Every universal-link prefix the app parses (`DeepLinkRouter`): connect, account link, handoff, Approve enrollment and link sessions.
                // Fragments (`#es=`) are never sent to a server; the matching rules ignore them.
                "applinks": ["details": [["appIDs": [appID], "components": [["/": "/c/*"], ["/": "/l/*"], ["/": "/h/*"], ["/": "/a/*"], ["/": "/k/*"]]]]],
                "webcredentials": ["apps": [appID]],
                "appclips": ["apps": [clipID]],
            ]
            let data = try JSONSerialization.data(withJSONObject: json, options: [.sortedKeys, .withoutEscapingSlashes])
            let response = Response(status: .ok, body: .init(data: data))
            response.headers.contentType = .json
            response.headers.replaceOrAdd(name: .cacheControl, value: "public, max-age=3600")
            return response
        }
        routes.grouped(IPRateLimitMiddleware(name: "web") { $0.rateLimits.directory }).get("c", ":code", use: connectPage)
        routes.grouped(IPRateLimitMiddleware(name: "web") { $0.rateLimits.directory }).get("l", ":token") { req in
            try await tokenPage(req, kind: "accountLink", title: "Link your phone",
                body: "<p>To finish linking this phone number, open the Viadere app, sign in with your passkey, and confirm the last four digits of your number when asked.</p><p class=\"muted\">Viadere will never ask you to approve a payment or sign-in by text message.</p>")
        }
        routes.grouped(IPRateLimitMiddleware(name: "web") { $0.rateLimits.directory }).get("h", ":token") { req in
            try await tokenPage(req, kind: "handoff", title: "Continue in Viadere",
                body: "<p>For your security, this step is completed in the Viadere app. Open the app to continue.</p><p class=\"muted\">Details are never shown on this page.</p>")
        }
    }

    // MARK: Pages

    static func page(title: String, head: String = "", body: String, status: HTTPStatus = .ok, ctx: ServerContext) -> Response {
        let html = """
        <!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">\
        <meta name="referrer" content="no-referrer"><meta name="robots" content="noindex"><title>\(escape(title)) · Viadere</title>\(head)\
        <style>\(css)</style></head><body><main><p class="muted">viadere</p><h1>\(escape(title))</h1>\(body)</main></body></html>
        """
        let response = Response(status: status, body: .init(string: html))
        response.headers.contentType = .html
        response.headers.replaceOrAdd(name: "Content-Security-Policy", value: csp)
        response.headers.replaceOrAdd(name: .cacheControl, value: "no-store")
        response.headers.replaceOrAdd(name: "X-Robots-Tag", value: "noindex")
        return response
    }

    @Sendable
    static func connectPage(_ req: Request) async throws -> Response {
        let ctx = req.ctx
        let directory = DirectoryService(db: req.db)
        guard let raw = req.parameters.get("code"), raw.count <= 16, let code = BusinessCode(parsing: raw),
              let business = try await directory.verified(code: code), let profile = try await directory.profile(for: business) else {
            return page(title: "Not available", body: "<p>This Viadere code isn't active. Check the code and try again.</p>", status: .notFound, ctx: ctx)
        }
        var head = ""
        if let storeID = ctx.config.appStoreID, storeID.allSatisfy(\.isNumber) {
            // Smart App Banner with App Clip support; argument carries only the public connect URL.
            let argument = escape(ConnectLink(code: code, domain: ctx.config.linkDomain).urlString)
            head = "<meta name=\"apple-itunes-app\" content=\"app-id=\(storeID), app-clip-bundle-id=\(escape(ctx.config.appClipBundleID)), app-argument=\(argument)\">"
        }
        var body = "<p><strong>\(escape(profile.displayName))</strong> is a verified business on Viadere.</p>"
        if let handle = profile.handle { body += "<p class=\"muted\">\(escape(handle.display))</p>" }
        body += "<p>Code <code>\(escape(code.display))</code></p>"
        body += "<p>Open Viadere to connect. You stay in control of what this business can send you.</p>"
        if let storeID = ctx.config.appStoreID, storeID.allSatisfy(\.isNumber) {
            body += "<a class=\"btn\" href=\"https://apps.apple.com/app/id\(storeID)\">Get Viadere</a>"
        }
        return page(title: "Connect with \(profile.displayName)", head: head, body: body, ctx: ctx)
    }

    static func tokenPage(_ req: Request, kind: String, title: String, body: String) async throws -> Response {
        let ctx = req.ctx
        let state = try await PhoneLinkService(db: req.db, ctx: ctx).view(token: req.parameters.get("token") ?? "", kind: kind)
        switch state {
        case .valid: return page(title: title, body: body, ctx: ctx)
        case .expired, .used:
            return page(title: "Link expired", body: "<p>This link has expired or was already used. Text Viadere to get a new one.</p>", status: .gone, ctx: ctx)
        case .unknown:
            return page(title: "Link not found", body: "<p>This link isn't valid. Text Viadere to get a new one.</p>", status: .notFound, ctx: ctx)
        }
    }

    static func escape(_ text: String) -> String {
        var out = ""
        for character in text {
            switch character {
            case "&": out += "&amp;"
            case "<": out += "&lt;"
            case ">": out += "&gt;"
            case "\"": out += "&quot;"
            case "'": out += "&#39;"
            default: out.append(character)
            }
        }
        return out
    }
}
