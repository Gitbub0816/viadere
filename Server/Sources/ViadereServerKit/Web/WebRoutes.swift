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
                // Every universal-link prefix the app parses (`DeepLinkRouter`): connect, the retired account-link and handoff prefixes (kept one release so old texts open the app on a "no longer used" screen), Approve enrollment, link sessions and
                // Loop install links and verification sessions (`/v/`, the "Verify with Viadere" button).
                // Fragments (`#es=`) are never sent to a server; the matching rules ignore them.
                "applinks": ["details": [["appIDs": [appID], "components": [["/": "/c/*"], ["/": "/l/*"], ["/": "/h/*"], ["/": "/a/*"], ["/": "/k/*"], ["/": "/lp/*"], ["/": "/v/*"]]]]],
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
        routes.grouped(IPRateLimitMiddleware(name: "web") { $0.rateLimits.directory }).get("v", ":code", use: verificationSessionPage)
        // Retired links (ADR-0027): `/l/…` and `/h/…` from texts sent by older builds. Nothing is looked up; the token is never read.
        routes.grouped(IPRateLimitMiddleware(name: "web") { $0.rateLimits.directory }).get("l", ":token", use: retiredLinkPage)
        routes.grouped(IPRateLimitMiddleware(name: "web") { $0.rateLimits.directory }).get("h", ":token", use: retiredLinkPage)
        routes.grouped(IPRateLimitMiddleware(name: "web") { $0.rateLimits.directory }).get("get", use: getAppPage)
        routes.grouped(IPRateLimitMiddleware(name: "web") { $0.rateLimits.directory }).get("lp", ":loopId", use: loopInstallPage)
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

    /// `/lp/{loopId}` without the app (§2.98 "Installed Loops"): names the Loop and its business only for a fully launched publication (active,
    /// rollout 100%, verified business in an allowed category, no switch); otherwise a generic page. Installing happens only in the app.
    @Sendable
    static func loopInstallPage(_ req: Request) async throws -> Response {
        let ctx = req.ctx
        guard let raw = req.parameters.get("loopId"), raw.count == 36, let id = UUID(uuidString: raw) else {
            return page(title: "Not available", body: "<p>This Loop link isn't valid.</p>", status: .notFound, ctx: ctx)
        }
        var body: String
        if let landing = try await LoopInstallService(db: req.db, ctx: ctx).publicLanding(definitionId: id) {
            body = "<p><strong>\(escape(landing.title))</strong></p><p class=\"muted\">Built by \(escape(landing.business)), a verified business on Viadere</p>"
        } else {
            body = "<p>This Loop is shown in the Viadere app.</p>"
        }
        body += "<p>Open Viadere to see what this Loop can do and add it. You choose whether to connect with the business.</p>"
        if let storeID = ctx.config.appStoreID, storeID.allSatisfy(\.isNumber) {
            body += "<a class=\"btn\" href=\"https://apps.apple.com/app/id\(storeID)\">Get Viadere</a>"
        }
        return page(title: "Add a Loop", body: body, ctx: ctx)
    }

    /// The landing page of a verification-session link (`/v/{CODE}`), shown when the link opened in a browser instead of the app (the app is not
    /// installed, or the link was opened on a computer). It looks **nothing** up: no business, no status, no oracle on whether the code exists.
    @Sendable
    static func verificationSessionPage(_ req: Request) async throws -> Response {
        let ctx = req.ctx
        guard let raw = req.parameters.get("code"), raw.count <= 16, let code = VerificationSessionCode.canonical(raw), code == raw else {
            return page(title: "Not available", body: "<p>This Viadere link isn't valid. Go back to the business's page and start again.</p>", status: .notFound, ctx: ctx)
        }
        var head = ""
        var body = "<p>This verification continues in the Viadere app. Viadere shows you which verified business is asking and exactly what it would learn before you decide.</p>"
        body += "<p>Already have Viadere on your phone? Open it and enter the code <code>\(escape(VerificationSessionCode.display(code)))</code>, or scan the QR code on the business's page.</p>"
        body += "<p class=\"muted\">The code expires a few minutes after it was shown. Viadere never asks for your password or a payment on this page.</p>"
        if let storeID = ctx.config.appStoreID, storeID.allSatisfy(\.isNumber) {
            let argument = escape(VerificationSessionLink.build(code: code, domain: ctx.config.linkDomain))
            head = "<meta name=\"apple-itunes-app\" content=\"app-id=\(storeID), app-argument=\(argument)\">"
            body += "<a class=\"btn\" href=\"https://apps.apple.com/app/id\(storeID)\">Get Viadere</a>"
        }
        return page(title: "Continue in Viadere", head: head, body: body, ctx: ctx)
    }

    /// UX_COPY S-LINK-RETIRED: an old text link opens the app (universal link) or this page. Viadere no longer texts links that sign you in,
    /// link you or ask for a decision.
    @Sendable
    static func retiredLinkPage(_ req: Request) async throws -> Response {
        page(title: "This link is no longer used", body: "<p>Open Viadere to see your requests.</p><p class=\"muted\">Viadere never asks you to approve a payment or sign-in by text message.</p>",
             status: .gone, ctx: req.ctx)
    }

    /// The static on-ramp page that "get Viadere" texts point at (UX_COPY SMS-01). No token, no query, nothing about the visitor.
    @Sendable
    static func getAppPage(_ req: Request) async throws -> Response {
        let ctx = req.ctx
        var head = ""
        var body = "<p>Viadere is a trusted way to connect with verified businesses. Get the app to message businesses, approve requests and keep your account private.</p>"
        if let storeID = ctx.config.appStoreID, storeID.allSatisfy(\.isNumber) {
            head = "<meta name=\"apple-itunes-app\" content=\"app-id=\(storeID)\">"
            body += "<a class=\"btn\" href=\"https://apps.apple.com/app/id\(storeID)\">Get Viadere</a>"
        }
        body += "<p class=\"muted\">Viadere never sends you a code or a sign-in link by text.</p>"
        return page(title: "Get Viadere", head: head, body: body, ctx: ctx)
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
