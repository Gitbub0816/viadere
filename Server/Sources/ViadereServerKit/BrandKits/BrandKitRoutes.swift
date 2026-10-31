import Crypto
import Foundation
import Vapor
import ViadereCore

/// Consumer brand route and public asset serving (WP-2.1, WP-2.3; SECURITY.md §2.93 "Serving").
enum BrandKitRoutes {
    static func register(_ app: Application) {
        let routes = app.routes
        routes.api(APIRoutes.businessBrandGet) { req in
            let principal = try req.consumer
            let business: BusinessID = try req.uuidParameter("businessId")
            try await req.ctx.limiter.enforce("brand-manifest", key: principal.consumerId.description, rule: req.ctx.config.brandKits.fetchRate)
            let view = try await BrandKitService(db: req.db, ctx: req.ctx).view(consumer: principal.consumerId, business: business)
            let body = try ViadereJSON.encode(view)
            // The ETag covers the whole answer (manifest, seed and pins), so a changed pin is never hidden behind a 304.
            let etag = "\"" + Hex.encode(Data(SHA256.hash(data: body)).prefix(16)) + "\""
            if let match = req.headers.first(name: .ifNoneMatch), match == etag {
                let response = Response(status: .notModified)
                response.headers.replaceOrAdd(name: .eTag, value: etag)
                return response
            }
            let response = Response(status: .ok, body: .init(data: body))
            response.headers.contentType = .json
            response.headers.replaceOrAdd(name: .eTag, value: etag)
            return response
        }
        // `https://{ASSET_DOMAIN}/b/{sha256}.png`. Immutable by name: a replaced image is a new URL.
        routes.on(.GET, "b", ":file") { req -> Response in
            // With an asset host configured, assets exist only there (never on the API, link or console host).
            // In staging and production assets are served only on the asset host, never on the cookie-bearing API origin.
            if let assetHost = req.ctx.config.brandKits.assetDomain?.host {
                guard AssetHostMiddleware.host(of: req) == assetHost else { throw APIError.notFound }
            } else if req.ctx.config.isStrict {
                throw APIError.notFound
            }
            guard req.url.query == nil, let file = req.parameters.get("file"), file.hasSuffix(".png") else { throw APIError.notFound }
            let sha = String(file.dropLast(4))
            guard ContractHash.isLowerHex64(sha),
                  let data = try await BrandAssetService(db: req.db, ctx: req.ctx, runtime: req.brandKits).servable(sha256: sha) else { throw APIError.notFound }
            let response = BrandAssetService.imageResponse(data, cache: "public, max-age=31536000, immutable")
            response.headers.replaceOrAdd(name: "Cross-Origin-Resource-Policy", value: "cross-origin")
            return response
        }
    }
}

/// The asset host answers exactly one thing (ADR-0017): `GET`/`HEAD /b/{64 lowercase hex}.png` without a query. Everything else on that
/// host, including the AASA file, the API, the console and the link routes, is a bare `404`; no response from it ever sets a cookie.
///
/// The server never reads `Host` (SECURITY.md §1). Asset-host traffic is recognised by `X-Viadere-Asset-Host`, which the Cloudflare
/// transform rule of the asset hostname sets (overwriting any client value) to `ASSET_DOMAIN`; the origin is reachable only through the
/// tunnel with the edge token. A client that sends the header itself on the API host only restricts its own request to assets.
struct AssetHostMiddleware: AsyncMiddleware {
    static let header = "X-Viadere-Asset-Host"

    static func host(of request: Request) -> String { (request.headers.first(name: header) ?? "").lowercased() }

    static func isAssetPath(_ path: String) -> Bool {
        guard path.hasPrefix("/b/"), path.hasSuffix(".png") else { return false }
        let name = path.dropFirst(3).dropLast(4)
        return ContractHash.isLowerHex64(String(name))
    }

    func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        guard let assetHost = request.ctx.config.brandKits.assetDomain?.host, Self.host(of: request) == assetHost else {
            return try await next.respond(to: request)
        }
        guard request.method == .GET || request.method == .HEAD, request.url.query == nil, Self.isAssetPath(request.url.path) else {
            return Response(status: .notFound)
        }
        let response: Response
        do { response = try await next.respond(to: request) } catch { return Response(status: .notFound) }
        response.headers.remove(name: .setCookie)
        response.cookies.all.removeAll()
        if response.status != .ok { return Response(status: response.status == .notModified ? .notModified : .notFound) }
        return response
    }
}
