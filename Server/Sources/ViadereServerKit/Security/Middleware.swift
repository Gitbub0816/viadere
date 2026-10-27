import Foundation
import Vapor
import ViadereCore

/// Adds security headers to every response. HTML pages set their own (stricter, hash-based) CSP first.
public struct SecurityHeadersMiddleware: AsyncMiddleware {
    public init() {}

    public func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        let response = try await next.respond(to: request)
        func set(_ name: String, _ value: String) {
            if !response.headers.contains(name: name) { response.headers.add(name: name, value: value) }
        }
        set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        set("X-Content-Type-Options", "nosniff")
        set("Referrer-Policy", "no-referrer")
        set("X-Frame-Options", "DENY")
        set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")
        set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        set("Cross-Origin-Resource-Policy", "same-origin")
        set("Cross-Origin-Opener-Policy", "same-origin")
        set("Cache-Control", "no-store")
        set("Pragma", "no-cache")
        response.headers.remove(name: "Server")
        return response
    }
}

/// Enforces JSON-only request bodies for the API (provider webhooks use form encoding and are exempt)
/// and rejects oversized bodies before they are read.
public struct RequestGuardMiddleware: AsyncMiddleware {
    public init() {}

    public func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        let ctx = request.ctx
        let method = request.method
        if method == .POST || method == .PUT || method == .PATCH || method == .DELETE {
            if let length = request.headers.first(name: .contentLength).flatMap(Int.init), length > ctx.config.maxBodyBytes {
                throw APIError(.payloadTooLarge, .badRequest, "Request body is too large.")
            }
            let isProvider = request.url.path.hasPrefix("/v1/providers/")
            let hasBody = (request.headers.first(name: .contentLength).flatMap(Int.init) ?? 0) > 0
                || request.headers.first(name: .transferEncoding) != nil
            // The dashboard and operator console post HTML forms; everything else is JSON-only.
            let isWebForm = request.url.path.hasPrefix(APIRoutes.Web.dashboardPrefix + "/") || request.url.path.hasPrefix(APIRoutes.Web.operatorPrefix + "/")
            if hasBody && isWebForm {
                guard let type = request.headers.contentType, (type.type == "application" && (type.subType == "json" || type.subType == "x-www-form-urlencoded")) else {
                    throw APIError(.unsupportedMediaType, .badRequest, "Unsupported content type.")
                }
            } else if hasBody && !isProvider {
                guard let type = request.headers.contentType, type.type == "application", type.subType == "json" else {
                    throw APIError(.unsupportedMediaType, .badRequest, "Content-Type must be application/json.")
                }
            }
        }
        return try await next.respond(to: request)
    }
}

/// CORS is locked down: the API serves native clients and servers, so no cross-origin access is allowed
/// unless an exact origin is configured. Credentials are never allowed and `*` is never emitted.
public struct CORSLockdownMiddleware: AsyncMiddleware {
    public init() {}

    public func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        let allowed = request.ctx.config.corsAllowedOrigins
        let origin = request.headers.first(name: .origin)
        let permitted = origin.map { allowed.contains($0) } ?? false
        if request.method == .OPTIONS {
            let response = Response(status: permitted ? .noContent : .forbidden)
            if permitted, let origin { Self.apply(to: response, origin: origin) }
            return response
        }
        let response = try await next.respond(to: request)
        if permitted, let origin { Self.apply(to: response, origin: origin) }
        return response
    }

    private static func apply(to response: Response, origin: String) {
        response.headers.replaceOrAdd(name: .accessControlAllowOrigin, value: origin)
        response.headers.replaceOrAdd(name: .vary, value: "Origin")
        response.headers.replaceOrAdd(name: .accessControlAllowMethods, value: "GET, POST, PUT, DELETE")
        response.headers.replaceOrAdd(name: .accessControlAllowHeaders,
                                      value: "Authorization, Content-Type, Idempotency-Key, Viadere-Device, Viadere-Timestamp, Viadere-Nonce, Viadere-Signature")
        response.headers.replaceOrAdd(name: .accessControlMaxAge, value: "600")
    }
}

/// Logs one structured line per request. Query strings, bodies and authorization headers are never
/// logged, and token-bearing path segments (`/l/{token}`, `/h/{token}`) are replaced.
public struct RequestLoggingMiddleware: AsyncMiddleware {
    public init() {}

    public func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        let start = Date()
        let id = request.requestID
        let response: Response
        do {
            response = try await next.respond(to: request)
        } catch {
            request.logger.info("request", metadata: ["method": "\(request.method.rawValue)", "path": "\(Self.safePath(request.url.path))",
                                                      "status": "500", "requestId": "\(id)"])
            throw error
        }
        request.logger.info("request", metadata: [
            "method": "\(request.method.rawValue)", "path": "\(Self.safePath(request.url.path))", "status": "\(response.status.code)",
            "ms": "\(Int(Date().timeIntervalSince(start) * 1000))", "requestId": "\(id)",
        ])
        return response
    }

    static func safePath(_ path: String) -> String {
        let parts = path.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        var out = parts
        for i in parts.indices where i > 0 {
            if ["l", "h"].contains(parts[i - 1]) && i == 2 { out[i] = ":token" }
            if parts[i - 1] == "handles" || parts[i - 1] == "codes" { out[i] = ":id" }
        }
        return out.joined(separator: "/")
    }
}
