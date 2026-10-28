import Foundation
import Vapor
import ViadereCore

/// What the origin lock established about a request. Set by `EdgeLockMiddleware`; nothing else may set it.
struct EdgeContext: Sendable {
    /// The request carried a valid `X-Viadere-Edge-Token`: it came through Cloudflare, so the headers Cloudflare sets are trustworthy.
    var viaEdge: Bool
    /// SHA-256 fingerprint (lowercase hex) of the client certificate Cloudflare API Shield verified, if it did.
    var clientCertFingerprint: String?
    /// Subject key identifier of the CA that issued that certificate (lowercase hex), if forwarded.
    var clientCertIssuerSKI: String?
    /// SHA-256 (lowercase hex) of the issuer certificate, if the edge forwards it. Cloudflare does not expose one today, so the edge ruleset removes
    /// the header; if it ever does, an issuer binding must match it.
    var clientCertIssuerSHA256: String?
}

struct EdgeContextKey: StorageKey { typealias Value = EdgeContext }

extension Request {
    /// The origin-lock result. Without an enforced lock (development and tests) `viaEdge` is `false` and no forwarded header is trusted.
    var edge: EdgeContext { storage[EdgeContextKey.self] ?? EdgeContext(viaEdge: false) }
}

/// Origin lock (ops gap G-10, SEC-TR-005): when `EDGE_TOKEN` is configured (required in staging and production), a request is served only if
/// it carries it in `X-Viadere-Edge-Token` (constant-time compare against the current and the previous value, so the value can be rotated).
/// A request that bypassed Cloudflare gets `421` before any routing, authentication or database access.
///
/// Health checks are exempt **only** when they come from Fly's internal network: the TCP peer is inside `healthPeerNetworks` and the request
/// carries no proxy header (Fly's proxy and Cloudflare always add `X-Forwarded-For`/`Fly-Client-IP`/`CF-*`; the checker adds none).
///
/// The client-certificate headers (Tier E mTLS) are read **only** from a request that passed the lock, so a client that reaches the origin
/// some other way cannot claim a certificate by sending the header.
struct EdgeLockMiddleware: AsyncMiddleware {
    enum Decision: Equatable {
        case allow(viaEdge: Bool)
        case rejectMissingToken
        case rejectBadToken
    }

    static let healthPaths: Set<String> = ["/healthz", "/readyz"]
    static let proxyHeaders = ["x-forwarded-for", "forwarded", "fly-client-ip", "cf-connecting-ip", "cf-ray", "x-real-ip", "true-client-ip", "via"]

    /// The decision as a pure function of what the request carries (the unit tests call it directly with synthetic peers).
    static func decide(settings: OperationsSettings, token: String?, path: String, method: HTTPMethod, headerNames: [String], peer: String?) -> Decision {
        guard !settings.edgeTokens.isEmpty else { return .allow(viaEdge: false) }
        if let token, !token.isEmpty {
            // Compare against every accepted value without stopping early.
            var matched = false
            for accepted in settings.edgeTokens where ConstantTime.equals(Data(token.utf8), accepted) { matched = true }
            return matched ? .allow(viaEdge: true) : .rejectBadToken
        }
        if (method == .GET || method == .HEAD), healthPaths.contains(path), let peer,
           IPNetwork.allows(peer, in: settings.healthPeerNetworks), !settings.healthPeerNetworks.isEmpty,
           !headerNames.contains(where: { proxyHeaders.contains($0.lowercased()) }) {
            return .allow(viaEdge: false)
        }
        return .rejectMissingToken
    }

    func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        let ctx = request.application.ctx
        let settings = ctx.config.operations
        let decision = Self.decide(settings: settings, token: request.headers.first(name: settings.edgeHeader), path: request.url.path,
                                   method: request.method, headerNames: request.headers.map(\.name), peer: request.remoteAddress?.ipAddress)
        switch decision {
        case .allow(let viaEdge):
            var edge = EdgeContext(viaEdge: viaEdge)
            if viaEdge, request.headers.first(name: settings.clientCertVerifiedHeader)?.lowercased() == "true" {
                edge.clientCertFingerprint = Self.hex(request.headers.first(name: settings.clientCertFingerprintHeader), length: 64)
                edge.clientCertIssuerSKI = Self.hex(request.headers.first(name: settings.clientCertIssuerHeader), length: nil)
                edge.clientCertIssuerSHA256 = Self.hex(request.headers.first(name: settings.clientCertIssuerSHA256Header), length: 64)
            }
            request.storage[EdgeContextKey.self] = edge
            return try await next.respond(to: request)
        case .rejectMissingToken, .rejectBadToken:
            ctx.metrics.count(.edgeRejected)
            // No detail beyond the status: the response must not help someone probing for the origin.
            request.logger.warning("origin lock refused a request", metadata: ["reason": "\(decision == .rejectBadToken ? "bad_token" : "no_token")",
                                                                              "requestId": "\(request.requestID)"])
            let response = Response(status: .misdirectedRequest)
            response.headers.contentType = .json
            response.body = .init(string: #"{"error":{"code":"forbidden","message":"Misdirected request."}}"#)
            return response
        }
    }

    /// A lowercase hex value of the expected length (colons stripped), or `nil`. Anything else is ignored rather than trusted.
    static func hex(_ raw: String?, length: Int?) -> String? {
        guard let raw else { return nil }
        let cleaned = raw.replacingOccurrences(of: ":", with: "").lowercased()
        guard !cleaned.isEmpty, cleaned.count <= 128, cleaned.allSatisfy({ $0.isHexDigit }) else { return nil }
        if let length, cleaned.count != length { return nil }
        return cleaned
    }
}
