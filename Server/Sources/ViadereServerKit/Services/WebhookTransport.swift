import Foundation
import NIOCore
import NIOPosix
import Vapor

public struct WebhookHTTPRequest: Sendable {
    public var url: URL
    public var headers: [String: String]
    public var body: Data
}

public struct WebhookHTTPResponse: Sendable {
    public var statusCode: Int
}

public enum WebhookTransportError: Error, Sendable { case blockedDestination, network }

/// HTTP delivery of webhooks. Replaceable in tests.
public protocol WebhookTransport: Sendable {
    func send(_ request: WebhookHTTPRequest) async throws -> WebhookHTTPResponse
}

/// SSRF defenses for business-supplied webhook URLs.
public enum WebhookURLPolicy {
    /// Syntactic validation at subscription time.
    public static func validate(_ url: URL, allowInsecure: Bool) -> Bool {
        guard let scheme = url.scheme?.lowercased(), let host = url.host?.lowercased(), !host.isEmpty else { return false }
        guard url.user == nil, url.password == nil, url.fragment == nil, url.absoluteString.count <= 2048 else { return false }
        if allowInsecure { return scheme == "https" || scheme == "http" }
        guard scheme == "https", url.port == nil || url.port == 443 else { return false }
        if host == "localhost" || host.hasSuffix(".localhost") || host.hasSuffix(".local") || host.hasSuffix(".internal")
            || host.hasSuffix(".lan") || host.hasSuffix(".home.arpa") { return false }
        if isIPLiteral(host) { return false }
        return host.contains(".")
    }

    static func isIPLiteral(_ host: String) -> Bool {
        if host.hasPrefix("[") || host.contains(":") { return true }
        let parts = host.split(separator: ".")
        return parts.count == 4 && parts.allSatisfy { Int($0) != nil } || Int(host) != nil || host.hasPrefix("0x")
    }

    /// Whether a resolved address is public (not loopback, private, link-local, CGNAT, multicast, metadata…).
    static func isPublic(_ address: SocketAddress) -> Bool {
        switch address {
        case .v4(let a):
            let raw = a.address.sin_addr.s_addr
            let b = withUnsafeBytes(of: raw) { Array($0) }
            guard b.count == 4 else { return false }
            switch (b[0], b[1]) {
            case (0, _), (10, _), (127, _): return false
            case (169, 254): return false
            case (172, 16...31): return false
            case (192, 168), (192, 0), (198, 18...19): return false
            case (100, 64...127): return false
            case (224...255, _): return false
            default: return true
            }
        case .v6(let a):
            let b = withUnsafeBytes(of: a.address.sin6_addr) { Array($0) }
            guard b.count == 16 else { return false }
            if b.allSatisfy({ $0 == 0 }) { return false }
            if b[0..<15].allSatisfy({ $0 == 0 }) && b[15] == 1 { return false }
            if b[0] == 0xFE && (b[1] & 0xC0) == 0x80 { return false }
            if (b[0] & 0xFE) == 0xFC { return false }
            if b[0] == 0xFF { return false }
            // IPv4-mapped (::ffff:a.b.c.d): evaluate the embedded IPv4 address.
            if b[0..<10].allSatisfy({ $0 == 0 }) && b[10] == 0xFF && b[11] == 0xFF {
                switch (b[12], b[13]) {
                case (0, _), (10, _), (127, _), (169, 254), (192, 168): return false
                case (172, 16...31): return false
                default: return true
                }
            }
            return true
        case .unixDomainSocket: return false
        }
    }
}

/// Real transport using Vapor's HTTP client: no redirects, short timeouts, destination re-checked at
/// connection time by resolving the host and rejecting non-public addresses.
public struct VaporWebhookTransport: WebhookTransport {
    let client: any Client
    let allowInsecure: Bool

    public init(client: any Client, allowInsecure: Bool) {
        self.client = client
        self.allowInsecure = allowInsecure
    }

    public func send(_ request: WebhookHTTPRequest) async throws -> WebhookHTTPResponse {
        guard WebhookURLPolicy.validate(request.url, allowInsecure: allowInsecure), let host = request.url.host else {
            throw WebhookTransportError.blockedDestination
        }
        if !allowInsecure {
            let port = request.url.port ?? 443
            let addresses = try await Self.resolve(host: host, port: port)
            guard !addresses.isEmpty, addresses.allSatisfy(WebhookURLPolicy.isPublic) else { throw WebhookTransportError.blockedDestination }
        }
        do {
            let response = try await client.post(URI(string: request.url.absoluteString)) { out in
                for (name, value) in request.headers { out.headers.replaceOrAdd(name: name, value: value) }
                out.body = ByteBuffer(data: request.body)
            }
            return WebhookHTTPResponse(statusCode: Int(response.status.code))
        } catch {
            throw WebhookTransportError.network
        }
    }

    private static func resolve(host: String, port: Int) async throws -> [SocketAddress] {
        try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global().async {
                var hints = addrinfo()
                hints.ai_socktype = Int32(SOCK_STREAM.rawValue)
                var result: UnsafeMutablePointer<addrinfo>?
                guard getaddrinfo(host, String(port), &hints, &result) == 0, let first = result else {
                    continuation.resume(throwing: WebhookTransportError.network)
                    return
                }
                defer { freeaddrinfo(result) }
                var out: [SocketAddress] = []
                var cursor: UnsafeMutablePointer<addrinfo>? = first
                while let info = cursor {
                    if let addr = info.pointee.ai_addr {
                        if info.pointee.ai_family == AF_INET {
                            addr.withMemoryRebound(to: sockaddr_in.self, capacity: 1) { out.append(SocketAddress($0.pointee, host: host)) }
                        } else if info.pointee.ai_family == AF_INET6 {
                            addr.withMemoryRebound(to: sockaddr_in6.self, capacity: 1) { out.append(SocketAddress($0.pointee, host: host)) }
                        }
                    }
                    cursor = info.pointee.ai_next
                }
                continuation.resume(returning: out)
            }
        }
    }
}
