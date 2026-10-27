import AsyncHTTPClient
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

    /// Whether an IPv4 address (4 bytes) is a public unicast address: not "this network", private, loopback, link-local, CGNAT,
    /// IETF protocol assignments, documentation (TEST-NET), benchmarking, multicast, reserved or broadcast.
    static func isPublicIPv4(_ b: [UInt8]) -> Bool {
        guard b.count == 4 else { return false }
        switch (b[0], b[1], b[2]) {
        case (0, _, _), (10, _, _), (127, _, _): return false
        case (100, 64...127, _): return false          // 100.64.0.0/10 carrier-grade NAT
        case (169, 254, _): return false               // link-local and cloud metadata
        case (172, 16...31, _): return false
        case (192, 0, 0), (192, 0, 2): return false    // 192.0.0.0/24 IETF protocol assignments, TEST-NET-1
        case (192, 88, 99): return false               // 6to4 relay anycast
        case (192, 168, _): return false
        case (198, 18...19, _): return false           // benchmarking
        case (198, 51, 100), (203, 0, 113): return false // TEST-NET-2, TEST-NET-3
        case (224...255, _, _): return false           // multicast, reserved, broadcast
        default: return true
        }
    }

    /// Whether a resolved address is public. IPv6 addresses that embed an IPv4 address (IPv4-mapped `::ffff:0:0/96`, NAT64
    /// `64:ff9b::/96`, 6to4 `2002::/16`, Teredo, IPv4-compatible) get the **same** IPv4 check on the embedded address.
    static func isPublic(_ address: SocketAddress) -> Bool {
        switch address {
        case .v4(let a):
            let raw = a.address.sin_addr.s_addr
            return isPublicIPv4(withUnsafeBytes(of: raw) { Array($0) })
        case .v6(let a):
            return isPublicIPv6(withUnsafeBytes(of: a.address.sin6_addr) { Array($0) })
        case .unixDomainSocket: return false
        }
    }

    static func isPublicIPv6(_ b: [UInt8]) -> Bool {
        guard b.count == 16 else { return false }
        if b.allSatisfy({ $0 == 0 }) { return false }                                   // ::
        if b[0..<15].allSatisfy({ $0 == 0 }) && b[15] == 1 { return false }             // ::1
        if b[0..<12].allSatisfy({ $0 == 0 }) { return false }                           // ::/96 IPv4-compatible (deprecated)
        if b[0] == 0xFE && (b[1] & 0xC0) == 0x80 { return false }                       // fe80::/10 link-local
        if b[0] == 0xFE && (b[1] & 0xC0) == 0xC0 { return false }                       // fec0::/10 site-local (deprecated)
        if (b[0] & 0xFE) == 0xFC { return false }                                       // fc00::/7 unique local
        if b[0] == 0xFF { return false }                                                // ff00::/8 multicast
        if b[0] == 0x01 && b[1..<8].allSatisfy({ $0 == 0 }) { return false }            // 100::/64 discard-only
        if b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8 { return false } // 2001:db8::/32 documentation
        if b[0] == 0x20 && b[1] == 0x01 && b[2] == 0 && b[3] == 0 { return false }      // 2001::/32 Teredo
        // IPv4-mapped (::ffff:a.b.c.d): evaluate the embedded IPv4 address.
        if b[0..<10].allSatisfy({ $0 == 0 }) && b[10] == 0xFF && b[11] == 0xFF { return isPublicIPv4(Array(b[12..<16])) }
        // NAT64 well-known prefix 64:ff9b::/96 embeds the IPv4 address in the last 32 bits; 64:ff9b:1::/48 is local-use NAT64.
        if b[0] == 0x00 && b[1] == 0x64 && b[2] == 0xFF && b[3] == 0x9B {
            if b[4..<12].allSatisfy({ $0 == 0 }) { return isPublicIPv4(Array(b[12..<16])) }
            if b[4] == 0x00 && b[5] == 0x01 { return false }
        }
        // 6to4 2002::/16 embeds the IPv4 address in bits 16-47.
        if b[0] == 0x20 && b[1] == 0x02 { return isPublicIPv4(Array(b[2..<6])) }
        return true
    }
}

/// Real transport using AsyncHTTPClient: no redirects, short timeouts, and **DNS pinning**. The host is resolved once, every
/// address is vetted (`WebhookURLPolicy.isPublic`), and the connection is made to the vetted address itself while TLS server name
/// and `Host` stay the original host name. A second resolution (the DNS-rebinding window between "check" and "connect") never happens.
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
        guard !allowInsecure else {
            // Development and tests only (loopback targets are allowed there): no pinning.
            do {
                let response = try await client.post(URI(string: request.url.absoluteString)) { out in
                    for (name, value) in request.headers { out.headers.replaceOrAdd(name: name, value: value) }
                    out.body = ByteBuffer(data: request.body)
                }
                return WebhookHTTPResponse(statusCode: Int(response.status.code))
            } catch { throw WebhookTransportError.network }
        }
        let port = request.url.port ?? 443
        let addresses = try await Self.resolve(host: host, port: port)
        guard !addresses.isEmpty, addresses.allSatisfy(WebhookURLPolicy.isPublic), let pinned = addresses.first?.ipAddress else {
            throw WebhookTransportError.blockedDestination
        }
        var configuration = HTTPClient.Configuration()
        configuration.redirectConfiguration = .disallow
        configuration.timeout = .init(connect: .seconds(5), read: .seconds(10))
        configuration.dnsOverride = [host: pinned]
        let pinnedClient = HTTPClient(eventLoopGroupProvider: .singleton, configuration: configuration)
        do {
            var out = HTTPClientRequest(url: request.url.absoluteString)
            out.method = .POST
            for (name, value) in request.headers { out.headers.replaceOrAdd(name: name, value: value) }
            out.body = .bytes(request.body)
            let response = try await pinnedClient.execute(out, timeout: .seconds(15))
            try await pinnedClient.shutdown()
            return WebhookHTTPResponse(statusCode: Int(response.status.code))
        } catch {
            try? await pinnedClient.shutdown()
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
