import AsyncHTTPClient
import Foundation
import NIOCore
import NIOHTTP1

/// A tiny HTTP seam for the Azure data-plane REST calls (Key Vault, Blob Storage, Service Bus). Replaceable in tests (`Overrides.outboundHTTP`);
/// the real one uses Vapor's client over TLS behind the identity-endpoint guard.
public protocol OutboundHTTP: Sendable {
    func send(method: NIOHTTP1.HTTPMethod, url: String, headers: [String: String], body: Data?) async throws -> (status: Int, body: Data)
    /// The same call, also returning the response headers (lowercased names). Service Bus answers a receive with the lock `Location` and the
    /// `BrokerProperties` in headers.
    func sendReturningHeaders(method: NIOHTTP1.HTTPMethod, url: String, headers: [String: String], body: Data?) async throws -> (status: Int, headers: [String: String], body: Data)
}

extension OutboundHTTP {
    public func sendReturningHeaders(method: NIOHTTP1.HTTPMethod, url: String, headers: [String: String], body: Data?) async throws -> (status: Int, headers: [String: String], body: Data) {
        let response = try await send(method: method, url: url, headers: headers, body: body)
        return (response.status, [:], response.body)
    }
}

/// An `OutboundHTTP` on AsyncHTTPClient for the boot path (before Vapor's client exists): https only, no redirects, short timeouts, behind the
/// identity-endpoint guard.
public struct StandaloneOutboundHTTP: OutboundHTTP {
    let destinationGuard: OutboundDestinationGuard

    public init(guard destinationGuard: OutboundDestinationGuard) { self.destinationGuard = destinationGuard }

    public func send(method: NIOHTTP1.HTTPMethod, url: String, headers: [String: String], body: Data?) async throws -> (status: Int, body: Data) {
        guard url.hasPrefix("https://"), let parsed = URL(string: url) else { throw OutboundDestinationGuard.Refusal.unresolvable }
        try await destinationGuard.check(parsed)
        var configuration = HTTPClient.Configuration()
        configuration.redirectConfiguration = .disallow
        configuration.timeout = .init(connect: .seconds(5), read: .seconds(15))
        let client = HTTPClient(eventLoopGroupProvider: .singleton, configuration: configuration)
        do {
            var request = HTTPClientRequest(url: url)
            request.method = method
            for (name, value) in headers { request.headers.replaceOrAdd(name: name, value: value) }
            if let body { request.body = .bytes(ByteBuffer(data: body)) }
            let response = try await client.execute(request, timeout: .seconds(20))
            let bytes = try await response.body.collect(upTo: 256 * 1024)
            try await client.shutdown()
            return (Int(response.status.code), Data(bytes.readableBytesView))
        } catch {
            try? await client.shutdown()
            throw error
        }
    }
}
