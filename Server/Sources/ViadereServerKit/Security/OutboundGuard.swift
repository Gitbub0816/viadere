import Foundation
import NIOCore
import NIOHTTP1
import Vapor

/// SSRF guard for the managed-identity endpoint (WP-B2, ADR-0010, SECURITY.md §1 "managed-identity token theft via SSRF").
///
/// On Azure Container Apps the process can mint Entra tokens for its user-assigned identity by calling `IDENTITY_ENDPOINT`
/// (`http://localhost:42356/msi/token` today) with the `X-IDENTITY-HEADER` secret. Whoever can make the server send a request there, or to the
/// instance metadata service (169.254.169.254) or the Azure wire server (168.63.129.16), can try to steal a token. Only `AzureManagedIdentity`
/// may talk to the identity endpoint, through `IdentityEndpointHTTP`; **every other outbound client** (the webhook transport, the cloud REST
/// clients, the provider clients for SMS, email, RCS and Didit, the domain checker) passes each destination through this guard first, and the
/// guard refuses:
///
/// - the identity endpoint's host, as a name or as any address it is written as;
/// - when the identity endpoint is on loopback (it always is on Container Apps): every loopback address (127.0.0.0/8, ::1), so `localhost`,
///   `127.1`, `[::1]` or a DNS name that resolves to loopback cannot reach it on any port;
/// - always: link-local (169.254.0.0/16, fe80::/10, which holds the metadata service) and the wire server 168.63.129.16;
/// - any host whose **resolved** addresses fall in one of those ranges (a business-controlled DNS name pointing at loopback).
///
/// Development and tests without `IDENTITY_ENDPOINT` keep loopback reachable (local stub servers); link-local stays refused everywhere.
public struct OutboundDestinationGuard: Sendable {
    public enum Refusal: Error, Sendable, Equatable { case identityEndpoint, unresolvable }

    /// Lowercased host names refused outright (the identity endpoint's host).
    let refusedHosts: Set<String>
    /// Whether every loopback address is refused (the identity endpoint lives on loopback).
    let refuseLoopback: Bool
    /// Resolves a host to its addresses (injectable so tests can model DNS rebinding without a network).
    let resolve: @Sendable (_ host: String, _ port: Int) async throws -> [SocketAddress]

    public init(identityEndpoint: String?, resolve: (@Sendable (_ host: String, _ port: Int) async throws -> [SocketAddress])? = nil) {
        var hosts: Set<String> = ["169.254.169.254", "168.63.129.16", "metadata.azure.internal"]
        var loopback = false
        if let raw = identityEndpoint, let url = URL(string: raw), let host = url.host?.lowercased() {
            let bare = host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
            hosts.insert(bare)
            if bare == "localhost" || bare.hasSuffix(".localhost") || Self.isLoopbackLiteral(bare) { loopback = true }
        }
        refusedHosts = hosts
        refuseLoopback = loopback
        self.resolve = resolve ?? { host, port in try await VaporWebhookTransport.resolve(host: host, port: port) }
    }

    /// The guard for this process: built from `IDENTITY_ENDPOINT` (Container Apps) or `MSI_ENDPOINT` (older App Service style), if present.
    public static func fromEnvironment(_ env: [String: String] = ProcessInfo.processInfo.environment) -> OutboundDestinationGuard {
        OutboundDestinationGuard(identityEndpoint: env["IDENTITY_ENDPOINT"].flatMap { $0.isEmpty ? nil : $0 } ?? env["MSI_ENDPOINT"].flatMap { $0.isEmpty ? nil : $0 })
    }

    /// Throws `Refusal.identityEndpoint` when `url` could reach the identity endpoint or the metadata services.
    public func check(_ url: URL) async throws {
        guard let rawHost = url.host?.lowercased(), !rawHost.isEmpty else { throw Refusal.unresolvable }
        let host = rawHost.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
        let port = url.port ?? (url.scheme?.lowercased() == "http" ? 80 : 443)
        if refusedHosts.contains(host) { throw Refusal.identityEndpoint }
        if refuseLoopback, host == "localhost" || host.hasSuffix(".localhost") { throw Refusal.identityEndpoint }
        // Literal addresses (including the shorthand forms inet_aton accepts, such as 127.1 or 2130706433) and DNS names alike: resolve and vet
        // every address. A literal resolves to itself without a network round trip.
        let addresses: [SocketAddress]
        do { addresses = try await resolve(host, port) } catch { throw Refusal.unresolvable }
        for address in addresses where isRefused(address) { throw Refusal.identityEndpoint }
    }

    /// Whether a resolved address is refused.
    func isRefused(_ address: SocketAddress) -> Bool {
        guard let ip = address.ipAddress?.lowercased() else { return true }
        if refusedHosts.contains(ip) { return true }
        switch address {
        case .v4(let a):
            let b = withUnsafeBytes(of: a.address.sin_addr.s_addr) { Array($0) }
            if b[0] == 169 && b[1] == 254 { return true }                    // link-local, instance metadata
            if b == [168, 63, 129, 16] { return true }                         // Azure wire server
            if refuseLoopback && b[0] == 127 { return true }
            return false
        case .v6(let a):
            let b = withUnsafeBytes(of: a.address.sin6_addr) { Array($0) }
            if b[0] == 0xFE && (b[1] & 0xC0) == 0x80 { return true }          // fe80::/10
            if b[0..<10].allSatisfy({ $0 == 0 }) && b[10] == 0xFF && b[11] == 0xFF {   // IPv4-mapped: judge the embedded address
                let v4 = Array(b[12..<16])
                if v4[0] == 169 && v4[1] == 254 { return true }
                if v4 == [168, 63, 129, 16] { return true }
                if refuseLoopback && v4[0] == 127 { return true }
            }
            if refuseLoopback && b[0..<15].allSatisfy({ $0 == 0 }) && b[15] == 1 { return true } // ::1
            return false
        case .unixDomainSocket:
            return true
        }
    }

    static func isLoopbackLiteral(_ host: String) -> Bool {
        host == "::1" || host.hasPrefix("127.") || host == "0:0:0:0:0:0:0:1"
    }
}

/// A Vapor `Client` that refuses identity-endpoint destinations before any connection is made (every provider client is built on it).
public struct GuardedClient: Client {
    let base: any Client
    let destinationGuard: OutboundDestinationGuard

    public init(base: any Client, guard destinationGuard: OutboundDestinationGuard) {
        self.base = base
        self.destinationGuard = destinationGuard
    }

    public var eventLoop: any EventLoop { base.eventLoop }
    public var byteBufferAllocator: ByteBufferAllocator { base.byteBufferAllocator }

    public func delegating(to eventLoop: any EventLoop) -> any Client {
        GuardedClient(base: base.delegating(to: eventLoop), guard: destinationGuard)
    }

    public func logging(to logger: Logger) -> any Client {
        GuardedClient(base: base.logging(to: logger), guard: destinationGuard)
    }

    public func allocating(to byteBufferAllocator: ByteBufferAllocator) -> any Client {
        GuardedClient(base: base.allocating(to: byteBufferAllocator), guard: destinationGuard)
    }

    public func send(_ request: ClientRequest) -> EventLoopFuture<ClientResponse> {
        let base = self.base
        let destinationGuard = self.destinationGuard
        return eventLoop.makeFutureWithTask {
            guard let url = URL(string: request.url.string) else { throw OutboundDestinationGuard.Refusal.unresolvable }
            try await destinationGuard.check(url)
            return try await base.send(request).get()
        }
    }
}
