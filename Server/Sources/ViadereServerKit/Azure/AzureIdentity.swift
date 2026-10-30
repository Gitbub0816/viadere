import AsyncHTTPClient
import Foundation
import NIOHTTP1
import Vapor

/// The Entra audiences the server requests tokens for (one token per audience; never a `.default` scope for everything).
public enum AzureResource: String, Sendable, CaseIterable {
    case keyVault = "https://vault.azure.net"
    case serviceBus = "https://servicebus.azure.net"
    case storage = "https://storage.azure.com/"
    /// Azure Database for PostgreSQL (Microsoft Learn, "Use Microsoft Entra ID for authentication", 2026-07-14).
    case postgres = "https://ossrdbms-aad.database.windows.net"
}

public enum AzureIdentityError: Error, Sendable, Equatable {
    /// `IDENTITY_ENDPOINT`, `IDENTITY_HEADER` or `AZURE_CLIENT_ID` is missing.
    case notConfigured
    /// The endpoint answered with an error or something that is not a token.
    case tokenUnavailable(status: Int)
}

/// Bearer tokens for Azure data planes. Replaceable in tests.
public protocol AccessTokenSource: Sendable {
    func token(for resource: AzureResource) async throws -> String
}

/// Container Apps managed identity (WP-B2): `GET {IDENTITY_ENDPOINT}?api-version=2019-08-01&resource=…&client_id=…` with the
/// `X-IDENTITY-HEADER` secret (Microsoft Learn, "Managed identities in Azure Container Apps", 2025-06-03). The user-assigned identity is selected by
/// `AZURE_CLIENT_ID`, so a process never falls back to another identity attached to the app. Tokens are cached per audience and refreshed five
/// minutes before `expires_on`; a token is never logged, persisted or returned to a caller outside the server.
public actor AzureManagedIdentity: AccessTokenSource {
    /// Pinned version of the identity endpoint protocol.
    public static let apiVersion = "2019-08-01"
    static let refreshMargin: TimeInterval = 300

    let endpoint: String
    let identityHeader: String
    let clientId: String
    let http: any OutboundHTTP
    let now: @Sendable () -> Date
    private var cache: [AzureResource: (token: String, expiresAt: Date)] = [:]
    private var inflight: [AzureResource: Task<(String, Date), any Error>] = [:]

    public init(endpoint: String, identityHeader: String, clientId: String, http: (any OutboundHTTP)? = nil, now: @escaping @Sendable () -> Date = { Date() }) {
        self.endpoint = endpoint
        self.identityHeader = identityHeader
        self.clientId = clientId
        self.http = http ?? IdentityEndpointHTTP(endpoint: endpoint)
        self.now = now
    }

    /// `nil` when the process does not run with a managed identity (Fly, development, tests).
    public static func fromEnvironment(_ env: [String: String], http: (any OutboundHTTP)? = nil) -> AzureManagedIdentity? {
        guard let endpoint = env["IDENTITY_ENDPOINT"], !endpoint.isEmpty, let header = env["IDENTITY_HEADER"], !header.isEmpty,
              let client = env["AZURE_CLIENT_ID"], !client.isEmpty else { return nil }
        return AzureManagedIdentity(endpoint: endpoint, identityHeader: header, clientId: client, http: http)
    }

    public func token(for resource: AzureResource) async throws -> String {
        if let cached = cache[resource], now() < cached.expiresAt.addingTimeInterval(-Self.refreshMargin) { return cached.token }
        if let running = inflight[resource] { return try await running.value.0 }
        let task = Task { try await self.fetch(resource) }
        inflight[resource] = task
        defer { inflight[resource] = nil }
        let (token, expiresAt) = try await task.value
        cache[resource] = (token, expiresAt)
        return token
    }

    private func fetch(_ resource: AzureResource) async throws -> (String, Date) {
        var components = URLComponents(string: endpoint)
        var items = components?.queryItems ?? []
        items.append(URLQueryItem(name: "api-version", value: Self.apiVersion))
        items.append(URLQueryItem(name: "resource", value: resource.rawValue))
        items.append(URLQueryItem(name: "client_id", value: clientId))
        components?.queryItems = items
        guard let url = components?.string else { throw AzureIdentityError.notConfigured }
        let response = try await http.send(method: .GET, url: url, headers: ["X-IDENTITY-HEADER": identityHeader, "Metadata": "true"], body: nil)
        guard response.status == 200, let object = try? JSONSerialization.jsonObject(with: response.body) as? [String: Any],
              let token = object["access_token"] as? String, !token.isEmpty else {
            throw AzureIdentityError.tokenUnavailable(status: response.status)
        }
        // `expires_on` is epoch seconds (a string on Container Apps, a number elsewhere); a missing value means "use once".
        let expires: Date
        if let text = object["expires_on"] as? String, let seconds = Double(text) { expires = Date(timeIntervalSince1970: seconds) }
        else if let seconds = object["expires_on"] as? Double { expires = Date(timeIntervalSince1970: seconds) }
        else if let seconds = object["expires_in"].flatMap({ ($0 as? String).flatMap(Double.init) ?? ($0 as? Double) }) { expires = now().addingTimeInterval(seconds) }
        else { expires = now() }
        return (token, expires)
    }
}

/// The only HTTP client allowed to reach the identity endpoint: it sends exclusively to the configured endpoint (same scheme, host, port and path)
/// and to nothing else, so it cannot be turned into a general client.
struct IdentityEndpointHTTP: OutboundHTTP {
    let endpoint: String

    func send(method: NIOHTTP1.HTTPMethod, url: String, headers: [String: String], body: Data?) async throws -> (status: Int, body: Data) {
        guard let configured = URLComponents(string: endpoint), let target = URLComponents(string: url),
              configured.scheme == target.scheme, configured.host == target.host, configured.port == target.port, configured.path == target.path,
              method == .GET else { throw AzureIdentityError.notConfigured }
        var configuration = HTTPClient.Configuration()
        configuration.redirectConfiguration = .disallow
        configuration.timeout = .init(connect: .seconds(3), read: .seconds(10))
        let client = HTTPClient(eventLoopGroupProvider: .singleton, configuration: configuration)
        do {
            var out = HTTPClientRequest(url: url)
            out.method = .GET
            for (name, value) in headers { out.headers.replaceOrAdd(name: name, value: value) }
            let response = try await client.execute(out, timeout: .seconds(10))
            let bytes = try await response.body.collect(upTo: 64 * 1024)
            try await client.shutdown()
            return (Int(response.status.code), Data(bytes.readableBytesView))
        } catch {
            try? await client.shutdown()
            throw error
        }
    }
}
