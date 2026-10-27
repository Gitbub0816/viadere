import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif
import ViadereCore

/// `URLSession`-backed transport.
///
/// - Ephemeral configuration: no persistent cookies, credentials or disk cache.
/// - `urlCache = nil` and `reloadIgnoringLocalCacheData`: API responses are never cached.
/// - TLS 1.2 minimum (the server should negotiate 1.3).
/// - On Apple platforms the session delegate pins the server's SPKI hashes (`PinningSessionDelegate`).
public final class URLSessionTransport: HTTPTransport, @unchecked Sendable {
    private let session: URLSession

    public init(configuration: ViadereConfiguration, timeout: TimeInterval = 20) {
        let config = URLSessionConfiguration.ephemeral
        config.urlCache = nil
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.httpCookieStorage = nil
        config.httpShouldSetCookies = false
        config.timeoutIntervalForRequest = timeout
        config.timeoutIntervalForResource = timeout * 3
        #if canImport(Security) && !os(Linux)
        config.tlsMinimumSupportedProtocolVersion = .TLSv12
        #endif
        #if canImport(Security)
        let delegate = PinningSessionDelegate(pinning: configuration.pinning, failClosed: configuration.failClosedPinning)
        session = URLSession(configuration: config, delegate: delegate, delegateQueue: nil)
        #else
        session = URLSession(configuration: config)
        #endif
    }

    public func send(_ request: HTTPRequest) async throws -> HTTPResponse {
        var urlRequest = URLRequest(url: request.url)
        urlRequest.httpMethod = request.method.rawValue
        urlRequest.cachePolicy = .reloadIgnoringLocalCacheData
        urlRequest.httpShouldHandleCookies = false
        for (name, value) in request.headers { urlRequest.setValue(value, forHTTPHeaderField: name) }
        urlRequest.httpBody = request.body

        let (data, response) = try await session.data(for: urlRequest)
        guard let http = response as? HTTPURLResponse else { throw APIError.transport("non-http") }
        var headers: [String: String] = [:]
        for (key, value) in http.allHeaderFields {
            if let key = key as? String, let value = value as? String { headers[key.lowercased()] = value }
        }
        return HTTPResponse(status: http.statusCode, headers: headers, body: data)
    }
}
