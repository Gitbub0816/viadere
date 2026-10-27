import Foundation
import ViadereCore

/// Typed API client over ViadereCore's endpoint catalog.
///
/// - `bearer` / `deviceSignedBearer` routes carry `Authorization: Bearer …`.
/// - `deviceSigned` / `deviceSignedBearer` routes carry `VIADERE-SIG-V1` headers, re-signed on every attempt
///   (fresh timestamp + nonce, so a retry is never mistaken for a replay).
/// - A `401` triggers one single-flight token refresh and one retry.
public final class APIClient: Sendable {
    private let executor: RequestExecutor
    private let sessions: SessionManager
    private let onDeviceRejected: @Sendable () -> Void

    public init(executor: RequestExecutor, sessions: SessionManager, onDeviceRejected: @escaping @Sendable () -> Void = {}) {
        self.executor = executor
        self.sessions = sessions
        self.onDeviceRejected = onDeviceRejected
    }

    public var sessionManager: SessionManager { sessions }

    // MARK: Typed calls

    /// Endpoint with a JSON request body.
    public func call<Req: Encodable & Sendable, Res: Decodable & Sendable>(
        _ endpoint: Endpoint<Req, Res>, params: [String: String] = [:], query: [(String, String)] = [], body: Req
    ) async throws -> Res {
        let data = try await perform(endpoint.descriptor, params: params, query: query, body: try encode(body))
        return try decode(Res.self, from: data)
    }

    /// Endpoint without a request body (`EmptyBody`).
    public func call<Res: Decodable & Sendable>(
        _ endpoint: Endpoint<EmptyBody, Res>, params: [String: String] = [:], query: [(String, String)] = []
    ) async throws -> Res {
        // POST/PUT with no payload send `{}` so JSON-decoding servers accept them; GET/DELETE send nothing.
        let hasBody = endpoint.method == .POST || endpoint.method == .PUT || endpoint.method == .PATCH
        let data = try await perform(endpoint.descriptor, params: params, query: query, body: hasBody ? Data("{}".utf8) : nil)
        return try decode(Res.self, from: data)
    }

    /// Binary responses (Wallet `.pkpass`).
    public func data(_ endpoint: Endpoint<EmptyBody, Data>, params: [String: String] = [:]) async throws -> Data {
        try await perform(endpoint.descriptor, params: params, query: [], body: nil)
    }

    // MARK: Core

    private func perform(_ descriptor: AnyEndpoint, params: [String: String], query: [(String, String)], body: Data?) async throws -> Data {
        let path: String
        do { path = try descriptor.path(params, query: query) } catch { throw APIError.invalidRequest("path") }
        let usesBearer = descriptor.auth == .bearer || descriptor.auth == .deviceSignedBearer
        let usesSignature = descriptor.auth == .deviceSigned || descriptor.auth == .deviceSignedBearer

        var attempt = 0
        var rejectedSignature = false
        while true {
            var bearer: String?
            if usesBearer { bearer = try await sessions.validAccessToken() }
            let response = try await executor.run(descriptor, pathAndQuery: path, body: body, bearer: bearer)
            if (200..<300).contains(response.status) { return response.body }

            let error = RequestExecutor.error(from: response)
            // A rejected device signature is not a token problem: retry once with a fresh nonce/timestamp, then
            // conclude the server no longer trusts this device (revoked) and say so.
            if usesSignature, error.code == .signatureInvalid {
                if rejectedSignature {
                    onDeviceRejected()
                    throw APIError.deviceRejected
                }
                rejectedSignature = true
                continue
            }
            if response.status == 401, attempt == 0 {
                attempt += 1
                if usesBearer {
                    _ = try await sessions.refresh(afterRejecting: bearer)
                    continue
                }
                if usesSignature, error.code == .clockSkew { continue }
            }
            if response.status == 401 { throw APIError.sessionExpired }
            throw error
        }
    }

    private func encode<T: Encodable>(_ value: T) throws -> Data {
        do { return try ViadereJSON.encode(value) } catch { throw APIError.invalidRequest("encode") }
    }

    private func decode<T: Decodable>(_ type: T.Type, from data: Data) throws -> T {
        if type == Data.self, let data = data as? T { return data }
        if data.isEmpty, let empty = EmptyBody() as? T { return empty }
        do { return try ViadereJSON.decode(type, from: data) } catch { throw APIError.decoding(String(describing: type)) }
    }
}
