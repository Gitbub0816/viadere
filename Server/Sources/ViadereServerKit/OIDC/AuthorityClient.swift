import Foundation
import NIOHTTP1
import Vapor
import ViadereCore

/// The api's side of the internal api ↔ authority interface (ADR-0019 §4, TRUST_BOUNDARIES §9): HTTPS to the authority's internal FQDN with an Entra token
/// for the authority's application. The api is a **relay**: it signs nothing and decides nothing; every answer that matters (a code, a grant) is the
/// authority's, after the authority verified device evidence against its own key log.
public protocol AuthorityTransport: Sendable {
    func send(method: NIOHTTP1.HTTPMethod, path: String, contentType: String?, body: Data?) async throws -> (status: Int, body: Data)
}

/// Tokens for an Entra application audience (`AzureManagedIdentity.token(audience:)`).
public protocol ApplicationTokenSource: Sendable {
    func token(audience: String) async throws -> String
}

extension AzureManagedIdentity: ApplicationTokenSource {}

public enum AuthorityClientError: Error, Sendable, Equatable {
    case notConfigured
    case unavailable(status: Int)
    case malformed
}

/// The production transport: `AUTHORITY_URL` (https only, no redirects, the identity-endpoint guard) with `Authorization: Bearer <Entra token>`.
struct HTTPAuthorityTransport: AuthorityTransport {
    let baseURL: String
    let audience: String
    let tokens: any ApplicationTokenSource
    let http: any OutboundHTTP

    func send(method: NIOHTTP1.HTTPMethod, path: String, contentType: String?, body: Data?) async throws -> (status: Int, body: Data) {
        guard baseURL.hasPrefix("https://"), path.hasPrefix("/v1/") else { throw AuthorityClientError.notConfigured }
        var headers = ["Authorization": "Bearer " + (try await tokens.token(audience: audience)), "Accept": "application/json"]
        if let contentType { headers["Content-Type"] = contentType }
        return try await http.send(method: method, url: baseURL + path, headers: headers, body: body)
    }
}

/// Typed calls over a transport.
struct AuthorityClient {
    let transport: any AuthorityTransport

    static func query(_ items: [(String, String)]) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return items.map { "\($0.0)=\($0.1.addingPercentEncoding(withAllowedCharacters: allowed) ?? "")" }.joined(separator: "&")
    }

    private func json<T: Decodable>(_ type: T.Type, _ result: (status: Int, body: Data), expect: Int = 200) throws -> T {
        guard result.status == expect else { throw AuthorityClientError.unavailable(status: result.status) }
        do { return try ViadereJSON.decode(T.self, from: result.body) } catch { throw AuthorityClientError.malformed }
    }

    func checkRedirect(clientId: String, redirectURI: String) async throws -> AuthorityClientCheckResponse {
        let path = AuthorityRoute.oidcClientCheck + "?" + Self.query([("client_id", clientId), ("redirect_uri", redirectURI)])
        return try json(AuthorityClientCheckResponse.self, try await transport.send(method: .GET, path: path, contentType: nil, body: nil))
    }

    func checkLogout(clientId: String, postLogoutRedirectURI: String) async throws -> AuthorityClientCheckResponse {
        let path = AuthorityRoute.oidcClientCheck + "?" + Self.query([("client_id", clientId), ("post_logout_redirect_uri", postLogoutRedirectURI)])
        return try json(AuthorityClientCheckResponse.self, try await transport.send(method: .GET, path: path, contentType: nil, body: nil))
    }

    /// `nil` when the authority refused the request (`4xx`); throws when it is unavailable.
    func createChallenge(_ request: AuthorityChallengeCreateRequest) async throws -> (status: Int, response: AuthorityChallengeCreateResponse?) {
        let result = try await transport.send(method: .POST, path: AuthorityRoute.challenges, contentType: "application/json", body: try ViadereJSON.encode(request))
        if result.status == 201 { return (201, try json(AuthorityChallengeCreateResponse.self, result, expect: 201)) }
        guard (400..<500).contains(result.status) else { throw AuthorityClientError.unavailable(status: result.status) }
        return (result.status, nil)
    }

    func submitEvidence(_ request: AuthorityEvidenceRequest) async throws -> AuthorityEvidenceResponse? {
        let result = try await transport.send(method: .POST, path: AuthorityRoute.evidence, contentType: "application/json", body: try ViadereJSON.encode(request))
        if result.status == 200 { return try json(AuthorityEvidenceResponse.self, result) }
        guard (400..<500).contains(result.status) else { throw AuthorityClientError.unavailable(status: result.status) }
        return nil
    }

    /// The token endpoint's form body, forwarded unchanged; the authority's answer is returned unchanged.
    func token(form: Data) async throws -> (status: Int, body: Data) {
        try await transport.send(method: .POST, path: AuthorityRoute.oidcToken, contentType: "application/x-www-form-urlencoded", body: form)
    }

    func oidcKeys() async throws -> AuthorityPublicKeySet {
        try json(AuthorityPublicKeySet.self, try await transport.send(method: .GET, path: AuthorityRoute.oidcKeys, contentType: nil, body: nil))
    }
}

extension Application {
    private struct AuthorityTransportKey: StorageKey { typealias Value = any AuthorityTransport }
    private struct OIDCKeyCacheKey: StorageKey { typealias Value = OIDCVerificationKeys }

    /// `nil` while OIDC is off or no authority is configured: every OIDC route then fails closed.
    var authorityTransport: (any AuthorityTransport)? {
        get { storage[AuthorityTransportKey.self] }
        set { storage[AuthorityTransportKey.self] = newValue }
    }

    var oidcVerificationKeys: OIDCVerificationKeys {
        if let existing = storage[OIDCKeyCacheKey.self] { return existing }
        let keys = OIDCVerificationKeys()
        storage[OIDCKeyCacheKey.self] = keys
        return keys
    }
}
