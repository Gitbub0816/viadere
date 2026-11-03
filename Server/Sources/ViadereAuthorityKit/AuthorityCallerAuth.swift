@preconcurrency import Crypto
import _CryptoExtras
import Foundation
import NIOHTTP1
import Vapor
import ViadereCore
import ViadereServiceSupport

/// Who called (ADR-0019 §4.2): an Entra workload identity on the authority's allow-list, with the app roles its token carries.
public struct AuthorityCaller: Sendable, Equatable {
    /// `api` or `worker` (the allow-list entry the `oid` matched).
    public var name: String
    public var objectId: String
    public var roles: Set<String>

    public init(name: String, objectId: String, roles: Set<String>) {
        self.name = name
        self.objectId = objectId
        self.roles = roles
    }
}

public enum AuthorityCallerError: Error, Sendable, Equatable {
    case missingToken
    case invalidToken(String)
    case notAllowed
}

/// Verifies the bearer token of an internal call. Replaceable in tests.
public protocol AuthorityCallerVerifier: Sendable {
    func verify(bearer: String) async throws -> AuthorityCaller
}

/// The signing keys of the Entra tenant (`https://login.microsoftonline.com/{tenant}/discovery/v2.0/keys`), RSA only.
public protocol EntraSigningKeySource: Sendable {
    func key(kid: String) async throws -> _RSA.Signing.PublicKey?
}

/// Entra access tokens for the authority's application (`AUTHORITY_ENTRA_AUDIENCE`): RS256 only, `kid` from the tenant's key set, issuer exactly the
/// tenant's v1 or v2 issuer, `aud` exactly the configured audience, `exp`/`nbf` with 60 s skew, `tid` the tenant, `oid` on the configured allow-list.
/// **A token is necessary, never sufficient**: routes then check the role, and evidence is verified against the authority's own records.
public struct EntraCallerVerifier: AuthorityCallerVerifier {
    let tenantId: String
    let audience: String
    let callers: [String: String]
    let keys: any EntraSigningKeySource
    let now: @Sendable () -> Date

    public init(tenantId: String, audience: String, callers: [String: String], keys: any EntraSigningKeySource, now: @escaping @Sendable () -> Date = { Date() }) {
        self.tenantId = tenantId.lowercased()
        self.audience = audience
        self.callers = callers
        self.keys = keys
        self.now = now
    }

    public func verify(bearer: String) async throws -> AuthorityCaller {
        guard bearer.utf8.count <= 8192 else { throw AuthorityCallerError.invalidToken("size") }
        let segments = bearer.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        guard segments.count == 3, let headerBytes = Base64URL.decode(segments[0]), let payloadBytes = Base64URL.decode(segments[1]),
              let signature = Base64URL.decode(segments[2]),
              let header = try? JSONSerialization.jsonObject(with: headerBytes) as? [String: Any],
              let claims = try? JSONSerialization.jsonObject(with: payloadBytes) as? [String: Any] else { throw AuthorityCallerError.invalidToken("encoding") }
        // RS256 only; no symmetric or `none`; no key carried in the token.
        guard header["alg"] as? String == "RS256", header["jku"] == nil, header["jwk"] == nil, header["x5u"] == nil, header["crit"] == nil,
              let kid = header["kid"] as? String, !kid.isEmpty else { throw AuthorityCallerError.invalidToken("header") }
        guard let key = try await keys.key(kid: kid),
              key.isValidSignature(_RSA.Signing.RSASignature(rawRepresentation: signature), for: Data((segments[0] + "." + segments[1]).utf8), padding: .insecurePKCS1v1_5) else {
            throw AuthorityCallerError.invalidToken("signature")
        }
        let issuers = ["https://login.microsoftonline.com/\(tenantId)/v2.0", "https://sts.windows.net/\(tenantId)/"]
        guard let iss = claims["iss"] as? String, issuers.contains(iss) else { throw AuthorityCallerError.invalidToken("issuer") }
        guard (claims["tid"] as? String)?.lowercased() == tenantId else { throw AuthorityCallerError.invalidToken("tenant") }
        guard let aud = claims["aud"] as? String, aud == audience else { throw AuthorityCallerError.invalidToken("audience") }
        let t = now().timeIntervalSince1970
        guard let exp = (claims["exp"] as? NSNumber)?.doubleValue, t <= exp + 60 else { throw AuthorityCallerError.invalidToken("expired") }
        if let nbf = (claims["nbf"] as? NSNumber)?.doubleValue, t + 60 < nbf { throw AuthorityCallerError.invalidToken("not yet valid") }
        guard let oid = (claims["oid"] as? String)?.lowercased(), let name = callers.first(where: { $0.value == oid })?.key else { throw AuthorityCallerError.notAllowed }
        let roles = Set((claims["roles"] as? [String]) ?? [])
        return AuthorityCaller(name: name, objectId: oid, roles: roles)
    }
}

/// Entra signing keys over the allow-listed outbound client; cached for an hour, refetched on an unknown `kid` at most once per 5 minutes.
public actor EntraJWKSKeySource: EntraSigningKeySource {
    let url: String
    let http: any OutboundHTTP
    let now: @Sendable () -> Date
    private var keys: [String: _RSA.Signing.PublicKey] = [:]
    private var fetchedAt: Date?

    public init(tenantId: String, http: any OutboundHTTP, now: @escaping @Sendable () -> Date = { Date() }) {
        url = "https://login.microsoftonline.com/\(tenantId.lowercased())/discovery/v2.0/keys"
        self.http = http
        self.now = now
    }

    public func key(kid: String) async throws -> _RSA.Signing.PublicKey? {
        if let fetchedAt, now().timeIntervalSince(fetchedAt) < 3600, let key = keys[kid] { return key }
        if let fetchedAt, now().timeIntervalSince(fetchedAt) < 300 { return keys[kid] }
        let response = try await http.send(method: .GET, url: url, headers: [:], body: nil)
        guard response.status == 200, let object = try? JSONSerialization.jsonObject(with: response.body) as? [String: Any],
              let list = object["keys"] as? [[String: Any]] else { throw AuthorityCallerError.invalidToken("keys unavailable") }
        var fresh: [String: _RSA.Signing.PublicKey] = [:]
        for jwk in list {
            guard jwk["kty"] as? String == "RSA", let id = jwk["kid"] as? String, let n = (jwk["n"] as? String).flatMap(Base64URL.decode),
                  let e = (jwk["e"] as? String).flatMap(Base64URL.decode), let key = try? _RSA.Signing.PublicKey(n: n, e: e) else { continue }
            fresh[id] = key
        }
        keys = fresh
        fetchedAt = now()
        return fresh[kid]
    }
}

/// The authority's outbound client in **allow-list mode** (TRUST_BOUNDARIES §9): only the hosts in `AUTHORITY_OUTBOUND_ALLOWLIST` (Entra login,
/// its Key Vault, its database), https only, after the identity-endpoint guard. Anything else is refused before a connection is made.
public struct AllowListOutboundHTTP: OutboundHTTP {
    public struct Refused: Error, Sendable {}
    let allowed: Set<String>
    let base: any OutboundHTTP

    public init(allowed: Set<String>, base: any OutboundHTTP) {
        self.allowed = Set(allowed.map { $0.lowercased() })
        self.base = base
    }

    public func send(method: NIOHTTP1.HTTPMethod, url: String, headers: [String: String], body: Data?) async throws -> (status: Int, body: Data) {
        guard let components = URLComponents(string: url), components.scheme == "https", let host = components.host?.lowercased(), allowed.contains(host),
              components.user == nil, components.password == nil else { throw Refused() }
        return try await base.send(method: method, url: url, headers: headers, body: body)
    }
}

/// Requires a verified caller holding `role` (ADR-0019 §4.2: the worker reaches only `revocations`; ADR-0028 §9, ST-AUTH-18).
struct AuthorityRoleMiddleware: AsyncMiddleware {
    let verifier: any AuthorityCallerVerifier
    let roles: Set<AuthorityAppRole>
    /// Which allow-list entries may use the route at all (the role and the identity must both fit).
    let callerNames: Set<String>

    func respond(to request: Request, chainingTo next: any AsyncResponder) async throws -> Response {
        guard let bearer = request.headers.bearerAuthorization?.token else { throw Abort(.unauthorized, reason: "caller_unauthenticated") }
        let caller: AuthorityCaller
        do { caller = try await verifier.verify(bearer: bearer) } catch {
            request.logger.warning("authority caller refused", metadata: ["reason": "\(error)"])
            throw Abort(.unauthorized, reason: "caller_unauthenticated")
        }
        guard callerNames.contains(caller.name), !roles.isDisjoint(with: Set(caller.roles.compactMap(AuthorityAppRole.init(rawValue:)))) else {
            throw Abort(.forbidden, reason: "caller_forbidden")
        }
        request.storage[CallerKey.self] = caller
        return try await next.respond(to: request)
    }

    struct CallerKey: StorageKey { typealias Value = AuthorityCaller }
}

extension Request {
    var authorityCaller: AuthorityCaller? { storage[AuthorityRoleMiddleware.CallerKey.self] }
}
