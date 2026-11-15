import Fluent
import Foundation
import Vapor
import ViadereCore

/// The api's side of the Viadere code as a CKey Safe Action (SECURITY.md §2.104 "Safe Actions"). **The api signs nothing**: the private authority
/// holds the ES256 issuer key (`ckey-safe-action-signing`, Key Vault) and returns the signed envelope with the OIDC challenge
/// (`AuthorityChallengeCreateResponse.safeAction`). The api checks that the text is the one sign-in envelope for that challenge before storing
/// it on the row, publishes the authority's public key in the issuer key file, and answers request information.
enum CKeySafeActionText {
    /// The stored or drawn text is used only if it parses as `signin.request` for the Viadere app, cross-device, from this link-domain issuer,
    /// naming exactly this challenge, with no params and a sign-in lifetime. Anything else is dropped and the plain link is drawn.
    static func accepted(_ text: String?, challengeId: String, linkDomain: LinkDomain) -> String? {
        guard let text, text.utf8.count <= ViadereSignInSafeAction.maxTextBytes(issuer: linkDomain.host),
              let action = try? CKeySafeAction.parse(text: text), action.requestId == challengeId, action.issuer == linkDomain.host,
              action.app == ViadereSignInSafeAction.appId, action.action == ViadereSignInSafeAction.action, action.scope == .crossDevice,
              action.params.isEmpty, action.expiresAt - action.issuedAt <= UInt64(ViadereSignInSafeAction.lifetimeSeconds) else { return nil }
        return text
    }
}

/// The authority's Safe Action public keys as the api publishes them: fetched over the internal interface (like `OIDCVerificationKeys`), kept
/// for 5 minutes, and dropped when the authority names another issuer than this api's link domain.
actor CKeySafeActionKeys {
    private var cached: [CKeySafeActionKeyFile.Key] = []
    private var fetchedAt: Date?

    func keys(client: AuthorityClient, linkDomain: LinkDomain, now: Date) async -> [CKeySafeActionKeyFile.Key] {
        if let fetchedAt, now.timeIntervalSince(fetchedAt) < 300, now >= fetchedAt { return cached }
        guard let set = try? await client.ckeySafeActionKeys() else { return [] }
        // Only keys a reader can use: this issuer, ES256 (or Ed25519) with a valid public key and a valid key id.
        let usable = set.issuer == linkDomain.host ? set.keys.filter {
            CKeySafeAction.isValid(Array($0.id.utf8)[...], as: .keyId) && (try? CKeySafeAction.PublicKey(alg: $0.alg, hex: $0.publicKey)) != nil
        } : []
        cached = usable
        fetchedAt = now
        return usable
    }
}

extension Application {
    private struct CKeySafeActionKeysKey: StorageKey { typealias Value = CKeySafeActionKeys }

    var ckeySafeActionKeys: CKeySafeActionKeys {
        if let existing = storage[CKeySafeActionKeysKey.self] { return existing }
        let keys = CKeySafeActionKeys()
        storage[CKeySafeActionKeysKey.self] = keys
        return keys
    }
}

/// The issuer's two public routes: its key file and the request information for a cross-device confirmation.
enum CKeySafeActionRoutes {
    static func register(_ app: Application) {
        app.grouped(IPRateLimitMiddleware(name: "web") { $0.rateLimits.directory }).get(".well-known", "ckey-safe-actions.json") { req in try await keyFile(req) }
        app.get("ckey", "requests", ":requestId") { req in try await requestInfo(req) }
    }

    static func json<T: Encodable>(_ value: T, status: HTTPResponseStatus = .ok, cache: String) throws -> Response {
        let response = Response(status: status, body: .init(data: try ViadereJSON.encode(value)))
        response.headers.contentType = .json
        response.headers.replaceOrAdd(name: .cacheControl, value: cache)
        response.headers.replaceOrAdd(name: "X-Robots-Tag", value: "noindex")
        return response
    }

    /// `GET /.well-known/ckey-safe-actions.json`: the authority's public key, cacheable for at most one hour (the spec's limit for readers).
    /// `404` while the provider is off or the authority holds no Safe Action key, so nothing advertises an issuer that signs nothing.
    static func keyFile(_ req: Request) async throws -> Response {
        let client = try OIDCGate.require(req)
        let domain = req.ctx.config.linkDomain
        let keys = await req.application.ckeySafeActionKeys.keys(client: client, linkDomain: domain, now: req.ctx.now)
        guard !keys.isEmpty else { throw APIError.notFound }
        return try json(CKeySafeActionKeyFile(issuer: domain.host, keys: keys, requestInfo: ViadereSignInSafeAction.requestInfoTemplate(issuer: domain.host)),
                        cache: "public, max-age=3600")
    }

    struct Unavailable: Encodable { let error = "not_found" }

    /// `2027-11-01T00:00:00Z`.
    static func timestamp(_ date: Date) -> String {
        let text = ViadereDate.format(date)
        return text.hasSuffix(".000Z") ? String(text.dropLast(5)) + "Z" : text
    }

    /// One answer for every request that is not pending (unknown, expired, used, approved, denied, malformed id): no oracle on which.
    static func notPending() throws -> Response { try json(Unavailable(), status: .notFound, cache: "no-store") }

    /// `GET /ckey/requests/{request_id}` (spec "Request information"): for a sign-in the browser is still waiting on, a coarse device label,
    /// a country when the edge supplied one, and when the browser chose the app. Unauthenticated by design (the reader has no session with
    /// an issuer); limited per client address, fail closed (`oidc-` namespace).
    static func requestInfo(_ req: Request) async throws -> Response {
        _ = try OIDCGate.require(req)
        let ctx = req.ctx
        let ip = ClientIP.rawAddress(req, trustedProxies: ctx.config.trustedProxyCount)
        guard await ctx.limiter.allow("oidc-ckey-request-info", key: ip, rule: ctx.config.oidc.requestInfoRate) else {
            let response = try json(["error": "rate_limited"], status: .tooManyRequests, cache: "no-store")
            return response
        }
        guard let ach = req.parameters.get("requestId"), AuthorityChallengeID.isValid(ach),
              let row = try await OIDCAuthorizationRecord.query(on: req.db).filter(\.$challengeId == ach).first(),
              row.status == "challenged", row.expiresAt > ctx.now,
              // Only a challenge the authority signed a Safe Action for, and only while that envelope is alive.
              let text = CKeySafeActionText.accepted(row.safeAction, challengeId: ach, linkDomain: ctx.config.linkDomain),
              let action = try? CKeySafeAction.parse(text: text),
              UInt64(max(0, ctx.now.timeIntervalSince1970)) < action.expiresAt else { return try notPending() }
        let info = CKeySafeActionRequestInfo(requestId: ach, device: OIDCRequestDevice.sanitized(row.requestedDevice),
                                             location: OIDCRequestDevice.countryName(row.requestedCountry),
                                             requestedAt: timestamp(Date(timeIntervalSince1970: TimeInterval(action.issuedAt))),
                                             status: CKeySafeActionRequestInfo.pending)
        return try json(info, cache: "no-store")
    }
}

/// What the confirmation may say about the browser that asked: a label from a fixed vocabulary and a country. The User-Agent itself and
/// the address are never stored or returned.
enum OIDCRequestDevice {
    static let unknown = "A web browser"

    /// "Chrome on Windows", "Safari on macOS"; `unknown` when either half is not recognised.
    static func label(userAgent: String?) -> String {
        let label = ClientContext.label(for: String((userAgent ?? "").prefix(300)))
        return label.contains("browser") || label.contains("unknown") ? unknown : label
    }

    /// A stored label is shown only if it is still in the vocabulary's shape; anything else becomes `unknown`.
    static func sanitized(_ stored: String?) -> String {
        guard let stored, stored.count <= 40, stored.contains(" on "), stored.unicodeScalars.allSatisfy({ $0.isASCII && ($0.properties.isAlphabetic || $0 == " ") }) else { return unknown }
        return stored
    }

    /// The edge's country for the request, only when it passed the origin lock (`ClientContext`): two letters or nothing.
    static func country(_ req: Request) -> String? { ClientContext(req).country }

    /// "United States" for `US`; `nil` when there is no code or no English name for it.
    static func countryName(_ code: String?) -> String? {
        guard let code, code.count == 2, code.unicodeScalars.allSatisfy({ $0.isASCII && $0.properties.isUppercase }),
              let name = Locale(identifier: "en_US").localizedString(forRegionCode: code), !name.isEmpty, name != code,
              name.count <= CKeySafeActionRequestInfo.maxLocationCharacters else { return nil }
        return name
    }
}

/// `OIDC.v3` (additive): the Safe Action envelope signed for a challenge (signed once, redrawn on every refresh), and what the request
/// information says about the browser that chose the app (a vocabulary label and the edge's country code; never the User-Agent or address).
struct CreateOIDCSafeActionSchema: AsyncMigration {
    var name: String { "OIDC.v3" }
    func prepare(on db: any Database) async throws {
        // One column per statement (SQLite adds one column per ALTER TABLE).
        for column in ["safe_action", "requested_device", "requested_country"] {
            try await db.schema(OIDCAuthorizationRecord.schema).field(FieldKey(stringLiteral: column), .string).update()
        }
    }
    func revert(on db: any Database) async throws {
        for column in ["safe_action", "requested_device", "requested_country"] {
            try await db.schema(OIDCAuthorizationRecord.schema).deleteField(FieldKey(stringLiteral: column)).update()
        }
    }
}
