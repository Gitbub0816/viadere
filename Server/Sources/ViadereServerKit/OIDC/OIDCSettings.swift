import Fluent
import Foundation
import SQLKit
import Vapor
import ViadereCore

/// The staging OpenID provider's front end (ADR-0024): flag, issuer, authority endpoint.
///
/// `OIDC_PROVIDER_ENABLED` defaults **off** everywhere and is **refused with `ENVIRONMENT=production`** until a new ADR and owner approval (owner decision 6).
/// While off, every `/oidc/*` route and the device routes `/v1/oidc/*` answer `404`. With it on, the api still mints nothing: codes and tokens come only
/// from the authority (`AUTHORITY_URL`), which it reaches with an Entra token for `AUTHORITY_ENTRA_AUDIENCE`.
public struct OIDCProviderSettings: Sendable {
    public var enabled = false
    /// `OIDC_ISSUER`: the exact issuer (`https://id.<staging domain>`, no trailing slash); also the host the `/oidc/*` routes are served on.
    public var issuer = "https://id.viadere.test"
    /// `AUTHORITY_URL`: the authority's internal HTTPS FQDN (`Infra/azure-authority` output `authority_internal_fqdn`).
    public var authorityURL: String?
    /// `AUTHORITY_ENTRA_AUDIENCE`: `api://viadere-authority-<env>`.
    public var authorityAudience: String?
    /// Fail-closed edge limits on challenge creation (ADR-0024 §4): per client IP 10 per minute and 60 per hour, per OIDC client.
    public var ipMinuteRate: RateRule = .perMinute(10)
    public var ipHourRate: RateRule = .perHour(60)
    public var clientRate: RateRule = .perMinute(120, burst: 60)
    /// A pending browser authorization lives at most this long.
    public var authorizationLifetime: TimeInterval = 600

    public init() {}
}

extension ServerConfig {
    /// `OIDC_PROVIDER_ENABLED`, `OIDC_ISSUER`, `AUTHORITY_URL`, `AUTHORITY_ENTRA_AUDIENCE`.
    mutating func applyOIDCEnvironment(_ env: [String: String], environment: DeploymentEnvironment) throws {
        switch env["OIDC_PROVIDER_ENABLED"]?.lowercased() {
        case nil, "", "false": oidc.enabled = false
        case "true":
            guard environment != .production else {
                throw ServerConfigError.invalid("OIDC_PROVIDER_ENABLED (refused with ENVIRONMENT=production: staging only, ADR-0024 section 1)")
            }
            oidc.enabled = true
        default: throw ServerConfigError.invalid("OIDC_PROVIDER_ENABLED (true or false)")
        }
        if let issuer = env["OIDC_ISSUER"], !issuer.isEmpty {
            guard let components = URLComponents(string: issuer), components.scheme == "https", components.host != nil, components.path.isEmpty,
                  components.query == nil, !issuer.hasSuffix("/") else { throw ServerConfigError.invalid("OIDC_ISSUER (https, host only, no trailing slash)") }
            oidc.issuer = issuer
        }
        if let url = env["AUTHORITY_URL"], !url.isEmpty {
            guard let components = URLComponents(string: url), components.scheme == "https", components.host != nil, components.path.isEmpty || components.path == "/",
                  components.query == nil, components.user == nil else { throw ServerConfigError.invalid("AUTHORITY_URL (https://<internal fqdn>)") }
            oidc.authorityURL = url.hasSuffix("/") ? String(url.dropLast()) : url
        }
        if let audience = env["AUTHORITY_ENTRA_AUDIENCE"], !audience.isEmpty {
            guard AzureManagedIdentity.isApplicationAudience(audience) else { throw ServerConfigError.invalid("AUTHORITY_ENTRA_AUDIENCE (api://… or an application id)") }
            oidc.authorityAudience = audience
        }
        if oidc.enabled, environment.isStrict {
            guard env["OIDC_ISSUER"].map({ !$0.isEmpty }) == true else { throw ServerConfigError.missing("OIDC_ISSUER (required when OIDC_PROVIDER_ENABLED is true)") }
            guard oidc.authorityURL != nil else { throw ServerConfigError.missing("AUTHORITY_URL (required when OIDC_PROVIDER_ENABLED is true)") }
            guard oidc.authorityAudience != nil else { throw ServerConfigError.missing("AUTHORITY_ENTRA_AUDIENCE (required when OIDC_PROVIDER_ENABLED is true)") }
        }
    }
}

/// `404` while `OIDC_PROVIDER_ENABLED` is off; `503` when on but no authority is reachable (fail closed, never a local fallback).
enum OIDCGate {
    static func require(_ req: Request) throws -> AuthorityClient {
        guard req.ctx.config.oidc.enabled else { throw APIError.notFound }
        guard let transport = req.application.authorityTransport else { throw APIError(.serviceUnavailable, .unavailable, "Sign-in with Viadere is unavailable right now.") }
        return AuthorityClient(transport: transport)
    }
}

/// One browser authorization in progress (class T, at most 10 minutes). Bound to the browser that started it by a `__Host-` cookie whose hash is stored;
/// the authorization code is held only until that browser is redirected (then the row is deleted).
final class OIDCAuthorizationRecord: Model, @unchecked Sendable {
    static let schema = "oidc_authorizations"
    @ID(key: .id) var id: UUID?
    @Field(key: "binding_hash") var bindingHash: String
    @Field(key: "csrf_hash") var csrfHash: String
    @Field(key: "client_id") var clientId: String
    @Field(key: "client_name") var clientName: String
    @Field(key: "redirect_uri") var redirectURI: String
    @OptionalField(key: "state") var state: String?
    @Field(key: "nonce") var nonce: String
    @Field(key: "code_challenge") var codeChallenge: String
    @OptionalField(key: "acr_values") var acrValues: String?
    /// `pending` → `challenged` → `approved` | `denied`.
    @Field(key: "status") var status: String
    @OptionalField(key: "challenge_id") var challengeId: String?
    @OptionalField(key: "statement") var statement: String?
    @OptionalField(key: "match_code") var matchCode: String?
    @OptionalField(key: "code") var code: String?
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "expires_at") var expiresAt: Date
    init() {}
}

/// `OIDC.v1` (additive): the browser authorization table of the staging OP front end.
struct CreateOIDCFrontEndSchema: AsyncMigration {
    var name: String { "OIDC.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema(OIDCAuthorizationRecord.schema)
            .id()
            .field("binding_hash", .string, .required).field("csrf_hash", .string, .required).field("client_id", .string, .required)
            .field("client_name", .string, .required).field("redirect_uri", .string, .required).field("state", .string).field("nonce", .string, .required)
            .field("code_challenge", .string, .required).field("acr_values", .string).field("status", .string, .required).field("challenge_id", .string)
            .field("statement", .string).field("match_code", .string).field("code", .string)
            .field("created_at", .datetime, .required).field("expires_at", .datetime, .required)
            .unique(on: "challenge_id")
            .create()
        if let sql = db as? any SQLDatabase {
            try await sql.raw("CREATE INDEX IF NOT EXISTS idx_oidc_authorizations_expiry ON oidc_authorizations (expires_at)").run()
        }
    }

    func revert(on db: any Database) async throws { try await db.schema(OIDCAuthorizationRecord.schema).delete() }
}
