import Fluent
import Foundation
import SQLKit
import ViadereCore

// The authority's own database `viadere_authority` (ADR-0019 §4.5): the api has no CONNECT on it. Key-log entries, grants and audit events are
// append-only (database triggers), like the ordinary tier's audit tables.

/// An account the authority knows. `id` is the account id (minted at genesis, or imported once from the reviewed snapshot: ADR-0023 §4 migration).
final class AuthorityAccount: Model, @unchecked Sendable {
    static let schema = "authority_accounts"
    @ID(custom: "id", generatedBy: .user) var id: UUID?
    @Field(key: "account_ref") var accountRef: String
    /// `imported` (one-time import, residual R-16) or `genesis`.
    @Field(key: "origin") var origin: String
    @Field(key: "frozen") var frozen: Bool
    @Field(key: "created_at") var createdAt: Date
    init() {}
}

/// One append-only key-log entry, hash-chained per account (`entry_hash = SHA-256(prev_hash ‖ canonical(entry))`).
final class AuthorityKeylogEntry: Model, @unchecked Sendable {
    static let schema = "authority_keylog_entries"
    @ID(key: .id) var id: UUID?
    @Field(key: "account_ref") var accountRef: String
    @Field(key: "seq") var seq: Int
    /// `imported`, `key_revoked` (the other ADR-0023 §4 entry types arrive with genesis and recovery).
    @Field(key: "type") var type: String
    @Field(key: "kid") var kid: String
    @Field(key: "public_key") var publicKey: String
    @Field(key: "key_purpose") var keyPurpose: String
    @Field(key: "detail") var detail: String
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "prev_hash") var prevHash: String
    @Field(key: "entry_hash") var entryHash: String
    init() {}
}

/// The current view of the log: one row per key the authority accepts. Written in the same transaction as the log entry that changes it.
final class AuthorityKey: Model, @unchecked Sendable {
    static let schema = "authority_keys"
    @ID(custom: "kid", generatedBy: .user) var id: String?
    @Field(key: "account_ref") var accountRef: String
    @Field(key: "public_key") var publicKey: String
    /// `approvalBiometric` or `approvalUserPresence` (the purpose fixes which `uv` value the key may claim).
    @Field(key: "key_purpose") var keyPurpose: String
    @Field(key: "hardware_attested") var hardwareAttested: Bool
    @Field(key: "grant_capable") var grantCapable: Bool
    @Field(key: "usable_from") var usableFrom: Date
    @OptionalField(key: "revoked_at") var revokedAt: Date?
    init() {}
}

/// An authority challenge (ADR-0023 §3, §7): pending → used | failed | expired. The display is the **authority-built** object.
final class AuthorityChallenge: Model, @unchecked Sendable {
    static let schema = "authority_challenges"
    @ID(custom: "id", generatedBy: .user) var id: String?
    @Field(key: "purpose") var purpose: String
    @Field(key: "nonce") var nonce: String
    @Field(key: "state") var state: String
    @Field(key: "display") var display: String
    @Field(key: "display_digest") var displayDigest: String
    @Field(key: "tenant_id") var tenantId: String
    @Field(key: "client_id") var clientId: String
    /// `oidc_login`: the exact redirect URI; `link_open`: the exact return URL.
    @Field(key: "target_url") var targetURL: String
    @OptionalField(key: "match_code") var matchCode: String?
    @Field(key: "match_failures") var matchFailures: Int
    @OptionalField(key: "code_challenge") var codeChallenge: String?
    @OptionalField(key: "oidc_nonce") var oidcNonce: String?
    @OptionalField(key: "require_passkey") var requirePasskey: Bool?
    @OptionalField(key: "delivery_id") var deliveryId: String?
    @OptionalField(key: "link_purpose") var linkPurpose: String?
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "used_at") var usedAt: Date?
    init() {}
}

/// OIDC relying parties, registered only by the reviewer-gated admin job (ADR-0024 §3).
final class AuthorityOIDCClient: Model, @unchecked Sendable {
    static let schema = "authority_oidc_clients"
    @ID(custom: "client_id", generatedBy: .user) var id: String?
    @Field(key: "tenant_id") var tenantId: String
    @Field(key: "display_name") var displayName: String
    /// JSON array of exact strings.
    @Field(key: "redirect_uris") var redirectURIs: String
    @Field(key: "post_logout_redirect_uris") var postLogoutRedirectURIs: String
    @Field(key: "sector_identifier") var sectorIdentifier: String
    /// The client's public JWKS (`private_key_jwt`), JSON.
    @Field(key: "jwks") var jwks: String
    @Field(key: "id_token_alg") var idTokenAlg: String
    @Field(key: "require_passkey") var requirePasskey: Bool
    @Field(key: "require_biometric") var requireBiometric: Bool
    @Field(key: "status") var status: String
    @Field(key: "change_commit") var changeCommit: String
    @Field(key: "created_at") var createdAt: Date
    init() {}
}

/// Link-service clients (ADR-0021 §5), registered only by the admin job. `business_id` feeds the grant `sub` (the tenant's `subject_ref`).
final class AuthorityLinkClient: Model, @unchecked Sendable {
    static let schema = "authority_link_clients"
    @ID(custom: "client_id", generatedBy: .user) var id: String?
    @Field(key: "tenant_id") var tenantId: String
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "tenant_name") var tenantName: String
    @Field(key: "display_name") var displayName: String
    @Field(key: "return_urls") var returnURLs: String
    @Field(key: "require_biometric") var requireBiometric: Bool
    @Field(key: "status") var status: String
    @Field(key: "change_commit") var changeCommit: String
    @Field(key: "created_at") var createdAt: Date
    init() {}
}

/// Authorization codes: stored as a hash, 60 s, single use (ADR-0024 §6).
final class AuthorityOIDCCode: Model, @unchecked Sendable {
    static let schema = "authority_oidc_codes"
    @ID(custom: "code_hash", generatedBy: .user) var id: String?
    @Field(key: "client_id") var clientId: String
    @Field(key: "redirect_uri") var redirectURI: String
    @Field(key: "code_challenge") var codeChallenge: String
    @Field(key: "nonce") var nonce: String
    @Field(key: "acr") var acr: String
    @Field(key: "amr") var amr: String
    @Field(key: "auth_time") var authTime: Date
    @Field(key: "account_id") var accountId: UUID
    @Field(key: "account_ref") var accountRef: String
    @Field(key: "kid") var kid: String
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "used_at") var usedAt: Date?
    init() {}
}

/// Every issued grant and token (append-only; class E retention, ADR-0026). No token bytes, only identifiers.
final class AuthorityGrantRecord: Model, @unchecked Sendable {
    static let schema = "authority_grants"
    @ID(custom: "jti", generatedBy: .user) var id: String?
    /// `grant`, `id_token`, `access_token`.
    @Field(key: "kind") var kind: String
    /// RFC 7638 thumbprint of the signing key.
    @Field(key: "kid") var kid: String
    @Field(key: "client_id") var clientId: String
    @Field(key: "account_ref") var accountRef: String
    @Field(key: "sub_hash") var subHash: String
    @Field(key: "acr") var acr: String
    @Field(key: "policy_version") var policyVersion: String
    @Field(key: "challenge_id") var challengeId: String
    @Field(key: "created_at") var createdAt: Date
    init() {}
}

/// Single-use values with an expiry (client-assertion `jti`s).
final class AuthorityReplayRecord: Model, @unchecked Sendable {
    static let schema = "authority_replay"
    @ID(custom: "key", generatedBy: .user) var id: String?
    @Field(key: "expires_at") var expiresAt: Date
    init() {}
}

/// The reviewed key-version pins (ADR-0028 §2): the authority signs only with `name/version` from here, and only if the version's RFC 7638 thumbprint
/// equals the pinned thumbprint (from the attested inventory) — checked at startup, fail closed.
final class AuthorityKeyPin: Model, @unchecked Sendable {
    static let schema = "authority_key_pins"
    @ID(custom: "name", generatedBy: .user) var id: String?
    @Field(key: "version") var version: String
    @Field(key: "thumbprint") var thumbprint: String
    @Field(key: "change_commit") var changeCommit: String
    @Field(key: "pinned_at") var pinnedAt: Date
    init() {}
}

/// Authority audit events (append-only): every decision, allow or deny, with reason; never a secret, nonce, code or token.
final class AuthorityAuditEvent: Model, @unchecked Sendable {
    static let schema = "authority_audit_events"
    @ID(key: .id) var id: UUID?
    @Field(key: "event") var event: String
    @Field(key: "outcome") var outcome: String
    @OptionalField(key: "reason") var reason: String?
    @OptionalField(key: "tenant_id") var tenantId: String?
    @OptionalField(key: "account_ref") var accountRef: String?
    @OptionalField(key: "challenge_id") var challengeId: String?
    @OptionalField(key: "kid") var kid: String?
    @OptionalField(key: "policy_version") var policyVersion: String?
    @OptionalField(key: "caller") var caller: String?
    @OptionalField(key: "detail") var detail: String?
    @Field(key: "at") var at: Date
    init() {}
}

/// `Authority.v1`: the authority schema (forward-only).
struct CreateAuthoritySchema: AsyncMigration {
    var name: String { "Authority.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema(AuthorityAccount.schema)
            .field("id", .uuid, .identifier(auto: false))
            .field("account_ref", .string, .required).field("origin", .string, .required).field("frozen", .bool, .required)
            .field("created_at", .datetime, .required)
            .unique(on: "account_ref").create()
        try await db.schema(AuthorityKeylogEntry.schema)
            .id()
            .field("account_ref", .string, .required).field("seq", .int, .required).field("type", .string, .required).field("kid", .string, .required)
            .field("public_key", .string, .required).field("key_purpose", .string, .required).field("detail", .string, .required)
            .field("created_at", .datetime, .required).field("prev_hash", .string, .required).field("entry_hash", .string, .required)
            .unique(on: "account_ref", "seq").create()
        try await db.schema(AuthorityKey.schema)
            .field("kid", .string, .identifier(auto: false))
            .field("account_ref", .string, .required).field("public_key", .string, .required).field("key_purpose", .string, .required)
            .field("hardware_attested", .bool, .required).field("grant_capable", .bool, .required).field("usable_from", .datetime, .required)
            .field("revoked_at", .datetime).create()
        try await db.schema(AuthorityChallenge.schema)
            .field("id", .string, .identifier(auto: false))
            .field("purpose", .string, .required).field("nonce", .string, .required).field("state", .string, .required)
            .field("display", .string, .required).field("display_digest", .string, .required).field("tenant_id", .string, .required)
            .field("client_id", .string, .required).field("target_url", .string, .required).field("match_code", .string)
            .field("match_failures", .int, .required).field("code_challenge", .string).field("oidc_nonce", .string).field("require_passkey", .bool)
            .field("delivery_id", .string).field("link_purpose", .string)
            .field("created_at", .datetime, .required).field("expires_at", .datetime, .required).field("used_at", .datetime).create()
        try await db.schema(AuthorityOIDCClient.schema)
            .field("client_id", .string, .identifier(auto: false))
            .field("tenant_id", .string, .required).field("display_name", .string, .required).field("redirect_uris", .string, .required)
            .field("post_logout_redirect_uris", .string, .required).field("sector_identifier", .string, .required).field("jwks", .string, .required)
            .field("id_token_alg", .string, .required).field("require_passkey", .bool, .required).field("require_biometric", .bool, .required)
            .field("status", .string, .required).field("change_commit", .string, .required).field("created_at", .datetime, .required).create()
        try await db.schema(AuthorityLinkClient.schema)
            .field("client_id", .string, .identifier(auto: false))
            .field("tenant_id", .string, .required).field("business_id", .uuid, .required).field("tenant_name", .string, .required)
            .field("display_name", .string, .required).field("return_urls", .string, .required).field("require_biometric", .bool, .required)
            .field("status", .string, .required).field("change_commit", .string, .required).field("created_at", .datetime, .required).create()
        try await db.schema(AuthorityOIDCCode.schema)
            .field("code_hash", .string, .identifier(auto: false))
            .field("client_id", .string, .required).field("redirect_uri", .string, .required).field("code_challenge", .string, .required)
            .field("nonce", .string, .required).field("acr", .string, .required).field("amr", .string, .required).field("auth_time", .datetime, .required)
            .field("account_id", .uuid, .required).field("account_ref", .string, .required).field("kid", .string, .required)
            .field("expires_at", .datetime, .required).field("used_at", .datetime).create()
        try await db.schema(AuthorityGrantRecord.schema)
            .field("jti", .string, .identifier(auto: false))
            .field("kind", .string, .required).field("kid", .string, .required).field("client_id", .string, .required).field("account_ref", .string, .required)
            .field("sub_hash", .string, .required).field("acr", .string, .required).field("policy_version", .string, .required)
            .field("challenge_id", .string, .required).field("created_at", .datetime, .required).create()
        try await db.schema(AuthorityReplayRecord.schema)
            .field("key", .string, .identifier(auto: false)).field("expires_at", .datetime, .required).create()
        try await db.schema(AuthorityKeyPin.schema)
            .field("name", .string, .identifier(auto: false))
            .field("version", .string, .required).field("thumbprint", .string, .required).field("change_commit", .string, .required)
            .field("pinned_at", .datetime, .required).create()
        try await db.schema(AuthorityAuditEvent.schema)
            .id()
            .field("event", .string, .required).field("outcome", .string, .required).field("reason", .string).field("tenant_id", .string)
            .field("account_ref", .string).field("challenge_id", .string).field("kid", .string).field("policy_version", .string)
            .field("caller", .string).field("detail", .string).field("at", .datetime, .required).create()
        guard let sql = db as? any SQLDatabase else { return }
        try await Self.appendOnly(sql, tables: [AuthorityKeylogEntry.schema, AuthorityGrantRecord.schema, AuthorityAuditEvent.schema])
    }

    /// UPDATE and DELETE are refused by the database itself (an authority compromise that runs SQL through the application still cannot rewrite history).
    static func appendOnly(_ sql: any SQLDatabase, tables: [String]) async throws {
        if sql.dialect.name == "postgresql" {
            try await sql.raw("""
                CREATE OR REPLACE FUNCTION viadere_authority_append_only() RETURNS trigger AS $$
                BEGIN
                    RAISE EXCEPTION '% is append-only', TG_TABLE_NAME;
                END;
                $$ LANGUAGE plpgsql
                """).run()
            for table in tables {
                try await sql.raw(SQLQueryString("""
                    CREATE TRIGGER \(unsafeRaw: table)_append_only BEFORE UPDATE OR DELETE ON \(unsafeRaw: table)
                    FOR EACH ROW EXECUTE FUNCTION viadere_authority_append_only()
                    """)).run()
            }
        } else {
            for table in tables {
                try await sql.raw(SQLQueryString("CREATE TRIGGER \(unsafeRaw: table)_no_update BEFORE UPDATE ON \(unsafeRaw: table) BEGIN SELECT RAISE(ABORT, 'append-only table'); END")).run()
                try await sql.raw(SQLQueryString("CREATE TRIGGER \(unsafeRaw: table)_no_delete BEFORE DELETE ON \(unsafeRaw: table) BEGIN SELECT RAISE(ABORT, 'append-only table'); END")).run()
            }
        }
    }

    func revert(on db: any Database) async throws {
        for table in [AuthorityAuditEvent.schema, AuthorityKeyPin.schema, AuthorityReplayRecord.schema, AuthorityGrantRecord.schema, AuthorityOIDCCode.schema,
                      AuthorityLinkClient.schema, AuthorityOIDCClient.schema, AuthorityChallenge.schema, AuthorityKey.schema, AuthorityKeylogEntry.schema,
                      AuthorityAccount.schema] {
            try await db.schema(table).delete()
        }
    }
}
