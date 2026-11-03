import Fluent
import Foundation
import SQLKit
import ViadereCore

// Authority.v2 (additive): key-log enrollment, device add (C-13), recovery (ADR-0032 §3, ADR-0034), signed heads, link codes (ADR-0021 §5),
// the reviewed key inventory (S6-06), sign and unwrap records for the Key Vault reconciliation (ADR-0023 §6, ADR-0028 §2) and seal keys.

/// Per-account lifecycle next to `authority_accounts` (v1): `unconfirmed` (minted, no `enrollment_confirmed` yet), `active`, `closed` (ADR-0032 §1.8).
final class AuthorityAccountState: Model, @unchecked Sendable {
    static let schema = "authority_account_states"
    @ID(custom: "account_ref", generatedBy: .user) var id: String?
    @Field(key: "state") var state: String
    @Field(key: "updated_at") var updatedAt: Date
    init() {}
}

/// Which log entry brought a key in (`genesis`, `imported`, `device_added`, `recovery_activated`) and the entry group whose keys confirm together.
final class AuthorityKeyEntry: Model, @unchecked Sendable {
    static let schema = "authority_key_entries"
    @ID(custom: "kid", generatedBy: .user) var id: String?
    @Field(key: "entry_type") var entryType: String
    @Field(key: "entry_group") var entryGroup: String
    @OptionalField(key: "confirmed_head") var confirmedHead: String?
    init() {}
}

/// Single-use PoP nonces for `genesis` and `device_added` (ADR-0032 §1.3, ADR-0033 §4.1 item 1): 256 bits, 10 minutes, never a comparison nonce.
final class AuthorityKeylogNonce: Model, @unchecked Sendable {
    static let schema = "authority_keylog_nonces"
    @ID(custom: "id", generatedBy: .user) var id: String?
    @Field(key: "nonce") var nonce: String
    @Field(key: "entry_type") var entryType: String
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "used_at") var usedAt: Date?
    init() {}
}

/// A `device_added` entry (ADR-0033 §4.1): stored with its keys **before** its one comparison challenge exists.
final class AuthorityDeviceAddEntry: Model, @unchecked Sendable {
    static let schema = "authority_device_add_entries"
    @ID(custom: "id", generatedBy: .user) var id: String?
    @Field(key: "account_ref") var accountRef: String
    /// JSON array of `{kid, public_key, key_purpose}`.
    @Field(key: "keys") var keys: String
    @Field(key: "reported_name") var reportedName: String
    /// `pending` → `added` | `abandoned` | `cancelled`.
    @Field(key: "state") var state: String
    @OptionalField(key: "challenge_id") var challengeId: String?
    @Field(key: "created_at") var createdAt: Date
    init() {}
}

/// The signed head cache (ADR-0033 §2 cadence: re-signed when older than 5 minutes when served, and on change).
final class AuthorityHeadCache: Model, @unchecked Sendable {
    static let schema = "authority_heads"
    @ID(custom: "account_ref", generatedBy: .user) var id: String?
    @Field(key: "seq") var seq: Int
    @Field(key: "head_hash") var headHash: String
    @Field(key: "statement") var statement: String
    @Field(key: "signed_at") var signedAt: Date
    init() {}
}

/// Link codes (ADR-0021 §5.3, ADR-0023 §7): the hash of the device-generated code (same device) or the challenge reference (cross device, after a
/// correct number), bound to the client, the PKCE challenge and the verified evidence. 120 s, single use; the grant is signed only at redemption.
final class AuthorityLinkCode: Model, @unchecked Sendable {
    static let schema = "authority_link_codes"
    @ID(custom: "id", generatedBy: .user) var id: String?
    @OptionalField(key: "code_hash") var codeHash: String?
    @Field(key: "challenge_id") var challengeId: String
    @Field(key: "client_id") var clientId: String
    @Field(key: "code_challenge") var codeChallenge: String
    @Field(key: "account_id") var accountId: UUID
    @Field(key: "account_ref") var accountRef: String
    @Field(key: "kid") var kid: String
    @Field(key: "amr") var amr: String
    @Field(key: "policy_version") var policyVersion: String
    @Field(key: "auth_time") var authTime: Date
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "used_at") var usedAt: Date?
    init() {}
}

/// The reviewed key inventory (S6-06): rows recorded by the admin job from a reviewed change file; the serving authority verifies each against its
/// own source of truth (Key Vault public key at `name/version`, or its unwrapped seal key) and records the outcome. Nothing is read from a log.
final class AuthorityInventoryRow: Model, @unchecked Sendable {
    static let schema = "authority_key_inventory"
    @ID(key: .id) var id: UUID?
    @Field(key: "change_commit") var changeCommit: String
    @Field(key: "name") var name: String
    @Field(key: "version") var version: String
    /// `key_vault` or `seal_key`.
    @Field(key: "source") var source: String
    @Field(key: "jwk") var jwk: String
    @Field(key: "thumbprint") var thumbprint: String
    /// `pending` → `verified` | `mismatch` | `unavailable`.
    @Field(key: "status") var status: String
    @Field(key: "recorded_at") var recordedAt: Date
    @OptionalField(key: "checked_at") var checkedAt: Date?
    init() {}
}

/// One row per KMS `sign` the authority requests, written **before** the call (ADR-0023 §6): the reconciliation matches every Key Vault `AuditEvent`
/// sign against these rows. Never a digest or payload.
final class AuthoritySignRecord: Model, @unchecked Sendable {
    static let schema = "authority_sign_records"
    @ID(key: .id) var id: UUID?
    @Field(key: "key_ref") var keyRef: String
    /// `challenge`, `head`, `grant`, `id_token`, `access_token`, `unwrap`.
    @Field(key: "kind") var kind: String
    @Field(key: "at") var at: Date
    init() {}
}

/// `recovery-seal` key pairs (ADR-0034 §5): the private scalar only wrapped under the KEK; one row per admin execution.
final class AuthoritySealKey: Model, @unchecked Sendable {
    static let schema = "authority_seal_keys"
    @ID(custom: "kid", generatedBy: .user) var id: String?
    @Field(key: "public_jwk") var publicJWK: String
    @Field(key: "wrapped_private") var wrappedPrivate: String
    @Field(key: "kek_name") var kekName: String
    @Field(key: "kek_version") var kekVersion: String
    /// `active` | `standby`.
    @Field(key: "role") var role: String
    /// `ready` | `exposed` | `retired`.
    @Field(key: "state") var state: String
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "not_after") var notAfter: Date
    @Field(key: "job_execution_id") var jobExecutionId: String
    @Field(key: "change_commit") var changeCommit: String
    init() {}
}

/// Authority recovery-code verifiers (ADR-0034 §4.6): `HMAC-SHA256(RECOVERY_VERIFIER_KEY, "recovery-code-v2\n" ‖ account_ref ‖ "\n" ‖ set_id ‖ "\n" ‖ code)`.
final class AuthorityRecoveryCode: Model, @unchecked Sendable {
    static let schema = "authority_recovery_codes"
    @ID(key: .id) var id: UUID?
    @Field(key: "account_ref") var accountRef: String
    @Field(key: "set_id") var setId: String
    @Field(key: "seal_kid") var sealKid: String
    @Field(key: "verifier") var verifier: String
    /// `active` | `used` | `superseded` | `invalidated`.
    @Field(key: "state") var state: String
    @Field(key: "created_at") var createdAt: Date
    init() {}
}

/// A recovery start (ADR-0032 §3.2, §3.3): authority-timed hold of 72 h, then exactly `kids` are added and every earlier key is revoked.
final class AuthorityRecovery: Model, @unchecked Sendable {
    static let schema = "authority_recoveries"
    @ID(custom: "id", generatedBy: .user) var id: String?
    @Field(key: "account_ref") var accountRef: String
    @Field(key: "recovery_id") var recoveryId: String
    /// JSON array of `{kid, public_key, key_purpose}` (the new keys, each with a verified PoP).
    @Field(key: "keys") var keys: String
    @Field(key: "legacy") var legacy: Bool
    /// `pending` → `activated` | `cancelled`.
    @Field(key: "state") var state: String
    @Field(key: "started_at") var startedAt: Date
    @Field(key: "activates_at") var activatesAt: Date
    @OptionalField(key: "challenge_id") var challengeId: String?
    init() {}
}

/// Failed recovery attempts (ADR-0032 §3.2: 5 per account per 24 h, 20 per recovery id).
final class AuthorityRecoveryAttempt: Model, @unchecked Sendable {
    static let schema = "authority_recovery_attempts"
    @ID(key: .id) var id: UUID?
    @Field(key: "account_ref") var accountRef: String
    @Field(key: "recovery_id") var recoveryId: String
    @Field(key: "reason") var reason: String
    @Field(key: "at") var at: Date
    init() {}
}

/// Recovery challenges carry the account the authority bound them to and, for code sets, the device-generated set id.
final class AuthorityChallengeBinding: Model, @unchecked Sendable {
    static let schema = "authority_challenge_bindings"
    @ID(custom: "challenge_id", generatedBy: .user) var id: String?
    @Field(key: "account_ref") var accountRef: String
    @OptionalField(key: "set_id") var setId: String?
    @OptionalField(key: "recovery_id") var recoveryId: String?
    @OptionalField(key: "entry_id") var entryId: String?
    init() {}
}

struct CreateAuthorityKeyLogSchema: AsyncMigration {
    var name: String { "Authority.v2" }

    func prepare(on db: any Database) async throws {
        try await db.schema(AuthorityAccountState.schema)
            .field("account_ref", .string, .identifier(auto: false)).field("state", .string, .required).field("updated_at", .datetime, .required).create()
        try await db.schema(AuthorityKeyEntry.schema)
            .field("kid", .string, .identifier(auto: false)).field("entry_type", .string, .required).field("entry_group", .string, .required)
            .field("confirmed_head", .string).create()
        try await db.schema(AuthorityKeylogNonce.schema)
            .field("id", .string, .identifier(auto: false)).field("nonce", .string, .required).field("entry_type", .string, .required)
            .field("expires_at", .datetime, .required).field("used_at", .datetime).create()
        try await db.schema(AuthorityDeviceAddEntry.schema)
            .field("id", .string, .identifier(auto: false)).field("account_ref", .string, .required).field("keys", .string, .required)
            .field("reported_name", .string, .required).field("state", .string, .required).field("challenge_id", .string)
            .field("created_at", .datetime, .required).create()
        try await db.schema(AuthorityHeadCache.schema)
            .field("account_ref", .string, .identifier(auto: false)).field("seq", .int, .required).field("head_hash", .string, .required)
            .field("statement", .string, .required).field("signed_at", .datetime, .required).create()
        try await db.schema(AuthorityLinkCode.schema)
            .field("id", .string, .identifier(auto: false)).field("code_hash", .string).field("challenge_id", .string, .required)
            .field("client_id", .string, .required).field("code_challenge", .string, .required).field("account_id", .uuid, .required)
            .field("account_ref", .string, .required).field("kid", .string, .required).field("amr", .string, .required)
            .field("policy_version", .string, .required).field("auth_time", .datetime, .required).field("expires_at", .datetime, .required)
            .field("used_at", .datetime).unique(on: "code_hash").unique(on: "challenge_id").create()
        try await db.schema(AuthorityInventoryRow.schema)
            .id().field("change_commit", .string, .required).field("name", .string, .required).field("version", .string, .required)
            .field("source", .string, .required).field("jwk", .string, .required).field("thumbprint", .string, .required).field("status", .string, .required)
            .field("recorded_at", .datetime, .required).field("checked_at", .datetime).create()
        try await db.schema(AuthoritySignRecord.schema)
            .id().field("key_ref", .string, .required).field("kind", .string, .required).field("at", .datetime, .required).create()
        try await db.schema(AuthoritySealKey.schema)
            .field("kid", .string, .identifier(auto: false)).field("public_jwk", .string, .required).field("wrapped_private", .string, .required)
            .field("kek_name", .string, .required).field("kek_version", .string, .required).field("role", .string, .required).field("state", .string, .required)
            .field("created_at", .datetime, .required).field("not_after", .datetime, .required).field("job_execution_id", .string, .required)
            .field("change_commit", .string, .required).unique(on: "job_execution_id").create()
        try await db.schema(AuthorityRecoveryCode.schema)
            .id().field("account_ref", .string, .required).field("set_id", .string, .required).field("seal_kid", .string, .required)
            .field("verifier", .string, .required).field("state", .string, .required).field("created_at", .datetime, .required)
            .unique(on: "account_ref", "verifier").create()
        try await db.schema(AuthorityRecovery.schema)
            .field("id", .string, .identifier(auto: false)).field("account_ref", .string, .required).field("recovery_id", .string, .required)
            .field("keys", .string, .required).field("legacy", .bool, .required).field("state", .string, .required)
            .field("started_at", .datetime, .required).field("activates_at", .datetime, .required).field("challenge_id", .string).create()
        try await db.schema(AuthorityRecoveryAttempt.schema)
            .id().field("account_ref", .string, .required).field("recovery_id", .string, .required).field("reason", .string, .required)
            .field("at", .datetime, .required).create()
        try await db.schema(AuthorityChallengeBinding.schema)
            .field("challenge_id", .string, .identifier(auto: false)).field("account_ref", .string, .required).field("set_id", .string)
            .field("recovery_id", .string).field("entry_id", .string).create()
        guard let sql = db as? any SQLDatabase else { return }
        // Sign records are evidence for the reconciliation: never rewritten (UPDATE refused); the retention purge may delete rows past 30 days.
        if sql.dialect.name == "postgresql" {
            try await sql.raw("""
                CREATE TRIGGER authority_sign_records_no_update BEFORE UPDATE ON authority_sign_records
                FOR EACH ROW EXECUTE FUNCTION viadere_authority_append_only()
                """).run()
        } else {
            try await sql.raw("CREATE TRIGGER authority_sign_records_no_update BEFORE UPDATE ON authority_sign_records BEGIN SELECT RAISE(ABORT, 'append-only table'); END").run()
        }
        for statement in [
            "CREATE INDEX IF NOT EXISTS idx_authority_sign_records_at ON authority_sign_records (at)",
            "CREATE INDEX IF NOT EXISTS idx_authority_challenges_expiry ON authority_challenges (expires_at)",
            "CREATE INDEX IF NOT EXISTS idx_authority_device_add_account ON authority_device_add_entries (account_ref, created_at)",
            "CREATE INDEX IF NOT EXISTS idx_authority_recovery_codes_seal ON authority_recovery_codes (seal_kid)",
        ] { try await sql.raw(SQLQueryString(statement)).run() }
    }

    func revert(on db: any Database) async throws {
        for table in [AuthorityChallengeBinding.schema, AuthorityRecoveryAttempt.schema, AuthorityRecovery.schema, AuthorityRecoveryCode.schema,
                      AuthoritySealKey.schema, AuthoritySignRecord.schema, AuthorityInventoryRow.schema, AuthorityLinkCode.schema, AuthorityHeadCache.schema,
                      AuthorityDeviceAddEntry.schema, AuthorityKeylogNonce.schema, AuthorityKeyEntry.schema, AuthorityAccountState.schema] {
            try await db.schema(table).delete()
        }
    }
}
