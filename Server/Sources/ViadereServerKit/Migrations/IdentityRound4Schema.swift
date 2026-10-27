import Fluent
import FluentSQL
import Foundation

/// Identity round 4: App Attest keys, account recovery (codes, profiles, recoveries), pending device replacement, notice actions and
/// business idempotency keys.
struct CreateIdentityRound4Schema: AsyncMigration {
    var name: String { "CreateIdentityRound4Schema.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema("app_attest_keys")
            .id()
            .field("device_id", .uuid, .required)
            .field("consumer_id", .uuid, .required)
            .field("key_id", .string, .required)
            .field("public_key", .string, .required)
            .field("counter", .int, .required)
            .field("environment", .string, .required)
            .field("created_at", .datetime, .required)
            .field("last_assertion_at", .datetime)
            .unique(on: "key_id")
            .unique(on: "device_id")
            .create()

        try await db.schema("recovery_profiles")
            .id()
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("recovery_id_hash", .string, .required)
            .field("failed_attempts", .int, .required)
            .field("locked_until", .datetime)
            .field("issued_at", .datetime, .required)
            .field("created_at", .datetime, .required)
            .unique(on: "consumer_id")
            .unique(on: "recovery_id_hash")
            .create()

        try await db.schema("recovery_codes")
            .id()
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("code_hash", .string, .required)
            .field("state", .string, .required)
            .field("created_at", .datetime, .required)
            .field("used_at", .datetime)
            .unique(on: "consumer_id", "code_hash")
            .create()

        try await db.schema("account_recoveries")
            .id()
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("state", .string, .required)
            .field("challenge", .string, .required)
            .field("user_handle", .string, .required)
            .field("passkey_expires_at", .datetime, .required)
            .field("new_credential_id", .string)
            .field("new_public_key", .string)
            .field("new_sign_count", .int)
            .field("new_backup_eligible", .bool)
            .field("status_token_hash", .string)
            .field("hold_until", .datetime)
            .field("created_at", .datetime, .required)
            .field("activated_at", .datetime)
            .field("cancelled_at", .datetime)
            .field("codes_issued_at", .datetime)
            .create()

        try await db.schema("business_idempotency")
            .id()
            .field("business_id", .uuid, .required)
            .field("operation", .string, .required)
            .field("idem_key", .string, .required)
            .field("request_hash", .string, .required)
            .field("resource_id", .uuid)
            .field("result_sealed", .string)
            .field("created_at", .datetime, .required)
            .unique(on: "business_id", "operation", "idem_key")
            .create()

        // One column per statement: SQLite cannot add several columns in a single ALTER TABLE.
        try await db.schema("devices").field("attestation_status", .string, .required, .sql(.default("none"))).update()
        try await db.schema("devices").field("pending_replacement_by", .uuid).update()
        try await db.schema("security_notices").field("action", .string).update()

        if let sql = db as? any SQLDatabase {
            let indexes: [(String, String, String)] = [
                ("idx_account_recoveries_consumer", "account_recoveries", "consumer_id, state"),
                ("idx_account_recoveries_hold", "account_recoveries", "state, hold_until"),
                ("idx_devices_pending_replacement", "devices", "pending_replacement_by"),
            ]
            for (name, table, columns) in indexes {
                // Identifiers are compile-time constants above; no user input reaches this statement.
                try await sql.raw(SQLQueryString("CREATE INDEX IF NOT EXISTS \(unsafeRaw: name) ON \(unsafeRaw: table) (\(unsafeRaw: columns))")).run()
            }
        }
    }

    func revert(on db: any Database) async throws {
        try await db.schema("security_notices").deleteField("action").update()
        try await db.schema("devices").deleteField("pending_replacement_by").update()
        try await db.schema("devices").deleteField("attestation_status").update()
        try await db.schema("business_idempotency").delete()
        try await db.schema("account_recoveries").delete()
        try await db.schema("recovery_codes").delete()
        try await db.schema("recovery_profiles").delete()
        try await db.schema("app_attest_keys").delete()
    }
}
