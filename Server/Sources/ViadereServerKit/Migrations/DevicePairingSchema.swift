import Fluent
import Foundation
import SQLKit

/// WP-D1 device pairing (SECURITY.md §2.107). **Additive and forward-only**: two new tables, nothing existing changes.
///
/// * `device_pairing_invitations`: the pairing codes trusted devices made (HMAC only), single use, 10 minutes.
/// * `device_pairings`: the ceremonies and pairings; at most one `pending` pairing per account (partial unique index, PostgreSQL and SQLite).
struct CreateDevicePairingSchema: AsyncMigration {
    var name: String { "DevicePairing.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema("device_pairing_invitations")
            .id()
            .field("consumer_id", .uuid, .required)
            .field("code_hash", .string, .required)
            .field("created_by_device_id", .uuid, .required)
            .field("state", .string, .required)
            .field("expires_at", .datetime, .required)
            .field("created_at", .datetime, .required)
            .field("used_at", .datetime)
            .unique(on: "code_hash")
            .create()

        try await db.schema("device_pairings")
            .id()
            .field("state", .string, .required)
            .field("challenge_hash", .string, .required)
            .field("consumer_id", .uuid)
            .field("invitation_id", .uuid)
            .field("nonce", .string)
            .field("device_name", .string)
            .field("platform", .string)
            .field("keys_json", .string)
            .field("key_list_digest", .string)
            .field("comparison_digest", .string)
            .field("status_token_hash", .string)
            .field("attestation_json", .string)
            .field("integrity_format", .string)
            .field("attempts", .int, .required, .sql(.default(0)))
            .field("silent", .bool, .required, .sql(.default(false)))
            .field("fatigue_warning", .bool, .required, .sql(.default(false)))
            .field("created_at", .datetime, .required)
            .field("started_at", .datetime)
            .field("expires_at", .datetime, .required)
            .field("shown_at", .datetime)
            .field("decided_at", .datetime)
            .field("decided_by_device_id", .uuid)
            .field("new_device_id", .uuid)
            .field("session_issued_at", .datetime)
            .field("end_reason", .string)
            .unique(on: "challenge_hash")
            .create()

        guard let sql = db as? any SQLDatabase else { return }
        // One live pairing per account: a new one cancels the old in the same transaction, and two concurrent starts cannot both be pending.
        try await sql.raw("CREATE UNIQUE INDEX IF NOT EXISTS uq_device_pairings_pending ON device_pairings (consumer_id) WHERE state = 'pending'").run()
        try await sql.raw("CREATE INDEX IF NOT EXISTS ix_device_pairings_consumer_created ON device_pairings (consumer_id, created_at)").run()
        try await sql.raw("CREATE INDEX IF NOT EXISTS ix_device_pairing_invitations_consumer ON device_pairing_invitations (consumer_id, state)").run()
    }

    func revert(on db: any Database) async throws {
        try await db.schema("device_pairings").delete()
        try await db.schema("device_pairing_invitations").delete()
    }
}
