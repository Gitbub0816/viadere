import Fluent
import FluentSQL
import Foundation
import SQLKit

/// WP3 (Verify): verification requests, attempts, results and provider-event deduplication.
///
/// No table holds evidence. A request holds its parameters (`{"years":18}`), an attempt holds a single-use nonce or a provider session id,
/// and a result holds the capability's output sealed per row until the business retrieves it once. The data inventory
/// (`docs/ops/DATA-INVENTORY.md`) lists the retention of each.
struct CreateVerifyWP3Schema: AsyncMigration {
    var name: String { "CreateVerifyWP3Schema.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema("verification_requests")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("key_id", .uuid, .required)
            .field("livemode", .bool, .required)
            .field("relationship_id", .uuid, .required)
            .field("consumer_id", .uuid, .required)
            .field("subject_ref", .string, .required)
            .field("capability", .string, .required)
            .field("parameters", .string, .required)
            .field("purpose", .string, .required)
            .field("callback_id", .uuid)
            .field("recipient_name", .string, .required)
            .field("status", .string, .required)
            .field("receipt_id", .uuid)
            .field("result_id", .uuid)
            .field("attempt_count", .int, .required)
            .field("idempotency_hash", .string, .required)
            .field("request_hash", .string, .required)
            .field("label", .string)
            .field("disclosed_fields", .string)
            .field("created_at", .datetime, .required)
            .field("expires_at", .datetime, .required)
            .field("decided_at", .datetime)
            .unique(on: "business_id", "idempotency_hash")
            .create()

        try await db.schema("verification_attempts")
            .id()
            .field("request_id", .uuid, .required, .references("verification_requests", "id"))
            .field("business_id", .uuid, .required)
            .field("method", .string, .required)
            .field("status", .string, .required)
            .field("nonce", .string)
            .field("provider_session_id", .string)
            .field("failure_reason", .string)
            .field("purge_status", .string)
            .field("purge_attempts", .int, .required)
            .field("purged_at", .datetime)
            .field("created_at", .datetime, .required)
            .field("expires_at", .datetime, .required)
            .field("finished_at", .datetime)
            .unique(on: "provider_session_id")
            .create()

        try await db.schema("verification_results")
            .id()
            .field("request_id", .uuid, .required, .references("verification_requests", "id"))
            .field("business_id", .uuid, .required)
            .field("ref_hash", .string, .required)
            .field("outcome", .string, .required)
            .field("payload", .string)
            .field("provenance", .string)
            .field("created_at", .datetime, .required)
            .field("expires_at", .datetime, .required)
            .field("retrieved_at", .datetime)
            .unique(on: "request_id")
            .unique(on: "ref_hash")
            .create()

        try await db.schema("verification_provider_events")
            .id()
            .field("provider", .string, .required)
            .field("event_id", .string, .required)
            .field("received_at", .datetime, .required)
            .unique(on: "provider", "event_id")
            .create()

        if let sql = db as? any SQLDatabase {
            try await sql.raw("CREATE INDEX IF NOT EXISTS idx_verification_requests_consumer ON verification_requests (consumer_id, status, expires_at)").run()
            try await sql.raw("CREATE INDEX IF NOT EXISTS idx_verification_requests_business ON verification_requests (business_id, created_at)").run()
            try await sql.raw("CREATE INDEX IF NOT EXISTS idx_verification_attempts_request ON verification_attempts (request_id)").run()
            try await sql.raw("CREATE INDEX IF NOT EXISTS idx_verification_attempts_purge ON verification_attempts (purge_status, created_at)").run()
        }
    }

    func revert(on db: any Database) async throws {
        guard let sql = db as? any SQLDatabase else { return }
        for table in ["verification_provider_events", "verification_results", "verification_attempts", "verification_requests"] {
            try await sql.raw(SQLQueryString("DROP TABLE IF EXISTS \(unsafeRaw: table)")).run()
        }
    }
}
