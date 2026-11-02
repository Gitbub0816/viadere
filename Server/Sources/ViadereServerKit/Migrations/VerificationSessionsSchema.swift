import Fluent
import Foundation

/// Verification sessions ("Verify with Viadere", `docs/SECURITY.md` §2.60). **Additive and forward-only**: one new table, nothing else changes.
///
/// * `verification_sessions`: one expiring (≤ 5 min), single-use session a business opens for one Verify capability on one of its verified web
///   origins. The code is stored only as a keyed hash. Once the app accepts it the row names the account (pairwise `subject_ref`), the
///   connection and the ordinary verification request it opened; once that request ends it holds Viadere's signed result (no personal data).
struct CreateVerificationSessionsSchema: AsyncMigration {
    var name: String { "VerificationSessions.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema("verification_sessions")
            .id()
            .field("business_id", .uuid, .required, .references("businesses", "id"))
            .field("api_key_id", .uuid, .required)
            .field("livemode", .bool, .required)
            .field("code_hash", .string, .required)
            .field("capability", .string, .required)
            .field("parameters", .string, .required)
            .field("purpose", .string, .required)
            .field("origin", .string, .required)
            .field("business_domain", .string, .required)
            .field("return_url", .string)
            .field("callback_id", .uuid)
            .field("status", .string, .required)
            .field("created_at", .datetime, .required)
            .field("expires_at", .datetime, .required)
            .field("consumer_id", .uuid)
            .field("device_id", .uuid)
            .field("subject_ref", .string)
            .field("relationship_id", .uuid)
            .field("request_id", .uuid)
            .field("accepted_at", .datetime)
            .field("result", .string)
            .field("completed_at", .datetime)
            .field("cancelled_at", .datetime)
            .field("ended_reason", .string)
            .unique(on: "code_hash")
            .create()
    }

    func revert(on db: any Database) async throws {
        try await db.schema("verification_sessions").delete()
    }
}
