import Fluent
import FluentSQL
import Foundation
import SQLKit

/// A begun phone link waiting for the customer's text (ADR-0027, class P: pending secret). The row holds the keyed hash of the nonce (never the
/// nonce), the claimed number (encrypted, plus its keyed hash for the From check) and the account and device that asked. It is **deleted at use or
/// expiry**: an unverified begin leaves nothing behind except an audit event. Its id is the `phoneLinkId` the app polls, and the id of the
/// `phone_links` row created on success.
final class PhoneLinkMOChallengeRecord: Model, @unchecked Sendable {
    static let schema = "phone_link_mo_challenges"
    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @OptionalField(key: "device_id") var deviceId: UUID?
    /// `HMAC-SHA256(SERVER_PEPPER, "phone-mo\n" ‖ phoneLinkId ‖ "\n" ‖ nonce)`.
    @Field(key: "nonce_hash") var nonceHash: String
    /// Keyed hash of the claimed number (`Hasher256.phoneHash`): the inbound From must equal it.
    @Field(key: "phone_hash") var phoneHash: String
    @Field(key: "phone_ciphertext") var phoneCiphertext: String
    @Field(key: "phone_masked") var phoneMasked: String
    @Field(key: "phone_last4") var phoneLast4: String
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "expires_at") var expiresAt: Date
    init() {}
}

/// `PhoneLinkMO.v1` (additive, forward-only):
/// * `phone_link_mo_challenges` (ADR-0027 §1.1);
/// * every outstanding SMS-code link attempt and every open SMS link token is revoked and their secrets cleared (decision 9: no authentication
///   over SMS; ADR-0027 §4 "Outstanding `link_tokens` revoked at deploy"). Verified links made by older builds are kept.
struct CreatePhoneLinkMOSchema: AsyncMigration {
    var name: String { "PhoneLinkMO.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema(PhoneLinkMOChallengeRecord.schema).id()
            .field("consumer_id", .uuid, .required, .references("consumers", "id"))
            .field("device_id", .uuid)
            .field("nonce_hash", .string, .required)
            .field("phone_hash", .string, .required)
            .field("phone_ciphertext", .string, .required)
            .field("phone_masked", .string, .required)
            .field("phone_last4", .string, .required)
            .field("created_at", .datetime, .required)
            .field("expires_at", .datetime, .required)
            .create()
        if let sql = db as? any SQLDatabase {
            // Identifiers are compile-time constants; no user input reaches these statements.
            try await sql.raw(SQLQueryString("CREATE INDEX IF NOT EXISTS idx_phone_link_mo_phone ON phone_link_mo_challenges (phone_hash, expires_at)")).run()
            try await sql.raw(SQLQueryString("CREATE INDEX IF NOT EXISTS idx_phone_link_mo_consumer ON phone_link_mo_challenges (consumer_id)")).run()
        }
        // Old code paths: an unfinished SMS code can no longer be completed, and an open SMS link or hand-off token can no longer be redeemed.
        try await PhoneLinkRecord.query(on: db).filter(\.$state == "pending").set(\.$state, to: "revoked").set(\.$otpHash, to: nil)
            .set(\.$otpExpiresAt, to: nil).update()
        try await LinkTokenRecord.query(on: db).filter(\.$state == "open").set(\.$state, to: "revoked").update()
    }

    func revert(on db: any Database) async throws {
        if let sql = db as? any SQLDatabase {
            try await sql.raw("DROP INDEX IF EXISTS idx_phone_link_mo_consumer").run()
            try await sql.raw("DROP INDEX IF EXISTS idx_phone_link_mo_phone").run()
        }
        try await db.schema(PhoneLinkMOChallengeRecord.schema).delete()
    }
}
