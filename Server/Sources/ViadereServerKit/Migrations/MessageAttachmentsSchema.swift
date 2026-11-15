import Fluent
import Foundation
import SQLKit

/// Message attachments (docs/SECURITY.md §2.113). One row per stored image: tenant, customer and conversation fixed at upload, the message it
/// was sent with once attached, the stored (re-encoded) type, size, dimensions and SHA-256, and the private object name. The image itself is
/// **not** in the database: it is field-encrypted and kept in the attachment object store under `object_name`.
struct CreateMessageAttachmentsSchema: AsyncMigration {
    var name: String { "MessageAttachments.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema(MessageAttachmentRecord.schema).id()
            .field("business_id", .uuid, .required)
            .field("consumer_id", .uuid, .required)
            .field("session_id", .uuid, .required, .references(ConversationSessionRecord.schema, "id"))
            .field("message_id", .uuid)
            .field("position", .int)
            .field("side", .string, .required)
            .field("uploader_ref", .string, .required)
            .field("media_type", .string, .required)
            .field("byte_size", .int, .required)
            .field("width", .int, .required)
            .field("height", .int, .required)
            .field("sha256", .string, .required)
            .field("object_name", .string, .required)
            .field("state", .string, .required)
            .field("created_at", .datetime, .required)
            .field("expires_at", .datetime)
            .field("attached_at", .datetime)
            .field("delete_requested_at", .datetime)
            .unique(on: "object_name")
            .create()
        guard let sql = db as? any SQLDatabase else { return }
        try await sql.raw("CREATE INDEX IF NOT EXISTS idx_message_attachments_message ON message_attachments (message_id)").run()
        try await sql.raw("CREATE INDEX IF NOT EXISTS idx_message_attachments_session ON message_attachments (session_id, state)").run()
        try await sql.raw("CREATE INDEX IF NOT EXISTS idx_message_attachments_state ON message_attachments (state, expires_at)").run()
        try await sql.raw("CREATE INDEX IF NOT EXISTS idx_message_attachments_business ON message_attachments (business_id)").run()
        try await sql.raw("CREATE INDEX IF NOT EXISTS idx_message_attachments_consumer ON message_attachments (consumer_id)").run()
    }

    func revert(on db: any Database) async throws {
        try await db.schema(MessageAttachmentRecord.schema).delete()
    }
}

/// `state`: `pending` (uploaded, not yet sent; `expires_at` set), `attached` (part of message `message_id` at `position`), `deleting` (expired,
/// retained out, or its account or tenant deleted: the object is removed by the next sweep, then the row).
final class MessageAttachmentRecord: Model, @unchecked Sendable {
    static let schema = "message_attachments"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "session_id") var sessionId: UUID
    @OptionalField(key: "message_id") var messageId: UUID?
    @OptionalField(key: "position") var position: Int?
    /// `consumer` or `business`: who uploaded it. A pending upload is visible only to its own side.
    @Field(key: "side") var side: String
    /// The device, API key or console user that uploaded it (audit; never shown to the other side).
    @Field(key: "uploader_ref") var uploaderRef: String
    @Field(key: "media_type") var mediaType: String
    @Field(key: "byte_size") var byteSize: Int
    @Field(key: "width") var width: Int
    @Field(key: "height") var height: Int
    /// Lowercase hex SHA-256 of the stored (plaintext, re-encoded) image.
    @Field(key: "sha256") var sha256: String
    @Field(key: "object_name") var objectName: String
    @Field(key: "state") var state: String
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "expires_at") var expiresAt: Date?
    @OptionalField(key: "attached_at") var attachedAt: Date?
    @OptionalField(key: "delete_requested_at") var deleteRequestedAt: Date?
    init() {}
}
