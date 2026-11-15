import Fluent
import Foundation
import SQLKit

/// Console conversation inbox (G5, docs/SECURITY.md §2.108): per-thread assignment and per-staff read marks. Neither table holds message
/// content; the bodies stay field-encrypted in `conversation_messages`.
struct CreateConsoleConversationsSchema: AsyncMigration {
    var name: String { "ConsoleConversations.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema(ConversationConsoleStateRecord.schema).id()
            .field("session_id", .uuid, .required, .references(ConversationSessionRecord.schema, "id"))
            .field("business_id", .uuid, .required)
            .field("assignee_id", .uuid)
            .field("updated_at", .datetime, .required)
            .unique(on: "session_id").create()
        try await db.schema(ConversationConsoleReadRecord.schema).id()
            .field("session_id", .uuid, .required, .references(ConversationSessionRecord.schema, "id"))
            .field("business_id", .uuid, .required)
            .field("staff_id", .uuid, .required)
            .field("read_at", .datetime, .required)
            .unique(on: "session_id", "staff_id").create()
        guard let sql = db as? any SQLDatabase else { return }
        try await sql.raw("CREATE INDEX IF NOT EXISTS idx_conversation_sessions_business_activity ON conversation_sessions (business_id, state, last_message_at)").run()
        try await sql.raw("CREATE INDEX IF NOT EXISTS idx_conversation_console_states_business ON conversation_console_states (business_id, assignee_id)").run()
    }

    func revert(on db: any Database) async throws {
        try await db.schema(ConversationConsoleReadRecord.schema).delete()
        try await db.schema(ConversationConsoleStateRecord.schema).delete()
    }
}

/// Who on the business's team owns a thread. One row per session, created on first assignment.
final class ConversationConsoleStateRecord: Model, @unchecked Sendable {
    static let schema = "conversation_console_states"
    @ID(key: .id) var id: UUID?
    @Field(key: "session_id") var sessionId: UUID
    @Field(key: "business_id") var businessId: UUID
    @OptionalField(key: "assignee_id") var assigneeId: UUID?
    @Field(key: "updated_at") var updatedAt: Date
    init() {}
}

/// When a staff member last opened a thread; a customer message after it makes the thread unread for them.
final class ConversationConsoleReadRecord: Model, @unchecked Sendable {
    static let schema = "conversation_console_reads"
    @ID(key: .id) var id: UUID?
    @Field(key: "session_id") var sessionId: UUID
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "staff_id") var staffId: UUID
    @Field(key: "read_at") var readAt: Date
    init() {}
}
