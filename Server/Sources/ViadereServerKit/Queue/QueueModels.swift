import Fluent
import Foundation
import SQLKit

/// A message recorded in the same database transaction as the state change it announces (transactional outbox, ADR-0014). The publisher sends it
/// to the transport after commit and marks it published; a transaction that rolled back leaves no row, so nothing is ever published for it.
final class OutboxMessageRecord: Model, @unchecked Sendable {
    static let schema = "outbox_messages"
    /// Also the broker `MessageId` and the consumer's idempotency key.
    @ID(key: .id) var id: UUID?
    @Field(key: "queue") var queue: String
    @Field(key: "type") var type: String
    @Field(key: "version") var version: Int
    @Field(key: "ref") var ref: UUID
    @OptionalField(key: "tenant_id") var tenantId: UUID?
    /// The canonical envelope (SECURITY.md §2.91): ids only.
    @Field(key: "payload_json") var payloadJSON: String
    @OptionalField(key: "not_before") var notBefore: Date?
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "published_at") var publishedAt: Date?
    /// Publisher lease (compare-and-swap), so concurrent publishers do not send the same row at the same time.
    @OptionalField(key: "claimed_until") var claimedUntil: Date?
    @Field(key: "attempts") var attempts: Int
    @OptionalField(key: "last_error") var lastError: String?

    init() {}
}

/// Idempotency of consumers: one row per processed message, inserted in the **same transaction** as the handler's state transition. A second
/// delivery of the same message finds the row (or loses the primary-key race) and has no effect. Service Bus Basic has no duplicate detection, so
/// this table is the only deduplication in the lean profile.
final class ProcessedMessageRecord: Model, @unchecked Sendable {
    static let schema = "processed_messages"
    @ID(custom: "message_id", generatedBy: .user) var id: UUID?
    @Field(key: "queue") var queue: String
    @Field(key: "type") var type: String
    @Field(key: "processed_at") var processedAt: Date

    init() {}
}

/// The database transport's queue (`QUEUE_TRANSPORT=database`): peek-lock by lease, delivery counts and scheduled visibility, the same semantics as
/// Service Bus.
final class QueueMessageRecord: Model, @unchecked Sendable {
    static let schema = "queue_messages"
    /// The message id (= outbox id). The primary key also gives this transport duplicate detection.
    @ID(key: .id) var id: UUID?
    @Field(key: "queue") var queue: String
    @Field(key: "body") var body: String
    @Field(key: "visible_at") var visibleAt: Date
    @Field(key: "enqueued_at") var enqueuedAt: Date
    @Field(key: "expires_at") var expiresAt: Date
    @Field(key: "delivery_count") var deliveryCount: Int
    @OptionalField(key: "lock_token") var lockToken: String?
    @OptionalField(key: "locked_until") var lockedUntil: Date?

    init() {}
}

/// Dead letters seen by the consumer, for both transports: unknown or malformed messages, tenant mismatches and poison messages that exhausted
/// their deliveries. Any row raises the `viadere_queue_dead_letters_total` alert metric. The body is the envelope only (ids, never personal data).
final class QueueDeadLetterRecord: Model, @unchecked Sendable {
    static let schema = "queue_dead_letters"
    @ID(key: .id) var id: UUID?
    @OptionalField(key: "message_id") var messageId: UUID?
    @Field(key: "queue") var queue: String
    @OptionalField(key: "type") var type: String?
    @Field(key: "reason") var reason: String
    @Field(key: "body") var body: String
    @Field(key: "delivery_count") var deliveryCount: Int
    @Field(key: "dead_lettered_at") var deadLetteredAt: Date

    init() {}
}

/// `QueueOutbox.v1` (additive, forward-only): the outbox, the idempotency table, the database transport's queue and the dead-letter record.
struct CreateQueueOutbox: AsyncMigration {
    var name: String { "QueueOutbox.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema(OutboxMessageRecord.schema)
            .id()
            .field("queue", .string, .required)
            .field("type", .string, .required)
            .field("version", .int, .required)
            .field("ref", .uuid, .required)
            .field("tenant_id", .uuid)
            .field("payload_json", .string, .required)
            .field("not_before", .datetime)
            .field("created_at", .datetime, .required)
            .field("published_at", .datetime)
            .field("claimed_until", .datetime)
            .field("attempts", .int, .required)
            .field("last_error", .string)
            .create()
        try await db.schema(ProcessedMessageRecord.schema)
            .field("message_id", .uuid, .identifier(auto: false))
            .field("queue", .string, .required)
            .field("type", .string, .required)
            .field("processed_at", .datetime, .required)
            .create()
        try await db.schema(QueueMessageRecord.schema)
            .id()
            .field("queue", .string, .required)
            .field("body", .string, .required)
            .field("visible_at", .datetime, .required)
            .field("enqueued_at", .datetime, .required)
            .field("expires_at", .datetime, .required)
            .field("delivery_count", .int, .required)
            .field("lock_token", .string)
            .field("locked_until", .datetime)
            .create()
        try await db.schema(QueueDeadLetterRecord.schema)
            .id()
            .field("message_id", .uuid)
            .field("queue", .string, .required)
            .field("type", .string)
            .field("reason", .string, .required)
            .field("body", .string, .required)
            .field("delivery_count", .int, .required)
            .field("dead_lettered_at", .datetime, .required)
            .create()
        guard let sql = db as? any SQLDatabase else { return }
        // Compile-time constant names and columns only.
        for (name, table, columns) in [
            ("idx_outbox_unpublished", OutboxMessageRecord.schema, "published_at, created_at"),
            ("idx_processed_at", ProcessedMessageRecord.schema, "processed_at"),
            ("idx_queue_messages_due", QueueMessageRecord.schema, "queue, visible_at"),
            ("idx_queue_dead_letters_at", QueueDeadLetterRecord.schema, "dead_lettered_at"),
        ] {
            try await sql.raw(SQLQueryString("CREATE INDEX IF NOT EXISTS \(unsafeRaw: name) ON \(unsafeRaw: table) (\(unsafeRaw: columns))")).run()
        }
    }

    func revert(on db: any Database) async throws {
        for table in [QueueDeadLetterRecord.schema, QueueMessageRecord.schema, ProcessedMessageRecord.schema, OutboxMessageRecord.schema] {
            try await db.schema(table).delete()
        }
    }
}
