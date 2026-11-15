import Fluent
import Foundation
import SQLKit
import ViadereCore

/// A message received under a peek-lock: nobody else receives it until it is completed, abandoned, dead-lettered or the lock expires.
public struct ReceivedQueueMessage: Sendable, Equatable {
    public var queue: QueueName
    /// The broker's message id (the outbox id).
    public var messageId: String
    public var body: Data
    /// 1 on the first delivery.
    public var deliveryCount: Int
    /// The lock handle: a lock token (database) or the locked message's `Location` URI (Service Bus).
    public var lock: String

    public init(queue: QueueName, messageId: String, body: Data, deliveryCount: Int, lock: String) {
        self.queue = queue
        self.messageId = messageId
        self.body = body
        self.deliveryCount = deliveryCount
        self.lock = lock
    }
}

public enum QueueTransportError: Error, Sendable, Equatable {
    /// The broker refused or failed (status code only).
    case service(status: Int)
    /// The lock was lost (expired, or the message was completed by someone else).
    case lockLost
}

/// How queue messages travel (WP-B3, ADR-0014). Implementations: `ServiceBusRESTTransport` (Azure) and `DatabaseQueueTransport` (development, tests,
/// Fly, emergency fallback). Both are at-least-once: consumers are idempotent (`processed_messages`), so a duplicate delivery has no second effect.
public protocol QueueTransport: Sendable {
    /// Sends a message with `messageId` (the broker's duplicate key where it has one), visible from `scheduledAt` (scheduled enqueue), expiring
    /// `timeToLive` after it becomes visible (then dead-lettered by the broker).
    func send(queue: QueueName, messageId: UUID, body: Data, scheduledAt: Date?, timeToLive: TimeInterval) async throws
    /// Peek-lock receive. Waits up to `wait` seconds where the transport can long-poll; `nil` when nothing is available.
    func receive(queue: QueueName, wait: TimeInterval) async throws -> ReceivedQueueMessage?
    /// Removes the message (processing finished, or it was a duplicate).
    func complete(_ message: ReceivedQueueMessage) async throws
    /// Releases the lock so the message is delivered again (its delivery count grows).
    func abandon(_ message: ReceivedQueueMessage) async throws
    /// Takes the message out of circulation for good. The consumer has already recorded it in `queue_dead_letters` and raised the alert metric.
    /// (Service Bus's REST API has no dead-letter operation: that transport completes the message, and the database record is the dead letter;
    /// messages the broker itself dead-letters, on expiry or after `maxDeliveryCount`, stay in the broker's DLQ and alert through Azure Monitor.)
    func deadLetter(_ message: ReceivedQueueMessage, reason: String) async throws
    /// Extends the lock of a long-running handler.
    func renewLock(_ message: ReceivedQueueMessage) async throws
}

/// The `queue_messages` table with Service Bus semantics: peek-lock leases taken by compare-and-swap on the delivery count, scheduled visibility,
/// expiry and `maxDeliveryCount` dead-lettering. Any number of instances can consume concurrently.
public struct DatabaseQueueTransport: QueueTransport {
    static let lockDuration: TimeInterval = 60

    let database: @Sendable () -> any Database
    let now: @Sendable () -> Date

    public init(database: @escaping @Sendable () -> any Database, now: @escaping @Sendable () -> Date) {
        self.database = database
        self.now = now
    }

    public func send(queue: QueueName, messageId: UUID, body: Data, scheduledAt: Date?, timeToLive: TimeInterval) async throws {
        let db = database()
        // The primary key is the duplicate detection: a second send of the same message id is a no-op.
        if try await QueueMessageRecord.find(messageId, on: db) != nil { return }
        let current = now()
        let visible = max(scheduledAt ?? current, current)
        let row = QueueMessageRecord()
        row.id = messageId
        row.queue = queue.rawValue
        row.body = String(decoding: body, as: UTF8.self)
        row.visibleAt = visible
        row.enqueuedAt = current
        row.expiresAt = visible.addingTimeInterval(timeToLive)
        row.deliveryCount = 0
        do { try await row.create(on: db) } catch {
            if try await QueueMessageRecord.find(messageId, on: db) != nil { return } // a concurrent publisher won the race
            throw error
        }
    }

    public func receive(queue: QueueName, wait: TimeInterval) async throws -> ReceivedQueueMessage? {
        let db = database()
        let current = now()
        let candidates = try await QueueMessageRecord.query(on: db).filter(\.$queue == queue.rawValue).filter(\.$visibleAt <= current)
            .group(.or) { $0.filter(\.$lockedUntil == nil); $0.filter(\.$lockedUntil < current) }
            .sort(\.$visibleAt, .ascending).limit(10).all()
        for candidate in candidates {
            guard let id = candidate.id else { continue }
            // Expired, or a consumer died holding the last allowed delivery: the broker would dead-letter it, so does this transport.
            if candidate.expiresAt <= current || candidate.deliveryCount >= queue.maxDeliveries {
                try await moveToDeadLetters(candidate, reason: candidate.expiresAt <= current ? "expired" : "max_deliveries", on: db)
                continue
            }
            let token = SecureToken.generate(byteCount: 16)
            // Every lock increments the delivery count, so the count is also the lock version: one winner per delivery.
            guard try await DB.swap(db, table: QueueMessageRecord.schema, id: id, column: "delivery_count", expected: candidate.deliveryCount,
                                    newValue: candidate.deliveryCount + 1,
                                    extra: [("lock_token", token), ("locked_until", current.addingTimeInterval(Self.lockDuration))]) else { continue }
            return ReceivedQueueMessage(queue: queue, messageId: id.uuidString.lowercased(), body: Data(candidate.body.utf8),
                                        deliveryCount: candidate.deliveryCount + 1, lock: token)
        }
        return nil
    }

    private func locked(_ message: ReceivedQueueMessage, on db: any Database) -> QueryBuilder<QueueMessageRecord>? {
        guard let id = UUID(uuidString: message.messageId) else { return nil }
        return QueueMessageRecord.query(on: db).filter(\.$id == id).filter(\.$lockToken == message.lock)
    }

    public func complete(_ message: ReceivedQueueMessage) async throws {
        let db = database()
        guard let query = locked(message, on: db) else { throw QueueTransportError.lockLost }
        guard try await query.count() == 1 else { throw QueueTransportError.lockLost }
        try await locked(message, on: db)?.delete()
    }

    public func abandon(_ message: ReceivedQueueMessage) async throws {
        let db = database()
        try await locked(message, on: db)?.set(\.$lockToken, to: nil).set(\.$lockedUntil, to: nil).update()
    }

    public func deadLetter(_ message: ReceivedQueueMessage, reason: String) async throws {
        try await complete(message)
    }

    public func renewLock(_ message: ReceivedQueueMessage) async throws {
        let db = database()
        guard let query = locked(message, on: db), try await query.count() == 1 else { throw QueueTransportError.lockLost }
        try await locked(message, on: db)?.set(\.$lockedUntil, to: now().addingTimeInterval(Self.lockDuration)).update()
    }

    private func moveToDeadLetters(_ row: QueueMessageRecord, reason: String, on db: any Database) async throws {
        guard let id = row.id else { return }
        try await db.transaction { tx in
            // Only the transaction that removes the row records it (two consumers can see the same expired row).
            let removed = try await QueueMessageRecord.query(on: tx).filter(\.$id == id).filter(\.$deliveryCount == row.deliveryCount).count()
            guard removed == 1 else { return }
            try await QueueMessageRecord.query(on: tx).filter(\.$id == id).delete()
            try await QueueDeadLetters.record(on: tx, messageId: id, queue: row.queue, type: (try? QueueEnvelope.decode(Data(row.body.utf8)))?.type,
                                              reason: reason, body: row.body, deliveryCount: row.deliveryCount, now: now())
        }
    }
}

enum QueueDeadLetters {
    static func record(on db: any Database, messageId: UUID?, queue: String, type: String?, reason: String, body: String, deliveryCount: Int, now: Date) async throws {
        let row = QueueDeadLetterRecord()
        row.id = UUID()
        row.messageId = messageId
        row.queue = queue
        row.type = type
        row.reason = reason
        // A valid envelope holds ids only and is kept for inspection; anything else could be anything (a foreign or forged message), so only its
        // SHA-256 is kept.
        row.body = (try? QueueEnvelope.decode(Data(body.utf8))) != nil ? body : "sha256:" + SecureToken.sha256Hex(Data(body.utf8))
        row.deliveryCount = deliveryCount
        row.deadLetteredAt = now
        try await row.create(on: db)
    }
}
