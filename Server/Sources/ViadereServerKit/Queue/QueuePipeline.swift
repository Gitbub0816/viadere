import Fluent
import Foundation
import Logging
import SQLKit
import ViadereCore

// MARK: - Message types

/// What a handler decided inside the message's transaction (the transaction that also writes the `processed_messages` marker).
enum QueueClaim: Sendable {
    /// Nothing more to do (the work was already done, or the row no longer exists).
    case done
    /// Not due yet: a follow-up message for the same work is scheduled at this time, in the same transaction.
    case retry(at: Date)
    /// The state transition committed with the marker (typically a compare-and-swap claim of the row); `work` performs the external effect after
    /// commit and returns when the work must run again, if it must.
    case afterCommit(QueueAfterCommit)
    /// The message is inconsistent with the row (a tenant mismatch): dead-letter it, execute nothing.
    case deadLetter(reason: String)
}

/// The external part of a message's work (sending an SMS, calling a webhook), run after the claim committed. Returns the time of the next attempt
/// when the row's state machine scheduled one; the consumer then enqueues a follow-up message.
typealias QueueAfterCommit = @Sendable (_ db: any Database, _ ctx: ServerContext) async throws -> Date?

/// One message type of the registry (SECURITY.md §2.91). Adding a type (a Loop action event, a hosted-inbox delivery, a notification step) is adding
/// one value here with its handler: the outbox, the transports, idempotency, dead-lettering and alerting are shared.
struct QueueMessageType: Sendable {
    let name: String
    let version: Int
    let queue: QueueName
    /// How long a message may wait before the broker dead-letters it (never more than the queue's default TTL in `Infra/azure/locals.tf`).
    let timeToLive: TimeInterval
    /// Whether the envelope must carry the tenant (business) the row belongs to.
    let requiresTenant: Bool
    /// Runs inside the message transaction. Must re-read state from the database and change it only by compare-and-swap.
    let claim: @Sendable (_ envelope: QueueEnvelope, _ tx: any Database, _ ctx: ServerContext) async throws -> QueueClaim

    var key: String { "\(name)@\(version)" }
}

/// The registered message types. A `(type, v)` pair that is not here is dead-lettered, never executed.
struct QueueRegistry: Sendable {
    let types: [String: QueueMessageType]

    init(_ types: [QueueMessageType]) {
        self.types = Dictionary(types.map { ($0.key, $0) }, uniquingKeysWith: { first, _ in first })
    }

    func type(for envelope: QueueEnvelope) -> QueueMessageType? { types["\(envelope.type)@\(envelope.version)"] }

    static let standard = QueueRegistry(QueueHandlers.all)
}

// MARK: - Outbox

enum Outbox {
    /// Records a message in the caller's transaction. The tenant is taken by the caller from the row it just wrote (trusted context), never from
    /// request input. Call it on the same `Database` (transaction) that wrote the row; when the caller is not in a transaction, wrap both writes.
    @discardableResult
    static func enqueue(_ type: QueueMessageType, ref: UUID, tenant: UUID? = nil, notBefore: Date? = nil, on db: any Database, ctx: ServerContext) async throws -> UUID {
        let id = UUID()
        let envelope = QueueEnvelope(type: type.name, version: type.version, id: id, ref: ref, tenant: tenant, notBefore: notBefore)
        let row = OutboxMessageRecord()
        row.id = id
        row.queue = type.queue.rawValue
        row.type = type.name
        row.version = type.version
        row.ref = ref
        row.tenantId = tenant
        row.payloadJSON = String(decoding: envelope.encoded(), as: UTF8.self)
        row.notBefore = envelope.notBefore
        row.createdAt = ctx.now
        row.attempts = 0
        try await row.create(on: db)
        // Wake the publisher: it reads only committed rows, so a wake before the commit costs nothing and the next one finds the row.
        ctx.queue.wake()
        return id
    }
}

/// Sends committed outbox rows to the transport and marks them published. Rows are claimed by compare-and-swap on `attempts` with a short lease,
/// so publishers on several instances never send the same row at the same time; a send that succeeded but whose mark failed is sent again later,
/// and the consumer's `processed_messages` makes that duplicate harmless.
struct OutboxPublisher {
    let db: any Database
    let ctx: ServerContext
    let transport: any QueueTransport

    static let lease: TimeInterval = 30

    @discardableResult
    func publishDue(limit: Int = 100) async throws -> Int {
        let now = ctx.now
        let due = try await OutboxMessageRecord.query(on: db).filter(\.$publishedAt == nil)
            .group(.or) { $0.filter(\.$claimedUntil == nil); $0.filter(\.$claimedUntil < now) }
            .sort(\.$createdAt, .ascending).limit(limit).all()
        var published = 0
        for row in due {
            guard let id = row.id, let queue = QueueName(rawValue: row.queue),
                  try await DB.swap(db, table: OutboxMessageRecord.schema, id: id, column: "attempts", expected: row.attempts, newValue: row.attempts + 1,
                                    extra: [("claimed_until", now.addingTimeInterval(Self.lease))]) else { continue }
            let ttl = QueueRegistry.standard.types["\(row.type)@\(row.version)"]?.timeToLive ?? 86_400
            do {
                try await transport.send(queue: queue, messageId: id, body: Data(row.payloadJSON.utf8), scheduledAt: row.notBefore, timeToLive: ttl)
                try await OutboxMessageRecord.query(on: db).filter(\.$id == id).set(\.$publishedAt, to: now).set(\.$lastError, to: nil).update()
                published += 1
            } catch {
                // Back off (the lease doubles per attempt, at most 10 minutes); the row stays unpublished and is retried.
                let backoff = min(Self.lease * pow(2, Double(min(row.attempts, 5))), 600)
                try? await OutboxMessageRecord.query(on: db).filter(\.$id == id).set(\.$claimedUntil, to: now.addingTimeInterval(backoff))
                    .set(\.$lastError, to: Self.errorCode(error)).update()
                ctx.metrics.count(.outboxPublishFailed)
                ctx.logger.warning("outbox publish failed", metadata: ["queue": "\(queue.rawValue)", "type": "\(type(of: error))"])
            }
        }
        return published
    }

    static func errorCode(_ error: any Error) -> String {
        if case QueueTransportError.service(let status) = error { return "service_\(status)" }
        return String(describing: type(of: error)).prefix(60).description
    }
}

// MARK: - Consumer

/// Processes received messages: strict envelope decoding, the type registry, idempotency, the handler's transaction and dead-lettering.
struct QueueConsumer {
    let db: any Database
    let ctx: ServerContext
    let transport: any QueueTransport
    var registry: QueueRegistry = .standard

    enum Outcome: Equatable, Sendable {
        case completed
        case duplicate
        case deadLettered(String)
        case abandoned
    }

    private struct Duplicate: Error {}
    private struct DeadLetterSignal: Error { let reason: String }

    /// Receives and processes up to `limit` messages from `queue` (stops when the queue is empty).
    @discardableResult
    func drain(_ queue: QueueName, limit: Int = 100, wait: TimeInterval = 0) async throws -> [Outcome] {
        var outcomes: [Outcome] = []
        while outcomes.count < limit, let message = try await transport.receive(queue: queue, wait: wait) {
            outcomes.append(await process(message))
        }
        return outcomes
    }

    func process(_ message: ReceivedQueueMessage) async -> Outcome {
        guard let envelope = try? QueueEnvelope.decode(message.body) else { return await deadLetter(message, envelope: nil, reason: "malformed") }
        if !message.messageId.isEmpty, message.messageId.lowercased() != envelope.id.uuidString.lowercased() {
            return await deadLetter(message, envelope: envelope, reason: "id_mismatch")
        }
        guard let type = registry.type(for: envelope) else { return await deadLetter(message, envelope: envelope, reason: "unknown_type") }
        guard type.queue == message.queue else { return await deadLetter(message, envelope: envelope, reason: "wrong_queue") }
        if type.requiresTenant, envelope.tenant == nil { return await deadLetter(message, envelope: envelope, reason: "missing_tenant") }
        do {
            if try await ProcessedMessageRecord.find(envelope.id, on: db) != nil { throw Duplicate() }
            let ctx = self.ctx
            let claim: QueueClaim = try await db.transaction { tx in
                // The marker and the handler's state transition commit together or not at all.
                let marker = ProcessedMessageRecord()
                marker.id = envelope.id
                marker.queue = type.queue.rawValue
                marker.type = type.name
                marker.processedAt = ctx.now
                try await marker.create(on: tx)
                let claim = try await type.claim(envelope, tx, ctx)
                switch claim {
                case .deadLetter(let reason): throw DeadLetterSignal(reason: reason)
                case .retry(let at): try await Outbox.enqueue(type, ref: envelope.ref, tenant: envelope.tenant, notBefore: at, on: tx, ctx: ctx)
                case .done, .afterCommit: break
                }
                return claim
            }
            if case .afterCommit(let work) = claim {
                do {
                    if let next = try await work(db, ctx) {
                        try await Outbox.enqueue(type, ref: envelope.ref, tenant: envelope.tenant, notBefore: max(next, ctx.now), on: db, ctx: ctx)
                    }
                } catch {
                    // The message is processed (its claim committed); the row's own state machine and the maintenance sweep take it from here.
                    ctx.metrics.count(.queueHandlerFailed)
                    ctx.logger.warning("queue work failed after commit", metadata: ["type": "\(type.name)", "error": "\(Swift.type(of: error))"])
                }
            }
            try? await transport.complete(message)
            ctx.metrics.count(.queueProcessed)
            return .completed
        } catch is Duplicate {
            ctx.metrics.count(.queueDuplicate)
            try? await transport.complete(message)
            return .duplicate
        } catch let signal as DeadLetterSignal {
            return await deadLetter(message, envelope: envelope, reason: signal.reason)
        } catch {
            // The transaction rolled back, so the message is not marked processed. A concurrent delivery may have won the marker race.
            if (try? await ProcessedMessageRecord.find(envelope.id, on: db)) != nil {
                ctx.metrics.count(.queueDuplicate)
                try? await transport.complete(message)
                return .duplicate
            }
            ctx.metrics.count(.queueHandlerFailed)
            ctx.logger.warning("queue handler failed", metadata: ["type": "\(type.name)", "delivery": "\(message.deliveryCount)", "error": "\(Swift.type(of: error))"])
            // Poison: the last allowed delivery failed too. Dead-letter it here (with the alert) instead of letting it cycle.
            if message.deliveryCount >= message.queue.maxDeliveries { return await deadLetter(message, envelope: envelope, reason: "max_deliveries") }
            try? await transport.abandon(message)
            return .abandoned
        }
    }

    private func deadLetter(_ message: ReceivedQueueMessage, envelope: QueueEnvelope?, reason: String) async -> Outcome {
        ctx.metrics.count(.queueDeadLettered)
        ctx.logger.error("queue message dead-lettered", metadata: ["queue": "\(message.queue.rawValue)", "reason": "\(reason)", "type": "\(envelope?.type ?? "?")"])
        try? await QueueDeadLetters.record(on: db, messageId: envelope?.id ?? UUID(uuidString: message.messageId), queue: message.queue.rawValue, type: envelope?.type,
                                           reason: reason, body: String(decoding: message.body, as: UTF8.self), deliveryCount: message.deliveryCount, now: ctx.now)
        try? await transport.deadLetter(message, reason: reason)
        return .deadLettered(reason)
    }
}

// MARK: - Runtime

/// The process's queue machinery: the transport (installed by `configure` once the database exists) and the publisher's wake flag.
final class QueueRuntime: @unchecked Sendable {
    private let lock = NSLock()
    private var _transport: (any QueueTransport)?
    private var pendingWake = false

    init(transport: (any QueueTransport)?) { _transport = transport }

    var transport: (any QueueTransport)? { lock.withLock { _transport } }

    func install(_ transport: any QueueTransport) { lock.withLock { if _transport == nil { _transport = transport } } }

    /// Signals the publisher loop that a row may be ready.
    func wake() { lock.withLock { pendingWake = true } }

    /// Returns at the first wake (checked every 50 ms) or after `timeout`.
    func waitForWake(timeout: Duration) async {
        let deadline = ContinuousClock.now + timeout
        while ContinuousClock.now < deadline, !Task.isCancelled {
            if lock.withLock({ () -> Bool in defer { pendingWake = false }; return pendingWake }) { return }
            try? await Task.sleep(for: .milliseconds(50))
        }
    }
}
