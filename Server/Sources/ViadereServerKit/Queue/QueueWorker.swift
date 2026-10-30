import Fluent
import Foundation
import Vapor

/// One pass of the queue pipeline: publish the committed outbox rows, then consume what is available on every queue. Used by the in-process loop
/// (`BackgroundJobs.runOnce`) and by tests; the worker role runs the same steps continuously (`QueueWorker`).
struct QueuePump {
    let app: Application

    func runOnce() async {
        let ctx = app.ctx
        guard let transport = ctx.queue.transport else { return }
        do { try await OutboxPublisher(db: app.db, ctx: ctx, transport: transport).publishDue() } catch {
            app.logger.warning("outbox publisher failed", metadata: ["type": "\(type(of: error))"])
        }
        let consumer = QueueConsumer(db: app.db, ctx: ctx, transport: transport)
        for queue in QueueName.allCases {
            do { _ = try await consumer.drain(queue, limit: 100) } catch {
                app.logger.warning("queue receive failed", metadata: ["queue": "\(queue.rawValue)", "type": "\(type(of: error))"])
            }
        }
    }

    /// Published outbox rows after 7 days, idempotency markers after 14 days (longer than any message's time to live, so a late duplicate still
    /// finds its marker), dead-letter records after 30 days.
    static func purge(on db: any Database, now: Date) async throws {
        try await OutboxMessageRecord.query(on: db).filter(\.$publishedAt != nil).filter(\.$publishedAt < now.addingTimeInterval(-7 * 86_400)).delete()
        try await ProcessedMessageRecord.query(on: db).filter(\.$processedAt < now.addingTimeInterval(-15 * 86_400)).delete()
        try await QueueDeadLetterRecord.query(on: db).filter(\.$deadLetteredAt < now.addingTimeInterval(-30 * 86_400)).delete()
    }
}

/// The long-running queue machinery of a process:
/// - every role that writes the outbox (api, worker, combined) runs the **publisher**, woken right after a commit and polling once a second;
/// - the worker runs one **consumer** loop per queue (long-polling where the transport can).
final class QueueWorker: LifecycleHandler, @unchecked Sendable {
    private let lock = NSLock()
    private var tasks: [_Concurrency.Task<Void, Never>] = []
    let consume: Bool

    init(consume: Bool) { self.consume = consume }

    func didBoot(_ application: Application) throws { start(application) }
    func didBootAsync(_ application: Application) async throws { start(application) }

    private func start(_ application: Application) {
        lock.withLock {
            guard tasks.isEmpty, let transport = application.ctx.queue.transport else { return }
            let ctx = application.ctx
            let logger = application.logger
            tasks.append(_Concurrency.Task { [application] in
                while !_Concurrency.Task.isCancelled {
                    do { try await OutboxPublisher(db: application.db, ctx: ctx, transport: transport).publishDue() } catch {
                        logger.warning("outbox publisher failed", metadata: ["type": "\(type(of: error))"])
                    }
                    await ctx.queue.waitForWake(timeout: .seconds(1))
                }
            })
            guard consume else { return }
            for queue in QueueName.allCases {
                tasks.append(_Concurrency.Task { [application] in
                    let consumer = QueueConsumer(db: application.db, ctx: ctx, transport: transport)
                    while !_Concurrency.Task.isCancelled {
                        do {
                            // Service Bus long-polls up to 20 s; the database transport answers at once, so it sleeps when the queue is empty.
                            if try await consumer.drain(queue, limit: 50, wait: 20).isEmpty { try? await _Concurrency.Task.sleep(for: .milliseconds(500)) }
                        } catch {
                            logger.warning("queue receive failed", metadata: ["queue": "\(queue.rawValue)", "type": "\(type(of: error))"])
                            try? await _Concurrency.Task.sleep(for: .seconds(5))
                        }
                    }
                })
            }
        }
    }

    func shutdown(_ application: Application) {
        lock.withLock {
            for task in tasks { task.cancel() }
            tasks.removeAll()
        }
    }

    func shutdownAsync(_ application: Application) async {
        let current = lock.withLock { () -> [_Concurrency.Task<Void, Never>] in
            defer { tasks.removeAll() }
            return tasks
        }
        for task in current { task.cancel() }
        for task in current { await task.value }
    }
}
