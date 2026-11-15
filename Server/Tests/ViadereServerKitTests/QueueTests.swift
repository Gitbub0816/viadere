import Fluent
import FluentSQL
import Foundation
import SQLKit
import Vapor
import ViadereCore
import XCTest
@testable import ViadereServerKit

/// WP-B3 (queues, ADR-0014, SECURITY.md §2.91): the plan's "Tests first" for the transactional outbox, idempotent consumers, dead-lettering and the
/// envelope, on the database transport and on the Service Bus REST transport (against a stub).
final class QueueTests: XCTestCase {
    private func phone(_ n: Int = 1) -> PhoneNumber { PhoneNumber("+1480555\(String(format: "%04d", 100 + n))")! }

    private func transport(_ h: TestHarness) -> any QueueTransport { h.ctx.queue.transport! }

    private func serviceBus(_ stub: AzureStub) -> ServiceBusRESTTransport {
        ServiceBusRESTTransport(fqdn: AzureStub.serviceBus, tokens: FakeAccessTokens(), http: stub)
    }

    /// A test-only type whose effect is a database write that can be made to fail.
    private struct Probe {
        static func type(queue: QueueName = .consumerExport, failing: @escaping @Sendable () -> Bool) -> QueueMessageType {
            QueueMessageType(name: "test.probe", version: 1, queue: queue, timeToLive: 3600, requiresTenant: false) { envelope, tx, ctx in
                // The effect: a row written in the message transaction.
                let row = PlatformFlagRecord()
                row.id = UUID()
                row.flag = "test.probe"
                row.scope = envelope.ref.uuidString.lowercased()
                row.value = "applied"
                row.reason = "test"
                row.updatedBy = "test"
                row.updatedAt = ctx.now
                try await row.create(on: tx)
                if failing() { throw Abort(.internalServerError) }
                return .done
            }
        }
        static func effects(_ db: any Database, ref: UUID) async throws -> Int {
            try await PlatformFlagRecord.query(on: db).filter(\.$flag == "test.probe").filter(\.$scope == ref.uuidString.lowercased()).count()
        }
    }

    // MARK: Delivered twice, effect once

    func testAMessageDeliveredTwicePerformsItsEffectOnce() async throws {
        try await withHarness { h in
            try await OutboundSMS(db: h.db, ctx: h.ctx).enqueue(to: phone(), body: "Your code is 123456", sensitive: true)
            let outbox = try await OutboxMessageRecord.query(on: h.db).all()
            XCTAssertEqual(outbox.count, 1, "the row and its message were written together")
            try await OutboxPublisher(db: h.db, ctx: h.ctx, transport: transport(h)).publishDue()
            let message = try await XCTUnwrapAsync(await transport(h).receive(queue: .smsOutbound, wait: 0))
            let consumer = QueueConsumer(db: h.db, ctx: h.ctx, transport: transport(h))
            let first = await consumer.process(message)
            XCTAssertEqual(first, .completed)
            // The broker redelivers the same message (Service Bus Basic has no duplicate detection; a lost completion does the same).
            let second = await consumer.process(message)
            XCTAssertEqual(second, .duplicate)
            XCTAssertEqual(h.texts.sent.count, 1, "one SMS for two deliveries")
            let markers = try await ProcessedMessageRecord.query(on: h.db).count()
            XCTAssertEqual(markers, 1)
            // The safety-net sweep finds nothing left to send.
            try await h.runJobs()
            XCTAssertEqual(h.texts.sent.count, 1)
        }
    }

    func testServiceBusRedeliveryOfTheSameMessageIdIsHarmless() async throws {
        let stub = AzureStub()
        let bus = serviceBus(stub)
        try await withHarness(overrides: { $0.queueTransport = bus }) { h in
            try await OutboundSMS(db: h.db, ctx: h.ctx).enqueue(to: phone(2), body: "Hello")
            try await OutboxPublisher(db: h.db, ctx: h.ctx, transport: bus).publishDue()
            let sent = try XCTUnwrap(stub.messages("sms-outbound").first)
            // A second copy with the same MessageId (a publisher retry after a lost mark, or a replay).
            stub.inject(queue: "sms-outbound", id: sent.id, body: sent.body)
            let outcomes = try await QueueConsumer(db: h.db, ctx: h.ctx, transport: bus).drain(.smsOutbound)
            XCTAssertEqual(outcomes, [.completed, .duplicate])
            XCTAssertEqual(h.texts.sent.count, 1)
            XCTAssertTrue(stub.messages("sms-outbound").isEmpty, "both copies were completed")
        }
    }

    // MARK: Rolled back, not processed

    func testAMessageWhoseEffectRolledBackIsNotMarkedProcessed() async throws {
        try await withHarness { h in
            let failing = ManagedFlag(true)
            let type = Probe.type(failing: { failing.value })
            var consumer = QueueConsumer(db: h.db, ctx: h.ctx, transport: transport(h))
            consumer.registry = QueueRegistry([type])
            let ref = UUID()
            try await Outbox.enqueue(type, ref: ref, on: h.db, ctx: h.ctx)
            try await OutboxPublisher(db: h.db, ctx: h.ctx, transport: transport(h)).publishDue()
            let message = try await XCTUnwrapAsync(await transport(h).receive(queue: .consumerExport, wait: 0))
            let outcome = await consumer.process(message)
            XCTAssertEqual(outcome, .abandoned)
            try await eq(try await Probe.effects(h.db, ref: ref), 0, "the effect rolled back")
            try await eq(try await ProcessedMessageRecord.query(on: h.db).count(), 0, "and the message is not marked processed")
            // It is delivered again and, once the effect commits, processed exactly once.
            failing.value = false
            let retry = try await XCTUnwrapAsync(await transport(h).receive(queue: .consumerExport, wait: 0))
            XCTAssertEqual(retry.deliveryCount, 2)
            let processed = await consumer.process(retry)
            XCTAssertEqual(processed, .completed)
            try await eq(try await Probe.effects(h.db, ref: ref), 1)
            try await eq(try await ProcessedMessageRecord.query(on: h.db).count(), 1)
        }
    }

    // MARK: Poison messages

    func testAPoisonMessageReachesTheDeadLetterQueueAfterMaxDeliveriesAndRaisesTheAlertMetric() async throws {
        for useServiceBus in [false, true] {
            let stub = AzureStub()
            try await withHarness(overrides: { if useServiceBus { $0.queueTransport = self.serviceBus(stub) } }) { h in
                let type = Probe.type(failing: { true })
                var consumer = QueueConsumer(db: h.db, ctx: h.ctx, transport: transport(h))
                consumer.registry = QueueRegistry([type])
                let ref = UUID()
                try await Outbox.enqueue(type, ref: ref, on: h.db, ctx: h.ctx)
                try await OutboxPublisher(db: h.db, ctx: h.ctx, transport: transport(h)).publishDue()
                var outcomes: [QueueConsumer.Outcome] = []
                for _ in 0..<5 { outcomes += try await consumer.drain(.consumerExport, limit: 1) }
                XCTAssertEqual(QueueName.consumerExport.maxDeliveries, 3)
                XCTAssertEqual(outcomes, [.abandoned, .abandoned, .deadLettered("max_deliveries")], "service bus: \(useServiceBus)")
                let dead = try await QueueDeadLetterRecord.query(on: h.db).all()
                XCTAssertEqual(dead.count, 1)
                XCTAssertEqual(dead.first?.reason, "max_deliveries")
                XCTAssertEqual(dead.first?.deliveryCount, 3)
                XCTAssertEqual(h.ctx.metrics.value(.queueDeadLettered), 1, "the alert metric")
                XCTAssertTrue(h.ctx.metrics.render(gauges: []).contains("viadere_security_events_total{event=\"queue_dead_lettered\"} 1"))
                try await eq(try await Probe.effects(h.db, ref: ref), 0)
                let more = try await consumer.drain(.consumerExport)
                XCTAssertTrue(more.isEmpty, "it is out of circulation")
            }
        }
    }

    /// The database transport also dead-letters what the broker would: an expired message, and one whose consumer died on its last delivery.
    func testTheDatabaseTransportDeadLettersExpiredMessages() async throws {
        try await withHarness { h in
            let type = Probe.type(failing: { false })
            try await Outbox.enqueue(type, ref: UUID(), on: h.db, ctx: h.ctx)
            try await OutboxPublisher(db: h.db, ctx: h.ctx, transport: transport(h)).publishDue()
            h.clock.advance(by: 86_401) // the publisher's default time to live for a type it does not know
            let received = try await transport(h).receive(queue: .consumerExport, wait: 0)
            XCTAssertNil(received)
            let dead = try await QueueDeadLetterRecord.query(on: h.db).all()
            XCTAssertEqual(dead.map(\.reason), ["expired"])
        }
    }

    // MARK: Outbox and commit

    func testAnOutboxRowIsNeverPublishedBeforeItsTransactionCommits() async throws {
        try await withHarness { h in
            // A transaction that rolls back leaves no message.
            do {
                try await h.db.transaction { tx in
                    try await OutboundSMS(db: tx, ctx: h.ctx).enqueue(to: PhoneNumber("+14805550103")!, body: "never")
                    throw Abort(.conflict)
                }
                XCTFail()
            } catch {}
            let published = try await OutboxPublisher(db: h.db, ctx: h.ctx, transport: transport(h)).publishDue()
            XCTAssertEqual(published, 0)
            try await eq(try await OutboxMessageRecord.query(on: h.db).count(), 0)
            try await eq(try await QueueMessageRecord.query(on: h.db).count(), 0)

            // While the transaction is open, a publisher on another connection sees nothing (PostgreSQL; SQLite serializes all writers on one
            // connection, so the concurrent half needs a server database).
            if DB.isPostgres(h.db) {
                let observed = try await h.db.transaction { tx -> Int in
                    try await OutboundSMS(db: tx, ctx: h.ctx).enqueue(to: PhoneNumber("+14805550104")!, body: "pending")
                    return try await OutboxPublisher(db: h.app.db, ctx: h.ctx, transport: h.ctx.queue.transport!).publishDue()
                }
                XCTAssertEqual(observed, 0, "an uncommitted row is invisible to the publisher")
                let afterCommit = try await OutboxPublisher(db: h.db, ctx: h.ctx, transport: transport(h)).publishDue()
                XCTAssertEqual(afterCommit, 1)
            }
        }
    }

    func testAFailedSendStaysUnpublishedAndIsRetried() async throws {
        let stub = AzureStub()
        let tokens = FakeAccessTokens()
        let bus = ServiceBusRESTTransport(fqdn: AzureStub.serviceBus, tokens: tokens, http: stub)
        try await withHarness(overrides: { $0.queueTransport = bus }) { h in
            try await OutboundSMS(db: h.db, ctx: h.ctx).enqueue(to: phone(5), body: "Hello")
            tokens.failing = true
            try await eq(try await OutboxPublisher(db: h.db, ctx: h.ctx, transport: bus).publishDue(), 0)
            let row = try await XCTUnwrapAsync(await OutboxMessageRecord.query(on: h.db).first())
            XCTAssertNil(row.publishedAt)
            XCTAssertEqual(h.ctx.metrics.value(.outboxPublishFailed), 1)
            tokens.failing = false
            try await eq(try await OutboxPublisher(db: h.db, ctx: h.ctx, transport: bus).publishDue(), 0, "backing off")
            h.clock.advance(by: 120)
            try await eq(try await OutboxPublisher(db: h.db, ctx: h.ctx, transport: bus).publishDue(), 1)
            XCTAssertEqual(stub.messages("sms-outbound").count, 1)
        }
    }

    // MARK: Unknown types and versions

    func testAMessageWithAnUnknownTypeOrVersionIsDeadLetteredNotExecuted() async throws {
        try await withHarness { h in
            let row = try await OutboundSMS(db: h.db, ctx: h.ctx).enqueue(to: phone(6), body: "do not send")
            // Drop the genuine message so only the crafted ones exist.
            try await OutboxMessageRecord.query(on: h.db).delete()
            let ref = try XCTUnwrap(row.id)
            let crafted: [(QueueName, Data, String)] = [
                (.smsOutbound, QueueEnvelope(type: "sms.send", version: 2, id: UUID(), ref: ref).encoded(), "unknown_type"),
                (.smsOutbound, QueueEnvelope(type: "loop.action_event", version: 1, id: UUID(), ref: ref).encoded(), "unknown_type"),
                (.smsOutbound, Data(#"{"id":"x","ref":"y","type":"sms.send","v":1}"#.utf8), "malformed"),
                (.smsOutbound, Data(#"{"id":"\#(UUID().uuidString.lowercased())","ref":"\#(ref.uuidString.lowercased())","type":"sms.send","v":true}"#.utf8), "malformed"),
                (.smsOutbound, Data(#"{"id":"\#(UUID().uuidString.lowercased())","phone":"+14805550106","ref":"\#(ref.uuidString.lowercased())","type":"sms.send","v":1}"#.utf8), "malformed"),
                (.webhookDelivery, QueueEnvelope(type: "sms.send", version: 1, id: UUID(), ref: ref).encoded(), "wrong_queue"),
            ]
            for (queue, body, _) in crafted {
                let id = (try? QueueEnvelope.decode(body))?.id ?? UUID()
                try await transport(h).send(queue: queue, messageId: id, body: body, scheduledAt: nil, timeToLive: 3600)
            }
            let consumer = QueueConsumer(db: h.db, ctx: h.ctx, transport: transport(h))
            var outcomes: [QueueConsumer.Outcome] = []
            for queue in [QueueName.smsOutbound, .webhookDelivery] { outcomes += try await consumer.drain(queue) }
            XCTAssertEqual(outcomes.sorted { "\($0)" < "\($1)" }, crafted.map { QueueConsumer.Outcome.deadLettered($0.2) }.sorted { "\($0)" < "\($1)" })
            XCTAssertTrue(h.texts.sent.isEmpty, "nothing was executed")
            try await eq(try await ProcessedMessageRecord.query(on: h.db).count(), 0)
            let dead = try await QueueDeadLetterRecord.query(on: h.db).all()
            XCTAssertEqual(dead.count, crafted.count)
            // A body that is not an envelope is kept only as a hash (it could be anything).
            XCTAssertTrue(dead.contains { $0.body.hasPrefix("sha256:") })
            XCTAssertFalse(dead.contains { $0.body.contains("+14805550106") })
            XCTAssertEqual(h.ctx.metrics.value(.queueDeadLettered), crafted.count)
            try await eq(try await SMSOutboundRecord.find(ref, on: h.db)?.status, "queued", "the row is untouched")
        }
    }

    /// The tenant comes from trusted context and must match the row: a message naming another business is dead-lettered, not executed.
    func testAMessageWhoseTenantDoesNotMatchItsRowIsDeadLettered() async throws {
        try await withHarness { h in
            let business = try await h.makeBusiness(name: "Tenant Co", handle: "tenantco")
            let other = try await h.makeBusiness(name: "Other Co", handle: "otherco")
            let created = try await h.businessPost(business, APIRoutes.businessWebhookCreate.template,
                                                   CreateWebhookRequest(url: URL(string: "https://hooks.example.com/viadere")!, events: [.messageReceived]))
            XCTAssertTrue([.ok, .created].contains(created.status), created.text)
            let subscription = try await XCTUnwrapAsync(await WebhookSubscriptionRecord.query(on: h.db).filter(\.$businessId == business.id.uuid).first())
            let deliveryId = try await WebhookService(db: h.db, ctx: h.ctx).sendTestEvent(businessId: business.id, id: WebhookSubscriptionID(subscription.id!))
            try await OutboxMessageRecord.query(on: h.db).delete()
            let forged = QueueEnvelope(type: "webhook.deliver", version: 1, id: UUID(), ref: deliveryId, tenant: other.id.uuid)
            try await transport(h).send(queue: .webhookDelivery, messageId: forged.id, body: forged.encoded(), scheduledAt: nil, timeToLive: 3600)
            let missing = QueueEnvelope(type: "webhook.deliver", version: 1, id: UUID(), ref: deliveryId)
            try await transport(h).send(queue: .webhookDelivery, messageId: missing.id, body: missing.encoded(), scheduledAt: nil, timeToLive: 3600)
            let sentBefore = h.webhooks.received.count
            let outcomes = try await QueueConsumer(db: h.db, ctx: h.ctx, transport: transport(h)).drain(.webhookDelivery)
            XCTAssertEqual(Set(outcomes.map { "\($0)" }), Set(["deadLettered(\"tenant_mismatch\")", "deadLettered(\"missing_tenant\")"]))
            XCTAssertEqual(h.webhooks.received.count, sentBefore, "nothing was delivered")
        }
    }

    // MARK: End to end

    /// The queue path performs exactly the work of the sweep it replaces, with the same state machine; a retry becomes a scheduled follow-up.
    func testTheQueuePathDeliversAndSchedulesRetriesWithTheExistingBackoff() async throws {
        try await withHarness { h in
            h.texts.failNext(1)
            try await OutboundSMS(db: h.db, ctx: h.ctx).enqueue(to: phone(7), body: "Retry me")
            await QueuePump(app: h.app).runOnce()
            XCTAssertTrue(h.texts.sent.isEmpty, "the first attempt failed transiently")
            let row = try await XCTUnwrapAsync(await SMSOutboundRecord.query(on: h.db).first())
            XCTAssertEqual(row.status, "queued")
            XCTAssertEqual(row.attempts, 1)
            // The follow-up message is scheduled at the row's next attempt (15 s backoff), not before.
            let followUp = try await XCTUnwrapAsync(await OutboxMessageRecord.query(on: h.db).filter(\.$publishedAt == nil).first())
            XCTAssertEqual(followUp.notBefore, row.nextAttemptAt)
            await QueuePump(app: h.app).runOnce()
            XCTAssertTrue(h.texts.sent.isEmpty, "not due yet")
            h.clock.advance(by: 16)
            await QueuePump(app: h.app).runOnce()
            XCTAssertEqual(h.texts.sent.map(\.body), ["Retry me"])
            let done = try await XCTUnwrapAsync(await SMSOutboundRecord.query(on: h.db).first())
            XCTAssertEqual(done.status, "sent")
        }
    }

    /// Interaction expiry is a scheduled message at `expires_at`.
    func testAnInteractionExpiresThroughItsScheduledMessage() async throws {
        try await withHarness { h in
            let business = try await h.makeBusiness(name: "Expiry Co", handle: "expiryco")
            let consumer = try await h.readyConsumer(name: "Expiry Test")
            let relationship = try await h.connect(consumer, to: business)
            let interaction = try await h.issue(business, relationship: relationship, payload: .authorize(.sample()), ttl: 120).json(Interaction.self)
            let scheduled = try await XCTUnwrapAsync(await OutboxMessageRecord.query(on: h.db).filter(\.$type == "interaction.expire").first())
            XCTAssertEqual(scheduled.ref, interaction.id.uuid)
            XCTAssertEqual(scheduled.tenantId, business.id.uuid, "the tenant comes from the row, not from the request")
            let record = try await XCTUnwrapAsync(await InteractionRecord.find(interaction.id.uuid, on: h.db))
            XCTAssertEqual(scheduled.notBefore, Date(timeIntervalSince1970: floor(record.expiresAt.timeIntervalSince1970)))
            // The message carries ids only.
            let envelope = try QueueEnvelope.decode(Data(scheduled.payloadJSON.utf8))
            XCTAssertEqual(Set((try JSONSerialization.jsonObject(with: Data(scheduled.payloadJSON.utf8)) as? [String: Any] ?? [:]).keys), ["id", "not_before", "ref", "tenant", "type", "v"])
            XCTAssertEqual(envelope.type, "interaction.expire")
            await QueuePump(app: h.app).runOnce()
            try await eq(try await InteractionRecord.find(interaction.id.uuid, on: h.db)?.status, InteractionStatus.pending.rawValue, "not before expires_at")
            h.clock.advance(by: record.expiresAt.timeIntervalSince(h.clock.now()) + 1)
            await QueuePump(app: h.app).runOnce()
            try await eq(try await InteractionRecord.find(interaction.id.uuid, on: h.db)?.status, InteractionStatus.expired.rawValue)
        }
    }

    // MARK: Transports and envelope

    func testTheServiceBusRESTTransportContract() async throws {
        let stub = AzureStub()
        let tokens = FakeAccessTokens()
        let bus = ServiceBusRESTTransport(fqdn: AzureStub.serviceBus, tokens: tokens, http: stub)
        let id = UUID()
        let scheduled = Date(timeIntervalSince1970: 1_900_000_000)
        try await bus.send(queue: .expiry, messageId: id, body: Data("{}".utf8), scheduledAt: scheduled, timeToLive: 600)
        let send = try XCTUnwrap(stub.calls.first)
        XCTAssertEqual(send.url, "https://\(AzureStub.serviceBus)/expiry/messages")
        XCTAssertEqual(send.headers["Authorization"], "Bearer token-for-servicebus.azure.net")
        let properties = try XCTUnwrap(try JSONSerialization.jsonObject(with: Data(try XCTUnwrap(send.headers["BrokerProperties"]).utf8)) as? [String: Any])
        XCTAssertEqual(properties["MessageId"] as? String, id.uuidString.lowercased())
        XCTAssertEqual(properties["ScheduledEnqueueTimeUtc"] as? String, "Sun, 17 Mar 2030 17:46:40 GMT")
        XCTAssertEqual(properties["TimeToLive"] as? Int, 600)
        stub.now = { scheduled.addingTimeInterval(1) }
        let received = try await XCTUnwrapAsync(await bus.receive(queue: .expiry, wait: 30))
        XCTAssertEqual(received.messageId, id.uuidString.lowercased())
        XCTAssertEqual(received.deliveryCount, 1)
        XCTAssertTrue(stub.calls.contains { $0.url == "https://\(AzureStub.serviceBus)/expiry/messages/head?timeout=30" })
        try await bus.abandon(received)
        let again = try await XCTUnwrapAsync(await bus.receive(queue: .expiry, wait: 0))
        XCTAssertEqual(again.deliveryCount, 2)
        try await bus.renewLock(again)
        try await bus.complete(again)
        let empty = try await bus.receive(queue: .expiry, wait: 0)
        XCTAssertNil(empty)
        do { try await bus.complete(again); XCTFail("a lost lock") } catch let error as QueueTransportError { XCTAssertEqual(error, .lockLost) }
        // A lock location outside the namespace or queue is never called (the token would go with it).
        var forged = again
        forged.lock = "https://evil.example/expiry/messages/1/abc"
        let before = stub.calls.count
        do { try await bus.complete(forged); XCTFail() } catch {}
        forged.lock = "https://\(AzureStub.serviceBus)/push/messages/1/abc"
        do { try await bus.complete(forged); XCTFail() } catch {}
        XCTAssertEqual(stub.calls.count, before)
        XCTAssertFalse(ServerConfig.isServiceBusFQDN("evil.example.com"))
        XCTAssertTrue(ServerConfig.isServiceBusFQDN("sb-viadere-stgl.servicebus.windows.net"))
    }

    func testTheEnvelopeIsCanonicalStrictAndCarriesIdsOnly() throws {
        let id = UUID(), ref = UUID(), tenant = UUID()
        let envelope = QueueEnvelope(type: "webhook.deliver", version: 1, id: id, ref: ref, tenant: tenant, notBefore: Date(timeIntervalSince1970: 1_900_000_000.7))
        let text = String(decoding: envelope.encoded(), as: UTF8.self)
        XCTAssertEqual(text, #"{"id":"\#(id.uuidString.lowercased())","not_before":"2030-03-17T17:46:40Z","ref":"\#(ref.uuidString.lowercased())","tenant":"\#(tenant.uuidString.lowercased())","type":"webhook.deliver","v":1}"#)
        XCTAssertEqual(try QueueEnvelope.decode(envelope.encoded()), envelope)
        for bad in [
            #"{"id":"\#(id.uuidString)","ref":"\#(ref.uuidString.lowercased())","type":"a.b","v":1}"#,           // uppercase id
            #"{"id":"\#(id.uuidString.lowercased())","ref":"\#(ref.uuidString.lowercased())","type":"A.b","v":1}"#, // type casing
            #"{"id":"\#(id.uuidString.lowercased())","ref":"\#(ref.uuidString.lowercased())","type":"a.b","v":0}"#,
            #"{"id":"\#(id.uuidString.lowercased())","ref":"\#(ref.uuidString.lowercased())","type":"a.b","v":1.5}"#,
            #"{"id":"\#(id.uuidString.lowercased())","ref":"\#(ref.uuidString.lowercased())","type":"a.b"}"#,
            #"{"id":"\#(id.uuidString.lowercased())","ref":"\#(ref.uuidString.lowercased())","type":"a.b","v":1,"not_before":"2030-03-17T17:46:40+01:00"}"#,
            #"{"id":"\#(id.uuidString.lowercased())","ref":"\#(ref.uuidString.lowercased())","type":"a.b","v":1,"body":"hi"}"#,
            "[]", "", String(repeating: " ", count: 2000),
        ] {
            XCTAssertThrowsError(try QueueEnvelope.decode(Data(bad.utf8)), bad)
        }
        // Every registered type maps to a queue the infrastructure creates, with matching delivery limits.
        let infra = ["push": 5, "sms-outbound": 8, "channel-outbound": 8, "webhook-delivery": 8, "wallet-push": 8, "operator-notices": 8, "consumer-export": 3, "expiry": 10, "loop-delivery": 8, "loop-timeout": 10]
        for queue in QueueName.allCases { XCTAssertEqual(infra[queue.rawValue], queue.maxDeliveries, queue.rawValue) }
        for type in QueueHandlers.all + LoopQueue.all { XCTAssertTrue(QueueEnvelope.isTypeName(type.name), type.name) }
        XCTAssertEqual(Set(QueueHandlers.all.map(\.key)).count, QueueHandlers.all.count, "no duplicate registrations")
    }
}

/// A Sendable boolean the tests flip while a handler runs.
final class ManagedFlag: @unchecked Sendable {
    private let lock = NSLock()
    private var stored: Bool
    init(_ value: Bool) { stored = value }
    var value: Bool {
        get { lock.withLock { stored } }
        set { lock.withLock { stored = newValue } }
    }
}
