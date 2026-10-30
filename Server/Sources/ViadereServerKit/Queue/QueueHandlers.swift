import Fluent
import Foundation
import ViadereCore

/// The message types and their handlers (plan 5.7). Each handler moves one existing background task onto a queue **without changing its
/// semantics**: the row's compare-and-swap state machine stays the source of truth, and the claim that makes an attempt exclusive commits in the
/// same transaction as the `processed_messages` marker. The periodic sweep (`MaintenanceTasks`) still runs the same per-row code as a safety net, so
/// a row whose message was lost, expired or dead-lettered is never stranded.
///
/// Reserved for the product expansion (FEATURE-EXPANSION-v4 A2, A3, A7; not registered yet, so a message of these types is dead-lettered):
/// `loop.action_event` (an action event with its outcome state accepted, rejected, pending, timed out or unknown), `inbox.deliver` (a hosted-inbox
/// delivery), `notify.step` (a notification-orchestrator step) and `push.send` (approval wake-up pushes). Each becomes one `QueueMessageType` with a
/// claim on its own row; delivery, retry and DLQ guarantees come from this pipeline.
enum QueueHandlers {
    static let all: [QueueMessageType] = [smsSend, channelDeliver, webhookDeliver, walletPush, operatorNotice, consumerExport, interactionExpire, approveExpire, identityMaintenance]

    /// A short delay before trying again when a row is busy (another message of the same phone ahead of it, a notice claimed elsewhere).
    static let busyRetry: TimeInterval = 15

    // MARK: SMS

    static let smsSend = QueueMessageType(name: "sms.send", version: 1, queue: .smsOutbound, timeToLive: 86_400, requiresTenant: false) { envelope, tx, ctx in
        guard let row = try await SMSOutboundRecord.find(envelope.ref, on: tx), row.status == "queued" else { return .done }
        let now = ctx.now
        if row.nextAttemptAt > now { return .retry(at: row.nextAttemptAt) }
        // Ordering per phone (as in `sendDue`): never overtake an earlier message that is still waiting for the same number.
        let earlier = try await SMSOutboundRecord.query(on: tx).filter(\.$phoneHash == row.phoneHash).filter(\.$seq < row.seq)
            .group(.or) { $0.filter(\.$status == "queued"); $0.filter(\.$status == "sending") }.count()
        if earlier > 0 { return .retry(at: now.addingTimeInterval(busyRetry)) }
        guard let id = row.id, try await DB.swap(tx, table: SMSOutboundRecord.schema, id: id, column: "status", expected: "queued", newValue: "sending") else { return .done }
        return .afterCommit { db, ctx in
            guard let claimed = try await SMSOutboundRecord.find(id, on: db), claimed.status == "sending" else { return nil }
            _ = try await OutboundSMS(db: db, ctx: ctx).dispatch(claimed, now: ctx.now)
            guard let after = try await SMSOutboundRecord.find(id, on: db), after.status == "queued" else { return nil }
            return after.nextAttemptAt
        }
    }

    // MARK: Channels (SMS / RCS deliveries of interactions)

    static let channelDeliver = QueueMessageType(name: "channel.deliver", version: 1, queue: .channelOutbound, timeToLive: 86_400, requiresTenant: true) { envelope, tx, ctx in
        guard let row = try await ChannelOutboundRecord.find(envelope.ref, on: tx) else { return .done }
        guard row.businessId == envelope.tenant else { return .deadLetter(reason: "tenant_mismatch") }
        guard row.status == "queued" else { return .done }
        let now = ctx.now
        if row.nextAttemptAt > now { return .retry(at: row.nextAttemptAt) }
        guard let id = row.id, try await DB.swap(tx, table: ChannelOutboundRecord.schema, id: id, column: "status", expected: "queued", newValue: "sending",
                                                 extra: [("next_attempt_at", now)]) else { return .done }
        return .afterCommit { db, ctx in
            guard let claimed = try await ChannelOutboundRecord.find(id, on: db), claimed.status == "sending" else { return nil }
            try await ChannelRouter(db: db, ctx: ctx).process(claimed)
            guard let after = try await ChannelOutboundRecord.find(id, on: db), after.status == "queued" else { return nil }
            return after.nextAttemptAt
        }
    }

    // MARK: Webhooks

    static let webhookDeliver = QueueMessageType(name: "webhook.deliver", version: 1, queue: .webhookDelivery, timeToLive: 3 * 86_400, requiresTenant: true) { envelope, tx, ctx in
        guard let delivery = try await WebhookDeliveryRecord.find(envelope.ref, on: tx) else { return .done }
        guard delivery.businessId == envelope.tenant else { return .deadLetter(reason: "tenant_mismatch") }
        guard ["pending", "sending"].contains(delivery.status) else { return .done }
        let now = ctx.now
        if delivery.nextAttemptAt > now { return .retry(at: delivery.nextAttemptAt) }
        // Paused endpoints and businesses (G-5) keep their deliveries queued; the sweep sends them after the resume.
        if try await WebhookSubscriptionRecord.find(delivery.subscriptionId, on: tx)?.pausedAt != nil { return .done }
        let pauses = try await PlatformFlagRecord.query(on: tx).filter(\.$flag == PlatformFlag.webhooksPause.rawValue).all()
        if pauses.contains(where: { $0.scope == PlatformFlags.globalScope || UUID(uuidString: $0.scope) == delivery.businessId }) { return .done }
        // Claim by compare-and-swap on the attempt counter and take the 60 s lease, exactly as `deliverDue` does.
        guard let id = delivery.id, try await DB.swap(tx, table: WebhookDeliveryRecord.schema, id: id, column: "attempts", expected: delivery.attempts,
                                                      newValue: delivery.attempts + 1,
                                                      extra: [("status", "sending"), ("next_attempt_at", now.addingTimeInterval(60))]) else { return .done }
        return .afterCommit { db, ctx in
            guard let claimed = try await WebhookDeliveryRecord.find(id, on: db), claimed.status == "sending" else { return nil }
            try await WebhookService(db: db, ctx: ctx).attempt(claimed, now: ctx.now)
            guard let after = try await WebhookDeliveryRecord.find(id, on: db), after.status == "pending" else { return nil }
            return after.nextAttemptAt
        }
    }

    // MARK: Wallet

    static let walletPush = QueueMessageType(name: "wallet.push", version: 1, queue: .walletPush, timeToLive: 86_400, requiresTenant: false) { envelope, tx, ctx in
        guard let row = try await WalletPushOutboxRecord.find(envelope.ref, on: tx), row.status == "queued" else { return .done }
        if row.nextAttemptAt > ctx.now { return .retry(at: row.nextAttemptAt) }
        guard let id = row.id, try await DB.swap(tx, table: WalletPushOutboxRecord.schema, id: id, column: "status", expected: "queued", newValue: "sending") else { return .done }
        return .afterCommit { db, ctx in
            guard let claimed = try await WalletPushOutboxRecord.find(id, on: db), claimed.status == "sending" else { return nil }
            try await WalletService(db: db, ctx: ctx).pushClaimed(claimed, now: ctx.now)
            guard let after = try await WalletPushOutboxRecord.find(id, on: db), after.status == "queued" else { return nil }
            return after.nextAttemptAt
        }
    }

    // MARK: Operator notices

    static let operatorNotice = QueueMessageType(name: "operator_notice.deliver", version: 1, queue: .operatorNotices, timeToLive: 3 * 86_400, requiresTenant: false) { envelope, tx, ctx in
        guard let notice = try await OperatorNoticeRecord.find(envelope.ref, on: tx), notice.status != "done" else { return .done }
        // Another runner holds the batch: it finishes it; try again after its lease.
        guard let token = try await OperatorNotices(db: tx, ctx: ctx).claim(notice) else { return .retry(at: ctx.now.addingTimeInterval(OperatorNotices.claimLease)) }
        let id = envelope.ref
        return .afterCommit { db, ctx in
            let notices = OperatorNotices(db: db, ctx: ctx)
            guard let claimed = try await OperatorNoticeRecord.find(id, on: db), claimed.status != "done" else {
                try await notices.release(id, token: token)
                return nil
            }
            do { _ = try await notices.deliver(claimed) } catch {
                try? await notices.release(id, token: token)
                throw error
            }
            // One batch per message: the next batch is the next message.
            return try await OperatorNoticeRecord.find(id, on: db)?.status == "done" ? nil : ctx.now
        }
    }

    // MARK: Account exports

    static let consumerExport = QueueMessageType(name: "consumer_export.process", version: 1, queue: .consumerExport, timeToLive: 3 * 86_400, requiresTenant: false) { envelope, tx, ctx in
        guard let record = try await ConsumerExportRecord.find(envelope.ref, on: tx), record.status == "queued", let id = record.id,
              try await DB.swap(tx, table: ConsumerExportRecord.schema, id: id, column: "status", expected: "queued", newValue: "building") else { return .done }
        return .afterCommit { db, ctx in
            guard let claimed = try await ConsumerExportRecord.find(id, on: db), claimed.status == "building" else { return nil }
            let ready = await ConsumerExports(db: db, ctx: ctx).buildClaimed(claimed)
            return ready ? nil : ctx.now.addingTimeInterval(60)
        }
    }

    // MARK: Scheduled expiries

    /// Expires one interaction at its `expires_at` (entirely inside the message transaction: the status change, the outcome and the webhook rows
    /// commit with the marker).
    static let interactionExpire = QueueMessageType(name: "interaction.expire", version: 1, queue: .expiry, timeToLive: 14 * 86_400, requiresTenant: true) { envelope, tx, ctx in
        guard let record = try await InteractionRecord.find(envelope.ref, on: tx) else { return .done }
        guard record.businessId == envelope.tenant else { return .deadLetter(reason: "tenant_mismatch") }
        guard record.statusValue == .pending else { return .done }
        if record.expiresAt > ctx.now { return .retry(at: record.expiresAt) }
        _ = try await InteractionService(db: tx, ctx: ctx).expireIfNeeded(record)
        return .done
    }

    /// Approval-request expiries (Approve v2). The request service's own CAS sweep does the work; the type exists so request creation can schedule a
    /// message at `expires_at`.
    static let approveExpire = QueueMessageType(name: "approve.expire", version: 1, queue: .expiry, timeToLive: 14 * 86_400, requiresTenant: false) { _, _, _ in
        .afterCommit { db, ctx in
            if ctx.config.approve.enabled { _ = try await ApproveRequestService(db: db, ctx: ctx).expireDue() }
            return nil
        }
    }

    /// Recovery holds and device replacements that fall due (`IdentityMaintenance`, CAS-safe).
    static let identityMaintenance = QueueMessageType(name: "identity.hold_due", version: 1, queue: .expiry, timeToLive: 14 * 86_400, requiresTenant: false) { _, _, _ in
        .afterCommit { db, ctx in
            try await IdentityMaintenance(db: db, ctx: ctx).run()
            return nil
        }
    }
}
