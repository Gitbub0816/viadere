import Fluent
import Foundation
import ViadereCore

/// Outbound SMS queue: ordered per phone, retried with backoff, never sent to opted-out numbers.
struct OutboundSMS {
    let db: any Database
    let ctx: ServerContext

    static let maxAttempts = 5
    static let backoff: [TimeInterval] = [15, 60, 300, 1800]

    @discardableResult
    func enqueue(to phone: PhoneNumber, body: String, sensitive: Bool = false, allowWhenOptedOut: Bool = false,
                 messageId: UUID? = nil) async throws -> SMSOutboundRecord {
        let now = ctx.now
        let row = SMSOutboundRecord()
        row.id = UUID()
        row.seq = Int(ctx.sequence.next(now: now))
        row.phoneHash = ctx.hasher.phoneHash(phone)
        row.phoneCiphertext = try ctx.cipher.seal(phone.e164, context: "sms_outbound.phone")
        row.bodyCiphertext = try ctx.cipher.seal(body, context: "sms_outbound.body")
        row.sensitive = sensitive
        row.allowWhenOptedOut = allowWhenOptedOut
        row.status = "queued"
        row.attempts = 0
        row.nextAttemptAt = now
        row.messageId = messageId
        row.createdAt = now
        try await row.create(on: db)
        return row
    }

    /// Sends every due message, per phone strictly in `seq` order. Returns the number of messages sent.
    @discardableResult
    func sendDue(limit: Int = 100) async throws -> Int {
        let now = ctx.now
        let due = try await SMSOutboundRecord.query(on: db).filter(\.$status == "queued").filter(\.$nextAttemptAt <= now)
            .sort(\.$seq, .ascending).limit(limit).all()
        var sent = 0
        var blockedPhones = Set<String>()
        for row in due {
            guard let id = row.id, !blockedPhones.contains(row.phoneHash) else { continue }
            // Ordering: never overtake an earlier message that is still waiting (e.g. retrying) for the same number.
            let earlier = try await SMSOutboundRecord.query(on: db).filter(\.$phoneHash == row.phoneHash).filter(\.$seq < row.seq)
                .group(.or) { $0.filter(\.$status == "queued"); $0.filter(\.$status == "sending") }.count()
            if earlier > 0 { blockedPhones.insert(row.phoneHash); continue }
            guard try await DB.swap(db, table: SMSOutboundRecord.schema, id: id, column: "status", expected: "queued", newValue: "sending")
            else { continue }
            row.status = "sending"
            if try await dispatch(row, now: now) { sent += 1 } else { blockedPhones.insert(row.phoneHash) }
        }
        return sent
    }

    /// Returns true if the message left the queue successfully.
    private func dispatch(_ row: SMSOutboundRecord, now: Date) async throws -> Bool {
        // Carrier compliance: after STOP only engine replies to that STOP/HELP exchange may be sent.
        if !row.allowWhenOptedOut, let context = try await SMSContextRecord.query(on: db).filter(\.$phoneHash == row.phoneHash).first(),
           context.optedOut {
            try await finish(row, status: "cancelled", error: "opted_out", wipe: true)
            return true
        }
        let phone: PhoneNumber
        let body: String
        do {
            guard let parsed = PhoneNumber(try ctx.cipher.openString(row.phoneCiphertext, context: "sms_outbound.phone")) else {
                try await finish(row, status: "failed", error: "bad_phone", wipe: true)
                return true
            }
            phone = parsed
            body = try ctx.cipher.openString(row.bodyCiphertext, context: "sms_outbound.body")
        } catch {
            try await finish(row, status: "failed", error: "decrypt", wipe: true)
            return true
        }
        do {
            let result = try await ctx.sms.send(OutboundSMSRequest(to: phone, body: body, reference: row.id!.uuidString.lowercased()))
            row.providerMessageId = result.providerMessageId
            row.sentAt = now
            row.attempts += 1
            try await finish(row, status: "sent", error: nil, wipe: row.sensitive)
            if let messageId = row.messageId {
                try await ConversationMessageRecord.query(on: db).filter(\.$id == messageId).set(\.$deliveryStatus, to: DeliveryStatus.sent.rawValue).update()
            }
            return true
        } catch let error as SMSProviderError {
            row.attempts += 1
            switch error {
            case .permanent(let code, let optedOut):
                if optedOut { try await markOptedOut(row.phoneHash, now: now) }
                try await finish(row, status: "failed", error: code, wipe: true)
                _ = try await AuditService(db: db, ctx: ctx).record("gateway.sms_failed", outcome: .failure, actor: AuditActor(kind: .gateway),
                    subjectType: "sms_outbound", subjectId: row.id?.uuidString.lowercased(), metadata: ["reason": "permanent", "provider_error": code])
                if let messageId = row.messageId {
                    try await ConversationMessageRecord.query(on: db).filter(\.$id == messageId).set(\.$deliveryStatus, to: DeliveryStatus.failed.rawValue).update()
                }
                return true
            default:
                if row.attempts >= Self.maxAttempts {
                    try await finish(row, status: "failed", error: "max_attempts", wipe: true)
                    _ = try await AuditService(db: db, ctx: ctx).record("gateway.sms_failed", outcome: .failure, actor: AuditActor(kind: .gateway),
                        subjectType: "sms_outbound", subjectId: row.id?.uuidString.lowercased(), metadata: ["reason": "max_attempts"])
                    return true
                }
                row.status = "queued"
                row.nextAttemptAt = now.addingTimeInterval(Self.backoff[min(row.attempts - 1, Self.backoff.count - 1)])
                row.errorCode = "transient"
                try await row.update(on: db)
                return false
            }
        }
    }

    private func finish(_ row: SMSOutboundRecord, status: String, error: String?, wipe: Bool) async throws {
        row.status = status
        row.errorCode = error
        if wipe { row.bodyCiphertext = (try? ctx.cipher.seal("[removed]", context: "sms_outbound.body")) ?? "" }
        try await row.update(on: db)
    }

    private func markOptedOut(_ phoneHash: String, now: Date) async throws {
        try await SMSContextRecord.query(on: db).filter(\.$phoneHash == phoneHash).set(\.$optedOut, to: true).update()
        try await SMSConsentEventRecord(phoneHash: phoneHash, optedOut: true, keyword: "carrier", at: now).create(on: db)
    }

    /// Applies a provider delivery receipt.
    func applyDeliveryUpdate(_ update: SMSDeliveryUpdate) async throws {
        guard let row = try await SMSOutboundRecord.query(on: db).filter(\.$providerMessageId == update.providerMessageId).first() else { return }
        switch update.status {
        case .delivered:
            row.status = "delivered"
            if let messageId = row.messageId {
                try await ConversationMessageRecord.query(on: db).filter(\.$id == messageId)
                    .set(\.$deliveryStatus, to: DeliveryStatus.delivered.rawValue).set(\.$deliveredAt, to: ctx.now).update()
            }
        case .failed:
            row.status = "failed"
            row.errorCode = update.errorCode
            if let messageId = row.messageId {
                try await ConversationMessageRecord.query(on: db).filter(\.$id == messageId).set(\.$deliveryStatus, to: DeliveryStatus.failed.rawValue).update()
            }
        case .sent, .queued: return
        }
        try await row.update(on: db)
    }
}
