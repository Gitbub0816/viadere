import Fluent
import Foundation
import Vapor
import ViadereCore

// MARK: - Re-encrypting legacy ciphertexts

/// Rewrites every column-bound (`v1.`) ciphertext, and the plaintext webhook bodies written before bodies were encrypted, as
/// row-bound (`v2.`) values. Idempotent; safe to run while the server is running (each row is rewritten from its own value).
struct FieldReencryptor {
    let db: any Database
    let ctx: ServerContext

    struct Report: Equatable { var rewritten = 0; var failed = 0 }

    func run() async throws -> Report {
        var report = Report()
        func convert<M: Model>(_ type: M.Type, context: String, id: (M) -> UUID?, columns: [ReferenceWritableKeyPath<M, String>]) async throws {
            for row in try await M.query(on: db).all() {
                guard let rowId = id(row) else { continue }
                var changed = false
                for column in columns where FieldCipher.isLegacy(row[keyPath: column]) {
                    do {
                        row[keyPath: column] = try ctx.cipher.seal(try ctx.cipher.openLegacy(row[keyPath: column], context: context), context: context, rowId: rowId)
                        changed = true
                    } catch { report.failed += 1 }
                }
                if changed { try await row.update(on: db); report.rewritten += 1 }
            }
        }
        func convertOptional<M: Model>(_ type: M.Type, context: String, id: (M) -> UUID?, columns: [ReferenceWritableKeyPath<M, String?>]) async throws {
            for row in try await M.query(on: db).all() {
                guard let rowId = id(row) else { continue }
                var changed = false
                for column in columns {
                    guard let value = row[keyPath: column], FieldCipher.isLegacy(value) else { continue }
                    do {
                        row[keyPath: column] = try ctx.cipher.seal(try ctx.cipher.openLegacy(value, context: context), context: context, rowId: rowId)
                        changed = true
                    } catch { report.failed += 1 }
                }
                if changed { try await row.update(on: db); report.rewritten += 1 }
            }
        }
        try await convert(PhoneLinkRecord.self, context: "phone_links.phone", id: { $0.id }, columns: [\.phoneCiphertext])
        try await convert(SMSOutboundRecord.self, context: "sms_outbound.phone", id: { $0.id }, columns: [\.phoneCiphertext])
        try await convert(SMSOutboundRecord.self, context: "sms_outbound.body", id: { $0.id }, columns: [\.bodyCiphertext])
        try await convert(ChannelOutboundRecord.self, context: "channel_outbound.phone", id: { $0.id }, columns: [\.phoneCiphertext])
        try await convert(LinkTokenRecord.self, context: "link_tokens.phone", id: { $0.id }, columns: [\.phoneCiphertext])
        try await convert(SMSContextRecord.self, context: "sms_contexts.context", id: { $0.id }, columns: [\.contextCiphertext])
        try await convert(ConversationMessageRecord.self, context: "conversation_messages.body", id: { $0.id }, columns: [\.bodyCiphertext])
        try await convert(DelegationInvitationRecord.self, context: "delegation.label", id: { $0.id }, columns: [\.labelCiphertext])
        try await convertOptional(DelegationGrantRecord.self, context: "delegation.label", id: { $0.id }, columns: [\.labelCiphertext])
        try await convertOptional(LoyaltyAccountRecord.self, context: "loyalty_accounts.member_reference", id: { $0.id }, columns: [\.memberReferenceCiphertext])
        try await convert(WebhookSubscriptionRecord.self, context: "webhook_subscriptions.secret", id: { $0.id }, columns: [\.secretCiphertext])
        try await convertOptional(WebhookSubscriptionRecord.self, context: "webhook_subscriptions.secret", id: { $0.id }, columns: [\.previousSecretCiphertext])
        try await convert(DashboardUserRecord.self, context: "dashboard_users.email", id: { $0.id }, columns: [\.emailCiphertext])
        try await convert(OrgInviteRecord.self, context: "org_invites.email", id: { $0.id }, columns: [\.emailCiphertext])
        // Webhook delivery bodies were plaintext before they were encrypted.
        for delivery in try await WebhookDeliveryRecord.query(on: db).all() where !(delivery.body.hasPrefix("v1.") || delivery.body.hasPrefix("v2.")) {
            delivery.body = try ctx.cipher.seal(delivery.body, context: "webhook_deliveries.body", rowId: delivery.id!)
            try await delivery.update(on: db)
            report.rewritten += 1
        }
        // Queued `interaction.decided` bodies written before businesses stopped receiving the raw signed decision: strip it at rest
        // (and `WebhookService.deliveryBody` strips it again on read, so a delivery is never sent with one).
        for delivery in try await WebhookDeliveryRecord.query(on: db).filter(\.$eventType == WebhookEventType.interactionDecided.rawValue).all() {
            guard let stored = WebhookService(db: db, ctx: ctx).storedBody(delivery), let clean = WebhookService.strippingSignedDecision(stored) else { continue }
            delivery.body = try ctx.cipher.seal(clean, context: "webhook_deliveries.body", rowId: delivery.id!)
            try await delivery.update(on: db)
            report.rewritten += 1
        }
        return report
    }
}

public struct ReencryptFieldsCommand: AsyncCommand {
    public struct Signature: CommandSignature { public init() {} }
    public let signature = Signature()
    public let help = "Rewrites legacy column-bound ciphertexts as row-bound ones. Idempotent."
    public init() {}

    public func run(using context: CommandContext, signature: Signature) async throws {
        let app = context.application
        let report = try await FieldReencryptor(db: app.db, ctx: app.ctx).run()
        context.console.print("Re-encrypted \(report.rewritten) rows; \(report.failed) values could not be opened with the current key.")
        if report.failed > 0 { throw Abort(.internalServerError) }
    }
}

// MARK: - Audit chain

/// `ViadereServer audit-head` prints the authenticated head of the audit chain as JSON. Store it in write-once storage (object lock /
/// WORM bucket) on a schedule: it is the only defence against an attacker who holds both the database and `AUDIT_CHAIN_KEY`.
public struct AuditHeadCommand: AsyncCommand {
    public struct Signature: CommandSignature { public init() {} }
    public let signature = Signature()
    public let help = "Prints the signed head of the audit hash chain (JSON) for export to write-once storage."
    public init() {}

    public func run(using context: CommandContext, signature: Signature) async throws {
        let app = context.application
        guard let head = try await AuditService.signedHead(on: app.db, key: app.ctx.config.auditChainKey, now: app.ctx.now) else {
            context.console.print("{}")
            return
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        context.console.print(String(decoding: try encoder.encode(head), as: UTF8.self))
    }
}

/// `ViadereServer audit-verify [--head <file>]` recomputes the chain and, with `--head`, checks a previously exported head.
public struct AuditVerifyCommand: AsyncCommand {
    public struct Signature: CommandSignature {
        @Option(name: "head") var head: String?
        public init() {}
    }
    public let signature = Signature()
    public let help = "Verifies the audit hash chain, and optionally an exported head."
    public init() {}

    public func run(using context: CommandContext, signature: Signature) async throws {
        let app = context.application
        let key = app.ctx.config.auditChainKey
        let result = try await AuditService.verifyChain(on: app.db, key: key, legacyThroughSeq: app.ctx.config.auditLegacyThroughSeq)
        guard result.valid else {
            context.console.error("Audit chain BROKEN at seq \(result.firstBrokenSeq.map(String.init) ?? "?") after \(result.checked) valid events.")
            throw Abort(.internalServerError)
        }
        if let path = signature.head {
            let data = try Data(contentsOf: URL(fileURLWithPath: path))
            guard let head = try? JSONDecoder().decode(AuditService.SignedHead.self, from: data),
                  try await AuditService.verify(head: head, on: app.db, key: key) else {
                context.console.error("The exported head does not match the chain (or its MAC is invalid).")
                throw Abort(.internalServerError)
            }
        }
        context.console.print("Audit chain valid: \(result.checked) events.")
    }
}

// MARK: - Dispute export

/// Everything needed to settle a dispute about one decision, including the raw device id and the signed decision that businesses
/// never receive (they get a per-business pseudonym and an attestation instead).
struct DisputeExport: Codable {
    var interactionId: String
    var businessId: String
    var consumerId: String
    var deviceId: String
    var decision: String
    var assurance: String
    var channel: String
    var decidedAt: String
    var signedPayload: String
    var signature: String
    var devicePublicKeys: [String: String]
    var evidenceRef: String
}

public struct ExportDisputeCommand: AsyncCommand {
    public struct Signature: CommandSignature {
        @Option(name: "interaction") var interaction: String?
        public init() {}
    }
    public let signature = Signature()
    public let help = "Prints the signed decision, device id and device public keys for one interaction (dispute handling; audited)."
    public init() {}

    public func run(using context: CommandContext, signature: Signature) async throws {
        guard let text = signature.interaction, let id = UUID(uuidString: text) else {
            context.console.error("Usage: export-dispute --interaction <interaction id>")
            throw Abort(.badRequest)
        }
        let app = context.application
        guard let export = try await Self.export(interactionId: id, db: app.db, ctx: app.ctx) else {
            context.console.error("No device-signed decision recorded for that interaction.")
            throw Abort(.notFound)
        }
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        context.console.print(String(decoding: try encoder.encode(export), as: UTF8.self))
    }

    static func export(interactionId: UUID, db: any Database, ctx: ServerContext) async throws -> DisputeExport? {
        guard let decision = try await DecisionRecord.query(on: db).filter(\.$interactionId == interactionId).first() else { return nil }
        let keys = try await DeviceKeyRecord.query(on: db).filter(\.$deviceId == decision.deviceId).all()
        _ = try await AuditService(db: db, ctx: ctx).record("dispute.exported", actor: AuditActor(kind: .system),
            consumerId: ConsumerID(decision.consumerId), businessId: BusinessID(decision.businessId), subjectType: "interaction",
            subjectId: interactionId.uuidString.lowercased())
        return DisputeExport(
            interactionId: interactionId.uuidString.lowercased(), businessId: decision.businessId.uuidString.lowercased(),
            consumerId: decision.consumerId.uuidString.lowercased(), deviceId: decision.deviceId.uuidString.lowercased(),
            decision: decision.decision, assurance: decision.assurance, channel: decision.channel,
            decidedAt: ViadereDate.format(decision.decidedAt), signedPayload: decision.signedPayload, signature: decision.signature,
            devicePublicKeys: Dictionary(keys.map { ($0.purpose, $0.publicKey) }, uniquingKeysWith: { first, _ in first }),
            evidenceRef: ctx.hasher.evidenceReference(decisionId: decision.id!))
    }
}

// MARK: - Retention

/// Deletes operational records that hold personal data or message text once they are no longer needed.
struct RetentionService {
    let db: any Database
    let ctx: ServerContext

    @discardableResult
    func purge() async throws -> Int {
        let now = ctx.now
        let r = ctx.config.retention
        var removed = 0
        let outboundCutoff = now.addingTimeInterval(-Double(r.outboundDays) * 86_400)
        let finished = ["sent", "delivered", "failed", "cancelled"]
        let sms = SMSOutboundRecord.query(on: db).filter(\.$status ~~ finished).filter(\.$createdAt < outboundCutoff)
        removed += try await sms.count()
        try await SMSOutboundRecord.query(on: db).filter(\.$status ~~ finished).filter(\.$createdAt < outboundCutoff).delete()
        let channel = ChannelOutboundRecord.query(on: db).filter(\.$status ~~ finished).filter(\.$createdAt < outboundCutoff)
        removed += try await channel.count()
        try await ChannelOutboundRecord.query(on: db).filter(\.$status ~~ finished).filter(\.$createdAt < outboundCutoff).delete()
        let tokenCutoff = now.addingTimeInterval(-Double(r.linkTokenDays) * 86_400)
        let tokens = LinkTokenRecord.query(on: db).filter(\.$expiresAt < tokenCutoff)
        removed += try await tokens.count()
        try await LinkTokenRecord.query(on: db).filter(\.$expiresAt < tokenCutoff).delete()
        let webhookCutoff = now.addingTimeInterval(-Double(r.webhookDeliveryDays) * 86_400)
        let old = try await WebhookDeliveryRecord.query(on: db).filter(\.$status ~~ ["succeeded", "dead"]).filter(\.$createdAt < webhookCutoff)
            .limit(500).all().compactMap(\.id)
        if !old.isEmpty {
            try await WebhookAttemptRecord.query(on: db).filter(\.$deliveryId ~~ old).delete()
            try await WebhookDeliveryRecord.query(on: db).filter(\.$id ~~ old).delete()
            removed += old.count
        }
        removed += try await DeviceLifecycle(db: db, ctx: ctx).revokeExpired()
        // Sealed refresh-token successors are only needed for the grace window after a rotation.
        try await RefreshTokenRecord.query(on: db).filter(\.$successorSealed != nil)
            .filter(\.$usedAt < now.addingTimeInterval(-ConsumerTokenService.graceWindow)).set(\.$successorSealed, to: nil).update()
        return removed
    }
}
