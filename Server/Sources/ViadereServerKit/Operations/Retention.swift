import Fluent
import Foundation
import ViadereCore

/// Retention by data class (LEG-PR-004/006, spec §13). Every class has a documented default and hard bounds; an operator may move the platform
/// value inside the bounds, and a business may **shorten** (never lengthen) the classes marked tenant-adjustable for its own data. A legal hold
/// stops the purge of a business's, a consumer's or everyone's records until it is released. The table-by-table list is docs/ops/DATA-INVENTORY.md.
enum RetentionClass: String, CaseIterable, Sendable {
    case interactionContent = "interaction_content"
    case conversationContent = "conversation_content"
    case signedDecisions = "signed_decisions"
    case consentHistory = "consent_history"
    case auditEvents = "audit_events"
    case applications = "business_applications"
    case usageRecords = "usage_records"
    case webhookDeliveries = "webhook_deliveries"
    case outbound = "outbound_messages"
    case linkTokens = "link_tokens"
    case securityTokens = "security_tokens"
    case channelCapability = "channel_capability"
    case securityNotices = "security_notices"
    case supportRecords = "support_records"

    struct Definition: Sendable {
        var defaultDays: Int
        var minDays: Int
        var maxDays: Int
        /// A business may shorten this for its own data (never beyond the platform value).
        var tenantAdjustable: Bool
        /// Whether a legal hold suspends the purge.
        var holdable: Bool
        var summary: String
        var tables: String
    }

    var definition: Definition {
        switch self {
        case .interactionContent:
            Definition(defaultDays: 400, minDays: 30, maxDays: 1095, tenantAdjustable: true, holdable: true,
                       summary: "Payload text and replies of finished interactions are erased; the row, ids and status stay for reporting.", tables: "interactions")
        case .conversationContent:
            Definition(defaultDays: 730, minDays: 30, maxDays: 3650, tenantAdjustable: true, holdable: true,
                       summary: "Message bodies in conversations are replaced by a placeholder.", tables: "conversation_messages")
        case .signedDecisions:
            Definition(defaultDays: 730, minDays: 365, maxDays: 2555, tenantAdjustable: false, holdable: true,
                       summary: "Device-signed decisions kept as dispute evidence, then deleted.", tables: "decisions")
        case .consentHistory:
            Definition(defaultDays: 1095, minDays: 365, maxDays: 3650, tenantAdjustable: false, holdable: true,
                       summary: "Superseded consent versions. The current consent of every relationship is never purged.", tables: "consent_grants")
        case .auditEvents:
            Definition(defaultDays: 2555, minDays: 730, maxDays: 3650, tenantAdjustable: false, holdable: true,
                       summary: "Audit events older than this are removed, but only after their chain head was exported to write-once storage; a checkpoint keeps the chain verifiable.", tables: "audit_events, audit_checkpoints")
        case .applications:
            Definition(defaultDays: 730, minDays: 90, maxDays: 3650, tenantAdjustable: false, holdable: true,
                       summary: "Free-text description and reviewer note of decided applications are erased.", tables: "business_applications")
        case .usageRecords:
            Definition(defaultDays: 2555, minDays: 365, maxDays: 3650, tenantAdjustable: false, holdable: true,
                       summary: "Metering records (billing basis).", tables: "usage_events")
        case .webhookDeliveries:
            Definition(defaultDays: 30, minDays: 1, maxDays: 365, tenantAdjustable: true, holdable: true,
                       summary: "Webhook deliveries (their bodies can hold message text); undelivered ones expire with them.", tables: "webhook_deliveries, webhook_delivery_attempts")
        case .outbound:
            Definition(defaultDays: 30, minDays: 1, maxDays: 365, tenantAdjustable: false, holdable: true,
                       summary: "Finished SMS and channel sends (encrypted phone numbers).", tables: "sms_outbound, channel_outbound")
        case .linkTokens:
            Definition(defaultDays: 7, minDays: 1, maxDays: 90, tenantAdjustable: false, holdable: false,
                       summary: "Used or expired link tokens.", tables: "link_tokens")
        case .securityTokens:
            Definition(defaultDays: 30, minDays: 7, maxDays: 180, tenantAdjustable: false, holdable: false,
                       summary: "Expired or revoked session tokens, enrollment and interaction challenges.", tables: "access_tokens, refresh_tokens, device_enroll_challenges, interaction_challenges")
        case .channelCapability:
            Definition(defaultDays: 180, minDays: 14, maxDays: 730, tenantAdjustable: false, holdable: false,
                       summary: "RCS capability cache, consumed postbacks and provider message de-duplication markers.", tables: "channel_endpoints, rcs_postbacks, processed_provider_messages")
        case .securityNotices:
            Definition(defaultDays: 365, minDays: 30, maxDays: 1095, tenantAdjustable: false, holdable: false,
                       summary: "In-app security notices of consumers.", tables: "security_notices")
        case .supportRecords:
            Definition(defaultDays: 730, minDays: 90, maxDays: 3650, tenantAdjustable: false, holdable: true,
                       summary: "Closed tickets and appeals, operator notices, decided approvals and data requests, released freezes.",
                       tables: "support_tickets, operator_notices, pending_changes, data_requests, account_freezes, consumer_exports")
        }
    }
}

struct RetentionPolicy {
    let db: any Database
    let ctx: ServerContext

    static let globalScope = "global"

    /// The platform value: an operator setting within the bounds, else the deployment's configured value, else the documented default.
    func platformDays(_ cls: RetentionClass) async throws -> Int {
        let def = cls.definition
        if let row = try await RetentionSettingRecord.query(on: db).filter(\.$scope == Self.globalScope).filter(\.$dataClass == cls.rawValue).first() {
            return min(max(row.days, def.minDays), def.maxDays)
        }
        let configured: Int?
        switch cls {
        case .webhookDeliveries: configured = ctx.config.retention.webhookDeliveryDays
        case .outbound: configured = ctx.config.retention.outboundDays
        case .linkTokens: configured = ctx.config.retention.linkTokenDays
        default: configured = nil
        }
        return min(max(configured ?? def.defaultDays, def.minDays), def.maxDays)
    }

    /// What applies to one business's own data: its shortened value if it set one (never above the platform value).
    func effectiveDays(_ cls: RetentionClass, businessId: UUID?) async throws -> Int {
        let platform = try await platformDays(cls)
        guard cls.definition.tenantAdjustable, let businessId,
              let row = try await RetentionSettingRecord.query(on: db).filter(\.$scope == businessId.uuidString.lowercased())
                  .filter(\.$dataClass == cls.rawValue).first() else { return platform }
        return min(platform, max(row.days, cls.definition.minDays))
    }

    func setPlatform(_ cls: RetentionClass, days: Int, operatorId: UUID, reason rawReason: String) async throws {
        let def = cls.definition
        let reason = rawReason.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (def.minDays...def.maxDays).contains(days) else {
            throw APIError.validation("\(cls.rawValue) must be between \(def.minDays) and \(def.maxDays) days.", details: ["days": "out_of_bounds"])
        }
        guard (8...300).contains(reason.count) else { throw APIError.validation("Record the reason (8 to 300 characters).", details: ["reason": "required"]) }
        try await upsert(scope: Self.globalScope, cls: cls, days: days, by: "operator:" + operatorId.uuidString.lowercased())
        _ = try await AuditService(db: db, ctx: ctx).record("retention.platform_set", actor: AuditActor(kind: .operator_, id: operatorId.uuidString.lowercased()),
            subjectType: "retention", subjectId: cls.rawValue, metadata: ["days": String(days), "reason": reason])
    }

    /// A business shortens its own retention. Lengthening, or a class it may not adjust, is refused.
    func setTenant(_ cls: RetentionClass, businessId: UUID, days: Int, by userId: UUID) async throws {
        let def = cls.definition
        guard def.tenantAdjustable else {
            throw APIError(.forbidden, .forbidden, "This retention period is set by Viadere and cannot be changed for one organization.")
        }
        let platform = try await platformDays(cls)
        guard (def.minDays...platform).contains(days) else {
            throw APIError.validation("Choose between \(def.minDays) and \(platform) days. Retention can be shortened but not extended.", details: ["days": "out_of_bounds"])
        }
        try await upsert(scope: businessId.uuidString.lowercased(), cls: cls, days: days, by: "user:" + userId.uuidString.lowercased())
        _ = try await AuditService(db: db, ctx: ctx).record("retention.tenant_set", actor: AuditActor(kind: .business, id: userId.uuidString.lowercased()),
            businessId: BusinessID(businessId), subjectType: "retention", subjectId: cls.rawValue, metadata: ["days": String(days)])
    }

    func clearTenant(_ cls: RetentionClass, businessId: UUID, by userId: UUID) async throws {
        try await RetentionSettingRecord.query(on: db).filter(\.$scope == businessId.uuidString.lowercased()).filter(\.$dataClass == cls.rawValue).delete()
        _ = try await AuditService(db: db, ctx: ctx).record("retention.tenant_cleared", actor: AuditActor(kind: .business, id: userId.uuidString.lowercased()),
            businessId: BusinessID(businessId), subjectType: "retention", subjectId: cls.rawValue)
    }

    private func upsert(scope: String, cls: RetentionClass, days: Int, by: String) async throws {
        if let row = try await RetentionSettingRecord.query(on: db).filter(\.$scope == scope).filter(\.$dataClass == cls.rawValue).first() {
            row.days = days
            row.updatedBy = by
            row.updatedAt = ctx.now
            try await row.update(on: db)
        } else {
            let row = RetentionSettingRecord()
            row.id = UUID()
            row.scope = scope
            row.dataClass = cls.rawValue
            row.days = days
            row.updatedBy = by
            row.updatedAt = ctx.now
            try await row.create(on: db)
        }
    }

    // MARK: Legal holds

    func placeHold(scopeKind: String, scopeId: String?, reason rawReason: String, operatorId: UUID) async throws -> LegalHoldRecord {
        let reason = rawReason.trimmingCharacters(in: .whitespacesAndNewlines)
        guard ["global", "business", "consumer"].contains(scopeKind), (8...300).contains(reason.count),
              scopeKind == "global" ? scopeId == nil : (scopeId.flatMap(UUID.init(uuidString:)) != nil) else {
            throw APIError.validation("Choose a scope and record the reason (8 to 300 characters).", details: ["hold": "invalid"])
        }
        let hold = LegalHoldRecord()
        hold.id = UUID()
        hold.scopeKind = scopeKind
        hold.scopeId = scopeId?.lowercased()
        hold.reason = reason
        hold.createdBy = operatorId.uuidString.lowercased()
        hold.createdAt = ctx.now
        try await hold.create(on: db)
        _ = try await AuditService(db: db, ctx: ctx).record("retention.hold_placed", actor: AuditActor(kind: .operator_, id: operatorId.uuidString.lowercased()),
            subjectType: "legal_hold", subjectId: hold.id?.uuidString.lowercased(), metadata: ["scope": scopeKind, "reason": reason])
        return hold
    }

    func releaseHold(id: UUID, operatorId: UUID) async throws {
        guard let hold = try await LegalHoldRecord.find(id, on: db), hold.releasedAt == nil else { throw APIError.notFound }
        hold.releasedAt = ctx.now
        hold.releasedBy = operatorId.uuidString.lowercased()
        try await hold.update(on: db)
        _ = try await AuditService(db: db, ctx: ctx).record("retention.hold_released", actor: AuditActor(kind: .operator_, id: operatorId.uuidString.lowercased()),
            subjectType: "legal_hold", subjectId: id.uuidString.lowercased())
    }

    struct Holds {
        var global: Bool
        var businesses: Set<UUID>
        var consumers: Set<UUID>
    }

    func activeHolds() async throws -> Holds {
        let rows = try await LegalHoldRecord.query(on: db).filter(\.$releasedAt == nil).all()
        return Holds(global: rows.contains { $0.scopeKind == "global" },
                     businesses: Set(rows.filter { $0.scopeKind == "business" }.compactMap { $0.scopeId.flatMap(UUID.init(uuidString:)) }),
                     consumers: Set(rows.filter { $0.scopeKind == "consumer" }.compactMap { $0.scopeId.flatMap(UUID.init(uuidString:)) }))
    }
}

/// The age-based purges (everything in docs/ops/DATA-INVENTORY.md §5). Idempotent and batched; each purge is independent, so one failing class
/// does not stop the others. Run by the background job at most once a minute per instance (`RetentionService.purge`).
struct RetentionPurger {
    let db: any Database
    let ctx: ServerContext
    static let batch = 200

    struct Report: Equatable {
        var counts: [String: Int] = [:]
        var skipped: [String: String] = [:]
        var total: Int { counts.values.reduce(0, +) }
    }

    func run() async -> Report {
        var report = Report()
        let policy = RetentionPolicy(db: db, ctx: ctx)
        guard let holds = try? await policy.activeHolds() else { return report }
        for cls in RetentionClass.allCases {
            if holds.global && cls.definition.holdable { report.skipped[cls.rawValue] = "legal_hold"; continue }
            do {
                let removed = try await purge(cls, policy: policy, holds: holds, report: &report)
                if removed > 0 { report.counts[cls.rawValue] = removed }
            } catch {
                ctx.logger.warning("retention purge failed", metadata: ["class": "\(cls.rawValue)", "type": "\(type(of: error))"])
                report.skipped[cls.rawValue] = "error"
            }
        }
        return report
    }

    private func cutoff(_ cls: RetentionClass, businessId: UUID? = nil, policy: RetentionPolicy) async throws -> Date {
        ctx.now.addingTimeInterval(-Double(try await policy.effectiveDays(cls, businessId: businessId)) * 86_400)
    }

    /// Businesses that shortened `cls` below the platform value, with their cutoffs.
    private func tenantCutoffs(_ cls: RetentionClass, policy: RetentionPolicy) async throws -> [(UUID, Date)] {
        guard cls.definition.tenantAdjustable else { return [] }
        let platform = try await policy.platformDays(cls)
        let rows = try await RetentionSettingRecord.query(on: db).filter(\.$dataClass == cls.rawValue).filter(\.$scope != RetentionPolicy.globalScope).all()
        return rows.compactMap { row in
            guard let id = UUID(uuidString: row.scope), row.days < platform else { return nil }
            return (id, ctx.now.addingTimeInterval(-Double(max(row.days, cls.definition.minDays)) * 86_400))
        }
    }

    private func purge(_ cls: RetentionClass, policy: RetentionPolicy, holds: RetentionPolicy.Holds, report: inout Report) async throws -> Int {
        let now = ctx.now
        let day: TimeInterval = 86_400
        let platformCutoff = try await cutoff(cls, policy: policy)
        let heldBusinesses = cls.definition.holdable ? Array(holds.businesses) : []
        let heldConsumers = cls.definition.holdable ? Array(holds.consumers) : []
        var removed = 0
        switch cls {
        case .interactionContent:
            let placeholder = String(decoding: try ViadereJSON.encode(JSONValue.object([:])), as: UTF8.self)
            func scrub(_ query: QueryBuilder<InteractionRecord>) async throws -> Int {
                var q = query.filter(\.$contentErased == false).filter(\.$status != InteractionStatus.pending.rawValue)
                if !heldBusinesses.isEmpty { q = q.filter(\.$businessId !~ heldBusinesses) }
                if !heldConsumers.isEmpty { q = q.filter(\.$consumerId !~ heldConsumers) }
                let rows = try await q.limit(Self.batch).all()
                for row in rows {
                    row.interactionJSON = placeholder
                    if var outcome = row.outcomeJSON.flatMap({ try? ViadereJSON.decode(InteractionOutcome.self, from: Data($0.utf8)) }) {
                        outcome.reply = nil
                        outcome.selectedOptionIds = nil
                        outcome.signedDecision = nil
                        row.outcomeJSON = String(decoding: try ViadereJSON.encode(outcome), as: UTF8.self)
                    }
                    row.contentErased = true
                    try await row.update(on: db)
                }
                return rows.count
            }
            removed += try await scrub(InteractionRecord.query(on: db).filter(\.$createdAt < platformCutoff))
            for (businessId, date) in try await tenantCutoffs(cls, policy: policy) where !heldBusinesses.contains(businessId) {
                removed += try await scrub(InteractionRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$createdAt < date))
            }
        case .conversationContent:
            func scrub(_ query: QueryBuilder<ConversationMessageRecord>) async throws -> Int {
                var q = query.filter(\.$contentErased == false)
                if !heldBusinesses.isEmpty { q = q.filter(\.$businessId !~ heldBusinesses) }
                if !heldConsumers.isEmpty { q = q.filter(\.$consumerId !~ heldConsumers) }
                let rows = try await q.limit(Self.batch).all()
                for row in rows {
                    row.bodyCiphertext = try ctx.cipher.seal("[expired]", context: "conversation_messages.body", rowId: row.id!)
                    row.contentErased = true
                    try await row.update(on: db)
                }
                return rows.count
            }
            removed += try await scrub(ConversationMessageRecord.query(on: db).filter(\.$createdAt < platformCutoff))
            for (businessId, date) in try await tenantCutoffs(cls, policy: policy) where !heldBusinesses.contains(businessId) {
                removed += try await scrub(ConversationMessageRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$createdAt < date))
            }
        case .signedDecisions:
            var q = DecisionRecord.query(on: db).filter(\.$decidedAt < platformCutoff)
            if !heldBusinesses.isEmpty { q = q.filter(\.$businessId !~ heldBusinesses) }
            if !heldConsumers.isEmpty { q = q.filter(\.$consumerId !~ heldConsumers) }
            let ids = try await q.limit(Self.batch).all().compactMap(\.id)
            if !ids.isEmpty { try await DecisionRecord.query(on: db).filter(\.$id ~~ ids).delete() }
            removed += ids.count
        case .consentHistory:
            var q = ConsentGrantRecord.query(on: db).filter(\.$createdAt < platformCutoff)
            if !heldBusinesses.isEmpty { q = q.filter(\.$businessId !~ heldBusinesses) }
            if !heldConsumers.isEmpty { q = q.filter(\.$consumerId !~ heldConsumers) }
            for row in try await q.limit(Self.batch * 2).all() {
                // Only a version that a newer one superseded: the current consent of a relationship is the evidence that matters.
                let newer = try await ConsentGrantRecord.query(on: db).filter(\.$relationshipId == row.relationshipId).filter(\.$purpose == row.purpose)
                    .filter(\.$version > row.version).count()
                if newer > 0, let id = row.id { try await ConsentGrantRecord.query(on: db).filter(\.$id == id).delete(); removed += 1 }
            }
        case .auditEvents:
            removed += try await AuditRetention(db: db, ctx: ctx).purge(before: platformCutoff, report: &report)
        case .applications:
            var applications = BusinessApplicationRecord.query(on: db).filter(\.$state != "pending").filter(\.$reviewedAt < platformCutoff)
                .group(.or) { $0.filter(\.$detail != nil); $0.filter(\.$decisionNote != nil) }
            if !heldBusinesses.isEmpty { applications = applications.filter(\.$businessId !~ heldBusinesses) }
            let rows = try await applications.limit(Self.batch).all()
            for row in rows {
                row.detail = nil
                row.decisionNote = nil
                try await row.update(on: db)
            }
            removed += rows.count
        case .usageRecords:
            var q = UsageEventRecord.query(on: db).filter(\.$occurredAt < platformCutoff)
            if !heldBusinesses.isEmpty { q = q.filter(\.$businessId !~ heldBusinesses) }
            let ids = try await q.limit(Self.batch * 5).all().compactMap(\.id)
            if !ids.isEmpty { try await UsageEventRecord.query(on: db).filter(\.$id ~~ ids).delete() }
            removed += ids.count
        case .webhookDeliveries:
            // Succeeded, dead and never-sent (paused or abandoned) deliveries alike: a pause cannot keep message text forever.
            func purgeOld(_ query: QueryBuilder<WebhookDeliveryRecord>) async throws -> Int {
                var q = query
                if !heldBusinesses.isEmpty { q = q.filter(\.$businessId !~ heldBusinesses) }
                let ids = try await q.limit(500).all().compactMap(\.id)
                guard !ids.isEmpty else { return 0 }
                try await WebhookAttemptRecord.query(on: db).filter(\.$deliveryId ~~ ids).delete()
                try await WebhookDeliveryRecord.query(on: db).filter(\.$id ~~ ids).delete()
                return ids.count
            }
            removed += try await purgeOld(WebhookDeliveryRecord.query(on: db).filter(\.$createdAt < platformCutoff))
            for (businessId, date) in try await tenantCutoffs(cls, policy: policy) where !heldBusinesses.contains(businessId) {
                removed += try await purgeOld(WebhookDeliveryRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$createdAt < date))
            }
        case .outbound:
            let finished = ["sent", "delivered", "failed", "cancelled"]
            removed += try await SMSOutboundRecord.query(on: db).filter(\.$status ~~ finished).filter(\.$createdAt < platformCutoff).count()
            try await SMSOutboundRecord.query(on: db).filter(\.$status ~~ finished).filter(\.$createdAt < platformCutoff).delete()
            var channel = ChannelOutboundRecord.query(on: db).filter(\.$status ~~ finished).filter(\.$createdAt < platformCutoff)
            if !heldBusinesses.isEmpty { channel = channel.filter(\.$businessId !~ heldBusinesses) }
            let ids = try await channel.limit(500).all().compactMap(\.id)
            if !ids.isEmpty { try await ChannelOutboundRecord.query(on: db).filter(\.$id ~~ ids).delete() }
            removed += ids.count
        case .linkTokens:
            removed += try await LinkTokenRecord.query(on: db).filter(\.$expiresAt < platformCutoff).count()
            try await LinkTokenRecord.query(on: db).filter(\.$expiresAt < platformCutoff).delete()
        case .securityTokens:
            removed += try await AccessTokenRecord.query(on: db).filter(\.$expiresAt < platformCutoff).count()
            try await AccessTokenRecord.query(on: db).filter(\.$expiresAt < platformCutoff).delete()
            removed += try await RefreshTokenRecord.query(on: db).filter(\.$expiresAt < platformCutoff).count()
            try await RefreshTokenRecord.query(on: db).filter(\.$expiresAt < platformCutoff).delete()
            let oneDayAgo = now.addingTimeInterval(-day)
            removed += try await DeviceEnrollChallengeRecord.query(on: db).filter(\.$expiresAt < oneDayAgo).count()
            try await DeviceEnrollChallengeRecord.query(on: db).filter(\.$expiresAt < oneDayAgo).delete()
            removed += try await InteractionChallengeRecord.query(on: db).filter(\.$expiresAt < oneDayAgo).count()
            try await InteractionChallengeRecord.query(on: db).filter(\.$expiresAt < oneDayAgo).delete()
        case .channelCapability:
            removed += try await ChannelEndpointRecord.query(on: db).filter(\.$updatedAt < platformCutoff).count()
            try await ChannelEndpointRecord.query(on: db).filter(\.$updatedAt < platformCutoff).delete()
            let weekAgo = now.addingTimeInterval(-7 * day)
            removed += try await RCSPostbackRecord.query(on: db).filter(\.$expiresAt < weekAgo).count()
            try await RCSPostbackRecord.query(on: db).filter(\.$expiresAt < weekAgo).delete()
            let twoWeeksAgo = now.addingTimeInterval(-14 * day)
            removed += try await ProcessedProviderMessageRecord.query(on: db).filter(\.$receivedAt < twoWeeksAgo).count()
            try await ProcessedProviderMessageRecord.query(on: db).filter(\.$receivedAt < twoWeeksAgo).delete()
        case .securityNotices:
            removed += try await SecurityNoticeRecord.query(on: db).filter(\.$createdAt < platformCutoff).count()
            try await SecurityNoticeRecord.query(on: db).filter(\.$createdAt < platformCutoff).delete()
            let dismissedCutoff = now.addingTimeInterval(-90 * day)
            removed += try await SecurityNoticeRecord.query(on: db).filter(\.$dismissedAt != nil).filter(\.$dismissedAt < dismissedCutoff).count()
            try await SecurityNoticeRecord.query(on: db).filter(\.$dismissedAt != nil).filter(\.$dismissedAt < dismissedCutoff).delete()
        case .supportRecords:
            var tickets = SupportTicketRecord.query(on: db).filter(\.$status == "closed").filter(\.$updatedAt < platformCutoff)
            if !heldBusinesses.isEmpty { tickets = tickets.filter(\.$businessId !~ heldBusinesses) }
            let ticketIds = try await tickets.limit(Self.batch).all().compactMap(\.id)
            if !ticketIds.isEmpty { try await SupportTicketRecord.query(on: db).filter(\.$id ~~ ticketIds).delete() }
            removed += ticketIds.count
            removed += try await OperatorNoticeRecord.query(on: db).filter(\.$status == "done").filter(\.$createdAt < platformCutoff).count()
            try await OperatorNoticeRecord.query(on: db).filter(\.$status == "done").filter(\.$createdAt < platformCutoff).delete()
            let decided = ["rejected", "executed", "expired", "cancelled"]
            removed += try await PendingChangeRecord.query(on: db).filter(\.$status ~~ decided).filter(\.$requestedAt < platformCutoff).count()
            try await PendingChangeRecord.query(on: db).filter(\.$status ~~ decided).filter(\.$requestedAt < platformCutoff).delete()
            var requests = DataRequestRecord.query(on: db).filter(\.$status ~~ ["completed", "rejected", "expired"]).filter(\.$createdAt < platformCutoff)
            if !heldBusinesses.isEmpty { requests = requests.filter(\.$businessId !~ heldBusinesses) }
            let requestIds = try await requests.limit(Self.batch).all().compactMap(\.id)
            if !requestIds.isEmpty { try await DataRequestRecord.query(on: db).filter(\.$id ~~ requestIds).delete() }
            removed += requestIds.count
            removed += try await AccountFreezeRecord.query(on: db).filter(\.$releasedAt != nil).filter(\.$releasedAt < platformCutoff).count()
            try await AccountFreezeRecord.query(on: db).filter(\.$releasedAt != nil).filter(\.$releasedAt < platformCutoff).delete()
            // A tenant export artifact is erased as soon as its 24-hour window ends.
            try await DataRequestRecord.query(on: db).filter(\.$artifactExpiresAt != nil).filter(\.$artifactExpiresAt < now).filter(\.$artifact != nil)
                .set(\.$artifact, to: nil).set(\.$status, to: "expired").update()
            // Short-lived: an expired data-export bundle is erased at once and its row removed after a week.
            try await ConsumerExportRecord.query(on: db).filter(\.$expiresAt < now).filter(\.$bundle != nil).set(\.$bundle, to: nil).set(\.$status, to: "expired").update()
            let exportCutoff = now.addingTimeInterval(-7 * day)
            removed += try await ConsumerExportRecord.query(on: db).filter(\.$expiresAt < exportCutoff).count()
            try await ConsumerExportRecord.query(on: db).filter(\.$expiresAt < exportCutoff).delete()
            // Dashboard sign-in context older than a year.
            let contextCutoff = now.addingTimeInterval(-400 * day)
            removed += try await DashboardKnownContextRecord.query(on: db).filter(\.$lastSeenAt < contextCutoff).count()
            try await DashboardKnownContextRecord.query(on: db).filter(\.$lastSeenAt < contextCutoff).delete()
        }
        return removed
    }
}

/// Audit-event retention with checkpoints. Events leave the table only when (a) a signed head at or beyond them was exported to the write-once
/// bucket, and (b) they are older than the cutoff. The last removed event's sequence and hash are kept in `audit_checkpoints`, and
/// `AuditService.verifyChain` continues from there, so a purge never makes the remaining chain unverifiable. Without an export target nothing
/// is purged (tamper evidence is worth more than the rows).
struct AuditRetention {
    let db: any Database
    let ctx: ServerContext

    func purge(before cutoff: Date, report: inout RetentionPurger.Report) async throws -> Int {
        guard ctx.config.operations.auditExport != nil else { report.skipped[RetentionClass.auditEvents.rawValue] = "no_export_target"; return 0 }
        guard let mark = try await PlatformFlagRecord.query(on: db).filter(\.$flag == PlatformFlag.auditExportMark.rawValue).first(),
              let exportedSeq = Int(mark.value) else { report.skipped[RetentionClass.auditEvents.rawValue] = "not_exported"; return 0 }
        // The boundary: the newest event that is old enough and already exported. At least one event always remains.
        guard let last = try await AuditEventRecord.query(on: db).filter(\.$occurredAt < cutoff).filter(\.$seq <= exportedSeq).sort(\.$seq, .descending).first(),
              let head = try await AuditEventRecord.query(on: db).sort(\.$seq, .descending).first(), last.seq < head.seq else { return 0 }
        let removed = try await AuditEventRecord.query(on: db).filter(\.$seq <= last.seq).count()
        guard removed > 0 else { return 0 }
        try await db.transaction { tx in
            let checkpoint = AuditCheckpointRecord()
            checkpoint.id = UUID()
            checkpoint.seq = last.seq
            checkpoint.hash = last.hash
            checkpoint.keyEpoch = last.keyEpoch
            checkpoint.removed = removed
            checkpoint.createdAt = ctx.now
            try await checkpoint.create(on: tx)
            try await AuditEventRecord.query(on: tx).filter(\.$seq <= last.seq).delete()
        }
        return removed
    }
}

final class AuditCheckpointRecord: Model, @unchecked Sendable {
    static let schema = "audit_checkpoints"
    @ID(key: .id) var id: UUID?
    @Field(key: "seq") var seq: Int
    @Field(key: "hash") var hash: String
    @OptionalField(key: "key_epoch") var keyEpoch: Int?
    @Field(key: "removed") var removed: Int
    @Field(key: "created_at") var createdAt: Date

    init() {}
}
