import Fluent
import Foundation
import ViadereCore
import enum ViadereCore.Channel

/// Purpose-scoped, versioned consent. History is append-only: a change inserts a new version.
struct ConsentService {
    let db: any Database
    let ctx: ServerContext

    static let currentPolicyVersion = "2026-10"

    /// Latest grant per purpose (explicit records only).
    func latest(relationshipId: UUID) async throws -> [InteractionPurpose: ConsentGrantRecord] {
        let all = try await ConsentGrantRecord.query(on: db).filter(\.$relationshipId == relationshipId).all()
        var out: [InteractionPurpose: ConsentGrantRecord] = [:]
        for record in all {
            guard let purpose = InteractionPurpose(rawValue: record.purpose) else { continue }
            if let existing = out[purpose], existing.version >= record.version { continue }
            out[purpose] = record
        }
        return out
    }

    /// All six purposes, with defaults filled in for purposes that have no record.
    func effective(relationship: RelationshipRecord) async throws -> [ConsentGrant] {
        let latest = try await self.latest(relationshipId: relationship.id!)
        return InteractionPurpose.allCases.map { purpose in
            if let record = latest[purpose], let dto = record.dto { return dto }
            return ConsentGrant(id: ConsentGrantID(), consumerId: ConsumerID(relationship.consumerId), businessId: BusinessID(relationship.businessId),
                                relationshipId: RelationshipID(relationship.id!), purpose: purpose, granted: purpose.isGrantedByDefault,
                                version: 0, policyVersion: Self.currentPolicyVersion, source: .system, channels: [],
                                createdAt: relationship.connectedAt, updatedAt: relationship.connectedAt)
        }
    }

    func permits(purpose: InteractionPurpose, relationshipId: UUID) async throws -> Bool {
        let grants = try await ConsentGrantRecord.query(on: db).filter(\.$relationshipId == relationshipId)
            .filter(\.$purpose == purpose.rawValue).all().compactMap(\.dto)
        return ConsentPolicy.permits(purpose: purpose, grants: grants)
    }

    /// Writes the initial consent versions for a (re)connected relationship.
    func initialize(relationship: RelationshipRecord, optIn: Set<InteractionPurpose>, source: ConsentSource, channels: [Channel]) async throws {
        let existing = try await latest(relationshipId: relationship.id!)
        for purpose in InteractionPurpose.allCases {
            let granted = purpose.isGrantedByDefault || optIn.contains(purpose)
            let previous = existing[purpose]
            if let previous, previous.granted == granted { continue }
            try await ConsentGrantRecord(consumerId: relationship.consumerId, businessId: relationship.businessId,
                                         relationshipId: relationship.id!, purpose: purpose, granted: granted,
                                         version: (previous?.version ?? 0) + 1, policyVersion: Self.currentPolicyVersion, source: source,
                                         channels: channels, now: ctx.now).create(on: db)
        }
    }

    /// Applies consumer changes. `security` and `accountService` cannot be revoked.
    @discardableResult
    func apply(changes: [ConsentChange], policyVersion: String, relationship: RelationshipRecord, source: ConsentSource,
               channels: [Channel] = [.nativePush, .inApp]) async throws -> [ConsentChange] {
        guard !changes.isEmpty, changes.count <= InteractionPurpose.allCases.count,
              Set(changes.map(\.purpose)).count == changes.count else {
            throw APIError.validation("Provide one change per purpose.", details: ["changes": "invalid"])
        }
        guard !policyVersion.isEmpty, policyVersion.count <= 32 else {
            throw APIError.validation("A policy version is required.", details: ["policyVersion": "invalid"])
        }
        for change in changes where !change.purpose.isRevocable && !change.granted {
            throw APIError(.forbidden, .forbidden, "Security and account-service messages cannot be turned off.",
                           details: ["purpose": change.purpose.rawValue])
        }
        let current = try await latest(relationshipId: relationship.id!)
        var applied: [ConsentChange] = []
        for change in changes {
            let previous = current[change.purpose]
            let previousValue = previous?.granted ?? change.purpose.isGrantedByDefault
            if previous != nil && previousValue == change.granted { continue }
            try await ConsentGrantRecord(consumerId: relationship.consumerId, businessId: relationship.businessId,
                                         relationshipId: relationship.id!, purpose: change.purpose, granted: change.granted,
                                         version: (previous?.version ?? 0) + 1, policyVersion: policyVersion, source: source,
                                         channels: channels, now: ctx.now).create(on: db)
            applied.append(change)
        }
        return applied
    }
}

/// Connect / list / disconnect.
struct RelationshipService {
    let db: any Database
    let ctx: ServerContext

    func dto(_ record: RelationshipRecord, business: BusinessSummary) -> Relationship {
        Relationship(id: RelationshipID(record.id!), consumerId: ConsumerID(record.consumerId), business: business,
                     status: record.isActive ? .active : .disconnected, source: ConnectSource(rawValue: record.source) ?? .link,
                     connectedAt: record.connectedAt, disconnectedAt: record.disconnectedAt)
    }

    /// The consumer's own relationship, or `nil` (never reveals other consumers' records).
    func owned(_ id: RelationshipID, by consumer: ConsumerID) async throws -> RelationshipRecord? {
        try await RelationshipRecord.query(on: db).filter(\.$id == id.uuid).filter(\.$consumerId == consumer.uuid).first()
    }

    func list(consumer: ConsumerID) async throws -> [Relationship] {
        // A connection waiting for a business's link confirmation is not a relationship yet (WP-C1).
        let records = try await RelationshipRecord.query(on: db).filter(\.$consumerId == consumer.uuid).filter(\.$status != RelationshipRecord.pendingLink)
            .sort(\.$connectedAt, .descending).all()
        let businesses = try await BusinessRecord.query(on: db).filter(\.$id ~~ records.map(\.businessId)).all()
        let summaries = try await DirectoryService(db: db).summaries(for: businesses)
        let byId = Dictionary(summaries.map { ($0.id.uuid, $0) }, uniquingKeysWith: { first, _ in first })
        return records.compactMap { record in byId[record.businessId].map { dto(record, business: $0) } }
    }

    /// Connects (or reconnects) a consumer to a verified business. Idempotent for an active relationship.
    func connect(consumer: ConsumerID, request: ConnectRequest, source: ConnectSource? = nil, channels: [Channel] = [.nativePush, .inApp],
                 consentSource: ConsentSource = .app) async throws -> (relationship: Relationship, created: Bool) {
        let directory = DirectoryService(db: db)
        guard let business = try await directory.verified(id: request.businessId.uuid),
              let summary = try await directory.summary(for: business) else { throw APIError.notFound }
        if let link = request.link {
            // A supplied link must be a valid Viadere link for *this* business; its signed context is verified, never trusted.
            guard let parsed = try? ConnectLink.parse(link, domain: ctx.config.linkDomain), parsed.code == summary.code else {
                throw APIError.validation("The connect link does not match this business.", details: ["link": "mismatch"])
            }
        }
        // A business the customer blocked cannot be connected again, by any path, until the customer unblocks it (WP-1.5).
        if try await PreferenceService(db: db, ctx: ctx).isBlocked(consumer: consumer.uuid, business: business.id!) {
            throw APIError.conflict(PreferenceService.blockedMessage)
        }
        let optIn = Set(request.optInPurposes.filter { !$0.isGrantedByDefault })
        let now = ctx.now
        let effectiveSource = source ?? request.source
        let (record, created) = try await db.transaction { tx -> (RelationshipRecord, Bool) in
            if let existing = try await RelationshipRecord.query(on: tx).filter(\.$consumerId == consumer.uuid)
                .filter(\.$businessId == business.id!).first() {
                if existing.isActive { return (existing, false) }
                existing.status = "active"
                existing.disconnectedAt = nil
                existing.connectedAt = now
                existing.lastActivityAt = now
                existing.source = effectiveSource.rawValue
                try await existing.update(on: tx)
                try await ConsentService(db: tx, ctx: ctx).initialize(relationship: existing, optIn: optIn, source: consentSource, channels: channels)
                return (existing, true)
            }
            let record = RelationshipRecord(consumerId: consumer.uuid, businessId: business.id!, source: effectiveSource, now: now)
            try await record.create(on: tx)
            try await ConsentService(db: tx, ctx: ctx).initialize(relationship: record, optIn: optIn, source: consentSource, channels: channels)
            return (record, true)
        }
        if created {
            let audit = AuditService(db: db, ctx: ctx)
            _ = try await audit.record("relationship.connected", actor: AuditActor(kind: .consumer, id: consumer.description),
                                       consumerId: consumer, businessId: summary.id, subjectType: "relationship",
                                       subjectId: record.id?.uuidString.lowercased(), metadata: ["source": effectiveSource.rawValue])
            try await WebhookService(db: db, ctx: ctx).enqueue(.relationshipConnected, businessId: summary.id,
                payload: RelationshipEventPayload(relationshipId: RelationshipID(record.id!), subjectRef: ctx.subjects.subjectRef(businessId: summary.id, consumerId: consumer),
                                                       source: effectiveSource, occurredAt: now))
        }
        return (dto(record, business: summary), created)
    }

    /// Disconnects: pending interactions are cancelled and the business is told.
    func disconnect(consumer: ConsumerID, relationshipId: RelationshipID) async throws {
        guard let record = try await owned(relationshipId, by: consumer) else { throw APIError.notFound }
        guard record.isActive else { return }
        let now = ctx.now
        let businessId = BusinessID(record.businessId)
        // Read before the transaction; ending is a no-op for any that did not end up cancelled.
        let pendingIds = try await InteractionRecord.query(on: db).filter(\.$relationshipId == record.id!)
            .filter(\.$status == InteractionStatus.pending.rawValue).all().compactMap(\.id)
        try await db.transaction { tx in
            record.status = "disconnected"
            record.disconnectedAt = now
            try await record.update(on: tx)
            let pending = try await InteractionRecord.query(on: tx).filter(\.$relationshipId == record.id!)
                .filter(\.$status == InteractionStatus.pending.rawValue).all()
            for interaction in pending {
                _ = try await InteractionService(db: tx, ctx: ctx).cancelPending(interaction, notify: true)
            }
            try await ConversationSessionRecord.query(on: tx).filter(\.$relationshipId == record.id!).filter(\.$state != "closed")
                .set(\.$state, to: "closed").set(\.$closedAt, to: now).update()
            // Disconnecting ends the business's ability to ask for approvals: its keys for this relationship are revoked and the requests stop.
            try await ApproveKeyService(db: tx, ctx: ctx).revokeKeys(where: .relationship(record.id!), reason: "disconnected")
            try await WebhookService(db: tx, ctx: ctx).enqueue(.relationshipDisconnected, businessId: businessId,
                payload: RelationshipEventPayload(relationshipId: relationshipId, subjectRef: ctx.subjects.subjectRef(businessId: businessId, consumerId: consumer),
                                                       source: nil, occurredAt: now))
            _ = try await AuditService(db: tx, ctx: ctx).record("relationship.disconnected",
                actor: AuditActor(kind: .consumer, id: consumer.description), consumerId: consumer, businessId: businessId,
                subjectType: "relationship", subjectId: relationshipId.description)
        }
        // Withdrawn requests end their decision Live Activities after the commit.
        let service = InteractionService(db: db, ctx: ctx)
        for id in pendingIds { await service.endDecisionActivity(id) }
    }
}

struct RelationshipEventPayload: Codable, Sendable {
    var relationshipId: RelationshipID
    var subjectRef: SubjectRef?
    var source: ConnectSource?
    var occurredAt: Date
}

struct ConsentEventPayload: Codable, Sendable {
    var relationshipId: RelationshipID
    var subjectRef: SubjectRef?
    var purpose: InteractionPurpose
    var granted: Bool
    var occurredAt: Date
}
