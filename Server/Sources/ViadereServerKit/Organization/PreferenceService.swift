import Fluent
import Foundation
import ViadereCore
import typealias ViadereCore.SessionID

/// Per-business preferences, the Businesses directory and block enforcement (WP-1.5; spec C7.2; SECURITY.md §2.96).
struct PreferenceService {
    let db: any Database
    let ctx: ServerContext

    /// The caller's connection with `business` that preferences may be read or written for: any relationship the customer has or had
    /// (a block must be reachable after it ended the connection), never one waiting for a link confirmation. Otherwise `404`.
    func ownedRelationship(consumer: ConsumerID, business: BusinessID) async throws -> RelationshipRecord {
        guard let relationship = try await RelationshipRecord.query(on: db).filter(\.$consumerId == consumer.uuid).filter(\.$businessId == business.uuid)
            .filter(\.$status != RelationshipRecord.pendingLink).first() else { throw APIError.notFound }
        return relationship
    }

    func record(consumer: UUID, business: UUID, on db: any Database) async throws -> BusinessPreferenceRecord? {
        try await BusinessPreferenceRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$businessId == business).first()
    }

    func get(consumer: ConsumerID, business: BusinessID) async throws -> BusinessPreferences {
        _ = try await ownedRelationship(consumer: consumer, business: business)
        return try await record(consumer: consumer.uuid, business: business.uuid, on: db)?.dto(business) ?? BusinessPreferences(businessId: business)
    }

    /// Whether the customer blocked the business (connect, link sessions and SMS threads refuse it).
    func isBlocked(consumer: UUID, business: UUID) async throws -> Bool {
        try await record(consumer: consumer, business: business, on: db)?.blockedAt != nil
    }

    static let blockedMessage = "You blocked this business. Unblock it in Viadere to connect again."

    /// Applies an update. Blocking also runs the normal disconnect (pending requests cancelled, conversations closed, approval keys revoked,
    /// the business told), so a block is never weaker than a disconnect.
    func update(principal: ConsumerPrincipal, business: BusinessID, update: BusinessPreferencesUpdate) async throws -> BusinessPreferences {
        let consumer = principal.consumerId
        guard !update.isEmpty else { throw APIError.validation("Change at least one preference.", details: ["preferences": "empty"]) }
        let now = ctx.now
        if let until = update.muteUntil {
            guard update.muteLevel != nil, update.muteLevel != MuteLevel.none else {
                throw APIError.validation("A mute end needs a mute level.", details: ["muteUntil": "invalid"])
            }
            guard until > now, until <= now.addingTimeInterval(BusinessPreferencesUpdate.maxMuteDuration) else {
                throw APIError.validation("A mute must end in the future and within a year.", details: ["muteUntil": "invalid"])
            }
        }
        let relationship = try await ownedRelationship(consumer: consumer, business: business)
        let result: BusinessPreferences = try await db.transaction { tx in
            let row = try await record(consumer: consumer.uuid, business: business.uuid, on: tx)
                ?? BusinessPreferenceRecord(consumerId: consumer.uuid, businessId: business.uuid, now: now)
            let wasBlocked = row.blockedAt != nil
            if let favorite = update.favorite { row.favorite = favorite }
            if let level = update.muteLevel {
                row.muteLevel = level.rawValue
                row.muteUntil = level == MuteLevel.none ? nil : update.muteUntil
            }
            if let blocked = update.blocked { row.blockedAt = blocked ? (row.blockedAt ?? now) : nil }
            row.updatedAt = now
            if row.$id.exists { try await row.update(on: tx) } else { try await row.create(on: tx) }
            // Mirror on the connection (`CustomerBusinessConnection.preferences`, WP-C1).
            try await RelationshipRecord.query(on: tx).filter(\.$id == relationship.id!)
                .set(\.$prefFavorite, to: row.favorite).set(\.$prefMuted, to: row.muteLevelValue != MuteLevel.none).update()
            var metadata = ["favorite": row.favorite ? "true" : "false", "mute_level": row.muteLevel]
            if let blocked = update.blocked, blocked != wasBlocked { metadata["blocked"] = blocked ? "true" : "false" }
            _ = try await AuditService(db: tx, ctx: ctx).record(update.blocked != nil && update.blocked != wasBlocked ? (update.blocked! ? "business.blocked" : "business.unblocked") : "business.preferences_updated",
                                                              principal: principal, businessId: business, subjectType: "relationship",
                                                              subjectId: relationship.id?.uuidString.lowercased(), metadata: metadata)
            return row.dto(business)
        }
        // The block is written first, so a connect racing this call is already refused; then the normal disconnect ends the connection
        // (it re-reads the relationship and does nothing when it already ended).
        if update.blocked == true {
            try await RelationshipService(db: db, ctx: ctx).disconnect(consumer: consumer, relationshipId: RelationshipID(relationship.id!))
        }
        return result
    }

    /// `GET /v1/businesses`: every connection the customer has or had (never pending link confirmations), with preferences, in directory order.
    func directory(consumer: ConsumerID) async throws -> [ConnectedBusiness] {
        let relationships = try await RelationshipRecord.query(on: db).filter(\.$consumerId == consumer.uuid)
            .filter(\.$status != RelationshipRecord.pendingLink).all()
        guard !relationships.isEmpty else { return [] }
        let ids = relationships.map(\.businessId)
        let businesses = try await BusinessRecord.query(on: db).filter(\.$id ~~ ids).all()
        let summaries = try await DirectoryService(db: db).summaries(for: businesses)
        let summaryById = Dictionary(summaries.map { ($0.id.uuid, $0) }, uniquingKeysWith: { a, _ in a })
        let categoryById = Dictionary(businesses.compactMap { b in b.id.map { ($0, b.category) } }, uniquingKeysWith: { a, _ in a })
        let prefs = try await BusinessPreferenceRecord.query(on: db).filter(\.$consumerId == consumer.uuid).filter(\.$businessId ~~ ids).all()
        let prefById = Dictionary(prefs.map { ($0.businessId, $0) }, uniquingKeysWith: { a, _ in a })
        let entries = relationships.compactMap { relationship -> ConnectedBusiness? in
            guard let summary = summaryById[relationship.businessId] else { return nil }
            let preferences = prefById[relationship.businessId]?.dto(summary.id) ?? BusinessPreferences(businessId: summary.id)
            return ConnectedBusiness(business: summary, category: categoryById[relationship.businessId].map(BusinessCategory.init(rawValue:)),
                                     relationshipId: RelationshipID(relationship.id!), status: relationship.isActive ? .active : .disconnected,
                                     connectedAt: relationship.connectedAt, lastActivityAt: relationship.lastActivityAt, preferences: preferences)
        }
        return BusinessDirectoryRules.ordered(entries)
    }

    /// The interruption a push for `purpose` from `business` may use under the customer's mute (spec C7.2: mute changes interruption only,
    /// never presence; never for security, account service or action-required items).
    func silences(consumer: UUID, business: UUID, purpose: InteractionPurpose, actionRequired: Bool) async -> Bool {
        guard let row = try? await record(consumer: consumer, business: business, on: db) else { return false }
        let level = row.dto(BusinessID(business)).effectiveMute(at: ctx.now)
        return MutePolicy.silences(level, purpose: purpose, actionRequired: actionRequired)
    }

    // MARK: Conversations (archive, mute)

    func conversationStates(consumer: UUID, sessions: [UUID]) async throws -> [UUID: ConversationStateRecord] {
        guard !sessions.isEmpty else { return [:] }
        let rows = try await ConversationStateRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$sessionId ~~ sessions).all()
        return Dictionary(rows.map { ($0.sessionId, $0) }, uniquingKeysWith: { a, _ in a })
    }

    func updateConversation(consumer: ConsumerID, session id: SessionID, update: ConversationStateUpdate) async throws -> ConversationStateView {
        guard update.archived != nil || update.muted != nil else { throw APIError.validation("Change at least one setting.", details: ["state": "empty"]) }
        let session = try await ConversationService(db: db, ctx: ctx).ownedSession(consumer: consumer, id: id)
        let now = ctx.now
        let row = try await ConversationStateRecord.query(on: db).filter(\.$consumerId == consumer.uuid).filter(\.$sessionId == session.id!).first()
            ?? ConversationStateRecord(consumerId: consumer.uuid, sessionId: session.id!, now: now)
        if let archived = update.archived { row.archivedAt = archived ? (row.archivedAt ?? now) : nil }
        if let muted = update.muted { row.muted = muted }
        row.updatedAt = now
        if row.$id.exists { try await row.update(on: db) } else { try await row.create(on: db) }
        return ConversationStateView(sessionId: id, archived: row.archivedAt != nil, muted: row.muted)
    }

    // MARK: Account deletion

    /// Erases the account's Organization rows (preferences, conversation state, seen marks). Called inside the deletion transaction.
    static func wipe(consumer: UUID, on db: any Database) async throws {
        try await BusinessPreferenceRecord.query(on: db).filter(\.$consumerId == consumer).delete()
        try await ConversationStateRecord.query(on: db).filter(\.$consumerId == consumer).delete()
        try await AlertSeenRecord.query(on: db).filter(\.$consumerId == consumer).delete()
    }
}
