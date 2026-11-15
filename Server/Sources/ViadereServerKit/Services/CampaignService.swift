import Fluent
import Foundation
import Vapor
import ViadereCore

/// A campaign link a business created (docs/SECURITY.md §2.106). `public_id` is the business's own identifier and the `cmp` member of the
/// signed connect context; it is unique per business and is never reused, archived or not.
final class CampaignRecord: Model, @unchecked Sendable {
    static let schema = "campaigns"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "public_id") var publicId: String
    /// A label for the console. Free text: escaped wherever it is shown.
    @Field(key: "name") var name: String
    /// `CampaignAction` raw value, or null.
    @OptionalField(key: "action") var action: String?
    @OptionalField(key: "expires_at") var expiresAt: Date?
    @OptionalField(key: "created_by") var createdBy: String?
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "archived_at") var archivedAt: Date?
    @OptionalField(key: "archived_by") var archivedBy: String?
    init() {}
}

/// Campaigns: stored, listed, credited and counted, always inside one business.
///
/// **Crediting rule.** A connection is credited to a campaign only when the connect link's context verifies under a server key (which
/// binds it to the business's code), names a campaign of that same business, and that campaign is neither archived nor expired at that
/// moment. Anything else still connects, because the link is the business's own permanent code, but credits nothing.
struct CampaignService {
    let db: any Database
    let ctx: ServerContext

    static let maxCampaignsPerBusiness = 500
    static let maxNameLength = 80
    static let identifierCharacters = CharacterSet(charactersIn: "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.-")

    enum Status: String { case active, expired, archived }

    static func status(_ record: CampaignRecord, now: Date) -> Status {
        if record.archivedAt != nil { return .archived }
        if let expiresAt = record.expiresAt, now >= expiresAt { return .expired }
        return .active
    }

    enum Credit {
        /// The link has no context, or its context names no campaign.
        case none
        case credited(CampaignRecord)
        /// A context was present but earns nothing: `unverified`, `expired`, `unknown`, `archived`.
        case uncredited(reason: String)
    }

    func list(businessId: UUID) async throws -> [CampaignRecord] {
        try await CampaignRecord.query(on: db).filter(\.$businessId == businessId).sort(\.$createdAt, .descending).all()
    }

    /// One campaign of **this** business; another tenant's id is `404`.
    func find(businessId: UUID, id: UUID) async throws -> CampaignRecord {
        guard let record = try await CampaignRecord.query(on: db).filter(\.$id == id).filter(\.$businessId == businessId).first() else { throw APIError.notFound }
        return record
    }

    func find(businessId: UUID, publicId: String) async throws -> CampaignRecord? {
        try await CampaignRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$publicId == publicId).first()
    }

    static func cleanIdentifier(_ value: String?) throws -> String {
        guard let value = value?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty else {
            throw APIError.validation("Give the campaign a short identifier.", details: ["campaign": "required"])
        }
        guard value.count <= 64, value.unicodeScalars.allSatisfy({ identifierCharacters.contains($0) }) else {
            throw APIError.validation("Use up to 64 letters, digits, dots, dashes or underscores.", details: ["campaign": "invalid"])
        }
        return value
    }

    static func cleanName(_ value: String?, fallback: String) throws -> String {
        guard let value = value?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty else { return fallback }
        guard value.count <= maxNameLength, !value.unicodeScalars.contains(where: { $0.properties.generalCategory == .control || $0.properties.generalCategory == .format }) else {
            throw APIError.validation("Use a name of up to \(maxNameLength) characters.", details: ["name": "invalid"])
        }
        return value
    }

    /// The action a form names: empty means none, anything off the closed list is refused.
    static func cleanAction(_ value: String?) throws -> CampaignAction? {
        guard let value = value?.trimmingCharacters(in: .whitespacesAndNewlines), !value.isEmpty else { return nil }
        guard let action = CampaignAction(rawValue: value) else {
            throw APIError.validation("Choose one of the listed actions.", details: ["action": "invalid"])
        }
        return action
    }

    func create(businessId: UUID, publicId: String, name: String, action: CampaignAction?, validDays: Int, actor: AuditActor) async throws -> CampaignRecord {
        guard try await find(businessId: businessId, publicId: publicId) == nil else {
            throw APIError.validation("You already have a campaign with that identifier. Open it from the list, or choose another identifier.", details: ["campaign": "taken"])
        }
        guard try await CampaignRecord.query(on: db).filter(\.$businessId == businessId).count() < Self.maxCampaignsPerBusiness else {
            throw APIError.conflict("You have reached the limit of \(Self.maxCampaignsPerBusiness) campaigns.")
        }
        let now = ViadereDate.truncatedToMilliseconds(ctx.now)
        let days = min(max(validDays, 0), 365)
        let record = CampaignRecord()
        record.id = UUID()
        record.businessId = businessId
        record.publicId = publicId
        record.name = name
        record.action = action?.rawValue
        record.expiresAt = days == 0 ? nil : now.addingTimeInterval(TimeInterval(days) * 86_400)
        record.createdBy = actor.id
        record.createdAt = now
        do { try await record.create(on: db) } catch {
            // The unique index decided a race between two submissions of the same identifier.
            throw APIError.validation("You already have a campaign with that identifier.", details: ["campaign": "taken"])
        }
        var metadata = ["campaign": publicId]
        if let action { metadata["action"] = action.rawValue }
        _ = try await AuditService(db: db, ctx: ctx).record("campaign.link_created", actor: actor, businessId: BusinessID(businessId), subjectType: "campaign",
                                                             subjectId: record.id?.uuidString.lowercased(), metadata: metadata)
        return record
    }

    /// Archiving ends crediting and the follow-up action. The link itself keeps connecting: it is the business's permanent code.
    func archive(businessId: UUID, id: UUID, actor: AuditActor) async throws {
        let record = try await find(businessId: businessId, id: id)
        guard record.archivedAt == nil else { return }
        record.archivedAt = ctx.now
        record.archivedBy = actor.id
        try await record.update(on: db)
        _ = try await AuditService(db: db, ctx: ctx).record("campaign.archived", actor: actor, businessId: BusinessID(businessId), subjectType: "campaign",
                                                             subjectId: id.uuidString.lowercased(), metadata: ["campaign": record.publicId])
    }

    /// The campaign's signed link. Built from the stored row, so it is the same link every time (until the signing key rotates; both
    /// links then verify).
    func link(for record: CampaignRecord, code: BusinessCode) throws -> ConnectLink {
        let context = ConnectContext(campaign: record.publicId, action: record.action, issuedAt: record.createdAt, expiresAt: record.expiresAt)
        return try ctx.connectKeys.link(code: code, context: context, domain: ctx.config.linkDomain)
    }

    /// What a parsed link of `businessId` earns. The caller has already checked that the link's code is this business's code.
    func credit(businessId: UUID, link: ConnectLink) async throws -> Credit {
        guard link.context != nil else { return .none }
        let context: ConnectContext
        do { context = try ctx.connectKeys.verifiedContext(of: link, now: ctx.now) } catch ConnectLink.ContextError.expired {
            return .uncredited(reason: "expired")
        } catch {
            return .uncredited(reason: "unverified")
        }
        guard let publicId = context.campaign else { return .none }
        guard let record = try await find(businessId: businessId, publicId: publicId) else { return .uncredited(reason: "unknown") }
        switch Self.status(record, now: ctx.now) {
        case .archived: return .uncredited(reason: "archived")
        case .expired: return .uncredited(reason: "expired")
        case .active: return .credited(record)
        }
    }

    /// The context to hand to the app for a link: verified, and with its action kept only when it is on the closed list **and** the
    /// campaign is live. The app never acts on an action from anywhere else.
    func presentable(businessId: UUID, link: ConnectLink) async throws -> ConnectContext? {
        guard var context = try? ctx.connectKeys.verifiedContext(of: link, now: ctx.now) else { return nil }
        if case .credited(let record) = try await credit(businessId: businessId, link: link), CampaignAction(verified: context) != nil, record.action == context.action {
            return context
        }
        context.action = nil
        return context
    }

    /// Connections credited to each campaign of this business (all time, or made at or after `since`).
    func connectCounts(businessId: UUID, since: Date? = nil) async throws -> [UUID: Int] {
        var query = RelationshipRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$campaignId != nil)
        if let since { query = query.filter(\.$connectedAt >= since) }
        var counts: [UUID: Int] = [:]
        for row in try await query.field(\.$campaignId).all() {
            if let id = row.campaignId { counts[id, default: 0] += 1 }
        }
        return counts
    }
}
