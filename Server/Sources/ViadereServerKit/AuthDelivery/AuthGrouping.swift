import Fluent
import Foundation
import ViadereCore

/// The open number-match tags of one person's requests at one business (class T, deleted at the terminal state). Viadere never sees a code, only the SDK's
/// HMAC tags (ADR-0020 section 2a). A group is (business, consumer).
final class AuthMatchTagRecord: Model, @unchecked Sendable {
    static let schema = "auth_match_tags"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "consumer_id") var consumerId: UUID
    /// The open request the tags belong to (a delivery or, in Stage 5, an approval).
    @Field(key: "ref_id") var refId: UUID
    @Field(key: "tag") var tag: String
    @OptionalField(key: "prefix_tag") var prefixTag: String?
    @Field(key: "created_at") var createdAt: Date

    init() {}
}

struct CreateAuthMatchTagsSchema: AsyncMigration {
    var name: String { "AuthMatchTags.v1" }

    func prepare(on db: any Database) async throws {
        try await db.schema(AuthMatchTagRecord.schema)
            .id()
            .field("business_id", .uuid, .required)
            .field("consumer_id", .uuid, .required)
            .field("ref_id", .uuid, .required)
            .field("tag", .string, .required)
            .field("prefix_tag", .string)
            .field("created_at", .datetime, .required)
            .unique(on: "ref_id")
            .create()
    }

    func revert(on db: any Database) async throws { try await db.schema(AuthMatchTagRecord.schema).delete() }
}

/// **Number-match allocation among one person's open requests (ADR-0020 section 2a).** The rule itself is `MatchGroupPolicy` (Core); this type stores the tags and
/// maps the decision to the three `409` answers. Allocation is serialized per person (a row lock on the consumer), so two concurrent requests cannot both take
/// the same code. There is deliberately **no per-initiator cap**: the first answer other than `409` is exhaustion of the code space (at least 639 requests).
struct AuthMatchGroups {
    let db: any Database
    let ctx: ServerContext

    /// Reserves the tags of one request inside the caller's transaction, or throws `409 match_code_in_use`, `match_digits_required` or `match_code_space_exhausted`
    /// (nothing is created).
    func reserve(businessId: UUID, consumerId: UUID, refId: UUID, members: AuthMatchTagMembers) async throws {
        try await DB.lockForUpdate(db, table: ConsumerRecord.schema, id: consumerId)
        try await check(businessId: businessId, consumerId: consumerId, members: members, alert: false)
        let tag = members.matchTag ?? ""
        let row = AuthMatchTagRecord()
        row.id = UUID()
        row.businessId = businessId
        row.consumerId = consumerId
        row.refId = refId
        row.tag = tag
        row.prefixTag = members.matchPrefixTag
        row.createdAt = ctx.now
        try await row.create(on: db)
    }

    /// The decision for a new request's tags. Call it **before** the creating transaction with `alert: true` (the exhaustion audit and the critical operator alert are
    /// then durable even though the request is refused); `reserve` repeats it inside the transaction under the row lock.
    func check(businessId: UUID, consumerId: UUID, members: AuthMatchTagMembers, alert: Bool = true) async throws {
        guard let tag = members.matchTag, AuthMatchTags.isValidTag(tag) else { throw APIError.validation("match_tag is required.", details: ["match_tag": "invalid"]) }
        let open = try await AuthMatchTagRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$consumerId == consumerId).all()
            .map { MatchGroupPolicy.Open(tag: $0.tag, prefixTag: $0.prefixTag) }
        switch MatchGroupPolicy.evaluate(new: (tag, members.matchPrefixTag), open: open) {
        case .accepted: break
        case .inUse: throw APIError(.conflict, .matchCodeInUse, "That code is already in use for this customer. Draw another.")
        case .digitsRequired: throw APIError(.conflict, .matchDigitsRequired, "Use a 3-digit code.", details: ["digits": "3"])
        case .exhausted:
            if alert {
                ctx.logger.critical("auth match code space exhausted", metadata: ["business": "\(businessId)"])
                _ = try? await AuditService(db: db, ctx: ctx).record("auth_delivery.match_code_space_exhausted", outcome: .failure, actor: AuditActor(kind: .system),
                                                                   consumerId: ConsumerID(consumerId), businessId: BusinessID(businessId), subjectType: "auth_match_group")
            }
            throw APIError(.conflict, .matchCodeSpaceExhausted, "No free code is available for this customer right now.")
        }
    }

    /// Terminal state: the tags are deleted.
    func release(refId: UUID) async throws {
        try await AuthMatchTagRecord.query(on: db).filter(\.$refId == refId).delete()
    }

    func openCount(businessId: UUID, consumerId: UUID) async throws -> Int {
        try await AuthMatchTagRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$consumerId == consumerId).count()
    }
}
