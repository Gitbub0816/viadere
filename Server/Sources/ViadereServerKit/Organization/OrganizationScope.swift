import Fluent
import Foundation
import ViadereCore

/// Which businesses an account may see in an Organization view, derived **only** from the authenticated principal (spec D3; plan 4.8). A
/// `business_id` filter is accepted only when it names one of them; anything else is `404`, the same answer as a business that does not exist.
///
/// * Own: businesses with an **active** relationship. A business the customer left disappears from All views (its history stays in the
///   relationship list and in the customer's own export).
/// * Delegated: for each active household grant received, the grant's businesses at which the **grantor** still has an active relationship,
///   limited to the grant's purposes. A delegate never sees the grantor's Approve v2 requests, verification requests or account notices: those
///   are bound to the grantor's own keys and devices.
struct OrganizationScope: Sendable {
    let consumerId: UUID
    let own: Set<UUID>
    let grants: [Grant]

    struct Grant: Sendable {
        var grantorId: UUID
        var businesses: Set<UUID>
        var purposes: Set<String>
        var canAct: Bool
    }

    /// Every business visible to the account (own or delegated).
    var visible: Set<UUID> { grants.reduce(own) { $0.union($1.businesses) } }

    func contains(_ business: UUID) -> Bool { visible.contains(business) }

    /// The checked filter: `nil` for All, the business when visible, `404` otherwise.
    func authorize(_ business: BusinessID?) throws -> UUID? {
        guard let business else { return nil }
        guard contains(business.uuid) else { throw APIError.notFound }
        return business.uuid
    }

    /// The scope restricted to one business (or unchanged for All).
    func narrowed(to business: UUID?) -> OrganizationScope {
        guard let business else { return self }
        return OrganizationScope(consumerId: consumerId, own: own.contains(business) ? [business] : [],
                                 grants: grants.compactMap { grant in
                                     guard grant.businesses.contains(business) else { return nil }
                                     var g = grant
                                     g.businesses = [business]
                                     return g
                                 })
    }

    static func load(consumer: ConsumerID, db: any Database, ctx: ServerContext) async throws -> OrganizationScope {
        let own = try await RelationshipRecord.query(on: db).filter(\.$consumerId == consumer.uuid).filter(\.$status == "active").all().map(\.businessId)
        var grants: [Grant] = []
        for grant in try await HouseholdService(db: db, ctx: ctx).activeReceivedGrants(delegate: consumer) {
            let wanted = grant.businessIdSet
            guard !wanted.isEmpty, !grant.purposeSet.isEmpty else { continue }
            guard let grantor = try await ConsumerRecord.find(grant.grantorId, on: db), grantor.status == "active" else { continue }
            let active = try await RelationshipRecord.query(on: db).filter(\.$consumerId == grant.grantorId).filter(\.$status == "active")
                .filter(\.$businessId ~~ wanted).all().map(\.businessId)
            guard !active.isEmpty else { continue }
            grants.append(Grant(grantorId: grant.grantorId, businesses: Set(active), purposes: Set(grant.purposeSet.map(\.rawValue)),
                                canAct: grant.roleValue == .manager))
        }
        return OrganizationScope(consumerId: consumer.uuid, own: Set(own), grants: grants)
    }
}
