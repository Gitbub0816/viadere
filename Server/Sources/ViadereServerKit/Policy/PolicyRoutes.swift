import Fluent
import Foundation
import Vapor
import ViadereCore

extension Request {
    /// Business-level policy check for the capability a handler is about to exercise: key scope, entitlement ceiling, tier, kill
    /// switches and law/policy. Call it first in the handler. A denial is audited and thrown as the API error (`403 insufficient_scope`,
    /// `403 not_entitled`, ...); an allowed check is silent (the service audits the final decision).
    func requireCapability(_ capability: Capability) async throws {
        try await PolicyService(db: db, ctx: ctx).enforce(PolicyInput(capability), principal: try business, auditAllowed: false)
    }
}

enum PolicyRoutes {
    static func register(_ routes: any RoutesBuilder) {
        // What this key can do right now. Any valid key may ask; it reveals only the key's own business.
        routes.api(APIRoutes.businessCapabilities) { req in
            let principal = try req.business
            let facts = try await PolicyService(db: req.db, ctx: req.ctx).businessFacts(principal: principal)
            let effective = Capability.known.filter { capability in
                guard let definition = capability.definition, facts.active, facts.keyScopes.contains(capability),
                      facts.entitlements.contains(capability), facts.tiers.contains(definition.minimumTier),
                      facts.disabled[capability] == nil else { return false }
                return !(facts.switchesUnavailable && definition.sensitivity >= .high)
            }
            let order = Dictionary(uniqueKeysWithValues: Capability.known.enumerated().map { ($1, $0) })
            func sorted(_ set: Set<Capability>) -> [Capability] { set.sorted { (order[$0] ?? .max) < (order[$1] ?? .max) } }
            return try req.jsonResponse(BusinessCapabilitiesResponse(
                businessId: principal.businessId, environment: facts.keyEnvironment, tiers: facts.tiers.sorted { $0.rawValue < $1.rawValue },
                entitlements: sorted(facts.entitlements), keyScopes: sorted(facts.keyScopes), effective: effective,
                catalog: CapabilityCatalog.definitions))
        }
    }
}
