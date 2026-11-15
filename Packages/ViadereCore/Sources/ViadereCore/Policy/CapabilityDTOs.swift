import Foundation

/// `GET /v1/business/capabilities`: what the calling API key can do **right now**, and the catalog that defines it.
///
/// `effective` is `keyScopes ∩ entitlements` minus anything switched off, so an integration can discover that a capability was
/// revoked or disabled without making a failing call. It is informational: every request is still evaluated by the policy engine.
public struct BusinessCapabilitiesResponse: Codable, Sendable, Hashable {
    public var businessId: BusinessID
    /// `live` or `test` (the key's environment).
    public var environment: PolicyEnvironment
    public var tiers: [BusinessRiskTier]
    /// What Viadere has granted the business (the ceiling).
    public var entitlements: [Capability]
    /// What this key carries.
    public var keyScopes: [Capability]
    public var effective: [Capability]
    public var catalog: [CapabilityDefinition]

    public init(businessId: BusinessID, environment: PolicyEnvironment, tiers: [BusinessRiskTier], entitlements: [Capability],
                keyScopes: [Capability], effective: [Capability], catalog: [CapabilityDefinition]) {
        self.businessId = businessId
        self.environment = environment
        self.tiers = tiers
        self.entitlements = entitlements
        self.keyScopes = keyScopes
        self.effective = effective
        self.catalog = catalog
    }
}
