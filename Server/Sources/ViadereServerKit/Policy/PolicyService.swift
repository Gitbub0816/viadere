import Fluent
import Foundation
import Vapor
import ViadereCore

/// Caches the platform-wide part of the policy state (global kill switches and law/policy rules) for a few seconds, so a policy
/// check costs no extra query for it. An operator change on this instance invalidates the cache at once; on other instances it
/// takes effect within `PolicyService.cacheTTL`.
actor PolicyStateCache {
    struct Global: Sendable {
        var disabled: [Capability: String]
        var rules: [PolicyRule]
        var loadedAt: Date
    }

    private var cached: Global?

    func global(now: Date, ttl: TimeInterval, load: @Sendable () async throws -> Global) async throws -> Global {
        if let cached, now.timeIntervalSince(cached.loadedAt) >= 0, now.timeIntervalSince(cached.loadedAt) < ttl { return cached }
        let fresh = try await load()
        cached = fresh
        return fresh
    }

    func invalidate() { cached = nil }
}

/// What the caller tells the engine about the request. Everything here must come from a validated source (a parsed body, a loaded
/// row), never from an unvalidated client string.
struct PolicyInput: Sendable {
    var capability: Capability
    var subjectRef: SubjectRef?
    var parameters: [String: JSONValue]?
    var purpose: String?
    var jurisdiction: String?
    var requestId: String?

    init(_ capability: Capability, subjectRef: SubjectRef? = nil, parameters: [String: JSONValue]? = nil, purpose: String? = nil,
         jurisdiction: String? = nil, requestId: String? = nil) {
        self.capability = capability
        self.subjectRef = subjectRef
        self.parameters = parameters
        self.purpose = purpose
        self.jurisdiction = jurisdiction
        self.requestId = requestId
    }
}

/// The one place every capability request is decided (spec §6.4, SEC-API-003):
/// `entitlement ∩ key scope ∩ customer consent ∩ evidence sufficiency ∩ law/policy`, fresh on every call, with an audit record.
///
/// Usage: call `enforce(_, stage: .business)` first thing in a handler (a credential that may not use the capability learns
/// nothing about the subject and no subject data is read), then `enforce(_, stage: .full, subject:)` once the subject is loaded.
struct PolicyService {
    let db: any Database
    let ctx: ServerContext

    /// How long the global switches and rules may be served from memory.
    static let cacheTTL: TimeInterval = 5

    // MARK: Facts

    func businessFacts(principal: BusinessPrincipal) async throws -> BusinessPolicyFacts {
        let business = try await BusinessRecord.find(principal.businessId.uuid, on: db)
        let entitlements = try await EntitlementService(db: db, ctx: ctx).snapshot(businessId: principal.businessId.uuid)
        var disabled: [Capability: String] = [:]
        var rules: [PolicyRule] = []
        var unavailable = false
        do {
            let global = try await ctx.policyCache.global(now: ctx.now, ttl: Self.cacheTTL) { try await loadGlobalState() }
            disabled = global.disabled
            rules = global.rules
            let own = try await CapabilitySwitchRecord.query(on: db).filter(\.$scope == principal.businessId.uuid.uuidString.lowercased())
                .filter(\.$disabled == true).all()
            for row in own { disabled[Capability(rawValue: row.capability)] = row.reason }
        } catch {
            // The switch table cannot be read: the engine fails closed for sensitive capabilities.
            unavailable = true
            ctx.logger.error("policy state unavailable", metadata: ["type": "\(type(of: error))"])
        }
        return BusinessPolicyFacts(active: business?.isVerified == true, tiers: entitlements.tiers, entitlements: entitlements.capabilities,
                                   keyScopes: principal.capabilities, keyEnvironment: principal.livemode ? .live : .test,
                                   disabled: disabled, switchesUnavailable: unavailable, rules: rules)
    }

    private func loadGlobalState() async throws -> PolicyStateCache.Global {
        let switches = try await CapabilitySwitchRecord.query(on: db).filter(\.$scope == CapabilitySwitchRecord.globalScope)
            .filter(\.$disabled == true).all()
        let rules = try await PolicyRuleRecord.query(on: db).filter(\.$active == true).all().compactMap(\.rule)
        return PolicyStateCache.Global(disabled: Dictionary(switches.map { (Capability(rawValue: $0.capability), $0.reason) }, uniquingKeysWith: { a, _ in a }),
                                       rules: rules, loadedAt: ctx.now)
    }

    /// The subject's facts for the interaction path: the relationship, the purpose-scoped consent and the authenticator evidence.
    func subjectFacts(relationship: RelationshipRecord, capability: Capability, interactionPurpose: InteractionPurpose?,
                      receipt: DisclosureReceipt? = nil) async throws -> SubjectPolicyFacts {
        let definition = capability.definition
        var consent: Bool?
        if definition?.consent.mode == .relationshipPurpose, let interactionPurpose {
            consent = try await ConsentService(db: db, ctx: ctx).permits(purpose: interactionPurpose, relationshipId: relationship.id!)
        }
        var evidence: [EvidenceHolding] = []
        if definition?.requiredEvidence == .registeredAuthenticator {
            let consumer = try await ConsumerRecord.find(relationship.consumerId, on: db)
            if consumer?.isSandbox == true {
                // A sandbox consumer stands for a person with an authenticator; test mode never reaches a real one.
                evidence.append(EvidenceHolding(kind: .registeredAuthenticator, verifiedAt: relationship.connectedAt))
            } else {
                let now = ctx.now
                let devices = try await DeviceRecord.query(on: db).filter(\.$consumerId == relationship.consumerId).filter(\.$revokedAt == nil).all()
                if let first = devices.filter({ !$0.isExpired(at: now) }).map(\.createdAt).min() {
                    evidence.append(EvidenceHolding(kind: .registeredAuthenticator, verifiedAt: first))
                }
            }
        }
        return SubjectPolicyFacts(relationshipActive: relationship.isActive, purposeConsentGranted: consent, evidence: evidence, receipt: receipt)
    }

    // MARK: Decide

    /// Evaluates and audits; never throws for a denial. Denials are always audited. An allowed decision is audited when the
    /// capability's definition says so and `auditAllowed` is true (the `.business` pre-check passes false: the final call audits).
    func decide(_ input: PolicyInput, principal: BusinessPrincipal, stage: PolicyEngine.Stage = .business, subject: SubjectPolicyFacts? = nil,
                auditAllowed: Bool = true) async throws -> PolicyDecision {
        let facts = try await businessFacts(principal: principal)
        let request = PolicyRequest(capability: input.capability, businessId: principal.businessId, environment: principal.livemode ? .live : .test,
                                    subjectRef: input.subjectRef, parameters: input.parameters, purpose: input.purpose,
                                    jurisdiction: input.jurisdiction, requestId: input.requestId, now: ctx.now)
        let decision = PolicyEngine.evaluate(request, business: facts, subject: subject, stage: stage)
        if auditAllowed || !decision.allowed { try await record(decision, input: input, principal: principal) }
        return decision
    }

    /// Persists the decision's audit record: always for a denial (a failed write must not turn the denial into a 500), and for an
    /// allowed decision when the capability's definition says so (that write is not best-effort: no unaudited sensitive allow).
    func record(_ decision: PolicyDecision, input: PolicyInput, principal: BusinessPrincipal) async throws {
        let actor = AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased())
        if !decision.allowed {
            _ = try? await AuditService(db: db, ctx: ctx).record(decision.audit.action, outcome: decision.audit.outcome, actor: actor,
                businessId: principal.businessId, subjectType: "capability", subjectId: input.capability.rawValue, metadata: decision.audit.metadata)
        } else if input.capability.definition?.auditsAllowedDecisions == true {
            _ = try await AuditService(db: db, ctx: ctx).record(decision.audit.action, outcome: decision.audit.outcome, actor: actor,
                businessId: principal.businessId, subjectType: "capability", subjectId: input.capability.rawValue, metadata: decision.audit.metadata)
        }
    }

    /// `decide`, mapping a denial to the API error.
    @discardableResult
    func enforce(_ input: PolicyInput, principal: BusinessPrincipal, stage: PolicyEngine.Stage = .business, subject: SubjectPolicyFacts? = nil,
                 auditAllowed: Bool = true) async throws -> PolicyDecision {
        let decision = try await decide(input, principal: principal, stage: stage, subject: subject, auditAllowed: auditAllowed)
        if let error = decision.apiError { throw error }
        return decision
    }
}

extension PolicyDecision {
    /// The HTTP error for a denial (`nil` when allowed). Messages name the capability only; they never reveal other tenants, entitlements
    /// of other businesses, or how the subject's consent or evidence is stored.
    var apiError: APIError? {
        guard let reason = primaryReason else { return nil }
        let capabilityName = capability.rawValue
        var details = ["capability": capabilityName, "reason": reason.rawValue]
        switch reason {
        case .businessInactive:
            return APIError(.forbidden, .forbidden, "This business is not currently active.")
        case .insufficientScope:
            return APIError(.forbidden, .insufficientScope, "This API key does not carry the capability this request needs.", details: details)
        case .notEntitled, .tierRequired:
            return APIError(.forbidden, .notEntitled, "Your business is not entitled to this capability.", details: details)
        case .capabilityDisabled:
            return APIError(.forbidden, .capabilityDisabled, "This capability is temporarily unavailable.", details: details)
        case .policyUnavailable:
            return APIError(.serviceUnavailable, .unavailable, "This capability is temporarily unavailable.", details: details)
        case .environmentMismatch:
            return APIError(.forbidden, .forbidden, "This API key's environment does not match the request.")
        case .consentRequired:
            // Same shape the interaction path always returned.
            if let purpose = self.details["purpose"], self.details["receipt"] == nil {
                return APIError(.forbidden, .consentRequired, "The consumer has not consented to this kind of message.", details: ["purpose": purpose])
            }
            if let receipt = self.details["receipt"] { details["receipt"] = receipt }
            return APIError(.forbidden, .consentRequired, "The consumer has not consented.", details: details)
        case .invalidParameters:
            return APIError.validation("The request parameters are invalid.", details: self.details.filter { $0.key.hasPrefix("parameter") })
        case .purposeRequired:
            return APIError.validation("A valid purpose is required.", details: ["purpose": "required"])
        case .jurisdictionBlocked, .evidenceInsufficient, .unknownCapability:
            return APIError(.forbidden, .policyDenied, "This request is not permitted.", details: details)
        }
    }
}
