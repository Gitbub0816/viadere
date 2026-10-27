import Foundation

/// Why the policy engine denied a request. Machine codes; stable.
public enum PolicyDenialReason: String, Sendable, Codable, CaseIterable, Hashable {
    /// The capability is not in the catalog (or is a forward-compatible `unknown`): never allowed.
    case unknownCapability = "unknown_capability"
    case businessInactive = "business_inactive"
    /// The API key does not carry the capability (SEC-API-003).
    case insufficientScope = "insufficient_scope"
    /// The business holds no (current) entitlement for the capability. A revoked entitlement removes the capability from every key.
    case notEntitled = "not_entitled"
    /// The business does not hold the risk tier the capability requires.
    case tierRequired = "tier_required"
    /// The key's environment (live/test) differs from the environment of the request.
    case environmentMismatch = "environment_mismatch"
    /// The capability is switched off (operator kill switch, globally or for this business).
    case capabilityDisabled = "capability_disabled"
    /// A sensitive capability while the switch table cannot be read (fail closed).
    case policyUnavailable = "policy_unavailable"
    case invalidParameters = "invalid_parameters"
    case purposeRequired = "purpose_required"
    /// A law/policy rule blocks the capability in this jurisdiction.
    case jurisdictionBlocked = "jurisdiction_blocked"
    case consentRequired = "consent_required"
    case evidenceInsufficient = "evidence_insufficient"
}

public enum PolicyEnvironment: String, Sendable, Codable, Hashable { case live, test }

/// A configurable law/policy rule (spec §6.4 "law/policy"). Stored by the server, edited by operators, always audited.
public struct PolicyRule: Sendable, Codable, Hashable, Identifiable {
    public enum Kind: String, Sendable, Codable, Hashable {
        /// The capability is blocked in the listed jurisdictions.
        case jurisdictionBlock = "jurisdiction_block"
        /// The capability is allowed **only** in the listed jurisdictions; an unknown jurisdiction is denied (fail closed).
        case jurisdictionAllowOnly = "jurisdiction_allow_only"
    }

    public var id: UUID
    public var capability: Capability
    public var kind: Kind
    /// Upper-case ISO 3166 region codes (or `US-CA`-style subdivisions).
    public var jurisdictions: [String]
    public var reason: String

    public init(id: UUID = UUID(), capability: Capability, kind: Kind, jurisdictions: [String], reason: String) {
        self.id = id
        self.capability = capability
        self.kind = kind
        self.jurisdictions = jurisdictions.map { $0.uppercased() }
        self.reason = reason
    }

    /// Whether this rule denies a request for `jurisdiction`.
    func blocks(_ jurisdiction: String?) -> Bool {
        let code = jurisdiction?.uppercased()
        switch kind {
        case .jurisdictionBlock:
            guard let code else { return false }
            return jurisdictions.contains(code) || jurisdictions.contains(String(code.prefix { $0 != "-" }))
        case .jurisdictionAllowOnly:
            guard let code else { return true }
            return !(jurisdictions.contains(code) || jurisdictions.contains(String(code.prefix { $0 != "-" })))
        }
    }
}

/// Evidence the **subject** holds (a verification result), with its validity.
public struct EvidenceHolding: Sendable, Codable, Hashable {
    public var kind: RequiredEvidence
    public var verifiedAt: Date
    public var expiresAt: Date?
    public init(kind: RequiredEvidence, verifiedAt: Date, expiresAt: Date? = nil) {
        self.kind = kind
        self.verifiedAt = verifiedAt
        self.expiresAt = expiresAt
    }
}

/// What the request is. Built by the endpoint handler, never copied from a client-supplied field it did not validate.
public struct PolicyRequest: Sendable {
    public var capability: Capability
    public var businessId: BusinessID
    /// The environment the request operates in (the relationship's, not the key's).
    public var environment: PolicyEnvironment
    public var subjectRef: SubjectRef?
    /// Capability parameters as received. `nil` means the endpoint validates its own payload (the interaction path today);
    /// endpoints that take catalog parameters (`age.minimum`, ...) MUST pass them.
    public var parameters: [String: JSONValue]?
    /// The disclosure purpose (snake_case), required by capabilities with `requiresPurpose`.
    public var purpose: String?
    /// ISO 3166 region the rules are evaluated for, when the endpoint knows it.
    public var jurisdiction: String?
    /// The identifier of this request (verification request id): what a per-request receipt is bound to.
    public var requestId: String?
    public var now: Date

    public init(capability: Capability, businessId: BusinessID, environment: PolicyEnvironment, subjectRef: SubjectRef? = nil,
                parameters: [String: JSONValue]? = nil, purpose: String? = nil, jurisdiction: String? = nil, requestId: String? = nil,
                now: Date) {
        self.capability = capability
        self.businessId = businessId
        self.environment = environment
        self.subjectRef = subjectRef
        self.parameters = parameters
        self.purpose = purpose
        self.jurisdiction = jurisdiction
        self.requestId = requestId
        self.now = now
    }
}

/// Facts about the business and its credential (loaded fresh on every request: entitlements are a ceiling **at use time**).
public struct BusinessPolicyFacts: Sendable {
    public var active: Bool
    public var tiers: Set<BusinessRiskTier>
    public var entitlements: Set<Capability>
    public var keyScopes: Set<Capability>
    public var keyEnvironment: PolicyEnvironment
    /// Capabilities switched off for this business (globally or specifically), with the operator's reason.
    public var disabled: [Capability: String]
    /// The switch table could not be read: sensitive capabilities fail closed.
    public var switchesUnavailable: Bool
    public var rules: [PolicyRule]

    public init(active: Bool, tiers: Set<BusinessRiskTier>, entitlements: Set<Capability>, keyScopes: Set<Capability>,
                keyEnvironment: PolicyEnvironment, disabled: [Capability: String] = [:], switchesUnavailable: Bool = false,
                rules: [PolicyRule] = []) {
        self.active = active
        self.tiers = tiers
        self.entitlements = entitlements
        self.keyScopes = keyScopes
        self.keyEnvironment = keyEnvironment
        self.disabled = disabled
        self.switchesUnavailable = switchesUnavailable
        self.rules = rules
    }
}

/// Facts about the subject: the customer's consent and the evidence held about them.
public struct SubjectPolicyFacts: Sendable {
    public var relationshipActive: Bool
    /// Whether the relationship's purpose-scoped consent permits the request's purpose (`nil` when not evaluated).
    public var purposeConsentGranted: Bool?
    public var evidence: [EvidenceHolding]
    /// The per-request receipt presented for this request, if any.
    public var receipt: DisclosureReceipt?

    public init(relationshipActive: Bool, purposeConsentGranted: Bool? = nil, evidence: [EvidenceHolding] = [], receipt: DisclosureReceipt? = nil) {
        self.relationshipActive = relationshipActive
        self.purposeConsentGranted = purposeConsentGranted
        self.evidence = evidence
        self.receipt = receipt
    }
}

/// The audit record every decision produces. The server persists it (always for a denial; for an allowed decision when the
/// capability's definition says so). Metadata never carries personal data.
public struct PolicyAuditRecord: Sendable, Hashable {
    public var action: String
    public var outcome: AuditEvent.Outcome
    public var metadata: [String: String]
}

/// `PolicyDecision = entitlement ∩ key scope ∩ customer consent ∩ evidence sufficiency ∩ law/policy`.
public struct PolicyDecision: Sendable {
    public var capability: Capability
    public var allowed: Bool
    /// Every check that failed, in evaluation order. Empty when allowed.
    public var reasons: [PolicyDenialReason]
    /// Parameter name to issue code when `invalid_parameters`; `purpose` when `consent_required` for a relationship purpose, etc.
    public var details: [String: String]
    public var audit: PolicyAuditRecord

    /// The reason reported to the caller: the first failed check.
    public var primaryReason: PolicyDenialReason? { reasons.first }
}

/// The pure policy evaluator. No I/O: the server loads the facts (fresh on every request) and persists the audit record.
public enum PolicyEngine {
    public enum Stage: Sendable {
        /// Everything that depends only on the business, its key, the switches, the parameters and the law/policy rules.
        case business
        /// Business-level checks, then the subject's consent and evidence.
        case full
    }

    /// Valid disclosure purpose: snake_case, 3 to 48 characters.
    public static func isValidPurpose(_ purpose: String) -> Bool {
        guard (3...48).contains(purpose.count), let first = purpose.unicodeScalars.first, ("a"..."z").contains(first) else { return false }
        return purpose.unicodeScalars.allSatisfy { ("a"..."z").contains($0) || ("0"..."9").contains($0) || $0 == "_" }
    }

    public static func evaluate(_ request: PolicyRequest, business: BusinessPolicyFacts, subject: SubjectPolicyFacts? = nil,
                                stage: Stage = .full) -> PolicyDecision {
        guard let definition = request.capability.definition else {
            return decision(request, nil, [.unknownCapability], [:], receiptId: nil)
        }
        var reasons: [PolicyDenialReason] = []
        var details: [String: String] = [:]

        if !business.active { reasons.append(.businessInactive) }
        // 1. Key scope, then the entitlement ceiling (both must hold: a key can never exceed what the business is entitled to now).
        if !business.keyScopes.contains(request.capability) { reasons.append(.insufficientScope) }
        if !business.entitlements.contains(request.capability) { reasons.append(.notEntitled) }
        if !business.tiers.contains(definition.minimumTier) { reasons.append(.tierRequired) }
        if request.environment != business.keyEnvironment { reasons.append(.environmentMismatch) }
        // 2. Operator switches (fail closed for sensitive capabilities when the table is unreadable).
        if business.disabled[request.capability] != nil { reasons.append(.capabilityDisabled) }
        if business.switchesUnavailable && definition.sensitivity >= .high { reasons.append(.policyUnavailable) }
        // 3. Typed parameters and purpose.
        if let parameters = request.parameters {
            let issues = definition.parameterIssues(parameters)
            if !issues.isEmpty {
                reasons.append(.invalidParameters)
                for (name, code) in issues { details["parameter.\(name)"] = code }
            }
        } else if !definition.parameters.isEmpty && !Capability.interactionPath.contains(request.capability) {
            // Only the interaction path (whose payload `InteractionValidation` checks) may omit parameters; every other capability
            // with inputs is evaluated against them, never without.
            reasons.append(.invalidParameters)
            details["parameters"] = "missing"
        }
        if definition.requiresPurpose {
            if let purpose = request.purpose, isValidPurpose(purpose) { details["purpose"] = purpose } else { reasons.append(.purposeRequired) }
        }
        // 4. Law / policy rules.
        for rule in business.rules where rule.capability == request.capability && rule.blocks(request.jurisdiction) {
            reasons.append(.jurisdictionBlocked)
            details["rule"] = rule.id.uuidString.lowercased()
            break
        }
        // 5. The subject: consent and evidence. Only when the business-level checks passed (a credential that may not use the
        //    capability learns nothing about the person, and the server does not even load the subject's data).
        if stage == .full && reasons.isEmpty {
            reasons.append(contentsOf: subjectReasons(request, definition, subject, &details))
        }
        return decision(request, definition, reasons, details, receiptId: subject?.receipt?.id)
    }

    private static func subjectReasons(_ request: PolicyRequest, _ definition: CapabilityDefinition, _ subject: SubjectPolicyFacts?,
                                       _ details: inout [String: String]) -> [PolicyDenialReason] {
        var reasons: [PolicyDenialReason] = []
        guard let subject else {
            // The subject's facts were not supplied: nothing about consent or evidence can be assumed.
            return definition.consent.mode == .none && definition.requiredEvidence == .none ? [] : [.consentRequired]
        }
        switch definition.consent.mode {
        case .none: break
        case .activeRelationship:
            if !subject.relationshipActive { reasons.append(.consentRequired) }
        case .relationshipPurpose:
            if !subject.relationshipActive || subject.purposeConsentGranted != true {
                reasons.append(.consentRequired)
                if let purpose = request.purpose { details["purpose"] = purpose }
            }
        case .perRequestReceipt:
            // No blanket consent: only a receipt for exactly this request authorizes the disclosure.
            if !subject.relationshipActive { reasons.append(.consentRequired) }
            if let receipt = subject.receipt {
                if let problem = receipt.problem(businessId: request.businessId, subjectRef: request.subjectRef, capability: request.capability,
                                                purpose: request.purpose, requestId: request.requestId, now: request.now) {
                    reasons.append(.consentRequired)
                    details["receipt"] = problem
                }
            } else {
                reasons.append(.consentRequired)
                details["receipt"] = "missing"
            }
        }
        if definition.requiredEvidence != .none {
            let sufficient = subject.evidence.contains { holding in
                holding.kind == definition.requiredEvidence && holding.verifiedAt <= request.now && (holding.expiresAt ?? .distantFuture) > request.now
            }
            if !sufficient { reasons.append(.evidenceInsufficient) }
        }
        return reasons
    }

    private static func decision(_ request: PolicyRequest, _ definition: CapabilityDefinition?, _ reasons: [PolicyDenialReason],
                                 _ details: [String: String], receiptId: UUID?) -> PolicyDecision {
        let allowed = reasons.isEmpty
        var metadata: [String: String] = ["capability": request.capability.rawValue, "environment": request.environment.rawValue]
        if !allowed {
            metadata["reason"] = reasons[0].rawValue
            metadata["reasons"] = reasons.map(\.rawValue).joined(separator: " ")
        }
        let wanted = Set(definition?.auditFields ?? [])
        if wanted.contains("subject_ref"), let ref = request.subjectRef { metadata["subject_ref"] = ref.rawValue }
        if wanted.contains("purpose"), let purpose = request.purpose { metadata["purpose"] = purpose }
        if wanted.contains("request_id"), let id = request.requestId { metadata["request_id"] = id }
        if wanted.contains("years"), case .integer(let years)? = request.parameters?["years"] { metadata["years"] = String(years) }
        if wanted.contains("receipt_id") {
            if let receiptId { metadata["receipt_id"] = receiptId.uuidString.lowercased() }
            if let problem = details["receipt"] { metadata["receipt_problem"] = problem }
        }
        let audit = PolicyAuditRecord(action: allowed ? "policy.allowed" : "policy.denied", outcome: allowed ? .success : .denied, metadata: metadata)
        return PolicyDecision(capability: request.capability, allowed: allowed, reasons: reasons, details: details, audit: audit)
    }
}
