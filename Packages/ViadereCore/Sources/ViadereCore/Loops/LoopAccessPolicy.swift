import Foundation

/// The customer's Loop consents (spec A6.2, plan WP-3.5): a global enablement and a separate authorization per business, each recorded
/// with the version of the counsel-approved text it was given for. Loops are **off by default**: no rows means no access.
public struct LoopConsentState: Sendable, Hashable {
    public var globalTextVersion: Int?
    public var globalRevoked: Bool
    public var businessTextVersion: Int?
    public var businessRevoked: Bool

    public init(globalTextVersion: Int? = nil, globalRevoked: Bool = false, businessTextVersion: Int? = nil, businessRevoked: Bool = false) {
        self.globalTextVersion = globalTextVersion
        self.globalRevoked = globalRevoked
        self.businessTextVersion = businessTextVersion
        self.businessRevoked = businessRevoked
    }

    public static let none = LoopConsentState()
}

public enum LoopPublicationStatus: String, Sendable, Codable, CaseIterable, Hashable {
    case active, suspended, revoked, retired
}

/// Everything the server knows when a customer starts, resumes or acts on a Loop instance. All values come from server records.
public struct LoopAccessInput: Sendable, Hashable {
    public var consent: LoopConsentState
    /// Current version of the consent text; a bump forces re-consent.
    public var currentConsentTextVersion: Int
    public var relationshipActive: Bool
    public var businessStatus: VerificationStatus
    public var businessCategory: BusinessCategory
    public var publicationStatus: LoopPublicationStatus
    /// `capability_switches` for `loop.*` at business scope, and the platform `loops` flag.
    public var businessLoopsSwitchedOff: Bool
    public var platformLoopsOff: Bool
    /// The instance (resume/act) has expired.
    public var instanceExpired: Bool
    /// The instance belongs to this customer and business (cross-business or other-customer ids are refused as not found).
    public var instanceOwnedByCaller: Bool

    public init(consent: LoopConsentState, currentConsentTextVersion: Int, relationshipActive: Bool, businessStatus: VerificationStatus,
                businessCategory: BusinessCategory, publicationStatus: LoopPublicationStatus, businessLoopsSwitchedOff: Bool = false,
                platformLoopsOff: Bool = false, instanceExpired: Bool = false, instanceOwnedByCaller: Bool = true) {
        self.consent = consent
        self.currentConsentTextVersion = currentConsentTextVersion
        self.relationshipActive = relationshipActive
        self.businessStatus = businessStatus
        self.businessCategory = businessCategory
        self.publicationStatus = publicationStatus
        self.businessLoopsSwitchedOff = businessLoopsSwitchedOff
        self.platformLoopsOff = platformLoopsOff
        self.instanceExpired = instanceExpired
        self.instanceOwnedByCaller = instanceOwnedByCaller
    }
}

public enum LoopAccessOperation: String, Sendable, Codable, CaseIterable, Hashable {
    case createInstance = "create_instance"
    case resume
    case act
}

public enum LoopAccessDenial: String, Sendable, Codable, CaseIterable, Hashable {
    case notFound = "not_found"
    case platformOff = "platform_off"
    case relationshipInactive = "relationship_inactive"
    case businessNotVerified = "business_not_verified"
    case categoryRefused = "category_refused"
    case globalConsentMissing = "global_consent_missing"
    case businessConsentMissing = "business_consent_missing"
    case consentOutdated = "consent_outdated"
    case businessSwitchedOff = "business_switched_off"
    case publicationNotActive = "publication_not_active"
    case expired
}

public enum LoopAccessDecision: Sendable, Hashable {
    case allowed
    case denied(LoopAccessDenial)
}

/// Whether a Loop operation may proceed (plan section 4.5 step 2, in that order; every denial is audited by the caller). There is no
/// input combination that reaches `.allowed` without both consents at the current text version (D3.T6 at model level).
public enum LoopAccessPolicy {
    public static func evaluate(_ operation: LoopAccessOperation, _ input: LoopAccessInput) -> LoopAccessDecision {
        if operation != .createInstance && !input.instanceOwnedByCaller { return .denied(.notFound) }
        if input.platformLoopsOff { return .denied(.platformOff) }
        guard input.relationshipActive else { return .denied(.relationshipInactive) }
        guard input.businessStatus == .verified else { return .denied(.businessNotVerified) }
        if case .refused = LoopCategoryPolicy.loops(input.businessCategory) { return .denied(.categoryRefused) }
        guard let global = input.consent.globalTextVersion, !input.consent.globalRevoked else { return .denied(.globalConsentMissing) }
        guard let business = input.consent.businessTextVersion, !input.consent.businessRevoked else { return .denied(.businessConsentMissing) }
        guard global >= input.currentConsentTextVersion, business >= input.currentConsentTextVersion else { return .denied(.consentOutdated) }
        if input.businessLoopsSwitchedOff { return .denied(.businessSwitchedOff) }
        guard input.publicationStatus == .active else { return .denied(.publicationNotActive) }
        if operation != .createInstance && input.instanceExpired { return .denied(.expired) }
        return .allowed
    }
}
