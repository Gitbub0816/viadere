import Foundation

/// Business verification lifecycle.
public enum VerificationStatus: String, Codable, Sendable, CaseIterable {
    case pending, verified, suspended, revoked

    public init(from decoder: any Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        // Unknown statuses are treated as not verified.
        self = VerificationStatus(rawValue: raw) ?? .suspended
    }
}

/// Directory category (open set; unknown values are preserved).
public struct BusinessCategory: RawRepresentable, Hashable, Sendable, Codable {
    public let rawValue: String
    public init(rawValue: String) { self.rawValue = rawValue }

    public static let retail = BusinessCategory(rawValue: "retail")
    public static let banking = BusinessCategory(rawValue: "banking")
    public static let airline = BusinessCategory(rawValue: "airline")
    public static let hospitality = BusinessCategory(rawValue: "hospitality")
    public static let foodAndDrink = BusinessCategory(rawValue: "food_and_drink")
    public static let healthcare = BusinessCategory(rawValue: "healthcare")
    public static let utilities = BusinessCategory(rawValue: "utilities")
    public static let telecom = BusinessCategory(rawValue: "telecom")
    public static let government = BusinessCategory(rawValue: "government")
    public static let other = BusinessCategory(rawValue: "other")
}

/// Compact, verified business identity used in directory results, menus and attributions.
public struct BusinessSummary: Codable, Sendable, Hashable, Identifiable {
    public var id: BusinessID
    public var displayName: String
    public var handle: BusinessHandle?
    public var code: BusinessCode
    public var verificationStatus: VerificationStatus

    public init(id: BusinessID, displayName: String, handle: BusinessHandle?, code: BusinessCode,
                verificationStatus: VerificationStatus) {
        self.id = id
        self.displayName = displayName
        self.handle = handle
        self.code = code
        self.verificationStatus = verificationStatus
    }

    /// Only verified businesses may appear in discovery, menus, or receive routed messages.
    public var isVerified: Bool { verificationStatus == .verified }
}

/// Full public business profile.
public struct BusinessProfile: Codable, Sendable, Hashable, Identifiable {
    public var id: BusinessID
    public var displayName: String
    public var legalName: String?
    public var handle: BusinessHandle?
    public var code: BusinessCode
    public var verificationStatus: VerificationStatus
    public var verifiedAt: Date?
    public var category: BusinessCategory
    public var brandColor: BrandColor?
    public var logoURL: URL?
    public var websiteURL: URL?
    public var supportedPurposes: [InteractionPurpose]

    public init(id: BusinessID, displayName: String, legalName: String? = nil, handle: BusinessHandle?, code: BusinessCode,
                verificationStatus: VerificationStatus, verifiedAt: Date? = nil, category: BusinessCategory = .other,
                brandColor: BrandColor? = nil, logoURL: URL? = nil, websiteURL: URL? = nil,
                supportedPurposes: [InteractionPurpose] = InteractionPurpose.allCases) {
        self.id = id
        self.displayName = displayName
        self.legalName = legalName
        self.handle = handle
        self.code = code
        self.verificationStatus = verificationStatus
        self.verifiedAt = verifiedAt
        self.category = category
        self.brandColor = brandColor
        self.logoURL = logoURL
        self.websiteURL = websiteURL
        self.supportedPurposes = supportedPurposes
    }

    public var summary: BusinessSummary {
        BusinessSummary(id: id, displayName: displayName, handle: handle, code: code, verificationStatus: verificationStatus)
    }

    /// The canonical connect link for this business.
    public var connectLink: ConnectLink { ConnectLink(code: code) }
}

/// How a relationship was initiated.
public enum ConnectSource: String, Codable, Sendable, CaseIterable {
    case handle, code, qr, button, link, search, sms, appClip
}

/// A consumer ↔ business relationship.
public struct Relationship: Codable, Sendable, Hashable, Identifiable {
    public enum Status: String, Codable, Sendable { case active, disconnected }

    public var id: RelationshipID
    public var consumerId: ConsumerID
    public var business: BusinessSummary
    public var status: Status
    public var source: ConnectSource
    public var connectedAt: Date
    public var disconnectedAt: Date?

    public init(id: RelationshipID, consumerId: ConsumerID, business: BusinessSummary, status: Status, source: ConnectSource,
                connectedAt: Date, disconnectedAt: Date? = nil) {
        self.id = id
        self.consumerId = consumerId
        self.business = business
        self.status = status
        self.source = source
        self.connectedAt = connectedAt
        self.disconnectedAt = disconnectedAt
    }
}

/// Where a consent change came from.
public enum ConsentSource: String, Codable, Sendable, CaseIterable {
    case app, web, sms, smsKeyword, businessAPI, system
}

/// A purpose-scoped, versioned consent record. Each change creates a new version; history is retained.
public struct ConsentGrant: Codable, Sendable, Hashable, Identifiable {
    public var id: ConsentGrantID
    public var consumerId: ConsumerID
    public var businessId: BusinessID
    public var relationshipId: RelationshipID
    public var purpose: InteractionPurpose
    public var granted: Bool
    /// Monotonic version of this (relationship, purpose) record.
    public var version: Int
    /// Version of the consent language/policy shown to the consumer.
    public var policyVersion: String
    public var source: ConsentSource
    public var channels: [Channel]
    public var createdAt: Date
    public var updatedAt: Date

    public init(id: ConsentGrantID, consumerId: ConsumerID, businessId: BusinessID, relationshipId: RelationshipID,
                purpose: InteractionPurpose, granted: Bool, version: Int, policyVersion: String, source: ConsentSource,
                channels: [Channel], createdAt: Date, updatedAt: Date) {
        self.id = id
        self.consumerId = consumerId
        self.businessId = businessId
        self.relationshipId = relationshipId
        self.purpose = purpose
        self.granted = granted
        self.version = version
        self.policyVersion = policyVersion
        self.source = source
        self.channels = channels
        self.createdAt = createdAt
        self.updatedAt = updatedAt
    }
}

/// Consent evaluation helpers.
public enum ConsentPolicy {
    /// Whether an interaction with `purpose` may be delivered given the consumer's grants.
    ///
    /// - Non-revocable purposes (`security`, `accountService`) are always permitted for an active
    ///   relationship; revoking marketing never disables them (spec §19 #10).
    /// - Otherwise the latest-version grant for *that purpose only* decides; with no grant the
    ///   purpose default applies (`InteractionPurpose.isGrantedByDefault`: marketing and rewards are opt-in).
    public static func permits(purpose: InteractionPurpose, grants: [ConsentGrant]) -> Bool {
        if !purpose.isRevocable { return true }
        let latest = grants.filter { $0.purpose == purpose }.max { $0.version < $1.version }
        return latest?.granted ?? purpose.isGrantedByDefault
    }
}
