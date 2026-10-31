import Foundation

extension IDTag {
    public enum ProfileRequest {}
    public enum ProfileAttempt {}
    public enum ProfileReceipt {}
}

public typealias ProfileRequestID = TypedID<IDTag.ProfileRequest>
public typealias ProfileAttemptID = TypedID<IDTag.ProfileAttempt>
public typealias ProfileReceiptID = TypedID<IDTag.ProfileReceipt>

// MARK: - Values

/// A postal address (mailing or service). `country` is ISO 3166-1 alpha-2.
public struct ProfileAddress: Codable, Sendable, Hashable {
    public var line1: String
    public var line2: String?
    public var locality: String
    public var region: String?
    public var postalCode: String?
    public var country: String

    public init(line1: String, line2: String? = nil, locality: String, region: String? = nil, postalCode: String? = nil, country: String) {
        self.line1 = line1
        self.line2 = line2
        self.locality = locality
        self.region = region
        self.postalCode = postalCode
        self.country = country
    }

    /// One line for display.
    public var singleLine: String {
        [line1, line2, locality, region, postalCode, country].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: ", ")
    }
}

/// A profile value on the wire: a string, an address object or (derived fields only) a boolean.
public enum ProfileValue: Codable, Sendable, Hashable {
    case text(String)
    case address(ProfileAddress)
    case boolean(Bool)

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        if let text = try? container.decode(String.self) { self = .text(text); return }
        if let flag = try? container.decode(Bool.self) { self = .boolean(flag); return }
        self = .address(try container.decode(ProfileAddress.self))
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .text(let text): try container.encode(text)
        case .address(let address): try container.encode(address)
        case .boolean(let flag): try container.encode(flag)
        }
    }

    /// Text for display.
    public var displayText: String {
        switch self {
        case .text(let text): text
        case .address(let address): address.singleLine
        case .boolean(let flag): flag ? "Yes" : "No"
        }
    }
}

/// Addresses one stored value: the field key and, for multi-entry fields, the entry label (airline code, program name).
public struct ProfileFieldRef: Codable, Sendable, Hashable {
    public var key: String
    public var entry: String?
    public init(key: String, entry: String? = nil) {
        self.key = key
        self.entry = entry
    }
}

/// A fact established with an ID through Verify (Apple Wallet ID or a document check), kept because the customer chose to keep it. Never a
/// document number, image, or the document's name or birth date: only the boolean fact and how and when it was established.
public enum ProfileVerifiedFactKind: String, Codable, Sendable, Hashable, CaseIterable {
    /// A valid ID was presented.
    case identity
    /// The first and last name on the profile match the ID.
    case legalName = "legal_name"
    case ageOver18 = "age_over_18"
    case ageOver21 = "age_over_21"

    /// The read-only catalog field that exposes the fact to a business with a grant.
    public var fieldKey: String { "verified." + rawValue }

    public var title: String {
        switch self {
        case .identity: "Verified ID"
        case .legalName: "Verified legal name"
        case .ageOver18: "Verified over 18"
        case .ageOver21: "Verified over 21"
        }
    }
}

/// Provenance of a verified fact (VER-007): method, when, the assurance string and the policy version. No personal data.
public struct ProfileVerifiedFact: Codable, Sendable, Hashable {
    public var fact: ProfileVerifiedFactKind
    public var method: VerificationMethod
    public var verifiedAt: Date
    /// `issuer_signed_credential_device_bound`, `document_and_biometric_match` or `sandbox_simulated`.
    public var assurance: String
    public var policyVersion: String

    public init(fact: ProfileVerifiedFactKind, method: VerificationMethod, verifiedAt: Date, assurance: String, policyVersion: String) {
        self.fact = fact
        self.method = method
        self.verifiedAt = verifiedAt
        self.assurance = assurance
        self.policyVersion = policyVersion
    }
}

/// One stored value as its owner sees it.
public struct ProfileFieldEntry: Codable, Sendable, Hashable {
    public var key: String
    public var entry: String?
    public var value: ProfileValue
    public var updatedAt: Date?

    public init(key: String, entry: String? = nil, value: ProfileValue, updatedAt: Date? = nil) {
        self.key = key
        self.entry = entry
        self.value = value
        self.updatedAt = updatedAt
    }

    public var ref: ProfileFieldRef { ProfileFieldRef(key: key, entry: entry) }
}

// MARK: - Customer

/// `GET /v1/profile`.
public struct CustomerProfile: Codable, Sendable, Hashable {
    /// What every connected business receives (`nil` when there is no name to derive it from and no custom one).
    public var publicName: String?
    /// The custom public name, when the customer set one.
    public var customPublicName: String?
    /// The default ("John D.") the customer would get without a custom name.
    public var derivedPublicName: String?
    public var fields: [ProfileFieldEntry]
    public var verified: [ProfileVerifiedFact]
    public var catalogVersion: Int

    public init(publicName: String?, customPublicName: String?, derivedPublicName: String?, fields: [ProfileFieldEntry], verified: [ProfileVerifiedFact],
                catalogVersion: Int = ProfileCatalog.version) {
        self.publicName = publicName
        self.customPublicName = customPublicName
        self.derivedPublicName = derivedPublicName
        self.fields = fields
        self.verified = verified
        self.catalogVersion = catalogVersion
    }

    public var isVerified: Bool { verified.contains { $0.fact == .identity } }
}

/// `PUT /v1/profile`: set and remove values, and choose the public name. Applied atomically; any invalid value refuses the whole update.
public struct ProfileUpdateRequest: Codable, Sendable, Hashable {
    /// Set a custom public name. Mutually exclusive with `useDerivedPublicName`.
    public var customPublicName: String?
    /// `true` drops the custom public name (the derived default is shared again).
    public var useDerivedPublicName: Bool?
    public var set: [ProfileFieldEntry]
    public var remove: [ProfileFieldRef]

    public init(customPublicName: String? = nil, useDerivedPublicName: Bool? = nil, set: [ProfileFieldEntry] = [], remove: [ProfileFieldRef] = []) {
        self.customPublicName = customPublicName
        self.useDerivedPublicName = useDerivedPublicName
        self.set = set
        self.remove = remove
    }

    public static let maxChanges = 60
}

/// One field of the per-business access page.
public struct ProfileAccessField: Codable, Sendable, Hashable {
    public var key: String
    /// Whether the business can see it now.
    public var granted: Bool
    public var grantedAt: Date?
    /// Whether the customer has a value (or, for derived fields, whether it can be computed) to share.
    public var hasValue: Bool

    public init(key: String, granted: Bool, grantedAt: Date?, hasValue: Bool) {
        self.key = key
        self.granted = granted
        self.grantedAt = grantedAt
        self.hasValue = hasValue
    }
}

/// `GET /v1/businesses/{businessId}/profile-access`: "What this business can see".
public struct ProfileAccessView: Codable, Sendable, Hashable {
    public var businessId: BusinessID
    public var businessName: String
    /// Always shared with a connected business.
    public var publicName: String?
    /// The categories Viadere allows this business to ask for. Fields outside them can never be shared with it.
    public var allowedCategories: [ProfileCategory]
    public var fields: [ProfileAccessField]

    public init(businessId: BusinessID, businessName: String, publicName: String?, allowedCategories: [ProfileCategory], fields: [ProfileAccessField]) {
        self.businessId = businessId
        self.businessName = businessName
        self.publicName = publicName
        self.allowedCategories = allowedCategories
        self.fields = fields
    }

    public var grantedKeys: [String] { fields.filter(\.granted).map(\.key) }
}

/// `PUT /v1/businesses/{businessId}/profile-access`: the complete set of field keys the business may see. An empty list revokes everything.
public struct ProfileAccessUpdate: Codable, Sendable, Hashable {
    public var grantedKeys: [String]
    public init(grantedKeys: [String]) { self.grantedKeys = grantedKeys }
}

/// Lifecycle of a business's profile request.
public enum ProfileRequestStatus: String, Codable, Sendable, Hashable {
    case pending, answered, declined, expired, cancelled
    case unknown

    public init(from decoder: any Decoder) throws {
        self = ProfileRequestStatus(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .unknown
    }
}

/// One requested field as the customer sees it.
public struct ProfileRequestedField: Codable, Sendable, Hashable {
    public var key: String
    public var hasValue: Bool
    public var alreadyGranted: Bool
    public init(key: String, hasValue: Bool, alreadyGranted: Bool) {
        self.key = key
        self.hasValue = hasValue
        self.alreadyGranted = alreadyGranted
    }
}

/// A business's request as the customer sees it (`GET /v1/profile/requests[/{id}]`). The purpose is the business's own words, validated as
/// display text on the way in and sanitized again by the app.
public struct ProfileRequestPrompt: Codable, Sendable, Hashable, Identifiable {
    public var id: ProfileRequestID
    public var business: BusinessSummary
    public var purpose: String
    public var fields: [ProfileRequestedField]
    public var status: ProfileRequestStatus
    public var approvedKeys: [String]?
    public var createdAt: Date
    public var expiresAt: Date

    public init(id: ProfileRequestID, business: BusinessSummary, purpose: String, fields: [ProfileRequestedField], status: ProfileRequestStatus,
                approvedKeys: [String]?, createdAt: Date, expiresAt: Date) {
        self.id = id
        self.business = business
        self.purpose = purpose
        self.fields = fields
        self.status = status
        self.approvedKeys = approvedKeys
        self.createdAt = createdAt
        self.expiresAt = expiresAt
    }

    public func isActionable(at now: Date) -> Bool { status == .pending && expiresAt > now }
}

/// `POST /v1/profile/requests/{id}/answer`: the fields approved (a subset of those requested; empty declines).
public struct ProfileRequestAnswer: Codable, Sendable, Hashable {
    public var approvedKeys: [String]
    public init(approvedKeys: [String]) { self.approvedKeys = approvedKeys }
}

/// What a disclosure receipt records.
public enum ProfileReceiptAction: String, Codable, Sendable, Hashable {
    case granted, revoked
    case unknown

    public init(from decoder: any Decoder) throws {
        self = ProfileReceiptAction(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .unknown
    }
}

/// The customer's disclosure receipt (`GET /v1/profile/receipts`): who, which fields (never values), why and when.
public struct ProfileDisclosureReceipt: Codable, Sendable, Hashable, Identifiable {
    public var id: ProfileReceiptID
    public var businessId: BusinessID
    public var businessName: String
    public var action: ProfileReceiptAction
    public var fieldKeys: [String]
    public var purpose: String?
    public var requestId: ProfileRequestID?
    public var createdAt: Date

    public init(id: ProfileReceiptID, businessId: BusinessID, businessName: String, action: ProfileReceiptAction, fieldKeys: [String], purpose: String?,
                requestId: ProfileRequestID?, createdAt: Date) {
        self.id = id
        self.businessId = businessId
        self.businessName = businessName
        self.action = action
        self.fieldKeys = fieldKeys
        self.purpose = purpose
        self.requestId = requestId
        self.createdAt = createdAt
    }
}

// MARK: - Verification (customer-initiated, reuses the Verify methods)

public enum ProfileVerificationMethod: String, Codable, Sendable, Hashable, CaseIterable {
    /// Apple Wallet ID (ISO 18013-5 mdoc), verified against the issuer's IACA.
    case wallet
    /// Didit document + liveness + face match.
    case document
}

/// `POST /v1/profile/verification`: the method and the facts the customer wants to keep (nothing else is stored).
public struct ProfileVerificationBegin: Codable, Sendable, Hashable {
    public var method: ProfileVerificationMethod
    public var keep: [ProfileVerifiedFactKind]
    public init(method: ProfileVerificationMethod, keep: [ProfileVerifiedFactKind]) {
        self.method = method
        self.keep = keep
    }
}

public struct ProfileVerificationStart: Codable, Sendable, Hashable {
    public var attemptId: ProfileAttemptID
    public var method: ProfileVerificationMethod
    /// Wallet: the single-use nonce (base64url) and merchant identifier for the `PKIdentityRequest`, and the ISO element identifiers to ask for.
    public var nonce: String?
    public var merchantIdentifier: String?
    public var requestedElements: [String]
    /// Document: the provider session token for the SDK.
    public var sessionToken: String?
    public var expiresAt: Date

    public init(attemptId: ProfileAttemptID, method: ProfileVerificationMethod, nonce: String?, merchantIdentifier: String?, requestedElements: [String],
                sessionToken: String?, expiresAt: Date) {
        self.attemptId = attemptId
        self.method = method
        self.nonce = nonce
        self.merchantIdentifier = merchantIdentifier
        self.requestedElements = requestedElements
        self.sessionToken = sessionToken
        self.expiresAt = expiresAt
    }
}

/// `POST /v1/profile/verification/{attemptId}/complete`. Wallet: the encrypted presentment envelope (base64url). Document: empty.
public struct ProfileVerificationComplete: Codable, Sendable, Hashable {
    public var envelope: String?
    public init(envelope: String? = nil) { self.envelope = envelope }
}

public enum ProfileVerificationStatus: String, Codable, Sendable, Hashable {
    case pending, verified
    case notVerified = "not_verified"
    case unknown

    public init(from decoder: any Decoder) throws {
        self = ProfileVerificationStatus(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .unknown
    }
}

public struct ProfileVerificationOutcome: Codable, Sendable, Hashable {
    public var status: ProfileVerificationStatus
    /// The facts now kept (those chosen and established).
    public var facts: [ProfileVerifiedFact]
    public init(status: ProfileVerificationStatus, facts: [ProfileVerifiedFact]) {
        self.status = status
        self.facts = facts
    }
}

/// `POST /v1/profile/verification/remove`: forget verified facts (an empty list forgets all).
public struct ProfileVerifiedFactsRemove: Codable, Sendable, Hashable {
    public var facts: [ProfileVerifiedFactKind]
    public init(facts: [ProfileVerifiedFactKind]) { self.facts = facts }
}

// MARK: - Business

/// `POST /v1/business/profile-requests` (scope `profiles:read`, `Idempotency-Key` header). Every key must be in a category Viadere allowed the
/// business; the purpose is shown to the customer verbatim and must pass the display-text rules.
public struct CreateProfileRequest: Codable, Sendable, Hashable {
    public var subjectRef: SubjectRef
    public var fieldKeys: [String]
    public var purpose: String
    /// 1 hour to 30 days (default 7 days).
    public var expiresInSeconds: Int?

    public init(subjectRef: SubjectRef, fieldKeys: [String], purpose: String, expiresInSeconds: Int? = nil) {
        self.subjectRef = subjectRef
        self.fieldKeys = fieldKeys
        self.purpose = purpose
        self.expiresInSeconds = expiresInSeconds
    }

    public static let maxPurposeCharacters = 200
    public static let maxFields = 20
    public static let defaultLifetime: TimeInterval = 7 * 86_400
    public static let lifetimeRange: ClosedRange<Int> = 3_600...(30 * 86_400)
}

/// A business's view of its own request.
public struct ProfileRequestResource: Codable, Sendable, Hashable {
    public var id: ProfileRequestID
    public var subjectRef: SubjectRef
    public var fieldKeys: [String]
    public var purpose: String
    public var status: ProfileRequestStatus
    /// Answered requests: the fields the customer approved (possibly fewer than asked, possibly none).
    public var approvedKeys: [String]?
    public var livemode: Bool
    public var createdAt: Date
    public var expiresAt: Date
    public var answeredAt: Date?

    public init(id: ProfileRequestID, subjectRef: SubjectRef, fieldKeys: [String], purpose: String, status: ProfileRequestStatus, approvedKeys: [String]?,
                livemode: Bool, createdAt: Date, expiresAt: Date, answeredAt: Date?) {
        self.id = id
        self.subjectRef = subjectRef
        self.fieldKeys = fieldKeys
        self.purpose = purpose
        self.status = status
        self.approvedKeys = approvedKeys
        self.livemode = livemode
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.answeredAt = answeredAt
    }
}

/// One granted field as a business reads it. Verified fields carry their provenance.
public struct BusinessProfileField: Codable, Sendable, Hashable {
    public var key: String
    public var entry: String?
    public var value: ProfileValue
    public var verification: ProfileVerifiedFact?

    public init(key: String, entry: String?, value: ProfileValue, verification: ProfileVerifiedFact? = nil) {
        self.key = key
        self.entry = entry
        self.value = value
        self.verification = verification
    }
}

/// `GET /v1/business/profiles/{subjectRef}` (scope `profiles:read`). The public name always; anything else only while the customer grants
/// it **and** the business's category entitlement holds. `Cache-Control: no-store`.
public struct BusinessProfileView: Codable, Sendable, Hashable {
    public var subjectRef: SubjectRef
    public var publicName: String?
    public var fields: [BusinessProfileField]
    /// Granted keys with no value right now (the customer removed it, or a derived fact cannot be computed).
    public var grantedWithoutValue: [String]
    public var catalogVersion: Int
    public var livemode: Bool

    public init(subjectRef: SubjectRef, publicName: String?, fields: [BusinessProfileField], grantedWithoutValue: [String], livemode: Bool,
                catalogVersion: Int = ProfileCatalog.version) {
        self.subjectRef = subjectRef
        self.publicName = publicName
        self.fields = fields
        self.grantedWithoutValue = grantedWithoutValue
        self.livemode = livemode
        self.catalogVersion = catalogVersion
    }
}

/// Body of `profile.access_granted` and `profile.access_revoked` webhooks: field keys only, **never values**.
public struct ProfileAccessEvent: Codable, Sendable, Hashable {
    public var subjectRef: SubjectRef
    public var fieldKeys: [String]
    public var requestId: ProfileRequestID?
    public var occurredAt: Date

    public init(subjectRef: SubjectRef, fieldKeys: [String], requestId: ProfileRequestID?, occurredAt: Date) {
        self.subjectRef = subjectRef
        self.fieldKeys = fieldKeys
        self.requestId = requestId
        self.occurredAt = occurredAt
    }
}

extension WebhookEventType {
    /// The customer granted fields (from a request or the access page). Keys only.
    public static let profileAccessGranted = WebhookEventType(rawValue: "profile.access_granted")
    /// The customer revoked fields (or disconnected, or deleted the account). Keys only; reads stop before the event is sent.
    public static let profileAccessRevoked = WebhookEventType(rawValue: "profile.access_revoked")
    /// A request ended without an answer (expired). Keys only.
    public static let profileRequestExpired = WebhookEventType(rawValue: "profile.request_expired")
}
