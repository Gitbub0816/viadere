import Fluent
import Foundation
import ViadereCore

/// The custom public name of an account (sealed; context `consumer_profiles.public_name`, row = the consumer id). No row = the derived default.
final class ConsumerProfileRecord: Model, @unchecked Sendable {
    static let schema = "consumer_profiles"
    static let publicNameContext = "consumer_profiles.public_name"

    @ID(key: .id) var id: UUID?
    @OptionalField(key: "public_name") var publicName: String?
    @Field(key: "updated_at") var updatedAt: Date

    init() {}
    init(consumerId: UUID, now: Date) {
        id = consumerId
        updatedAt = now
    }
}

/// One profile value, sealed with the row-bound field cipher (`profile_values.value#{rowId}`), as canonical JSON of the `ProfileValue`.
final class ProfileValueRecord: Model, @unchecked Sendable {
    static let schema = "profile_values"
    static let valueContext = "profile_values.value"

    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "field_key") var fieldKey: String
    /// `""` for single-value fields.
    @Field(key: "entry_key") var entryKey: String
    @Field(key: "value") var value: String
    @Field(key: "catalog_version") var catalogVersion: Int
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "updated_at") var updatedAt: Date

    init() {}
    init(consumerId: UUID, fieldKey: String, entryKey: String, now: Date) {
        id = UUID()
        self.consumerId = consumerId
        self.fieldKey = fieldKey
        self.entryKey = entryKey
        value = ""
        catalogVersion = ProfileCatalog.version
        createdAt = now
        updatedAt = now
    }

    var entry: String? { entryKey.isEmpty ? nil : entryKey }
}

/// The customer's grant of one field to one business. A revoked row stays as history (no value is ever stored here).
final class ProfileGrantRecord: Model, @unchecked Sendable {
    static let schema = "profile_grants"

    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "relationship_id") var relationshipId: UUID
    @Field(key: "field_key") var fieldKey: String
    @OptionalField(key: "request_id") var requestId: UUID?
    @Field(key: "granted_at") var grantedAt: Date
    @OptionalField(key: "revoked_at") var revokedAt: Date?
    /// `customer`, `disconnected`, `account_deleted`.
    @OptionalField(key: "revoke_reason") var revokeReason: String?

    init() {}
    init(consumerId: UUID, businessId: UUID, relationshipId: UUID, fieldKey: String, requestId: UUID?, now: Date) {
        id = UUID()
        self.consumerId = consumerId
        self.businessId = businessId
        self.relationshipId = relationshipId
        self.fieldKey = fieldKey
        self.requestId = requestId
        grantedAt = now
    }
}

final class ProfileRequestRecord: Model, @unchecked Sendable {
    static let schema = "profile_requests"

    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "key_id") var keyId: UUID
    @Field(key: "livemode") var livemode: Bool
    @Field(key: "relationship_id") var relationshipId: UUID
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "subject_ref") var subjectRef: String
    /// Space-separated catalog keys.
    @Field(key: "field_keys") var fieldKeys: String
    /// The business's own words, validated as display text.
    @Field(key: "purpose") var purpose: String
    @Field(key: "status") var status: String
    @OptionalField(key: "approved_keys") var approvedKeys: String?
    @Field(key: "idempotency_hash") var idempotencyHash: String
    @Field(key: "request_hash") var requestHash: String
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "answered_at") var answeredAt: Date?

    init() {}

    var keys: [String] { fieldKeys.split(separator: " ").map(String.init) }
    var approved: [String]? { approvedKeys.map { $0.split(separator: " ").map(String.init) } }
    var statusValue: ProfileRequestStatus { ProfileRequestStatus(rawValue: status) ?? .unknown }
}

final class ProfileReceiptRecord: Model, @unchecked Sendable {
    static let schema = "profile_receipts"

    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "recipient_name") var recipientName: String
    @Field(key: "action") var action: String
    @Field(key: "field_keys") var fieldKeys: String
    @OptionalField(key: "purpose") var purpose: String?
    @OptionalField(key: "request_id") var requestId: UUID?
    @Field(key: "created_at") var createdAt: Date

    init() {}
    init(consumerId: UUID, businessId: UUID, recipientName: String, action: ProfileReceiptAction, fieldKeys: [String], purpose: String?, requestId: UUID?, now: Date) {
        id = UUID()
        self.consumerId = consumerId
        self.businessId = businessId
        self.recipientName = recipientName
        self.action = action.rawValue
        self.fieldKeys = fieldKeys.joined(separator: " ")
        self.purpose = purpose
        self.requestId = requestId
        createdAt = now
    }

    var dto: ProfileDisclosureReceipt {
        ProfileDisclosureReceipt(id: ProfileReceiptID(id!), businessId: BusinessID(businessId), businessName: recipientName,
                                 action: ProfileReceiptAction(rawValue: action) ?? .unknown, fieldKeys: fieldKeys.split(separator: " ").map(String.init),
                                 purpose: purpose, requestId: requestId.map(ProfileRequestID.init), createdAt: createdAt)
    }
}

final class ProfileVerifiedFactRecord: Model, @unchecked Sendable {
    static let schema = "profile_verified_facts"

    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "fact") var fact: String
    @Field(key: "method") var method: String
    @Field(key: "assurance") var assurance: String
    @Field(key: "policy_version") var policyVersion: String
    @Field(key: "verified_at") var verifiedAt: Date

    init() {}

    var dto: ProfileVerifiedFact? {
        guard let kind = ProfileVerifiedFactKind(rawValue: fact), let method = VerificationMethod(rawValue: method) else { return nil }
        return ProfileVerifiedFact(fact: kind, method: method, verifiedAt: verifiedAt, assurance: assurance, policyVersion: policyVersion)
    }
}

final class ProfileVerificationAttemptRecord: Model, @unchecked Sendable {
    static let schema = "profile_verification_attempts"

    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "method") var method: String
    /// Space-separated `ProfileVerifiedFactKind` the customer chose to keep.
    @Field(key: "keep") var keep: String
    /// `issued`, `processing`, `succeeded`, `failed`.
    @Field(key: "status") var status: String
    @OptionalField(key: "nonce") var nonce: String?
    @OptionalField(key: "provider_session_id") var providerSessionId: String?
    @OptionalField(key: "failure_reason") var failureReason: String?
    @OptionalField(key: "purge_status") var purgeStatus: String?
    @Field(key: "purge_attempts") var purgeAttempts: Int
    @OptionalField(key: "purged_at") var purgedAt: Date?
    @OptionalField(key: "purge_next_at") var purgeNextAt: Date?
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "finished_at") var finishedAt: Date?

    init() {}
    init(consumerId: UUID, method: ProfileVerificationMethod, keep: [ProfileVerifiedFactKind], nonce: String?, now: Date, expiresAt: Date) {
        id = UUID()
        self.consumerId = consumerId
        self.method = method.rawValue
        self.keep = keep.map(\.rawValue).joined(separator: " ")
        status = "issued"
        self.nonce = nonce
        purgeAttempts = 0
        createdAt = now
        self.expiresAt = expiresAt
    }

    var keepKinds: [ProfileVerifiedFactKind] { keep.split(separator: " ").compactMap { ProfileVerifiedFactKind(rawValue: String($0)) } }
}

/// A business's request (onboarding or later) that Viadere allow it a profile category. Approving creates a `business_entitlements` row
/// (`kind = profile_category`) through `EntitlementService`; the business itself never can.
final class ProfileCategoryRequestRecord: Model, @unchecked Sendable {
    static let schema = "profile_category_requests"

    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "category") var category: String
    @OptionalField(key: "justification") var justification: String?
    /// `pending`, `approved`, `denied`, `withdrawn`.
    @Field(key: "status") var status: String
    @OptionalField(key: "requested_by") var requestedBy: UUID?
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "decided_at") var decidedAt: Date?
    @OptionalField(key: "decided_by") var decidedBy: String?
    @OptionalField(key: "decision_note") var decisionNote: String?

    init() {}
    init(businessId: UUID, category: ProfileCategory, justification: String?, requestedBy: UUID?, now: Date) {
        id = UUID()
        self.businessId = businessId
        self.category = category.rawValue
        self.justification = justification
        status = "pending"
        self.requestedBy = requestedBy
        createdAt = now
    }

    var categoryValue: ProfileCategory? { ProfileCategory(rawValue: category) }
}

extension BusinessEntitlementRecord {
    /// `value` = a `ProfileCategory` raw value.
    static let profileCategoryKind = "profile_category"
}
