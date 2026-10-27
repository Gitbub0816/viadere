import Fluent
import Foundation
import ViadereCore

/// A verified (or pending) business. The id is immutable and is the only identity other records reference.
final class BusinessRecord: Model, @unchecked Sendable {
    static let schema = "businesses"
    @ID(key: .id) var id: UUID?
    @Field(key: "display_name") var displayName: String
    @OptionalField(key: "legal_name") var legalName: String?
    /// Lowercased name + handle used for directory search.
    @Field(key: "search_text") var searchText: String
    @Field(key: "category") var category: String
    @Field(key: "verification_status") var verificationStatus: String
    @OptionalField(key: "verified_at") var verifiedAt: Date?
    @OptionalField(key: "brand_color") var brandColor: String?
    @OptionalField(key: "logo_url") var logoURL: String?
    @OptionalField(key: "website_url") var websiteURL: String?
    /// `free` or `paid`. Paid tiers raise quotas only; they never affect interaction priority.
    @Field(key: "tier") var tier: String
    @Field(key: "daily_quota") var dailyQuota: Int
    @Field(key: "created_at") var createdAt: Date

    init() {}

    init(id: UUID = UUID(), displayName: String, legalName: String? = nil, category: BusinessCategory, status: VerificationStatus,
         verifiedAt: Date?, tier: String = "free", dailyQuota: Int, now: Date) {
        self.id = id
        self.displayName = displayName
        self.legalName = legalName
        searchText = displayName.lowercased()
        self.category = category.rawValue
        verificationStatus = status.rawValue
        self.verifiedAt = verifiedAt
        self.tier = tier
        self.dailyQuota = dailyQuota
        createdAt = now
    }

    var status: VerificationStatus { VerificationStatus(rawValue: verificationStatus) ?? .suspended }
    var isVerified: Bool { status == .verified }
    var businessID: BusinessID { BusinessID(id ?? UUID()) }
}

/// Public handle. Handles are never reassigned: a retired handle stays in this table with status `retired`.
final class BusinessHandleRecord: Model, @unchecked Sendable {
    static let schema = "business_handles"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "handle") var handle: String
    /// `BusinessHandle.confusableSkeleton`; unique so look-alike handles cannot be registered.
    @Field(key: "skeleton") var skeleton: String
    @Field(key: "status") var status: String
    @Field(key: "created_at") var createdAt: Date

    init() {}

    init(businessId: UUID, handle: BusinessHandle, now: Date) {
        id = UUID()
        self.businessId = businessId
        self.handle = handle.value
        skeleton = handle.confusableSkeleton
        status = "active"
        createdAt = now
    }
}

/// Permanent six-character code. Unique on the canonical form (I→1, O→0).
final class BusinessCodeRecord: Model, @unchecked Sendable {
    static let schema = "business_codes"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "canonical") var canonical: String
    @Field(key: "created_at") var createdAt: Date

    init() {}

    init(businessId: UUID, code: BusinessCode, now: Date) {
        id = UUID()
        self.businessId = businessId
        canonical = code.canonical
        createdAt = now
    }
}

/// Retired codes are kept forever so a code is never reassigned to another business.
final class RetiredBusinessCodeRecord: Model, @unchecked Sendable {
    static let schema = "retired_business_codes"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "canonical") var canonical: String
    @Field(key: "retired_at") var retiredAt: Date

    init() {}

    init(businessId: UUID, canonical: String, now: Date) {
        id = UUID()
        self.businessId = businessId
        self.canonical = canonical
        retiredAt = now
    }
}

/// Business API key. Only the SHA-256 of the key is stored; the key is shown once at creation.
final class BusinessAPIKeyRecord: Model, @unchecked Sendable {
    static let schema = "business_api_keys"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "key_hash") var keyHash: String
    /// `vdk_live_` or `vdk_test_`.
    @Field(key: "prefix") var prefix: String
    /// Last four characters, for display only.
    @Field(key: "last4") var last4: String
    @Field(key: "name") var name: String
    /// Comma-separated operational scopes (`interactions:write`, `webhooks:manage`, ...). Capability access is `capabilities`.
    @Field(key: "scopes") var scopes: String
    /// Comma-separated capability IDs (`message.send`, `auth.challenge`, ...): what this key may ever do. Never exceeds the
    /// business's entitlements **at use time** (SEC-API-003): the policy engine intersects the two on every request.
    @Field(key: "capabilities") var capabilities: String
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "last_used_at") var lastUsedAt: Date?
    @OptionalField(key: "expires_at") var expiresAt: Date?
    @OptionalField(key: "revoked_at") var revokedAt: Date?

    init() {}

    init(businessId: UUID, keyHash: String, prefix: String, last4: String, name: String, scopes: [String], capabilities: [Capability] = Capability.messaging,
         now: Date, expiresAt: Date? = nil) {
        id = UUID()
        self.businessId = businessId
        self.keyHash = keyHash
        self.prefix = prefix
        self.last4 = last4
        self.name = name
        self.scopes = scopes.joined(separator: ",")
        self.capabilities = Set(capabilities.filter(\.isKnown).map(\.rawValue)).sorted().joined(separator: ",")
        createdAt = now
        self.expiresAt = expiresAt
    }

    var scopeSet: Set<String> { Set(scopes.split(separator: ",").map(String.init)) }
    var capabilitySet: Set<Capability> { Set(capabilities.split(separator: ",").map { Capability(rawValue: String($0)) }.filter(\.isKnown)) }
    var livemode: Bool { prefix == BusinessAPIKeys.livePrefix }
}
