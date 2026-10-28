import Fluent
import Foundation
import ViadereCore

/// One entitlement a Viadere operator granted a business: either a **risk tier** (`kind = tier`, `value` M/A/V/E) or a
/// **capability** (`kind = capability`, `value` a catalog ID). Rows are never deleted: a revocation stamps `revoked_at` and keeps
/// who, when and why. Every grant carries a recorded purpose justification (AGE-007); a category label alone never creates a row.
final class BusinessEntitlementRecord: Model, @unchecked Sendable {
    static let schema = "business_entitlements"
    static let tierKind = "tier"
    static let capabilityKind = "capability"
    /// `value = LegacyApproval.entitlementValue`; always has `expires_at`.
    static let legacyKind = "legacy"

    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "kind") var kind: String
    @Field(key: "value") var value: String
    /// Operator user id (lowercase UUID) or `system:<reason>` for grants made by a migration.
    @Field(key: "granted_by") var grantedBy: String
    @Field(key: "justification") var justification: String
    /// Reference to the heightened-review record, required for capabilities that release personal data.
    @OptionalField(key: "review_reference") var reviewReference: String?
    @Field(key: "granted_at") var grantedAt: Date
    @OptionalField(key: "expires_at") var expiresAt: Date?
    @OptionalField(key: "revoked_at") var revokedAt: Date?
    @OptionalField(key: "revoked_by") var revokedBy: String?
    @OptionalField(key: "revoke_justification") var revokeJustification: String?

    init() {}

    init(businessId: UUID, kind: String, value: String, grantedBy: String, justification: String, reviewReference: String?, now: Date,
         expiresAt: Date? = nil) {
        id = UUID()
        self.businessId = businessId
        self.kind = kind
        self.value = value
        self.grantedBy = grantedBy
        self.justification = justification
        self.reviewReference = reviewReference
        grantedAt = now
        self.expiresAt = expiresAt
    }

    func isActive(at now: Date) -> Bool { revokedAt == nil && (expiresAt ?? .distantFuture) > now }
}

/// An operator switch that turns one capability off, for the whole platform (`scope = "global"`) or one business (`scope` = the
/// business id). One row per (capability, scope); the history of toggles is in the audit chain. Closes ops gap G-2.
final class CapabilitySwitchRecord: Model, @unchecked Sendable {
    static let schema = "capability_switches"
    static let globalScope = "global"

    @ID(key: .id) var id: UUID?
    @Field(key: "capability") var capability: String
    @Field(key: "scope") var scope: String
    @Field(key: "disabled") var disabled: Bool
    @Field(key: "reason") var reason: String
    @Field(key: "updated_by") var updatedBy: String
    @Field(key: "updated_at") var updatedAt: Date

    init() {}

    init(capability: String, scope: String, disabled: Bool, reason: String, updatedBy: String, now: Date) {
        id = UUID()
        self.capability = capability
        self.scope = scope
        self.disabled = disabled
        self.reason = reason
        self.updatedBy = updatedBy
        updatedAt = now
    }
}

/// A configurable law/policy rule (`PolicyRule`), edited by operators and always audited.
final class PolicyRuleRecord: Model, @unchecked Sendable {
    static let schema = "policy_rules"
    @ID(key: .id) var id: UUID?
    @Field(key: "capability") var capability: String
    @Field(key: "kind") var kind: String
    /// Comma-separated upper-case region codes.
    @Field(key: "jurisdictions") var jurisdictions: String
    @Field(key: "reason") var reason: String
    @Field(key: "active") var active: Bool
    @Field(key: "created_by") var createdBy: String
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "deactivated_by") var deactivatedBy: String?
    @OptionalField(key: "deactivated_at") var deactivatedAt: Date?

    init() {}

    init(rule: PolicyRule, createdBy: String, now: Date) {
        id = rule.id
        capability = rule.capability.rawValue
        kind = rule.kind.rawValue
        jurisdictions = rule.jurisdictions.joined(separator: ",")
        reason = rule.reason
        active = true
        self.createdBy = createdBy
        createdAt = now
    }

    var rule: PolicyRule? {
        guard let id, let kind = PolicyRule.Kind(rawValue: kind) else { return nil }
        return PolicyRule(id: id, capability: Capability(rawValue: capability), kind: kind,
                          jurisdictions: jurisdictions.split(separator: ",").map(String.init), reason: reason)
    }
}

/// A customer's consent to **one** disclosure (`DisclosureReceipt`). Append-mostly: only `revoked_at` and `consumed_at` are ever
/// set, each once, by compare-and-swap. Evidence of consent; retention follows docs/ops/DATA-INVENTORY.md.
final class DisclosureReceiptRecord: Model, @unchecked Sendable {
    static let schema = "disclosure_receipts"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "subject_ref") var subjectRef: String
    @Field(key: "recipient_name") var recipientName: String
    @Field(key: "capability") var capability: String
    @Field(key: "purpose") var purpose: String
    /// Comma-separated field names released.
    @Field(key: "fields") var fields: String
    @Field(key: "request_id") var requestId: String
    @Field(key: "granted_at") var grantedAt: Date
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "revoked_at") var revokedAt: Date?
    @OptionalField(key: "consumed_at") var consumedAt: Date?

    init() {}

    init(receipt: DisclosureReceipt, consumerId: UUID) {
        id = receipt.id
        businessId = receipt.businessId.uuid
        self.consumerId = consumerId
        subjectRef = receipt.subjectRef.rawValue
        recipientName = receipt.recipientName
        capability = receipt.capability.rawValue
        purpose = receipt.purpose
        fields = receipt.fields.joined(separator: ",")
        requestId = receipt.requestId
        grantedAt = receipt.grantedAt
        expiresAt = receipt.expiresAt
    }

    var receipt: DisclosureReceipt? {
        guard let id, let ref = SubjectRef(subjectRef) else { return nil }
        return DisclosureReceipt(id: id, subjectRef: ref, businessId: BusinessID(businessId), recipientName: recipientName,
                                 capability: Capability(rawValue: capability), purpose: purpose,
                                 fields: fields.split(separator: ",").map(String.init), requestId: requestId, grantedAt: grantedAt,
                                 expiresAt: expiresAt, revokedAt: revokedAt, consumedAt: consumedAt)
    }
}
