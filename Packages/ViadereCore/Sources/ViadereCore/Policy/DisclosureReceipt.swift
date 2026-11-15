import Foundation

/// The evidence that a customer agreed to **one specific disclosure** (spec §6.4): which capability, for what purpose, to which
/// business (the recipient the customer was shown), which fields, until when. It is created when the customer confirms in the app
/// and is the only thing that can satisfy a per-request consent requirement. A relationship-level consent never can (no blanket
/// consent), and a receipt cannot be reused for another business, subject, capability, purpose or request.
public struct DisclosureReceipt: Codable, Sendable, Hashable, Identifiable {
    /// Longest a receipt may be valid (seconds). The customer confirms and the disclosure follows immediately.
    public static let maxLifetime: TimeInterval = 600

    public var id: UUID
    public var subjectRef: SubjectRef
    /// The recipient business, as displayed to the customer.
    public var businessId: BusinessID
    public var recipientName: String
    public var capability: Capability
    /// Snake_case disclosure purpose shown to the customer (for example `age_restricted_access`).
    public var purpose: String
    /// Exactly the fields released (a subset of the capability's output fields).
    public var fields: [String]
    /// The verification request this receipt is for. One receipt, one request.
    public var requestId: String
    public var grantedAt: Date
    public var expiresAt: Date
    public var revokedAt: Date?
    public var consumedAt: Date?

    public init(id: UUID = UUID(), subjectRef: SubjectRef, businessId: BusinessID, recipientName: String, capability: Capability,
                purpose: String, fields: [String], requestId: String, grantedAt: Date, expiresAt: Date,
                revokedAt: Date? = nil, consumedAt: Date? = nil) {
        self.id = id
        self.subjectRef = subjectRef
        self.businessId = businessId
        self.recipientName = recipientName
        self.capability = capability
        self.purpose = purpose
        self.fields = fields
        self.requestId = requestId
        self.grantedAt = grantedAt
        self.expiresAt = expiresAt
        self.revokedAt = revokedAt
        self.consumedAt = consumedAt
    }

    /// Why a receipt does not authorize a disclosure, as a machine code; `nil` when it does.
    public func problem(businessId: BusinessID, subjectRef: SubjectRef?, capability: Capability, purpose: String?, requestId: String?,
                        now: Date) -> String? {
        guard let definition = capability.definition else { return "unknown_capability" }
        guard self.businessId == businessId else { return "wrong_recipient" }
        guard let subjectRef, self.subjectRef == subjectRef else { return "wrong_subject" }
        guard self.capability == capability else { return "wrong_capability" }
        guard let purpose, !purpose.isEmpty, self.purpose == purpose else { return "wrong_purpose" }
        guard let requestId, !requestId.isEmpty, self.requestId == requestId else { return "wrong_request" }
        guard revokedAt == nil else { return "revoked" }
        guard consumedAt == nil else { return "already_used" }
        guard now >= grantedAt, now < expiresAt, expiresAt.timeIntervalSince(grantedAt) <= Self.maxLifetime else { return "expired" }
        // The receipt must name every claim the capability discloses and nothing beyond its output schema (no widening).
        let released = Set(fields)
        guard released.isSubset(of: Set(definition.output.fieldNames)),
              Set(definition.disclosedClaimFields).isSubset(of: released) else { return "fields_mismatch" }
        return nil
    }
}

extension CapabilityDefinition {
    /// The fields that carry the claim itself or personal data (not the assurance/validity metadata): what a receipt must cover.
    public var disclosedClaimFields: [String] {
        output.fields.filter { $0.fieldClass == .assertion || $0.fieldClass == .personalData }.map(\.name)
    }
}
