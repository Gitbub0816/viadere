import Fluent
import Foundation
import ViadereCore

/// Per-request disclosure consent (spec §6.4): a customer's receipt for **one** disclosure, and the atomic use of it.
struct DisclosureReceiptService {
    let db: any Database
    let ctx: ServerContext

    /// Records the customer's confirmation of one disclosure. Called by the app-facing verification flow (Verify, WP3) after the
    /// person saw the recipient, purpose and fields and confirmed with local authentication. The receipt names exactly the fields the
    /// capability discloses, expires within `DisclosureReceipt.maxLifetime`, and is bound to the business, the subject, the capability,
    /// the purpose and the request id.
    func grant(consumer: ConsumerID, relationshipId: RelationshipID, capability: Capability, purpose: String, requestId: String,
               lifetime: TimeInterval = DisclosureReceipt.maxLifetime) async throws -> DisclosureReceipt {
        guard let definition = capability.definition, definition.consent.mode == .perRequestReceipt else {
            throw APIError.validation("This capability does not use disclosure receipts.", details: ["capability": "invalid"])
        }
        guard PolicyEngine.isValidPurpose(purpose), (1...128).contains(requestId.count), lifetime > 0 else {
            throw APIError.validation("A purpose and request id are required.", details: ["purpose": "invalid"])
        }
        // The relationship must be the consumer's own and active, with a verified business.
        guard let relationship = try await RelationshipRecord.query(on: db).filter(\.$id == relationshipId.uuid)
            .filter(\.$consumerId == consumer.uuid).first(), relationship.isActive,
              let business = try await BusinessRecord.find(relationship.businessId, on: db), business.isVerified else { throw APIError.notFound }
        let now = ctx.now
        let receipt = DisclosureReceipt(subjectRef: SubjectResolver(db: db, ctx: ctx).ref(for: relationship), businessId: BusinessID(business.id!),
                                        recipientName: business.displayName, capability: capability, purpose: purpose,
                                        fields: definition.disclosedClaimFields, requestId: requestId, grantedAt: now,
                                        expiresAt: now.addingTimeInterval(min(lifetime, DisclosureReceipt.maxLifetime)))
        do {
            try await db.transaction { tx in
                try await DisclosureReceiptRecord(receipt: receipt, consumerId: consumer.uuid).create(on: tx)
                _ = try await AuditService(db: tx, ctx: ctx).record("consent.disclosure_granted", actor: AuditActor(kind: .consumer, id: consumer.description),
                    consumerId: consumer, businessId: receipt.businessId, subjectType: "disclosure_receipt", subjectId: receipt.id.uuidString.lowercased(),
                    metadata: ["capability": capability.rawValue, "purpose": purpose, "request_id": requestId, "fields": receipt.fields.joined(separator: " "),
                               "expires_at": ISO8601DateFormatter().string(from: receipt.expiresAt)])
            }
        } catch {
            if error.isConstraintViolation { throw APIError.conflict("A receipt for this request already exists.") }
            throw error
        }
        return receipt
    }

    /// The customer withdraws a receipt before it was used. Only the consumer's own receipt; a used receipt cannot be revoked.
    func revoke(consumer: ConsumerID, receiptId: UUID) async throws {
        guard let row = try await DisclosureReceiptRecord.query(on: db).filter(\.$id == receiptId).filter(\.$consumerId == consumer.uuid).first() else {
            throw APIError.notFound
        }
        guard row.revokedAt == nil else { return }
        guard row.consumedAt == nil else { throw APIError.conflict("This disclosure was already made.") }
        guard try await DB.swapFromNull(db, table: DisclosureReceiptRecord.schema, id: receiptId, column: "revoked_at", newValue: ctx.now) else {
            throw APIError.conflict("This disclosure was already made.")
        }
        _ = try await AuditService(db: db, ctx: ctx).record("consent.disclosure_revoked", actor: AuditActor(kind: .consumer, id: consumer.description),
            consumerId: consumer, businessId: BusinessID(row.businessId), subjectType: "disclosure_receipt", subjectId: receiptId.uuidString.lowercased())
    }

    /// The receipt of **this business** for this subject, capability and request. Tenant-scoped: another business's receipt is never
    /// visible, even with its id.
    func receipt(businessId: BusinessID, subjectRef: SubjectRef, capability: Capability, requestId: String) async throws -> DisclosureReceipt? {
        try await DisclosureReceiptRecord.query(on: db).filter(\.$businessId == businessId.uuid).filter(\.$subjectRef == subjectRef.rawValue)
            .filter(\.$capability == capability.rawValue).filter(\.$requestId == requestId).first()?.receipt
    }

    /// Marks the receipt used (compare-and-swap): a receipt authorizes **one** disclosure.
    func consume(_ id: UUID) async throws -> Bool {
        try await DB.swapFromNull(db, table: DisclosureReceiptRecord.schema, id: id, column: "consumed_at", newValue: ctx.now)
    }
}

extension PolicyService {
    /// The entry point for a disclosure capability (`age.minimum`, `identity.*`): looks up the business's own receipt for this exact
    /// request, evaluates the policy (consent, evidence, law/policy) and, only when allowed, consumes the receipt atomically. A
    /// lost race (two concurrent requests, one receipt) denies the loser. `evidence` is what the Verify service holds about the subject.
    func authorizeDisclosure(_ input: PolicyInput, principal: BusinessPrincipal, relationship: RelationshipRecord,
                             evidence: [EvidenceHolding]) async throws -> PolicyDecision {
        guard let requestId = input.requestId, let subjectRef = input.subjectRef else {
            return try await decide(input, principal: principal, stage: .full, subject: SubjectPolicyFacts(relationshipActive: relationship.isActive, evidence: evidence))
        }
        let receipts = DisclosureReceiptService(db: db, ctx: ctx)
        let receipt = try await receipts.receipt(businessId: principal.businessId, subjectRef: subjectRef, capability: input.capability, requestId: requestId)
        let subject = SubjectPolicyFacts(relationshipActive: relationship.isActive, evidence: evidence, receipt: receipt)
        let decision = try await decide(input, principal: principal, stage: .full, subject: subject, auditAllowed: false)
        guard decision.allowed, let receipt else {
            if decision.allowed { try await record(decision, input: input, principal: principal) }
            return decision
        }
        if try await receipts.consume(receipt.id) {
            try await record(decision, input: input, principal: principal)
            return decision
        }
        // Lost the race: the receipt was used by a concurrent request.
        var denied = decision
        denied.allowed = false
        denied.reasons = [.consentRequired]
        denied.details["receipt"] = "already_used"
        denied.audit = PolicyAuditRecord(action: "policy.denied", outcome: .denied,
                                         metadata: decision.audit.metadata.merging(["reason": "consent_required", "receipt_problem": "already_used"]) { _, new in new })
        try await record(denied, input: input, principal: principal)
        return denied
    }
}
