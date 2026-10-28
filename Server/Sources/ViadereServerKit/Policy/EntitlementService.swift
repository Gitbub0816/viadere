import Fluent
import Foundation
import ViadereCore

/// Who grants or revokes an entitlement: an operator (re-authenticated by the caller) or the system (migrations, tests).
struct EntitlementActor: Sendable {
    var kind: AuditActor.Kind
    var id: String

    static func operatorUser(_ id: UUID) -> EntitlementActor { EntitlementActor(kind: .operator_, id: id.uuidString.lowercased()) }
    static func system(_ reason: String) -> EntitlementActor { EntitlementActor(kind: .system, id: "system:\(reason)") }
}

/// What a business holds **now**: its risk tiers and capability entitlements (spec §8.2).
///
/// Defaults: every verified business holds **Tier M only** and the three messaging capabilities. Anything else exists only as an
/// explicit, justified, audited operator grant. A category label (bank, retailer, adult site) never creates an entitlement, and a
/// verified badge never implies one.
struct EntitlementSnapshot: Sendable {
    var tiers: Set<BusinessRiskTier>
    var capabilities: Set<Capability>
    /// The operator-granted, expiring legacy approval entitlement (`LegacyApproval`): `authorize` and high/critical `authenticate` interactions
    /// decided on relay status alone, while Approve v2 exists.
    var legacyApproval = false
}

struct EntitlementService {
    let db: any Database
    let ctx: ServerContext

    /// Minimum length of a grant justification (the recorded purpose, AGE-007).
    static let minimumJustificationLength = 20

    // MARK: Read

    /// Loaded fresh on every request: the entitlement is a ceiling **at use time**, so a revocation takes effect on the next call.
    func snapshot(businessId: UUID) async throws -> EntitlementSnapshot {
        let now = ctx.now
        var tiers = BusinessRiskTier.baseline
        var capabilities = Set(Capability.messaging)
        var legacy = false
        let rows = try await BusinessEntitlementRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$revokedAt == nil).all()
        for row in rows where row.isActive(at: now) {
            switch row.kind {
            case BusinessEntitlementRecord.tierKind: if let tier = BusinessRiskTier(rawValue: row.value) { tiers.insert(tier) }
            case BusinessEntitlementRecord.capabilityKind:
                let capability = Capability(rawValue: row.value)
                if capability.isKnown { capabilities.insert(capability) }
            case BusinessEntitlementRecord.legacyKind: if row.value == LegacyApproval.entitlementValue, now < LegacyApproval.sunset { legacy = true }
            default: break
            }
        }
        return EntitlementSnapshot(tiers: tiers, capabilities: capabilities, legacyApproval: legacy)
    }

    /// Every entitlement row of a business, newest first (operator console).
    func history(businessId: UUID) async throws -> [BusinessEntitlementRecord] {
        try await BusinessEntitlementRecord.query(on: db).filter(\.$businessId == businessId).sort(\.$grantedAt, .descending).all()
    }

    // MARK: Grant

    /// Grants a tier or a capability. The justification is required for **every** grant and must state the purpose; capabilities
    /// that release personal data, and every identity.* capability, also need the reference of the heightened review (AGE-007). A capability needs its minimum tier
    /// to be held first. Idempotent: an already-active grant returns without a second row.
    @discardableResult
    func grant(businessId: UUID, tier: BusinessRiskTier, actor: EntitlementActor, justification: String) async throws -> BusinessEntitlementRecord {
        guard !BusinessRiskTier.baseline.contains(tier) else {
            throw APIError.conflict("Tier M is held by every verified business and cannot be granted or revoked separately.")
        }
        return try await create(businessId: businessId, kind: BusinessEntitlementRecord.tierKind, value: tier.rawValue, actor: actor,
                                justification: justification, reviewReference: nil, audited: "entitlement.tier_granted")
    }

    @discardableResult
    func grant(businessId: UUID, capability: Capability, actor: EntitlementActor, justification: String,
               reviewReference: String? = nil, expiresAt: Date? = nil) async throws -> BusinessEntitlementRecord {
        guard let definition = capability.definition else { throw APIError.validation("Unknown capability.", details: ["capability": "unknown"]) }
        guard !Capability.messaging.contains(capability) else {
            throw APIError.conflict("Messaging capabilities are held by every verified business. Suspend the business to stop them.")
        }
        let snapshot = try await snapshot(businessId: businessId)
        guard snapshot.tiers.contains(definition.minimumTier) else {
            throw APIError.validation("Grant tier \(definition.minimumTier.rawValue) first.", details: ["tier": definition.minimumTier.rawValue])
        }
        // Every identity.* capability (and any capability that releases personal data) needs the reference of the heightened review (AGE-007)
        // besides the purpose justification: `identity.verified` releases no attribute, but it is the same sensitive-industry access path.
        if capability.rawValue.hasPrefix("identity.") || !definition.output.personalDataFields.isEmpty {
            let reference = (reviewReference ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            guard (4...120).contains(reference.count) else {
                throw APIError.validation("Identity capabilities need the reference of the heightened review.", details: ["reviewReference": "required"])
            }
        }
        return try await create(businessId: businessId, kind: BusinessEntitlementRecord.capabilityKind, value: capability.rawValue, actor: actor,
                                justification: justification, reviewReference: reviewReference?.trimmingCharacters(in: .whitespacesAndNewlines),
                                audited: "entitlement.capability_granted", expiresAt: expiresAt)
    }

    /// Grants the legacy approval entitlement (gate finding F2): the business may keep deciding `authorize` and high/critical `authenticate`
    /// interactions on relay status alone. It always expires (at most 180 days, never after the platform sunset) and needs a justification that
    /// names the migration plan to Approve v2.
    @discardableResult
    func grantLegacyApproval(businessId: UUID, actor: EntitlementActor, justification: String, expiresAt: Date) async throws -> BusinessEntitlementRecord {
        let now = ctx.now
        guard now < LegacyApproval.sunset, expiresAt > now, expiresAt <= min(LegacyApproval.sunset, now.addingTimeInterval(LegacyApproval.maximumGrant)) else {
            throw APIError.validation("The legacy approval path ends on \(ISO8601DateFormatter().string(from: LegacyApproval.sunset)); a grant lasts at most 180 days.",
                                      details: ["expires_at": "invalid"])
        }
        let snapshot = try await snapshot(businessId: businessId)
        guard snapshot.capabilities.contains(.transactionApprove) || snapshot.capabilities.contains(.authChallenge) else {
            throw APIError.validation("The business holds neither transaction.approve nor auth.challenge.", details: ["capability": "required"])
        }
        return try await create(businessId: businessId, kind: BusinessEntitlementRecord.legacyKind, value: LegacyApproval.entitlementValue, actor: actor,
                                justification: justification, reviewReference: nil, audited: "entitlement.legacy_approval_granted", expiresAt: expiresAt)
    }

    func revokeLegacyApproval(businessId: UUID, actor: EntitlementActor, justification: String) async throws {
        try await revoke(businessId: businessId, kind: BusinessEntitlementRecord.legacyKind, value: LegacyApproval.entitlementValue, actor: actor,
                         justification: justification, cascade: [], audited: "entitlement.legacy_approval_revoked")
    }

    private func create(businessId: UUID, kind: String, value: String, actor: EntitlementActor, justification rawJustification: String,
                        reviewReference: String?, audited action: String, expiresAt: Date? = nil) async throws -> BusinessEntitlementRecord {
        guard let business = try await BusinessRecord.find(businessId, on: db) else { throw APIError.notFound }
        guard business.isVerified else { throw APIError.conflict("Only a verified business can be granted entitlements.") }
        let justification = rawJustification.trimmingCharacters(in: .whitespacesAndNewlines)
        guard justification.count >= Self.minimumJustificationLength, justification.count <= 1000,
              !justification.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) && $0 != "\n" }) else {
            throw APIError.validation("Record the purpose that justifies this grant (at least \(Self.minimumJustificationLength) characters).",
                                      details: ["justification": "required"])
        }
        let now = ctx.now
        if let existing = try await BusinessEntitlementRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$kind == kind)
            .filter(\.$value == value).filter(\.$revokedAt == nil).all().first(where: { $0.isActive(at: now) }) {
            return existing
        }
        let record = BusinessEntitlementRecord(businessId: businessId, kind: kind, value: value, grantedBy: actor.id, justification: justification,
                                               reviewReference: reviewReference, now: now, expiresAt: expiresAt)
        try await db.transaction { tx in
            try await record.create(on: tx)
            _ = try await AuditService(db: tx, ctx: ctx).record(action, actor: AuditActor(kind: actor.kind, id: actor.id), businessId: BusinessID(businessId),
                subjectType: "entitlement", subjectId: record.id?.uuidString.lowercased(),
                metadata: ["kind": kind, "value": value, "justification": justification, "review_reference": reviewReference ?? ""])
        }
        return record
    }

    // MARK: Revoke

    /// Revokes the active grant(s) of a tier or capability. Revoking a tier also revokes the capabilities that need it, so nothing
    /// is left that the business could not have been granted today. Takes effect on the next request of every key of the business.
    func revoke(businessId: UUID, tier: BusinessRiskTier, actor: EntitlementActor, justification: String) async throws {
        let dependents = Capability.known.filter { $0.definition?.minimumTier == tier }
        try await revoke(businessId: businessId, kind: BusinessEntitlementRecord.tierKind, value: tier.rawValue, actor: actor,
                         justification: justification, cascade: dependents.map { (BusinessEntitlementRecord.capabilityKind, $0.rawValue) },
                         audited: "entitlement.tier_revoked")
    }

    func revoke(businessId: UUID, capability: Capability, actor: EntitlementActor, justification: String) async throws {
        try await revoke(businessId: businessId, kind: BusinessEntitlementRecord.capabilityKind, value: capability.rawValue, actor: actor,
                         justification: justification, cascade: [], audited: "entitlement.capability_revoked")
    }

    private func revoke(businessId: UUID, kind: String, value: String, actor: EntitlementActor, justification rawJustification: String,
                        cascade: [(String, String)], audited action: String) async throws {
        let justification = rawJustification.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (8...1000).contains(justification.count) else {
            throw APIError.validation("Record why the entitlement is revoked.", details: ["justification": "required"])
        }
        let now = ctx.now
        _ = try await db.transaction { tx -> Int in
            var revoked = 0
            for (rowKind, rowValue) in [(kind, value)] + cascade {
                let rows = try await BusinessEntitlementRecord.query(on: tx).filter(\.$businessId == businessId).filter(\.$kind == rowKind)
                    .filter(\.$value == rowValue).filter(\.$revokedAt == nil).all()
                for row in rows {
                    row.revokedAt = now
                    row.revokedBy = actor.id
                    row.revokeJustification = justification
                    try await row.update(on: tx)
                    revoked += 1
                }
            }
            guard revoked > 0 else { throw APIError.notFound }
            _ = try await AuditService(db: tx, ctx: ctx).record(action, actor: AuditActor(kind: actor.kind, id: actor.id), businessId: BusinessID(businessId),
                subjectType: "entitlement", subjectId: nil,
                metadata: ["kind": kind, "value": value, "justification": justification, "revoked_rows": String(revoked)])
            return revoked
        }
    }
}
