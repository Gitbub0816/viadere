import Fluent
import Foundation
import ViadereCore

/// Operator-controlled policy state: per-capability kill switches (ops gap G-2) and law/policy rules. Every change needs a
/// recorded reason, is audited with the operator as actor, and clears the policy cache on this instance at once (other instances
/// pick it up within `PolicyService.cacheTTL`). The caller enforces operator re-authentication.
struct PolicyAdmin {
    let db: any Database
    let ctx: ServerContext

    private func reason(_ raw: String) throws -> String {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (8...300).contains(trimmed.count), !trimmed.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
            throw APIError.validation("Record the reason (8 to 300 characters).", details: ["reason": "required"])
        }
        return trimmed
    }

    // MARK: Kill switches

    /// Turns a capability off (or back on) for the whole platform (`businessId == nil`) or for one business.
    func setSwitch(capability: Capability, businessId: UUID? = nil, disabled: Bool, reason rawReason: String, actor: EntitlementActor) async throws {
        guard capability.isKnown else { throw APIError.validation("Unknown capability.", details: ["capability": "unknown"]) }
        let reason = try reason(rawReason)
        let scope = businessId?.uuidString.lowercased() ?? CapabilitySwitchRecord.globalScope
        if let businessId, try await BusinessRecord.find(businessId, on: db) == nil { throw APIError.notFound }
        let now = ctx.now
        try await db.transaction { tx in
            if let row = try await CapabilitySwitchRecord.query(on: tx).filter(\.$capability == capability.rawValue).filter(\.$scope == scope).first() {
                row.disabled = disabled
                row.reason = reason
                row.updatedBy = actor.id
                row.updatedAt = now
                try await row.update(on: tx)
            } else {
                try await CapabilitySwitchRecord(capability: capability.rawValue, scope: scope, disabled: disabled, reason: reason,
                                                 updatedBy: actor.id, now: now).create(on: tx)
            }
            _ = try await AuditService(db: tx, ctx: ctx).record(disabled ? "policy.capability_disabled" : "policy.capability_enabled",
                actor: AuditActor(kind: actor.kind, id: actor.id), businessId: businessId.map(BusinessID.init), subjectType: "capability",
                subjectId: capability.rawValue, metadata: ["scope": businessId == nil ? "global" : "business", "reason": reason])
        }
        await ctx.policyCache.invalidate()
    }

    func switches() async throws -> [CapabilitySwitchRecord] {
        try await CapabilitySwitchRecord.query(on: db).sort(\.$updatedAt, .descending).all()
    }

    // MARK: Law / policy rules

    @discardableResult
    func addRule(capability: Capability, kind: PolicyRule.Kind, jurisdictions raw: [String], reason rawReason: String,
                 actor: EntitlementActor) async throws -> PolicyRuleRecord {
        guard capability.isKnown else { throw APIError.validation("Unknown capability.", details: ["capability": "unknown"]) }
        let reason = try reason(rawReason)
        let codes = raw.map { $0.trimmingCharacters(in: .whitespaces).uppercased() }.filter { !$0.isEmpty }
        guard !codes.isEmpty, codes.count <= 100, codes.allSatisfy({ Self.isRegion($0) }) else {
            throw APIError.validation("List ISO 3166 region codes such as US or US-CA.", details: ["jurisdictions": "invalid"])
        }
        let record = PolicyRuleRecord(rule: PolicyRule(capability: capability, kind: kind, jurisdictions: codes, reason: reason),
                                      createdBy: actor.id, now: ctx.now)
        try await db.transaction { tx in
            try await record.create(on: tx)
            _ = try await AuditService(db: tx, ctx: ctx).record("policy.rule_added", actor: AuditActor(kind: actor.kind, id: actor.id),
                subjectType: "policy_rule", subjectId: record.id?.uuidString.lowercased(),
                metadata: ["capability": capability.rawValue, "kind": kind.rawValue, "jurisdictions": codes.joined(separator: " "), "reason": reason])
        }
        await ctx.policyCache.invalidate()
        return record
    }

    func deactivateRule(id: UUID, reason rawReason: String, actor: EntitlementActor) async throws {
        let reason = try reason(rawReason)
        guard let row = try await PolicyRuleRecord.find(id, on: db), row.active else { throw APIError.notFound }
        row.active = false
        row.deactivatedBy = actor.id
        row.deactivatedAt = ctx.now
        try await db.transaction { tx in
            try await row.update(on: tx)
            _ = try await AuditService(db: tx, ctx: ctx).record("policy.rule_removed", actor: AuditActor(kind: actor.kind, id: actor.id),
                subjectType: "policy_rule", subjectId: id.uuidString.lowercased(), metadata: ["capability": row.capability, "reason": reason])
        }
        await ctx.policyCache.invalidate()
    }

    func rules() async throws -> [PolicyRuleRecord] {
        try await PolicyRuleRecord.query(on: db).sort(\.$createdAt, .descending).limit(200).all()
    }

    /// `US`, `CA`, or a subdivision such as `US-CA`.
    static func isRegion(_ code: String) -> Bool {
        let parts = code.split(separator: "-", omittingEmptySubsequences: false)
        guard (1...2).contains(parts.count), parts[0].count == 2, parts[0].unicodeScalars.allSatisfy({ ("A"..."Z").contains($0) }) else { return false }
        if parts.count == 2 { return (1...3).contains(parts[1].count) && parts[1].unicodeScalars.allSatisfy { ("A"..."Z").contains($0) || ("0"..."9").contains($0) } }
        return true
    }
}
