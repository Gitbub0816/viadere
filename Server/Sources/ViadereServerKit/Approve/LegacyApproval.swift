import Fluent
import Foundation
import ViadereCore

/// The legacy `authorize` / `authenticate` interaction path as an **approval** (gate finding F2).
///
/// A legacy interaction is decided on the relay's own status: the signed decision is stripped for businesses
/// (`InteractionService.outcome`), so a business that authorizes a payment or a sign-in on it trusts the relay completely. Approve v2 gives
/// the business an end-to-end verifiable result instead. While Approve v2 exists the legacy path therefore stays closed for live traffic
/// unless an operator granted the business the explicit **legacy approval** entitlement: audited, justified, and ending no later than the
/// platform sunset. The sandbox is never affected.
///
/// This path is not independently verifiable and is never documented as such.
enum LegacyApproval {
    /// No grant can run past this date, and no grant is accepted after it (the entitlement simply cannot be active): 2027-06-30T00:00:00Z.
    static let sunset = Date(timeIntervalSince1970: 1_814_313_600)
    static let entitlementValue = "interactive-approval"
    static let maximumGrant: TimeInterval = 180 * 86_400

    /// Whether an interaction of this kind is an approval decided on relay status alone: every `authorize`, and `authenticate` at high or critical
    /// sensitivity.
    static func isApproval(kind: InteractionKind, sensitivity: Sensitivity) -> Bool {
        switch kind {
        case .authorize: true
        case .authenticate: sensitivity >= .high
        default: false
        }
    }

    /// Throws `403 legacy_approval_not_entitled` unless the request may proceed.
    static func require(kind: InteractionKind, sensitivity: Sensitivity, principal: BusinessPrincipal, ctx: ServerContext, db: any Database) async throws {
        guard principal.livemode, isApproval(kind: kind, sensitivity: sensitivity) else { return }
        if ctx.now < sunset {
            // Before the sunset the path is only restricted while Approve v2 exists; after it, it is closed whatever the gate says (WP-C2).
            guard ctx.config.approve.enabled else { return }
            if try await EntitlementService(db: db, ctx: ctx).snapshot(businessId: principal.businessId.uuid).legacyApproval { return }
        }
        _ = try? await AuditService(db: db, ctx: ctx).record("interaction.legacy_approval_refused", outcome: .denied,
            actor: AuditActor(kind: .businessAPIKey, id: principal.keyId.uuidString.lowercased()), businessId: principal.businessId,
            subjectType: "interaction_kind", subjectId: kind.rawValue)
        throw APIError(.forbidden, .forbidden,
                       "Approvals use Approve v2 (end-to-end verifiable results). The legacy authorize/authenticate path is closed for your business.",
                       details: ["reason": "legacy_approval_not_entitled", "use": "/v1/business/approve/requests"])
    }
}
