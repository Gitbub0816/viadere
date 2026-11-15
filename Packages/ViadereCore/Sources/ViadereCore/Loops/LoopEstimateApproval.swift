import Foundation

// MARK: - Binding estimate approvals (feature expansion v4 Phase 4, WP-4.4; plan sections 4.9, 4.11.7; SECURITY.md §2.115)
//
// `approve_estimate` binds through the existing decision machinery instead of a parallel one: the server issues a single-use challenge
// for exactly one step and action of one instance, expressed as an `authorize` interaction (sensitivity `high`) whose payload carries the
// reviewed amount, the reviewed terms and the business reference. The device signs a v2 `DecisionPayload` (`approve`, the context digest
// of that interaction, a device-bound biometric key) and sends it with the action. The server rebuilds the interaction from its own rows,
// verifies with `DecisionVerifier` (signature, binding, freshness, `AssurancePolicy`, context digest), consumes the challenge once
// (`ReplayGuard` and a compare-and-swap on the approval row) and only then records the event. It never charges anything: Viadere moves no
// money, and the validator refuses any definition that pairs an amount-bearing approval with a checkout handoff (FX-5).

/// The amount, terms and reference of an `approve_estimate` binding, read from its reviewed parameters.
public struct LoopEstimateTerms: Sendable, Hashable {
    public var amount: MoneyAmount
    public var terms: String
    public var reference: String

    public init(amount: MoneyAmount, terms: String, reference: String) {
        self.amount = amount
        self.terms = terms
        self.reference = reference
    }

    /// `nil` unless the binding has exactly a valid `amount`, a non-empty `terms` text and a non-empty `reference` (the validator enforces
    /// the full grammar on submission; this only refuses to build an approval from anything incomplete).
    public init?(_ binding: LoopActionBinding) {
        guard let params = binding.params, let amount = LoopParameterValue.money(params["amount"]),
              let terms = params["terms"]?.stringValue, !terms.isEmpty, let reference = params["reference"]?.stringValue, !reference.isEmpty else { return nil }
        self.init(amount: amount, terms: terms, reference: reference)
    }
}

public enum LoopEstimateApproval {
    /// How long an issued challenge may be signed and used (bounded by the instance's own expiry).
    public static let lifetime: TimeInterval = 600
    /// The action type that binds through this path.
    public static let actionType = "approve_estimate"
    /// What approving does, in Viadere's words (the registry's confirmation effect).
    public static let effect = "This approves the estimate. It does not charge you."

    /// The authorization context the customer signs. `merchant` is the verified display name of the business (from the server's business
    /// record, never from the definition); the description names the reference and the terms; sensitivity `high` requires a device-bound
    /// biometric signature (`AssurancePolicy`).
    public static func interaction(approvalId: InteractionID, consumerId: ConsumerID, relationshipId: RelationshipID?, businessId: BusinessID,
                                   businessName: String, terms: LoopEstimateTerms, challenge: ChallengeNonce, createdAt: Date, expiresAt: Date) -> Interaction {
        let payload = AuthorizePayload(actionDescription: description(terms), amount: terms.amount, merchant: businessName, effectOfApproval: effect)
        return Interaction(id: approvalId, businessId: businessId,
                           scope: RelationshipScope(consumerId: consumerId, relationshipId: relationshipId ?? RelationshipID(nilUUID)),
                           purpose: .transactional, payload: .authorize(payload), priority: .normal, sensitivity: .high, allowedChannels: [.inApp],
                           createdAt: ViadereDate.truncatedToMilliseconds(createdAt), expiresAt: ViadereDate.truncatedToMilliseconds(expiresAt),
                           idempotencyKey: "loop-approval:" + approvalId.description, challenge: challenge, kind: .authorize)
    }

    /// The business name both sides put in the context: the verified display name sanitized exactly as the attribution bar shows it
    /// (`nil` for a name the builder would refuse). The server takes it from its business record, the device from its verified directory
    /// record; a difference makes the device refuse to sign.
    public static func merchantName(_ displayName: String) -> String? { PresentationBuilder.verifiedName(displayName) }

    /// Stands in for the relationship of an install-only customer (outside the context digest; never resolves to a relationship).
    static let nilUUID = UUID(uuid: (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0))

    /// "Estimate {reference}: {terms}".
    public static func description(_ terms: LoopEstimateTerms) -> String { "Estimate \(terms.reference): \(terms.terms)" }

    /// The device's check before it signs: the challenge is for this instance, step and action, its interaction is an `authorize` of the
    /// instance's business with sensitivity `high`, and its payload is exactly the amount and terms of the binding the device rendered
    /// from its own verified definition, under the business name the device shows. Anything else is never signed.
    public static func matches(_ challenge: LoopApprovalChallenge, instanceId: LoopInstanceID, stepId: String, binding: LoopActionBinding,
                               businessId: BusinessID, businessName: String, now: Date) -> Bool {
        guard binding.action == actionType, let terms = LoopEstimateTerms(binding), challenge.instanceId == instanceId,
              challenge.stepId == stepId, challenge.actionId == binding.id, challenge.interaction.id.description == challenge.approvalId,
              challenge.interaction.businessId == businessId, challenge.interaction.kind == .authorize, challenge.interaction.sensitivity == .high,
              !challenge.interaction.isExpired(at: now), case .authorize(let payload) = challenge.interaction.payload else { return false }
        return payload == AuthorizePayload(actionDescription: description(terms), amount: terms.amount, merchant: businessName, effectOfApproval: effect)
    }
}

/// `POST /v1/loops/instances/{instanceId}/approvals`: asks for the single-use challenge of an `approve_estimate` action on the current step.
public struct LoopApprovalStartRequest: Codable, Sendable, Hashable {
    public var stepId: String
    public var actionId: String

    public init(stepId: String, actionId: String) {
        self.stepId = stepId
        self.actionId = actionId
    }
}

/// The challenge: sign `interaction` (decision `approve`, v2 with its context digest, biometric) and send it with the action.
public struct LoopApprovalChallenge: Codable, Sendable, Hashable {
    /// Equal to `interaction.id`.
    public var approvalId: String
    public var instanceId: LoopInstanceID
    public var stepId: String
    public var actionId: String
    public var interaction: Interaction
    public var expiresAt: Date

    public init(approvalId: String, instanceId: LoopInstanceID, stepId: String, actionId: String, interaction: Interaction, expiresAt: Date) {
        self.approvalId = approvalId
        self.instanceId = instanceId
        self.stepId = stepId
        self.actionId = actionId
        self.interaction = interaction
        self.expiresAt = expiresAt
    }
}

/// Carried by `LoopActionRequest.approval` for `approve_estimate`: the approval id and the signed decision over its interaction.
public struct LoopActionApproval: Codable, Sendable, Hashable {
    public var approvalId: String
    public var signedDecision: SignedDecision

    public init(approvalId: String, signedDecision: SignedDecision) {
        self.approvalId = approvalId
        self.signedDecision = signedDecision
    }
}

extension APIRoutes {
    /// Issues the single-use approval challenge for an `approve_estimate` action on the instance's current step (device-signed). `404` for
    /// anything that is not the caller's; `409` when the step is not current or Loops are paused; `422` for an action that binds nothing.
    public static let loopInstanceApprovalStart = Endpoint<LoopApprovalStartRequest, LoopApprovalChallenge>(
        "loops.instances.approvals.start", .POST, "/v1/loops/instances/{instanceId}/approvals", auth: .deviceSignedBearer)
}
