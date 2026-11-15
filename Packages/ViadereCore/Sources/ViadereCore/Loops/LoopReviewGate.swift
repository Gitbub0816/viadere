import Foundation

/// A human review decision on one revision (plan section 4.12 stages 2 and 3). Stored server-side (`loop_reviews`); the reviewer id is the
/// Viadere operator's id from the authenticated console session, never from a form field.
public struct LoopReview: Sendable, Hashable {
    public enum Decision: String, Sendable, Codable, CaseIterable, Hashable {
        case approve, reject
        case requestChanges = "request_changes"
    }

    public var reviewerId: String
    public var decision: Decision
    /// The exact definition hash the reviewer saw (the preview is rendered from it).
    public var definitionHash: String

    public init(reviewerId: String, decision: Decision, definitionHash: String) {
        self.reviewerId = reviewerId
        self.decision = decision
        self.definitionHash = definitionHash
    }
}

public enum LoopPublicationRefusal: Sendable, Hashable {
    /// The automated hard gate failed. **No review outcome changes this** (FX-3).
    case hardGate(LoopHardGateFailure)
    /// The validation report is not for this definition, or was produced by an older rule set or registry: validate again.
    case validationStale
    /// A reviewer is an author of the revision.
    case selfReview
    case rejected
    case changesRequested
}

public enum LoopPublicationVerdict: Sendable, Hashable {
    /// May be signed: the manifest is signed over exactly `definitionHash`.
    case publishable(definitionHash: String, reviewers: [String])
    /// Waiting for (more) human approvals.
    case awaitingReview(required: LoopReviewLevel, approvals: Int, needed: Int)
    case refused(LoopPublicationRefusal)

    public var isPublishable: Bool { if case .publishable = self { true } else { false } }
}

/// Decides whether a revision may be signed and published (FX-3: every Loop and every revision; Core logic for WP-3.2).
///
/// Order: hard gate (non-overridable) → report freshness and hash binding → self-review → any rejection or change request → enough
/// distinct approvers for the required level (two for high risk or any review flag). Reviews of another hash do not count.
public enum LoopPublicationGate {
    public static func evaluate(report: LoopValidationReport, definitionHash: String, authorIds: Set<String>, reviews: [LoopReview],
                                registry: LoopActionRegistry = .v1) -> LoopPublicationVerdict {
        if case .failed(let failure) = report.gate { return .refused(.hardGate(failure)) }
        guard report.definitionHash == definitionHash, report.ruleSetVersion == LoopPolicyValidator.ruleSetVersion,
              report.registryVersion == registry.version else { return .refused(.validationStale) }
        let relevant = reviews.filter { $0.definitionHash == definitionHash }
        if relevant.contains(where: { authorIds.contains($0.reviewerId) }) { return .refused(.selfReview) }
        if relevant.contains(where: { $0.decision == .reject }) { return .refused(.rejected) }
        if relevant.contains(where: { $0.decision == .requestChanges }) { return .refused(.changesRequested) }
        var approvers: [String] = []
        for review in relevant where review.decision == .approve && !approvers.contains(review.reviewerId) { approvers.append(review.reviewerId) }
        let needed = report.requiredReview == .twoPerson ? 2 : 1
        guard approvers.count >= needed else { return .awaitingReview(required: report.requiredReview, approvals: approvers.count, needed: needed) }
        return .publishable(definitionHash: definitionHash, reviewers: approvers)
    }
}
