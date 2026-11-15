import Foundation
import ViadereCore

/// What a business may see of the audit log: the one projection used by **every** business-facing view and export (the dashboard audit
/// page, the tenant export), so every current and future event is covered in one place.
///
/// Two rules, both privacy controls:
/// 1. **No global consumer identifier (cross-tenant linkage).** A consumer UUID, or the id of a consumer's device, is the same in every
///    business's audit rows; showing it would let two businesses recognise the same person. Consumer actors are rendered as *this*
///    business's `subject_ref` for that person (which is per business and unlinkable), device actors as "customer device", and any
///    other occurrence of the consumer's id in an event's subject or metadata is replaced the same way.
/// 2. **No Verify oracle (AGE-005).** The business is told only that a verification was `requested`, `completed` as `verified` or
///    `not_verified`, and that the result was retrieved. The detailed events (attempts, reasons, methods, consent, provider purge) are
///    written to the platform-only trail without a business id; rows from before that split are hidden here, and `verification.completed`
///    is reduced to the capability and the outcome.
struct BusinessAuditProjection: Sendable {
    let ctx: ServerContext

    struct Entry: Sendable, Equatable {
        var occurredAt: Date
        var action: String
        /// `success` / `failure` / `denied`.
        var outcome: String
        var actorKind: String
        /// The business's own member / key / system id; a consumer is its `subject_ref`; `nil` when there is nothing safe to show.
        var actorId: String?
        var subjectType: String?
        var subjectId: String?
        var metadata: [String: String]
    }

    /// The only Verify events a business sees.
    static let businessVisibleVerifyActions: Set<String> = ["verification.requested", "verification.completed", "verification.result_retrieved"]
    static let completedMetadataKeys: Set<String> = ["capability", "outcome"]
    /// Metadata keys that name a global identifier of a person or their device.
    static let globalIdentifierKeys: Set<String> = ["consumer_id", "consumerid", "device_id", "deviceid", "account_id", "accountid"]

    func project(_ e: AuditEventRecord) -> Entry? {
        let consumerString = e.consumerId?.uuidString.lowercased()
        // Verify: allowlist (also hides detailed rows written before the platform-only split).
        if e.action.hasPrefix("verification.") && !Self.businessVisibleVerifyActions.contains(e.action) { return nil }
        if e.action.hasPrefix("consent.disclosure_") { return nil }

        var metadata = (try? JSONDecoder().decode([String: String].self, from: Data(e.metadataJSON.utf8))) ?? [:]
        var outcome = e.outcome
        if e.action == "verification.completed" {
            metadata = metadata.filter { Self.completedMetadataKeys.contains($0.key) }
            // Whatever the stored row says, the business sees only the verified / not_verified distinction.
            outcome = metadata["outcome"] == "verified" ? "success" : "failure"
        }

        let ref = consumerRef(e)
        func scrub(_ value: String) -> String {
            guard let consumerString, value.lowercased().contains(consumerString), let ref else { return value }
            return value.replacingOccurrences(of: consumerString, with: ref, options: .caseInsensitive)
        }
        metadata = metadata.filter { !Self.globalIdentifierKeys.contains($0.key.lowercased()) }.mapValues(scrub)

        var actorId = e.actorId
        switch e.actorKind {
        case AuditActor.Kind.consumer.rawValue: actorId = ref
        case AuditActor.Kind.device.rawValue: actorId = nil
        default: actorId = actorId.map(scrub)
        }
        var subjectId = e.subjectId.map(scrub)
        if e.subjectType == "consumer" || e.subjectType == "device" { subjectId = ref }
        return Entry(occurredAt: e.occurredAt, action: e.action, outcome: outcome, actorKind: e.actorKind, actorId: actorId,
                     subjectType: e.subjectType, subjectId: subjectId, metadata: metadata)
    }

    func project(_ events: [AuditEventRecord]) -> [Entry] { events.compactMap(project) }

    /// This business's `subject_ref` for the event's consumer, when the event names one.
    private func consumerRef(_ e: AuditEventRecord) -> String? {
        guard let businessId = e.businessId else { return nil }
        let consumer = e.consumerId ?? (e.actorKind == AuditActor.Kind.consumer.rawValue ? e.actorId.flatMap(UUID.init(uuidString:)) : nil)
        guard let consumer else { return nil }
        return ctx.subjects.subjectRef(businessId: BusinessID(businessId), consumerId: ConsumerID(consumer)).rawValue
    }
}
