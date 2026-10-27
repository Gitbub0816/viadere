import Fluent
import Foundation
import ViadereCore

/// The v1 payload of an Approve webhook event: ids only, never an amount, a payee, a decision or a status the business could be tempted
/// to trust. (A v2 subscription receives the opaque `WebhookEnvelopeV2` instead.)
struct ApproveEventPayload: Codable, Sendable {
    var requestId: String
    var resultRef: String?
    var subjectRef: String?
    var kid: String?

    enum CodingKeys: String, CodingKey {
        case requestId = "request_id", resultRef = "result_ref", subjectRef = "subject_ref", kid
    }
}

/// Queues Approve events. Every event is opaque (SEC-CR-001 / spec 14.3): the business fetches what it needs with its own credentials.
struct ApproveWebhooks {
    let db: any Database
    let ctx: ServerContext

    private func send(_ type: WebhookEventType, businessId: UUID, payload: ApproveEventPayload) async throws {
        try await WebhookService(db: db, ctx: ctx).enqueue(type, businessId: BusinessID(businessId), payload: payload,
                                                           opaque: OpaqueWebhookEvent(requestId: payload.requestId, resultRef: payload.resultRef))
    }

    func enrollmentDeviceCompleted(_ enrollment: ApproveEnrollmentRecord) async throws {
        try await send(.approveEnrollmentDeviceCompleted, businessId: enrollment.businessId,
                       payload: ApproveEventPayload(requestId: enrollment.id!.uuidString.lowercased(), resultRef: nil, subjectRef: enrollment.subjectRef, kid: enrollment.kid))
    }

    func enrollmentConfirmed(_ enrollment: ApproveEnrollmentRecord) async throws {
        try await send(.approveEnrollmentConfirmed, businessId: enrollment.businessId,
                       payload: ApproveEventPayload(requestId: enrollment.id!.uuidString.lowercased(), resultRef: nil, subjectRef: enrollment.subjectRef, kid: enrollment.kid))
    }

    func keyRevoked(_ key: ApproveKeyRecord) async throws {
        try await send(.approveKeyRevoked, businessId: key.businessId,
                       payload: ApproveEventPayload(requestId: key.enrollmentId.uuidString.lowercased(), resultRef: nil, subjectRef: key.subjectRef, kid: key.kid))
    }

    func requestDecided(_ request: ApproveRequestRecord) async throws {
        try await send(.approveRequestDecided, businessId: request.businessId,
                       payload: ApproveEventPayload(requestId: request.requestId, resultRef: request.resultRef, subjectRef: request.subjectRef, kid: nil))
    }

    func requestExpired(_ request: ApproveRequestRecord) async throws {
        try await send(.approveRequestExpired, businessId: request.businessId,
                       payload: ApproveEventPayload(requestId: request.requestId, resultRef: nil, subjectRef: request.subjectRef, kid: nil))
    }

    func frozen(relationship: RelationshipRecord, by: String) async throws {
        let subject = relationship.subjectRef ?? ""
        try await send(.approveFrozen, businessId: relationship.businessId, payload: ApproveEventPayload(requestId: subject, resultRef: nil, subjectRef: subject, kid: nil))
    }
}
