import Fluent
import Foundation
import Vapor
import ViadereCore

extension VerifyService {
    /// A document attempt has at most this long to finish before its provider session is deleted.
    static let documentAttemptLifetime: TimeInterval = 600

    // MARK: Begin

    /// Creates a provider session for one attempt. `vendor_data` is the attempt's own id: opaque, single-use and unlinkable to the person,
    /// so the provider holds nothing that names the customer, the business or the request. The app receives only the short-lived
    /// session token and runs the provider's SDK; images and biometrics go from the device to the provider and never through Viadere.
    func documentBegin(consumer: ConsumerID, id: VerificationRequestID) async throws -> DocumentAttemptStart {
        try await limit("verify-attempt", key: consumer.description, rule: settings.attemptRate)
        let record = try await ownRequest(consumer, id)
        let now = ctx.now
        guard record.livemode, record.consumerStatus == .consented, now < record.expiresAt else { throw APIError.conflict("This request is not ready for verification.") }
        guard runtime.documentAvailable(settings: settings), let didit = runtime.didit, let workflow = settings.diditWorkflowIdentity,
              record.capabilityValue == .ageMinimum || record.capabilityValue.definition?.requiredEvidence == .verifiedIdentity else {
            throw VerifyService.methodUnavailable
        }
        guard record.attemptCount < VerifyPolicy.maxAttemptsPerRequest else { throw APIError(.tooManyRequests, .rateLimited, "No verification attempts remain for this request.") }
        guard try await DB.swap(db, table: VerificationRequestRecord.schema, id: record.id!, column: "attempt_count", expected: record.attemptCount,
                                newValue: record.attemptCount + 1) else { throw APIError.conflict("Try again.") }
        let expiresAt = min(now.addingTimeInterval(Self.documentAttemptLifetime), record.expiresAt)
        let attempt = VerificationAttemptRecord(requestId: record.id!, businessId: record.businessId, method: .document, nonce: nil, now: now, expiresAt: expiresAt)
        attempt.purgeStatus = nil
        try await attempt.create(on: db)
        let session: DiditSession
        do {
            session = try await didit.createSession(workflowId: workflow, vendorData: attempt.id!.uuidString.lowercased())
        } catch {
            // A provider outage fails the attempt cleanly: nothing was collected, nothing is disclosed, the person can use another method.
            await fail(attempt, record, reason: "provider_unavailable")
            throw VerifyService.methodUnavailable
        }
        attempt.providerSessionId = session.sessionId
        attempt.purgeStatus = "pending"
        try await attempt.update(on: db)
        await audit("verification.attempt_started", record, metadata: ["method": "document"])
        return DocumentAttemptStart(attemptId: attempt.id!, sessionToken: session.sessionToken, expiresAt: expiresAt)
    }

    // MARK: Complete (the app, after the SDK finished) and webhook (the provider)

    func documentComplete(consumer: ConsumerID, id: VerificationRequestID, body: DocumentAttemptComplete) async throws -> VerificationAttemptOutcome {
        try await limit("verify-attempt", key: consumer.description, rule: settings.attemptRate)
        let record = try await ownRequest(consumer, id)
        guard let attempt = try await VerificationAttemptRecord.query(on: db).filter(\.$id == body.attemptId).filter(\.$requestId == record.id!)
            .filter(\.$method == VerificationMethodKind.document.rawValue).first() else { throw APIError.notFound }
        return try await finalizeDocument(attempt)
    }

    enum WebhookDisposition: Equatable {
        case accepted
        /// The provider could not be reached to re-fetch the decision: answer 5xx so the provider retries.
        case retry
    }

    /// Handles a **verified** `status.updated` webhook. The body is only a hint at which session changed: the decision is always
    /// re-fetched from the API (`finalizeDocument`), and a delivery repeating a known `event_id` does nothing.
    func handleDiditWebhook(_ body: [String: JSONValue]) async -> WebhookDisposition {
        guard let eventId = body["event_id"]?.stringValue, (1...100).contains(eventId.count), body["webhook_type"]?.stringValue == "status.updated",
              let sessionId = body["session_id"]?.stringValue, (1...64).contains(sessionId.count) else { return .accepted }
        if (try? await VerificationProviderEventRecord.query(on: db).filter(\.$provider == "didit").filter(\.$eventId == eventId).count()) ?? 0 > 0 { return .accepted }
        guard let attempt = try? await VerificationAttemptRecord.query(on: db).filter(\.$providerSessionId == sessionId).first() else {
            // A customer's own profile verification (docs/PROFILES.md) uses the same provider and the same handling.
            if let handled = await ProfileVerificationService(db: db, ctx: ctx, runtime: runtime).handleDiditSession(sessionId) {
                if handled == .accepted { try? await VerificationProviderEventRecord(provider: "didit", eventId: eventId, now: ctx.now).create(on: db) }
                return handled
            }
            // Not ours (or already purged and gone): acknowledge without saying which.
            return .accepted
        }
        do {
            _ = try await finalizeDocument(attempt)
        } catch let error as DiditError where error == .unavailable {
            return .retry
        } catch {
            return .retry
        }
        try? await VerificationProviderEventRecord(provider: "didit", eventId: eventId, now: ctx.now).create(on: db)
        return .accepted
    }

    /// Re-fetches the session decision, derives the claim in memory, concludes the request and **purges the session at the provider**.
    ///
    /// Order is the privacy contract: read → minimize (reduce to the capability's output) → persist the result → delete at the provider
    /// (`privacy_erasure`) and record the deletion. The decision, the document fields, the face scores and every URL never reach the
    /// database, a log or a response.
    func finalizeDocument(_ attempt: VerificationAttemptRecord) async throws -> VerificationAttemptOutcome {
        guard let record = try await VerificationRequestRecord.find(attempt.requestId, on: db) else { throw APIError.notFound }
        guard let sessionId = attempt.providerSessionId, let didit = runtime.didit else { return outcome(record) }
        // An attempt that already finished returns where it ended (idempotent; a duplicate webhook or a second app call).
        guard attempt.status == "issued" else { return outcome(record) }
        guard try await DB.swap(db, table: VerificationAttemptRecord.schema, id: attempt.id!, column: "status", expected: "issued", newValue: "processing") else {
            return outcome(try await VerificationRequestRecord.find(record.id, on: db) ?? record)
        }
        let decision: [String: JSONValue]
        do {
            decision = try await didit.decision(sessionId: sessionId)
        } catch {
            // Nothing was disclosed; the attempt can be finalized again (the provider retries the webhook, the app can ask again).
            _ = try? await DB.swap(db, table: VerificationAttemptRecord.schema, id: attempt.id!, column: "status", expected: "processing", newValue: "issued")
            await audit("verification.provider_unavailable", record, metadata: ["method": "document"], outcome: .failure)
            throw DiditError.unavailable
        }
        let now = ctx.now
        let mapped = DiditDecisionMapper.map(decision: decision, expectedSession: sessionId, expectedAttempt: attempt.id!.uuidString.lowercased(), now: now)
        if mapped.state == .inProgress {
            _ = try? await DB.swap(db, table: VerificationAttemptRecord.schema, id: attempt.id!, column: "status", expected: "processing", newValue: "issued")
            return outcome(try await VerificationRequestRecord.find(record.id, on: db) ?? record)
        }
        var result: VerificationAttemptOutcome
        do {
            // `mapped.claims` (and the `decision` above) are the only copies of the personal data; both die at the end of this scope.
            result = try await conclude(try await VerificationRequestRecord.find(record.id, on: db) ?? record, claims: mapped.claims, source: "document")
            switch mapped.state {
            case .approved:
                attempt.status = mapped.claims == nil ? "failed" : "succeeded"
                attempt.failureReason = mapped.claims == nil ? "no_claim" : nil
            case .notApproved(let reason):
                attempt.status = "failed"
                attempt.failureReason = reason
            case .inProgress: break
            }
        } catch {
            attempt.status = "failed"
            attempt.failureReason = "error"
            result = outcome(record)
        }
        attempt.finishedAt = now
        try? await attempt.update(on: db)
        await audit(attempt.status == "succeeded" ? "verification.document_verified" : "verification.document_rejected", record,
                    metadata: ["method": "document", "reason": attempt.failureReason ?? "none", "estimate_only": mapped.estimatedAgeOnly ? "true" : "false"],
                    outcome: attempt.status == "succeeded" ? .success : .failure)
        // Purge whatever the outcome: a declined or abandoned session may still hold images.
        await purge(attempt, didit: didit)
        return result
    }

    // MARK: Purge

    /// Deletes the provider session (`privacy_erasure`) and the provider's user entity, and records it. A failure is recorded and retried
    /// by the maintenance job; the attempt is never forgotten while a session may exist.
    func purge(_ attempt: VerificationAttemptRecord, didit: any DiditAPI) async {
        guard let sessionId = attempt.providerSessionId, attempt.purgeStatus != "done" else { return }
        let vendorData = attempt.id!.uuidString.lowercased()
        do {
            try await didit.deleteSession(sessionId: sessionId, instructionId: "viadere-" + vendorData)
            try await didit.deleteUser(vendorData: vendorData)
            attempt.purgeStatus = "done"
            attempt.purgedAt = ctx.now
            attempt.purgeNextAt = nil
        } catch {
            attempt.purgeStatus = "failed"
            attempt.purgeAttempts += 1
            attempt.purgeNextAt = ctx.now.addingTimeInterval(Self.purgeBackoff(afterFailures: attempt.purgeAttempts))
            ctx.metrics.count(.verifyPurgeFailed)
            runtime.logger.error("provider purge failed; will retry", metadata: ["failures": "\(attempt.purgeAttempts)"])
        }
        try? await attempt.update(on: db)
        _ = try? await AuditService(db: db, ctx: ctx).record(attempt.purgeStatus == "done" ? "verification.provider_purged" : "verification.provider_purge_failed",
            outcome: attempt.purgeStatus == "done" ? .success : .failure, actor: AuditActor(kind: .system, id: "verify"),
            subjectType: "verification_attempt", subjectId: attempt.id!.uuidString.lowercased(),
            metadata: ["attempts": String(attempt.purgeAttempts)])
    }
}
