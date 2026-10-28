import Fluent
import Foundation
import ViadereCore

extension VerifyService {
    // MARK: Sandbox (test-mode keys only)

    /// A test-mode request for a sandbox customer completes at once with a **simulated** result (`method: sandbox`, assurance
    /// `sandbox_simulated`). It runs the same consent receipt, policy, projection and one-time retrieval as a live request, so an
    /// integration can be built end to end; it can never be produced for a live key, and nothing about it is evidence of anything.
    func completeSandbox(_ record: VerificationRequestRecord, relationship: RelationshipRecord) async throws {
        guard !record.livemode else { return }
        let now = ctx.now
        let receipts = DisclosureReceiptService(db: db, ctx: ctx)
        let receipt = try await receipts.grant(consumer: ConsumerID(record.consumerId), relationshipId: RelationshipID(relationship.id!), capability: record.capabilityValue,
                                               purpose: record.purpose, requestId: record.requestID.description, lifetime: max(1, record.expiresAt.timeIntervalSince(now)))
        guard try await DB.swap(db, table: VerificationRequestRecord.schema, id: record.id!, column: "status", expected: ConsumerVerificationStatus.pendingConsent.rawValue,
                                newValue: ConsumerVerificationStatus.consented.rawValue, extra: [("receipt_id", receipt.id)]) else { return }
        var claims = EvidenceClaims(method: .sandbox, issuer: "sandbox", verifiedAt: now, validUntil: now.addingTimeInterval(VerifyPolicy.resultValidity), revocation: .notApplicable)
        if case .integer(let years)? = record.parameterValues["years"], let n = Int(exactly: years) { claims.ageOver[n] = true }
        claims.givenName = "Test"
        claims.familyName = "Person"
        claims.address = ["formatted": .string("1 Test Street"), "country": .string("USA")]
        claims.documentPresented = true
        _ = try await conclude(try await VerificationRequestRecord.find(record.id, on: db) ?? record, claims: claims, source: "sandbox")
    }

    // MARK: Maintenance

    /// Runs every background tick, whether or not Verify is enabled (a switched-off feature must still finish what it started and purge).
    ///
    /// - open requests past their expiry end as `not_verified` (the business is told with the same webhook as any other end);
    /// - attempts that never finished are failed, their nonces erased and their provider sessions deleted;
    /// - provider purges that failed are retried;
    /// - results past their expiry, or already retrieved, lose their payload;
    /// - old provider event ids and closed records past retention are deleted.
    @discardableResult
    func runMaintenance() async throws -> Int {
        let now = ctx.now
        var changed = 0
        let open = [ConsumerVerificationStatus.pendingConsent.rawValue, ConsumerVerificationStatus.consented.rawValue]
        for record in try await VerificationRequestRecord.query(on: db).filter(\.$status ~~ open).filter(\.$expiresAt <= now).limit(100).all() {
            try await close(record, status: .expired, reason: "expired")
            changed += 1
        }
        // A conclusion that was claimed but never persisted (a crash between the claim and the write) ends as not_verified.
        let stuckBefore = now.addingTimeInterval(-120)
        for record in try await VerificationRequestRecord.query(on: db).filter(\.$status ~~ open).filter(\.$resultId != nil).filter(\.$expiresAt <= stuckBefore).limit(50).all() {
            if let resultId = record.resultId, try await VerificationResultRecord.query(on: db).filter(\.$id == resultId).count() == 0 {
                try await repair(record, resultId: resultId)
                changed += 1
            }
        }
        // Attempts that outlived their lifetime.
        for attempt in try await VerificationAttemptRecord.query(on: db).filter(\.$status ~~ ["issued", "processing"]).filter(\.$expiresAt <= now.addingTimeInterval(-60)).limit(100).all() {
            attempt.status = "failed"
            attempt.failureReason = "abandoned"
            attempt.nonce = nil
            attempt.finishedAt = now
            try await attempt.update(on: db)
            changed += 1
        }
        // Nonces never outlive their attempt.
        for attempt in try await VerificationAttemptRecord.query(on: db).filter(\.$nonce != nil).filter(\.$status != "issued").limit(100).all() {
            attempt.nonce = nil
            try await attempt.update(on: db)
        }
        // Provider sessions: purge every finished or abandoned one that is not yet deleted, retrying failures.
        if let didit = runtime.didit {
            // Never gives up: retries are spaced by `purgeNextAt` (exponential backoff), not capped by a count.
            let due = try await VerificationAttemptRecord.query(on: db).filter(\.$providerSessionId != nil).filter(\.$purgeStatus ~~ ["pending", "failed"])
                .filter(\.$status !~ ["issued", "processing"]).group(.or) { group in
                    group.filter(\.$purgeNextAt == nil)
                    group.filter(\.$purgeNextAt <= now)
                }.limit(25).all()
            for attempt in due {
                await purge(attempt, didit: didit)
                changed += 1
            }
        }
        // Results: payloads erased after retrieval and at expiry.
        for result in try await VerificationResultRecord.query(on: db).group(.or, { group in
            group.filter(\.$payload != nil)
            group.filter(\.$encryptedPayload != nil)
        }).group(.or, { group in
            group.filter(\.$retrievedAt != nil)
            group.filter(\.$expiresAt <= now)
        }).limit(100).all() {
            result.payload = nil
            result.encryptedPayload = nil
            result.encryptedKid = nil
            try await result.update(on: db)
            changed += 1
        }
        // Attempts kept past their request's deletion (account deletion) go once their provider session is gone.
        for attempt in try await VerificationAttemptRecord.query(on: db).filter(\.$purgeStatus == "done").limit(200).all() {
            if try await VerificationRequestRecord.find(attempt.requestId, on: db) == nil { try await attempt.delete(on: db) }
        }
        if await ctx.limiter.allow("verify-retention", key: "all", rule: .perMinute(1, burst: 1)) {
            try await VerificationProviderEventRecord.query(on: db).filter(\.$receivedAt < now.addingTimeInterval(-Self.providerEventRetention)).delete()
            let cutoff = now.addingTimeInterval(-Self.recordRetention)
            let old = try await VerificationRequestRecord.query(on: db).filter(\.$createdAt < cutoff).filter(\.$status !~ open).limit(200).all()
            for record in old {
                let id = record.id!
                try await VerificationAttemptRecord.query(on: db).filter(\.$requestId == id).group(.or) { group in
                    group.filter(\.$providerSessionId == nil)
                    group.filter(\.$purgeStatus == "done")
                }.delete()
                try await VerificationResultRecord.query(on: db).filter(\.$requestId == id).delete()
                if try await VerificationAttemptRecord.query(on: db).filter(\.$requestId == id).count() == 0 { try await record.delete(on: db) }
            }
        }
        return changed
    }

    /// Account deletion (LEG-PR-004): the person's requests and results are deleted. An attempt whose provider session still has to be deleted
    /// stays (it holds no customer id, only an opaque session reference) until `runMaintenance` has purged it.
    static func wipe(consumer: UUID, on db: any Database) async throws {
        let requests = try await VerificationRequestRecord.query(on: db).filter(\.$consumerId == consumer).all()
        let ids = requests.compactMap(\.id)
        guard !ids.isEmpty else { return }
        try await VerificationResultRecord.query(on: db).filter(\.$requestId ~~ ids).delete()
        try await VerificationAttemptRecord.query(on: db).filter(\.$requestId ~~ ids).filter(\.$nonce != nil).set(\.$nonce, to: nil).update()
        // A provider session that is still open is over now: the next maintenance run deletes it at the provider.
        try await VerificationAttemptRecord.query(on: db).filter(\.$requestId ~~ ids).filter(\.$status ~~ ["issued", "processing"])
            .set(\.$status, to: "failed").set(\.$failureReason, to: "account_deleted").update()
        try await VerificationAttemptRecord.query(on: db).filter(\.$requestId ~~ ids).group(.or) { group in
            group.filter(\.$providerSessionId == nil)
            group.filter(\.$purgeStatus == "done")
        }.delete()
        try await VerificationRequestRecord.query(on: db).filter(\.$id ~~ ids).delete()
    }

    private func repair(_ record: VerificationRequestRecord, resultId: UUID) async throws {
        let now = ctx.now
        let ref = resultRef(for: record.requestID)
        let row = VerificationResultRecord(id: resultId, requestId: record.id!, businessId: record.businessId, refHash: SecureToken.sha256Hex(Data(ref.rawValue.utf8)),
                                           outcome: .notVerified, now: now, expiresAt: now.addingTimeInterval(VerifyPolicy.resultValidity))
        try await db.transaction { tx in
            try await row.create(on: tx)
            record.status = ConsumerVerificationStatus.notVerified.rawValue
            record.decidedAt = now
            try await record.update(on: tx)
            if let callback = record.callbackId {
                try await WebhookService(db: tx, ctx: ctx).enqueue(.verificationCompleted, businessId: BusinessID(record.businessId),
                    payload: VerificationCompletedEventData(requestId: record.requestID, resultRef: ref), onlySubscription: callback,
                    opaque: OpaqueWebhookEvent(requestId: record.requestID.description, resultRef: ref.rawValue))
            }
        }
    }
}
