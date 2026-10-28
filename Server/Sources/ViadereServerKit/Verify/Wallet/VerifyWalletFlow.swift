@preconcurrency import Crypto
import Fluent
import Foundation
import ViadereCore

extension VerifyService {
    /// Wallet envelopes carry a few elements (never a portrait): far below this, which bounds what the server will decode.
    static let maxEnvelopeCharacters = 48_000

    // MARK: Begin

    /// Issues a single-use nonce for one Wallet presentment of an open, consented request.
    func walletBegin(consumer: ConsumerID, id: VerificationRequestID) async throws -> WalletAttemptStart {
        try await limit("verify-attempt", key: consumer.description, rule: settings.attemptRate)
        let record = try await ownRequest(consumer, id)
        let now = ctx.now
        guard record.livemode, record.consumerStatus == .consented, now < record.expiresAt else { throw APIError.conflict("This request is not ready for verification.") }
        guard runtime.walletAvailable(settings: settings, now: now), let merchant = settings.walletMerchantIdentifier,
              WalletElementPlan.request(for: record.capabilityValue, parameters: record.parameterValues) != nil else {
            throw VerifyService.methodUnavailable
        }
        guard record.attemptCount < VerifyPolicy.maxAttemptsPerRequest else { throw APIError(.tooManyRequests, .rateLimited, "No verification attempts remain for this request.") }
        // One open Wallet attempt at a time: an unused nonce is retired when a new one is issued.
        for stale in try await VerificationAttemptRecord.query(on: db).filter(\.$requestId == record.id!).filter(\.$method == VerificationMethodKind.wallet.rawValue)
            .filter(\.$status == "issued").all() {
            stale.status = "failed"
            stale.failureReason = "superseded"
            stale.nonce = nil
            stale.finishedAt = now
            try await stale.update(on: db)
        }
        guard try await DB.swap(db, table: VerificationRequestRecord.schema, id: record.id!, column: "attempt_count", expected: record.attemptCount,
                                newValue: record.attemptCount + 1) else { throw APIError.conflict("Try again.") }
        let nonce = SecureToken.randomBytes(32)
        let expiresAt = min(now.addingTimeInterval(VerifyPolicy.walletNonceLifetime), record.expiresAt)
        let attempt = VerificationAttemptRecord(requestId: record.id!, businessId: record.businessId, method: .wallet, nonce: Base64URL.encode(nonce), now: now, expiresAt: expiresAt)
        try await attempt.create(on: db)
        await audit("verification.attempt_started", record, metadata: ["method": "wallet"])
        return WalletAttemptStart(attemptId: attempt.id!, nonce: Base64URL.encode(nonce), merchantIdentifier: merchant, expiresAt: expiresAt)
    }

    // MARK: Complete

    /// Verifies the encrypted presentment of `attemptId` and, if it supports the claim, concludes the request.
    ///
    /// The nonce is consumed first (compare-and-swap), so a second submission of the same envelope — or any envelope for this attempt —
    /// finds nothing to open (replay guard). Whatever happens next, the attempt is over.
    func walletComplete(consumer: ConsumerID, id: VerificationRequestID, body: WalletAttemptComplete) async throws -> VerificationAttemptOutcome {
        try await limit("verify-attempt", key: consumer.description, rule: settings.attemptRate)
        let record = try await ownRequest(consumer, id)
        guard let attempt = try await VerificationAttemptRecord.query(on: db).filter(\.$id == body.attemptId).filter(\.$requestId == record.id!)
            .filter(\.$method == VerificationMethodKind.wallet.rawValue).first() else { throw APIError.notFound }
        let now = ctx.now
        guard body.envelope.count <= Self.maxEnvelopeCharacters, let envelopeBytes = Base64URL.decode(body.envelope) else {
            throw APIError.validation("The presentation is malformed.", details: ["envelope": "invalid"])
        }
        let nonce = attempt.nonce.flatMap { Base64URL.decode($0) }
        // Single use: only the caller that moves `issued` to `processing` may use the nonce.
        guard try await DB.swap(db, table: VerificationAttemptRecord.schema, id: attempt.id!, column: "status", expected: "issued", newValue: "processing") else {
            await audit("verification.attempt_replayed", record, metadata: ["method": "wallet"], outcome: .denied)
            return outcome(try await VerificationRequestRecord.find(record.id, on: db) ?? record)
        }
        attempt.nonce = nil
        attempt.status = "processing"
        try await attempt.update(on: db)
        guard now < attempt.expiresAt, record.consumerStatus == .consented, let nonce, let plan = WalletElementPlan.request(for: record.capabilityValue, parameters: record.parameterValues),
              let merchant = settings.walletMerchantIdentifier, let trust = runtime.trust, !trust.isEmpty, let source = runtime.walletKeys else {
            await fail(attempt, record, reason: now >= attempt.expiresAt ? "nonce_expired" : "not_available")
            return try await conclude(try await VerificationRequestRecord.find(record.id, on: db) ?? record, claims: nil, source: "wallet")
        }
        let claims: EvidenceClaims?
        do {
            let keys = try await source.keys()
            let envelope = try AppleIdentityEnvelope(parsing: envelopeBytes)
            let opened = try envelope.open(keys: keys, nonce: nonce, merchantIdentifier: merchant, teamIdentifier: ctx.config.appleTeamID)
            // `opened.plaintext` is the only copy of the DeviceResponse; it is verified, reduced to the requested elements and dropped.
            let verification = try await MDocVerifier(trust: trust).verify(plaintext: opened.plaintext, sessionTranscript: opened.sessionTranscript,
                                                                           requested: WalletElementPlan.readableElements(for: plan), now: now)
            claims = WalletClaims.claims(from: verification, plan: plan, now: now)
            attempt.status = claims == nil ? "failed" : "succeeded"
            attempt.failureReason = claims == nil ? MDocFailure.noRequestedElement.rawValue : nil
        } catch let failure as MDocFailure {
            claims = nil
            attempt.status = "failed"
            attempt.failureReason = failure.rawValue
        } catch {
            claims = nil
            attempt.status = "failed"
            attempt.failureReason = "error"
        }
        attempt.finishedAt = ctx.now
        try await attempt.update(on: db)
        await audit(attempt.status == "succeeded" ? "verification.wallet_verified" : "verification.wallet_rejected", record,
                    metadata: ["method": "wallet", "reason": attempt.failureReason ?? "none"], outcome: attempt.status == "succeeded" ? .success : .failure)
        return try await conclude(try await VerificationRequestRecord.find(record.id, on: db) ?? record, claims: claims, source: "wallet")
    }

    func fail(_ attempt: VerificationAttemptRecord, _ record: VerificationRequestRecord, reason: String) async {
        attempt.status = "failed"
        attempt.failureReason = reason
        attempt.nonce = nil
        attempt.finishedAt = ctx.now
        try? await attempt.update(on: db)
        await audit("verification.attempt_failed", record, metadata: ["reason": reason], outcome: .failure)
    }

    /// Detailed events: the platform-only trail (no business id; see `platformAudit`).
    func audit(_ action: String, _ record: VerificationRequestRecord, metadata: [String: String] = [:], outcome: AuditEvent.Outcome = .success) async {
        await platformAudit(action, record, metadata: metadata, outcome: outcome)
    }
}

/// Reduces a verified presentation to `EvidenceClaims`: the requested elements, nothing else. The values are consumed by
/// `ClaimsBuilder` and dropped.
enum WalletClaims {
    static func claims(from verification: MDocVerification, plan: WalletElementPlan.Request, now: Date) -> EvidenceClaims? {
        var claims = EvidenceClaims(method: .walletMdoc, issuer: verification.issuerAnchor, verifiedAt: now, validUntil: verification.validUntil, revocation: .notChecked)
        func text(_ id: String) -> String? { verification.elements[MDocElement(namespace: WalletElementPlan.isoNamespace, identifier: id)]?.textString }
        var present = false
        switch plan {
        case .ageAtLeast:
            for (element, value) in verification.elements where element.namespace == WalletElementPlan.isoNamespace {
                if element.identifier.hasPrefix("age_over_"), let years = Int(element.identifier.dropFirst("age_over_".count)), (0...99).contains(years),
                   let flag = value.boolValue {
                    claims.ageOver[years] = flag
                    present = true
                }
            }
            if case .unsigned(let age)? = verification.elements[MDocElement(namespace: WalletElementPlan.isoNamespace, identifier: "age_in_years")], age <= 150 {
                claims.ageInYears = Int(age)
                present = true
            }
            // `birth_date` (a `full-date`, tag 1004 or plain text) is read only to answer the yes/no in memory.
            let dob = verification.elements[MDocElement(namespace: WalletElementPlan.isoNamespace, identifier: "birth_date")]
            if let string = dob?.content(taggedWith: 1004)?.textString ?? dob?.textString, let day = AgeThreshold.Day(isoDate: string) {
                claims.birthDate = day
                present = true
            }
        case .givenAndFamilyName:
            claims.givenName = text("given_name")
            claims.familyName = text("family_name")
            present = claims.givenName != nil && claims.familyName != nil
        case .residentAddress:
            var address: [String: JSONValue] = [:]
            for (key, id) in [("street", "resident_address"), ("locality", "resident_city"), ("region", "resident_state"), ("postal_code", "resident_postal_code"),
                              ("country", "resident_country")] {
                if let value = text(id), !value.isEmpty, value.count <= 200 { address[key] = .string(value) }
            }
            if !address.isEmpty { claims.address = address }
            present = claims.address != nil
        case .documentPresented:
            claims.documentPresented = text("issuing_authority") != nil
            present = claims.documentPresented
        }
        return present ? claims : nil
    }
}
