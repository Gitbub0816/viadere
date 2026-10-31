import Fluent
import Foundation
import ViadereCore

/// The customer verifies their own profile (docs/PROFILES.md §Verified profile) with the **existing Verify methods**: an Apple Wallet ID
/// (`AppleIdentityEnvelope` + `MDocVerifier` + `WalletClaims`, unchanged) or a Didit document + liveness + face-match session
/// (`DiditAPI` + `DiditDecisionMapper`, unchanged, purged after every outcome). Behind the same release gate (`VERIFY_ENABLED`).
///
/// Only the facts the customer chose to **keep** are stored, as booleans with provenance (method, time, assurance, policy version): never
/// a document number, image, or the document's name or birth date. The name is compared to the profile's first and last name in memory and
/// only "matches" is kept. No promotion: a fact is kept only when the method can establish its label (`VerificationMethod.establishes`).
struct ProfileVerificationService {
    let db: any Database
    let ctx: ServerContext
    let runtime: VerifyRuntime

    var settings: VerifySettings { ctx.config.verify }
    static let attemptLifetime: TimeInterval = 600
    static let attemptRate = RateRule(capacity: 5, perMinute: 0.2)

    /// The Wallet plans a profile verification asks for: always the document (the Verified badge), plus the name and age checks the customer
    /// chose to keep.
    static func plans(for keep: [ProfileVerifiedFactKind]) -> [WalletElementPlan.Request] {
        var plans: [WalletElementPlan.Request] = [.documentPresented]
        if keep.contains(.legalName) { plans.append(.givenAndFamilyName) }
        if keep.contains(.ageOver18) { plans.append(.ageAtLeast(18)) }
        if keep.contains(.ageOver21) { plans.append(.ageAtLeast(21)) }
        return plans
    }

    // MARK: Begin

    func begin(principal: ConsumerPrincipal, body: ProfileVerificationBegin) async throws -> ProfileVerificationStart {
        try VerifyService.requireEnabled(ctx)
        let consumer = principal.consumerId.uuid
        guard await ctx.limiter.allow("profile-verify", key: consumer.uuidString, rule: Self.attemptRate) else { throw APIError.rateLimited(retryAfter: 60) }
        let keep = Array(Set(body.keep)).sorted { $0.rawValue < $1.rawValue }
        guard !keep.isEmpty else { throw APIError.validation("Choose what to keep.", details: ["keep": "required"]) }
        let now = ctx.now
        // One open attempt per account: an unused one is retired.
        for stale in try await ProfileVerificationAttemptRecord.query(on: db).filter(\.$consumerId == consumer).filter(\.$status == "issued").all() {
            stale.status = "failed"
            stale.failureReason = "superseded"
            stale.nonce = nil
            stale.finishedAt = now
            try await stale.update(on: db)
        }
        let expiresAt = now.addingTimeInterval(Self.attemptLifetime)
        switch body.method {
        case .wallet:
            guard runtime.walletAvailable(settings: settings, now: now), let merchant = settings.walletMerchantIdentifier else { throw VerifyService.methodUnavailable }
            let nonce = Base64URL.encode(SecureToken.randomBytes(32))
            let attempt = ProfileVerificationAttemptRecord(consumerId: consumer, method: .wallet, keep: keep, nonce: nonce, now: now,
                                                           expiresAt: now.addingTimeInterval(VerifyPolicy.walletNonceLifetime))
            try await attempt.create(on: db)
            await audit("profile.verification_started", consumer: consumer, attempt: attempt)
            let elements = Self.plans(for: keep).flatMap(WalletElementPlan.requestedIdentifiers(for:))
            return ProfileVerificationStart(attemptId: ProfileAttemptID(attempt.id!), method: .wallet, nonce: nonce, merchantIdentifier: merchant,
                                            requestedElements: elements, sessionToken: nil, expiresAt: attempt.expiresAt)
        case .document:
            guard runtime.documentAvailable(settings: settings), let didit = runtime.didit, let workflow = settings.diditWorkflowIdentity else {
                throw VerifyService.methodUnavailable
            }
            let attempt = ProfileVerificationAttemptRecord(consumerId: consumer, method: .document, keep: keep, nonce: nil, now: now, expiresAt: expiresAt)
            try await attempt.create(on: db)
            let session: DiditSession
            do {
                // `vendor_data` is the attempt id: opaque, single use, unlinkable to the person.
                session = try await didit.createSession(workflowId: workflow, vendorData: attempt.id!.uuidString.lowercased())
            } catch {
                attempt.status = "failed"
                attempt.failureReason = "provider_unavailable"
                attempt.finishedAt = now
                try? await attempt.update(on: db)
                throw VerifyService.methodUnavailable
            }
            attempt.providerSessionId = session.sessionId
            attempt.purgeStatus = "pending"
            try await attempt.update(on: db)
            await audit("profile.verification_started", consumer: consumer, attempt: attempt)
            return ProfileVerificationStart(attemptId: ProfileAttemptID(attempt.id!), method: .document, nonce: nil, merchantIdentifier: nil,
                                            requestedElements: [], sessionToken: session.sessionToken, expiresAt: expiresAt)
        }
    }

    // MARK: Complete

    func complete(principal: ConsumerPrincipal, attemptId: UUID, body: ProfileVerificationComplete) async throws -> ProfileVerificationOutcome {
        try VerifyService.requireEnabled(ctx)
        let consumer = principal.consumerId.uuid
        guard let attempt = try await ProfileVerificationAttemptRecord.query(on: db).filter(\.$id == attemptId).filter(\.$consumerId == consumer).first() else {
            throw APIError.notFound
        }
        switch ProfileVerificationMethod(rawValue: attempt.method) {
        case .wallet?: return try await completeWallet(attempt, envelope: body.envelope)
        case .document?: return try await finalizeDocument(attempt)
        case nil: throw APIError.notFound
        }
    }

    private func completeWallet(_ attempt: ProfileVerificationAttemptRecord, envelope: String?) async throws -> ProfileVerificationOutcome {
        guard let envelope, envelope.count <= VerifyService.maxEnvelopeCharacters, let bytes = Base64URL.decode(envelope) else {
            throw APIError.validation("The presentation is malformed.", details: ["envelope": "invalid"])
        }
        let nonce = attempt.nonce.flatMap { Base64URL.decode($0) }
        // Single use: only the caller that moves `issued` to `processing` may use the nonce (replay guard).
        guard try await DB.swap(db, table: ProfileVerificationAttemptRecord.schema, id: attempt.id!, column: "status", expected: "issued", newValue: "processing",
                                extra: [("nonce", Optional<String>.none)]) else {
            await audit("profile.verification_replayed", consumer: attempt.consumerId, attempt: attempt, outcome: .denied)
            return try await outcome(consumer: attempt.consumerId, status: .notVerified, kept: [])
        }
        let now = ctx.now
        guard now < attempt.expiresAt, let nonce, let merchant = settings.walletMerchantIdentifier, let trust = runtime.trust, !trust.isEmpty,
              let source = runtime.walletKeys else {
            return try await finish(attempt, claims: nil, reason: now >= attempt.expiresAt ? "nonce_expired" : "not_available")
        }
        let plans = Self.plans(for: attempt.keepKinds)
        var claims: EvidenceClaims?
        var reason: String?
        do {
            let keys = try await source.keys()
            let opened = try AppleIdentityEnvelope(parsing: bytes).open(keys: keys, nonce: nonce, merchantIdentifier: merchant, teamIdentifier: ctx.config.appleTeamID)
            let requested = plans.reduce(into: Set<MDocElement>()) { $0.formUnion(WalletElementPlan.readableElements(for: $1)) }
            let verification = try await MDocVerifier(trust: trust).verify(plaintext: opened.plaintext, sessionTranscript: opened.sessionTranscript,
                                                                           requested: requested, now: now)
            // Each plan reduces the same verified presentation; the claims are merged in memory and dropped after `finish`.
            for plan in plans {
                guard let part = WalletClaims.claims(from: verification, plan: plan, now: now) else { continue }
                if claims == nil { claims = part; continue }
                claims!.ageOver.merge(part.ageOver) { a, _ in a }
                claims!.ageInYears = claims!.ageInYears ?? part.ageInYears
                claims!.birthDate = claims!.birthDate ?? part.birthDate
                claims!.givenName = claims!.givenName ?? part.givenName
                claims!.familyName = claims!.familyName ?? part.familyName
                claims!.documentPresented = claims!.documentPresented || part.documentPresented
            }
            if claims == nil { reason = MDocFailure.noRequestedElement.rawValue }
        } catch let failure as MDocFailure {
            reason = failure.rawValue
        } catch {
            reason = "error"
        }
        return try await finish(attempt, claims: claims, reason: reason)
    }

    /// Re-fetches the provider decision, keeps the chosen facts, and **purges the provider session whatever the outcome**.
    func finalizeDocument(_ attempt: ProfileVerificationAttemptRecord) async throws -> ProfileVerificationOutcome {
        guard let sessionId = attempt.providerSessionId, let didit = runtime.didit else {
            return try await outcome(consumer: attempt.consumerId, status: .notVerified, kept: [])
        }
        guard attempt.status == "issued",
              try await DB.swap(db, table: ProfileVerificationAttemptRecord.schema, id: attempt.id!, column: "status", expected: "issued", newValue: "processing") else {
            let current = try await ProfileVerificationAttemptRecord.find(attempt.id, on: db)
            return try await outcome(consumer: attempt.consumerId, status: current?.status == "succeeded" ? .verified : (current?.status == "processing" ? .pending : .notVerified), kept: [])
        }
        let decision: [String: JSONValue]
        do {
            decision = try await didit.decision(sessionId: sessionId)
        } catch {
            _ = try? await DB.swap(db, table: ProfileVerificationAttemptRecord.schema, id: attempt.id!, column: "status", expected: "processing", newValue: "issued")
            throw DiditError.unavailable
        }
        let mapped = DiditDecisionMapper.map(decision: decision, expectedSession: sessionId, expectedAttempt: attempt.id!.uuidString.lowercased(), now: ctx.now)
        if mapped.state == .inProgress {
            _ = try? await DB.swap(db, table: ProfileVerificationAttemptRecord.schema, id: attempt.id!, column: "status", expected: "processing", newValue: "issued")
            return try await outcome(consumer: attempt.consumerId, status: .pending, kept: [])
        }
        var reason: String?
        if case .notApproved(let why) = mapped.state { reason = why }
        let result = try await finish(attempt, claims: mapped.claims, reason: reason)
        await purge(attempt, didit: didit)
        return result
    }

    // MARK: Facts

    /// The facts `claims` establishes among those the customer chose to keep. Pure (tested directly).
    static func facts(from claims: EvidenceClaims, keep: [ProfileVerifiedFactKind], profileGiven: String?, profileFamily: String?, now: Date) -> [ProfileVerifiedFactKind] {
        let labels = claims.method.establishes
        var out: [ProfileVerifiedFactKind] = []
        for kind in keep {
            switch kind {
            case .identity:
                if claims.documentPresented, labels.contains(.verifiedIdentity) { out.append(kind) }
            case .legalName:
                guard labels.contains(.verifiedIdentity), let given = profileGiven, let family = profileFamily,
                      let documentGiven = claims.givenName, let documentFamily = claims.familyName else { continue }
                if namesMatch(given, documentGiven) && namesMatch(family, documentFamily) { out.append(kind) }
            case .ageOver18:
                if labels.contains(.verifiedAgeThreshold), ClaimsBuilder.meetsThreshold(claims, years: 18, now: now) == true { out.append(kind) }
            case .ageOver21:
                if labels.contains(.verifiedAgeThreshold), ClaimsBuilder.meetsThreshold(claims, years: 21, now: now) == true { out.append(kind) }
            }
        }
        return out
    }

    /// Case-, width- and accent-insensitive comparison of names, ignoring punctuation and spacing ("O'Brien" = "OBRIEN", "José" = "Jose").
    static func namesMatch(_ a: String, _ b: String) -> Bool {
        func fold(_ text: String) -> String {
            text.folding(options: [.caseInsensitive, .diacriticInsensitive, .widthInsensitive], locale: Locale(identifier: "en_US_POSIX"))
                .unicodeScalars.filter { CharacterSet.alphanumerics.contains($0) }.map(String.init).joined()
        }
        let left = fold(a)
        return !left.isEmpty && left == fold(b)
    }

    private func finish(_ attempt: ProfileVerificationAttemptRecord, claims: EvidenceClaims?, reason: String?) async throws -> ProfileVerificationOutcome {
        let now = ctx.now
        var kept: [ProfileVerifiedFactKind] = []
        if let claims {
            let values = try await ProfileService(db: db, ctx: ctx).values(consumer: attempt.consumerId)
            func text(_ key: String) -> String? {
                if case .text(let value)? = values.first(where: { $0.key == key })?.value { return value }
                return nil
            }
            kept = Self.facts(from: claims, keep: attempt.keepKinds, profileGiven: text("personal.given_name"), profileFamily: text("personal.family_name"), now: now)
            let dimensions: AssuranceDimensions
            switch claims.method {
            case .walletMdoc: dimensions = VerificationAssuranceMapper.walletDimensions(verifiedAt: now, validUntil: claims.validUntil, risk: .high)
            case .sandbox: dimensions = VerificationAssuranceMapper.sandboxDimensions(verifiedAt: now, validUntil: claims.validUntil, risk: .high)
            default: dimensions = VerificationAssuranceMapper.providerDimensions(verifiedAt: now, validUntil: claims.validUntil, risk: .high)
            }
            let keptFacts = kept
            try await db.transaction { tx in
                for kind in keptFacts {
                    try await ProfileVerifiedFactRecord.query(on: tx).filter(\.$consumerId == attempt.consumerId).filter(\.$fact == kind.rawValue).delete()
                    let fact = ProfileVerifiedFactRecord()
                    fact.id = UUID()
                    fact.consumerId = attempt.consumerId
                    fact.fact = kind.rawValue
                    fact.method = claims.method.rawValue
                    fact.assurance = dimensions.level
                    fact.policyVersion = VerifyPolicy.version
                    fact.verifiedAt = now
                    try await fact.create(on: tx)
                }
            }
        }
        attempt.status = kept.isEmpty ? "failed" : "succeeded"
        attempt.failureReason = kept.isEmpty ? (reason ?? "no_fact") : nil
        attempt.nonce = nil
        attempt.finishedAt = now
        try await attempt.update(on: db)
        // Platform trail: outcome, method, kept fact kinds and reason; never a value.
        await audit(kept.isEmpty ? "profile.verification_failed" : "profile.verified", consumer: attempt.consumerId, attempt: attempt,
                    metadata: ["kept": kept.map(\.rawValue).joined(separator: " "), "reason": attempt.failureReason ?? "none"],
                    outcome: kept.isEmpty ? .failure : .success)
        return try await outcome(consumer: attempt.consumerId, status: kept.isEmpty ? .notVerified : .verified, kept: kept)
    }

    private func outcome(consumer: UUID, status: ProfileVerificationStatus, kept: [ProfileVerifiedFactKind]) async throws -> ProfileVerificationOutcome {
        let facts = try await ProfileService(db: db, ctx: ctx).facts(consumer: consumer)
        return ProfileVerificationOutcome(status: status, facts: facts.filter { kept.contains($0.fact) })
    }

    /// The customer forgets verified facts (empty = all). Grants of `verified.*` fields then read as "no value".
    func remove(principal: ConsumerPrincipal, facts: [ProfileVerifiedFactKind]) async throws -> CustomerProfile {
        let consumer = principal.consumerId.uuid
        var query = ProfileVerifiedFactRecord.query(on: db).filter(\.$consumerId == consumer)
        if !facts.isEmpty { query = query.filter(\.$fact ~~ facts.map(\.rawValue)) }
        try await query.delete()
        _ = try await AuditService(db: db, ctx: ctx).record("profile.verified_facts_removed", principal: principal, subjectType: "profile",
                                                         metadata: ["facts": facts.isEmpty ? "all" : facts.map(\.rawValue).joined(separator: " ")])
        return try await ProfileService(db: db, ctx: ctx).profile(consumer: consumer)
    }

    // MARK: Provider webhook, purge, maintenance

    /// Called by the Didit webhook for a session that is not a business verification attempt. `true` = handled (ours).
    func handleDiditSession(_ sessionId: String) async -> VerifyService.WebhookDisposition? {
        guard let attempt = try? await ProfileVerificationAttemptRecord.query(on: db).filter(\.$providerSessionId == sessionId).first() else { return nil }
        do {
            _ = try await finalizeDocument(attempt)
            return .accepted
        } catch {
            return .retry
        }
    }

    func purge(_ attempt: ProfileVerificationAttemptRecord, didit: any DiditAPI) async {
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
            attempt.purgeNextAt = ctx.now.addingTimeInterval(VerifyService.purgeBackoff(afterFailures: attempt.purgeAttempts))
            ctx.metrics.count(.verifyPurgeFailed)
        }
        try? await attempt.update(on: db)
        _ = try? await AuditService(db: db, ctx: ctx).record(attempt.purgeStatus == "done" ? "profile.provider_purged" : "profile.provider_purge_failed",
            outcome: attempt.purgeStatus == "done" ? .success : .failure, actor: AuditActor(kind: .system, id: "profile-verify"),
            subjectType: "profile_verification_attempt", subjectId: vendorData, metadata: ["attempts": String(attempt.purgeAttempts)])
    }

    /// Every tick, gate on or off: abandoned attempts fail (nonce erased), provider sessions are purged with backoff and never given up,
    /// attempts older than 30 days that need no purge are deleted, and expired profile requests are closed.
    func runMaintenance() async throws {
        let now = ctx.now
        for attempt in try await ProfileVerificationAttemptRecord.query(on: db).filter(\.$status ~~ ["issued", "processing"])
            .filter(\.$expiresAt <= now.addingTimeInterval(-60)).limit(100).all() {
            attempt.status = "failed"
            attempt.failureReason = "abandoned"
            attempt.nonce = nil
            attempt.finishedAt = now
            try await attempt.update(on: db)
        }
        if let didit = runtime.didit {
            for attempt in try await ProfileVerificationAttemptRecord.query(on: db).filter(\.$providerSessionId != nil).filter(\.$status ~~ ["succeeded", "failed"])
                .filter(\.$purgeStatus ~~ ["pending", "failed"]).limit(50).all() where (attempt.purgeNextAt ?? .distantPast) <= now {
                await purge(attempt, didit: didit)
            }
        }
        try await ProfileVerificationAttemptRecord.query(on: db).filter(\.$createdAt < now.addingTimeInterval(-30 * 86_400)).group(.or) { group in
            group.filter(\.$providerSessionId == nil)
            group.filter(\.$purgeStatus == "done")
        }.delete()
        try await ProfileService(db: db, ctx: ctx).expireRequests()
    }

    private func audit(_ action: String, consumer: UUID, attempt: ProfileVerificationAttemptRecord, metadata: [String: String] = [:],
                       outcome: AuditEvent.Outcome = .success) async {
        var meta = metadata
        meta["method"] = attempt.method
        _ = try? await AuditService(db: db, ctx: ctx).record(action, outcome: outcome, actor: AuditActor(kind: .consumer, id: ConsumerID(consumer).description),
            consumerId: ConsumerID(consumer), subjectType: "profile_verification_attempt", subjectId: attempt.id?.uuidString.lowercased(), metadata: meta)
    }
}
