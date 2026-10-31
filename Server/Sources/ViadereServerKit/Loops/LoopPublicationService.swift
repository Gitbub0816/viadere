import Crypto
import Fluent
import Foundation
import ViadereCore

/// Operator-console permissions (FX-3). Granted only by `ViadereServer grant-operator-permission`, checked on every request against the
/// database (a revocation takes effect at once).
enum OperatorPermission: String, CaseIterable, Sendable {
    /// Review Loop revisions (stage 2 and 3 of plan section 4.12) and operate publications (rollout, suspend, revoke, switches).
    case loopReviewer = "loop_reviewer"

    static func holds(_ permission: OperatorPermission, userId: UUID, on db: any Database) async throws -> Bool {
        try await OperatorPermissionRecord.query(on: db).filter(\.$userId == userId).filter(\.$permission == permission.rawValue)
            .filter(\.$revokedAt == nil).first() != nil
    }
}

/// The Loop review pipeline (plan section 4.12, FX-3, WP-3.2): **every Loop and every revision** passes the automated hard gate, then human
/// review by Viadere operators (two different operators for high risk or any review flag), then signing with the `loop-publication` key over
/// exactly the reviewed `definition_hash`. Business roles submit; there is no business path that publishes.
struct LoopPublicationService {
    let db: any Database
    let ctx: ServerContext

    static let maxReasonLength = 500
    static let defaultQueue = "default"

    enum ReviewStage: String { case automated, reviewer1 = "reviewer_1", reviewer2 = "reviewer_2" }

    // MARK: Submit (business)

    /// A business member submits a definition. The tenant and the author come from the authenticated console session; the publisher identity
    /// from the business record (never the document). Healthcare and prohibited categories are refused before anything is stored (FX-4 layer 1).
    func submit(businessId: UUID, authorId: UUID, definition data: Data, templateKey: String? = nil) async throws -> LoopRevisionRecord {
        guard let business = try await BusinessRecord.find(businessId, on: db) else { throw APIError.notFound }
        let category = BusinessCategory(rawValue: business.category)
        if case .refused(let reason) = LoopCategoryPolicy.loops(category) {
            _ = try? await AuditService(db: db, ctx: ctx).record("loop.submit_refused", outcome: .denied, actor: Self.businessActor(authorId),
                businessId: BusinessID(businessId), subjectType: "loop", metadata: ["reason": reason])
            throw APIError(.forbidden, .forbidden, reason == "healthcare_banned"
                ? "Healthcare organizations can't use Loops on Viadere." : "Organizations in this category can't use Loops on Viadere.")
        }
        let publisher = LoopPublisherIdentity(publisherType: .business, businessId: BusinessID(businessId), verificationStatus: business.status, category: category)
        // Brand Kit keys are checked by the Brand Kit service once kits exist on this branch; until then a `brand_kit` appearance fails the gate.
        let context = LoopValidationContext(submittingBusinessId: BusinessID(businessId), publisher: publisher, phase: .hosted, brandKitKeys: [])
        let report = LoopPolicyValidator.validate(data, context: context)
        guard let hash = report.definitionHash, let parsed = LoopDefinition.parse(data).definition, let canonical = try? parsed.canonicalJSON() else {
            throw APIError.validation("The definition could not be read.", details: Self.details(report.hits))
        }
        if let templateKey, !LoopIDs.isValid(templateKey) { throw APIError.validation("Check the template.") }
        let now = ctx.now
        let passed = report.gate.passed
        return try await db.transaction { tx in
            let definition: LoopDefinitionRecord
            if let existing = try await LoopDefinitionRecord.query(on: tx).filter(\.$businessId == businessId).filter(\.$key == parsed.key).first() {
                definition = existing
            } else {
                definition = LoopDefinitionRecord()
                definition.id = UUID()
                definition.businessId = businessId
                definition.key = parsed.key
                definition.createdBy = authorId
                definition.createdAt = now
                try await definition.create(on: tx)
            }
            let last = try await LoopRevisionRecord.query(on: tx).filter(\.$definitionId == definition.id!).sort(\.$revision, .descending).first()
            let revision = LoopRevisionRecord()
            revision.id = UUID()
            revision.definitionId = definition.id!
            revision.businessId = businessId
            revision.revision = (last?.revision ?? 0) + 1
            revision.schemaVersion = Int(parsed.schemaVersion)
            revision.definitionJSON = String(decoding: canonical, as: UTF8.self)
            revision.definitionHash = hash
            revision.state = (passed ? LoopRevisionState.inReview : .validationFailed).rawValue
            revision.riskClass = report.derivedRiskClass.rawValue
            revision.requiredReview = report.requiredReview.rawValue
            revision.ruleHitsJSON = Self.hitsJSON(report.hits)
            revision.ruleSetVersion = report.ruleSetVersion
            revision.registryVersion = report.registryVersion
            revision.templateKey = templateKey
            revision.createdBy = authorId
            revision.createdAt = now
            revision.decidedAt = passed ? nil : now
            try await revision.create(on: tx)
            try await Self.insertReview(tx, revision: revision, stage: .automated, reviewer: nil, decision: passed ? "pass" : "fail",
                                        hits: Self.hitsJSON(report.hits), notes: nil, ctx: ctx)
            let audit = AuditService(db: tx, ctx: ctx)
            _ = try await audit.record("loop.submitted", actor: Self.businessActor(authorId), businessId: BusinessID(businessId), subjectType: "loop_revision",
                                       subjectId: revision.id!.uuidString.lowercased(), metadata: ["revision": String(revision.revision), "risk": revision.riskClass])
            if !passed {
                _ = try await audit.record("loop.validation_failed", outcome: .denied, actor: AuditActor(kind: .system, id: "loop-policy-validator"),
                    businessId: BusinessID(businessId), subjectType: "loop_revision", subjectId: revision.id!.uuidString.lowercased(),
                    metadata: ["rules": report.hardGateHits.map(\.rule.rawValue).joined(separator: ",").prefix(200).description])
            }
            return revision
        }
    }

    /// The author withdraws a revision that is still waiting for review.
    func withdraw(revisionId: UUID, businessId: UUID, by userId: UUID) async throws {
        guard let revision = try await LoopRevisionRecord.query(on: db).filter(\.$id == revisionId).filter(\.$businessId == businessId).first() else { throw APIError.notFound }
        guard LoopRevisionState.canMove(from: revision.stateValue, to: .withdrawn),
              try await DB.swap(db, table: LoopRevisionRecord.schema, id: revisionId, column: "state", expected: LoopRevisionState.inReview.rawValue,
                                newValue: LoopRevisionState.withdrawn.rawValue, extra: [("decided_at", ctx.now)]) else {
            throw APIError.conflict("This revision is no longer waiting for review.")
        }
        _ = try await AuditService(db: db, ctx: ctx).record("loop.withdrawn", actor: Self.businessActor(userId), businessId: BusinessID(businessId),
                                                            subjectType: "loop_revision", subjectId: revisionId.uuidString.lowercased())
    }

    // MARK: Review (Viadere operators)

    /// One human decision. The caller (route) has already required the operator realm and a fresh passkey assertion; this checks the
    /// `loop_reviewer` permission, the reason, self-review and the stage, records the decision bound to the exact hash, and publishes when
    /// the gate says so.
    @discardableResult
    func review(revisionId: UUID, reviewerId: UUID, decision: LoopReview.Decision, reason rawReason: String?) async throws -> LoopRevisionRecord {
        guard try await OperatorPermission.holds(.loopReviewer, userId: reviewerId, on: db) else {
            _ = try? await AuditService(db: db, ctx: ctx).record("loop.review_denied", outcome: .denied, actor: Self.operatorActor(reviewerId),
                subjectType: "loop_revision", subjectId: revisionId.uuidString.lowercased(), metadata: ["reason": "missing_permission"])
            throw APIError(.forbidden, .forbidden, "You need the loop_reviewer permission to review Loops.")
        }
        let reason = (rawReason ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard !reason.isEmpty, reason.count <= Self.maxReasonLength else { throw APIError.validation("Give a reason (up to \(Self.maxReasonLength) characters).") }
        guard let revision = try await LoopRevisionRecord.find(revisionId, on: db) else { throw APIError.notFound }
        guard revision.stateValue == .inReview else { throw APIError.conflict("This revision is not waiting for review.") }
        // Self-review: the author (or anyone who already decided this revision) cannot decide it.
        if revision.createdBy == reviewerId {
            _ = try? await AuditService(db: db, ctx: ctx).record("loop.review_denied", outcome: .denied, actor: Self.operatorActor(reviewerId),
                businessId: BusinessID(revision.businessId), subjectType: "loop_revision", subjectId: revisionId.uuidString.lowercased(), metadata: ["reason": "self_review"])
            throw APIError(.forbidden, .forbidden, "Authors cannot review their own revision.")
        }
        let human = try await LoopReviewRecord.query(on: db).filter(\.$revisionId == revisionId).filter(\.$stage != ReviewStage.automated.rawValue).all()
        if human.contains(where: { $0.reviewerId == reviewerId }) {
            throw APIError(.forbidden, .forbidden, "A different reviewer has to make the second decision.")
        }
        let stage: ReviewStage = human.isEmpty ? .reviewer1 : .reviewer2
        guard human.count < 2 else { throw APIError.conflict("This revision already has two decisions.") }
        let ctx = self.ctx
        try await db.transaction { tx in
            try await Self.insertReview(tx, revision: revision, stage: stage, reviewer: reviewerId, decision: decision.rawValue, hits: nil, notes: reason, ctx: ctx)
            _ = try await AuditService(db: tx, ctx: ctx).record("loop.review_decision", outcome: decision == .approve ? .success : .denied,
                actor: Self.operatorActor(reviewerId), businessId: BusinessID(revision.businessId), subjectType: "loop_revision",
                subjectId: revisionId.uuidString.lowercased(), metadata: ["decision": decision.rawValue, "stage": stage.rawValue])
            try await LoopPublicationService(db: tx, ctx: ctx).advance(revisionId: revisionId)
        }
        let updated = try await LoopRevisionRecord.find(revisionId, on: db) ?? revision
        if updated.stateValue == .changesRequested || updated.stateValue == .rejected || updated.stateValue == .published {
            await Notifier(db: db, ctx: ctx).notifyBusiness(revision.businessId, roles: [.owner, .orgAdmin, .developer], includeSecurityContacts: false,
                subject: updated.stateValue == .published ? "Your Loop was published" : "Viadere reviewed your Loop",
                text: updated.stateValue == .published
                    ? "Viadere approved and published a revision of one of your Loops. See it in the console under Loops."
                    : "Viadere reviewed a revision of one of your Loops. See the reviewer's message in the console under Loops.",
                kind: "loop-review")
        }
        return updated
    }

    /// Re-evaluates the gate from **stored** reviews and moves the revision: rejected, changes requested, still waiting, or approved and
    /// published. The only caller of `publish`. Safe to call repeatedly.
    func advance(revisionId: UUID) async throws {
        guard let revision = try await LoopRevisionRecord.find(revisionId, on: db), revision.stateValue == .inReview else { return }
        let verdict = try await gate(revision)
        switch verdict {
        case .publishable:
            guard try await move(revision, from: .inReview, to: .approved) else { throw APIError.conflict("This revision changed; reload.") }
            try await publish(revisionId: revisionId)
        case .awaitingReview:
            return
        case .refused(.rejected):
            _ = try await move(revision, from: .inReview, to: .rejected)
        case .refused(.changesRequested):
            _ = try await move(revision, from: .inReview, to: .changesRequested)
        case .refused(.hardGate), .refused(.validationStale):
            // The rule set or registry changed since submission, or the stored document no longer passes: it can never be published.
            _ = try await move(revision, from: .inReview, to: .rejected)
        case .refused(.selfReview):
            throw APIError(.forbidden, .forbidden, "Authors cannot review their own revision.")
        }
    }

    /// The gate over the stored document and the stored human reviews (the hard gate runs again here, on publish).
    func gate(_ revision: LoopRevisionRecord) async throws -> LoopPublicationVerdict {
        guard let business = try await BusinessRecord.find(revision.businessId, on: db) else { throw APIError.notFound }
        let publisher = LoopPublisherIdentity(publisherType: .business, businessId: BusinessID(revision.businessId), verificationStatus: business.status,
                                              category: BusinessCategory(rawValue: business.category))
        let report = LoopPolicyValidator.validate(Data(revision.definitionJSON.utf8),
                                                  context: LoopValidationContext(submittingBusinessId: BusinessID(revision.businessId), publisher: publisher, brandKitKeys: []))
        let reviews = try await LoopReviewRecord.query(on: db).filter(\.$revisionId == revision.id!).filter(\.$stage != ReviewStage.automated.rawValue).all()
            .compactMap { record -> LoopReview? in
                guard let reviewer = record.reviewerId, let decision = LoopReview.Decision(rawValue: record.decision) else { return nil }
                return LoopReview(reviewerId: reviewer.uuidString.lowercased(), decision: decision, definitionHash: record.definitionHash)
            }
        return LoopPublicationGate.evaluate(report: report, definitionHash: revision.definitionHash, authorIds: [revision.createdBy.uuidString.lowercased()],
                                            reviews: reviews)
    }

    /// Signs and publishes an **approved** revision. Recomputes the gate and refuses unless it is publishable for exactly the stored hash,
    /// so no caller (and no state flipped behind the service's back) can get an unreviewed revision signed.
    func publish(revisionId: UUID) async throws {
        guard let revision = try await LoopRevisionRecord.find(revisionId, on: db) else { throw APIError.notFound }
        guard revision.stateValue == .approved else { throw APIError.conflict("Only an approved revision can be published.") }
        guard case .publishable(let hash, let reviewers) = try await gate(revision), ConstantTime.equals(hash, revision.definitionHash) else {
            _ = try? await AuditService(db: db, ctx: ctx).record("loop.publish_refused", outcome: .denied, actor: AuditActor(kind: .system, id: "loop-publication"),
                businessId: BusinessID(revision.businessId), subjectType: "loop_revision", subjectId: revisionId.uuidString.lowercased())
            throw APIError(.forbidden, .forbidden, "This revision has not passed review.")
        }
        let now = ctx.now
        let previous = try await LoopPublicationRecord.query(on: db).filter(\.$definitionId == revision.definitionId)
            .filter(\.$status ~~ [LoopPublicationStatus.active.rawValue, LoopPublicationStatus.suspended.rawValue]).all()
        let publicationId = UUID()
        let jws = try await sign(publicationId: publicationId, revision: revision, validFrom: now)
        let publication = LoopPublicationRecord()
        publication.id = publicationId
        publication.revisionId = revisionId
        publication.definitionId = revision.definitionId
        publication.businessId = revision.businessId
        publication.revision = revision.revision
        publication.manifestJWS = jws.compact
        publication.kid = jws.kid
        publication.definitionHash = hash
        publication.status = LoopPublicationStatus.active.rawValue
        // Allow-list rollout: a first publication starts with the allow-list only; a new revision keeps the audience of the one it replaces.
        publication.rolloutPercent = previous.first(where: { $0.statusValue == .active })?.rolloutPercent ?? 0
        publication.validFrom = now
        publication.notAfter = jws.notAfter
        publication.createdAt = now
        try await publication.create(on: db)
        for old in previous {
            try await LoopPublicationRecord.query(on: db).filter(\.$id == old.id!).set(\.$status, to: LoopPublicationStatus.retired.rawValue)
                .set(\.$statusReason, to: "superseded").set(\.$statusChangedAt, to: now).set(\.$supersededBy, to: publicationId).update()
            _ = try await DB.swap(db, table: LoopRevisionRecord.schema, id: old.revisionId, column: "state", expected: LoopRevisionState.published.rawValue,
                                  newValue: LoopRevisionState.superseded.rawValue)
        }
        guard try await move(revision, from: .approved, to: .published) else { throw APIError.conflict("This revision changed; reload.") }
        ctx.metrics.count(.loopPublished)
        _ = try await AuditService(db: db, ctx: ctx).record("loop.published", actor: AuditActor(kind: .system, id: "loop-publication"),
            businessId: BusinessID(revision.businessId), subjectType: "loop_publication", subjectId: publicationId.uuidString.lowercased(),
            metadata: ["revision_id": revisionId.uuidString.lowercased(), "definition_hash": hash, "reviewers": String(reviewers.count), "kid": jws.kid])
    }

    struct SignedManifest { var compact: String; var kid: String; var notAfter: Date }

    private func sign(publicationId: UUID, revision: LoopRevisionRecord, validFrom: Date) async throws -> SignedManifest {
        let key = ctx.config.loops.publicationKey
        let kid = KeyIdentifier.make(try key.publicKey.signingKey())
        let from = Int64(validFrom.timeIntervalSince1970.rounded(.down))
        let lifetime = Int64(min(ctx.config.loops.manifestLifetime, Double(LoopPublicationManifest.maxLifetime)))
        let manifest = LoopPublicationManifest(publisherType: .business, publisherBusinessId: BusinessID(revision.businessId),
                                               publishedDefinitionId: LoopPublicationID(publicationId), revision: Int64(revision.revision),
                                               definitionHash: revision.definitionHash, validFrom: from, notAfter: from + lifetime, kid: kid)
        do {
            let compact = try await manifest.sign(with: key)
            // Verify locally before use: a misbehaving key service cannot hand out a manifest devices would refuse.
            _ = try LoopPublicationManifest.verify(compact, keys: [PinnedManifestKey(kid: kid, publicKey: key.publicKey)], now: validFrom)
            return SignedManifest(compact: compact, kid: kid, notAfter: Date(timeIntervalSince1970: Double(from + lifetime)))
        } catch {
            ctx.metrics.count(.loopManifestSignFailed)
            throw APIError(.serviceUnavailable, .unavailable, "The Loop could not be signed. Try again later.")
        }
    }

    /// The manifest to serve: re-signed (same publication id and hash) when it is within a week of `not_after`.
    func currentManifest(_ publication: LoopPublicationRecord) async throws -> String {
        guard publication.notAfter.timeIntervalSince(ctx.now) < 7 * 86_400,
              let revision = try await LoopRevisionRecord.find(publication.revisionId, on: db), revision.stateValue == .published || revision.stateValue == .superseded,
              let signed = try? await sign(publicationId: publication.id!, revision: revision, validFrom: ctx.now) else { return publication.manifestJWS }
        try await LoopPublicationRecord.query(on: db).filter(\.$id == publication.id!).set(\.$manifestJWS, to: signed.compact).set(\.$kid, to: signed.kid)
            .set(\.$notAfter, to: signed.notAfter).update()
        return signed.compact
    }

    /// The public key set devices pin (the current key; previous kids stay verifiable while their manifests are re-signed).
    func keySet() throws -> LoopPublicationKeySet {
        let key = ctx.config.loops.publicationKey
        guard !(key is UnavailableSigningKey) else { return LoopPublicationKeySet(keys: []) }
        return LoopPublicationKeySet(keys: [.init(kid: KeyIdentifier.make(try key.publicKey.signingKey()), publicKey: Base64URL.encode(key.publicKey.x963))])
    }

    // MARK: Operating publications (operators; per-Loop and per-business kill switches)

    func setStatus(publicationId: UUID, to status: LoopPublicationStatus, operatorId: UUID, reason rawReason: String?) async throws {
        try await requireReviewer(operatorId)
        let reason = try Self.reason(rawReason)
        guard let publication = try await LoopPublicationRecord.find(publicationId, on: db) else { throw APIError.notFound }
        let from = publication.statusValue
        let allowed: Bool = switch (from, status) {
        case (.active, .suspended), (.suspended, .active), (.active, .revoked), (.suspended, .revoked), (.active, .retired), (.suspended, .retired): true
        default: false
        }
        guard allowed, try await DB.swap(db, table: LoopPublicationRecord.schema, id: publicationId, column: "status", expected: from.rawValue, newValue: status.rawValue,
                                         extra: [("status_reason", reason), ("status_changed_at", ctx.now)]) else {
            throw APIError.conflict("The Loop cannot move from \(from.rawValue) to \(status.rawValue).")
        }
        if status == .revoked { try await LoopRuntimeService(db: db, ctx: ctx).cancelOpenInstances(publicationId: publicationId, reason: "publication_revoked") }
        let action = switch status {
        case .suspended: "loop.suspended"
        case .active: "loop.resumed"
        case .revoked: "loop.revoked"
        case .retired: "loop.retired"
        }
        _ = try await AuditService(db: db, ctx: ctx).record(action, actor: Self.operatorActor(operatorId), businessId: BusinessID(publication.businessId),
            subjectType: "loop_publication", subjectId: publicationId.uuidString.lowercased(), metadata: ["reason": reason])
        if status != .active {
            await Notifier(db: db, ctx: ctx).notifyBusiness(publication.businessId, roles: [.owner, .orgAdmin, .developer], includeSecurityContacts: false,
                subject: "Viadere \(status == .suspended ? "paused" : status == .revoked ? "removed" : "retired") one of your Loops",
                text: "Viadere changed the status of one of your Loops to \(status.rawValue). Customers see a neutral paused state; no data was deleted. See the console under Loops.",
                kind: "loop-status")
        }
    }

    func setRollout(publicationId: UUID, percent: Int, operatorId: UUID, reason rawReason: String?) async throws {
        try await requireReviewer(operatorId)
        let reason = try Self.reason(rawReason)
        guard (0...100).contains(percent) else { throw APIError.validation("Choose a percentage from 0 to 100.") }
        guard let publication = try await LoopPublicationRecord.find(publicationId, on: db) else { throw APIError.notFound }
        try await LoopPublicationRecord.query(on: db).filter(\.$id == publicationId).set(\.$rolloutPercent, to: percent).update()
        _ = try await AuditService(db: db, ctx: ctx).record("loop.rollout_changed", actor: Self.operatorActor(operatorId), businessId: BusinessID(publication.businessId),
            subjectType: "loop_publication", subjectId: publicationId.uuidString.lowercased(), metadata: ["percent": String(percent), "reason": reason])
    }

    func allowList(publicationId: UUID, consumerId: UUID, operatorId: UUID) async throws {
        try await requireReviewer(operatorId)
        guard let publication = try await LoopPublicationRecord.find(publicationId, on: db) else { throw APIError.notFound }
        guard try await ConsumerRecord.find(consumerId, on: db) != nil else { throw APIError.validation("No such customer account.") }
        let row = LoopRolloutAllowRecord()
        row.publicationId = publicationId
        row.consumerId = consumerId
        row.addedBy = operatorId
        row.addedAt = ctx.now
        do { try await row.create(on: db) } catch let error where error.isConstraintViolation { return }
        _ = try await AuditService(db: db, ctx: ctx).record("loop.rollout_allowlisted", actor: Self.operatorActor(operatorId), businessId: BusinessID(publication.businessId),
            subjectType: "loop_publication", subjectId: publicationId.uuidString.lowercased())
    }

    /// The per-business switch: every Loop of the business is paused (no new instances, nothing actionable) until cleared.
    func setBusinessSwitch(businessId: UUID, on: Bool, operatorId: UUID, reason rawReason: String?) async throws {
        try await requireReviewer(operatorId)
        let reason = try Self.reason(rawReason)
        guard try await BusinessRecord.find(businessId, on: db) != nil else { throw APIError.notFound }
        let active = try await LoopSwitchRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$clearedAt == nil).all()
        if on {
            guard active.isEmpty else { return }
            let row = LoopSwitchRecord()
            row.businessId = businessId
            row.reason = reason
            row.setBy = operatorId
            row.setAt = ctx.now
            try await row.create(on: db)
        } else {
            try await LoopSwitchRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$clearedAt == nil).set(\.$clearedAt, to: ctx.now).update()
        }
        _ = try await AuditService(db: db, ctx: ctx).record(on ? "loop.business_switch_on" : "loop.business_switch_off", actor: Self.operatorActor(operatorId),
            businessId: BusinessID(businessId), subjectType: "business", subjectId: businessId.uuidString.lowercased(), metadata: ["reason": reason])
        if on {
            await Notifier(db: db, ctx: ctx).notifyBusiness(businessId, roles: [.owner, .orgAdmin, .developer], includeSecurityContacts: false,
                subject: "Viadere paused your Loops", text: "Viadere paused every Loop of your organization. Customers see a neutral paused state; no data was deleted.",
                kind: "loop-status")
        }
    }

    static func businessSwitchedOff(_ businessId: UUID, on db: any Database) async throws -> Bool {
        try await LoopSwitchRecord.query(on: db).filter(\.$businessId == businessId).filter(\.$clearedAt == nil).first() != nil
    }

    // MARK: Reports and automatic suspension

    func report(publication: LoopPublicationRecord, instance: LoopInstanceRecord, consumerId: UUID, reason: LoopReportReason) async throws {
        let row = LoopReportRecord()
        row.publicationId = publication.id!
        row.businessId = publication.businessId
        row.instanceId = instance.id!
        row.consumerId = consumerId
        row.reason = reason.rawValue
        row.state = "open"
        row.at = ctx.now
        do { try await row.create(on: db) } catch let error where error.isConstraintViolation { return }
        _ = try await AuditService(db: db, ctx: ctx).record("loop.reported", actor: AuditActor(kind: .consumer, id: consumerId.uuidString.lowercased()),
            consumerId: ConsumerID(consumerId), businessId: BusinessID(publication.businessId), subjectType: "loop_publication",
            subjectId: publication.id!.uuidString.lowercased(), metadata: ["reason": reason.rawValue])
        let reporters = try await LoopReportRecord.query(on: db).filter(\.$publicationId == publication.id!).count()
        let customers = Set(try await LoopInstanceRecord.query(on: db).filter(\.$publicationId == publication.id!).all().map(\.consumerId)).count
        guard publication.statusValue == .active, LoopReportPolicy.shouldAutoSuspend(distinctReporters: reporters, distinctCustomers: customers) else { return }
        guard try await DB.swap(db, table: LoopPublicationRecord.schema, id: publication.id!, column: "status", expected: LoopPublicationStatus.active.rawValue,
                                newValue: LoopPublicationStatus.suspended.rawValue, extra: [("status_reason", "customer_reports"), ("status_changed_at", ctx.now)]) else { return }
        ctx.metrics.count(.loopAutoSuspended)
        _ = try await AuditService(db: db, ctx: ctx).record("loop.suspended", actor: AuditActor(kind: .system, id: "loop-reports"),
            businessId: BusinessID(publication.businessId), subjectType: "loop_publication", subjectId: publication.id!.uuidString.lowercased(),
            metadata: ["reason": "customer_reports", "reporters": String(reporters)])
        await Notifier(db: db, ctx: ctx).notifyBusiness(publication.businessId, roles: [.owner, .orgAdmin, .developer], includeSecurityContacts: false,
            subject: "One of your Loops was paused", text: "Customer reports paused one of your Loops pending Viadere review. No data was deleted.", kind: "loop-status")
    }

    // MARK: Helpers

    private func move(_ revision: LoopRevisionRecord, from: LoopRevisionState, to: LoopRevisionState) async throws -> Bool {
        guard LoopRevisionState.canMove(from: from, to: to) else { return false }
        return try await DB.swap(db, table: LoopRevisionRecord.schema, id: revision.id!, column: "state", expected: from.rawValue, newValue: to.rawValue,
                                 extra: [("decided_at", ctx.now)])
    }

    private func requireReviewer(_ operatorId: UUID) async throws {
        guard try await OperatorPermission.holds(.loopReviewer, userId: operatorId, on: db) else {
            throw APIError(.forbidden, .forbidden, "You need the loop_reviewer permission.")
        }
    }

    static func reason(_ raw: String?) throws -> String {
        let reason = (raw ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard !reason.isEmpty, reason.count <= maxReasonLength else { throw APIError.validation("Give a reason (up to \(maxReasonLength) characters).") }
        return reason
    }

    static func insertReview(_ db: any Database, revision: LoopRevisionRecord, stage: ReviewStage, reviewer: UUID?, decision: String, hits: String?,
                             notes: String?, ctx: ServerContext) async throws {
        let review = LoopReviewRecord()
        review.id = UUID()
        review.revisionId = revision.id!
        review.businessId = revision.businessId
        review.stage = stage.rawValue
        review.reviewerId = reviewer
        review.decision = decision
        review.definitionHash = revision.definitionHash
        review.ruleHitsJSON = hits
        review.notesSealed = try notes.map { try ctx.cipher.seal($0, context: "loop_reviews.notes", rowId: review.id!) }
        review.at = ctx.now
        do { try await review.create(on: db) } catch let error where error.isConstraintViolation {
            throw APIError.conflict("Another reviewer decided this stage first; reload.")
        }
    }

    static func hitsJSON(_ hits: [LoopRuleHit]) -> String {
        (try? String(decoding: JSONEncoder().encode(hits), as: UTF8.self)) ?? "[]"
    }

    static func hits(_ json: String) -> [LoopRuleHit] { (try? JSONDecoder().decode([LoopRuleHit].self, from: Data(json.utf8))) ?? [] }

    static func details(_ hits: [LoopRuleHit]) -> [String: String] {
        var out: [String: String] = [:]
        for hit in hits.prefix(20) { out[hit.path.isEmpty ? "definition" : hit.path] = hit.rule.rawValue }
        return out
    }

    static func businessActor(_ id: UUID) -> AuditActor { AuditActor(kind: .business, id: id.uuidString.lowercased()) }
    static func operatorActor(_ id: UUID) -> AuditActor { AuditActor(kind: .operator_, id: id.uuidString.lowercased()) }
}
