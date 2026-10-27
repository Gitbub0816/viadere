import Fluent
import Foundation
import ViadereCore

/// Business onboarding and operator moderation.
///
/// Lifecycle: an organization applies (`pending`, **no handle and no code**) → a Viadere operator reviews →
/// `verified` (handle and permanent code are issued at that moment, never before). `suspended` blocks API keys
/// and interactions immediately (the API-key middleware re-reads the status on every request).
struct BusinessOnboarding {
    let db: any Database
    let ctx: ServerContext

    enum Failure: Error, Equatable {
        case notFound
        case notPending
        case notVerified
        case notSuspended
        case handleUnavailable
        case invalidHandle
        case invalidCeiling
    }

    // MARK: Apply

    /// Creates a pending organization, its application and the owner membership. Call inside the sign-up transaction.
    func createPending(businessId: UUID, ownerId: UUID, displayName: String, legalName: String?, category: BusinessCategory,
                       website: String?, requestedHandle: String?, description: String?) async throws -> BusinessRecord {
        let now = ctx.now
        let business = BusinessRecord(id: businessId, displayName: displayName, legalName: legalName, category: category, status: .pending,
                                      verifiedAt: nil, dailyQuota: ctx.config.freeDailyInteractionQuota, now: now)
        business.websiteURL = website
        try await business.create(on: db)
        let application = BusinessApplicationRecord()
        application.id = UUID()
        application.businessId = businessId
        application.requestedHandle = requestedHandle
        application.legalName = legalName
        application.website = website
        application.detail = description
        application.state = "pending"
        application.submittedAt = now
        try await application.create(on: db)
        let membership = OrgMembershipRecord()
        membership.id = UUID()
        membership.businessId = businessId
        membership.userId = ownerId
        membership.role = OrgRole.owner.rawValue
        membership.createdAt = now
        try await membership.create(on: db)
        try await OnboardingService.create(businessId: businessId, category: category.rawValue, now: now, on: db)
        _ = try await AuditService(db: db, ctx: ctx).record("organization.applied", actor: AuditActor(kind: .business, id: ownerId.uuidString.lowercased()),
            businessId: BusinessID(businessId), subjectType: "organization", subjectId: businessId.uuidString.lowercased())
        return business
    }

    /// A declined organization may correct its details and apply again.
    func resubmit(businessId: UUID, by userId: UUID, legalName: String?, website: String?, requestedHandle: String?, description: String?) async throws {
        guard let business = try await BusinessRecord.find(businessId, on: db), business.status == .pending,
              let application = try await BusinessApplicationRecord.query(on: db).filter(\.$businessId == businessId).first(),
              application.state == "rejected" else { throw Failure.notPending }
        application.legalName = legalName
        application.website = website
        application.requestedHandle = requestedHandle
        application.detail = description
        application.state = "pending"
        application.submittedAt = ctx.now
        application.reviewedAt = nil
        application.reviewedBy = nil
        application.decisionNote = nil
        try await application.update(on: db)
        business.legalName = legalName
        business.websiteURL = website
        try await business.update(on: db)
        _ = try await AuditService(db: db, ctx: ctx).record("organization.reapplied", actor: AuditActor(kind: .business, id: userId.uuidString.lowercased()),
            businessId: BusinessID(businessId))
    }

    // MARK: Operator decisions

    /// Verifies a pending business and issues its handle and permanent code.
    @discardableResult
    func approve(businessId: UUID, operatorId: UUID, handleOverride: String?, note: String?) async throws -> BusinessRecord {
        let now = ctx.now
        return try await db.transaction { tx in
            guard let business = try await BusinessRecord.find(businessId, on: tx) else { throw Failure.notFound }
            guard business.status == .pending, let application = try await BusinessApplicationRecord.query(on: tx).filter(\.$businessId == businessId).first(),
                  application.state == "pending" else { throw Failure.notPending }
            // Single decision: of two concurrent approvals only one flips pending → verified.
            guard try await DB.swap(tx, table: BusinessRecord.schema, id: businessId, column: "verification_status",
                                    expected: VerificationStatus.pending.rawValue, newValue: VerificationStatus.verified.rawValue,
                                    extra: [("verified_at", now)]) else { throw Failure.notPending }
            let rawHandle = (handleOverride?.isEmpty == false ? handleOverride : application.requestedHandle)?.replacingOccurrences(of: "@", with: "")
            var searchText = business.displayName.lowercased()
            if let rawHandle, !rawHandle.isEmpty {
                let handle: BusinessHandle
                do { handle = try BusinessHandle.validateForRegistration(rawHandle) } catch { throw Failure.invalidHandle }
                do { try await BusinessRegistry.checkHandleAvailable(handle, on: tx) } catch { throw Failure.handleUnavailable }
                try await BusinessHandleRecord(businessId: businessId, handle: handle, now: now).create(on: tx)
                searchText += " " + handle.value
            }
            if try await BusinessCodeRecord.query(on: tx).filter(\.$businessId == businessId).count() == 0 {
                _ = try await BusinessRegistry.issueCode(for: businessId, explicit: nil, now: now, on: tx)
            }
            try await BusinessRecord.query(on: tx).filter(\.$id == businessId).set(\.$searchText, to: searchText).update()
            application.state = "approved"
            application.reviewedAt = now
            application.reviewedBy = operatorId
            application.decisionNote = note.map { String($0.prefix(500)) }
            try await application.update(on: tx)
            try await OnboardingService(db: tx, ctx: ctx).identityVerified(businessId: businessId, operatorId: operatorId)
            _ = try await AuditService(db: tx, ctx: ctx).record("business.verified", actor: AuditActor(kind: .operator_, id: operatorId.uuidString.lowercased()),
                businessId: BusinessID(businessId), subjectType: "organization", subjectId: businessId.uuidString.lowercased())
            business.verificationStatus = VerificationStatus.verified.rawValue
            return business
        }
    }

    func reject(businessId: UUID, operatorId: UUID, note: String?) async throws {
        let now = ctx.now
        try await db.transaction { tx in
            guard let business = try await BusinessRecord.find(businessId, on: tx), business.status == .pending,
                  let application = try await BusinessApplicationRecord.query(on: tx).filter(\.$businessId == businessId).first(),
                  application.state == "pending" else { throw Failure.notPending }
            application.state = "rejected"
            application.reviewedAt = now
            application.reviewedBy = operatorId
            application.decisionNote = note.map { String($0.prefix(500)) }
            try await application.update(on: tx)
            _ = try await AuditService(db: tx, ctx: ctx).record("business.rejected", outcome: .denied,
                actor: AuditActor(kind: .operator_, id: operatorId.uuidString.lowercased()), businessId: BusinessID(businessId),
                subjectType: "organization", subjectId: businessId.uuidString.lowercased())
        }
    }

    // MARK: Suspension

    /// Suspends a verified business. Effect is immediate: the API-key middleware and `InteractionService.issue`
    /// check the status on every call, consumer decisions on its interactions are refused, and every pending
    /// interaction is cancelled (without webhooks — the business is suspended).
    func suspend(businessId: UUID, operatorId: UUID, reason: String) async throws {
        let now = ctx.now
        try await db.transaction { tx in
            guard let business = try await BusinessRecord.find(businessId, on: tx) else { throw Failure.notFound }
            guard business.status == .verified else { throw Failure.notVerified }
            guard try await DB.swap(tx, table: BusinessRecord.schema, id: businessId, column: "verification_status",
                                    expected: VerificationStatus.verified.rawValue, newValue: VerificationStatus.suspended.rawValue) else {
                throw Failure.notVerified
            }
            let controls = try await BusinessControls.loadOrCreate(businessId, now: now, on: tx)
            controls.suspensionReason = String(reason.prefix(300))
            controls.updatedAt = now
            controls.updatedBy = operatorId
            try await controls.update(on: tx)
            let pending = try await InteractionRecord.query(on: tx).filter(\.$businessId == businessId)
                .filter(\.$status == InteractionStatus.pending.rawValue).all()
            for record in pending { _ = try await InteractionService(db: tx, ctx: ctx).cancelPending(record, notify: false) }
            _ = try await AuditService(db: tx, ctx: ctx).record("business.suspended", outcome: .denied,
                actor: AuditActor(kind: .operator_, id: operatorId.uuidString.lowercased()), businessId: BusinessID(businessId),
                subjectType: "organization", subjectId: businessId.uuidString.lowercased(), metadata: ["pending_cancelled": String(pending.count)])
        }
        ctx.metrics.count(.businessSuspended)
        await Notifier(db: db, ctx: ctx).notifyBusiness(businessId, roles: [.owner, .orgAdmin, .securityAdmin], subject: "Your Viadere organization was suspended",
            text: """
            Viadere suspended your organization. API keys and interactions are blocked until it is reinstated.

            Reason: \(String(reason.prefix(300)))

            You can appeal in the console under Support, or reply to this message through the Support section.
            """, kind: "suspension")
    }

    func unsuspend(businessId: UUID, operatorId: UUID) async throws {
        let now = ctx.now
        try await db.transaction { tx in
            guard let business = try await BusinessRecord.find(businessId, on: tx) else { throw Failure.notFound }
            guard business.status == .suspended else { throw Failure.notSuspended }
            guard try await DB.swap(tx, table: BusinessRecord.schema, id: businessId, column: "verification_status",
                                    expected: VerificationStatus.suspended.rawValue, newValue: VerificationStatus.verified.rawValue) else {
                throw Failure.notSuspended
            }
            if let controls = try await BusinessControls.load(businessId, on: tx) {
                controls.suspensionReason = nil
                controls.updatedAt = now
                controls.updatedBy = operatorId
                try await controls.update(on: tx)
            }
            _ = try await AuditService(db: tx, ctx: ctx).record("business.unsuspended", actor: AuditActor(kind: .operator_, id: operatorId.uuidString.lowercased()),
                businessId: BusinessID(businessId), subjectType: "organization", subjectId: businessId.uuidString.lowercased())
        }
    }

    // MARK: Trust overrides (downward only)

    /// Lowers the priority ceiling. Accepts only `low`, `normal` or `high`: a ceiling can never *grant* priority,
    /// it can only cap what the Trust Engine already allows. Passing `nil` removes the cap (restores the default),
    /// which never exceeds the Trust Engine's own clamp.
    func setPriorityCeiling(businessId: UUID, operatorId: UUID, ceiling: InteractionPriority?) async throws {
        if let ceiling, !BusinessControls.allowedCeilings.contains(ceiling) { throw Failure.invalidCeiling }
        guard try await BusinessRecord.find(businessId, on: db) != nil else { throw Failure.notFound }
        let controls = try await BusinessControls.loadOrCreate(businessId, now: ctx.now, on: db)
        controls.priorityCeiling = ceiling?.rawValue
        controls.updatedAt = ctx.now
        controls.updatedBy = operatorId
        try await controls.update(on: db)
        _ = try await AuditService(db: db, ctx: ctx).record("business.priority_ceiling", actor: AuditActor(kind: .operator_, id: operatorId.uuidString.lowercased()),
            businessId: BusinessID(businessId), metadata: ["ceiling": ceiling?.rawValue ?? "none"])
    }

    func setThrottle(businessId: UUID, operatorId: UUID, throttled: Bool, reason: String?) async throws {
        guard try await BusinessRecord.find(businessId, on: db) != nil else { throw Failure.notFound }
        let now = ctx.now
        let controls = try await BusinessControls.loadOrCreate(businessId, now: now, on: db)
        controls.throttled = throttled
        controls.throttleSource = throttled ? "operator" : nil
        controls.throttleReason = throttled ? String((reason ?? "operator").prefix(200)) : nil
        controls.throttledAt = throttled ? now : nil
        controls.updatedAt = now
        controls.updatedBy = operatorId
        try await controls.update(on: db)
        _ = try await AuditService(db: db, ctx: ctx).record(throttled ? "business.throttled" : "business.throttle_cleared",
            actor: AuditActor(kind: .operator_, id: operatorId.uuidString.lowercased()), businessId: BusinessID(businessId))
    }
}
