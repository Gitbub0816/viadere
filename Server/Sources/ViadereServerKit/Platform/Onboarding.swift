import Fluent
import Foundation
import ViadereCore

// MARK: - The state machine (pure)

/// The stages of spec §8.1. A business sits in the first stage that is not complete; access is decided by the specific facts a capability
/// needs (`OnboardingGate`), not by the stage name.
enum OnboardingStage: String, CaseIterable, Sendable, Comparable {
    /// 1. Workspace: verified email, account security, organization and intended use.
    case workspace
    /// 2. Prove organizational control: a verified domain, the legal entity reviewed by an operator, extra checks for sensitive categories.
    case control
    /// 3. Public identity: handle and permanent code issued by the operator's approval of the application.
    case identity
    /// 4. Contract acceptance: every required document at its current version.
    case contracts
    /// 5. Integration: a sandbox key, a test customer and a test event.
    case integration
    /// 6. Go-live review: requested by the business, decided by an operator.
    case goLive
    /// 7. Production, under ongoing assurance.
    case live

    static func < (lhs: OnboardingStage, rhs: OnboardingStage) -> Bool {
        (allCases.firstIndex(of: lhs) ?? 0) < (allCases.firstIndex(of: rhs) ?? 0)
    }
}

enum OnboardingReview: String, Sendable, Equatable { case none, submitted, approved, rejected }
enum OnboardingEnhanced: String, Sendable, Equatable { case notRequired = "not_required", pending, approved, rejected }
enum OnboardingGoLive: String, Sendable, Equatable { case none, requested, approved, rejected }

/// What blocks a go-live request or its approval.
enum OnboardingBlocker: String, Sendable, Equatable, CaseIterable {
    case domain, legalEntity = "legal_entity", enhancedReview = "enhanced_review", identity, contracts
    case sandboxKey = "sandbox_key", testCustomer = "test_customer", testEvent = "test_event", securityContact = "security_contact"

    var title: String {
        switch self {
        case .domain: "Verify a domain you control"
        case .legalEntity: "Have your legal entity reviewed"
        case .enhancedReview: "Complete the additional review for your category"
        case .identity: "Have your application approved (handle and code)"
        case .contracts: "Accept the current agreements"
        case .sandboxKey: "Create a sandbox API key"
        case .testCustomer: "Create a test customer"
        case .testEvent: "Send a test message or event"
        case .securityContact: "Add a security contact"
        }
    }
}

enum OnboardingEvent: String, Sendable, Equatable, CaseIterable {
    case domainVerified, legalSubmitted, legalApproved, legalRejected
    case enhancedRequired, enhancedApproved, enhancedRejected
    case identityVerified, contractsAccepted, contractsLapsed
    case sandboxKeyIssued, sandboxRelationshipCreated, testEventSent, securityContactSet
    case goLiveRequested, goLiveApproved, goLiveRejected, goLiveRevoked
    case suspended, reinstated
}

enum OnboardingError: Error, Equatable {
    case invalidTransition(OnboardingEvent, OnboardingStage)
    case blocked([OnboardingBlocker])
}

/// Everything the machine needs, as plain facts.
struct OnboardingState: Sendable, Equatable {
    var domainVerified = false
    var legalEntity = OnboardingReview.none
    var enhanced = OnboardingEnhanced.notRequired
    var identityVerified = false
    var contractsCurrent = false
    var sandboxKey = false
    var testCustomer = false
    var testEvent = false
    var securityContact = false
    var goLive = OnboardingGoLive.none
    var suspended = false

    var controlComplete: Bool { domainVerified && legalEntity == .approved && (enhanced == .notRequired || enhanced == .approved) }
    var integrationComplete: Bool { sandboxKey && testCustomer && testEvent }

    var stage: OnboardingStage {
        if !controlComplete { return .control }
        if !identityVerified { return .identity }
        if !contractsCurrent { return .contracts }
        if !integrationComplete { return .integration }
        return goLive == .approved ? .live : .goLive
    }

    /// What stands between this business and a go-live **request**.
    var requestBlockers: [OnboardingBlocker] {
        var out: [OnboardingBlocker] = []
        if !domainVerified { out.append(.domain) }
        if legalEntity != .approved { out.append(.legalEntity) }
        if enhanced == .pending || enhanced == .rejected { out.append(.enhancedReview) }
        if !contractsCurrent { out.append(.contracts) }
        if !sandboxKey { out.append(.sandboxKey) }
        if !testCustomer { out.append(.testCustomer) }
        if !testEvent { out.append(.testEvent) }
        if !securityContact { out.append(.securityContact) }
        return out
    }

    /// The same list plus what only an operator can complete before approving (the public identity).
    var approvalBlockers: [OnboardingBlocker] { requestBlockers + (identityVerified ? [] : [.identity]) }
}

enum OnboardingStateMachine {
    /// Applies one event. Every event is valid only from the states below; anything else throws, so a client cannot skip a stage by calling
    /// a later action first (`goLiveApproved` needs a request, which needs every earlier fact).
    static func apply(_ event: OnboardingEvent, to state: OnboardingState) throws -> OnboardingState {
        var next = state
        func reject() -> OnboardingError { .invalidTransition(event, state.stage) }
        switch event {
        case .domainVerified:
            next.domainVerified = true
        case .legalSubmitted:
            guard state.domainVerified else { throw OnboardingError.blocked([.domain]) }
            guard state.legalEntity == .none || state.legalEntity == .rejected else { throw reject() }
            next.legalEntity = .submitted
        case .legalApproved:
            guard state.legalEntity == .submitted else { throw reject() }
            next.legalEntity = .approved
        case .legalRejected:
            guard state.legalEntity == .submitted else { throw reject() }
            next.legalEntity = .rejected
        case .enhancedRequired:
            guard state.enhanced == .notRequired || state.enhanced == .rejected else { throw reject() }
            next.enhanced = .pending
        case .enhancedApproved:
            guard state.enhanced == .pending else { throw reject() }
            next.enhanced = .approved
        case .enhancedRejected:
            guard state.enhanced == .pending else { throw reject() }
            next.enhanced = .rejected
        case .identityVerified:
            next.identityVerified = true
        case .contractsAccepted:
            next.contractsCurrent = true
        case .contractsLapsed:
            next.contractsCurrent = false
        case .sandboxKeyIssued:
            guard state.domainVerified else { throw OnboardingError.blocked([.domain]) }
            next.sandboxKey = true
        case .sandboxRelationshipCreated:
            guard state.sandboxKey else { throw OnboardingError.blocked([.sandboxKey]) }
            next.testCustomer = true
        case .testEventSent:
            guard state.testCustomer else { throw OnboardingError.blocked([.testCustomer]) }
            next.testEvent = true
        case .securityContactSet:
            next.securityContact = true
        case .goLiveRequested:
            guard state.goLive == .none || state.goLive == .rejected else { throw reject() }
            let blockers = state.requestBlockers
            guard blockers.isEmpty else { throw OnboardingError.blocked(blockers) }
            next.goLive = .requested
        case .goLiveApproved:
            guard state.goLive == .requested else { throw reject() }
            let blockers = state.approvalBlockers
            guard blockers.isEmpty else { throw OnboardingError.blocked(blockers) }
            next.goLive = .approved
        case .goLiveRejected:
            guard state.goLive == .requested else { throw reject() }
            next.goLive = .rejected
        case .goLiveRevoked:
            guard state.goLive == .approved else { throw reject() }
            next.goLive = .rejected
        case .suspended:
            next.suspended = true
        case .reinstated:
            guard state.suspended else { throw reject() }
            next.suspended = false
        }
        return next
    }
}

// MARK: - Access gate

enum OnboardingGate {
    /// Whether a key of this mode may be used for this business **now**.
    /// - A verified business may use test keys, and live keys once go-live is approved (a business without an onboarding row predates it and
    ///   is judged by its status alone).
    /// - A pending business (application not yet approved) may use only test keys, and only after its domain control was verified.
    /// - Suspended and revoked businesses may use nothing.
    static func allows(business: BusinessRecord, livemode: Bool, on db: any Database) async throws -> Bool {
        guard let id = business.id else { return false }
        switch business.status {
        case .verified:
            guard livemode else { return true }
            guard let row = try await BusinessOnboardingRecord.query(on: db).filter(\.$businessId == id).first() else { return true }
            return row.goLiveStatus == OnboardingGoLive.approved.rawValue
        case .pending:
            guard !livemode else { return false }
            return try await BusinessOnboardingRecord.query(on: db).filter(\.$businessId == id).first()?.controlVerifiedAt != nil
        case .suspended, .revoked:
            return false
        }
    }
}

// MARK: - Service

struct OnboardingService {
    let db: any Database
    let ctx: ServerContext

    static let sensitiveCategories: Set<String> = ["banking", "healthcare", "government"]

    // MARK: Creation

    /// The onboarding row of a new business (call inside the sign-up transaction).
    static func create(businessId: UUID, category: String, now: Date, on db: any Database) async throws {
        let row = BusinessOnboardingRecord(businessId: businessId, now: now)
        if sensitiveCategories.contains(category) { row.enhancedStatus = OnboardingEnhanced.pending.rawValue }
        try await row.create(on: db)
    }

    func row(_ businessId: UUID) async throws -> BusinessOnboardingRecord {
        if let found = try await BusinessOnboardingRecord.query(on: db).filter(\.$businessId == businessId).first() { return found }
        guard let business = try await BusinessRecord.find(businessId, on: db) else { throw APIError.notFound }
        let created = BusinessOnboardingRecord(businessId: businessId, now: ctx.now)
        if Self.sensitiveCategories.contains(business.category) { created.enhancedStatus = OnboardingEnhanced.pending.rawValue }
        if business.status == .verified { created.grandfathered = true; created.goLiveStatus = OnboardingGoLive.approved.rawValue }
        do { try await created.create(on: db) } catch {
            if error.isConstraintViolation, let found = try await BusinessOnboardingRecord.query(on: db).filter(\.$businessId == businessId).first() { return found }
            throw error
        }
        return created
    }

    // MARK: State

    func state(businessId: UUID) async throws -> OnboardingState {
        let row = try await row(businessId)
        guard let business = try await BusinessRecord.find(businessId, on: db) else { throw APIError.notFound }
        var state = OnboardingState()
        state.domainVerified = row.controlVerifiedAt != nil
        state.legalEntity = OnboardingReview(rawValue: row.legalStatus) ?? .none
        state.enhanced = OnboardingEnhanced(rawValue: row.enhancedStatus) ?? .notRequired
        state.identityVerified = business.status == .verified || business.status == .suspended
        state.contractsCurrent = try await ContractService(db: db, ctx: ctx).outstanding(businessId: businessId).isEmpty
        state.sandboxKey = row.sandboxKeyAt != nil
        state.testCustomer = row.sandboxRelationshipAt != nil
        state.testEvent = row.testEventAt != nil
        state.securityContact = try await SecuritySettings(db: db, ctx: ctx).contacts(businessId: businessId).isEmpty == false
        state.goLive = OnboardingGoLive(rawValue: row.goLiveStatus) ?? .none
        state.suspended = business.status == .suspended
        return state
    }

    /// Runs `event` through the machine (rejecting an invalid transition) and writes the facts it changes.
    @discardableResult
    func apply(_ event: OnboardingEvent, businessId: UUID, actor: AuditActor, metadata: [String: String] = [:],
               write: (BusinessOnboardingRecord, Date) -> Void = { _, _ in }) async throws -> OnboardingState {
        let current = try await state(businessId: businessId)
        let next = try OnboardingStateMachine.apply(event, to: current)
        let row = try await row(businessId)
        let now = ctx.now
        write(row, now)
        row.updatedAt = now
        try await row.update(on: db)
        var meta = metadata
        meta["stage"] = next.stage.rawValue
        _ = try await AuditService(db: db, ctx: ctx).record("onboarding.\(event.rawValue)", actor: actor, businessId: BusinessID(businessId),
                                                          subjectType: "onboarding", subjectId: businessId.uuidString.lowercased(), metadata: meta)
        return next
    }

    // MARK: Facts reported by other services (idempotent: a repeated report changes nothing)

    func domainVerified(businessId: UUID, domain: String, method: String) async throws {
        let row = try await row(businessId)
        guard row.controlVerifiedAt == nil else { return }
        try await apply(.domainVerified, businessId: businessId, actor: AuditActor(kind: .system), metadata: ["method": method]) { row, now in
            row.controlVerifiedAt = now
            row.controlMethod = method
            row.controlDomain = domain
        }
    }

    func sandboxKeyIssued(businessId: UUID) async throws {
        let current = try await row(businessId)
        guard current.sandboxKeyAt == nil else { return }
        // An operator-approved business may hold test keys before its domain is verified (`OnboardingGate`); the fact is recorded, and the
        // domain stays an open go-live blocker. The machine's ordering rule applies to the event, not to a key that already exists.
        guard current.controlVerifiedAt != nil else {
            current.sandboxKeyAt = ctx.now
            current.updatedAt = ctx.now
            try await current.update(on: db)
            return
        }
        try await apply(.sandboxKeyIssued, businessId: businessId, actor: AuditActor(kind: .system)) { row, now in row.sandboxKeyAt = now }
    }

    func sandboxRelationshipCreated(businessId: UUID) async throws {
        let row = try await row(businessId)
        guard row.sandboxRelationshipAt == nil else { return }
        // A business that created a sandbox customer with a test key necessarily has a sandbox key (keys issued before onboarding existed).
        if row.sandboxKeyAt == nil, row.controlVerifiedAt != nil { try await sandboxKeyIssued(businessId: businessId) }
        guard try await self.row(businessId).sandboxKeyAt != nil else { return }
        try await apply(.sandboxRelationshipCreated, businessId: businessId, actor: AuditActor(kind: .system)) { row, now in row.sandboxRelationshipAt = now }
    }

    func testEventSent(businessId: UUID) async throws {
        let row = try await row(businessId)
        guard row.testEventAt == nil, row.sandboxRelationshipAt != nil else { return }
        try await apply(.testEventSent, businessId: businessId, actor: AuditActor(kind: .system)) { row, now in row.testEventAt = now }
    }

    func identityVerified(businessId: UUID, operatorId: UUID) async throws {
        try await apply(.identityVerified, businessId: businessId, actor: AuditActor(kind: .operator_, id: operatorId.uuidString.lowercased()))
    }

    // MARK: Legal entity (operator review fields; no documents are stored)

    func submitLegalEntity(businessId: UUID, registryNumber: String, jurisdiction: String, registryName: String, evidence: [String], by userId: UUID) async throws {
        func clean(_ value: String, max: Int) throws -> String {
            let text = value.trimmingCharacters(in: .whitespacesAndNewlines)
            guard (1...max).contains(text.count), !text.unicodeScalars.contains(where: { CharacterSet.controlCharacters.contains($0) }) else {
                throw APIError.validation("Check the legal entity details.", details: ["legalEntity": "invalid"])
            }
            return text
        }
        let number = try clean(registryNumber, max: 64)
        let name = try clean(registryName, max: 120)
        let region = jurisdiction.trimmingCharacters(in: .whitespaces).uppercased()
        guard PolicyAdmin.isRegion(region) else { throw APIError.validation("Use an ISO region such as US or US-DE.", details: ["jurisdiction": "invalid"]) }
        let refs = try evidence.map { try clean($0, max: 160) }
        guard !refs.isEmpty, refs.count <= 5 else {
            throw APIError.validation("List one to five references to your registration evidence (a registry URL or record id). Do not upload documents.", details: ["evidence": "invalid"])
        }
        try await apply(.legalSubmitted, businessId: businessId, actor: AuditActor(kind: .business, id: userId.uuidString.lowercased())) { row, now in
            row.legalStatus = OnboardingReview.submitted.rawValue
            row.legalRegistryNumber = number
            row.legalRegistryName = name
            row.legalJurisdiction = region
            row.legalEvidenceRefs = refs.joined(separator: "\n")
            row.legalSubmittedAt = now
            row.legalReviewedBy = nil
            row.legalReviewedAt = nil
            row.legalNote = nil
        }
    }

    func reviewLegalEntity(businessId: UUID, approve: Bool, note rawNote: String?, operatorId: UUID) async throws {
        let note = rawNote.map { String($0.prefix(500)) }
        try await apply(approve ? .legalApproved : .legalRejected, businessId: businessId,
                        actor: AuditActor(kind: .operator_, id: operatorId.uuidString.lowercased())) { row, now in
            row.legalStatus = (approve ? OnboardingReview.approved : .rejected).rawValue
            row.legalReviewedBy = operatorId.uuidString.lowercased()
            row.legalReviewedAt = now
            row.legalNote = note
        }
    }

    /// Extra checks for sensitive categories: an operator records the reference of the review that was done.
    func reviewEnhanced(businessId: UUID, approve: Bool, reference rawReference: String, operatorId: UUID) async throws {
        let reference = rawReference.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (4...120).contains(reference.count) else { throw APIError.validation("Record the reference of the review.", details: ["reference": "required"]) }
        let current = try await state(businessId: businessId)
        // A business outside the sensitive categories can still be put under review by an operator.
        if current.enhanced == .notRequired {
            try await apply(.enhancedRequired, businessId: businessId, actor: AuditActor(kind: .operator_, id: operatorId.uuidString.lowercased())) { row, _ in
                row.enhancedStatus = OnboardingEnhanced.pending.rawValue
            }
        }
        try await apply(approve ? .enhancedApproved : .enhancedRejected, businessId: businessId,
                        actor: AuditActor(kind: .operator_, id: operatorId.uuidString.lowercased())) { row, now in
            row.enhancedStatus = (approve ? OnboardingEnhanced.approved : .rejected).rawValue
            row.enhancedReference = reference
            row.enhancedReviewedBy = operatorId.uuidString.lowercased()
            row.enhancedReviewedAt = now
        }
    }

    // MARK: Contracts and the security contact feed the same machine

    /// Recomputes whether every required contract is current and reports the change.
    func contractsChanged(businessId: UUID, actor: AuditActor) async throws {
        let current = try await state(businessId: businessId)
        let outstanding = try await ContractService(db: db, ctx: ctx).outstanding(businessId: businessId)
        if outstanding.isEmpty, !current.contractsCurrent {
            // `state` already reads contracts live, so there is no stored flag to flip; record the milestone.
            _ = try await AuditService(db: db, ctx: ctx).record("onboarding.\(OnboardingEvent.contractsAccepted.rawValue)", actor: actor,
                businessId: BusinessID(businessId), subjectType: "onboarding", subjectId: businessId.uuidString.lowercased())
        }
    }

    // MARK: Go-live

    func requestGoLive(businessId: UUID, useCase rawUseCase: String, volume rawVolume: String, by userId: UUID) async throws {
        let useCase = rawUseCase.trimmingCharacters(in: .whitespacesAndNewlines)
        let volume = rawVolume.trimmingCharacters(in: .whitespacesAndNewlines)
        guard (20...1000).contains(useCase.count), (1...120).contains(volume.count) else {
            throw APIError.validation("Describe the use case (at least 20 characters) and the expected volume.", details: ["useCase": "invalid"])
        }
        do {
            try await apply(.goLiveRequested, businessId: businessId, actor: AuditActor(kind: .business, id: userId.uuidString.lowercased())) { row, now in
                row.goLiveStatus = OnboardingGoLive.requested.rawValue
                row.goLiveRequestedAt = now
                row.goLiveRequestedBy = userId.uuidString.lowercased()
                row.goLiveUseCase = useCase
                row.goLiveVolume = volume
                row.goLiveDecidedAt = nil
                row.goLiveDecidedBy = nil
                row.goLiveNote = nil
            }
        } catch let error as OnboardingError {
            throw Self.apiError(error)
        }
    }

    func decideGoLive(businessId: UUID, approve: Bool, note rawNote: String?, operatorId: UUID) async throws {
        let note = rawNote.map { String($0.prefix(500)) }
        do {
            try await apply(approve ? .goLiveApproved : .goLiveRejected, businessId: businessId,
                            actor: AuditActor(kind: .operator_, id: operatorId.uuidString.lowercased())) { row, now in
                row.goLiveStatus = (approve ? OnboardingGoLive.approved : .rejected).rawValue
                row.goLiveDecidedAt = now
                row.goLiveDecidedBy = operatorId.uuidString.lowercased()
                row.goLiveNote = note
                if approve { row.assuranceCheckedAt = now }
            }
        } catch let error as OnboardingError {
            throw Self.apiError(error)
        }
        await Notifier(db: db, ctx: ctx).notifyBusiness(businessId, roles: [.owner, .orgAdmin, .securityAdmin],
            subject: approve ? "Production access approved" : "Production access request declined",
            text: approve ? "Viadere approved production access for your organization. You can now create live API keys in the console (Developers > API keys)."
                          : "Viadere could not approve production access yet\(note.map { ": " + $0 } ?? ".") You can address the points and request again.",
            kind: "golive-decision")
    }

    /// Withdraws production access (an operator action): live keys are revoked and the request returns to `rejected`.
    func revokeGoLive(businessId: UUID, reason: String, operatorId: UUID) async throws {
        try await apply(.goLiveRevoked, businessId: businessId, actor: AuditActor(kind: .operator_, id: operatorId.uuidString.lowercased()),
                        metadata: ["reason": String(reason.prefix(200))]) { row, now in
            row.goLiveStatus = OnboardingGoLive.rejected.rawValue
            row.goLiveDecidedAt = now
            row.goLiveDecidedBy = operatorId.uuidString.lowercased()
            row.goLiveNote = String(reason.prefix(500))
        }
        _ = try await APIKeyLifecycle(db: db, ctx: ctx).revokeAll(businessId: businessId, live: true, reason: "go-live revoked: " + reason,
                                                                 actor: .operatorUser(operatorId))
    }

    static func apiError(_ error: OnboardingError) -> APIError {
        switch error {
        case .invalidTransition: .conflict("That step is not available in the current state.")
        case .blocked(let blockers):
            APIError(.conflict, .conflict, "Complete the open steps first: " + blockers.map(\.title).joined(separator: "; ") + ".",
                     details: Dictionary(uniqueKeysWithValues: blockers.map { ($0.rawValue, "open") }))
        }
    }
}
