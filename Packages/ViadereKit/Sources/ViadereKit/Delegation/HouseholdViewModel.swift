import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

/// Normalizes an invitation code typed by hand: uppercase, no spaces, one hyphen in the middle ("k7m2 9qxp" -> "K7M2-9QXP").
public enum InvitationCodeInput {
    public static func normalize(_ raw: String) -> String {
        let allowed = Set("ABCDEFGHJKMNPQRSTUVWXYZ23456789")
        let characters = raw.uppercased().filter { allowed.contains($0) }.prefix(8)
        guard characters.count > 4 else { return String(characters) }
        return String(characters.prefix(4)) + "-" + String(characters.dropFirst(4))
    }

    public static func isComplete(_ text: String) -> Bool { text.count == 9 && text.contains("-") }
}

/// Settings → Household: grants given and received, inviting a delegate with a scoped, expiring grant, accepting an
/// invitation, revocation and the audit trail.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class HouseholdViewModel {
    public enum Phase: Equatable, Sendable { case idle, loading, loaded, unavailable, failed(String) }
    public enum Creation: Equatable, Sendable {
        case idle
        /// Waiting for Face ID (sensitive scopes) and the server.
        case working
        case created(DelegationInvitation)
        case failed(String)
    }
    public enum Acceptance: Equatable, Sendable {
        case idle
        case loadingPreview
        case preview(DelegationInvitationPreview)
        case accepting(DelegationInvitationPreview)
        case accepted(String)
        case failed(String)
    }

    public private(set) var overview = HouseholdOverview()
    public private(set) var audit: [HouseholdAuditEntry] = []
    public private(set) var businesses: [BusinessSummary] = []
    public private(set) var phase: Phase = .idle
    public private(set) var creation: Creation = .idle
    public private(set) var acceptance: Acceptance = .idle
    public private(set) var errorMessage: String?
    public private(set) var auditPhase: Phase = .idle
    public var draft: DelegationDraft

    private let services: ViadereServices

    public init(services: ViadereServices) {
        self.services = services
        self.draft = .blank(now: services.clock())
    }

    // MARK: Loading

    public func load() async {
        if overview.given.isEmpty, overview.received.isEmpty { phase = .loading }
        async let relationships = try? services.api.relationships()
        do {
            overview = try await services.api.household()
            phase = .loaded
        } catch let error as APIError {
            phase = error.code == .notFound ? .unavailable : .failed(error.userMessage)
        } catch {
            phase = .failed("Something went wrong.")
        }
        businesses = (await relationships ?? []).filter { $0.status == .active }.map(\.business)
            .sorted { $0.displayName < $1.displayName }
    }

    public func loadAudit() async {
        auditPhase = .loading
        do {
            audit = try await services.api.householdAudit().sorted { $0.occurredAt > $1.occurredAt }
            auditPhase = .loaded
        } catch let error as APIError {
            auditPhase = error.code == .notFound ? .unavailable : .failed(error.userMessage)
        } catch {
            auditPhase = .failed("Something went wrong.")
        }
    }

    public var activeGiven: [HouseholdGrant] { overview.given.filter { $0.status == .active || $0.status == .pending } }
    public var activeReceived: [HouseholdGrant] { overview.received.filter { $0.status == .active } }
    public var pastGrants: [HouseholdGrant] {
        (overview.given + overview.received).filter { $0.status == .expired || $0.status == .revoked }
            .sorted { ($0.grant.revokedAt ?? $0.grant.expiresAt) > ($1.grant.revokedAt ?? $1.grant.expiresAt) }
    }

    // MARK: Draft

    public func resetDraft() {
        draft = .blank(now: services.clock())
        creation = .idle
    }

    public func togglePurpose(_ purpose: InteractionPurpose) {
        guard DelegationScopePolicy.delegablePurposes.contains(purpose) else { return }
        if draft.purposes.contains(purpose) { draft.purposes.remove(purpose) } else { draft.purposes.insert(purpose) }
        clampExpiry()
    }

    public func toggleBusiness(_ id: BusinessID) {
        if draft.businessIds.contains(id) { draft.businessIds.remove(id) } else { draft.businessIds.insert(id) }
    }

    public func setRole(_ role: DelegationGrant.Role) { draft.role = role }

    /// Picks the end date as a number of days from now, within what the scope allows.
    public func setLifetime(days: Int) {
        draft.expiresAt = services.clock().addingTimeInterval(Double(days) * 86_400)
        clampExpiry()
    }

    /// Adding a sensitive purpose shortens an over-long end date instead of silently leaving an invalid draft.
    private func clampExpiry() {
        let now = services.clock()
        let limit = now.addingTimeInterval(DelegationScopePolicy.maximumLifetime(for: draft))
        if draft.expiresAt > limit { draft.expiresAt = limit }
    }

    /// Lifetimes offered in the picker (days), limited to what the scope allows (sensitive scopes cap at 30).
    public var lifetimeChoices: [Int] {
        let limit = DelegationScopePolicy.maximumLifetime(for: draft)
        return [7, 14, 30, 90, 365].filter { Double($0) * 86_400 <= limit }
    }

    public var selectedLifetimeDays: Int {
        Int((draft.expiresAt.timeIntervalSince(services.clock()) / 86_400).rounded())
    }

    public var issues: [DelegationIssue] { DelegationScopePolicy.validate(draft, now: services.clock()) }
    public var warnings: [DelegationWarning] { DelegationScopePolicy.warnings(draft) }
    public var requiresStepUp: Bool { DelegationScopePolicy.requiresStepUp(draft) }
    public var canCreate: Bool { issues.isEmpty && creation != .working }

    // MARK: Create

    /// Validates, performs the Face ID step-up for sensitive scopes, and asks the server for the invitation.
    public func createInvitation() async {
        let now = services.clock()
        guard DelegationScopePolicy.isValid(draft, now: now) else {
            creation = .failed(issues.first?.message ?? "Check the details and try again.")
            return
        }
        creation = .working
        var request = DelegationScopePolicy.request(from: draft)
        if DelegationScopePolicy.requiresStepUp(draft) {
            do {
                let proof = try await DelegationStepUp(keys: services.keys, records: services.records, clock: services.clock)
                    .prove(request, delegateLabel: request.delegateLabel)
                request.stepUp = proof
            } catch let error as StepUpError {
                creation = error == .cancelled ? .idle : .failed(error.userMessage)
                return
            } catch {
                creation = .failed(StepUpError.failed.userMessage)
                return
            }
        }
        do {
            let invitation = try await services.api.createDelegationInvitation(request)
            creation = .created(invitation)
            await load()
        } catch let error as APIError {
            creation = .failed(error.userMessage)
        } catch {
            creation = .failed("Something went wrong. Please try again.")
        }
    }

    // MARK: Revoke

    public func revoke(_ grant: HouseholdGrant) async {
        errorMessage = nil
        do {
            try await services.api.revokeDelegation(grant.id)
            await load()
        } catch {
            errorMessage = (error as? APIError)?.userMessage ?? "Couldn't end that access."
        }
    }

    // MARK: Accept

    public func previewInvitation(code: String) async {
        guard InvitationCodeInput.isComplete(code) else { acceptance = .failed("Enter the 8-character code."); return }
        acceptance = .loadingPreview
        do {
            acceptance = .preview(try await services.api.previewDelegationInvitation(code: code))
        } catch let error as APIError {
            acceptance = .failed(error.code == .notFound || error.code == .gone || error.code == .expired
                                 ? "That code isn't valid any more. Ask for a new one." : error.userMessage)
        } catch {
            acceptance = .failed("Something went wrong. Please try again.")
        }
    }

    public func acceptInvitation(code: String) async {
        guard case .preview(let preview) = acceptance else { return }
        acceptance = .accepting(preview)
        do {
            let grant = try await services.api.acceptDelegationInvitation(code: code)
            acceptance = .accepted(grant.counterpartName)
            await load()
        } catch let error as APIError {
            acceptance = .failed(error.userMessage)
        } catch {
            acceptance = .failed("Something went wrong. Please try again.")
        }
    }

    public func resetAcceptance() { acceptance = .idle }

    // MARK: Display

    public func summary(_ grant: HouseholdGrant) -> String {
        DelegationScopePolicy.summary(purposes: grant.grant.purposes, businessNames: grant.businessNames, expiresAt: grant.grant.expiresAt)
    }

    public func statusText(_ grant: HouseholdGrant) -> String {
        switch grant.status {
        case .pending: "Waiting for \(grant.counterpartName) to accept"
        case .active: "Active"
        case .expired: "Expired"
        case .revoked: "Ended"
        }
    }
}
