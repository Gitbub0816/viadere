import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

/// The state behind every Approve v2 screen: requests waiting for a decision, enrollment, the keys held per business, freeze, and the
/// directory warnings. All crypto lives in the flows; this type only sequences them and phrases failures for the person.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class ApproveController {
    public enum Phase: Equatable, Sendable { case idle, loading, working }

    public private(set) var phase: Phase = .idle
    public private(set) var prompts: [ApprovalPrompt] = []
    public private(set) var rejected: [RejectedRequest] = []
    public private(set) var keys: [LocalApprovalKey] = []
    public private(set) var freeze = ApproveFreezeState(entries: [])
    /// Directory alerts by business id description.
    public private(set) var alerts: [String: DirectoryAlert] = [:]
    public private(set) var offer: EnrollmentOffer?
    public private(set) var message: String?
    public private(set) var confirmations: [ConfirmationOutcome] = []
    /// The request sheet's content. Set when a verified request arrives; cleared when the person closes the sheet or answers.
    public var presented: ApprovalPrompt?
    private var closed: Set<UUID> = []

    private let environment: ApproveEnvironment?

    public init(environment: ApproveEnvironment?) { self.environment = environment }

    /// False when the build has no pinned log key (or the app has no Approve API): Approve v2 stays closed rather than guessing.
    public var isAvailable: Bool { environment?.isConfigured ?? false }

    public func clearMessage() { message = nil }

    /// Everything the app refreshes on open and on return to the foreground.
    public func refresh() async {
        guard let env = environment, env.isConfigured else { return }
        phase = .loading
        defer { phase = .idle }
        confirmations = (try? await env.enrollment.refreshConfirmations()) ?? []
        try? await env.enrollment.syncRevocations()
        for outcome in confirmations {
            if case .substitutionDetected = outcome {
                message = "A business confirmed a different key than the one on this phone, so we removed it. Nothing was approved."
            }
        }
        do {
            let loaded = try await env.requests.load()
            prompts = loaded.prompts
            rejected = loaded.rejected
        } catch { report(error) }
        presentNextIfIdle()
        let state = (try? await env.store.load()) ?? ApproveLocalState()
        keys = state.keys.filter { $0.status != .revoked }
        var found: [String: DirectoryAlert] = [:]
        for key in state.keys {
            if let alert = try? await env.directory.alert(for: key.businessId) { found[key.businessId.description] = alert }
        }
        for (business, change) in state.pendingRootChanges where found[business] == nil { found[business] = .rootChanged(change) }
        alerts = found
        if let state = try? await env.freeze.state() { freeze = state }
    }

    // MARK: Enrollment

    public func lookup(code: String, expectedRootKid: String?) async {
        guard let env = environment, env.isConfigured else { message = ApproveText.notAvailable; return }
        phase = .working
        defer { phase = .idle }
        do { offer = try await env.enrollment.lookup(code: code, expectedRootKid: expectedRootKid) } catch { offer = nil; report(error) }
    }

    public func cancelOffer() { offer = nil }

    @discardableResult
    public func confirmEnrollment() async -> Bool {
        guard let env = environment, let offer else { return false }
        phase = .working
        defer { phase = .idle }
        do {
            _ = try await env.enrollment.enroll(offer)
            self.offer = nil
            await refresh()
            return true
        } catch { report(error); return false }
    }

    // MARK: Requests

    /// Answers `prompt`. Returns whether the answer was accepted by the relay.
    @discardableResult
    public func answer(_ prompt: ApprovalPrompt, _ decision: ApprovalDecision) async -> Bool {
        guard let env = environment else { return false }
        phase = .working
        defer { phase = .idle }
        do {
            _ = try await env.requests.answer(prompt, decision: decision)
            prompts.removeAll { $0.id == prompt.id }
            if presented?.id == prompt.id { presented = nil }
            presentNextIfIdle()
            return true
        } catch { report(error); return false }
    }

    /// The person closed the sheet without answering: it stays in the list, but is not pushed at them again until the next launch.
    public func closePresented() {
        if let id = presented?.id { closed.insert(id) }
        presented = nil
    }

    public func present(_ prompt: ApprovalPrompt) { closed.remove(prompt.id); presented = prompt }

    private func presentNextIfIdle() {
        guard presented == nil, let next = prompts.first(where: { !closed.contains($0.id) }) else { return }
        presented = next
    }

    public func dismissRejected(_ id: UUID) { rejected.removeAll { $0.id == id } }

    // MARK: Keys and directory

    public func revoke(_ key: LocalApprovalKey) async {
        guard let env = environment else { return }
        phase = .working
        defer { phase = .idle }
        do { try await env.enrollment.revoke(kid: key.kid); await refresh() } catch { report(error) }
    }

    public func acceptRootChange(businessId: BusinessID) async {
        guard let env = environment else { return }
        do { try await env.directory.acceptRootChange(businessId: businessId); await refresh() } catch { report(error) }
    }

    public func acknowledgeConflict(businessId: BusinessID) async {
        guard let env = environment else { return }
        do { try await env.directory.acknowledgeConflict(businessId: businessId); await refresh() } catch { report(error) }
    }

    // MARK: Freeze

    public var accountFrozen: Bool { freeze.accountFrozen }

    public func isFrozen(relationship id: RelationshipID) -> Bool {
        freeze.entries.contains { $0.scope == .relationship && $0.relationshipId == id }
    }

    public func setAccountFrozen(_ frozen: Bool) async { await setFreeze(scope: .account, relationshipId: nil, frozen: frozen) }

    public func setFrozen(_ frozen: Bool, relationship id: RelationshipID) async { await setFreeze(scope: .relationship, relationshipId: id, frozen: frozen) }

    private func setFreeze(scope: ApproveFreezeScope, relationshipId: RelationshipID?, frozen: Bool) async {
        guard let env = environment else { return }
        phase = .working
        defer { phase = .idle }
        do {
            freeze = frozen ? try await env.freeze.freeze(scope: scope, relationshipId: relationshipId)
                            : try await env.freeze.unfreeze(scope: scope, relationshipId: relationshipId)
        } catch { report(error) }
    }

    // MARK: Failures

    private func report(_ error: Error) { message = ApproveText.message(for: error) }
}

/// Calm, specific wording for the failures of Approve v2. None of them blames the person; none says "error".
public enum ApproveText {
    public static let notAvailable = "Approvals with this business aren't available in this version of the app."

    public static func message(for error: Error) -> String {
        guard let error = error as? ApproveError else { return "We couldn't reach Viadere. Nothing was approved." }
        switch error {
        case .notConfigured: return notAvailable
        case .api(let api): return api.userMessage
        case .directory, .directoryHasNoRoot: return "We couldn't verify this business's keys, so we didn't continue."
        case .businessNotReady: return "This business isn't ready to set up approvals yet. Ask them to try again."
        case .rootMismatchWithLink: return "The business key doesn't match the one in the link or code you used. Don't continue, and tell the business."
        case .rootChanged: return "This business changed its signing key. Review the change before approving anything for it."
        case .rootConflict: return "This business's key history doesn't match what this phone remembers. Approvals are paused for it."
        case .deviceCannotSatisfy: return "This phone can't use Face ID or Touch ID for this action."
        case .userCancelled: return "Cancelled. Nothing was approved."
        case .authenticationFailed: return "That didn't match. Nothing was approved."
        case .keyMissing: return "The key for this business is gone from this phone, for example after a Face ID change. Ask them to set up approvals again."
        case .substitutionDetected: return "A business confirmed a different key than the one on this phone, so we removed it."
        case .requestRejected(let reason): return "We hid a request that failed verification: \(reason)"
        case .frozen: return "Approvals are turned off. Turn them back on in Settings."
        case .expired: return "This request expired. Nothing was approved."
        case .notEnrolled: return "This phone isn't set up yet."
        case .keysUnavailable: return "The keys for this business aren't available right now. Try again in a moment."
        }
    }
}
