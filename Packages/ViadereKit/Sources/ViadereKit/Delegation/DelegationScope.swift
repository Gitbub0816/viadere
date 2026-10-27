import Crypto
import Foundation
import ViadereCore

/// What the person is setting up in the Invite sheet. Starts with **nothing** selected: sensitive access is never
/// pre-ticked, inherited from another grant, or implied by a role.
public struct DelegationDraft: Equatable, Sendable {
    public var delegateLabel: String
    public var role: DelegationGrant.Role
    public var purposes: Set<InteractionPurpose>
    public var businessIds: Set<BusinessID>
    public var expiresAt: Date

    public init(delegateLabel: String = "", role: DelegationGrant.Role = .viewer, purposes: Set<InteractionPurpose> = [],
                businessIds: Set<BusinessID> = [], expiresAt: Date) {
        self.delegateLabel = delegateLabel
        self.role = role
        self.purposes = purposes
        self.businessIds = businessIds
        self.expiresAt = expiresAt
    }

    /// A blank draft that ends in 30 days.
    public static func blank(now: Date) -> DelegationDraft {
        DelegationDraft(expiresAt: now.addingTimeInterval(30 * 86_400))
    }
}

public enum DelegationIssue: Equatable, Sendable {
    case missingName
    case noPurposes
    case noBusinesses
    case expiresTooSoon
    case expiresTooFar(maxDays: Int)

    public var message: String {
        switch self {
        case .missingName: "Add a name so you can recognize this person."
        case .noPurposes: "Choose at least one kind of access."
        case .noBusinesses: "Choose at least one business."
        case .expiresTooSoon: "Pick an end date at least an hour from now."
        case .expiresTooFar(let days): "Access can last at most \(days) days."
        }
    }
}

public struct DelegationWarning: Equatable, Sendable, Identifiable {
    public enum Severity: Sendable, Equatable { case notice, caution }
    public var id: String
    public var severity: Severity
    public var title: String
    public var message: String
}

/// Pure delegation rules (spec §12: scoped roles, expiration, revocation, never silently inherit sensitive
/// permissions). The server enforces them; this lets the screen explain and block early.
public enum DelegationScopePolicy {
    /// Purposes that can be shared at all. Offers and news (marketing consent) stay personal.
    public static let delegablePurposes: [InteractionPurpose] = [.transactional, .support, .rewards, .accountService, .security]

    /// Purposes that need a biometric step-up and a clear warning before they can be granted.
    public static let sensitivePurposes: Set<InteractionPurpose> = [.security, .accountService]

    public static let minimumLifetime: TimeInterval = 3_600
    /// Core's cap (`DelegationGrant.maxLifetime`, one year).
    public static let maximumLifetime: TimeInterval = DelegationGrant.maxLifetime
    /// Sensitive scopes are limited to 30 days and must be renewed deliberately.
    public static let sensitiveMaximumLifetime: TimeInterval = 30 * 86_400

    public static func isSensitive(_ purpose: InteractionPurpose) -> Bool { sensitivePurposes.contains(purpose) }

    public static func includesSensitiveScope(_ draft: DelegationDraft) -> Bool {
        !draft.purposes.isDisjoint(with: sensitivePurposes)
    }

    /// Creating a grant with a sensitive scope requires a fresh biometric step-up.
    public static func requiresStepUp(_ draft: DelegationDraft) -> Bool { includesSensitiveScope(draft) }

    public static func maximumLifetime(for draft: DelegationDraft) -> TimeInterval {
        includesSensitiveScope(draft) ? sensitiveMaximumLifetime : maximumLifetime
    }

    public static func validate(_ draft: DelegationDraft, now: Date) -> [DelegationIssue] {
        var issues: [DelegationIssue] = []
        if draft.delegateLabel.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { issues.append(.missingName) }
        if draft.purposes.isEmpty { issues.append(.noPurposes) }
        if draft.businessIds.isEmpty { issues.append(.noBusinesses) }
        let lifetime = draft.expiresAt.timeIntervalSince(now)
        if lifetime < minimumLifetime {
            issues.append(.expiresTooSoon)
        } else if lifetime > maximumLifetime(for: draft) {
            issues.append(.expiresTooFar(maxDays: Int(maximumLifetime(for: draft) / 86_400)))
        }
        return issues
    }

    public static func isValid(_ draft: DelegationDraft, now: Date) -> Bool { validate(draft, now: now).isEmpty }

    /// Plain-language warnings shown before the person confirms. Never empty for sensitive scopes.
    public static func warnings(_ draft: DelegationDraft) -> [DelegationWarning] {
        var out: [DelegationWarning] = []
        let who = draft.delegateLabel.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? "This person" : draft.delegateLabel
        if draft.purposes.contains(.security) {
            out.append(DelegationWarning(
                id: "security", severity: .caution, title: "Security notices are sensitive",
                message: "\(who) will see sign-in checks and approval requests for these businesses, including locations and amounts. "
                    + "They can't approve sign-ins or payments for you; those always need your own device."))
        }
        if draft.purposes.contains(.accountService) {
            out.append(DelegationWarning(
                id: "account", severity: .caution, title: "Account notices are sensitive",
                message: "\(who) will see important notices about your accounts at these businesses."))
        }
        if draft.role == .manager {
            out.append(DelegationWarning(
                id: "manager", severity: .notice, title: "Managers can respond for you",
                message: "\(who) can confirm, decline and choose options on your behalf for the access you share. "
                    + "Everything they do is labeled \"on behalf of you\" and recorded."))
        }
        if includesSensitiveScope(draft) {
            out.append(DelegationWarning(
                id: "stepup", severity: .notice, title: "Face ID is required",
                message: "Sharing sensitive access needs Face ID or Touch ID. It ends automatically within 30 days, and you can revoke it at any time."))
        }
        return out
    }

    // MARK: Request and proof

    public static func request(from draft: DelegationDraft, stepUp: DelegationStepUpProof? = nil) -> DelegationInvitationRequest {
        DelegationInvitationRequest(
            delegateLabel: draft.delegateLabel.trimmingCharacters(in: .whitespacesAndNewlines),
            role: draft.role,
            purposes: draft.purposes.sorted { $0.rawValue < $1.rawValue },
            businessIds: draft.businessIds.sorted { $0.description < $1.description },
            expiresAt: ViadereDate.truncatedToMilliseconds(draft.expiresAt),
            includesSensitiveScope: includesSensitiveScope(draft),
            stepUp: stepUp)
    }

    /// Deterministic text of the scope the biometric signature covers. The server rebuilds it from the request body.
    public static func canonicalScope(of request: DelegationInvitationRequest) -> String {
        [
            "role=\(request.role.rawValue)",
            "purposes=" + request.purposes.map(\.rawValue).sorted().joined(separator: ","),
            "businesses=" + request.businessIds.map(\.description).sorted().joined(separator: ","),
            "expires=" + ViadereDate.format(request.expiresAt),
            "label=" + request.delegateLabel,
        ].joined(separator: "\n")
    }

    public static func scopeDigest(of request: DelegationInvitationRequest) -> String {
        SecureToken.sha256Hex(Data(canonicalScope(of: request).utf8))
    }

    // MARK: Copy

    public static func purposeTitle(_ purpose: InteractionPurpose) -> String { PermissionCopy.title(purpose) }

    public static func roleTitle(_ role: DelegationGrant.Role) -> String {
        switch role {
        case .viewer: "Can view"
        case .manager: "Can respond"
        }
    }

    public static func roleDetail(_ role: DelegationGrant.Role) -> String {
        switch role {
        case .viewer: "Sees updates and tickets. Can't respond."
        case .manager: "Can also confirm, decline and choose for you."
        }
    }

    /// "Orders and receipts, Rewards · Juniper Coffee and 1 more · until Nov 30"
    public static func summary(purposes: [InteractionPurpose], businessNames: [String], expiresAt: Date) -> String {
        let order = delegablePurposes
        let purposeText = order.filter { purposes.contains($0) }.map(purposeTitle).joined(separator: ", ")
        let businessText: String
        switch businessNames.count {
        case 0: businessText = "No businesses"
        case 1: businessText = businessNames[0]
        case 2: businessText = "\(businessNames[0]) and \(businessNames[1])"
        default: businessText = "\(businessNames[0]) and \(businessNames.count - 1) more"
        }
        return "\(purposeText) · \(businessText) · until \(expiresAt.formatted(date: .abbreviated, time: .omitted))"
    }

    /// Human sentence for an audit action.
    public static func auditTitle(_ entry: HouseholdAuditEntry) -> String {
        let place = entry.businessName.map { " at \($0)" } ?? ""
        let base: String
        switch entry.action {
        case "delegation.created": base = "\(entry.actorName) shared access"
        case "delegation.accepted": base = "\(entry.actorName) accepted access"
        case "delegation.revoked": base = "\(entry.actorName) ended access"
        case "delegation.expired": base = "Access expired"
        case "delegation.used": base = "\(entry.actorName) responded"
        case "delegation.denied": base = "\(entry.actorName) was blocked"
        default: base = "\(entry.actorName) · \(entry.action)"
        }
        var text = base + place
        if let onBehalf = entry.onBehalfOfName { text += " on behalf of \(onBehalf)" }
        if entry.outcome == .denied, entry.action != "delegation.denied" { text += " (blocked)" }
        return text
    }

    /// "On behalf of Alex" for an interaction that belongs to someone who delegated to this person; `nil` when it's yours.
    /// Derived from ids only: an interaction scoped to another consumer is by definition delegated.
    public static func onBehalfOfName(scopeConsumerId: ConsumerID, myConsumerId: ConsumerID?, received: [HouseholdGrant]) -> String? {
        guard let myConsumerId, scopeConsumerId != myConsumerId else { return nil }
        return received.first { $0.grant.grantorId == scopeConsumerId }?.counterpartName ?? "someone in your household"
    }
}

// MARK: - Step-up signing

public enum StepUpError: Error, Equatable, Sendable {
    /// No Face ID / Touch ID key on this device (biometrics not set up, or the key was invalidated).
    case biometricsUnavailable
    case cancelled
    case failed
    public var userMessage: String {
        switch self {
        case .biometricsUnavailable: "Sharing security access needs Face ID or Touch ID, which isn't set up on this iPhone."
        case .cancelled: "Not shared. Face ID was cancelled."
        case .failed: "We couldn't verify it's you. Try again."
        }
    }
}

/// Produces the biometric proof for a sensitive delegation with the Secure Enclave `approvalBiometric` key.
public struct DelegationStepUp: Sendable {
    private let keys: any DeviceKeyStore
    private let records: any DeviceRecordStore
    private let clock: @Sendable () -> Date

    public init(keys: any DeviceKeyStore, records: any DeviceRecordStore, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.keys = keys
        self.records = records
        self.clock = clock
    }

    public func prove(_ request: DelegationInvitationRequest, delegateLabel: String) async throws -> DelegationStepUpProof {
        guard let record = try? await records.load(), record.purposes.contains(.approvalBiometric) else { throw StepUpError.biometricsUnavailable }
        let key: any ManagedSigningKey
        do { key = try await keys.requireKey(for: .approvalBiometric) } catch { throw StepUpError.biometricsUnavailable }
        let signedAt = ViadereDate.truncatedToMilliseconds(clock())
        let proof = DelegationStepUpProof(deviceId: record.deviceId, signedAt: signedAt,
                                          scopeDigest: DelegationScopePolicy.scopeDigest(of: request), signature: "")
        let prompt = SigningPrompt(reason: String("Share access with \(delegateLabel)".prefix(90)))
        do {
            let signature = try await key.signature(for: proof.signingInput(), prompt: prompt)
            var signed = proof
            signed.signature = ViadereSignatureEncoding.encode(signature)
            return signed
        } catch let error as KeyStoreError {
            switch error {
            case .userCancelled: throw StepUpError.cancelled
            case .keyInvalidated, .keyNotFound: throw StepUpError.biometricsUnavailable
            default: throw StepUpError.failed
            }
        } catch {
            throw StepUpError.failed
        }
    }
}
