import Foundation
import ViadereCore

/// One approval key as this device knows it: what it signed at enrollment (kept to check the business's confirmation against), and where it
/// stands. The private keys are in the `ApprovalKeyVault`, never here.
public struct LocalApprovalKey: Codable, Sendable, Equatable, Identifiable {
    public enum Status: String, Codable, Sendable {
        /// Enrolled; waiting for the business's signed confirmation. It cannot approve anything yet.
        case pendingConfirmation
        case active
        /// Removed (by the customer, the business or a lifecycle event).
        case revoked
        /// The business's confirmation did not cover this device's key: the relay substituted a key. The key was removed and revoked.
        case substitutionDetected
    }

    public var id: UUID { enrollmentId }
    public var enrollmentId: UUID
    public var kid: String
    public var hpkeKid: String
    public var businessId: BusinessID
    public var businessName: String
    public var relationshipId: RelationshipID
    public var subject: SubjectRef
    public var assurance: ApprovalAMR
    public var statement: SignedStatement
    public var status: Status
    public var createdAt: Date

    public init(enrollmentId: UUID, kid: String, hpkeKid: String, businessId: BusinessID, businessName: String, relationshipId: RelationshipID, subject: SubjectRef,
                assurance: ApprovalAMR, statement: SignedStatement, status: Status, createdAt: Date) {
        self.enrollmentId = enrollmentId
        self.kid = kid
        self.hpkeKid = hpkeKid
        self.businessId = businessId
        self.businessName = businessName
        self.relationshipId = relationshipId
        self.subject = subject
        self.assurance = assurance
        self.statement = statement
        self.status = status
        self.createdAt = createdAt
    }
}

/// How a business's root key came to be trusted on this device.
public enum RootTrust: String, Codable, Sendable {
    /// The key id came with the enrollment link or QR the business displayed, and the log showed the same key: the strongest case.
    case verifiedOutOfBand
    /// Seen for the first time in the log (trust on first use, with the log as witness); the person compared the fingerprint, or did not.
    case firstUse
}

/// A pinned root plus how it was trusted.
public struct PinnedBusinessRoot: Codable, Sendable, Equatable {
    public var root: PinnedRoot
    public var trust: RootTrust
    public init(root: PinnedRoot, trust: RootTrust) {
        self.root = root
        self.trust = trust
    }
}

/// A valid succession from the pinned root to a new one: the person must confirm before this business can ask for anything again.
public struct PendingRootChange: Codable, Sendable, Equatable {
    public var businessId: BusinessID
    public var pinnedKid: String
    public var newKid: String
    public var detectedAt: Date
}

/// A prompt the customer answered, for the local fatigue warning.
public struct LocalDecision: Codable, Sendable, Equatable {
    public var businessId: BusinessID
    public var at: Date
    public var decision: ApprovalDecision
}

/// Everything the device persists for Approve v2 (one JSON value in the Keychain-backed `SecretStore`).
public struct ApproveLocalState: Codable, Sendable, Equatable {
    public var keys: [LocalApprovalKey] = []
    public var pins: [String: PinnedBusinessRoot] = [:]
    public var pendingRootChanges: [String: PendingRootChange] = [:]
    /// Businesses whose directory contradicted the pinned root (the relay or the business showed a different history): blocked.
    public var rootConflicts: [String: Date] = [:]
    /// The log head last verified; the next one must extend it.
    public var lastSeenHead: SeenTreeHead?
    public var decisions: [LocalDecision] = []
    public init() {}
}

/// Persistence for `ApproveLocalState`. Serialized: every mutation is read-modify-write under one lock.
public protocol ApproveLocalStore: Sendable {
    func load() async throws -> ApproveLocalState
    /// Applies `change` atomically.
    func update(_ change: @Sendable (inout ApproveLocalState) -> Void) async throws
    /// Forgets everything (sign-out, device revocation).
    func wipe() async throws
}

/// `ApproveLocalStore` in a `SecretStore` (the Keychain in the app, memory in tests).
public actor SecretApproveLocalStore: ApproveLocalStore {
    private let slot: JSONSecretSlot<ApproveLocalState>

    public init(secrets: any SecretStore, account: String = "approve.v2.state") {
        slot = JSONSecretSlot(secrets: secrets, account: account)
    }

    public func load() async throws -> ApproveLocalState { try slot.load() ?? ApproveLocalState() }

    public func update(_ change: @Sendable (inout ApproveLocalState) -> Void) async throws {
        var state = try slot.load() ?? ApproveLocalState()
        change(&state)
        try slot.save(state)
    }

    public func wipe() async throws { try slot.clear() }
}
