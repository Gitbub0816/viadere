import Crypto
import Foundation
import ViadereCore

// MARK: - What the business must remember

/// The approval keys **you** recorded when you confirmed each enrollment. This is the only trustworthy source of keys: **never** load them
/// from the Viadere API at verification time. The relay could add a key it controls to such a list; a key you verified and stored at
/// enrollment (`ConfirmedEnrollment`) is one it cannot.
public protocol ApprovalKeyStore: Sendable {
    /// The keys recorded for `subject` (revoked ones included, flagged `revoked`).
    func keys(for subject: SubjectRef) async throws -> [EnrolledApprovalKey]
}

/// An in-memory `ApprovalKeyStore` for tests and single-process tools. Use your database in production.
public actor InMemoryApprovalKeyStore: ApprovalKeyStore {
    private var storage: [SubjectRef: [String: EnrolledApprovalKey]] = [:]

    public init() {}

    public func add(_ key: EnrolledApprovalKey) { storage[key.subject, default: [:]][key.kid] = key }

    public func add(_ enrollment: ConfirmedEnrollment) { add(enrollment.key) }

    public func revoke(kid: String, subject: SubjectRef) {
        storage[subject]?[kid]?.revoked = true
    }

    public func keys(for subject: SubjectRef) async throws -> [EnrolledApprovalKey] { Array(storage[subject, default: [:]].values) }
}

/// The one-time-use cache for approval challenges. It is `ViadereCore.ReplayGuard`: a bounded `InMemoryReplayGuard` for one process, or an
/// implementation over your database (unique key on `(scope, nonce)`) when several instances verify results.
public typealias ApprovalReplayCache = ReplayGuard

/// A transaction as **your own system** recorded it when you created the request. The verifier recomputes the transaction digest from this,
/// never from anything the relay or the result says.
public struct PendingApproval: Sendable, Hashable {
    public var requestId: String
    public var subject: SubjectRef
    public var challenge: String
    public var details: ApprovalSubject
    /// When you set the request to expire.
    public var expiresAt: Date

    public init(requestId: String, subject: SubjectRef, challenge: String, details: ApprovalSubject, expiresAt: Date) {
        self.requestId = requestId
        self.subject = subject
        self.challenge = challenge
        self.details = details
        self.expiresAt = expiresAt
    }
}

/// Verifies signed approval results (APP-005): **the relay's status is never sufficient.**
///
/// `verify` checks, against your own records: the ES256 signature under a key you enrolled for this customer; that the result is addressed
/// to you (`aud`), for this customer (`sub`), this request, this nonce and capability; that the digest equals the digest of the transaction
/// you recorded (amount, payee, currency, reference); the clock; that the key's enrolled strength covers the authentication claimed and your
/// minimum; and that the challenge is **unused**, consuming it atomically so a replay fails. Only a returned value with
/// `decision == .approve` grants anything.
///
/// ```swift
/// let verifier = ApprovalVerifier(businessId: myId, keys: myKeyStore, replayCache: myReplayCache)
/// let result = try await client.approvalResult(resultRef: webhook.resultRef)
/// let verified = try await verifier.verify(result: result.result,
///                                          for: PendingApproval(requestId: tx.requestId, subject: tx.subject, challenge: tx.challenge,
///                                                               details: .transaction(tx.displayed), expiresAt: tx.expiresAt))
/// guard verified.decision == .approve else { return deny() }
/// ```
public struct ApprovalVerifier: Sendable {
    public let businessId: BusinessID
    private let keys: any ApprovalKeyStore
    private let replayCache: any ReplayGuard
    private let minimumAMR: ApprovalAMR?
    private let clock: @Sendable () -> Date
    private let maxClockSkew: TimeInterval

    /// - Parameters:
    ///   - minimumAMR: the weakest authentication you accept (`.biometric` for payments and sign-ins that matter).
    public init(businessId: BusinessID, keys: any ApprovalKeyStore, replayCache: any ReplayGuard, minimumAMR: ApprovalAMR? = .biometric,
                maxClockSkew: TimeInterval = 60, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.businessId = businessId
        self.keys = keys
        self.replayCache = replayCache
        self.minimumAMR = minimumAMR
        self.maxClockSkew = min(max(maxClockSkew, 0), 300)
        self.clock = clock
    }

    /// Verifies without consuming the challenge (a dry run for tests and tooling). Never grant access on this.
    public func check(result compact: String, for pending: PendingApproval) async throws -> VerifiedApproval {
        try ApprovalResultVerifier.verify(compact, expecting: expectation(pending), keys: try await keys.keys(for: pending.subject), now: clock())
    }

    /// Verifies and consumes the one-time challenge. Throws `ApprovalVerificationError` for every failure (including `.notApproved` for a
    /// signed denial and `.replayed` for a challenge already used).
    public func verify(result compact: String, for pending: PendingApproval) async throws -> VerifiedApproval {
        try await ApprovalResultVerifier.verifyAndConsume(compact, expecting: expectation(pending), keys: try await keys.keys(for: pending.subject), now: clock(), replayGuard: replayCache)
    }

    /// The signed decision of a result that verified, including a denial (which `verify` reports as an error). For showing "the customer declined".
    public func decision(of compact: String, for pending: PendingApproval) async throws -> ApprovalDecision {
        try await check(result: compact, for: pending).decision
    }

    private func expectation(_ pending: PendingApproval) -> ApprovalExpectation {
        ApprovalExpectation(audience: businessId, subject: pending.subject, requestId: pending.requestId, challenge: pending.challenge, subjectDetails: pending.details,
                            requestExpiresAt: pending.expiresAt, minimumAMR: minimumAMR, maxClockSkew: maxClockSkew)
    }
}
