import Crypto
import Foundation

/// Pure delegation rules shared by the server (which enforces them) and the app (which explains and blocks early).
/// Spec §12: scoped roles, expiration, revocation, and never silently inheriting sensitive permissions.
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
    /// How long an invitation code stays valid.
    public static let invitationLifetime: TimeInterval = 24 * 3_600

    public static func isSensitive(_ purpose: InteractionPurpose) -> Bool { sensitivePurposes.contains(purpose) }

    /// True when any purpose is sensitive. The server recomputes this from the purposes; it never trusts the client's flag.
    public static func includesSensitiveScope(purposes: some Sequence<InteractionPurpose>) -> Bool {
        purposes.contains { sensitivePurposes.contains($0) }
    }

    public static func maximumLifetime(includesSensitive: Bool) -> TimeInterval {
        includesSensitive ? sensitiveMaximumLifetime : maximumLifetime
    }

    // MARK: Canonical scope

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

    /// Lowercase hex SHA-256 of `canonicalScope(of:)`.
    public static func scopeDigest(of request: DelegationInvitationRequest) -> String {
        SecureToken.sha256Hex(Data(canonicalScope(of: request).utf8))
    }

    // MARK: Decisions

    /// Whether a delegate holding `role` may record `decision` on an interaction of `kind` for the grantor.
    ///
    /// Delegates can **never** decide `authenticate` or `authorize` (security approvals and payments always need the
    /// owner's own device), and viewers decide nothing. Managers may confirm, decline and choose only.
    public static func delegateMayDecide(role: DelegationGrant.Role, kind: InteractionKind, decision: Decision) -> Bool {
        guard role == .manager else { return false }
        switch (kind, decision) {
        case (.confirm, .confirm), (.confirm, .decline), (.choose, .select), (.choose, .decline): return true
        default: return false
        }
    }
}

/// Verifies the biometric step-up carried by a sensitive delegation invitation.
///
/// The proof is an ECDSA signature by the device's `approvalBiometric` key over
/// `DelegationStepUpProof.signingInput()`; the digest binds it to the exact scope being granted.
public enum DelegationStepUpVerifier {
    public enum Failure: Error, Equatable, Sendable {
        case missing
        case deviceMismatch
        case scopeMismatch
        case malformedSignature
        case badSignature
        case signedInFuture
        case tooOld
        case replayed
    }

    /// A proof older than this is rejected.
    public static let maxAge: TimeInterval = 300
    public static let allowedFutureSkew: TimeInterval = 60

    /// Checks structure, binding, freshness and the signature. `publicKey` must be the device's `approvalBiometric` key.
    public static func verify(_ proof: DelegationStepUpProof?, for request: DelegationInvitationRequest, deviceId: DeviceID,
                              publicKey: DevicePublicKey, now: Date) throws {
        guard let proof else { throw Failure.missing }
        guard proof.deviceId == deviceId else { throw Failure.deviceMismatch }
        guard ConstantTime.equals(proof.scopeDigest, DelegationScopePolicy.scopeDigest(of: request)) else { throw Failure.scopeMismatch }
        guard let signature = ViadereSignatureEncoding.decode(proof.signature) else { throw Failure.malformedSignature }
        guard proof.signedAt <= now.addingTimeInterval(allowedFutureSkew) else { throw Failure.signedInFuture }
        guard now.timeIntervalSince(proof.signedAt) <= maxAge else { throw Failure.tooOld }
        guard let key = try? publicKey.signingKey(), key.isValidSignature(signature, for: proof.signingInput()) else {
            throw Failure.badSignature
        }
    }

    /// `verify` plus single-use consumption of the proof through `replayGuard`.
    public static func verify(_ proof: DelegationStepUpProof?, for request: DelegationInvitationRequest, deviceId: DeviceID,
                              publicKey: DevicePublicKey, now: Date, replayGuard: any ReplayGuard) async throws {
        try verify(proof, for: request, deviceId: deviceId, publicKey: publicKey, now: now)
        guard let proof else { throw Failure.missing }
        let fresh = try await replayGuard.registerIfFresh(
            nonce: SecureToken.sha256Hex(Data(proof.signature.utf8)), scope: "delegation-stepup:\(deviceId)",
            expiresAt: proof.signedAt.addingTimeInterval(maxAge + allowedFutureSkew), now: now)
        guard fresh else { throw Failure.replayed }
    }
}
