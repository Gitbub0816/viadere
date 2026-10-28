import Foundation
import ViadereCore

/// Why Approve v2 cannot be used with a business right now.
public enum ApproveError: Error, Equatable, Sendable {
    /// The app has no pinned transparency-log key, so no business key can be verified: Approve v2 fails closed.
    case notConfigured
    case api(APIError)
    case directory(KeyDirectoryError)
    case directoryHasNoRoot
    /// The business has not published an `approval-enrollment-confirmation` key.
    case businessNotReady
    /// Neither the link's secret nor the business's check code is available: the business could not tell this phone's key from one the relay
    /// made, so no key is created. Open the business's link or QR, or type its check code too.
    case enrollmentSecretRequired
    /// The root key the log shows is not the one the business displayed in the link or QR.
    case rootMismatchWithLink
    /// A valid succession replaced the pinned root: the person must confirm the change before this business can ask for approvals.
    case rootChanged(BusinessID)
    /// The log contradicts the pinned root (a different history): refuse and warn.
    case rootConflict(BusinessID)
    case deviceCannotSatisfy
    case userCancelled
    case authenticationFailed
    /// The local key is gone (biometrics changed): the business has to enroll a new one.
    case keyMissing
    /// The business's confirmation did not cover this device's key; the key was removed and revoked.
    case substitutionDetected
    /// A request failed verification (signature, binding, expiry, decryption) and was hidden.
    case requestRejected(String)
    case frozen
    case expired
    case notEnrolled
    case keysUnavailable
}

/// What a verified look at a business's directory page returned.
public struct DirectoryCheck: Sendable {
    public var state: BusinessKeyState
    public var head: TreeHead
    public var trust: RootTrust
    /// `ABCDE-FGHIJ-...`: shown so the person can compare it with what the business displays.
    public var rootFingerprint: String
}

/// Verifies businesses' published keys on the device (SEC-CR-006): the signed tree head (against the log key built into the app), the
/// consistency with the head seen last, an inclusion proof for every statement, and the root pinned on first contact. A changed root is
/// surfaced, never accepted silently.
public struct BusinessDirectoryClient: Sendable {
    private let api: any ApproveAPI
    private let store: any ApproveLocalStore
    private let verifier: KeyDirectoryVerifier?
    private let clock: @Sendable () -> Date

    public init(api: any ApproveAPI, store: any ApproveLocalStore, logKeys: [DevicePublicKey], logId: String = TransparencyLog.defaultLogId,
                clock: @escaping @Sendable () -> Date = { Date() }) {
        self.api = api
        self.store = store
        verifier = logKeys.isEmpty ? nil : KeyDirectoryVerifier(logKeys: logKeys, logId: logId)
        self.clock = clock
    }

    /// Verifies `businessId`'s directory page and applies the pinning policy.
    /// - Parameters:
    ///   - expectedRootKid: the root key id the business displayed out of band (enrollment link or QR). A mismatch is a hard failure.
    ///   - allowPendingRootChange: only the screen that asks the person to confirm a changed root passes true.
    public func verify(businessId: BusinessID, expectedRootKid: String? = nil, allowPendingRootChange: Bool = false) async throws -> DirectoryCheck {
        guard let verifier else { throw ApproveError.notConfigured }
        let local = try await store.load()
        let response: KeyDirectoryResponse
        do { response = try await api.keyDirectory(businessId: businessId, since: local.lastSeenHead?.treeSize) } catch let error as APIError { throw ApproveError.api(error) }
        let verified: VerifiedDirectory
        do {
            verified = try verifier.verify(response, businessId: businessId, lastSeen: local.lastSeenHead, now: clock())
        } catch let error as KeyDirectoryError {
            throw ApproveError.directory(error)
        }
        let key = businessId.description
        let existing = local.pins[key]
        let status = KeyDirectoryVerifier.pinStatus(pin: existing?.root, state: verified.state)
        let now = clock()
        switch status {
        case .noRoot:
            throw ApproveError.directoryHasNoRoot
        case .firstUse(let kid):
            if let expectedRootKid, expectedRootKid != kid { throw ApproveError.rootMismatchWithLink }
            guard let epoch = verified.state.currentRoot else { throw ApproveError.directoryHasNoRoot }
            let trust: RootTrust = expectedRootKid == nil ? .firstUse : .verifiedOutOfBand
            let pinned = PinnedBusinessRoot(root: PinnedRoot(from: epoch, businessId: businessId, at: now), trust: trust)
            let head = SeenTreeHead(verified.head)
            try await store.update { $0.pins[key] = pinned; $0.advanceHead(to: head) }
            try await requireNoFork(head)
            return DirectoryCheck(state: verified.state, head: verified.head, trust: trust, rootFingerprint: KeyIdentifier.displayFingerprint(kid))
        case .unchanged:
            if let expectedRootKid, expectedRootKid != existing?.root.rootKid { throw ApproveError.rootMismatchWithLink }
            let head = SeenTreeHead(verified.head)
            try await store.update { $0.advanceHead(to: head); $0.pendingRootChanges[key] = nil }
            try await requireNoFork(head)
            return DirectoryCheck(state: verified.state, head: verified.head, trust: existing?.trust ?? .firstUse,
                                  rootFingerprint: KeyIdentifier.displayFingerprint(existing?.root.rootKid ?? ""))
        case .rotated(let pinnedKid, let currentKid):
            let change = PendingRootChange(businessId: businessId, pinnedKid: pinnedKid, newKid: currentKid, detectedAt: now)
            let head = SeenTreeHead(verified.head)
            try await store.update { $0.pendingRootChanges[key] = change; $0.advanceHead(to: head) }
            try await requireNoFork(head)
            guard allowPendingRootChange else { throw ApproveError.rootChanged(businessId) }
            return DirectoryCheck(state: verified.state, head: verified.head, trust: existing?.trust ?? .firstUse, rootFingerprint: KeyIdentifier.displayFingerprint(currentKid))
        case .conflict:
            try await store.update { $0.rootConflicts[key] = now }
            throw ApproveError.rootConflict(businessId)
        }
    }

    /// Two refreshes can run at once. If the head another one stored has the same size as this one but a different root, the log showed two
    /// trees of one size: a fork. Fail closed (the next `verify` against the stored head fails the same way until the log is consistent).
    private func requireNoFork(_ head: SeenTreeHead) async throws {
        if let stored = try await store.load().lastSeenHead, stored.treeSize == head.treeSize, stored.rootHash != head.rootHash { throw ApproveError.directory(.forkDetected) }
    }

    /// The person re-confirmed after being told the business's root key changed: the new root is pinned, and the business can ask for approvals
    /// again once it has re-published its keys under the new root.
    ///
    /// **The caller's tap is not enough** (gate finding F5): the change needs a fresh Face ID / Touch ID proof from the device's own
    /// biometric-protected key (`authorizer`), so a thief holding an unlocked phone cannot re-trust an attacker's root. If the proof fails or is
    /// cancelled nothing is pinned and the change stays pending.
    public func acceptRootChange(businessId: BusinessID, authorizer: any RootChangeAuthorizer) async throws {
        let check = try await verify(businessId: businessId, allowPendingRootChange: true)
        guard let epoch = check.state.currentRoot else { throw ApproveError.directoryHasNoRoot }
        let key = businessId.description
        let now = clock()
        do {
            try await authorizer.authorize(reason: "Trust the new signing key of this business")
        } catch let error as KeyStoreError {
            switch error {
            case .userCancelled: throw ApproveError.userCancelled
            case .authenticationFailed: throw ApproveError.authenticationFailed
            default: throw ApproveError.deviceCannotSatisfy
            }
        }
        try await store.update {
            $0.pins[key] = PinnedBusinessRoot(root: PinnedRoot(from: epoch, businessId: businessId, at: now), trust: .firstUse)
            $0.pendingRootChanges[key] = nil
        }
    }

    /// The person has read the warning about a contradicted root. Approvals with that business stay blocked until its keys are enrolled again.
    /// (A conflict is never cleared by the network: only by this explicit act.)
    public func acknowledgeConflict(businessId: BusinessID) async throws {
        try await store.update { $0.rootConflicts[businessId.description] = nil; $0.pins[businessId.description] = nil }
    }

    /// Whether the pinned root of a business is pending a change or contradicted (without any network call).
    public func alert(for businessId: BusinessID) async throws -> DirectoryAlert? {
        let local = try await store.load()
        let key = businessId.description
        if local.rootConflicts[key] != nil { return .rootConflict }
        if let change = local.pendingRootChanges[key] { return .rootChanged(change) }
        return nil
    }
}

public enum DirectoryAlert: Sendable, Equatable {
    case rootChanged(PendingRootChange)
    case rootConflict
}

/// A fresh proof that the person is at the phone, required before a changed business root is trusted (gate finding F5).
public protocol RootChangeAuthorizer: Sendable {
    /// Throws `KeyStoreError.userCancelled` / `.authenticationFailed` (or anything else, which refuses) unless the person just authenticated.
    func authorize(reason: String) async throws
}

/// Signs a random challenge with the device's biometric-protected key, which the Secure Enclave releases only after Face ID or Touch ID
/// (`.biometryCurrentSet`), and checks the signature. The same primitive as unfreezing approvals.
public struct DeviceBiometricAuthorizer: RootChangeAuthorizer {
    private let keys: any DeviceKeyStore
    public init(keys: any DeviceKeyStore) { self.keys = keys }

    public func authorize(reason: String) async throws {
        let key: any ManagedSigningKey
        do { key = try await keys.requireKey(for: .approvalBiometric) } catch { throw KeyStoreError.keyNotFound(.approvalBiometric) }
        let challenge = SecureToken.randomBytes(32)
        let signature = try await PromptBoundKey(key, prompt: SigningPrompt(reason: reason)).signature(for: challenge)
        guard let verifier = try? key.publicKey.signingKey(), verifier.isValidSignature(signature, for: challenge) else { throw KeyStoreError.authenticationFailed }
    }
}
