import Crypto
import Foundation
import ViadereCore

/// What the person is shown before confirming an enrollment (APP-002, APP-003): the verified business, what the key is for, and the business's
/// root key fingerprint to compare with what the business displays.
public struct EnrollmentOffer: Sendable, Equatable {
    public var preview: ApproveEnrollmentPreview
    public var rootFingerprint: String
    public var trust: RootTrust
    public var expectedRootKid: String?

    public static func == (lhs: EnrollmentOffer, rhs: EnrollmentOffer) -> Bool { lhs.preview == rhs.preview && lhs.rootFingerprint == rhs.rootFingerprint && lhs.trust == rhs.trust }
}

/// The result of checking one pending key's confirmation.
public enum ConfirmationOutcome: Sendable, Equatable {
    case activated(kid: String)
    /// The business confirmed a key that is not this device's: the relay substituted the key. The key was removed and revoked.
    case substitutionDetected(kid: String)
    case revoked(kid: String)
    case stillWaiting(kid: String)
    /// The confirmation could not be verified against the directory right now (network, log); retry later.
    case unverifiable(kid: String, reason: ApproveError)
}

/// Business-authorized enrollment of a pairwise approval key, on the device.
public struct ApproveEnrollmentFlow: Sendable {
    private let api: any ApproveAPI
    private let vault: any ApprovalKeyVault
    private let store: any ApproveLocalStore
    private let directory: BusinessDirectoryClient
    private let clock: @Sendable () -> Date

    public init(api: any ApproveAPI, vault: any ApprovalKeyVault, store: any ApproveLocalStore, directory: BusinessDirectoryClient, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.api = api
        self.vault = vault
        self.store = store
        self.directory = directory
        self.clock = clock
    }

    /// Step 1: the person typed the code or opened the link/QR. Looks it up (only the relationship's own customer can) and verifies the
    /// business's directory, including — when the link carried one — that the root key is the one the business displayed.
    public func lookup(code: String, expectedRootKid: String? = nil) async throws -> EnrollmentOffer {
        let preview: ApproveEnrollmentPreview
        do { preview = try await api.lookupEnrollment(code: code) } catch let error as APIError { throw ApproveError.api(error) }
        let check = try await directory.verify(businessId: preview.business.id, expectedRootKid: expectedRootKid)
        // Without a confirmation key the business could never activate the key: do not create one.
        guard !check.state.validKeys(for: .approvalEnrollmentConfirmation, at: clock()).isEmpty else { throw ApproveError.businessNotReady }
        return EnrollmentOffer(preview: preview, rootFingerprint: check.rootFingerprint, trust: check.trust, expectedRootKid: expectedRootKid)
    }

    /// Step 2: the person confirmed. Creates the pairwise keys, signs the enrollment statement with the new approval key (Face ID or Touch
    /// ID for a biometric key), and sends it. If anything fails the keys are deleted.
    @discardableResult
    public func enroll(_ offer: EnrollmentOffer, deviceName: String? = nil) async throws -> LocalApprovalKey {
        let preview = offer.preview
        let assurance = preview.requiredAssurance
        let key: any ManagedSigningKey
        do { key = try await vault.createApprovalKey(enrollment: preview.enrollmentId, assurance: assurance) } catch {
            // No biometrics enrolled (or no Secure Enclave): this device cannot hold a key strong enough. Nothing was created.
            throw ApproveError.deviceCannotSatisfy
        }
        do {
            let hpke = try await vault.createHPKEKey(enrollment: preview.enrollmentId)
            let statement = try ApprovalEnrollmentStatement(businessId: preview.business.id, subject: preview.subjectRef, enrollmentId: preview.enrollmentId, publicKey: key.publicKey,
                                                            hpkePublicKey: hpke.publicKey, assurance: assurance, createdAt: clock())
            let prompt = SigningPrompt(reason: "Set up approvals with \(preview.business.displayName)")
            let signed = try await statement.sign(with: PromptBoundKey(key, prompt: prompt))
            let result: ApproveKey
            do { result = try await api.completeEnrollment(id: preview.enrollmentId, statement: signed) } catch let error as APIError { throw ApproveError.api(error) }
            guard result.kid == statement.kid else { throw ApproveError.substitutionDetected }
            let local = LocalApprovalKey(enrollmentId: preview.enrollmentId, kid: statement.kid, hpkeKid: statement.hpkePublicKey.kid, businessId: preview.business.id,
                                         businessName: preview.business.displayName, relationshipId: preview.relationshipId, subject: preview.subjectRef, assurance: assurance,
                                         statement: signed, status: .pendingConfirmation, createdAt: clock())
            try await store.update { $0.keys.removeAll { $0.enrollmentId == local.enrollmentId }; $0.keys.append(local) }
            return local
        } catch {
            try? await vault.delete(enrollment: preview.enrollmentId)
            if let known = error as? ApproveError { throw known }
            if let keyError = error as? KeyStoreError {
                switch keyError {
                case .userCancelled: throw ApproveError.userCancelled
                case .authenticationFailed: throw ApproveError.authenticationFailed
                default: throw ApproveError.keysUnavailable
                }
            }
            throw ApproveError.keysUnavailable
        }
    }

    /// Step 3 (and whenever the app opens): checks the business's confirmation of each waiting key **against the directory**. A key becomes
    /// active only when the confirmation is signed by a key the business published, names this business, customer and enrollment, and covers
    /// exactly the statement this device signed. Any other confirmation means the relay swapped the key: it is removed and revoked.
    public func refreshConfirmations() async throws -> [ConfirmationOutcome] {
        let local = try await store.load()
        let waiting = local.keys.filter { $0.status == .pendingConfirmation }
        guard !waiting.isEmpty else { return [] }
        let remote: [ApproveKey]
        do { remote = try await api.keys() } catch let error as APIError { throw ApproveError.api(error) }
        var outcomes: [ConfirmationOutcome] = []
        for key in waiting {
            guard let server = remote.first(where: { $0.kid == key.kid || $0.enrollmentId == key.enrollmentId }) else {
                outcomes.append(.stillWaiting(kid: key.kid))
                continue
            }
            if server.status == .revoked {
                try await finish(key, as: .revoked)
                outcomes.append(.revoked(kid: key.kid))
                continue
            }
            guard let confirmation = server.confirmation else {
                // A key id the server reports that is not ours is itself a substitution.
                if server.kid != key.kid { outcomes.append(try await reject(key, serverKid: server.kid)) } else { outcomes.append(.stillWaiting(kid: key.kid)) }
                continue
            }
            do {
                let check = try await directory.verify(businessId: key.businessId)
                guard let published = check.state.validKey(kid: confirmation.kid, purpose: .approvalEnrollmentConfirmation, at: clock())?.signingKey else {
                    outcomes.append(try await reject(key, serverKid: server.kid))
                    continue
                }
                let parsed = try ApprovalEnrollmentConfirmation.verify(confirmation, confirmationKey: published)
                let statement = try ApprovalEnrollmentStatement.verify(key.statement)
                try parsed.checkMatches(statement, signed: key.statement)
                try await finish(key, as: .active)
                outcomes.append(.activated(kid: key.kid))
            } catch let error as ApproveError {
                outcomes.append(.unverifiable(kid: key.kid, reason: error))
            } catch is ApprovalEnrollmentError {
                outcomes.append(try await reject(key, serverKid: server.kid))
            } catch {
                outcomes.append(.unverifiable(kid: key.kid, reason: .keysUnavailable))
            }
        }
        return outcomes
    }

    /// Removes a key whose confirmation was wrong: revoke on the server (best effort), delete the private keys, remember why.
    private func reject(_ key: LocalApprovalKey, serverKid: String) async throws -> ConfirmationOutcome {
        _ = try? await api.revokeKey(kid: key.kid)
        // The relay's record for this enrollment may name another key (the substituted one): revoke that too.
        if serverKid != key.kid { _ = try? await api.revokeKey(kid: serverKid) }
        try await finish(key, as: .substitutionDetected)
        return .substitutionDetected(kid: key.kid)
    }

    private func finish(_ key: LocalApprovalKey, as status: LocalApprovalKey.Status) async throws {
        if status != .active { try? await vault.delete(enrollment: key.enrollmentId) }
        try await store.update { state in
            if let index = state.keys.firstIndex(where: { $0.enrollmentId == key.enrollmentId }) { state.keys[index].status = status }
        }
    }

    // MARK: Revocation

    /// The customer removes a key: revoked on the relay first, then the private keys are deleted.
    public func revoke(kid: String) async throws {
        let local = try await store.load()
        guard let key = local.keys.first(where: { $0.kid == kid }) else { return }
        do { _ = try await api.revokeKey(kid: kid) } catch let error as APIError {
            // Already gone on the server is fine; anything else keeps the key so the person can retry.
            if error.code != .notFound { throw ApproveError.api(error) }
        }
        try await finish(key, as: .revoked)
    }

    /// Reconciles local records with the server (a key revoked by the business, or by a device revocation, disappears here).
    public func syncRevocations() async throws {
        let remote: [ApproveKey]
        do { remote = try await api.keys() } catch let error as APIError { throw ApproveError.api(error) }
        let local = try await store.load()
        for key in local.keys where key.status == .active || key.status == .pendingConfirmation {
            if let server = remote.first(where: { $0.kid == key.kid }), server.status == .revoked { try await finish(key, as: .revoked) }
        }
    }
}
