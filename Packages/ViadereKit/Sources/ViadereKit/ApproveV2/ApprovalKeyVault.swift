import Crypto
import Foundation
import ViadereCore

/// Holds the **pairwise** keys of Approve v2 (ADR-06): for each business relationship one approval signing key and one HPKE key.
///
/// * The approval key is a Secure Enclave P-256 key, `.biometryCurrentSet` for high and critical capabilities (invalidated when the enrolled
///   biometrics change, which makes the business enroll a new one), `.userPresence` otherwise. It never leaves the enclave.
/// * The HPKE key is a software P-256 key in the Keychain (`WhenUnlockedThisDeviceOnly`, never synced, never backed up): CryptoKit's HPKE
///   with Secure Enclave keys depends on the OS version, so it is not relied on.
///
/// Keys are addressed by the **enrollment id** until the server knows them; nothing ever derives from the device or account keys, so two
/// businesses cannot correlate them.
public protocol ApprovalKeyVault: Sendable {
    /// Creates (replacing any existing) approval key for `enrollment`. Throws `KeyStoreError.creationFailed` if the device cannot make a key with
    /// this protection (for example, no biometrics enrolled).
    func createApprovalKey(enrollment: UUID, assurance: ApprovalAMR) async throws -> any ManagedSigningKey
    func approvalKey(enrollment: UUID) async throws -> (any ManagedSigningKey)?
    func createHPKEKey(enrollment: UUID) async throws -> any E2EEPrivateKey
    func hpkeKey(enrollment: UUID) async throws -> (any E2EEPrivateKey)?
    /// Deletes both keys of the enrollment.
    func delete(enrollment: UUID) async throws
}

#if DEBUG
/// ⚠️ DEVELOPMENT ONLY. Software keys for the simulator and tests; compiled out of release builds.
public actor SoftwareApprovalKeyVault: ApprovalKeyVault {
    private struct Key: ManagedSigningKey {
        let purpose: DeviceKeyPurpose
        let inner: SoftwareP256SigningKey
        var publicKey: DevicePublicKey { inner.publicKey }
        var isHardwareBacked: Bool { false }
        func signature(for data: Data, prompt: SigningPrompt) async throws -> P256.Signing.ECDSASignature { try await inner.signature(for: data) }
    }

    private let secrets: any SecretStore
    private let unsupported: Set<ApprovalAMR>
    public private(set) var prompts: [SigningPrompt] = []

    /// - Parameter unsupported: protections this simulated device cannot create (a phone without biometrics cannot make `.biometric`).
    public init(secrets: any SecretStore = InMemorySecretStore(), unsupported: Set<ApprovalAMR> = []) {
        self.secrets = secrets
        self.unsupported = unsupported
    }

    private func signingAccount(_ id: UUID) -> String { "dev.approve.sign." + id.uuidString.lowercased() }
    private func hpkeAccount(_ id: UUID) -> String { "dev.approve.hpke." + id.uuidString.lowercased() }
    private func purpose(_ assurance: ApprovalAMR) -> DeviceKeyPurpose { assurance == .biometric ? .approvalBiometric : .approvalUserPresence }

    public func createApprovalKey(enrollment: UUID, assurance: ApprovalAMR) async throws -> any ManagedSigningKey {
        let purpose = purpose(assurance)
        if unsupported.contains(assurance) { throw KeyStoreError.creationFailed(purpose, -1) }
        let inner = SoftwareP256SigningKey()
        try secrets.write(inner.rawRepresentation, account: signingAccount(enrollment))
        try secrets.write(Data(purpose.rawValue.utf8), account: signingAccount(enrollment) + ".purpose")
        return Key(purpose: purpose, inner: inner)
    }

    public func approvalKey(enrollment: UUID) async throws -> (any ManagedSigningKey)? {
        guard let raw = try secrets.read(signingAccount(enrollment)), let inner = try? SoftwareP256SigningKey(rawRepresentation: raw),
              let purposeData = try secrets.read(signingAccount(enrollment) + ".purpose"),
              let purpose = DeviceKeyPurpose(rawValue: String(decoding: purposeData, as: UTF8.self)) else { return nil }
        return Key(purpose: purpose, inner: inner)
    }

    public func createHPKEKey(enrollment: UUID) async throws -> any E2EEPrivateKey {
        let key = SoftwareE2EEPrivateKey()
        try secrets.write(key.rawRepresentation, account: hpkeAccount(enrollment))
        return key
    }

    public func hpkeKey(enrollment: UUID) async throws -> (any E2EEPrivateKey)? {
        guard let raw = try secrets.read(hpkeAccount(enrollment)) else { return nil }
        return try? SoftwareE2EEPrivateKey(rawRepresentation: raw)
    }

    public func delete(enrollment: UUID) async throws {
        try secrets.delete(signingAccount(enrollment))
        try secrets.delete(signingAccount(enrollment) + ".purpose")
        try secrets.delete(hpkeAccount(enrollment))
    }
}
#endif
