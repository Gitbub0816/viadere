import Crypto
import Foundation
import ViadereCore

#if canImport(Security) && canImport(LocalAuthentication)
import Security

/// The production `ApprovalKeyVault`: one Secure Enclave approval key per enrollment (a `SecureEnclaveKeyStore` namespaced by the enrollment id,
/// in the app-only access group) and one software HPKE key in the Keychain (`WhenUnlockedThisDeviceOnly`, never synced).
public struct AppleApprovalKeyVault: ApprovalKeyVault {
    private let configuration: ViadereConfiguration
    private let hpkeSecrets: KeychainSecretStore

    public init(configuration: ViadereConfiguration) {
        self.configuration = configuration
        hpkeSecrets = KeychainSecretStore(service: configuration.keychainService + ".approve.hpke", accessGroup: configuration.approvalKeychainAccessGroup,
                                          accessibility: kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
    }

    private func enclave(_ enrollment: UUID) -> SecureEnclaveKeyStore {
        SecureEnclaveKeyStore(tagPrefix: "com.viadere.approve." + enrollment.uuidString.lowercased() + ".", accessGroup: configuration.approvalKeychainAccessGroup,
                              approvalAccessGroup: configuration.approvalKeychainAccessGroup)
    }

    private func purpose(_ assurance: ApprovalAMR) -> DeviceKeyPurpose { assurance == .biometric ? .approvalBiometric : .approvalUserPresence }
    private func account(_ enrollment: UUID) -> String { enrollment.uuidString.lowercased() }

    public func createApprovalKey(enrollment: UUID, assurance: ApprovalAMR) async throws -> any ManagedSigningKey {
        try await enclave(enrollment).createKey(for: purpose(assurance))
    }

    public func approvalKey(enrollment: UUID) async throws -> (any ManagedSigningKey)? {
        let store = enclave(enrollment)
        if let key = try await store.existingKey(for: .approvalBiometric) { return key }
        return try await store.existingKey(for: .approvalUserPresence)
    }

    public func createHPKEKey(enrollment: UUID) async throws -> any E2EEPrivateKey {
        let key = SoftwareE2EEPrivateKey()
        try hpkeSecrets.write(key.rawRepresentation, account: account(enrollment))
        return key
    }

    public func hpkeKey(enrollment: UUID) async throws -> (any E2EEPrivateKey)? {
        guard let raw = try hpkeSecrets.read(account(enrollment)) else { return nil }
        return try? SoftwareE2EEPrivateKey(rawRepresentation: raw)
    }

    public func delete(enrollment: UUID) async throws {
        let store = enclave(enrollment)
        try await store.deleteKey(for: .approvalBiometric)
        try await store.deleteKey(for: .approvalUserPresence)
        try hpkeSecrets.delete(account(enrollment))
    }
}

extension ApproveEnvironment {
    /// The device graph: Secure Enclave pairwise keys, Keychain state. `nil` when the services have no Approve API (extensions, App Clip).
    public static func live(services: ViadereServices) -> ApproveEnvironment? {
        guard let api = services.approveAPI else { return nil }
        let state = KeychainSecretStore(service: services.configuration.keychainService + ".approve.state", accessGroup: services.configuration.approvalKeychainAccessGroup,
                                        accessibility: kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
        return ApproveEnvironment(services: services, api: api, vault: AppleApprovalKeyVault(configuration: services.configuration),
                                  store: SecretApproveLocalStore(secrets: state))
    }
}
#endif
