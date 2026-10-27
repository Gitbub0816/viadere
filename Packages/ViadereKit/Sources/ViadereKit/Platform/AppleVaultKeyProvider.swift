import Foundation
import ViadereCore

#if canImport(Security) && canImport(LocalAuthentication)
import Crypto
import LocalAuthentication
import Security

/// The vault identity on iOS.
///
/// - **Signing key** (approves manifests): a Secure Enclave P-256 key, `.privateKeyUsage + .userPresence`, so signing needs Face ID / Touch ID /
///   the passcode. Its keychain item holds only the enclave's opaque `dataRepresentation`.
/// - **Agreement key** (opens the HPKE envelope, the "device vault key"): a P-256 key-agreement key kept in a Keychain item with
///   `.userPresence` access control and `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (never synced, never backed up, never migrated). It is
///   a Keychain key rather than an enclave key so it can drive HPKE without depending on enclave HPKE support.
///
/// Both items live in the vault-only keychain access group shared by the app and the credential-provider extension. `existingIdentity()` asks
/// the person once (`LAContext`, device owner authentication) and hands that authenticated context to both keys, so one prompt covers one
/// unlock. The agreement key's bytes then sit in memory until the vault locks.
public final class AppleVaultKeyProvider: VaultKeyProvider, @unchecked Sendable {
    private let service: String
    private let accessGroup: String?
    private let reason: String

    public init(service: String = "\(ViadereCore.bundlePrefix).vault", accessGroup: String?, reason: String = "Unlock your passkeys and codes") {
        self.service = service
        self.accessGroup = accessGroup
        self.reason = reason
    }

    private enum Account {
        static let signing = "vault.signing.se"
        static let agreement = "vault.agreement"
    }

    private func query(_ account: String) -> [String: Any] {
        var q: [String: Any] = [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service, kSecAttrAccount as String: account]
        if let accessGroup { q[kSecAttrAccessGroup as String] = accessGroup }
        return q
    }

    private func exists(_ account: String) -> Bool {
        var q = query(account)
        q[kSecReturnAttributes as String] = true
        let noPrompt = LAContext()
        noPrompt.interactionNotAllowed = true
        q[kSecUseAuthenticationContext as String] = noPrompt
        let status = SecItemCopyMatching(q as CFDictionary, nil)
        // `errSecInteractionNotAllowed` means "present, needs the person".
        return status == errSecSuccess || status == errSecInteractionNotAllowed
    }

    private func read(_ account: String, context: LAContext) throws -> Data {
        var q = query(account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        q[kSecUseAuthenticationContext as String] = context
        var result: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        switch status {
        case errSecSuccess:
            guard let data = result as? Data else { throw VaultKeyError.failed(status) }
            return data
        case errSecUserCanceled, errSecAuthFailed: throw VaultKeyError.userCancelled
        default: throw VaultKeyError.failed(status)
        }
    }

    private func write(_ data: Data, account: String, access: SecAccessControl?) throws {
        SecItemDelete(query(account) as CFDictionary)
        var add = query(account)
        add[kSecValueData as String] = data
        if let access { add[kSecAttrAccessControl as String] = access } else { add[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly }
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw VaultKeyError.failed(status) }
    }

    private func authenticatedContext() async throws -> LAContext {
        let context = LAContext()
        do {
            guard try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason) else { throw VaultKeyError.userCancelled }
        } catch let error as LAError where error.code == .userCancel || error.code == .systemCancel || error.code == .appCancel {
            throw VaultKeyError.userCancelled
        } catch let error as LAError where error.code == .passcodeNotSet {
            throw VaultKeyError.unavailable
        }
        return context
    }

    public func existingIdentity() async throws -> VaultDeviceIdentity? {
        guard exists(Account.signing), exists(Account.agreement) else { return nil }
        let context = try await authenticatedContext()
        let signingRepresentation = try read(Account.signing, context: context)
        let agreementRaw = try read(Account.agreement, context: context)
        return VaultDeviceIdentity(signingKey: try Self.signingKey(dataRepresentation: signingRepresentation, context: context),
                                   agreementKey: try SoftwareVaultAgreementKey(rawRepresentation: agreementRaw))
    }

    public func createIdentity() async throws -> VaultDeviceIdentity {
        try await deleteIdentity()
        let context = try await authenticatedContext()
        var error: Unmanaged<CFError>?
        guard let storageAccess = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .userPresence, &error) else {
            throw VaultKeyError.failed(Int32(CFErrorGetCode(error?.takeRetainedValue())))
        }
        let signing: any DeviceSigningKey
        let representation: Data
        #if targetEnvironment(simulator)
        #if DEBUG
        // The Simulator has no Secure Enclave: DEBUG builds use a software key so the flows can be exercised. Release builds refuse.
        _ = context
        let software = SoftwareP256SigningKey()
        signing = software
        representation = software.rawRepresentation
        #else
        throw VaultKeyError.unavailable
        #endif
        #else
        guard SecureEnclave.isAvailable,
              let signingAccess = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.privateKeyUsage, .userPresence], &error) else {
            throw VaultKeyError.unavailable
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(compactRepresentable: true, accessControl: signingAccess, authenticationContext: context)
        representation = key.dataRepresentation
        signing = try Self.signingKey(dataRepresentation: representation, context: context)
        #endif
        let agreement = P256.KeyAgreement.PrivateKey()
        try write(representation, account: Account.signing, access: nil)
        try write(agreement.rawRepresentation, account: Account.agreement, access: storageAccess)
        return VaultDeviceIdentity(signingKey: signing, agreementKey: try SoftwareVaultAgreementKey(rawRepresentation: agreement.rawRepresentation))
    }

    public func deleteIdentity() async throws {
        for account in [Account.signing, Account.agreement] {
            let status = SecItemDelete(query(account) as CFDictionary)
            guard status == errSecSuccess || status == errSecItemNotFound else { throw VaultKeyError.failed(status) }
        }
    }

    private static func signingKey(dataRepresentation: Data, context: LAContext) throws -> any DeviceSigningKey {
        #if targetEnvironment(simulator) && DEBUG
        return try SoftwareP256SigningKey(rawRepresentation: dataRepresentation)
        #else
        do {
            return EnclaveVaultSigningKey(key: try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: dataRepresentation, authenticationContext: context))
        } catch {
            throw VaultKeyError.failed(-1)
        }
        #endif
    }
}

#if !(targetEnvironment(simulator) && DEBUG)
/// A Secure Enclave signing key bound to an authenticated `LAContext`.
struct EnclaveVaultSigningKey: DeviceSigningKey, @unchecked Sendable {
    let key: SecureEnclave.P256.Signing.PrivateKey
    var publicKey: DevicePublicKey { DevicePublicKey(key.publicKey) }

    func signature(for data: Data) async throws -> P256.Signing.ECDSASignature {
        let key = self.key
        // Signing may show the system prompt if the context has expired; keep it off the cooperative thread pool.
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                do { continuation.resume(returning: try key.signature(for: data)) } catch { continuation.resume(throwing: VaultKeyError.userCancelled) }
            }
        }
    }
}
#endif

/// Builds the vault engine for the app and for the credential-provider extension.
public enum VaultRuntime {
    /// The App Group directory both processes read and write. In DEBUG, falls back to Application Support when the group is not provisioned.
    public static func containerDirectory(appGroupID: String) -> URL? {
        if !appGroupID.isEmpty, let container = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupID) {
            return container.appendingPathComponent("Vault", isDirectory: true)
        }
        #if DEBUG
        return try? FileManager.default.url(for: .applicationSupportDirectory, in: .userDomainMask, appropriateFor: nil, create: true).appendingPathComponent("Vault", isDirectory: true)
        #else
        return nil
        #endif
    }

    /// - Parameters:
    ///   - api: the sync client in the app; **`nil` in the extension**, which never uses the network.
    ///   - vaultKeychainAccessGroup: the keychain group shared by the app and the extension only (`$(AppIdentifierPrefix)com.viadere.vault`).
    public static func makeEngine(appGroupID: String, vaultKeychainAccessGroup: String?, api: (any VaultSyncAPI)?, deviceLabel: String) throws -> VaultEngine {
        guard let directory = containerDirectory(appGroupID: appGroupID) else { throw VaultStoreError.unreadable }
        let service = "\(ViadereCore.bundlePrefix).vault"
        return VaultEngine(store: FileVaultLocalStore(directory: directory), keys: AppleVaultKeyProvider(accessGroup: vaultKeychainAccessGroup), api: api,
                           anchors: KeychainSecretStore(service: service + ".anchor", accessGroup: vaultKeychainAccessGroup, accessibility: kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
                           deviceLabel: deviceLabel)
    }
}
#endif
