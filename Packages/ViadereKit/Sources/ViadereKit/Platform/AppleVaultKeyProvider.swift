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
///   `.biometryCurrentSet` **or** the device passcode as access control and `kSecAttrAccessibleWhenUnlockedThisDeviceOnly` (never synced,
///   never backed up, never migrated). Changing the enrolled biometrics invalidates the biometric path (the passcode still opens it: that is
///   the documented fallback; removing it is a product decision that would make a biometric change a vault-recovery event). It is a Keychain
///   key rather than an enclave key so it can drive HPKE without depending on enclave HPKE support. TODO(vault-se-dhkem): move it into the
///   Secure Enclave with a CryptoKit `SecureEnclave.P256.KeyAgreement.PrivateKey` and HPKE decapsulation inside the enclave
///   (`SecureEnclaveVaultAgreementKey`, below); that needs validation on a device before it replaces this.
///
/// Both items live in the vault-only keychain access group shared by the app and the credential-provider extension. Every identity request
/// (`existingIdentity()` at unlock, `freshIdentity(reason:)` for a membership or recovery operation) asks the person once through a **new**
/// `LAContext` (device owner authentication, no reuse) and hands that authenticated context to both keys. The agreement key's secret bytes are
/// **not** kept in memory: only its public key is, and the private bytes are read from the Keychain for each HPKE operation and overwritten
/// afterwards (best effort: the crypto library offers no guaranteed zeroization of its own copy).
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
        /// The agreement key's public half (not secret, no access control), so the identity can be built without reading the private bytes.
        static let agreementPublic = "vault.agreement.pub"
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

    private func authenticatedContext(reason: String) async throws -> LAContext {
        let context = LAContext()
        context.touchIDAuthenticationAllowableReuseDuration = 0          // a new evaluation every time, never a reused one
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
        try await identity(reason: reason)
    }

    public func freshIdentity(reason: String) async throws -> VaultDeviceIdentity {
        guard let identity = try await identity(reason: reason) else { throw VaultKeyError.unavailable }
        return identity
    }

    private func identity(reason: String) async throws -> VaultDeviceIdentity? {
        guard exists(Account.signing), exists(Account.agreement) else { return nil }
        let context = try await authenticatedContext(reason: reason)
        let signingRepresentation = try read(Account.signing, context: context)
        let publicKey = try agreementPublicKey(context: context)
        return VaultDeviceIdentity(signingKey: try Self.signingKey(dataRepresentation: signingRepresentation, context: context),
                                   agreementKey: KeychainVaultAgreementKey(publicKey: publicKey, loadRawKey: agreementLoader(context)))
    }

    private struct ContextBox: @unchecked Sendable { let context: LAContext }

    /// Reads the agreement key's private bytes from the Keychain with `context`'s authentication, when (and only when) an HPKE operation asks.
    private func agreementLoader(_ context: LAContext) -> @Sendable () throws -> Data {
        let box = ContextBox(context: context)
        return { [self] in try self.read(Account.agreement, context: box.context) }
    }

    private func agreementPublicKey(context: LAContext) throws -> P256.KeyAgreement.PublicKey {
        if exists(Account.agreementPublic), let stored = try? read(Account.agreementPublic, context: context),
           let key = try? P256.KeyAgreement.PublicKey(x963Representation: stored) { return key }
        // An item written before the public half was stored separately: derive it once from the private bytes.
        var raw = try read(Account.agreement, context: context)
        defer { raw.resetBytes(in: 0..<raw.count) }
        return try P256.KeyAgreement.PrivateKey(rawRepresentation: raw).publicKey
    }

    public func createIdentity() async throws -> VaultDeviceIdentity {
        try await deleteIdentity()
        let context = try await authenticatedContext(reason: reason)
        var error: Unmanaged<CFError>?
        guard let storageAccess = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, [.biometryCurrentSet, .or, .devicePasscode], &error) else {
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
        try write(agreement.publicKey.x963Representation, account: Account.agreementPublic, access: nil)
        let publicKey = agreement.publicKey
        return VaultDeviceIdentity(signingKey: signing, agreementKey: KeychainVaultAgreementKey(publicKey: publicKey, loadRawKey: agreementLoader(context)))
    }

    public func deleteIdentity() async throws {
        for account in [Account.signing, Account.agreement, Account.agreementPublic] {
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

/// The device's agreement key as a handle: it holds the public key and a way to read the private bytes from the Keychain **for one HPKE
/// operation**. The bytes live in memory only while `recipient` runs and are overwritten afterwards (best effort; see the provider's notes).
struct KeychainVaultAgreementKey: VaultAgreementKey, @unchecked Sendable {
    let publicKey: P256.KeyAgreement.PublicKey
    let loadRawKey: @Sendable () throws -> Data

    func recipient(info: Data, encapsulatedKey: Data) throws -> HPKE.Recipient {
        var raw = try loadRawKey()
        defer { raw.resetBytes(in: 0..<raw.count) }
        let key = try P256.KeyAgreement.PrivateKey(rawRepresentation: raw)
        return try HPKE.Recipient(privateKey: key, ciphersuite: .P256_SHA256_AES_GCM_256, info: info, encapsulatedKey: encapsulatedKey)
    }
}

/// TODO(vault-se-dhkem): an agreement key whose private half never leaves the Secure Enclave. The intended implementation holds a CryptoKit
/// `SecureEnclave.P256.KeyAgreement.PrivateKey` (created with `.privateKeyUsage` and the same access control as the signing key) and builds the
/// HPKE recipient from it (`HPKE.Recipient(privateKey:ciphersuite:info:encapsulatedKey:)` accepts any `HPKEDiffieHellmanPrivateKey`; if the
/// enclave key type does not conform on the deployment targets, perform the DHKEM `Decap` by hand: ECDH in the enclave, then RFC 9180
/// `ExtractAndExpand`). It also needs a new envelope-recipient enrollment so existing devices can move from the Keychain key. NOT WIRED IN:
/// it must be validated on real devices (including the credential-provider extension, which shares the key through the access group)
/// before `AppleVaultKeyProvider` uses it. Until then it refuses, so nothing can depend on it by accident.
struct SecureEnclaveVaultAgreementKey: VaultAgreementKey, @unchecked Sendable {
    let publicKey: P256.KeyAgreement.PublicKey

    func recipient(info: Data, encapsulatedKey: Data) throws -> HPKE.Recipient {
        throw VaultKeyError.unavailable
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
