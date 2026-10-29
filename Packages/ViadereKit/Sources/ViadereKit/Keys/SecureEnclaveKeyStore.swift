import Crypto
import Foundation
import ViadereCore

#if canImport(Security) && canImport(LocalAuthentication)
import LocalAuthentication
import Security

/// Secure Enclave keys: one P-256 key per `DeviceKeyPurpose`, generated inside the enclave and
/// **non-exportable** (`kSecAttrTokenIDSecureEnclave`). The keychain item only holds an opaque reference.
///
/// | purpose | access control | meaning |
/// |---|---|---|
/// | `.request` | `.privateKeyUsage` | signs API requests silently (no user presence) |
/// | `.approvalUserPresence` | `.privateKeyUsage` + `.userPresence` | Face ID / Touch ID **or** passcode |
/// | `.approvalBiometric` | `.privateKeyUsage` + `.biometryCurrentSet` | biometrics only; **invalidated** when the enrolled biometrics change |
///
/// Approval keys use `kSecAttrAccessibleWhenUnlockedThisDeviceOnly`. The request key uses
/// `AfterFirstUnlockThisDeviceOnly` so the notification service extension can authenticate its
/// interaction-detail fetch while the device is locked (it can never approve anything: it carries no user presence).
public final class SecureEnclaveKeyStore: DeviceKeyStore, @unchecked Sendable {
    /// False on the simulator.
    public static var isAvailable: Bool {
        #if targetEnvironment(simulator)
        false
        #else
        true
        #endif
    }

    private let tagPrefix: String
    private let requestAccessGroup: String?
    private let approvalAccessGroup: String?

    /// - Parameters:
    ///   - accessGroup: shared with the extensions; holds the **request key** only.
    ///   - approvalAccessGroup: app-only group for the approval keys. When `nil` (extensions, tests) approval keys
    ///     are looked up in `accessGroup`, where the app never puts them.
    public init(tagPrefix: String = "com.viadere.devicekey.", accessGroup: String?, approvalAccessGroup: String? = nil) {
        self.tagPrefix = tagPrefix
        self.requestAccessGroup = accessGroup
        self.approvalAccessGroup = approvalAccessGroup
    }

    private func accessGroup(for purpose: DeviceKeyPurpose) -> String? {
        switch purpose {
        case .request: requestAccessGroup
        case .approvalUserPresence, .approvalBiometric: approvalAccessGroup ?? requestAccessGroup
        }
    }

    private func tag(_ purpose: DeviceKeyPurpose) -> Data { Data((tagPrefix + purpose.rawValue).utf8) }

    private func baseQuery(_ purpose: DeviceKeyPurpose) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag(purpose),
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
        ]
        if let accessGroup = accessGroup(for: purpose) { q[kSecAttrAccessGroup as String] = accessGroup }
        return q
    }

    public func existingKey(for purpose: DeviceKeyPurpose) async throws -> (any ManagedSigningKey)? {
        guard Self.isAvailable else { throw KeyStoreError.unavailable }
        var q = baseQuery(purpose)
        q[kSecReturnRef as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        // Fetching the reference never prompts; the prompt appears when the key is used to sign.
        var item: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &item)
        switch status {
        case errSecSuccess:
            guard let item, CFGetTypeID(item) == SecKeyGetTypeID() else { return nil }
            return try EnclaveKey(purpose: purpose, tag: tag(purpose), accessGroup: accessGroup(for: purpose),
                                  privateKey: unsafeDowncast(item, to: SecKey.self))
        case errSecItemNotFound:
            // `.biometryCurrentSet` keys vanish when the enrolled biometrics change.
            return nil
        default:
            // -25308 (locked) and friends are "try again later", not "the key is gone".
            throw KeychainStatus.lookupError(status, purpose: purpose) ?? KeyStoreError.unexpectedStatus(status)
        }
    }

    public func createKey(for purpose: DeviceKeyPurpose) async throws -> any ManagedSigningKey {
        guard Self.isAvailable else { throw KeyStoreError.unavailable }
        try await deleteKey(for: purpose)

        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        let accessibility: CFString
        switch purpose {
        case .request:
            accessibility = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        case .approvalUserPresence:
            flags.insert(.userPresence)
            accessibility = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        case .approvalBiometric:
            flags.insert(.biometryCurrentSet)
            accessibility = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
        var cfError: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(nil, accessibility, flags, &cfError) else {
            throw KeyStoreError.creationFailed(purpose, Int32(CFErrorGetCode(cfError?.takeRetainedValue())))
        }
        var privateAttributes: [String: Any] = [
            kSecAttrIsPermanent as String: true,
            kSecAttrApplicationTag as String: tag(purpose),
            kSecAttrAccessControl as String: access,
        ]
        if let accessGroup = accessGroup(for: purpose) { privateAttributes[kSecAttrAccessGroup as String] = accessGroup }
        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: privateAttributes,
        ]
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &cfError) else {
            throw KeyStoreError.creationFailed(purpose, Int32(CFErrorGetCode(cfError?.takeRetainedValue())))
        }
        return try EnclaveKey(purpose: purpose, tag: tag(purpose), accessGroup: accessGroup(for: purpose), privateKey: privateKey)
    }

    public func deleteKey(for purpose: DeviceKeyPurpose) async throws {
        let status = SecItemDelete(baseQuery(purpose) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainStatus.lookupError(status, purpose: purpose) ?? KeyStoreError.unexpectedStatus(status)
        }
    }
}

/// A Secure Enclave key handle. Only public data is stored; the private key reference is re-fetched with a
/// fresh `LAContext` at signing time so the system prompt carries the caller's reason.
struct EnclaveKey: ManagedSigningKey {
    let purpose: DeviceKeyPurpose
    let publicKey: DevicePublicKey
    private let tag: Data
    private let accessGroup: String?
    var isHardwareBacked: Bool { true }

    init(purpose: DeviceKeyPurpose, tag: Data, accessGroup: String?, privateKey: SecKey) throws {
        self.purpose = purpose
        self.tag = tag
        self.accessGroup = accessGroup
        guard let publicSecKey = SecKeyCopyPublicKey(privateKey),
              let external = SecKeyCopyExternalRepresentation(publicSecKey, nil) as Data? else {
            throw KeyStoreError.keyInvalidated(purpose)
        }
        // For EC keys this is the ANSI X9.63 uncompressed point (0x04 || x || y).
        do { publicKey = try DevicePublicKey(bytes: external) } catch { throw KeyStoreError.keyInvalidated(purpose) }
    }

    func signature(for data: Data, prompt: SigningPrompt) async throws -> P256.Signing.ECDSASignature {
        let purpose = self.purpose
        let tag = self.tag
        let accessGroup = self.accessGroup
        let reason = prompt.reason
        // SecKeyCreateSignature blocks while Face ID is shown, so keep it off the cooperative thread pool.
        return try await withCheckedThrowingContinuation { continuation in
            DispatchQueue.global(qos: .userInitiated).async {
                let context = LAContext()
                #if !os(watchOS)
                // watchOS has no custom prompt text: the system shows its own wrist-confirmation UI.
                context.localizedReason = reason
                #else
                _ = reason
                #endif
                var query: [String: Any] = [
                    kSecClass as String: kSecClassKey,
                    kSecAttrApplicationTag as String: tag,
                    kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
                    kSecReturnRef as String: true,
                    kSecMatchLimit as String: kSecMatchLimitOne,
                    kSecUseAuthenticationContext as String: context,
                ]
                if let accessGroup { query[kSecAttrAccessGroup as String] = accessGroup }
                var item: CFTypeRef?
                let status = SecItemCopyMatching(query as CFDictionary, &item)
                guard status == errSecSuccess, let item, CFGetTypeID(item) == SecKeyGetTypeID() else {
                    continuation.resume(throwing: status == errSecItemNotFound
                        ? KeyStoreError.keyInvalidated(purpose)
                        : (KeychainStatus.lookupError(status, purpose: purpose) ?? KeyStoreError.signingFailed(status)))
                    return
                }
                let key = unsafeDowncast(item, to: SecKey.self)
                var error: Unmanaged<CFError>?
                guard let der = SecKeyCreateSignature(key, .ecdsaSignatureMessageX962SHA256, data as CFData, &error) as Data? else {
                    continuation.resume(throwing: Self.map(error?.takeRetainedValue(), purpose: purpose))
                    return
                }
                do {
                    // The Security framework returns DER; the wire format is raw r||s (ViadereSignatureEncoding).
                    continuation.resume(returning: try P256.Signing.ECDSASignature(derRepresentation: der))
                } catch {
                    continuation.resume(throwing: KeyStoreError.signingFailed(-1))
                }
            }
        }
    }

    private static func map(_ error: CFError?, purpose: DeviceKeyPurpose) -> KeyStoreError {
        guard let error else { return .signingFailed(-1) }
        let code = Int32(CFErrorGetCode(error))
        switch code {
        case Int32(errSecUserCanceled), -2, -4: // user cancel / LAError.userCancel / systemCancel
            return .userCancelled
        case Int32(errSecAuthFailed), -1: // LAError.authenticationFailed
            return .authenticationFailed
        case Int32(errSecItemNotFound), Int32(errSecDecode):
            return .keyInvalidated(purpose)
        case let code where KeychainStatus.classify(code).isTransientOutcome:
            return .temporarilyUnavailable(code)
        default:
            return .signingFailed(code)
        }
    }
}
#endif
