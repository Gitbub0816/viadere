import Foundation
#if canImport(Security)
import Security

/// Keychain-backed `SecretStore` (generic passwords).
///
/// - Items are `…ThisDeviceOnly`: they never leave the device (no iCloud Keychain, not restored to a new device).
/// - `AfterFirstUnlock` (not `WhenUnlocked`) so the notification service extension can fetch interaction
///   details while the phone is locked but has been unlocked once since boot. These items are bearer
///   *session* credentials; sensitive actions still need a Secure Enclave signature with user verification.
/// - The shared `accessGroup` lets the app, its extensions and the App Clip read the same items.
public final class KeychainSecretStore: SecretStore, @unchecked Sendable {
    private let service: String
    private let accessGroup: String?
    private let accessibility: CFString

    public init(service: String, accessGroup: String?,
                accessibility: CFString = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly) {
        self.service = service
        self.accessGroup = accessGroup
        self.accessibility = accessibility
    }

    private func query(account: String?) -> [String: Any] {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
        ]
        if let account { q[kSecAttrAccount as String] = account }
        if let accessGroup { q[kSecAttrAccessGroup as String] = accessGroup }
        return q
    }

    public func read(_ account: String) throws -> Data? {
        var q = query(account: account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &result)
        switch status {
        case errSecSuccess: return result as? Data
        case errSecItemNotFound: return nil
        default: throw SecretStoreError.unhandled(status)
        }
    }

    public func write(_ data: Data, account: String) throws {
        let update = SecItemUpdate(query(account: account) as CFDictionary, [kSecValueData as String: data] as CFDictionary)
        if update == errSecSuccess { return }
        guard update == errSecItemNotFound else { throw SecretStoreError.unhandled(update) }
        var add = query(account: account)
        add[kSecValueData as String] = data
        add[kSecAttrAccessible as String] = accessibility
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else { throw SecretStoreError.unhandled(status) }
    }

    public func delete(_ account: String) throws {
        let status = SecItemDelete(query(account: account) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw SecretStoreError.unhandled(status) }
    }

    public func deleteAll() throws {
        let status = SecItemDelete(query(account: nil) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw SecretStoreError.unhandled(status) }
    }
}
#endif
