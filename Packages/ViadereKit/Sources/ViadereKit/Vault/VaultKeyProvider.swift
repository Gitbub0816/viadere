import Crypto
import Foundation
import ViadereCore

/// This device's vault identity: a signing key (approves manifests) and an agreement key (opens the vault-key envelope). On iOS both need the
/// person (`AppleVaultKeyProvider`: Face ID / Touch ID / passcode through the Secure Enclave and a user-presence Keychain item,
/// `ThisDeviceOnly`), so nothing opens the vault, or signs for it, without them.
public protocol VaultKeyProvider: Sendable {
    /// The identity if one was created on this device. On iOS this is where the person is asked (Face ID / Touch ID / passcode): the keys it
    /// returns are usable only for that authenticated session.
    func existingIdentity() async throws -> VaultDeviceIdentity?
    func createIdentity() async throws -> VaultDeviceIdentity
    func deleteIdentity() async throws
}

public enum VaultKeyError: Error, Equatable, Sendable {
    case unavailable
    case userCancelled
    case failed(Int32)
}

/// Software keys, for tests and previews only. Never used in a release build of the app.
public final class SoftwareVaultKeyProvider: VaultKeyProvider, @unchecked Sendable {
    private let lock = NSLock()
    private var identity: VaultDeviceIdentity?
    public init() {}
    public func existingIdentity() async throws -> VaultDeviceIdentity? { lock.withLock { identity } }
    public func createIdentity() async throws -> VaultDeviceIdentity {
        lock.withLock {
            let new = VaultDeviceIdentity.software()
            identity = new
            return new
        }
    }
    public func deleteIdentity() async throws { lock.withLock { identity = nil } }
}
