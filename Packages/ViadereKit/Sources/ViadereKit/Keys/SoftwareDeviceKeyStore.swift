import Crypto
import Foundation
import ViadereCore

#if DEBUG
/// ⚠️ DEVELOPMENT ONLY. Software P-256 keys for the simulator (which has no Secure Enclave) and unit tests.
/// Compiled out of release builds: `#if DEBUG`. Keys are reported as `hardwareBacked == false` so a server can
/// refuse them in production. Never ships.
public actor SoftwareDeviceKeyStore: DeviceKeyStore {
    private struct Key: ManagedSigningKey {
        let purpose: DeviceKeyPurpose
        let inner: SoftwareP256SigningKey
        var publicKey: DevicePublicKey { inner.publicKey }
        var isHardwareBacked: Bool { false }
        func signature(for data: Data, prompt: SigningPrompt) async throws -> P256.Signing.ECDSASignature {
            try await inner.signature(for: data)
        }
    }

    private let secrets: any SecretStore
    private var cache: [DeviceKeyPurpose: Key] = [:]
    /// Purposes this store should refuse to create (simulates a device without biometrics).
    private let unsupported: Set<DeviceKeyPurpose>

    public init(secrets: any SecretStore = InMemorySecretStore(), unsupported: Set<DeviceKeyPurpose> = []) {
        self.secrets = secrets
        self.unsupported = unsupported
    }

    private func account(_ purpose: DeviceKeyPurpose) -> String { "dev.softkey." + purpose.rawValue }

    public func existingKey(for purpose: DeviceKeyPurpose) async throws -> (any ManagedSigningKey)? {
        if let key = cache[purpose] { return key }
        guard let raw = try secrets.read(account(purpose)), let inner = try? SoftwareP256SigningKey(rawRepresentation: raw) else {
            return nil
        }
        let key = Key(purpose: purpose, inner: inner)
        cache[purpose] = key
        return key
    }

    public func createKey(for purpose: DeviceKeyPurpose) async throws -> any ManagedSigningKey {
        if unsupported.contains(purpose) { throw KeyStoreError.creationFailed(purpose, -1) }
        let inner = SoftwareP256SigningKey()
        try secrets.write(inner.rawRepresentation, account: account(purpose))
        let key = Key(purpose: purpose, inner: inner)
        cache[purpose] = key
        return key
    }

    public func deleteKey(for purpose: DeviceKeyPurpose) async throws {
        cache[purpose] = nil
        try secrets.delete(account(purpose))
    }
}
#endif
