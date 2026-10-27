import Foundation
import ViadereCore
#if canImport(Glibc)
import Glibc
#elseif canImport(Darwin)
import Darwin
#endif

/// Everything a device keeps about its vault on disk: ciphertext, signed public structures and sync bookkeeping. **No key material and no
/// plaintext**: the vault key exists only inside an unlocked session, opened from the device's own envelope with a key that needs the person
/// (`VaultKeyProvider`). This is the whole of what the credential-provider extension shares with the app (App Group container).
public struct VaultLocalState: Codable, Sendable, Equatable {
    /// The device's current view of the vault (including changes not yet uploaded).
    public var manifest: SignedVaultManifest
    public var blobs: [String: Data]
    public var envelopes: [String: Data]
    public var sync: SyncMarker

    public struct SyncMarker: Codable, Sendable, Equatable {
        public var enabled: Bool
        /// The newest manifest this device verified **against the server** (its trust anchor: anything older is a rollback).
        public var anchor: SignedVaultManifest?
        /// Local versions the server has not seen yet, oldest first.
        public var pending: [VaultDelta]
        /// Items changed locally since the anchor (rebasing re-applies these on a newer remote state).
        public var upserted: [UUID]
        public var deleted: [UUID]

        public init(enabled: Bool = false, anchor: SignedVaultManifest? = nil, pending: [VaultDelta] = [], upserted: [UUID] = [], deleted: [UUID] = []) {
            self.enabled = enabled
            self.anchor = anchor
            self.pending = pending
            self.upserted = upserted
            self.deleted = deleted
        }
    }

    public init(snapshot: VaultSnapshot, sync: SyncMarker = SyncMarker()) {
        manifest = snapshot.verified.signed
        blobs = Dictionary(uniqueKeysWithValues: snapshot.blobs.map { ($0.key.uuidString, $0.value) })
        envelopes = snapshot.envelopes
        self.sync = sync
    }

    /// The snapshot, with the manifest re-parsed (structure only: its signature was checked when it was accepted).
    public func snapshot() throws -> VaultSnapshot {
        VaultSnapshot(verified: try VaultChainVerifier.restore(manifest),
                      blobs: Dictionary(uniqueKeysWithValues: blobs.compactMap { key, value in UUID(uuidString: key).map { ($0, value) } }), envelopes: envelopes)
    }

    public var headHash: Data { manifest.hash }
}

public enum VaultStoreError: Error, Equatable, Sendable {
    /// Another process changed the vault since it was read (`save(ifHeadIs:)`).
    case changedElsewhere
    case unreadable
}

/// Persistence for `VaultLocalState`, shared by the app and the credential-provider extension.
public protocol VaultLocalStore: Sendable {
    func load() throws -> VaultLocalState?
    /// Saves `state` only if the stored head is still `expectedHead` (`nil` = nothing stored yet): the app and the extension can both write, and
    /// neither may overwrite the other's change.
    func save(_ state: VaultLocalState, ifHeadIs expectedHead: Data?) throws
    func erase() throws
}

public final class InMemoryVaultLocalStore: VaultLocalStore, @unchecked Sendable {
    private let lock = NSLock()
    private var state: VaultLocalState?
    public init(_ state: VaultLocalState? = nil) { self.state = state }

    public func load() throws -> VaultLocalState? { lock.withLock { state } }

    public func save(_ new: VaultLocalState, ifHeadIs expectedHead: Data?) throws {
        try lock.withLock {
            guard state?.headHash == expectedHead else { throw VaultStoreError.changedElsewhere }
            state = new
        }
    }

    public func erase() throws { lock.withLock { state = nil } }
}

/// One JSON file in a directory (the App Group container in production), written atomically under an exclusive `flock` so the app and the
/// extension never interleave. The file is excluded from backup (a restored copy would only be an unusable, possibly stale, ciphertext).
public final class FileVaultLocalStore: VaultLocalStore, @unchecked Sendable {
    private let directory: URL
    private var fileURL: URL { directory.appendingPathComponent("vault-state.json") }
    private var lockURL: URL { directory.appendingPathComponent("vault-state.lock") }

    public init(directory: URL) { self.directory = directory }

    /// The names of the files this store creates (tests list the container to check that only these exist).
    public static let fileNames: Set<String> = ["vault-state.json", "vault-state.lock"]

    private func withLock<T>(_ body: () throws -> T) throws -> T {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let fd = open(lockURL.path, O_CREAT | O_RDWR, 0o600)
        guard fd >= 0 else { throw VaultStoreError.unreadable }
        defer { close(fd) }
        guard flock(fd, LOCK_EX) == 0 else { throw VaultStoreError.unreadable }
        defer { flock(fd, LOCK_UN) }
        return try body()
    }

    private func read() throws -> VaultLocalState? {
        guard FileManager.default.fileExists(atPath: fileURL.path) else { return nil }
        guard let data = try? Data(contentsOf: fileURL), let state = try? JSONDecoder().decode(VaultLocalState.self, from: data) else { throw VaultStoreError.unreadable }
        return state
    }

    public func load() throws -> VaultLocalState? { try withLock { try read() } }

    public func save(_ state: VaultLocalState, ifHeadIs expectedHead: Data?) throws {
        try withLock {
            guard try read()?.headHash == expectedHead else { throw VaultStoreError.changedElsewhere }
            let data = try JSONEncoder().encode(state)
            try data.write(to: fileURL, options: [.atomic])
            #if os(iOS) || os(macOS) || os(watchOS)
            try? FileManager.default.setAttributes([.protectionKey: FileProtectionType.completeUntilFirstUserAuthentication], ofItemAtPath: fileURL.path)
            #endif
            var url = fileURL
            var values = URLResourceValues()
            values.isExcludedFromBackup = true
            try? url.setResourceValues(values)
        }
    }

    public func erase() throws {
        try withLock { try? FileManager.default.removeItem(at: fileURL) }
    }
}
