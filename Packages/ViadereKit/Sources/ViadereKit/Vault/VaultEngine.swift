import Crypto
import Foundation
import ViadereCore

public enum VaultPhase: Equatable, Sendable {
    /// No vault on this device yet.
    case empty
    /// A vault exists, sealed. Nothing opens it without the person (Face ID / Touch ID / passcode).
    case locked
    case unlocked
}

public enum VaultEngineError: Error, Equatable, Sendable {
    case notCreated, alreadyExists, locked, deviceKeyMissing
    /// The release gate is off, or the server has no vault service (sync can't be used right now; the local vault is unaffected).
    case syncUnavailable
    case syncNotEnabled
    /// The account already has a synced vault: join it from another device or restore it with the recovery key instead of creating a second one.
    case remoteVaultExists
    case remoteVaultMissing
    /// This account device is not part of the synced vault (approve it from a vault device, or restore with the recovery key).
    case notBound
    case removedFromVault
    /// The server showed an older state than this device already verified.
    case rollbackDetected
    /// Local membership or key changes cannot be merged with changes made elsewhere in the meantime: review the devices list.
    case membershipConflict
    case itemNotFound
    case invalidItem
    /// The on-disk vault does not match what this device last saw (rolled back or replaced).
    case stateTampered
    case storeChanged
    case joinNotApproved
    case noRecoveryKey
    case tooManySyncAttempts
}

/// A passkey-registration request as the credential-provider extension receives it.
public struct PasskeyRegistrationRequest: Sendable {
    public var rpId: String
    public var userName: String
    public var displayName: String?
    public var userHandle: Data
    public var clientDataHash: Data
    public var supportedAlgorithms: [Int]?
    public var excludedCredentialIds: [Data]
    public var requireUserVerification: Bool

    public init(rpId: String, userName: String, displayName: String? = nil, userHandle: Data, clientDataHash: Data, supportedAlgorithms: [Int]? = nil,
                excludedCredentialIds: [Data] = [], requireUserVerification: Bool = true) {
        self.rpId = rpId
        self.userName = userName
        self.displayName = displayName
        self.userHandle = userHandle
        self.clientDataHash = clientDataHash
        self.supportedAlgorithms = supportedAlgorithms
        self.excludedCredentialIds = excludedCredentialIds
        self.requireUserVerification = requireUserVerification
    }
}

/// What the system's AutoFill identity store may hold for a passkey: the minimum the OS needs to offer it. No key material.
public struct PasskeyIdentity: Sendable, Equatable {
    public var recordIdentifier: String
    public var credentialId: Data
    public var rpId: String
    public var userName: String
    public var userHandle: Data
}

/// What the system may hold for a one-time code (iOS 18): a label only. Never the secret or a code.
public struct OneTimeCodeIdentity: Sendable, Equatable {
    public var recordIdentifier: String
    public var label: String
}

public struct VaultDeviceSummary: Sendable, Equatable, Identifiable {
    public var memberId: String
    public var label: String
    public var isThisDevice: Bool
    public var isRecovery: Bool
    public var addedAt: Date
    /// `false` when the server says the account device bound to this member was revoked (remove it and rotate the key).
    public var accountDeviceActive: Bool?
    public var id: String { memberId }
}

/// A new device waiting to be approved (shown on the approving device).
public struct AddDeviceInvite: Sendable {
    public let secret: PairingSecret
    public var code: String { secret.displayString }
    /// The QR payload the new device scans (the pairing code, nothing else).
    public var qrPayload: String { "viadere-vault://pair?c=\(secret.displayString)" }
    public var joinId: String { secret.joinId }
}

public struct JoinRequestPreview: Sendable, Equatable {
    /// The name the new device gave itself, authenticated by the pairing secret.
    public var deviceLabel: String
    /// A short fingerprint of the new device's keys, shown on both devices.
    public var fingerprint: String
}

public struct JoinHandle: Sendable {
    public let secret: PairingSecret
    public var joinId: String { secret.joinId }
}

public struct SyncReport: Sendable, Equatable {
    public enum Outcome: Sendable, Equatable { case upToDate, pushed, pulled, merged }
    public var outcome: Outcome
    public var version: UInt64
}

/// The vault state machine for one device: local encrypted storage, unlock, item changes, passkeys and TOTP, optional sync, device approval and
/// recovery. Used by the app (with a `VaultSyncAPI`) and by the credential-provider extension (without one: it never touches the network).
///
/// Threat notes, in short (`docs/SECURITY.md` §2.40): the vault key lives only in `unlocked` while the vault is open; the store, the server and
/// the extension's shared container hold ciphertext; every change is a signed manifest version; sync verifies the server's chain against the
/// newest manifest this device has already verified and refuses anything older or forked.
public actor VaultEngine {
    private let store: any VaultLocalStore
    private let keys: any VaultKeyProvider
    private let api: (any VaultSyncAPI)?
    private let anchors: any SecretStore
    private let clock: @Sendable () -> Date
    private let deviceLabel: String
    private var unlocked: UnlockedVault?

    private static let anchorAccount = "vault.head"

    public init(store: any VaultLocalStore, keys: any VaultKeyProvider, api: (any VaultSyncAPI)? = nil, anchors: any SecretStore = InMemorySecretStore(),
                deviceLabel: String = "This iPhone", clock: @escaping @Sendable () -> Date = { Date() }) {
        self.store = store
        self.keys = keys
        self.api = api
        self.anchors = anchors
        self.deviceLabel = deviceLabel
        self.clock = clock
    }

    // MARK: State

    private struct HeadAnchor: Codable { var version: UInt64; var hash: Data }

    /// The stored state, checked against the head this device last wrote (stored in the keychain): an older or replaced file is refused.
    private func currentState() throws -> VaultLocalState? {
        guard let state = try store.load() else { return nil }
        if let raw = try anchors.read(Self.anchorAccount), let anchor = try? JSONDecoder().decode(HeadAnchor.self, from: raw) {
            let version = try VaultManifest.decode(state.manifest.manifestBytes).version
            guard version > anchor.version || (version == anchor.version && state.headHash == anchor.hash) else { throw VaultEngineError.stateTampered }
        }
        return state
    }

    private func save(_ state: VaultLocalState, ifHeadIs expected: Data?) throws {
        do { try store.save(state, ifHeadIs: expected) } catch VaultStoreError.changedElsewhere { throw VaultEngineError.storeChanged }
        if let version = try? VaultManifest.decode(state.manifest.manifestBytes).version {
            try anchors.write(try JSONEncoder().encode(HeadAnchor(version: version, hash: state.headHash)), account: Self.anchorAccount)
        }
    }

    public func phase() throws -> VaultPhase {
        guard try currentState() != nil else { return .empty }
        return unlocked == nil ? .locked : .unlocked
    }

    public struct SyncInfo: Sendable, Equatable {
        public var enabled: Bool
        public var pendingChanges: Int
        public var version: UInt64
        public var hasRecoveryKey: Bool
        public var deviceCount: Int
    }

    public func syncInfo() throws -> SyncInfo? {
        guard let state = try currentState() else { return nil }
        let m = try VaultManifest.decode(state.manifest.manifestBytes)
        return SyncInfo(enabled: state.sync.enabled, pendingChanges: state.sync.pending.count, version: m.version, hasRecoveryKey: m.recoveryMember != nil, deviceCount: m.devices.count)
    }

    private func requireUnlocked() throws -> UnlockedVault {
        guard let unlocked else { throw VaultEngineError.locked }
        return unlocked
    }

    public func lock() {
        unlocked = nil
        totpCache = nil
    }

    // MARK: Create, unlock

    /// Creates the (local) vault on this device. The device keys are created first and need the person from then on.
    public func create() async throws {
        guard try currentState() == nil else { throw VaultEngineError.alreadyExists }
        let identity = try await keys.createIdentity()
        let created = try await UnlockedVault.create(identity: identity, label: deviceLabel, now: clock())
        try save(VaultLocalState(snapshot: created.vault.snapshot), ifHeadIs: nil)
        unlocked = created.vault
    }

    /// Opens the vault: the device's envelope is opened with its agreement key, which asks for Face ID / Touch ID / passcode.
    public func unlock() async throws {
        guard let state = try currentState() else { throw VaultEngineError.notCreated }
        guard let identity = try await keys.existingIdentity() else { throw VaultEngineError.deviceKeyMissing }
        unlocked = try UnlockedVault.open(try state.snapshot(), identity: identity)
    }

    /// Re-reads the stored state if another process (the extension) changed it since this one unlocked.
    private func refreshed() async throws -> UnlockedVault {
        let vault = try requireUnlocked()
        guard let state = try currentState() else { throw VaultEngineError.notCreated }
        if state.headHash == vault.snapshot.verified.hash { return vault }
        guard let identity = try await keys.existingIdentity() else { throw VaultEngineError.deviceKeyMissing }
        let reopened = try UnlockedVault.open(try state.snapshot(), identity: identity)
        unlocked = reopened
        return reopened
    }

    // MARK: Items

    public func items() async throws -> [VaultItemPayload] { try await refreshed().items() }

    public func item(id: UUID) async throws -> VaultItemPayload {
        guard let item = try await refreshed().item(id: id) else { throw VaultEngineError.itemNotFound }
        return item
    }

    @discardableResult
    public func addTOTP(_ parameters: TOTPParameters) async throws -> UUID {
        do { try TOTP.validate(parameters) } catch { throw VaultEngineError.invalidItem }
        let item = VaultItemPayload(body: .totp(parameters), createdAt: clock())
        try await apply(upserts: [item], deletes: [])
        return item.id
    }

    @discardableResult
    public func addTOTP(uri: String) async throws -> UUID {
        do { return try await addTOTP(try OTPAuthURI.parse(uri)) } catch is TOTPError { throw VaultEngineError.invalidItem }
    }

    public func deleteItem(_ id: UUID) async throws {
        guard try await refreshed().manifest.items.contains(where: { $0.itemId == id }) else { throw VaultEngineError.itemNotFound }
        try await apply(upserts: [], deletes: [id])
    }

    /// Adds or replaces items (a TOTP edit, an import).
    public func upsert(_ items: [VaultItemPayload]) async throws { try await apply(upserts: items, deletes: []) }

    private func apply(upserts: [VaultItemPayload], deletes: [UUID]) async throws {
        let vault = try await refreshed()
        let mutation = try await vault.applying(upserts: upserts, deletes: deletes, now: clock())
        try commit(mutation, upserted: upserts.map(\.id), deleted: deletes)
    }

    /// Persists a local mutation. With sync on, its delta waits in the queue until `syncNow` uploads it.
    private func commit(_ mutation: VaultMutation, upserted: [UUID] = [], deleted: [UUID] = []) throws {
        guard let state = try currentState() else { throw VaultEngineError.notCreated }
        var next = VaultLocalState(snapshot: mutation.vault.snapshot, sync: state.sync)
        if state.sync.enabled {
            next.sync.pending.append(mutation.delta)
            for id in upserted { next.sync.upserted.removeAll { $0 == id }; next.sync.deleted.removeAll { $0 == id }; next.sync.upserted.append(id) }
            for id in deleted { next.sync.upserted.removeAll { $0 == id }; next.sync.deleted.removeAll { $0 == id }; next.sync.deleted.append(id) }
        }
        try save(next, ifHeadIs: state.headHash)
        unlocked = mutation.vault
    }

    // MARK: Passkeys and codes

    public func passkeys(for rpId: String? = nil) async throws -> [PasskeyCredential] {
        try await refreshed().items().compactMap { item in
            if case .passkey(let credential) = item.body, rpId == nil || credential.rpId == rpId { return credential }
            return nil
        }
    }

    /// Creates and stores a passkey. `userVerified` must reflect a verification that really happened (the extension runs it first).
    public func registerPasskey(_ request: PasskeyRegistrationRequest, userVerified: Bool, attestation: AttestationFormat = .none) async throws -> CreatedPasskey {
        let vault = try await refreshed()
        let existing = try await passkeys(for: request.rpId)
        let created = try WebAuthnAuthenticator.makeCredential(
            rpId: request.rpId, userHandle: request.userHandle, userName: request.userName, displayName: request.displayName, clientDataHash: request.clientDataHash,
            supportedAlgorithms: request.supportedAlgorithms, excludedCredentialIds: request.excludedCredentialIds, existingCredentialIds: Set(existing.map(\.credentialId)),
            requireUserVerification: request.requireUserVerification, userVerified: userVerified, backedUp: try currentState()?.sync.enabled ?? false,
            attestation: attestation, now: clock())
        let item = VaultItemPayload(body: .passkey(created.credential), createdAt: clock())
        let mutation = try await vault.applying(upserts: [item], now: clock())
        try commit(mutation, upserted: [item.id])
        return created
    }

    public func assertPasskey(credentialId: Data, rpId: String, clientDataHash: Data, requireUserVerification: Bool = true, userVerified: Bool) async throws -> PasskeyAssertion {
        guard let credential = try await passkeys(for: rpId).first(where: { $0.credentialId == credentialId }) else { throw VaultEngineError.itemNotFound }
        return try WebAuthnAuthenticator.getAssertion(credential: credential, rpId: rpId, clientDataHash: clientDataHash, requireUserVerification: requireUserVerification,
                                                      userVerified: userVerified, backedUp: try currentState()?.sync.enabled ?? false)
    }

    /// The current code of a TOTP item.
    public func oneTimeCode(for id: UUID, at date: Date? = nil) async throws -> String {
        guard let item = try await refreshed().item(id: id), case .totp(let parameters) = item.body else { throw VaultEngineError.itemNotFound }
        return TOTP.code(for: parameters, at: date ?? clock())
    }

    /// A TOTP code with its countdown, for the list.
    public struct LiveCode: Sendable, Equatable {
        public var code: String
        public var secondsRemaining: Int
        public var period: Int
    }

    /// TOTP parameters decrypted for the current unlock session (the list ticks once a second; decrypting every item each tick would be wasteful).
    /// Keyed by the manifest it was built from and dropped on lock or on any change.
    private var totpCache: (head: Data, items: [UUID: TOTPParameters])?

    /// The current codes of every TOTP item in one call. Uses the vault as this process last opened or changed it (no store re-read per tick);
    /// `items()` and every mutation pick up changes made by the extension.
    public func liveCodes(at date: Date? = nil) async throws -> [UUID: LiveCode] {
        let vault = try requireUnlocked()
        let head = vault.snapshot.verified.hash
        if totpCache?.head != head {
            var parameters: [UUID: TOTPParameters] = [:]
            for item in try vault.items() { if case .totp(let t) = item.body { parameters[item.id] = t } }
            totpCache = (head, parameters)
        }
        let now = date ?? clock()
        return (totpCache?.items ?? [:]).mapValues { t in
            LiveCode(code: TOTP.code(for: t, at: now), secondsRemaining: TOTP.secondsRemaining(period: t.period, at: now), period: t.period)
        }
    }

    /// Metadata for the system AutoFill identity store (`ASCredentialIdentityStore`). Only what the OS needs to offer the credential.
    public func passkeyIdentities() async throws -> [PasskeyIdentity] {
        try await refreshed().items().compactMap { item in
            guard case .passkey(let c) = item.body else { return nil }
            return PasskeyIdentity(recordIdentifier: item.id.uuidString.lowercased(), credentialId: c.credentialId, rpId: c.rpId, userName: c.userName, userHandle: c.userHandle)
        }
    }

    public func oneTimeCodeIdentities() async throws -> [OneTimeCodeIdentity] {
        try await refreshed().items().compactMap { item in
            guard case .totp(let t) = item.body else { return nil }
            let label = [t.issuer, t.accountName].compactMap { $0 }.filter { !$0.isEmpty }.joined(separator: " · ")
            return OneTimeCodeIdentity(recordIdentifier: item.id.uuidString.lowercased(), label: DisplayTextSanitizer.sanitize(label, maxCharacters: 80))
        }
    }

    // MARK: Devices and recovery key (local reads)

    public func devices(serverInfo: [VaultDeviceInfo] = []) async throws -> [VaultDeviceSummary] {
        let vault = try await refreshed()
        return vault.manifest.members.map { member in
            VaultDeviceSummary(memberId: member.id, label: member.role == .recovery ? "Recovery key" : (vault.label(of: member.id) ?? "Device"),
                               isThisDevice: member.id == vault.memberId, isRecovery: member.role == .recovery,
                               addedAt: Date(timeIntervalSince1970: TimeInterval(member.addedAt)),
                               accountDeviceActive: serverInfo.first { $0.memberId == member.id }?.accountDeviceActive)
        }.sorted { $0.addedAt < $1.addedAt }
    }

    /// Whether `text` is the recovery key of this vault (compares derived public keys with the manifest; nothing leaves the device).
    public func verifyRecoveryKey(_ text: String) async throws -> Bool {
        let vault = try await refreshed()
        guard let member = vault.manifest.recoveryMember else { throw VaultEngineError.noRecoveryKey }
        guard let key = try? RecoveryKey(parsing: text), let identity = try? key.identity(vaultId: vault.vaultId) else { return false }
        return identity.signingPublicKey == member.signingKey && identity.agreementPublicKey == member.agreementKey
    }

    public func makeRecoveryKey() -> RecoveryKey { RecoveryKey.generate() }

    /// Installs (or replaces) the recovery key. Replace with `rotateVaultKey` when the old key may have leaked.
    public func installRecoveryKey(_ key: RecoveryKey, rotateVaultKey: Bool = false) async throws {
        let vault = try await refreshed()
        let mutation = try await vault.settingRecoveryKey(key, rotateKey: rotateVaultKey, now: clock())
        try commit(mutation)
        if try currentState()?.sync.enabled == true { try await syncNow() }
    }

    // MARK: Sync

    private func requireAPI() throws -> any VaultSyncAPI {
        guard let api else { throw VaultEngineError.syncUnavailable }
        return api
    }

    /// `true` when the server offers vault sync right now (the release gate is open).
    public func syncAvailable() async -> Bool {
        guard let api else { return false }
        return (try? await api.status()) != nil
    }

    private func mapped<T>(_ body: () async throws -> T) async throws -> T {
        do { return try await body() } catch let error as APIError {
            if case .server(let status, let code, _) = error, status == 404, code == .notFound { throw VaultEngineError.syncUnavailable }
            throw error
        } catch VaultError.rollback {
            throw VaultEngineError.rollbackDetected
        }
    }

    /// Turns sync on: the vault is re-created as a synced one (new vault key, new history) holding the same items, with this device as its first
    /// device. Needs the vault unlocked. Show the recovery key and have the person confirm it BEFORE calling this.
    public func enableSync(recoveryKey: RecoveryKey?) async throws {
        let api = try requireAPI()
        guard let state = try currentState() else { throw VaultEngineError.notCreated }
        guard !state.sync.enabled else { return }
        let vault = try await refreshed()
        let remote = try await mapped { try await api.status() }
        guard !remote.exists else { throw VaultEngineError.remoteVaultExists }
        let items = try vault.items()
        let created = try await UnlockedVault.create(identity: vault.identity, label: vault.label(of: vault.memberId) ?? deviceLabel, recoveryKey: recoveryKey, items: items, now: clock())
        _ = try await mapped { try await api.put(Self.request(created.delta, expected: 0, bind: created.vault.memberId)) }
        try save(VaultLocalState(snapshot: created.vault.snapshot, sync: .init(enabled: true, anchor: created.delta.manifest)), ifHeadIs: state.headHash)
        unlocked = created.vault
    }

    /// Stops syncing. With `deleteFromServer` the encrypted copy is erased from the server as well; the local vault stays either way.
    public func disableSync(deleteFromServer: Bool) async throws {
        guard let state = try currentState() else { throw VaultEngineError.notCreated }
        if deleteFromServer, state.sync.enabled { try await mapped { try await requireAPI().deleteVault() } }
        var next = state
        next.sync = .init()
        try save(next, ifHeadIs: state.headHash)
    }

    static func request(_ delta: VaultDelta, expected: UInt64, bind: String? = nil, join: (id: String, memberId: String, approval: Data)? = nil) -> VaultPutRequest {
        VaultPutRequest(expectedVersion: expected, manifest: VaultManifestDTO(delta.manifest),
                        blobs: delta.blobs.map { VaultBlobDTO(itemId: $0.key, blob: Base64URL.encode($0.value)) },
                        envelopes: delta.envelopes.map { VaultEnvelopeDTO(memberId: $0.key, envelope: Base64URL.encode($0.value)) },
                        bindMemberId: bind, joinId: join?.id, joinApproval: join.map { Base64URL.encode($0.approval) }, joinMemberId: join?.memberId)
    }

    /// Pulls and pushes. Safe to call at any time; retries when another device wins a race.
    @discardableResult
    public func syncNow() async throws -> SyncReport {
        for _ in 0..<4 {
            do { return try await syncOnce() } catch VaultEngineError.storeChanged {
                continue
            } catch APIError.server(let status, _, _) where status == 409 {
                continue
            }
        }
        throw VaultEngineError.tooManySyncAttempts
    }

    private func syncOnce() async throws -> SyncReport {
        let api = try requireAPI()
        guard let state = try currentState() else { throw VaultEngineError.notCreated }
        guard state.sync.enabled, let anchorSigned = state.sync.anchor else { throw VaultEngineError.syncNotEnabled }
        let vault = try await refreshed()
        let anchor = try VaultChainVerifier.restore(anchorSigned)
        let status = try await mapped { try await api.status() }
        guard status.exists else { throw VaultEngineError.remoteVaultMissing }
        guard status.bound else { throw VaultEngineError.notBound }
        guard status.version >= anchor.manifest.version else { throw VaultEngineError.rollbackDetected }

        // The server's history since the anchor, verified link by link against it.
        var chain: [SignedVaultManifest] = []
        var after = anchor.manifest.version
        while after < status.version {
            let page = try await mapped { try await api.manifests(after: after) }
            let signed = page.manifests.compactMap(\.signed)
            guard let newest = signed.last, let version = try? VaultManifest.decode(newest.manifestBytes).version, version > after else { break }
            chain += signed
            after = version
        }
        let remoteHead: VerifiedManifest
        if chain.isEmpty {
            guard status.version == anchor.manifest.version else { throw VaultEngineError.rollbackDetected }
            remoteHead = anchor
        } else {
            remoteHead = try await mapped { try VaultChainVerifier.verifyChain(chain, trusted: anchor) }
        }
        guard remoteHead.manifest.version == status.version else { throw VaultEngineError.rollbackDetected }

        // Nothing changed remotely: upload what is waiting.
        if remoteHead.hash == anchor.hash {
            guard !state.sync.pending.isEmpty else { return SyncReport(outcome: .upToDate, version: status.version) }
            var expected = status.version
            for delta in state.sync.pending {
                let result = try await mapped { try await api.put(Self.request(delta, expected: expected)) }
                expected = result.version
            }
            try finishSync(pushedThrough: state.sync.pending.last!.manifest)
            return SyncReport(outcome: .pushed, version: expected)
        }

        // Something changed remotely: fetch the new head (reusing blobs already held) and open it with this device's envelope.
        let envelope = try await mapped { try await api.envelope() }
        guard let identityEnvelope = Base64URL.decode(envelope.envelope), envelope.memberId == vault.memberId else { throw VaultEngineError.removedFromVault }
        let local = try state.snapshot()
        var blobs: [UUID: Data] = [:]
        var needed: [UUID] = []
        for ref in remoteHead.manifest.items {
            if let held = local.blobs[ref.itemId], Data(SHA256.hash(data: held)) == ref.blobHash { blobs[ref.itemId] = held } else { needed.append(ref.itemId) }
        }
        if !needed.isEmpty {
            for dto in try await mapped({ try await api.blobs(needed) }) { if let data = Base64URL.decode(dto.blob) { blobs[dto.itemId] = data } }
        }
        let remoteSnapshot = VaultSnapshot(verified: remoteHead, blobs: blobs, envelopes: [vault.memberId: identityEnvelope])
        let remoteVault: UnlockedVault
        do { remoteVault = try UnlockedVault.open(remoteSnapshot, identity: vault.identity) } catch VaultError.notAMember { throw VaultEngineError.removedFromVault }

        if state.sync.pending.isEmpty {
            try save(VaultLocalState(snapshot: remoteVault.snapshot, sync: .init(enabled: true, anchor: remoteHead.signed)), ifHeadIs: state.headHash)
            unlocked = remoteVault
            return SyncReport(outcome: .pulled, version: remoteHead.manifest.version)
        }

        // Both sides changed. Item changes are re-applied on top of the remote state (last writer wins per item); membership and key changes
        // made here cannot be merged silently.
        let localManifest = vault.manifest
        guard localManifest.epoch == anchor.manifest.epoch, Set(localManifest.members.map(\.id)) == Set(anchor.manifest.members.map(\.id)) else {
            throw VaultEngineError.membershipConflict
        }
        let upserts = try state.sync.upserted.compactMap { try vault.item(id: $0) }
        let merged = try await remoteVault.applying(upserts: upserts, deletes: state.sync.deleted, now: clock())
        _ = try await mapped { try await api.put(Self.request(merged.delta, expected: remoteHead.manifest.version)) }
        try save(VaultLocalState(snapshot: merged.vault.snapshot, sync: .init(enabled: true, anchor: merged.delta.manifest)), ifHeadIs: state.headHash)
        unlocked = merged.vault
        return SyncReport(outcome: .merged, version: merged.vault.manifest.version)
    }

    /// After uploading: the server has everything up to `manifest`. Re-reads the state (the extension may have added changes meanwhile) and drops only what was uploaded.
    private func finishSync(pushedThrough manifest: SignedVaultManifest) throws {
        guard var latest = try currentState() else { return }
        let pushed = latest.sync.pending.firstIndex { $0.manifest.hash == manifest.hash }
        if let pushed { latest.sync.pending.removeFirst(pushed + 1) }
        latest.sync.anchor = manifest
        if latest.sync.pending.isEmpty { latest.sync.upserted = []; latest.sync.deleted = [] }
        try save(latest, ifHeadIs: latest.headHash)
    }

    // MARK: Adding a device (approving side)

    /// Starts adding a device: shows a one-time pairing code (the device that scans or types it proves it has been in front of this one).
    public func beginAddingDevice() async throws -> AddDeviceInvite {
        let api = try requireAPI()
        _ = try requireUnlocked()
        _ = try await syncNow()
        let invite = AddDeviceInvite(secret: PairingSecret.generate())
        _ = try await mapped { try await api.createJoin(invite.joinId) }
        return invite
    }

    /// The new device's request, once it has arrived (decrypted with the pairing secret; the server only held ciphertext).
    public func joinRequest(for invite: AddDeviceInvite) async throws -> JoinRequestPreview? {
        let api = try requireAPI()
        let state = try await mapped { try await api.join(invite.joinId) }
        guard let sealed = state.request.flatMap(Base64URL.decode) else { return nil }
        let request = try JoinRequest.open(sealed, with: invite.secret)
        let fingerprint = CrockfordFingerprint.short(of: request.signingKey)
        return JoinRequestPreview(deviceLabel: request.label, fingerprint: fingerprint)
    }

    /// Approves the new device. The caller must have shown `JoinRequestPreview` and asked for Face ID / Touch ID (signing the manifest needs it).
    public func approveJoin(_ invite: AddDeviceInvite) async throws {
        let api = try requireAPI()
        _ = try await syncNow()
        let vault = try await refreshed()
        let state = try await mapped { try await api.join(invite.joinId) }
        guard let sealed = state.request.flatMap(Base64URL.decode) else { throw VaultEngineError.joinNotApproved }
        let request = try JoinRequest.open(sealed, with: invite.secret)
        let mutation = try await vault.approvingJoin(request, secret: invite.secret, now: clock())
        let memberId = VaultMemberID.make(signingKey: request.signingKey)
        guard let approval = mutation.approval else { throw VaultEngineError.joinNotApproved }
        _ = try await mapped { try await api.put(Self.request(mutation.delta, expected: vault.manifest.version, join: (invite.joinId, memberId, approval))) }
        guard let current = try currentState() else { throw VaultEngineError.notCreated }
        try save(VaultLocalState(snapshot: mutation.vault.snapshot, sync: .init(enabled: true, anchor: mutation.delta.manifest)), ifHeadIs: current.headHash)
        unlocked = mutation.vault
    }

    public func cancelAddingDevice(_ invite: AddDeviceInvite) async {
        try? await requireAPI().cancelJoin(invite.joinId)
    }

    // MARK: Joining (new device side)

    /// The new device asks to join with the pairing code from the approving device. This device's keys are created first.
    public func requestJoin(code: String, label: String? = nil) async throws -> JoinHandle {
        let api = try requireAPI()
        guard try currentState() == nil else { throw VaultEngineError.alreadyExists }
        let secret = try PairingSecret(parsing: code)
        let identity = try await keys.createIdentity()
        let sealed = try JoinRequest.make(for: identity, label: label ?? deviceLabel).sealed(with: secret)
        _ = try await mapped { try await api.submitJoinRequest(secret.joinId, sealed: Base64URL.encode(sealed)) }
        return JoinHandle(secret: secret)
    }

    /// Completes the join once the approving device has approved: verifies, through the pairing channel, that the manifest and the approving
    /// device are the ones the person paired with, downloads the vault and opens it.
    public func completeJoin(_ handle: JoinHandle) async throws {
        let api = try requireAPI()
        guard let identity = try await keys.existingIdentity() else { throw VaultEngineError.deviceKeyMissing }
        let join = try await mapped { try await api.join(handle.joinId) }
        guard let approval = join.approval.flatMap(Base64URL.decode), let approvedVersion = join.approvedVersion else { throw VaultEngineError.joinNotApproved }
        // The manifest the approval names (hash and signer pinned by the pairing secret).
        let first = try await mapped { try await api.manifests(after: approvedVersion - 1) }
        guard let approvedManifest = first.manifests.compactMap(\.signed).first else { throw VaultEngineError.joinNotApproved }
        let anchor = try UnlockedVault.pinningJoin(approval: approval, secret: handle.secret, manifest: approvedManifest)
        // Then onward to the newest version, verified link by link.
        var chain = [approvedManifest]
        var after = anchor.manifest.version
        let status = try await mapped { try await api.status() }
        while after < status.version {
            let page = try await mapped { try await api.manifests(after: after) }
            let signed = page.manifests.compactMap(\.signed)
            guard let newest = signed.last, let version = try? VaultManifest.decode(newest.manifestBytes).version, version > after else { break }
            chain += signed
            after = version
        }
        let head = try await mapped { try VaultChainVerifier.verifyChain(chain, trusted: anchor) }
        let envelope = try await mapped { try await api.envelope() }
        guard let envelopeBytes = Base64URL.decode(envelope.envelope), envelope.memberId == identity.memberId else { throw VaultEngineError.notBound }
        var blobs: [UUID: Data] = [:]
        for dto in try await mapped({ try await api.blobs(head.manifest.items.map(\.itemId)) }) { if let data = Base64URL.decode(dto.blob) { blobs[dto.itemId] = data } }
        let snapshot = VaultSnapshot(verified: head, blobs: blobs, envelopes: [identity.memberId: envelopeBytes])
        let opened = try UnlockedVault.open(snapshot, identity: identity)
        _ = try opened.items()          // every item must decrypt before the vault is accepted
        try save(VaultLocalState(snapshot: snapshot, sync: .init(enabled: true, anchor: head.signed)), ifHeadIs: nil)
        unlocked = opened
        try? await api.cancelJoin(handle.joinId)
    }

    // MARK: Removing a device

    /// Removes a device and replaces the vault key, so it cannot read anything written from now on (what it already copied stays copied:
    /// change the passwords and passkeys that were in the vault if the device was stolen).
    public func removeDevice(_ memberId: String) async throws {
        let api = try requireAPI()
        _ = try await syncNow()
        let vault = try await refreshed()
        let mutation = try await vault.removingDevice(memberId, now: clock())
        _ = try await mapped { try await api.put(Self.request(mutation.delta, expected: vault.manifest.version)) }
        guard let current = try currentState() else { throw VaultEngineError.notCreated }
        try save(VaultLocalState(snapshot: mutation.vault.snapshot, sync: .init(enabled: true, anchor: mutation.delta.manifest)), ifHeadIs: current.headHash)
        unlocked = mutation.vault
    }

    public func serverDevices() async throws -> [VaultDeviceInfo] { try await mapped { try await requireAPI().devices() } }

    // MARK: Restoring with the recovery key (new device)

    /// Restores the synced vault onto this device with the vault recovery key. Account sign-in alone never reaches this: without the key the
    /// server's data cannot be opened or authenticated. The recovery key is used up: `newRecoveryKey` (shown to the person and confirmed BEFORE
    /// this call) replaces it, the vault key is replaced, and every other device is removed.
    public func restore(recoveryKey text: String, newRecoveryKey: RecoveryKey, label: String? = nil) async throws {
        let api = try requireAPI()
        guard try currentState() == nil else { throw VaultEngineError.alreadyExists }
        let key = try RecoveryKey(parsing: text)
        let status = try await mapped { try await api.status() }
        guard status.exists else { throw VaultEngineError.remoteVaultMissing }
        var chain: [SignedVaultManifest] = []
        var after: UInt64 = 0
        while after < status.version {
            let page = try await mapped { try await api.manifests(after: after) }
            let signed = page.manifests.compactMap(\.signed)
            guard let newest = signed.last, let version = try? VaultManifest.decode(newest.manifestBytes).version, version > after else { break }
            chain += signed
            after = version
        }
        let head = try await mapped { try UnlockedVault.authenticateChain(chain, recoveryKey: key) }
        guard head.manifest.version == status.version else { throw VaultEngineError.rollbackDetected }
        guard let recoveryMember = head.manifest.recoveryMember else { throw VaultEngineError.noRecoveryKey }
        let envelope = try await mapped { try await api.recoveryEnvelope() }
        guard envelope.memberId == recoveryMember.id, let envelopeBytes = Base64URL.decode(envelope.envelope) else { throw VaultError.blobMismatch }
        var blobs: [UUID: Data] = [:]
        for dto in try await mapped({ try await api.blobs(head.manifest.items.map(\.itemId)) }) { if let data = Base64URL.decode(dto.blob) { blobs[dto.itemId] = data } }
        let snapshot = VaultSnapshot(verified: head, blobs: blobs, envelopes: [recoveryMember.id: envelopeBytes])
        let identity = try await keys.createIdentity()
        let mutation = try await UnlockedVault.recovering(snapshot, recoveryKey: key, newRecoveryKey: newRecoveryKey, newDevice: identity, label: label ?? deviceLabel, now: clock())
        _ = try await mapped { try await api.put(Self.request(mutation.delta, expected: head.manifest.version, bind: identity.memberId)) }
        try save(VaultLocalState(snapshot: mutation.vault.snapshot, sync: .init(enabled: true, anchor: mutation.delta.manifest)), ifHeadIs: nil)
        unlocked = mutation.vault
    }

    // MARK: Wiping

    /// Removes the local vault and this device's vault keys (sign-out, account deletion, device revoked). The server copy is untouched.
    public func wipeLocal() async throws {
        unlocked = nil
        totpCache = nil
        try store.erase()
        try? anchors.delete(Self.anchorAccount)
        try await keys.deleteIdentity()
    }
}

enum CrockfordFingerprint {
    /// Ten characters of the SHA-256 of a public key, in two groups, for comparing two screens by eye.
    static func short(of publicKey: Data) -> String {
        let text = Hex.encode(SHA256.hash(data: publicKey).prefix(5)).uppercased()
        return String(text.prefix(5)) + "-" + String(text.suffix(5))
    }
}
