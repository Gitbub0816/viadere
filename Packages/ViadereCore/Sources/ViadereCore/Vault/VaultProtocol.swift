import Crypto
import Foundation

/// A vault as one device holds it: the verified manifest, the encrypted blobs and the envelopes it has. Everything in it is ciphertext
/// or public; it is what the extension and the app share on disk and what the server stores.
public struct VaultSnapshot: Sendable, Equatable {
    public var verified: VerifiedManifest
    public var blobs: [UUID: Data]
    /// Envelopes by member id (a device normally holds its own, the creating device holds those it made).
    public var envelopes: [String: Data]

    public init(verified: VerifiedManifest, blobs: [UUID: Data] = [:], envelopes: [String: Data] = [:]) {
        self.verified = verified
        self.blobs = blobs
        self.envelopes = envelopes
    }

    public var manifest: VaultManifest { verified.manifest }
    public var vaultId: UUID { manifest.vaultId }

    /// Items the manifest lists that this snapshot has no blob for yet.
    public var missingBlobs: [UUID] { manifest.items.map(\.itemId).filter { blobs[$0] == nil } }

    /// Every held blob and envelope must be exactly what the signed manifest commits to; anything else is the server (or disk) lying.
    public func validateContents() throws {
        let refs = Dictionary(uniqueKeysWithValues: manifest.items.map { ($0.itemId, $0) })
        for (id, blob) in blobs {
            guard let ref = refs[id], Data(SHA256.hash(data: blob)) == ref.blobHash else { throw VaultError.blobMismatch }
        }
        for (memberId, envelope) in envelopes {
            guard let member = manifest.member(memberId), VaultEnvelope.hash(envelope) == member.envelopeHash else { throw VaultError.blobMismatch }
        }
    }
}

/// What a mutation adds to the server: the new signed manifest plus only the blobs and envelopes that changed.
public struct VaultDelta: Sendable, Equatable, Codable {
    public var manifest: SignedVaultManifest
    public var blobs: [UUID: Data]
    public var removedItems: [UUID]
    public var envelopes: [String: Data]
}

public struct VaultMutation: Sendable {
    public var vault: UnlockedVault
    public var delta: VaultDelta
    /// For a device approval: the sealed approval the new device reads (`VaultProtocol` docs).
    public var approval: Data?
}

/// A device the vault is being opened for: an unlocked vault key plus the verified snapshot. Created by `create`, `open`, `acceptJoin`
/// or `recover`; every change returns a new value and the delta to upload.
public struct UnlockedVault: Sendable {
    public let vaultKey: VaultKey
    public let snapshot: VaultSnapshot
    public let identity: VaultDeviceIdentity

    public var manifest: VaultManifest { snapshot.manifest }
    public var vaultId: UUID { snapshot.vaultId }
    public var memberId: String { identity.memberId }

    init(vaultKey: VaultKey, snapshot: VaultSnapshot, identity: VaultDeviceIdentity) {
        self.vaultKey = vaultKey
        self.snapshot = snapshot
        self.identity = identity
    }

    /// The same vault opened with a freshly authenticated copy of this device's own keys. Membership and recovery operations (approve a
    /// device, remove one, replace the recovery key) sign with a key bound to an authentication evaluated **for that operation** instead of
    /// the one from unlock (gate review L2). The member must be the same one.
    public func withIdentity(_ fresh: VaultDeviceIdentity) throws -> UnlockedVault {
        guard fresh.memberId == identity.memberId, fresh.agreementPublicKey == identity.agreementPublicKey else { throw VaultError.forbidden("different device identity") }
        return UnlockedVault(vaultKey: vaultKey, snapshot: snapshot, identity: fresh)
    }

    // MARK: Labels

    private static func labelKey(_ key: VaultKey, vaultId: UUID) -> SymmetricKey {
        VaultKDF.deriveKey(key.key, salt: VaultBytes.uuid(vaultId), label: VaultFormat.Label.deviceLabelKey)
    }

    private static func sealLabel(_ label: String, memberId: String, key: VaultKey, vaultId: UUID) throws -> Data {
        let trimmed = label.trimmingCharacters(in: .whitespacesAndNewlines)
        let clean = String(trimmed.unicodeScalars.filter { !DisplayTextSanitizer.isDisallowed($0) }.map(Character.init))
        var bytes = Data(clean.utf8)
        while bytes.count > VaultFormat.maxLabelBytes { bytes = Data(String(decoding: bytes, as: UTF8.self).dropLast().utf8) }
        return try VaultSeal.seal(bytes, key: labelKey(key, vaultId: vaultId), aad: VaultAAD.make("device-label", [VaultBytes.uuid(vaultId), Data(memberId.utf8)]))
    }

    /// The name a device gave itself, readable only with the vault key.
    public func label(of memberId: String) -> String? {
        guard let sealed = manifest.member(memberId)?.sealedLabel,
              let plain = try? VaultSeal.open(sealed, key: Self.labelKey(vaultKey, vaultId: vaultId),
                                              aad: VaultAAD.make("device-label", [VaultBytes.uuid(vaultId), Data(memberId.utf8)])) else { return nil }
        return String(decoding: plain, as: UTF8.self)
    }

    // MARK: Creating and opening

    /// A vault holds at most `VaultFormat.maxTotalBlobBytes` of item ciphertext, so that a key rotation (which re-uploads every blob in one
    /// atomic request) always fits. The error is `limitExceeded("vault size")`: the app shows it as "Your vault is full".
    static func requireRoom(_ blobs: some Collection<Data>) throws {
        guard blobs.reduce(0, { $0 + $1.count }) <= VaultFormat.maxTotalBlobBytes else { throw VaultError.limitExceeded("vault size") }
    }

    /// A new vault with this device as its only device. `recoveryKey` (optional) adds the recovery member.
    public static func create(identity: VaultDeviceIdentity, label: String, recoveryKey: RecoveryKey? = nil, items: [VaultItemPayload] = [],
                              now: Date) async throws -> VaultMutation {
        let vaultId = UUID()
        let key = VaultKey.generate()
        let epoch: UInt64 = 1
        let at = UInt64(max(0, now.timeIntervalSince1970))
        let me = identity.memberId
        var members: [VaultMember] = []
        var envelopes: [String: Data] = [:]
        let myEnvelope = try VaultEnvelope.seal(key, to: identity.agreementPublicKey, vaultId: vaultId, epoch: epoch, memberId: me)
        envelopes[me] = myEnvelope
        members.append(VaultMember(role: .device, signingKey: identity.signingPublicKey, agreementKey: identity.agreementPublicKey,
                                   envelopeHash: VaultEnvelope.hash(myEnvelope), addedAt: at,
                                   sealedLabel: try sealLabel(label, memberId: me, key: key, vaultId: vaultId)))
        if let recoveryKey {
            let (member, envelope) = try recoveryMember(recoveryKey, vaultId: vaultId, key: key, epoch: epoch, installer: identity, at: at)
            members.append(member)
            envelopes[member.id] = envelope
        }
        var refs: [VaultItemRef] = []
        var blobs: [UUID: Data] = [:]
        for item in items {
            let blob = try VaultItemBlob.seal(item, vaultId: vaultId, epoch: epoch, revision: 1, vaultKey: key)
            refs.append(VaultItemRef(itemId: item.id, revision: 1, blobHash: Data(SHA256.hash(data: blob))))
            blobs[item.id] = blob
        }
        try requireRoom(blobs.values)
        let manifest = VaultManifest(vaultId: vaultId, version: 1, previousHash: VaultManifest.genesisPreviousHash, epoch: epoch, keyCheck: key.keyCheck(epoch: epoch),
                                     members: members, items: refs, signerId: me, createdAt: at)
        let signed = try await SignedVaultManifest.sign(manifest, with: identity.signingKey)
        let verified = try VaultChainVerifier.verifyGenesis(signed)
        let vault = UnlockedVault(vaultKey: key, snapshot: VaultSnapshot(verified: verified, blobs: blobs, envelopes: envelopes), identity: identity)
        return VaultMutation(vault: vault, delta: VaultDelta(manifest: signed, blobs: blobs, removedItems: [], envelopes: envelopes), approval: nil)
    }

    private static func recoveryMember(_ recoveryKey: RecoveryKey, vaultId: UUID, key: VaultKey, epoch: UInt64, installer: VaultDeviceIdentity, at: UInt64) throws -> (VaultMember, Data) {
        let recovery = try recoveryKey.identity(vaultId: vaultId)
        let envelope = try VaultEnvelope.seal(key, to: recovery.agreementPublicKey, vaultId: vaultId, epoch: epoch, memberId: recovery.memberId)
        let binding = recoveryKey.binding(vaultId: vaultId, memberId: recovery.memberId, installerKey: installer.signingPublicKey)
        return (VaultMember(role: .recovery, signingKey: recovery.signingPublicKey, agreementKey: recovery.agreementPublicKey,
                            envelopeHash: VaultEnvelope.hash(envelope), addedAt: at, sealedLabel: nil, binding: binding), envelope)
    }

    /// Opens a verified snapshot for `identity` (a device, or the recovery member): its envelope must open, and the key inside must match the
    /// manifest's signed commitment.
    public static func open(_ snapshot: VaultSnapshot, identity: VaultDeviceIdentity) throws -> UnlockedVault {
        guard let member = snapshot.manifest.member(identity.memberId), member.agreementKey == identity.agreementPublicKey else { throw VaultError.notAMember }
        try snapshot.validateContents()
        guard let envelope = snapshot.envelopes[member.id] else { throw VaultError.malformed("no envelope for this device") }
        let key = try VaultEnvelope.open(envelope, with: identity.agreementKey, vaultId: snapshot.vaultId, epoch: snapshot.manifest.epoch, memberId: member.id)
        guard ConstantTime.equals(key.keyCheck(epoch: snapshot.manifest.epoch), snapshot.manifest.keyCheck) else { throw VaultError.keyCheckMismatch }
        return UnlockedVault(vaultKey: key, snapshot: snapshot, identity: identity)
    }

    /// All decrypted items. Every manifest entry needs its blob (`VaultError.blobMismatch` otherwise).
    public func items() throws -> [VaultItemPayload] {
        try manifest.items.map { try item($0) }
    }

    private func item(_ ref: VaultItemRef) throws -> VaultItemPayload {
        guard let blob = snapshot.blobs[ref.itemId], Data(SHA256.hash(data: blob)) == ref.blobHash else { throw VaultError.blobMismatch }
        return try VaultItemBlob.open(blob, itemId: ref.itemId, vaultId: vaultId, epoch: manifest.epoch, revision: ref.revision, vaultKey: vaultKey)
    }

    public func item(id: UUID) throws -> VaultItemPayload? {
        try manifest.items.first { $0.itemId == id }.map { try item($0) }
    }

    // MARK: Changing items

    /// Adds, replaces and deletes items in one new manifest version signed by this device. Each upsert gets a new revision and a fresh item key.
    public func applying(upserts: [VaultItemPayload] = [], deletes: [UUID] = [], now: Date) async throws -> VaultMutation {
        var refs = Dictionary(uniqueKeysWithValues: manifest.items.map { ($0.itemId, $0) })
        var blobs = snapshot.blobs
        var changed: [UUID: Data] = [:]
        for id in deletes { refs[id] = nil; blobs[id] = nil }
        for var payload in upserts {
            let revision = (refs[payload.id]?.revision ?? 0) + 1
            payload.updatedAt = now
            let blob = try VaultItemBlob.seal(payload, vaultId: vaultId, epoch: manifest.epoch, revision: revision, vaultKey: vaultKey)
            refs[payload.id] = VaultItemRef(itemId: payload.id, revision: revision, blobHash: Data(SHA256.hash(data: blob)))
            blobs[payload.id] = blob
            changed[payload.id] = blob
        }
        guard refs.count <= VaultFormat.maxItems else { throw VaultError.limitExceeded("items") }
        try Self.requireRoom(blobs.filter { refs[$0.key] != nil }.values)
        let next = try await successor(members: manifest.members, items: Array(refs.values), epoch: manifest.epoch, keyCheck: manifest.keyCheck, now: now)
        let removed = deletes.filter { id in manifest.items.contains { $0.itemId == id } }
        let snap = VaultSnapshot(verified: next.verified, blobs: blobs.filter { refs[$0.key] != nil }, envelopes: snapshot.envelopes)
        return VaultMutation(vault: UnlockedVault(vaultKey: vaultKey, snapshot: snap, identity: identity),
                             delta: VaultDelta(manifest: next.signed, blobs: changed, removedItems: removed, envelopes: [:]), approval: nil)
    }

    /// Builds, signs and self-verifies the next manifest version.
    private func successor(members: [VaultMember], items: [VaultItemRef], epoch: UInt64, keyCheck: Data, now: Date,
                           signer: VaultDeviceIdentity? = nil, recoveryAuthorizedBy recovery: VaultDeviceIdentity? = nil) async throws -> (signed: SignedVaultManifest, verified: VerifiedManifest) {
        let signer = signer ?? identity
        let next = VaultManifest(vaultId: vaultId, version: manifest.version + 1, previousHash: snapshot.verified.hash, epoch: epoch, keyCheck: keyCheck,
                                 members: members, items: items, signerId: signer.memberId, createdAt: UInt64(max(0, now.timeIntervalSince1970)))
        let signed = try await SignedVaultManifest.sign(next, with: signer.signingKey, recoveryAuthorizedBy: recovery?.signingKey)
        return (signed, try VaultChainVerifier.verify(signed, after: snapshot.verified))
    }

    // MARK: Adding a device

    /// Approves a new device's join request: adds it to the manifest, seals the vault key to it and returns the sealed approval for the new
    /// device. The caller must have shown the person the request's device name and obtained biometric approval (signing uses the device key).
    public func approvingJoin(_ request: JoinRequest, secret: PairingSecret, now: Date) async throws -> VaultMutation {
        let newId = VaultMemberID.make(signingKey: request.signingKey)
        guard manifest.member(newId) == nil else { throw VaultError.forbidden("already a member") }
        guard manifest.devices.count < VaultFormat.maxDevices else { throw VaultError.limitExceeded("devices") }
        guard identity.memberId != newId, manifest.member(identity.memberId)?.role == .device else { throw VaultError.forbidden("not an approving device") }
        let envelope = try VaultEnvelope.seal(vaultKey, to: request.agreementKey, vaultId: vaultId, epoch: manifest.epoch, memberId: newId)
        let member = VaultMember(role: .device, signingKey: request.signingKey, agreementKey: request.agreementKey, envelopeHash: VaultEnvelope.hash(envelope),
                                 addedAt: UInt64(max(0, now.timeIntervalSince1970)),
                                 sealedLabel: try Self.sealLabel(request.label, memberId: newId, key: vaultKey, vaultId: vaultId))
        let next = try await successor(members: manifest.members + [member], items: manifest.items, epoch: manifest.epoch, keyCheck: manifest.keyCheck, now: now)
        let approval = try JoinApproval(vaultId: vaultId, approverSigningKey: identity.signingPublicKey, manifestHash: next.verified.hash).sealed(with: secret)
        var envelopes = snapshot.envelopes
        envelopes[newId] = envelope
        return VaultMutation(vault: UnlockedVault(vaultKey: vaultKey, snapshot: VaultSnapshot(verified: next.verified, blobs: snapshot.blobs, envelopes: envelopes),
                                                  identity: identity),
                             delta: VaultDelta(manifest: next.signed, blobs: [:], removedItems: [], envelopes: [newId: envelope]), approval: approval)
    }

    /// The new device's side of a join: pins the approving device's key and the manifest through the pairing channel (which the server cannot
    /// read or forge), then unseals its envelope.
    public static func acceptingJoin(approval: Data, secret: PairingSecret, manifest signed: SignedVaultManifest, envelope: Data,
                                     identity: VaultDeviceIdentity) throws -> UnlockedVault {
        let anchor = try pinningJoin(approval: approval, secret: secret, manifest: signed)
        let snapshot = VaultSnapshot(verified: anchor, blobs: [:], envelopes: [identity.memberId: envelope])
        return try open(snapshot, identity: identity)
    }

    /// Verifies that `manifest` is the one the approving device approved (hash and signer pinned through the pairing channel). The result is a
    /// trust anchor: later versions are verified onward from it with `VaultChainVerifier.verifyChain`.
    public static func pinningJoin(approval: Data, secret: PairingSecret, manifest signed: SignedVaultManifest) throws -> VerifiedManifest {
        let approved = try JoinApproval.open(approval, with: secret)
        let anchor = try VaultChainVerifier.anchor(signed, expectedHash: approved.manifestHash, signerKey: approved.approverSigningKey)
        guard anchor.manifest.vaultId == approved.vaultId else { throw VaultError.invalidChain("vault") }
        return anchor
    }

    // MARK: Removing a device, recovery key changes (vault key rotation)

    /// Replaces the vault key: new key, epoch + 1, every item re-encrypted under a fresh item key, every kept member's envelope re-sealed.
    /// A device that was removed keeps whatever it already copied; rotation only protects what is written afterwards.
    private func rotated(keeping kept: [VaultMember],
                         recovery: (RecoveryKey, installer: VaultDeviceIdentity)? = nil, newDevice: (signing: Data, agreement: Data, label: String)? = nil,
                         signer: VaultDeviceIdentity, recoveryAuthorizedBy recoveryAuthority: VaultDeviceIdentity? = nil,
                         resulting result: VaultDeviceIdentity, now: Date) async throws -> VaultMutation {
        let plain = try items()
        let newKey = VaultKey.generate()
        let epoch = manifest.epoch + 1
        let at = UInt64(max(0, now.timeIntervalSince1970))
        var members: [VaultMember] = []
        var envelopes: [String: Data] = [:]
        for member in kept {
            let envelope = try VaultEnvelope.seal(newKey, to: member.agreementKey, vaultId: vaultId, epoch: epoch, memberId: member.id)
            var copy = member
            copy.envelopeHash = VaultEnvelope.hash(envelope)
            if member.role == .device {
                copy.sealedLabel = try Self.sealLabel(label(of: member.id) ?? "Device", memberId: member.id, key: newKey, vaultId: vaultId)
            }
            members.append(copy)
            envelopes[member.id] = envelope
        }
        if let newDevice {
            let id = VaultMemberID.make(signingKey: newDevice.signing)
            let envelope = try VaultEnvelope.seal(newKey, to: newDevice.agreement, vaultId: vaultId, epoch: epoch, memberId: id)
            members.append(VaultMember(role: .device, signingKey: newDevice.signing, agreementKey: newDevice.agreement, envelopeHash: VaultEnvelope.hash(envelope), addedAt: at,
                                       sealedLabel: try Self.sealLabel(newDevice.label, memberId: id, key: newKey, vaultId: vaultId)))
            envelopes[id] = envelope
        }
        if let (recoveryKey, installer) = recovery {
            let (member, envelope) = try Self.recoveryMember(recoveryKey, vaultId: vaultId, key: newKey, epoch: epoch, installer: installer, at: at)
            members.append(member)
            envelopes[member.id] = envelope
        }
        var refs: [VaultItemRef] = []
        var blobs: [UUID: Data] = [:]
        for payload in plain {
            let revision = (manifest.items.first { $0.itemId == payload.id }?.revision ?? 0) + 1
            let blob = try VaultItemBlob.seal(payload, vaultId: vaultId, epoch: epoch, revision: revision, vaultKey: newKey)
            refs.append(VaultItemRef(itemId: payload.id, revision: revision, blobHash: Data(SHA256.hash(data: blob))))
            blobs[payload.id] = blob
        }
        let next = try await successor(members: members, items: refs, epoch: epoch, keyCheck: newKey.keyCheck(epoch: epoch), now: now, signer: signer,
                                  recoveryAuthorizedBy: recoveryAuthority)
        let snap = VaultSnapshot(verified: next.verified, blobs: blobs, envelopes: envelopes)
        return VaultMutation(vault: UnlockedVault(vaultKey: newKey, snapshot: snap, identity: result),
                             delta: VaultDelta(manifest: next.signed, blobs: blobs, removedItems: [], envelopes: envelopes), approval: nil)
    }

    /// Removes a device and replaces the vault key. A device cannot remove itself (leave by deleting the vault instead).
    public func removingDevice(_ memberId: String, now: Date) async throws -> VaultMutation {
        guard memberId != identity.memberId, let target = manifest.member(memberId), target.role == .device else { throw VaultError.forbidden("cannot remove this member") }
        return try await rotated(keeping: manifest.members.filter { $0.id != memberId }, signer: identity, resulting: identity, now: now)
    }

    /// Installs (or replaces) the recovery member. With `rotateKey` the vault key is replaced too, which is what retires an old recovery key
    /// that may have leaked; without it only the recovery member changes.
    public func settingRecoveryKey(_ recoveryKey: RecoveryKey, rotateKey: Bool, now: Date) async throws -> VaultMutation {
        guard manifest.member(identity.memberId)?.role == .device else { throw VaultError.forbidden("not a device") }
        let withoutRecovery = manifest.members.filter { $0.role != .recovery }
        if rotateKey {
            return try await rotated(keeping: withoutRecovery, recovery: (recoveryKey, identity), signer: identity, resulting: identity, now: now)
        }
        let at = UInt64(max(0, now.timeIntervalSince1970))
        let (member, envelope) = try Self.recoveryMember(recoveryKey, vaultId: vaultId, key: vaultKey, epoch: manifest.epoch, installer: identity, at: at)
        let next = try await successor(members: withoutRecovery + [member], items: manifest.items, epoch: manifest.epoch, keyCheck: manifest.keyCheck, now: now)
        var envelopes = snapshot.envelopes.filter { manifest.member($0.key)?.role != .recovery }
        envelopes[member.id] = envelope
        return VaultMutation(vault: UnlockedVault(vaultKey: vaultKey, snapshot: VaultSnapshot(verified: next.verified, blobs: snapshot.blobs, envelopes: envelopes),
                                                  identity: identity),
                             delta: VaultDelta(manifest: next.signed, blobs: [:], removedItems: [], envelopes: [member.id: envelope]), approval: nil)
    }

    // MARK: Recovery

    /// Authenticates a server-supplied chain with **only the recovery key**. The recovery member's `binding` was computed by a genuine device
    /// while it held the key; matching it against the signer of one manifest proves that device's signing key is genuine, and the chain is
    /// verified onward from that manifest. A server that does not know the key cannot forge the binding. It *can* serve an older (but genuine)
    /// state: see SECURITY.md §2.40 residual risks.
    public static func authenticateChain(_ chain: [SignedVaultManifest], recoveryKey: RecoveryKey) throws -> VerifiedManifest {
        guard let last = chain.last, let latest = try? VaultManifest.decode(last.manifestBytes), let current = latest.recoveryMember, let tag = current.binding else {
            throw VaultError.invalidRecoveryKey
        }
        let recovery = try recoveryKey.identity(vaultId: latest.vaultId)
        guard current.signingKey == recovery.signingPublicKey, current.agreementKey == recovery.agreementPublicKey else { throw VaultError.invalidRecoveryKey }
        let decoded = try chain.map { try VaultManifest.decode($0.manifestBytes) }
        guard let start = decoded.firstIndex(where: { $0.recoveryMember?.id == current.id }) else { throw VaultError.invalidRecoveryKey }
        for index in start..<decoded.count {
            let manifest = decoded[index]
            guard manifest.vaultId == latest.vaultId, let signer = manifest.member(manifest.signerId), signer.role == .device else { continue }
            let expected = recoveryKey.binding(vaultId: manifest.vaultId, memberId: current.id, installerKey: signer.signingKey)
            guard ConstantTime.equals(tag, expected) else { continue }
            let anchor = try VaultChainVerifier.anchor(chain[index], expectedHash: chain[index].hash, signerKey: signer.signingKey)
            return try VaultChainVerifier.verifyChain(Array(chain[index...]), trusted: anchor)
        }
        throw VaultError.invalidRecoveryKey
    }

    /// Restores the vault onto a new device with the recovery key: replaces the vault key (the lost devices are removed), installs
    /// `newDevice` and a **new** recovery key, and signs with the recovery member. `snapshot` must come from `authenticateChain`.
    public static func recovering(_ snapshot: VaultSnapshot, recoveryKey: RecoveryKey, newRecoveryKey: RecoveryKey, newDevice: VaultDeviceIdentity,
                                  label: String, now: Date) async throws -> VaultMutation {
        let recoveryIdentity = try recoveryKey.identity(vaultId: snapshot.vaultId)
        let opened = try open(snapshot, identity: recoveryIdentity)
        return try await opened.rotated(keeping: [], recovery: (newRecoveryKey, newDevice),
                                        newDevice: (newDevice.signingPublicKey, newDevice.agreementPublicKey, label), signer: newDevice,
                                        recoveryAuthorizedBy: recoveryIdentity, resulting: newDevice, now: now)
    }
}
