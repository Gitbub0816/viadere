import Crypto
import Foundation

/// One participant of a vault: an enrolled device, or the recovery member derived from the recovery key.
public struct VaultMember: Sendable, Equatable {
    public enum Role: UInt64, Sendable { case device = 1, recovery = 2 }

    public var role: Role
    /// ECDSA P-256 public key (X9.63) that signs manifests for this member.
    public var signingKey: Data
    /// P-256 key-agreement public key (X9.63) the vault key is HPKE-sealed to.
    public var agreementKey: Data
    /// SHA-256 of this member's envelope at the manifest's key epoch.
    public var envelopeHash: Data
    /// Unix seconds.
    public var addedAt: UInt64
    /// The device name sealed under a key derived from the vault key (`nil` for the recovery member). The server cannot read it.
    public var sealedLabel: Data?
    /// Recovery member only: `HMAC(recovery key, vault, member, installing device)`. Whoever holds the recovery key can check it
    /// to learn that the installing device's key is genuine, which anchors the chain without any earlier trust (`VaultRecovery`).
    public var binding: Data?

    public var id: String { VaultMemberID.make(signingKey: signingKey) }

    public init(role: Role, signingKey: Data, agreementKey: Data, envelopeHash: Data, addedAt: UInt64, sealedLabel: Data?, binding: Data? = nil) {
        self.binding = binding
        self.role = role
        self.signingKey = signingKey
        self.agreementKey = agreementKey
        self.envelopeHash = envelopeHash
        self.addedAt = addedAt
        self.sealedLabel = sealedLabel
    }
}

/// A reference to one item blob: its identifier, revision (strictly increasing per change) and the SHA-256 of the stored blob.
public struct VaultItemRef: Sendable, Equatable {
    public var itemId: UUID
    public var revision: UInt64
    public var blobHash: Data

    public init(itemId: UUID, revision: UInt64, blobHash: Data) {
        self.itemId = itemId
        self.revision = revision
        self.blobHash = blobHash
    }
}

/// The signed, hash-chained description of a vault at one version: its members, its key epoch (with a commitment to the vault key) and
/// exactly which item blobs belong to it. Anything the server stores that is not described here is ignored; anything described here that
/// does not match is rejected.
public struct VaultManifest: Sendable, Equatable {
    public var vaultId: UUID
    /// 1 for the genesis manifest, then +1 per change.
    public var version: UInt64
    /// `SignedVaultManifest.hash` of the previous version; 32 zero bytes at genesis.
    public var previousHash: Data
    /// Increments when the vault key is replaced (a device was removed, or the vault was recovered).
    public var epoch: UInt64
    /// `VaultKey.keyCheck(epoch:)`.
    public var keyCheck: Data
    public var members: [VaultMember]
    public var items: [VaultItemRef]
    /// Member id of the signer.
    public var signerId: String
    /// Unix seconds.
    public var createdAt: UInt64

    public static let genesisPreviousHash = Data(repeating: 0, count: 32)

    public init(vaultId: UUID, version: UInt64, previousHash: Data, epoch: UInt64, keyCheck: Data, members: [VaultMember], items: [VaultItemRef],
                signerId: String, createdAt: UInt64) {
        self.vaultId = vaultId
        self.version = version
        self.previousHash = previousHash
        self.epoch = epoch
        self.keyCheck = keyCheck
        self.members = members
        self.items = items
        self.signerId = signerId
        self.createdAt = createdAt
    }

    public func member(_ id: String) -> VaultMember? { members.first { $0.id == id } }
    public var devices: [VaultMember] { members.filter { $0.role == .device } }
    public var recoveryMember: VaultMember? { members.first { $0.role == .recovery } }

    // MARK: Deterministic CBOR

    /// `{v, vault, ver, prev, epoch, check, members: [{role, sign, agree, env, at, label?}], items: [{id, rev, hash}], signer, at}`,
    /// members sorted by id and items by item id, keys in deterministic order. One manifest has exactly one encoding.
    public func encoded() -> Data {
        let sortedMembers = members.sorted { $0.id < $1.id }.map { m -> CBORValue in
            var fields: [(String, CBORValue)] = [("role", .unsigned(m.role.rawValue)), ("sign", .bytes(m.signingKey)), ("agree", .bytes(m.agreementKey)),
                                                 ("env", .bytes(m.envelopeHash)), ("at", .unsigned(m.addedAt))]
            if let label = m.sealedLabel { fields.append(("label", .bytes(label))) }
            if let binding = m.binding { fields.append(("bind", .bytes(binding))) }
            return .textMap(fields)
        }
        let sortedItems = items.sorted { VaultBytes.uuid($0.itemId).lexicographicallyPrecedes(VaultBytes.uuid($1.itemId)) }.map {
            CBORValue.textMap([("id", .bytes(VaultBytes.uuid($0.itemId))), ("rev", .unsigned($0.revision)), ("hash", .bytes($0.blobHash))])
        }
        return CBOR.encode(.textMap([("v", .unsigned(UInt64(VaultFormat.version))), ("vault", .bytes(VaultBytes.uuid(vaultId))), ("ver", .unsigned(version)),
                                     ("prev", .bytes(previousHash)), ("epoch", .unsigned(epoch)), ("check", .bytes(keyCheck)),
                                     ("members", .array(sortedMembers)), ("items", .array(sortedItems)), ("signer", .text(signerId)),
                                     ("at", .unsigned(createdAt))]), deterministic: true)
    }

    /// Strict parse of deterministic bytes. The result re-encodes to exactly `data`.
    public static func decode(_ data: Data) throws -> VaultManifest {
        guard data.count <= VaultFormat.maxManifestBytes else { throw VaultError.limitExceeded("manifest size") }
        let limits = CBOR.Limits(maxDepth: 4, maxBytes: VaultFormat.maxManifestBytes, maxItems: VaultFormat.maxItems + 8)
        guard let root = try? CBOR.decodeDeterministic(data, limits: limits) else { throw VaultError.invalidManifest("encoding") }
        guard let format = root["v"]?.unsignedValue else { throw VaultError.invalidManifest("version") }
        guard format == UInt64(VaultFormat.version) else { throw VaultError.unsupportedVersion(Int(clamping: format)) }
        guard let vault = root["vault"]?.byteString.flatMap(VaultBytes.uuid(from:)), let version = root["ver"]?.unsignedValue, version >= 1,
              let previous = root["prev"]?.byteString, previous.count == 32, let epoch = root["epoch"]?.unsignedValue, epoch >= 1,
              let check = root["check"]?.byteString, check.count == 32, let rawMembers = root["members"]?.arrayValue,
              let rawItems = root["items"]?.arrayValue, let signer = root["signer"]?.textString, let at = root["at"]?.unsignedValue,
              rawMembers.count <= VaultFormat.maxDevices + 1, rawItems.count <= VaultFormat.maxItems else { throw VaultError.invalidManifest("fields") }
        var members: [VaultMember] = []
        for raw in rawMembers {
            guard let roleValue = raw["role"]?.unsignedValue, let role = VaultMember.Role(rawValue: roleValue), let sign = raw["sign"]?.byteString, sign.count == 65,
                  let agree = raw["agree"]?.byteString, agree.count == 65, let env = raw["env"]?.byteString, env.count == 32, let added = raw["at"]?.unsignedValue,
                  (try? P256.Signing.PublicKey(x963Representation: sign)) != nil, (try? P256.KeyAgreement.PublicKey(x963Representation: agree)) != nil
            else { throw VaultError.invalidManifest("member") }
            let label = raw["label"]?.byteString
            let binding = raw["bind"]?.byteString
            if (role == .recovery) != (label == nil) { throw VaultError.invalidManifest("member label") }
            if (role == .recovery) != (binding != nil) || (binding != nil && binding?.count != 32) { throw VaultError.invalidManifest("member binding") }
            if let label, label.count > VaultFormat.maxLabelBytes + VaultFormat.sealedBoxOverhead + 4 { throw VaultError.invalidManifest("member label") }
            members.append(VaultMember(role: role, signingKey: sign, agreementKey: agree, envelopeHash: env, addedAt: added, sealedLabel: label, binding: binding))
        }
        var items: [VaultItemRef] = []
        for raw in rawItems {
            guard let id = raw["id"]?.byteString.flatMap(VaultBytes.uuid(from:)), let revision = raw["rev"]?.unsignedValue, revision >= 1,
                  let hash = raw["hash"]?.byteString, hash.count == 32 else { throw VaultError.invalidManifest("item") }
            items.append(VaultItemRef(itemId: id, revision: revision, blobHash: hash))
        }
        let manifest = VaultManifest(vaultId: vault, version: version, previousHash: previous, epoch: epoch, keyCheck: check, members: members, items: items,
                                     signerId: signer, createdAt: at)
        // Sorted and unique, which also makes the bytes canonical (checked by comparing the re-encoding with the input).
        guard manifest.encoded() == data else { throw VaultError.invalidManifest("not canonical") }
        guard Set(manifest.members.map(\.id)).count == manifest.members.count, Set(manifest.items.map(\.itemId)).count == manifest.items.count else {
            throw VaultError.invalidManifest("duplicates")
        }
        return manifest
    }
}

/// A manifest with its signature: ECDSA P-256 / SHA-256 (raw `r || s`, low-S) over `"viadere.vault.v1.manifest\0" || manifestBytes`.
///
/// `recoveryAuthorization` exists only on the manifest that restores a vault with the recovery key: the recovery member signs "this new
/// device may sign the successor of manifest H", so the new device (not yet a member) can sign it.
public struct SignedVaultManifest: Sendable, Equatable, Codable {
    public var manifestBytes: Data
    public var signature: Data
    public var recoveryAuthorization: Data?

    public init(manifestBytes: Data, signature: Data, recoveryAuthorization: Data? = nil) {
        self.manifestBytes = manifestBytes
        self.signature = signature
        self.recoveryAuthorization = recoveryAuthorization
    }

    static func signedMessage(_ manifestBytes: Data) -> Data { Data((VaultFormat.Label.manifestSignature + "\0").utf8) + manifestBytes }

    static func authorizationMessage(vaultId: UUID, signerKey: Data, previousHash: Data) -> Data {
        VaultAAD.make("recovery-authorization", [VaultBytes.uuid(vaultId), signerKey, previousHash])
    }

    /// SHA-256 over a domain label and the manifest bytes; the next manifest's `previousHash`.
    public var hash: Data { Data(SHA256.hash(data: Data("viadere.vault.v1.manifest-hash\0".utf8) + manifestBytes)) }

    public static func sign(_ manifest: VaultManifest, with key: any DeviceSigningKey, recoveryAuthorizedBy recovery: (any DeviceSigningKey)? = nil) async throws -> SignedVaultManifest {
        let bytes = manifest.encoded()
        let raw = ViadereSignatureEncoding.normalizedRaw(try await key.signature(for: signedMessage(bytes)).rawRepresentation)
        var authorization: Data?
        if let recovery {
            let message = authorizationMessage(vaultId: manifest.vaultId, signerKey: key.publicKey.x963, previousHash: manifest.previousHash)
            authorization = ViadereSignatureEncoding.normalizedRaw(try await recovery.signature(for: message).rawRepresentation)
        }
        return SignedVaultManifest(manifestBytes: bytes, signature: raw, recoveryAuthorization: authorization)
    }

    static func isValid(_ signature: Data, over message: Data, by publicKey: Data) -> Bool {
        guard signature.count == 64, let key = try? P256.Signing.PublicKey(x963Representation: publicKey),
              let sig = try? P256.Signing.ECDSASignature(rawRepresentation: signature), ViadereSignatureEncoding.isCanonical(sig) else { return false }
        return key.isValidSignature(sig, for: message)
    }

    func hasValidSignature(by publicKey: Data) -> Bool { Self.isValid(signature, over: Self.signedMessage(manifestBytes), by: publicKey) }
}

/// A manifest that passed every check against its predecessor (or is a verified genesis / pinned anchor).
public struct VerifiedManifest: Sendable, Equatable {
    public let signed: SignedVaultManifest
    public let manifest: VaultManifest
    public var hash: Data { signed.hash }
}

/// Anti-rollback and chain verification. The server stores manifests but is not trusted to order them: every client checks the chain, and
/// the server runs the same checks as a guard against account-level attackers who hold no vault key.
public enum VaultChainVerifier {
    /// Structural rules that hold for any manifest.
    static func validateStructure(_ m: VaultManifest) throws {
        let devices = m.devices
        guard (1...VaultFormat.maxDevices).contains(devices.count) else { throw VaultError.invalidManifest("device count") }
        guard m.members.filter({ $0.role == .recovery }).count <= 1 else { throw VaultError.invalidManifest("recovery member count") }
        guard m.items.count <= VaultFormat.maxItems else { throw VaultError.limitExceeded("items") }
    }

    /// Verifies the first manifest of a vault: version 1, no predecessor, signed by one of its own device members.
    public static func verifyGenesis(_ signed: SignedVaultManifest) throws -> VerifiedManifest {
        let m = try VaultManifest.decode(signed.manifestBytes)
        try validateStructure(m)
        guard m.version == 1, m.previousHash == VaultManifest.genesisPreviousHash, m.epoch == 1,
              m.devices.count == 1 else { throw VaultError.invalidChain("genesis") }
        guard let signer = m.member(m.signerId), signer.role == .device, signed.hasValidSignature(by: signer.signingKey) else { throw VaultError.badSignature }
        guard m.items.allSatisfy({ $0.revision >= 1 }) else { throw VaultError.invalidChain("revision") }
        return VerifiedManifest(signed: signed, manifest: m)
    }

    /// Verifies `signed` as the direct successor of `previous`.
    public static func verify(_ signed: SignedVaultManifest, after previous: VerifiedManifest) throws -> VerifiedManifest {
        let m = try VaultManifest.decode(signed.manifestBytes)
        try validateStructure(m)
        let p = previous.manifest
        guard m.vaultId == p.vaultId else { throw VaultError.invalidChain("vault") }
        guard m.version == p.version + 1 else {
            throw m.version <= p.version ? VaultError.rollback : VaultError.invalidChain("version gap")
        }
        guard m.previousHash == previous.hash else { throw VaultError.fork }
        // The signer is a member of the PREVIOUS manifest: membership is granted only by an already-trusted member. The one exception is a
        // restore with the recovery key: a device the recovery member authorized for exactly this successor.
        var recoveryRestore = false
        if let signerBefore = p.member(m.signerId) {
            guard signed.hasValidSignature(by: signerBefore.signingKey) else { throw VaultError.badSignature }
            guard signerBefore.role == .device else { throw VaultError.unknownSigner }
            guard m.member(m.signerId) != nil else { throw VaultError.invalidChain("signer removed itself") }
        } else {
            guard let authorization = signed.recoveryAuthorization, let recovery = p.recoveryMember, let signer = m.member(m.signerId), signer.role == .device
            else { throw VaultError.unknownSigner }
            guard SignedVaultManifest.isValid(authorization, over: SignedVaultManifest.authorizationMessage(vaultId: p.vaultId, signerKey: signer.signingKey,
                                                                                                            previousHash: previous.hash),
                                              by: recovery.signingKey), signed.hasValidSignature(by: signer.signingKey) else { throw VaultError.badSignature }
            // The used recovery key is retired, and the vault key is replaced (checked below as a rotation).
            guard m.member(recovery.id) == nil else { throw VaultError.invalidChain("recovery key must be replaced after use") }
            recoveryRestore = true
        }

        // Key epoch.
        let rotated: Bool
        if m.epoch == p.epoch {
            rotated = false
            guard m.keyCheck == p.keyCheck else { throw VaultError.invalidChain("key check changed without a new epoch") }
        } else if m.epoch == p.epoch + 1 {
            rotated = true
            guard m.keyCheck != p.keyCheck else { throw VaultError.invalidChain("key check unchanged across epochs") }
        } else {
            throw VaultError.invalidChain("epoch")
        }

        if recoveryRestore { guard rotated else { throw VaultError.invalidChain("a recovery restore must replace the vault key") } }

        // A device that disappears from the member list must lose the key: otherwise its envelope still opens the current vault key and
        // "removal" would only be cosmetic (gate review L4).
        if !rotated, p.devices.contains(where: { m.member($0.id) == nil }) { throw VaultError.invalidChain("a removed device requires a key rotation") }

        // Members: at most one device added per version; existing members keep their keys; envelopes change exactly when the epoch does.
        let added = m.devices.filter { p.member($0.id) == nil }
        guard added.count <= 1 else { throw VaultError.invalidChain("more than one device added") }
        for member in m.members {
            guard let before = p.member(member.id) else { continue }
            guard before.role == member.role, before.agreementKey == member.agreementKey else { throw VaultError.invalidChain("member keys changed") }
            if rotated {
                guard before.envelopeHash != member.envelopeHash else { throw VaultError.invalidChain("envelope not replaced at rotation") }
            } else {
                guard before.envelopeHash == member.envelopeHash, before.sealedLabel == member.sealedLabel, before.addedAt == member.addedAt,
                      before.binding == member.binding else {
                    throw VaultError.invalidChain("member changed without rotation")
                }
            }
        }

        // Items: revisions never go backwards, change only upward, and everything is re-encrypted at rotation.
        let before = Dictionary(uniqueKeysWithValues: p.items.map { ($0.itemId, $0) })
        for item in m.items {
            guard let old = before[item.itemId] else { continue }
            if rotated {
                guard item.revision > old.revision else { throw VaultError.invalidChain("item not re-encrypted at rotation") }
            } else if item.revision == old.revision {
                guard item.blobHash == old.blobHash else { throw VaultError.invalidChain("item changed without a new revision") }
            } else {
                guard item.revision > old.revision else { throw VaultError.rollback }
            }
        }
        return VerifiedManifest(signed: signed, manifest: m)
    }

    /// Verifies a server-supplied chain against the newest manifest this device already trusts.
    /// - Entries at or below the trusted version must reproduce the trusted manifest exactly (`fork` otherwise).
    /// - The newest entry must not be older than the trusted version (`rollback`).
    /// - With no trusted manifest, the chain must start at genesis.
    public static func verifyChain(_ chain: [SignedVaultManifest], trusted: VerifiedManifest?) throws -> VerifiedManifest {
        guard !chain.isEmpty else { throw VaultError.invalidChain("empty") }
        var current: VerifiedManifest
        var rest = chain[...]
        if let trusted {
            var index = 0
            var matched = false
            while index < chain.count {
                let version = try VaultManifest.decode(chain[index].manifestBytes).version
                if version < trusted.manifest.version { index += 1; continue }
                if version == trusted.manifest.version {
                    guard chain[index].hash == trusted.hash else { throw VaultError.fork }
                    matched = true
                    index += 1
                }
                break
            }
            if !matched {
                // Nothing at or below the trusted version: the first entry must be its direct successor.
                guard index < chain.count else { throw VaultError.rollback }
                let first = try VaultManifest.decode(chain[index].manifestBytes)
                guard first.version == trusted.manifest.version + 1 else {
                    throw first.version > trusted.manifest.version ? VaultError.invalidChain("gap") : VaultError.rollback
                }
            }
            current = trusted
            rest = chain[index...]
            if rest.isEmpty { return trusted }
        } else {
            current = try verifyGenesis(chain[0])
            rest = chain.dropFirst()
        }
        for next in rest { current = try verify(next, after: current) }
        return current
    }

    /// Re-reads a manifest that **this process already verified and stored itself** (a device's trust anchor, the server's latest version).
    /// It parses and checks structure only: the signature was checked against the predecessor when the manifest was accepted, and a recovery
    /// signer is no longer a member of its own manifest, so it cannot be re-checked in isolation.
    public static func restore(_ signed: SignedVaultManifest) throws -> VerifiedManifest {
        let m = try VaultManifest.decode(signed.manifestBytes)
        try validateStructure(m)
        return VerifiedManifest(signed: signed, manifest: m)
    }

    /// Pins a manifest a new device learned out of band: the hash and signer key came through the pairing channel the server cannot read.
    public static func anchor(_ signed: SignedVaultManifest, expectedHash: Data, signerKey: Data) throws -> VerifiedManifest {
        guard ConstantTime.equals(signed.hash, expectedHash) else { throw VaultError.fork }
        let m = try VaultManifest.decode(signed.manifestBytes)
        try validateStructure(m)
        guard let signer = m.member(m.signerId), signer.role == .device, signer.signingKey == signerKey, signed.hasValidSignature(by: signerKey) else {
            throw VaultError.badSignature
        }
        return VerifiedManifest(signed: signed, manifest: m)
    }
}
