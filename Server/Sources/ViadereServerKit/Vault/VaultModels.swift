import Fluent
import Foundation

/// A synced credential vault. One per account (`consumer_id` is unique). Holds **no plaintext**: `version` and `manifest_hash` mirror the
/// newest signed manifest, whose bytes live in `vault_manifests`.
final class VaultRecord: Model, @unchecked Sendable {
    static let schema = "vault_vaults"
    /// The vault id the first manifest chose.
    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "version") var version: Int
    @Field(key: "epoch") var epoch: Int
    @Field(key: "manifest_hash") var manifestHash: String
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "updated_at") var updatedAt: Date

    init() {}

    init(id: UUID, consumerId: UUID, version: Int, epoch: Int, manifestHash: String, now: Date) {
        self.id = id
        self.consumerId = consumerId
        self.version = version
        self.epoch = epoch
        self.manifestHash = manifestHash
        createdAt = now
        updatedAt = now
    }
}

/// One signed manifest version (append-only history; clients verify the hash chain themselves).
final class VaultManifestRecord: Model, @unchecked Sendable {
    static let schema = "vault_manifests"
    @ID(key: .id) var id: UUID?
    @Field(key: "vault_id") var vaultId: UUID
    @Field(key: "version") var version: Int
    /// base64url of the canonical manifest bytes, the signature and the optional recovery authorization (`VaultManifestDTO`).
    @Field(key: "manifest") var manifest: String
    @Field(key: "signature") var signature: String
    @OptionalField(key: "authorization") var authorization: String?
    @Field(key: "hash") var hash: String
    @Field(key: "created_at") var createdAt: Date

    init() {}

    init(vaultId: UUID, version: Int, manifest: String, signature: String, authorization: String?, hash: String, now: Date) {
        id = UUID()
        self.vaultId = vaultId
        self.version = version
        self.manifest = manifest
        self.signature = signature
        self.authorization = authorization
        self.hash = hash
        createdAt = now
    }
}

/// One encrypted item blob (the newest revision only).
final class VaultBlobRecord: Model, @unchecked Sendable {
    static let schema = "vault_blobs"
    @ID(key: .id) var id: UUID?
    @Field(key: "vault_id") var vaultId: UUID
    @Field(key: "item_id") var itemId: UUID
    @Field(key: "revision") var revision: Int
    @Field(key: "blob_hash") var blobHash: String
    @Field(key: "blob") var blob: Data
    @Field(key: "updated_at") var updatedAt: Date

    init() {}

    init(vaultId: UUID, itemId: UUID, revision: Int, blobHash: String, blob: Data, now: Date) {
        id = UUID()
        self.vaultId = vaultId
        self.itemId = itemId
        self.revision = revision
        self.blobHash = blobHash
        self.blob = blob
        updatedAt = now
    }
}

/// A vault member the server knows about: its public keys, its HPKE envelope (ciphertext) and the account device bound to it.
final class VaultMemberRecord: Model, @unchecked Sendable {
    static let schema = "vault_members"
    @ID(key: .id) var id: UUID?
    @Field(key: "vault_id") var vaultId: UUID
    @Field(key: "member_id") var memberId: String
    /// `device` or `recovery`.
    @Field(key: "role") var role: String
    @Field(key: "signing_key") var signingKey: String
    @Field(key: "envelope_hash") var envelopeHash: String
    @OptionalField(key: "envelope") var envelope: Data?
    /// The account device allowed to act as this member; set by the genesis, a device approval or a recovery restore, never by the account alone.
    @OptionalField(key: "account_device_id") var accountDeviceId: UUID?
    @Field(key: "added_at") var addedAt: Date
    @OptionalField(key: "removed_at") var removedAt: Date?

    init() {}

    init(vaultId: UUID, memberId: String, role: String, signingKey: String, envelopeHash: String, envelope: Data?, accountDeviceId: UUID?, addedAt: Date) {
        id = UUID()
        self.vaultId = vaultId
        self.memberId = memberId
        self.role = role
        self.signingKey = signingKey
        self.envelopeHash = envelopeHash
        self.envelope = envelope
        self.accountDeviceId = accountDeviceId
        self.addedAt = addedAt
    }
}

/// A new device waiting for an existing vault device to approve it. `request` and `approval` are sealed under the one-time pairing secret,
/// which the server never sees.
final class VaultJoinRecord: Model, @unchecked Sendable {
    static let schema = "vault_joins"
    @ID(key: .id) var id: UUID?
    @Field(key: "join_id") var joinId: String
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "vault_id") var vaultId: UUID
    @OptionalField(key: "requester_device_id") var requesterDeviceId: UUID?
    @OptionalField(key: "request") var request: Data?
    @OptionalField(key: "approval") var approval: Data?
    @OptionalField(key: "approved_member_id") var approvedMemberId: String?
    @OptionalField(key: "approved_version") var approvedVersion: Int?
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "expires_at") var expiresAt: Date

    init() {}

    init(joinId: String, consumerId: UUID, vaultId: UUID, now: Date, expiresAt: Date) {
        id = UUID()
        self.joinId = joinId
        self.consumerId = consumerId
        self.vaultId = vaultId
        createdAt = now
        self.expiresAt = expiresAt
    }
}
