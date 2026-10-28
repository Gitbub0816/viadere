import Foundation

/// Wire forms for vault sync (`/v1/vault/...`). Every binary value is unpadded base64url. The server stores and returns these
/// opaquely; see `docs/SECURITY.md` §2.40 for what each one is.

/// `SignedVaultManifest` on the wire.
public struct VaultManifestDTO: Codable, Sendable, Equatable {
    public var manifest: String
    public var signature: String
    /// Present only on the manifest that restores a vault with the recovery key.
    public var recoveryAuthorization: String?

    public init(manifest: String, signature: String, recoveryAuthorization: String? = nil) {
        self.manifest = manifest
        self.signature = signature
        self.recoveryAuthorization = recoveryAuthorization
    }

    public init(_ signed: SignedVaultManifest) {
        self.init(manifest: Base64URL.encode(signed.manifestBytes), signature: Base64URL.encode(signed.signature),
                  recoveryAuthorization: signed.recoveryAuthorization.map { Base64URL.encode($0) })
    }

    /// The manifest, or `nil` when any field is not canonical base64url.
    public var signed: SignedVaultManifest? {
        guard let bytes = Base64URL.decode(manifest), let sig = Base64URL.decode(signature) else { return nil }
        var authorization: Data?
        if let recoveryAuthorization {
            guard let decoded = Base64URL.decode(recoveryAuthorization) else { return nil }
            authorization = decoded
        }
        return SignedVaultManifest(manifestBytes: bytes, signature: sig, recoveryAuthorization: authorization)
    }
}

/// One encrypted item blob.
public struct VaultBlobDTO: Codable, Sendable, Equatable {
    public var itemId: UUID
    public var blob: String
    public init(itemId: UUID, blob: String) {
        self.itemId = itemId
        self.blob = blob
    }
}

/// An HPKE envelope for one member.
public struct VaultEnvelopeDTO: Codable, Sendable, Equatable {
    public var memberId: String
    public var envelope: String
    public init(memberId: String, envelope: String) {
        self.memberId = memberId
        self.envelope = envelope
    }
}

/// `PUT /v1/vault`: one atomic compare-and-swap that moves the vault from `expectedVersion` to the manifest's version (`0` creates it).
public struct VaultPutRequest: Codable, Sendable, Equatable {
    public var expectedVersion: UInt64
    public var manifest: VaultManifestDTO
    /// New or replaced item blobs (anything else the manifest lists must already be stored with the same hash).
    public var blobs: [VaultBlobDTO]
    /// New or replaced envelopes (a member added, or every member at a key rotation).
    public var envelopes: [VaultEnvelopeDTO]
    /// Creating a vault or restoring it with the recovery key: the member (in this manifest) the calling account device is bound to.
    public var bindMemberId: String?
    /// Approving a join: the join, the sealed approval for the new device, and the member (added by this manifest) its requester binds to.
    public var joinId: String?
    public var joinApproval: String?
    public var joinMemberId: String?

    public init(expectedVersion: UInt64, manifest: VaultManifestDTO, blobs: [VaultBlobDTO] = [], envelopes: [VaultEnvelopeDTO] = [],
                bindMemberId: String? = nil, joinId: String? = nil, joinApproval: String? = nil, joinMemberId: String? = nil) {
        self.expectedVersion = expectedVersion
        self.manifest = manifest
        self.blobs = blobs
        self.envelopes = envelopes
        self.bindMemberId = bindMemberId
        self.joinId = joinId
        self.joinApproval = joinApproval
        self.joinMemberId = joinMemberId
    }
}

/// Where the account's synced vault stands, as the calling device sees it.
public struct VaultStatus: Codable, Sendable, Equatable {
    public var exists: Bool
    public var vaultId: UUID?
    public var version: UInt64
    public var epoch: UInt64
    /// This account device is bound to a vault member (it may read blobs and its envelope).
    public var bound: Bool
    public var memberId: String?
    public var deviceCount: Int
    public var recoveryConfigured: Bool
    /// The account's open recovery-envelope release (a hold, or the 24 h window after it), if any (see `VaultRecoveryRelease`).
    public var recoveryRelease: VaultRecoveryRelease?

    public init(exists: Bool, vaultId: UUID? = nil, version: UInt64 = 0, epoch: UInt64 = 0, bound: Bool = false, memberId: String? = nil,
                deviceCount: Int = 0, recoveryConfigured: Bool = false, recoveryRelease: VaultRecoveryRelease? = nil) {
        self.recoveryRelease = recoveryRelease
        self.exists = exists
        self.vaultId = vaultId
        self.version = version
        self.epoch = epoch
        self.bound = bound
        self.memberId = memberId
        self.deviceCount = deviceCount
        self.recoveryConfigured = recoveryConfigured
    }
}

/// `GET /v1/vault/manifests?after=N&limit=M`: manifests with a version greater than `after`, oldest first.
public struct VaultManifestsResponse: Codable, Sendable, Equatable {
    public var manifests: [VaultManifestDTO]
    public var latestVersion: UInt64
    public init(manifests: [VaultManifestDTO], latestVersion: UInt64) {
        self.manifests = manifests
        self.latestVersion = latestVersion
    }
}

public struct VaultBlobsRequest: Codable, Sendable, Equatable {
    public var itemIds: [UUID]
    public init(itemIds: [UUID]) { self.itemIds = itemIds }
}

public struct VaultBlobsResponse: Codable, Sendable, Equatable {
    public var blobs: [VaultBlobDTO]
    public init(blobs: [VaultBlobDTO]) { self.blobs = blobs }
}

/// `GET /v1/vault/envelope`: the calling device's own envelope. `GET /v1/vault/recovery-envelope`: the recovery member's.
public struct VaultEnvelopeResponse: Codable, Sendable, Equatable {
    public var memberId: String
    public var envelope: String
    public init(memberId: String, envelope: String) {
        self.memberId = memberId
        self.envelope = envelope
    }
}

/// A vault device as the server knows it. The device's name is sealed in the manifest, not here.
public struct VaultDeviceInfo: Codable, Sendable, Equatable, Identifiable {
    public var memberId: String
    public var role: String
    public var addedAt: Date
    /// The account device bound to this member, if any.
    public var accountDeviceId: UUID?
    /// The bound account device exists and is not revoked. A member whose account device was revoked should be removed (which rotates the key).
    public var accountDeviceActive: Bool
    public var removed: Bool
    public var id: String { memberId }

    public init(memberId: String, role: String, addedAt: Date, accountDeviceId: UUID?, accountDeviceActive: Bool, removed: Bool) {
        self.memberId = memberId
        self.role = role
        self.addedAt = addedAt
        self.accountDeviceId = accountDeviceId
        self.accountDeviceActive = accountDeviceActive
        self.removed = removed
    }
}

/// `PUT /v1/vault/joins/{joinId}/request`.
public struct VaultJoinRequestBody: Codable, Sendable, Equatable {
    public var request: String
    public init(request: String) { self.request = request }
}

public struct VaultJoinState: Codable, Sendable, Equatable {
    public var joinId: String
    public var expiresAt: Date
    /// The new device's sealed request (`nil` until it sends one).
    public var request: String?
    /// The approving device's sealed approval (`nil` until approved).
    public var approval: String?
    /// The member the requesting account device was bound to by the approval.
    public var approvedMemberId: String?
    /// The vault version of the manifest that added the device.
    public var approvedVersion: UInt64?

    public init(joinId: String, expiresAt: Date, request: String? = nil, approval: String? = nil, approvedMemberId: String? = nil, approvedVersion: UInt64? = nil) {
        self.approvedVersion = approvedVersion
        self.joinId = joinId
        self.expiresAt = expiresAt
        self.request = request
        self.approval = approval
        self.approvedMemberId = approvedMemberId
    }
}


/// A request to release the vault's recovery envelope (`POST /v1/vault/recovery-release`). Account access plus the recovery key would
/// otherwise decrypt the vault silently, so the envelope is withheld for a **72 hour hold** during which every vault device and every other
/// account device is told ("Not you? Cancel"); after the hold it is released for 24 hours to the requesting device only (gate review M2).
public struct VaultRecoveryRelease: Codable, Sendable, Equatable {
    public enum State: String, Codable, Sendable {
        /// The hold is running; nothing is released yet.
        case holding
        /// The hold passed without cancellation: the requesting device may read the recovery envelope (and ciphertext) until `expiresAt`.
        case released
        case cancelled, expired
        /// The restore was completed.
        case consumed
        case unknown

        public init(from decoder: any Decoder) throws {
            self = State(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .unknown
        }
    }

    public static let holdSeconds: TimeInterval = 72 * 3600
    public static let windowSeconds: TimeInterval = 24 * 3600

    public var releaseId: UUID
    public var state: State
    public var requestedAt: Date
    /// When the hold ends and the envelope becomes readable.
    public var releaseAt: Date
    /// When the 24 hour window closes.
    public var expiresAt: Date
    /// The calling device is the one that asked (only it can read what is released).
    public var requestedByThisDevice: Bool

    public init(releaseId: UUID, state: State, requestedAt: Date, releaseAt: Date, expiresAt: Date, requestedByThisDevice: Bool) {
        self.releaseId = releaseId
        self.state = state
        self.requestedAt = requestedAt
        self.releaseAt = releaseAt
        self.expiresAt = expiresAt
        self.requestedByThisDevice = requestedByThisDevice
    }
}
