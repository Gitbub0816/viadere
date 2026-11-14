import Foundation

// MARK: - Device pairing (WP-D1, SECURITY.md §2.105). Primitives in `Security/DevicePairing.swift`.

/// `201` from `POST /v1/device-pairings/invitations` (a D1 device): the code the person types on the new device. Shown on this device only.
/// Creating a new one revokes the previous open code of the account.
public struct DevicePairingInvitation: Codable, Sendable, Hashable {
    /// `XXXX-XXXX-XXXX` (`DevicePairingCode`).
    public var code: String
    public var expiresAt: Date

    public init(code: String, expiresAt: Date) {
        self.code = code
        self.expiresAt = expiresAt
    }
}

/// `POST /v1/device-pairings/begin` (public; no body). A single-use ceremony for the new device: `pairingId` is the subject of its key proofs
/// (`VIADERE-ENROLL-V1\n{pairingId}\n{challenge}\n{purpose}\n{key}`) and of its App Attest binding. Says nothing about any account.
public struct DevicePairingBeginResponse: Codable, Sendable, Hashable {
    public var pairingId: DevicePairingID
    /// base64url, 256 random bits, single use, valid until `expiresAt` (5 minutes).
    public var challenge: String
    public var expiresAt: Date
    public var integrity: IntegrityRequirement

    public init(pairingId: DevicePairingID, challenge: String, expiresAt: Date, integrity: IntegrityRequirement) {
        self.pairingId = pairingId
        self.challenge = challenge
        self.expiresAt = expiresAt
        self.integrity = integrity
    }

    /// The id to put in the subject slot of `DeviceEnrollment` and `AppAttestBinding` (they were written for an account id; here the pairing
    /// id takes its place, a fresh UUIDv4 that is never an account id).
    public var proofSubject: ConsumerID { ConsumerID(pairingId.uuid) }
}

/// `POST /v1/device-pairings/{pairingId}/start` (public). There is no account field and no tier field: the code names the account to the server
/// and the server alone decides the tier, at approval. Unknown members (a tier, a name, an account id) are ignored.
public struct DevicePairingStartRequest: Codable, Sendable, Hashable {
    public var challenge: String
    /// The code shown on the trusted device.
    public var pairingCode: String
    public var platform: DevicePlatform
    /// Optional label (≤ 64). Shown on the trusted device as reported text ("Name chosen on the new device").
    public var deviceName: String?
    /// One per purpose, including `request`; each proves possession over the pairing id (above).
    public var keys: [DeviceKeyRegistration]
    public var integrity: IntegrityEvidence?

    public init(challenge: String, pairingCode: String, platform: DevicePlatform, deviceName: String?, keys: [DeviceKeyRegistration],
                integrity: IntegrityEvidence?) {
        self.challenge = challenge
        self.pairingCode = pairingCode
        self.platform = platform
        self.deviceName = deviceName
        self.keys = keys
        self.integrity = integrity
    }
}

/// `201` from `start`. `nonce` is drawn **after** the keys were stored. B computes the comparison code from its own keys
/// (`DevicePairing.comparisonDigest(pairingId:nonce:keys:)`), never from anything else the server says. `statusToken` (256 bits, shown once)
/// is B's credential for `status` and `cancel`.
public struct DevicePairingStartResponse: Codable, Sendable, Hashable {
    public var pairingId: DevicePairingID
    public var nonce: String
    public var expiresAt: Date
    public var statusToken: String

    public init(pairingId: DevicePairingID, nonce: String, expiresAt: Date, statusToken: String) {
        self.pairingId = pairingId
        self.nonce = nonce
        self.expiresAt = expiresAt
        self.statusToken = statusToken
    }
}

/// Body of `status` and `cancel` (the new device).
public struct DevicePairingStatusRequest: Codable, Sendable, Hashable {
    public var statusToken: String
    public init(statusToken: String) { self.statusToken = statusToken }
}

public enum DevicePairingState: String, Codable, Sendable, Hashable {
    case pending, approved, denied, expired, cancelled
    /// Three wrong numbers: the pairing ended; B starts again with new keys.
    case failed
    case unknown

    public init(from decoder: any Decoder) throws {
        self = DevicePairingState(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .unknown
    }

    public var isFinal: Bool { self != .pending }
}

/// The new device's view. On the **first** `status` after approval it also carries `device` and a `session` already bound to it (exactly once).
public struct DevicePairingStatus: Codable, Sendable, Hashable {
    public var pairingId: DevicePairingID
    public var state: DevicePairingState
    public var expiresAt: Date
    public var device: Device?
    public var session: AuthSession?

    public init(pairingId: DevicePairingID, state: DevicePairingState, expiresAt: Date, device: Device? = nil, session: AuthSession? = nil) {
        self.pairingId = pairingId
        self.state = state
        self.expiresAt = expiresAt
        self.device = device
        self.session = session
    }
}

/// A pending pairing as a trusted (D1) device of the account sees it in its own device-signed session (`GET /v1/device-pairings/pending`).
/// There is no comparison code here: the approving device asks the person for the number shown on the new device.
public struct DevicePairingRequest: Codable, Sendable, Hashable, Identifiable {
    public var pairingId: DevicePairingID
    public var accountId: ConsumerID
    public var nonce: String
    /// Reported by the new device; display only as "Name chosen on the new device: …".
    public var deviceName: String
    public var platform: DevicePlatform
    public var keys: [DevicePairingKey]
    /// `DevicePairing.keyListDigest(keys)`; the approving device recomputes it and refuses a mismatch.
    public var newDeviceKeys: String
    /// `DevicePairing.comparisonDigest`; recomputed and compared the same way.
    public var comparisonDigest: String
    /// When the new device asked (absolute time, no countdown).
    public var requestedAt: Date
    public var expiresAt: Date
    public var attemptsRemaining: Int
    /// Several pairings in the last hour (ADR-0022 §5.1 applied to pairings): show the fatigue warning.
    public var fatigueWarning: Bool
    /// The new device's integrity evidence verified (App Attest).
    public var integrityVerified: Bool

    public var id: DevicePairingID { pairingId }

    public init(pairingId: DevicePairingID, accountId: ConsumerID, nonce: String, deviceName: String, platform: DevicePlatform, keys: [DevicePairingKey],
                newDeviceKeys: String, comparisonDigest: String, requestedAt: Date, expiresAt: Date, attemptsRemaining: Int, fatigueWarning: Bool,
                integrityVerified: Bool) {
        self.pairingId = pairingId
        self.accountId = accountId
        self.nonce = nonce
        self.deviceName = deviceName
        self.platform = platform
        self.keys = keys
        self.newDeviceKeys = newDeviceKeys
        self.comparisonDigest = comparisonDigest
        self.requestedAt = requestedAt
        self.expiresAt = expiresAt
        self.attemptsRemaining = attemptsRemaining
        self.fatigueWarning = fatigueWarning
        self.integrityVerified = integrityVerified
    }

    /// The request is internally consistent: the digests are the ones its own keys, pairing id and nonce give. A trusted device signs only then.
    public var isConsistent: Bool {
        DevicePairing.isNonce(nonce) && !keys.isEmpty && Set(keys.map(\.purpose)).count == keys.count
            && ConstantTime.equals(DevicePairing.keyListDigest(keys), newDeviceKeys)
            && ConstantTime.equals(DevicePairing.comparisonDigest(pairingId: pairingId, nonce: nonce, keyListDigest: newDeviceKeys), comparisonDigest)
    }
}

/// `POST /v1/device-pairings/{pairingId}/approve` (device-signed, a D1 device of the account).
public struct DevicePairingApproveRequest: Codable, Sendable, Hashable {
    public var approval: DevicePairingApproval
    public init(approval: DevicePairingApproval) { self.approval = approval }
}

public struct DevicePairingApproveResponse: Codable, Sendable, Hashable {
    public var pairingId: DevicePairingID
    public var state: DevicePairingState
    /// The added device, with its server-decided tier.
    public var device: Device

    public init(pairingId: DevicePairingID, state: DevicePairingState, device: Device) {
        self.pairingId = pairingId
        self.state = state
        self.device = device
    }
}

/// `POST /v1/device-pairings/{pairingId}/deny` (device-signed, any live app device of the account: saying no is always safe). `report: true` is
/// "This wasn't me": it also tells every device of the account and counts toward the pause.
public struct DevicePairingDenyRequest: Codable, Sendable, Hashable {
    public var report: Bool?
    public init(report: Bool? = nil) { self.report = report }
}
