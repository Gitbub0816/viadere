import Foundation

/// Device platform.
public enum DevicePlatform: String, Codable, Sendable, CaseIterable {
    case iOS, iPadOS, watchOS, macOS, web, android
}

/// One registered public key on a device.
public struct DeviceKey: Codable, Sendable, Hashable, Identifiable {
    public var id: DeviceKeyID
    public var purpose: DeviceKeyPurpose
    public var publicKey: DevicePublicKey
    /// True if the private key is hardware-backed (Secure Enclave), **as claimed by the client at enrollment**.
    public var hardwareBacked: Bool
    /// True only when the server verified Apple App Attest evidence for this key. Until a verifier is configured this is
    /// always `false`, and policy or telemetry must not rely on `hardwareBacked` alone.
    public var attested: Bool
    public var createdAt: Date

    public init(id: DeviceKeyID, purpose: DeviceKeyPurpose, publicKey: DevicePublicKey, hardwareBacked: Bool, createdAt: Date,
                attested: Bool = false) {
        self.id = id
        self.purpose = purpose
        self.publicKey = publicKey
        self.hardwareBacked = hardwareBacked
        self.attested = attested
        self.createdAt = createdAt
    }

    enum CodingKeys: String, CodingKey { case id, purpose, publicKey, hardwareBacked, attested, createdAt }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(DeviceKeyID.self, forKey: .id)
        purpose = try c.decode(DeviceKeyPurpose.self, forKey: .purpose)
        publicKey = try c.decode(DevicePublicKey.self, forKey: .publicKey)
        hardwareBacked = try c.decode(Bool.self, forKey: .hardwareBacked)
        attested = try c.decodeIfPresent(Bool.self, forKey: .attested) ?? false
        createdAt = try c.decode(Date.self, forKey: .createdAt)
    }
}

/// A trusted device enrolled to a consumer.
public struct Device: Codable, Sendable, Hashable, Identifiable {
    public var id: DeviceID
    public var consumerId: ConsumerID
    /// User-visible name (≤ 64), e.g. "Ana's iPhone".
    public var name: String
    public var platform: DevicePlatform
    public var keys: [DeviceKey]
    /// Highest decision assurance this device can produce (from its registered keys).
    public var maxAssurance: DecisionAssurance
    public var createdAt: Date
    public var lastSeenAt: Date?
    public var revokedAt: Date?
    /// `app` or `appClip` (App Clip devices hold a request key only and never decide interactions).
    public var clientKind: DeviceClientKind
    /// New-device cool-down: until this instant, `deny`/`report` work but the device may not approve **high or critical**
    /// requests, unless another trusted device confirms it (`POST /v1/devices/{id}/confirm`). `nil` = trusted.
    public var approvalsLockedUntil: Date?
    /// When the device stops working on its own (App Clips: 7 days after enrollment). `nil` = never.
    public var expiresAt: Date?
    /// Set on a **live** device that "Set up again" is replacing: the new device that will take its place. The old device keeps working
    /// until that device is confirmed or its cool-down ends (`pendingReplacementAt`), or until the owner cancels
    /// (`APIRoutes.deviceReplacementCancel`, which revokes the new device).
    public var pendingReplacementBy: DeviceID?
    /// The latest moment the old device is revoked automatically (the new device's cool-down end).
    public var pendingReplacementAt: Date?
    /// Present **only** in the `POST /v1/devices` response that started a pending replacement of a live device: a new session already
    /// bound to this new device (the caller's own session stays bound to the old device, which keeps working). The app stores these
    /// tokens for the new device; there is no second passkey prompt.
    public var replacementSession: AuthSession?

    public init(id: DeviceID, consumerId: ConsumerID, name: String, platform: DevicePlatform, keys: [DeviceKey],
                createdAt: Date, lastSeenAt: Date? = nil, revokedAt: Date? = nil, clientKind: DeviceClientKind = .app,
                approvalsLockedUntil: Date? = nil, expiresAt: Date? = nil, pendingReplacementBy: DeviceID? = nil,
                pendingReplacementAt: Date? = nil, replacementSession: AuthSession? = nil) {
        self.id = id
        self.consumerId = consumerId
        self.name = name
        self.platform = platform
        self.keys = keys
        self.maxAssurance = Device.maxAssurance(for: keys)
        self.createdAt = createdAt
        self.lastSeenAt = lastSeenAt
        self.revokedAt = revokedAt
        self.clientKind = clientKind
        self.approvalsLockedUntil = approvalsLockedUntil
        self.expiresAt = expiresAt
        self.pendingReplacementBy = pendingReplacementBy
        self.pendingReplacementAt = pendingReplacementAt
        self.replacementSession = replacementSession
    }

    enum CodingKeys: String, CodingKey {
        case id, consumerId, name, platform, keys, maxAssurance, createdAt, lastSeenAt, revokedAt, clientKind, clipDevice, approvalsLockedUntil, expiresAt
        case pendingReplacementBy, pendingReplacementAt, replacementSession
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(DeviceID.self, forKey: .id)
        consumerId = try c.decode(ConsumerID.self, forKey: .consumerId)
        name = try c.decode(String.self, forKey: .name)
        platform = try c.decode(DevicePlatform.self, forKey: .platform)
        keys = try c.decode([DeviceKey].self, forKey: .keys)
        maxAssurance = try c.decode(DecisionAssurance.self, forKey: .maxAssurance)
        createdAt = try c.decode(Date.self, forKey: .createdAt)
        lastSeenAt = try c.decodeIfPresent(Date.self, forKey: .lastSeenAt)
        revokedAt = try c.decodeIfPresent(Date.self, forKey: .revokedAt)
        let clip = try c.decodeIfPresent(Bool.self, forKey: .clipDevice) ?? false
        clientKind = clip ? .appClip : (try c.decodeIfPresent(DeviceClientKind.self, forKey: .clientKind) ?? .app)
        approvalsLockedUntil = try c.decodeIfPresent(Date.self, forKey: .approvalsLockedUntil)
        expiresAt = try c.decodeIfPresent(Date.self, forKey: .expiresAt)
        pendingReplacementBy = try c.decodeIfPresent(DeviceID.self, forKey: .pendingReplacementBy)
        pendingReplacementAt = try c.decodeIfPresent(Date.self, forKey: .pendingReplacementAt)
        replacementSession = try c.decodeIfPresent(AuthSession.self, forKey: .replacementSession)
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(consumerId, forKey: .consumerId)
        try c.encode(name, forKey: .name)
        try c.encode(platform, forKey: .platform)
        try c.encode(keys, forKey: .keys)
        try c.encode(maxAssurance, forKey: .maxAssurance)
        try c.encode(createdAt, forKey: .createdAt)
        try c.encodeIfPresent(lastSeenAt, forKey: .lastSeenAt)
        try c.encodeIfPresent(revokedAt, forKey: .revokedAt)
        try c.encode(clientKind, forKey: .clientKind)
        try c.encode(clientKind == .appClip, forKey: .clipDevice)
        try c.encodeIfPresent(approvalsLockedUntil, forKey: .approvalsLockedUntil)
        try c.encodeIfPresent(expiresAt, forKey: .expiresAt)
        try c.encodeIfPresent(pendingReplacementBy, forKey: .pendingReplacementBy)
        try c.encodeIfPresent(pendingReplacementAt, forKey: .pendingReplacementAt)
        try c.encodeIfPresent(replacementSession, forKey: .replacementSession)
    }

    /// Whether the device is inside its new-device cool-down at `now`.
    public func isCoolingDown(at now: Date) -> Bool { approvalsLockedUntil.map { now < $0 } ?? false }

    /// Whether the device has passed its own lifetime.
    public func isExpired(at now: Date) -> Bool { expiresAt.map { now >= $0 } ?? false }

    public var isRevoked: Bool { revokedAt != nil }

    /// Wire convenience for the app: true for App Clip devices.
    public var clipDevice: Bool { clientKind == .appClip }

    /// The key that must verify a request or decision with the given assurance.
    public func key(for purpose: DeviceKeyPurpose) -> DeviceKey? { keys.first { $0.purpose == purpose } }

    static func maxAssurance(for keys: [DeviceKey]) -> DecisionAssurance {
        let purposes = Set(keys.map(\.purpose))
        if purposes.contains(.approvalBiometric) { return .biometric }
        if purposes.contains(.approvalUserPresence) { return .devicePasscode }
        return .none
    }
}
