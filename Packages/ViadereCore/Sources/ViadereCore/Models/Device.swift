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
    /// True if the private key is hardware-backed (Secure Enclave), as reported at enrollment.
    public var hardwareBacked: Bool
    public var createdAt: Date

    public init(id: DeviceKeyID, purpose: DeviceKeyPurpose, publicKey: DevicePublicKey, hardwareBacked: Bool, createdAt: Date) {
        self.id = id
        self.purpose = purpose
        self.publicKey = publicKey
        self.hardwareBacked = hardwareBacked
        self.createdAt = createdAt
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

    public init(id: DeviceID, consumerId: ConsumerID, name: String, platform: DevicePlatform, keys: [DeviceKey],
                createdAt: Date, lastSeenAt: Date? = nil, revokedAt: Date? = nil) {
        self.id = id
        self.consumerId = consumerId
        self.name = name
        self.platform = platform
        self.keys = keys
        self.maxAssurance = Device.maxAssurance(for: keys)
        self.createdAt = createdAt
        self.lastSeenAt = lastSeenAt
        self.revokedAt = revokedAt
    }

    public var isRevoked: Bool { revokedAt != nil }

    /// The key that must verify a request or decision with the given assurance.
    public func key(for purpose: DeviceKeyPurpose) -> DeviceKey? { keys.first { $0.purpose == purpose } }

    static func maxAssurance(for keys: [DeviceKey]) -> DecisionAssurance {
        let purposes = Set(keys.map(\.purpose))
        if purposes.contains(.approvalBiometric) { return .biometric }
        if purposes.contains(.approvalUserPresence) { return .devicePasscode }
        return .none
    }
}
