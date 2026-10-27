import Foundation
import ViadereCore

/// The consumer's session credentials. Stored in the Keychain (`ThisDeviceOnly`), never in defaults.
public struct TokenSet: Codable, Sendable, Equatable {
    public var consumerId: ConsumerID
    public var accessToken: String
    public var accessExpiresAt: Date
    public var refreshToken: String?

    public init(consumerId: ConsumerID, accessToken: String, accessExpiresAt: Date, refreshToken: String? = nil) {
        self.consumerId = consumerId
        self.accessToken = accessToken
        self.accessExpiresAt = accessExpiresAt
        self.refreshToken = refreshToken
    }

    public init(_ session: AuthSession) {
        self.init(consumerId: session.consumerId, accessToken: session.accessToken,
                  accessExpiresAt: session.expiresAt, refreshToken: session.refreshToken)
    }

    /// True when the access token is expired or within `leeway` seconds of expiring.
    public func needsRefresh(now: Date, leeway: TimeInterval = 30) -> Bool {
        now.addingTimeInterval(leeway) >= accessExpiresAt
    }
}

public protocol TokenStore: Sendable {
    func load() async throws -> TokenSet?
    func save(_ tokens: TokenSet) async throws
    func clear() async throws
}

/// Keychain-backed (via `SecretStore`) token store.
public struct SecretTokenStore: TokenStore {
    private let slot: JSONSecretSlot<TokenSet>

    public init(secrets: any SecretStore) {
        slot = JSONSecretSlot(secrets: secrets, account: "session.tokens")
    }

    public func load() async throws -> TokenSet? { try slot.load() }
    public func save(_ tokens: TokenSet) async throws { try slot.save(tokens) }
    public func clear() async throws { try slot.clear() }
}

/// What this installation knows about its own enrolled device. Public identifiers only; no key material.
public struct DeviceRecord: Codable, Sendable, Equatable {
    public var deviceId: DeviceID
    public var consumerId: ConsumerID
    public var name: String
    /// Key purposes registered with the server at enrollment.
    public var purposes: [DeviceKeyPurpose]
    public var enrolledAt: Date

    public init(deviceId: DeviceID, consumerId: ConsumerID, name: String, purposes: [DeviceKeyPurpose], enrolledAt: Date) {
        self.deviceId = deviceId
        self.consumerId = consumerId
        self.name = name
        self.purposes = purposes
        self.enrolledAt = enrolledAt
    }

    /// Highest decision assurance this device can sign with.
    public var maxAssurance: DecisionAssurance {
        if purposes.contains(.approvalBiometric) { return .biometric }
        if purposes.contains(.approvalUserPresence) { return .devicePasscode }
        return .none
    }
}

public protocol DeviceRecordStore: Sendable {
    func load() async throws -> DeviceRecord?
    func save(_ record: DeviceRecord) async throws
    func clear() async throws
}

public struct SecretDeviceRecordStore: DeviceRecordStore {
    private let slot: JSONSecretSlot<DeviceRecord>

    public init(secrets: any SecretStore) {
        slot = JSONSecretSlot(secrets: secrets, account: "device.record")
    }

    public func load() async throws -> DeviceRecord? { try slot.load() }
    public func save(_ record: DeviceRecord) async throws { try slot.save(record) }
    public func clear() async throws { try slot.clear() }
}
