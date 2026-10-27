import Foundation
import ViadereCore

/// The consumer's session credentials. Stored in the Keychain (`ThisDeviceOnly`), never in defaults.
public struct TokenSet: Codable, Sendable, Equatable {
    public var consumerId: ConsumerID
    public var accessToken: String
    public var accessExpiresAt: Date
    public var refreshToken: String?
    /// Set by the token store when the (more strongly protected) refresh token could not be read right now, for
    /// example in the notification extension while the phone is locked. Never persisted. A set with this flag is
    /// still good for the access token, but must not be refreshed or treated as signed out.
    public var refreshTokenUnavailable: Bool

    enum CodingKeys: String, CodingKey { case consumerId, accessToken, accessExpiresAt, refreshToken }

    public init(consumerId: ConsumerID, accessToken: String, accessExpiresAt: Date, refreshToken: String? = nil,
                refreshTokenUnavailable: Bool = false) {
        self.consumerId = consumerId
        self.accessToken = accessToken
        self.accessExpiresAt = accessExpiresAt
        self.refreshToken = refreshToken
        self.refreshTokenUnavailable = refreshTokenUnavailable
    }

    public init(_ session: AuthSession) {
        self.init(consumerId: session.consumerId, accessToken: session.accessToken,
                  accessExpiresAt: session.expiresAt, refreshToken: session.refreshToken)
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init(consumerId: try c.decode(ConsumerID.self, forKey: .consumerId), accessToken: try c.decode(String.self, forKey: .accessToken),
                  accessExpiresAt: try c.decode(Date.self, forKey: .accessExpiresAt),
                  refreshToken: try c.decodeIfPresent(String.self, forKey: .refreshToken))
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

/// Keychain-backed (via `SecretStore`) token store with **two protection classes**:
///
/// - the access token (short-lived) and its expiry live in `secrets`, `AfterFirstUnlockThisDeviceOnly`, so the
///   notification service extension can fetch request details while the phone is locked;
/// - the **refresh token** (long-lived, the real credential) lives in `refreshSecrets`,
///   `WhenUnlockedThisDeviceOnly`: it is readable only while the phone is unlocked. A locked-phone extension
///   therefore cannot rotate the session (it shows a generic banner instead), and a device that is merely
///   powered on but locked does not expose it.
///
/// If `refreshSecrets` is `nil` both live in `secrets` (tests, previews).
public struct SecretTokenStore: TokenStore {
    private struct AccessRecord: Codable {
        var consumerId: ConsumerID
        var accessToken: String
        var accessExpiresAt: Date
        /// Written by older builds, which kept the refresh token here. Migrated on first load.
        var refreshToken: String?
    }

    private let access: JSONSecretSlot<AccessRecord>
    private let secrets: any SecretStore
    private let refreshSecrets: any SecretStore
    private static let refreshAccount = "session.refresh"

    public init(secrets: any SecretStore, refreshSecrets: (any SecretStore)? = nil) {
        access = JSONSecretSlot(secrets: secrets, account: "session.tokens")
        self.secrets = secrets
        self.refreshSecrets = refreshSecrets ?? secrets
    }

    public func load() async throws -> TokenSet? {
        guard let record = try access.load() else { return nil }
        var tokens = TokenSet(consumerId: record.consumerId, accessToken: record.accessToken, accessExpiresAt: record.accessExpiresAt)
        do {
            if let data = try refreshSecrets.read(Self.refreshAccount) {
                tokens.refreshToken = String(data: data, encoding: .utf8)
            } else if let legacy = record.refreshToken {
                // Migrate a refresh token an older build stored next to the access token.
                try refreshSecrets.write(Data(legacy.utf8), account: Self.refreshAccount)
                try access.save(AccessRecord(consumerId: record.consumerId, accessToken: record.accessToken,
                                             accessExpiresAt: record.accessExpiresAt, refreshToken: nil))
                tokens.refreshToken = legacy
            }
        } catch {
            // Locked or otherwise unreadable right now. This is *not* "signed out": keep the access token usable.
            tokens.refreshTokenUnavailable = true
        }
        return tokens
    }

    public func save(_ tokens: TokenSet) async throws {
        try access.save(AccessRecord(consumerId: tokens.consumerId, accessToken: tokens.accessToken,
                                     accessExpiresAt: tokens.accessExpiresAt, refreshToken: nil))
        if let refresh = tokens.refreshToken {
            try refreshSecrets.write(Data(refresh.utf8), account: Self.refreshAccount)
        } else if !tokens.refreshTokenUnavailable {
            try refreshSecrets.delete(Self.refreshAccount)
        }
    }

    public func clear() async throws {
        try? refreshSecrets.delete(Self.refreshAccount)
        try access.clear()
    }
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
