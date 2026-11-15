import Foundation

// MARK: - Device-first account creation (WP-B4, ADR-0013, SECURITY.md §2.5a)

/// `POST /v1/accounts/enroll/begin` (public; no body is needed). Opens a single-use ceremony and **reserves** an account id, so the existing
/// proof formats (`VIADERE-ENROLL-V1`, `VIADERE-APPATTEST-ENROLL-V1`), which both name the account, work unchanged before the account exists.
/// The response says nothing about any existing account.
public struct AccountEnrollBeginResponse: Codable, Sendable, Hashable {
    public var ceremonyId: CeremonyID
    /// The id the account will have if `POST /v1/accounts` succeeds. Not an account yet; internal, never shown to businesses.
    public var accountId: ConsumerID
    /// base64url, ≥ 256 random bits, single use, valid until `expiresAt` (5 minutes).
    public var challenge: String
    public var expiresAt: Date
    public var integrity: IntegrityRequirement

    public init(ceremonyId: CeremonyID, accountId: ConsumerID, challenge: String, expiresAt: Date, integrity: IntegrityRequirement) {
        self.ceremonyId = ceremonyId
        self.accountId = accountId
        self.challenge = challenge
        self.expiresAt = expiresAt
        self.integrity = integrity
    }
}

/// `POST /v1/accounts` (public). Creates the pseudonymous account, its first device and a session bound to that device, in one transaction.
/// There is **no** personal field: no name, email, phone or password. `deviceName` is a label for the person's own device list.
///
/// * `keys`: one per purpose, including `request`; each proves possession over
///   `VIADERE-ENROLL-V1\n{accountId}\n{challenge}\n{purpose}\n{publicKey}` with the **reserved** `accountId`. An App Clip sends a request key only.
/// * `integrity`: `apple-app-attest` evidence over `VIADERE-APPATTEST-ENROLL-V1\n{accountId}\n{challenge}\n{keyListDigest}`.
public struct AccountCreateRequest: Codable, Sendable, Hashable {
    public var ceremonyId: CeremonyID
    public var challenge: String
    public var platform: DevicePlatform
    /// Optional label (≤ 64) for the device list; a neutral default is used when absent.
    public var deviceName: String?
    public var keys: [DeviceKeyRegistration]
    public var integrity: IntegrityEvidence?
    public var clientKind: DeviceClientKind

    public init(ceremonyId: CeremonyID, challenge: String, platform: DevicePlatform, deviceName: String?, keys: [DeviceKeyRegistration],
                integrity: IntegrityEvidence?, clientKind: DeviceClientKind = .app) {
        self.ceremonyId = ceremonyId
        self.challenge = challenge
        self.platform = platform
        self.deviceName = deviceName
        self.keys = keys
        self.integrity = integrity
        self.clientKind = clientKind
    }

    enum CodingKeys: String, CodingKey { case ceremonyId, challenge, platform, deviceName, keys, integrity, clientKind }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        ceremonyId = try c.decode(CeremonyID.self, forKey: .ceremonyId)
        challenge = try c.decode(String.self, forKey: .challenge)
        platform = try c.decode(DevicePlatform.self, forKey: .platform)
        deviceName = try c.decodeIfPresent(String.self, forKey: .deviceName)
        keys = try c.decode([DeviceKeyRegistration].self, forKey: .keys)
        integrity = try c.decodeIfPresent(IntegrityEvidence.self, forKey: .integrity)
        clientKind = try c.decodeIfPresent(DeviceClientKind.self, forKey: .clientKind) ?? .app
    }
}

/// `201` from `POST /v1/accounts`: the account, its device (with the server-decided `trustTier`) and a session already bound to the device
/// (every later request is device-signed). There are no recovery codes here: recovery credentials are optional and added afterwards
/// ("Protect your account", `APIRoutes.recoveryCodesRegenerate`, `APIRoutes.recoveryPasskeyBegin`).
public struct AccountCreateResponse: Codable, Sendable, Hashable {
    public var accountId: ConsumerID
    public var device: Device
    public var session: AuthSession

    public init(accountId: ConsumerID, device: Device, session: AuthSession) {
        self.accountId = accountId
        self.device = device
        self.session = session
    }
}
