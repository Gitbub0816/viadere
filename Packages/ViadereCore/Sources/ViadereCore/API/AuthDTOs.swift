import Foundation

// MARK: - Passkeys (WebAuthn). Binary fields are base64url strings.

/// Begin consumer registration.
public struct PasskeyRegistrationBeginRequest: Codable, Sendable, Hashable {
    /// Display name shown in the passkey sheet (≤ 64).
    public var displayName: String
    public init(displayName: String) { self.displayName = displayName }
}

/// Options for `ASAuthorizationPlatformPublicKeyCredentialProvider.createCredentialRegistrationRequest`.
public struct PasskeyRegistrationOptions: Codable, Sendable, Hashable {
    public var ceremonyId: CeremonyID
    /// base64url challenge (≥ 32 random bytes).
    public var challenge: String
    /// `viadere.com`.
    public var relyingPartyId: String
    public var relyingPartyName: String
    /// base64url opaque user handle (never contains PII).
    public var userId: String
    public var userName: String
    public var userDisplayName: String
    public var timeoutMilliseconds: Int
    /// Credential ids (base64url) already registered, to exclude.
    public var excludeCredentialIds: [String]
    /// "required".
    public var userVerification: String

    public init(ceremonyId: CeremonyID, challenge: String, relyingPartyId: String, relyingPartyName: String, userId: String,
                userName: String, userDisplayName: String, timeoutMilliseconds: Int = 120_000,
                excludeCredentialIds: [String] = [], userVerification: String = "required") {
        self.ceremonyId = ceremonyId
        self.challenge = challenge
        self.relyingPartyId = relyingPartyId
        self.relyingPartyName = relyingPartyName
        self.userId = userId
        self.userName = userName
        self.userDisplayName = userDisplayName
        self.timeoutMilliseconds = timeoutMilliseconds
        self.excludeCredentialIds = excludeCredentialIds
        self.userVerification = userVerification
    }
}

/// Attestation result from the platform authenticator.
public struct PasskeyRegistrationCredential: Codable, Sendable, Hashable {
    public var id: String
    public var rawId: String
    public var attestationObject: String
    public var clientDataJSON: String
    public var transports: [String]

    public init(id: String, rawId: String, attestationObject: String, clientDataJSON: String, transports: [String] = []) {
        self.id = id
        self.rawId = rawId
        self.attestationObject = attestationObject
        self.clientDataJSON = clientDataJSON
        self.transports = transports
    }
}

public struct PasskeyRegistrationFinishRequest: Codable, Sendable, Hashable {
    public var ceremonyId: CeremonyID
    public var credential: PasskeyRegistrationCredential
    public init(ceremonyId: CeremonyID, credential: PasskeyRegistrationCredential) {
        self.ceremonyId = ceremonyId
        self.credential = credential
    }
}

public struct PasskeyLoginBeginRequest: Codable, Sendable, Hashable {
    public init() {}
}

/// Options for `createCredentialAssertionRequest`.
public struct PasskeyAssertionOptions: Codable, Sendable, Hashable {
    public var ceremonyId: CeremonyID
    public var challenge: String
    public var relyingPartyId: String
    /// Empty = discoverable credentials.
    public var allowCredentialIds: [String]
    public var timeoutMilliseconds: Int
    public var userVerification: String

    public init(ceremonyId: CeremonyID, challenge: String, relyingPartyId: String, allowCredentialIds: [String] = [],
                timeoutMilliseconds: Int = 120_000, userVerification: String = "required") {
        self.ceremonyId = ceremonyId
        self.challenge = challenge
        self.relyingPartyId = relyingPartyId
        self.allowCredentialIds = allowCredentialIds
        self.timeoutMilliseconds = timeoutMilliseconds
        self.userVerification = userVerification
    }
}

public struct PasskeyAssertionCredential: Codable, Sendable, Hashable {
    public var id: String
    public var rawId: String
    public var authenticatorData: String
    public var clientDataJSON: String
    public var signature: String
    public var userHandle: String?

    public init(id: String, rawId: String, authenticatorData: String, clientDataJSON: String, signature: String, userHandle: String?) {
        self.id = id
        self.rawId = rawId
        self.authenticatorData = authenticatorData
        self.clientDataJSON = clientDataJSON
        self.signature = signature
        self.userHandle = userHandle
    }
}

public struct PasskeyLoginFinishRequest: Codable, Sendable, Hashable {
    public var ceremonyId: CeremonyID
    public var credential: PasskeyAssertionCredential
    public init(ceremonyId: CeremonyID, credential: PasskeyAssertionCredential) {
        self.ceremonyId = ceremonyId
        self.credential = credential
    }
}

/// A consumer session. `accessToken` is opaque (the server stores only its SHA-256).
public struct AuthSession: Codable, Sendable, Hashable {
    public var consumerId: ConsumerID
    public var accessToken: String
    public var tokenType: String
    public var expiresAt: Date

    public init(consumerId: ConsumerID, accessToken: String, tokenType: String = "Bearer", expiresAt: Date) {
        self.consumerId = consumerId
        self.accessToken = accessToken
        self.tokenType = tokenType
        self.expiresAt = expiresAt
    }
}

// MARK: - Devices

/// Server challenge for device enrollment.
public struct DeviceEnrollmentChallenge: Codable, Sendable, Hashable {
    public var challenge: String
    public var expiresAt: Date
    public init(challenge: String, expiresAt: Date) {
        self.challenge = challenge
        self.expiresAt = expiresAt
    }
}

/// One key being enrolled, with proof of possession.
public struct DeviceKeyRegistration: Codable, Sendable, Hashable {
    public var purpose: DeviceKeyPurpose
    public var publicKey: DevicePublicKey
    public var hardwareBacked: Bool
    /// base64url raw r||s signature over `DeviceEnrollment.proofMessage(…)`.
    public var proof: String

    public init(purpose: DeviceKeyPurpose, publicKey: DevicePublicKey, hardwareBacked: Bool, proof: String) {
        self.purpose = purpose
        self.publicKey = publicKey
        self.hardwareBacked = hardwareBacked
        self.proof = proof
    }
}

public struct DeviceEnrollRequest: Codable, Sendable, Hashable {
    public var name: String
    public var platform: DevicePlatform
    public var challenge: String
    /// Must include a `.request` key; approval keys optional.
    public var keys: [DeviceKeyRegistration]

    public init(name: String, platform: DevicePlatform, challenge: String, keys: [DeviceKeyRegistration]) {
        self.name = name
        self.platform = platform
        self.challenge = challenge
        self.keys = keys
    }
}

/// Proof-of-possession format for device enrollment.
///
/// `message = "VIADERE-ENROLL-V1\n{consumerId}\n{challenge}\n{purpose}\n{base64url x963 public key}"`
public enum DeviceEnrollment {
    public static func proofMessage(consumerId: ConsumerID, challenge: String, purpose: DeviceKeyPurpose, publicKey: DevicePublicKey) -> Data {
        Data("VIADERE-ENROLL-V1\n\(consumerId)\n\(challenge)\n\(purpose.rawValue)\n\(publicKey.base64URL)".utf8)
    }

    /// Creates a registration with proof (device side).
    public static func register(key: any DeviceSigningKey, purpose: DeviceKeyPurpose, hardwareBacked: Bool, consumerId: ConsumerID,
                                challenge: String) async throws -> DeviceKeyRegistration {
        let message = proofMessage(consumerId: consumerId, challenge: challenge, purpose: purpose, publicKey: key.publicKey)
        let signature = try await key.signature(for: message)
        return DeviceKeyRegistration(purpose: purpose, publicKey: key.publicKey, hardwareBacked: hardwareBacked,
                                     proof: ViadereSignatureEncoding.encode(signature))
    }

    /// Verifies a registration's proof (server side).
    public static func verify(_ registration: DeviceKeyRegistration, consumerId: ConsumerID, challenge: String) -> Bool {
        guard let signature = ViadereSignatureEncoding.decode(registration.proof),
              let key = try? registration.publicKey.signingKey() else { return false }
        let message = proofMessage(consumerId: consumerId, challenge: challenge, purpose: registration.purpose,
                                   publicKey: registration.publicKey)
        return key.isValidSignature(signature, for: message)
    }
}

// MARK: - Phone links

public struct PhoneLinkStartRequest: Codable, Sendable, Hashable {
    public var phone: PhoneNumber
    public init(phone: PhoneNumber) { self.phone = phone }
}

public struct PhoneLinkStartResponse: Codable, Sendable, Hashable {
    public var phoneLinkId: PhoneLinkID
    public var expiresAt: Date
    public init(phoneLinkId: PhoneLinkID, expiresAt: Date) {
        self.phoneLinkId = phoneLinkId
        self.expiresAt = expiresAt
    }
}

public struct PhoneLinkVerifyRequest: Codable, Sendable, Hashable {
    public var phoneLinkId: PhoneLinkID
    /// 6-digit code sent by SMS.
    public var code: String
    public init(phoneLinkId: PhoneLinkID, code: String) {
        self.phoneLinkId = phoneLinkId
        self.code = code
    }
}

/// A verified phone link (phone shown masked).
public struct PhoneLink: Codable, Sendable, Hashable, Identifiable {
    public var id: PhoneLinkID
    public var maskedPhone: String
    public var verifiedAt: Date
    public init(id: PhoneLinkID, maskedPhone: String, verifiedAt: Date) {
        self.id = id
        self.maskedPhone = maskedPhone
        self.verifiedAt = verifiedAt
    }
}

/// Redeem an SMS account-link token after passkey sign-in on the web.
public struct SMSLinkRedeemRequest: Codable, Sendable, Hashable {
    /// Token from the `https://viadere.com/l/{token}` link.
    public var token: String
    /// Explicit confirmation of the last 4 digits of the phone being linked.
    public var confirmPhoneLast4: String
    public init(token: String, confirmPhoneLast4: String) {
        self.token = token
        self.confirmPhoneLast4 = confirmPhoneLast4
    }
}

// MARK: - Push

public struct APNsTokenRegistration: Codable, Sendable, Hashable {
    public enum Environment: String, Codable, Sendable { case sandbox, production }
    /// Hex device token.
    public var token: String
    public var environment: Environment
    public var bundleId: String
    public init(token: String, environment: Environment, bundleId: String) {
        self.token = token
        self.environment = environment
        self.bundleId = bundleId
    }
}

public struct LiveActivityTokenRegistration: Codable, Sendable, Hashable {
    public enum Kind: String, Codable, Sendable { case pushToStart, update }
    public var kind: Kind
    /// ActivityKit activity id (for `.update`).
    public var activityId: String?
    public var businessId: BusinessID?
    public var interactionId: InteractionID?
    /// Hex push token.
    public var pushToken: String
    public init(kind: Kind, activityId: String? = nil, businessId: BusinessID? = nil, interactionId: InteractionID? = nil, pushToken: String) {
        self.kind = kind
        self.activityId = activityId
        self.businessId = businessId
        self.interactionId = interactionId
        self.pushToken = pushToken
    }
}
