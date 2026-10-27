import Crypto
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
///
/// `refreshToken` is also opaque and single-use: redeeming it (`APIRoutes.authRefresh`) returns a new
/// session with a **new** refresh token. Presenting an already-used refresh token revokes the whole
/// session family. Both optional fields are absent in responses from servers that predate rotation.
public struct AuthSession: Codable, Sendable, Hashable {
    public var consumerId: ConsumerID
    public var accessToken: String
    public var tokenType: String
    public var expiresAt: Date
    public var refreshToken: String?
    public var refreshExpiresAt: Date?
    /// The account's 10 single-use recovery codes. Present **only** in the `register/finish` response, exactly once: the app must make
    /// the person save them (print, password manager) before continuing. The server keeps only peppered HMACs and can never show them
    /// again (`RecoveryCodeSet`, §2.25).
    public var recoveryCodes: RecoveryCodeSet?

    public init(consumerId: ConsumerID, accessToken: String, tokenType: String = "Bearer", expiresAt: Date,
                refreshToken: String? = nil, refreshExpiresAt: Date? = nil, recoveryCodes: RecoveryCodeSet? = nil) {
        self.consumerId = consumerId
        self.accessToken = accessToken
        self.tokenType = tokenType
        self.expiresAt = expiresAt
        self.refreshToken = refreshToken
        self.refreshExpiresAt = refreshExpiresAt
        self.recoveryCodes = recoveryCodes
    }
}

/// Rotates a session: exchange the current refresh token for a new access + refresh token pair.
///
/// **Device-signed when the session is bound to a device.** `POST /v1/auth/refresh` carries the `VIADERE-SIG-V1` headers
/// (`Viadere-Device`, `Viadere-Timestamp`, `Viadere-Nonce`, `Viadere-Signature`, §2.3) made with the bound device's `request` key
/// over this exact request (method, path, body). A bound session without a valid signature from its device is `401 signature_invalid`
/// (the 60 s grace replay included), so a copied refresh token is useless without the device. A session that has not enrolled a
/// device yet (fresh passkey sign-in) refreshes without headers. There is no bearer header.
public struct AuthRefreshRequest: Codable, Sendable, Hashable {
    public var refreshToken: String
    public init(refreshToken: String) { self.refreshToken = refreshToken }
}

/// Redeems a secure-handoff token (`https://viadere.com/h/{token}`) inside the app.
public struct HandoffRedeemRequest: Codable, Sendable, Hashable {
    public var token: String
    public init(token: String) { self.token = token }
}

/// What the app should continue after redeeming a handoff token.
public struct HandoffRedeemResponse: Codable, Sendable, Hashable {
    public var purpose: HandoffPurpose
    public var interactionId: InteractionID?
    public init(purpose: HandoffPurpose, interactionId: InteractionID? = nil) {
        self.purpose = purpose
        self.interactionId = interactionId
    }
}

// MARK: - Devices

/// Server challenge for device enrollment.
///
/// **Passkey-bound enrollment.** A bearer token alone never creates a device: the new device's keys are the strongest
/// credential the account has (the biometric key approves payments and sign-ins). `assertion` carries WebAuthn
/// assertion options whose `challenge` equals `challenge`: the app performs a user-verified passkey assertion over it and
/// sends the result in `DeviceEnrollRequest.assertion`. The one exception is `assertionOptional == true`: the token
/// family was minted by a passkey sign-in or registration less than five minutes ago and has not enrolled yet
/// (single use), so the ceremony the user just completed already proves the same thing.
public struct DeviceEnrollmentChallenge: Codable, Sendable, Hashable {
    public var challenge: String
    public var expiresAt: Date
    /// Assertion options (`challenge` identical to `challenge`, `userVerification` = required). `nil` only from servers
    /// that predate passkey-bound enrollment.
    public var assertion: PasskeyAssertionOptions?
    /// True when this session may enroll without `DeviceEnrollRequest.assertion` (fresh, unused passkey sign-in).
    public var assertionOptional: Bool

    public init(challenge: String, expiresAt: Date, assertion: PasskeyAssertionOptions? = nil, assertionOptional: Bool = false) {
        self.challenge = challenge
        self.expiresAt = expiresAt
        self.assertion = assertion
        self.assertionOptional = assertionOptional
    }

    enum CodingKeys: String, CodingKey { case challenge, expiresAt, assertion, assertionOptional }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        challenge = try c.decode(String.self, forKey: .challenge)
        expiresAt = try c.decode(Date.self, forKey: .expiresAt)
        assertion = try c.decodeIfPresent(PasskeyAssertionOptions.self, forKey: .assertion)
        assertionOptional = try c.decodeIfPresent(Bool.self, forKey: .assertionOptional) ?? false
    }
}

/// What kind of Viadere client is enrolling.
public enum DeviceClientKind: String, Codable, Sendable, CaseIterable {
    /// The full app: may enroll approval keys.
    case app
    /// The App Clip: request key only, a 7-day device lifetime, and it can never decide interactions.
    case appClip
}

/// Apple App Attest evidence for the keys being enrolled (`DCAppAttestService.attestKey(_:clientDataHash:)`). The server verifies it
/// against Apple's App Attestation Root CA (§2.5): `DeviceKey.attested` is `true` only on success, and with
/// `APP_ATTEST_MODE=require` an enrollment without a valid attestation is refused (`403 attestation_required`).
///
/// **clientDataHash** = `AppAttestBinding.clientDataHash(consumerId:challenge:keys:)`: SHA-256 of
/// `"VIADERE-APPATTEST-ENROLL-V1\n{consumerId}\n{challenge}\n{SHA-256 hex of the canonical key list}"`, so an attestation vouches for
/// exactly this enrollment challenge, account and key set and cannot be replayed to vouch for other keys.
public struct AppAttestEvidence: Codable, Sendable, Hashable {
    /// App Attest key identifier as `DCAppAttestService.generateKey` returned it (base64, standard or url alphabet).
    public var keyId: String
    /// base64url (or standard base64) CBOR attestation object returned by `attestKey`.
    public var attestation: String

    public init(keyId: String, attestation: String) {
        self.keyId = keyId
        self.attestation = attestation
    }
}

/// The App Attest client-data binding for an enrollment (`AppAttestEvidence`). Reference implementation shared by the app and server.
public enum AppAttestBinding {
    public static let domain = "VIADERE-APPATTEST-ENROLL-V1"

    /// Lowercase hex SHA-256 of the canonical key list: one line `"{purpose}:{base64url X9.63 public key}"` per key, sorted by purpose
    /// raw value, joined with `"\n"` (no trailing newline).
    public static func keyListDigest(_ keys: [DeviceKeyRegistration]) -> String {
        let lines = keys.map { "\($0.purpose.rawValue):\($0.publicKey.base64URL)" }.sorted()
        return SecureToken.sha256Hex(Data(lines.joined(separator: "\n").utf8))
    }

    /// `"VIADERE-APPATTEST-ENROLL-V1\n{consumerId}\n{challenge}\n{keyListDigest}"` (UTF-8). The attestation's `clientData`.
    public static func clientData(consumerId: ConsumerID, challenge: String, keys: [DeviceKeyRegistration]) -> Data {
        Data([domain, consumerId.description, challenge, keyListDigest(keys)].joined(separator: "\n").utf8)
    }

    /// SHA-256 of `clientData`: the value to pass as `clientDataHash` to `attestKey`.
    public static func clientDataHash(consumerId: ConsumerID, challenge: String, keys: [DeviceKeyRegistration]) -> Data {
        Data(SHA256.hash(data: clientData(consumerId: consumerId, challenge: challenge, keys: keys)))
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
    /// Must include a `.request` key; approval keys optional (and not allowed for `appClip`).
    public var keys: [DeviceKeyRegistration]
    /// A user-verified passkey assertion whose challenge is `challenge` (see `DeviceEnrollmentChallenge`). Required unless the
    /// challenge response said `assertionOptional`.
    public var assertion: PasskeyAssertionCredential?
    /// `app` (default) or `appClip`.
    public var clientKind: DeviceClientKind
    /// Wire alias used by the app: `true` for an App Clip enrollment (omitted otherwise). `true` means `clientKind == .appClip`.
    public var clipDevice: Bool?
    /// App Attest evidence (recorded; not yet trusted).
    public var appAttest: AppAttestEvidence?
    /// "Set up again": the caller's own device (or one revoked within the last 30 days) that this enrollment replaces.
    /// * An old device that is already **revoked** is replaced at once (the session moves to the new device).
    /// * A **live** old device is not revoked yet: it is marked `Device.pendingReplacementBy`, keeps working, and is revoked when the
    ///   new device is confirmed or its cool-down ends, unless the owner cancels from the old device
    ///   (`APIRoutes.deviceReplacementCancel`). The caller's session stays bound to the old device; the response carries a new
    ///   session bound to the new device (`Device.replacementSession`).
    /// The new device is still subject to the new-device cool-down. Omitted for an ordinary enrollment.
    public var replacesDeviceId: DeviceID?

    public init(name: String, platform: DevicePlatform, challenge: String, keys: [DeviceKeyRegistration],
                assertion: PasskeyAssertionCredential? = nil, clientKind: DeviceClientKind = .app, appAttest: AppAttestEvidence? = nil,
                clipDevice: Bool? = nil, replacesDeviceId: DeviceID? = nil) {
        self.clipDevice = clipDevice
        self.replacesDeviceId = replacesDeviceId
        self.name = name
        self.platform = platform
        self.challenge = challenge
        self.keys = keys
        self.assertion = assertion
        self.clientKind = clientKind
        self.appAttest = appAttest
    }

    enum CodingKeys: String, CodingKey { case name, platform, challenge, keys, assertion, clientKind, appAttest, clipDevice, replacesDeviceId }

    /// The effective client kind: `clipDevice == true` or `clientKind == .appClip` both mean App Clip.
    public var effectiveClientKind: DeviceClientKind { clipDevice == true || clientKind == .appClip ? .appClip : .app }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        name = try c.decode(String.self, forKey: .name)
        platform = try c.decode(DevicePlatform.self, forKey: .platform)
        challenge = try c.decode(String.self, forKey: .challenge)
        keys = try c.decode([DeviceKeyRegistration].self, forKey: .keys)
        assertion = try c.decodeIfPresent(PasskeyAssertionCredential.self, forKey: .assertion)
        clientKind = try c.decodeIfPresent(DeviceClientKind.self, forKey: .clientKind) ?? .app
        appAttest = try c.decodeIfPresent(AppAttestEvidence.self, forKey: .appAttest)
        clipDevice = try c.decodeIfPresent(Bool.self, forKey: .clipDevice)
        replacesDeviceId = try c.decodeIfPresent(DeviceID.self, forKey: .replacesDeviceId)
    }
}

/// Confirms a security-relevant addition from a device that is already trusted.
///
/// Used for (a) a **new device** that is in its cool-down (`POST /v1/devices/{deviceId}/confirm`, signed by *another*
/// device of the same account that is not itself cooling down) and (b) a **newly linked phone**
/// (`POST /v1/phone-links/{phoneLinkId}/confirm`). `signature` is the confirming device's ECDSA P-256 / SHA-256 signature
/// (raw r‖s, base64url) over `signingInput()`, made with its
/// `approvalBiometric` key (`assurance` = biometric); a passcode or request key cannot confirm.
public struct ConfirmationProof: Codable, Sendable, Hashable {
    public enum Subject: String, Codable, Sendable { case device, phoneLink }

    public static let domain = "VIADERE-CONFIRM-V1\n"
    /// A proof older than this (or more than `allowedFutureSkew` in the future) is rejected.
    public static let maxAge: TimeInterval = 300
    public static let allowedFutureSkew: TimeInterval = 60

    public var subject: Subject
    /// Lowercase UUID of the device or phone link being confirmed.
    public var subjectId: String
    /// The confirming device.
    public var deviceId: DeviceID
    public var signedAt: Date
    public var assurance: DecisionAssurance
    public var signature: String

    public init(subject: Subject, subjectId: String, deviceId: DeviceID, signedAt: Date, assurance: DecisionAssurance, signature: String) {
        self.subject = subject
        self.subjectId = subjectId
        self.deviceId = deviceId
        self.signedAt = ViadereDate.truncatedToMilliseconds(signedAt)
        self.assurance = assurance
        self.signature = signature
    }

    /// `"VIADERE-CONFIRM-V1\n{subject}\n{subjectId}\n{deviceId}\n{signedAt ISO-8601 ms}\n{assurance}"`.
    public static func signingInput(subject: Subject, subjectId: String, deviceId: DeviceID, signedAt: Date,
                                    assurance: DecisionAssurance) -> Data {
        Data((domain + [subject.rawValue, subjectId, deviceId.description, ViadereDate.format(signedAt), assurance.rawValue]
            .joined(separator: "\n")).utf8)
    }

    public func signingInput() -> Data {
        Self.signingInput(subject: subject, subjectId: subjectId, deviceId: deviceId, signedAt: signedAt, assurance: assurance)
    }

    /// Signs a confirmation (device side).
    public static func sign(subject: Subject, subjectId: String, deviceId: DeviceID, assurance: DecisionAssurance,
                            key: any DeviceSigningKey, now: Date = Date()) async throws -> ConfirmationProof {
        let signedAt = ViadereDate.truncatedToMilliseconds(now)
        let signature = try await key.signature(for: signingInput(subject: subject, subjectId: subjectId, deviceId: deviceId,
                                                                   signedAt: signedAt, assurance: assurance))
        return ConfirmationProof(subject: subject, subjectId: subjectId, deviceId: deviceId, signedAt: signedAt, assurance: assurance,
                                 signature: ViadereSignatureEncoding.encode(signature))
    }

    public enum Failure: Error, Equatable, Sendable {
        case wrongSubject, assuranceTooLow, malformedSignature, signedInFuture, tooOld, badSignature, replayed
    }

    /// The key purpose that must have signed this proof. Only `biometric` assurance confirms: a device passcode is known to a
    /// shoulder-surfer or thief, and a request key never counts, so those are `nil` (`Failure.assuranceTooLow`).
    public var requiredKeyPurpose: DeviceKeyPurpose? {
        switch assurance {
        case .none: nil
        case .devicePasscode: nil
        case .biometric: .approvalBiometric
        }
    }

    /// Content-based replay key (never the signature string: `(r, n - s)` is a second encoding of the same proof).
    public var replayKey: String {
        SecureToken.sha256Hex(signingInput())
    }

    /// Checks subject binding, freshness and the signature. `publicKey` must be the confirming device's key for `requiredKeyPurpose`.
    public func verify(subject expected: Subject, subjectId expectedId: String, publicKey: DevicePublicKey, now: Date) throws {
        guard subject == expected, ConstantTime.equals(subjectId.lowercased(), expectedId.lowercased()) else { throw Failure.wrongSubject }
        guard requiredKeyPurpose != nil else { throw Failure.assuranceTooLow }
        guard let decoded = ViadereSignatureEncoding.decode(signature) else { throw Failure.malformedSignature }
        guard signedAt <= now.addingTimeInterval(Self.allowedFutureSkew) else { throw Failure.signedInFuture }
        guard now.timeIntervalSince(signedAt) <= Self.maxAge else { throw Failure.tooOld }
        guard let key = try? publicKey.signingKey(), key.isValidSignature(decoded, for: signingInput()) else { throw Failure.badSignature }
    }

    /// `verify` plus single-use consumption through `replayGuard` (scope `confirm:{deviceId}`).
    public func verify(subject expected: Subject, subjectId expectedId: String, publicKey: DevicePublicKey, now: Date,
                       replayGuard: any ReplayGuard) async throws {
        try verify(subject: expected, subjectId: expectedId, publicKey: publicKey, now: now)
        let fresh = try await replayGuard.registerIfFresh(nonce: replayKey, scope: "confirm:\(deviceId)",
                                                          expiresAt: signedAt.addingTimeInterval(Self.maxAge + Self.allowedFutureSkew), now: now)
        guard fresh else { throw Failure.replayed }
    }
}

/// Body of `POST /v1/devices/{deviceId}/confirm` and `POST /v1/phone-links/{phoneLinkId}/confirm`.
public struct ConfirmationRequest: Codable, Sendable, Hashable {
    public var proof: ConfirmationProof
    public init(proof: ConfirmationProof) { self.proof = proof }
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
///
/// A link created from an SMS link token (or from a device that is itself cooling down) is **not used** as an interaction
/// delivery target or as an RCS/SMS decider until `usableFrom` (24 hours after verification) unless it is confirmed
/// from a trusted device (`POST /v1/phone-links/{id}/confirm`). `usableFrom == nil` means usable now.
public struct PhoneLink: Codable, Sendable, Hashable, Identifiable {
    public var id: PhoneLinkID
    public var maskedPhone: String
    public var verifiedAt: Date
    public var usableFrom: Date?
    public init(id: PhoneLinkID, maskedPhone: String, verifiedAt: Date, usableFrom: Date? = nil) {
        self.id = id
        self.maskedPhone = maskedPhone
        self.verifiedAt = verifiedAt
        self.usableFrom = usableFrom
    }

    enum CodingKeys: String, CodingKey { case id, maskedPhone, verifiedAt, usableFrom }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        id = try c.decode(PhoneLinkID.self, forKey: .id)
        maskedPhone = try c.decode(String.self, forKey: .maskedPhone)
        verifiedAt = try c.decode(Date.self, forKey: .verifiedAt)
        usableFrom = try c.decodeIfPresent(Date.self, forKey: .usableFrom)
    }
}

/// What an SMS account-link token would link, shown **before** redeeming it
/// (`GET /v1/sms/link-tokens/{token}/preview`; device-signed, rate-limited, does not consume the token).
/// The app must show `maskedPhone` in full with "This is my phone" and a warning that anyone who can read this number's
/// texts will see this account's messages.
public struct SMSLinkPreview: Codable, Sendable, Hashable {
    public var maskedPhone: String
    public var expiresAt: Date
    public init(maskedPhone: String, expiresAt: Date) {
        self.maskedPhone = maskedPhone
        self.expiresAt = expiresAt
    }
}

/// Redeem an SMS account-link token from the app (device-signed) after previewing it.
public struct SMSLinkRedeemRequest: Codable, Sendable, Hashable {
    /// Token from the `https://viadere.com/l/{token}` link.
    public var token: String
    /// Explicit confirmation of the last 4 digits of the phone being linked.
    public var confirmPhoneLast4: String
    /// The `maskedPhone` from `SMSLinkPreview`, echoed back after the person confirmed it is their phone. Optional on the wire
    /// (the app confirms from the preview and sends `confirmPhoneLast4`); when present it must match exactly.
    public var confirmMaskedPhone: String?
    public init(token: String, confirmPhoneLast4: String, confirmMaskedPhone: String? = nil) {
        self.token = token
        self.confirmPhoneLast4 = confirmPhoneLast4
        self.confirmMaskedPhone = confirmMaskedPhone
    }
}

// MARK: - Sessions & account

/// A signed-in session (one refresh-token family) as shown in security settings.
public struct SessionInfo: Codable, Sendable, Hashable, Identifiable {
    public var id: UUID
    public var createdAt: Date
    public var expiresAt: Date
    /// True for the session making this request.
    public var current: Bool
    public init(id: UUID, createdAt: Date, expiresAt: Date, current: Bool) {
        self.id = id
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.current = current
    }
}

// MARK: - Security notices

/// What happened. Unknown values decode as `.unknown` so older apps survive new kinds.
public enum SecurityNoticeKind: String, Codable, Sendable, Hashable {
    case newDevice, newPhone, appClip, deviceReplaced, unknown

    public init(from decoder: any Decoder) throws {
        self = SecurityNoticeKind(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .unknown
    }
}

/// Every notice topic the server sends, including the ones added after `SecurityNoticeKind` shipped (which an older app decodes as
/// `.unknown`). `SecurityNotice.topic` is derived from the wire `kind`, so new apps can tell them apart and old ones keep compiling.
public enum SecurityNoticeTopic: String, Codable, Sendable, Hashable {
    case newDevice, newPhone, appClip, deviceReplaced
    /// A new device is replacing this account's live device and will take over when it is confirmed or its cool-down ends
    /// (`action == .cancelDeviceReplacement`, `subjectId` = the NEW device).
    case devicePendingReplacement
    /// Account recovery was started with a recovery code (`action == .cancelRecovery`, `subjectId` = the recovery id).
    case recoveryStarted
    /// A recovery was cancelled, or its remaining recovery codes were invalidated.
    case recoveryCancelled
    /// Repeated wrong recovery codes locked recovery for a while.
    case recoveryAttemptsLocked
    /// A recovery took effect on this account: household access ended and linked phone numbers are cooling down again.
    case recoveryCompleted
    /// A household grant with another account ended because that account was recovered.
    case delegationEnded
    /// A device was added to (or removed from) the account's synced credential vault, or the synced vault was deleted.
    case vaultDeviceAdded, vaultDeviceRemoved, vaultDeleted
    case unknown

    public init(from decoder: any Decoder) throws {
        self = SecurityNoticeTopic(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .unknown
    }
}

/// What the person can do about a notice ("Not you? Cancel"). Unknown values decode as `.unknown` (show no button).
public enum SecurityNoticeAction: String, Codable, Sendable, Hashable {
    /// `POST /v1/recovery/{subjectId}/cancel` (a trusted device).
    case cancelRecovery
    /// `POST /v1/devices/{subjectId}/cancel-replacement`: revokes the NEW device; the old one keeps working.
    case cancelDeviceReplacement
    case unknown

    public init(from decoder: any Decoder) throws {
        self = SecurityNoticeAction(rawValue: try decoder.singleValueContainer().decode(String.self)) ?? .unknown
    }
}

/// An in-app notice about a sensitive change to the account (a device or phone was added, an App Clip session started, a device was set
/// up again). `GET /v1/security-notices` returns the undismissed ones, newest first, without the ones the calling device caused; the app
/// shows them when it opens, so an account whose other devices received no push still hears about it. Dismissing needs a trusted device.
public struct SecurityNotice: Codable, Sendable, Hashable, Identifiable {
    public var id: UUID
    /// The notice kind as this app version knows it; kinds added later (recovery, pending replacement) are `.unknown` here:
    /// use `topic` (or `action`) for those.
    public var kind: SecurityNoticeKind
    /// The wire `kind` string exactly as sent.
    public var rawKind: String
    /// Plain text, safe to show as-is.
    public var message: String
    public var createdAt: Date
    /// The device or phone link id (or recovery id) the notice is about, when there is one.
    public var subjectId: String?
    /// "Not you? Cancel": what the notice's button does (acting on `subjectId`). `nil` for informational notices.
    public var action: SecurityNoticeAction?

    /// Every topic, including those newer than `SecurityNoticeKind`.
    public var topic: SecurityNoticeTopic { SecurityNoticeTopic(rawValue: rawKind) ?? .unknown }

    public init(id: UUID, kind: SecurityNoticeKind, message: String, createdAt: Date, subjectId: String? = nil,
                action: SecurityNoticeAction? = nil) {
        self.init(id: id, rawKind: kind.rawValue, message: message, createdAt: createdAt, subjectId: subjectId, action: action)
    }

    public init(id: UUID, rawKind: String, message: String, createdAt: Date, subjectId: String? = nil, action: SecurityNoticeAction? = nil) {
        self.id = id
        self.rawKind = rawKind
        kind = SecurityNoticeKind(rawValue: rawKind) ?? .unknown
        self.message = message
        self.createdAt = createdAt
        self.subjectId = subjectId
        self.action = action
    }

    enum CodingKeys: String, CodingKey { case id, kind, message, createdAt, subjectId, action }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        self.init(id: try c.decode(UUID.self, forKey: .id), rawKind: try c.decode(String.self, forKey: .kind), message: try c.decode(String.self, forKey: .message),
                  createdAt: try c.decode(Date.self, forKey: .createdAt), subjectId: try c.decodeIfPresent(String.self, forKey: .subjectId),
                  action: try c.decodeIfPresent(SecurityNoticeAction.self, forKey: .action))
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(id, forKey: .id)
        try c.encode(rawKind, forKey: .kind)
        try c.encode(message, forKey: .message)
        try c.encode(createdAt, forKey: .createdAt)
        try c.encodeIfPresent(subjectId, forKey: .subjectId)
        try c.encodeIfPresent(action, forKey: .action)
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
