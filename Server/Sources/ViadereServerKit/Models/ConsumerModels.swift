import Fluent
import Foundation
import ViadereCore

final class ConsumerRecord: Model, @unchecked Sendable {
    static let schema = "consumers"
    @ID(key: .id) var id: UUID?
    @Field(key: "display_name") var displayName: String
    /// Opaque WebAuthn user handle (random, no PII).
    @Field(key: "user_handle") var userHandle: String
    @Field(key: "status") var status: String
    @Field(key: "created_at") var createdAt: Date

    init() {}

    init(id: UUID, displayName: String, userHandle: String, now: Date) {
        self.id = id
        self.displayName = displayName
        self.userHandle = userHandle
        status = "active"
        createdAt = now
    }

    var consumerID: ConsumerID { ConsumerID(id ?? UUID()) }

    /// Sandbox consumers are created for test-mode API keys; they have no passkey, device or phone and cannot sign in.
    var isSandbox: Bool { status == ConsumerRecord.sandboxStatus }
    static let sandboxStatus = "sandbox"
}

final class PasskeyCredentialRecord: Model, @unchecked Sendable {
    static let schema = "passkey_credentials"
    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "credential_id") var credentialId: String
    /// Public key bytes, base64url.
    @Field(key: "public_key") var publicKey: String
    @Field(key: "sign_count") var signCount: Int
    @Field(key: "backup_eligible") var backupEligible: Bool
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "last_used_at") var lastUsedAt: Date?

    init() {}

    init(consumerId: UUID, credentialId: String, publicKey: String, signCount: Int, backupEligible: Bool, now: Date) {
        id = UUID()
        self.consumerId = consumerId
        self.credentialId = credentialId
        self.publicKey = publicKey
        self.signCount = signCount
        self.backupEligible = backupEligible
        createdAt = now
    }
}

/// A short-lived WebAuthn ceremony (registration or login). Consumed exactly once.
final class PasskeyCeremonyRecord: Model, @unchecked Sendable {
    static let schema = "passkey_ceremonies"
    @ID(key: .id) var id: UUID?
    @Field(key: "kind") var kind: String
    @Field(key: "challenge") var challenge: String
    @OptionalField(key: "consumer_id") var consumerId: UUID?
    @OptionalField(key: "display_name") var displayName: String?
    @OptionalField(key: "user_handle") var userHandle: String?
    @Field(key: "state") var state: String
    @Field(key: "expires_at") var expiresAt: Date
    @Field(key: "created_at") var createdAt: Date

    init() {}

    init(kind: String, challenge: String, consumerId: UUID?, displayName: String?, userHandle: String?, now: Date, ttl: TimeInterval) {
        id = UUID()
        self.kind = kind
        self.challenge = challenge
        self.consumerId = consumerId
        self.displayName = displayName
        self.userHandle = userHandle
        state = "open"
        createdAt = now
        expiresAt = now.addingTimeInterval(ttl)
    }
}

final class AccessTokenRecord: Model, @unchecked Sendable {
    static let schema = "access_tokens"
    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "token_hash") var tokenHash: String
    @Field(key: "family_id") var familyId: UUID
    @Field(key: "expires_at") var expiresAt: Date
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "revoked_at") var revokedAt: Date?

    init() {}

    init(consumerId: UUID, tokenHash: String, familyId: UUID, now: Date, expiresAt: Date) {
        id = UUID()
        self.consumerId = consumerId
        self.tokenHash = tokenHash
        self.familyId = familyId
        createdAt = now
        self.expiresAt = expiresAt
    }
}

final class RefreshTokenRecord: Model, @unchecked Sendable {
    static let schema = "refresh_tokens"
    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "token_hash") var tokenHash: String
    @Field(key: "family_id") var familyId: UUID
    /// `active`, `used` (rotated) or `revoked`.
    @Field(key: "state") var state: String
    @Field(key: "expires_at") var expiresAt: Date
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "used_at") var usedAt: Date?

    init() {}

    init(consumerId: UUID, tokenHash: String, familyId: UUID, now: Date, expiresAt: Date) {
        id = UUID()
        self.consumerId = consumerId
        self.tokenHash = tokenHash
        self.familyId = familyId
        state = "active"
        createdAt = now
        self.expiresAt = expiresAt
    }
}

final class DeviceRecord: Model, @unchecked Sendable {
    static let schema = "devices"
    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "name") var name: String
    @Field(key: "platform") var platform: String
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "last_seen_at") var lastSeenAt: Date?
    @OptionalField(key: "revoked_at") var revokedAt: Date?
    /// `app` or `appClip` (`DeviceClientKind`).
    @Field(key: "client_kind") var clientKind: String
    /// New-device cool-down: no high/critical approvals before this instant unless confirmed from another trusted device.
    @OptionalField(key: "approvals_locked_until") var approvalsLockedUntil: Date?
    /// App Clip devices stop working on their own after 7 days.
    @OptionalField(key: "expires_at") var expiresAt: Date?
    /// The token family this device was enrolled with (revoked together with the device, and vice versa).
    @OptionalField(key: "family_id") var familyId: UUID?
    @OptionalField(key: "confirmed_at") var confirmedAt: Date?
    /// `assertion` (fresh passkey assertion), `fresh_session` (unused passkey sign-in < 5 min old) or `legacy`.
    @Field(key: "enrollment_method") var enrollmentMethod: String

    init() {}

    init(id: UUID = UUID(), consumerId: UUID, name: String, platform: DevicePlatform, now: Date, clientKind: DeviceClientKind = .app) {
        self.id = id
        self.consumerId = consumerId
        self.name = name
        self.platform = platform.rawValue
        createdAt = now
        self.clientKind = clientKind.rawValue
        enrollmentMethod = "legacy"
    }

    var kind: DeviceClientKind { DeviceClientKind(rawValue: clientKind) ?? .app }

    func isExpired(at now: Date) -> Bool { expiresAt.map { now >= $0 } ?? false }
    func isCoolingDown(at now: Date) -> Bool { approvalsLockedUntil.map { now < $0 } ?? false }
}

/// A session (refresh-token family). Created by a passkey ceremony; bound to the device it enrolled.
final class TokenFamilyRecord: Model, @unchecked Sendable {
    static let schema = "token_families"
    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    /// `register` or `login`: the passkey ceremony that minted the family.
    @Field(key: "origin") var origin: String
    @Field(key: "created_at") var createdAt: Date
    /// While this is in the future the family may enroll one device without a separate assertion (single use).
    @OptionalField(key: "enroll_until") var enrollUntil: Date?
    /// The device this session belongs to; once set, the bearer is only valid with that device's signature.
    @OptionalField(key: "device_id") var deviceId: UUID?
    /// Hard cap on the session's lifetime (App Clip sessions).
    @OptionalField(key: "expires_at") var expiresAt: Date?
    @OptionalField(key: "revoked_at") var revokedAt: Date?

    init() {}

    init(id: UUID, consumerId: UUID, origin: String, now: Date, enrollUntil: Date?) {
        self.id = id
        self.consumerId = consumerId
        self.origin = origin
        createdAt = now
        self.enrollUntil = enrollUntil
    }
}

final class DeviceKeyRecord: Model, @unchecked Sendable {
    static let schema = "device_keys"
    @ID(key: .id) var id: UUID?
    @Field(key: "device_id") var deviceId: UUID
    @Field(key: "purpose") var purpose: String
    @Field(key: "public_key") var publicKey: String
    /// As claimed by the client. Trust `attested` instead.
    @Field(key: "hardware_backed") var hardwareBacked: Bool
    /// True only if an App Attest verifier accepted the key's attestation. Always false until one is configured.
    @Field(key: "attested") var attested: Bool
    @Field(key: "created_at") var createdAt: Date

    init() {}

    init(deviceId: UUID, purpose: DeviceKeyPurpose, publicKey: DevicePublicKey, hardwareBacked: Bool, now: Date, attested: Bool = false) {
        id = UUID()
        self.deviceId = deviceId
        self.purpose = purpose.rawValue
        self.publicKey = publicKey.base64URL
        self.hardwareBacked = hardwareBacked
        self.attested = attested
        createdAt = now
    }
}

/// Single-use challenge for device enrollment proof-of-possession.
final class DeviceEnrollChallengeRecord: Model, @unchecked Sendable {
    static let schema = "device_enroll_challenges"
    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "challenge_hash") var challengeHash: String
    @Field(key: "state") var state: String
    @Field(key: "expires_at") var expiresAt: Date
    /// The token family that asked for the challenge: a challenge is only good for the session that began it.
    @OptionalField(key: "family_id") var familyId: UUID?

    init() {}

    init(consumerId: UUID, challengeHash: String, expiresAt: Date, familyId: UUID? = nil) {
        id = UUID()
        self.consumerId = consumerId
        self.challengeHash = challengeHash
        state = "open"
        self.expiresAt = expiresAt
        self.familyId = familyId
    }
}

/// Phone link. `verified_phone_hash` is non-NULL only while verified and is unique, so a number is
/// verified for at most one consumer at a time.
final class PhoneLinkRecord: Model, @unchecked Sendable {
    static let schema = "phone_links"
    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "phone_hash") var phoneHash: String
    @Field(key: "phone_ciphertext") var phoneCiphertext: String
    @Field(key: "phone_masked") var phoneMasked: String
    @Field(key: "phone_last4") var phoneLast4: String
    /// `pending`, `verified` or `revoked`.
    @Field(key: "state") var state: String
    @OptionalField(key: "otp_hash") var otpHash: String?
    @OptionalField(key: "otp_expires_at") var otpExpiresAt: Date?
    @Field(key: "otp_attempts") var otpAttempts: Int
    @OptionalField(key: "verified_phone_hash") var verifiedPhoneHash: String?
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "verified_at") var verifiedAt: Date?
    /// A new link is not an interaction delivery target or an RCS/SMS decider before this instant, unless confirmed
    /// from a trusted device. `nil` = usable.
    @OptionalField(key: "usable_from") var usableFrom: Date?
    /// `otp` or `sms_link`.
    @OptionalField(key: "source") var source: String?
    @OptionalField(key: "confirmed_at") var confirmedAt: Date?

    init() {}

    init(consumerId: UUID, phone: PhoneNumber, hasher: Hasher256, cipher: FieldCipher, now: Date) throws {
        id = UUID()
        self.consumerId = consumerId
        phoneHash = hasher.phoneHash(phone)
        phoneCiphertext = try cipher.seal(phone.e164, context: "phone_links.phone", rowId: id!)
        phoneMasked = phone.masked
        phoneLast4 = String(phone.e164.suffix(4))
        state = "pending"
        otpAttempts = 0
        createdAt = now
    }
}
