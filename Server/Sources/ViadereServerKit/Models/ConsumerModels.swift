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

    init() {}

    init(id: UUID = UUID(), consumerId: UUID, name: String, platform: DevicePlatform, now: Date) {
        self.id = id
        self.consumerId = consumerId
        self.name = name
        self.platform = platform.rawValue
        createdAt = now
    }
}

final class DeviceKeyRecord: Model, @unchecked Sendable {
    static let schema = "device_keys"
    @ID(key: .id) var id: UUID?
    @Field(key: "device_id") var deviceId: UUID
    @Field(key: "purpose") var purpose: String
    @Field(key: "public_key") var publicKey: String
    @Field(key: "hardware_backed") var hardwareBacked: Bool
    @Field(key: "created_at") var createdAt: Date

    init() {}

    init(deviceId: UUID, purpose: DeviceKeyPurpose, publicKey: DevicePublicKey, hardwareBacked: Bool, now: Date) {
        id = UUID()
        self.deviceId = deviceId
        self.purpose = purpose.rawValue
        self.publicKey = publicKey.base64URL
        self.hardwareBacked = hardwareBacked
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

    init() {}

    init(consumerId: UUID, challengeHash: String, expiresAt: Date) {
        id = UUID()
        self.consumerId = consumerId
        self.challengeHash = challengeHash
        state = "open"
        self.expiresAt = expiresAt
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

    init() {}

    init(consumerId: UUID, phone: PhoneNumber, hasher: Hasher256, cipher: FieldCipher, now: Date) throws {
        id = UUID()
        self.consumerId = consumerId
        phoneHash = hasher.phoneHash(phone)
        phoneCiphertext = try cipher.seal(phone.e164, context: "phone_links.phone")
        phoneMasked = phone.masked
        phoneLast4 = String(phone.e164.suffix(4))
        state = "pending"
        otpAttempts = 0
        createdAt = now
    }
}
