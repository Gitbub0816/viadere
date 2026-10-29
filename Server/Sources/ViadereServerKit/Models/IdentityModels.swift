import Fluent
import Foundation
import ViadereCore

/// The App Attest key that vouched for a device at enrollment (`AppAttestVerifier`). One row per device; `key_id` is unique across the
/// whole table, so an attestation cannot be used to vouch for a second device. `counter` only ever increases (assertions).
final class AppAttestKeyRecord: Model, @unchecked Sendable {
    static let schema = "app_attest_keys"
    @ID(key: .id) var id: UUID?
    @Field(key: "device_id") var deviceId: UUID
    @Field(key: "consumer_id") var consumerId: UUID
    /// Lowercase hex of the key identifier (SHA-256 of the X9.63 public key).
    @Field(key: "key_id") var keyId: String
    /// base64url of the attested public key (X9.63).
    @Field(key: "public_key") var publicKey: String
    /// Last assertion counter accepted (0 right after attestation).
    @Field(key: "counter") var counter: Int
    /// `production` or `development` (the AAGUID the attestation carried).
    @Field(key: "environment") var environment: String
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "last_assertion_at") var lastAssertionAt: Date?
    /// The integrity evidence format (`apple-app-attest`); the table is format-neutral so another platform's attested key fits too.
    @Field(key: "format") var format: String

    init() {}

    init(deviceId: UUID, consumerId: UUID, keyId: String, publicKey: String, counter: Int, environment: String, now: Date,
         format: IntegrityEvidenceFormat = .appleAppAttest) {
        self.format = format.rawValue
        id = UUID()
        self.deviceId = deviceId
        self.consumerId = consumerId
        self.keyId = keyId
        self.publicKey = publicKey
        self.counter = counter
        self.environment = environment
        createdAt = now
    }
}

/// An account's recovery identity: the recovery ID (stored only as a peppered HMAC), the attempt counter and lock.
final class RecoveryProfileRecord: Model, @unchecked Sendable {
    static let schema = "recovery_profiles"
    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "recovery_id_hash") var recoveryIdHash: String
    /// Wrong codes since the last success; at the cap the account is locked for `RecoveryService.lockDuration`.
    @Field(key: "failed_attempts") var failedAttempts: Int
    @OptionalField(key: "locked_until") var lockedUntil: Date?
    @Field(key: "issued_at") var issuedAt: Date
    @Field(key: "created_at") var createdAt: Date

    init() {}

    init(consumerId: UUID, recoveryIdHash: String, now: Date) {
        id = UUID()
        self.consumerId = consumerId
        self.recoveryIdHash = recoveryIdHash
        failedAttempts = 0
        issuedAt = now
        createdAt = now
    }
}

/// One recovery code: only a peppered HMAC of the normalized code. `active` → `used` (compare-and-swap) or `invalidated`.
final class RecoveryCodeRecord: Model, @unchecked Sendable {
    static let schema = "recovery_codes"
    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "code_hash") var codeHash: String
    @Field(key: "state") var state: String
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "used_at") var usedAt: Date?

    init() {}

    init(consumerId: UUID, codeHash: String, now: Date) {
        id = UUID()
        self.consumerId = consumerId
        self.codeHash = codeHash
        state = "active"
        createdAt = now
    }
}

/// One account recovery. `awaiting_passkey` → `holding` → `activated`, or `cancelled` / `expired`.
final class AccountRecoveryRecord: Model, @unchecked Sendable {
    static let schema = "account_recoveries"
    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "state") var state: String
    /// Registration challenge (base64url) for the new passkey.
    @Field(key: "challenge") var challenge: String
    @Field(key: "user_handle") var userHandle: String
    @Field(key: "passkey_expires_at") var passkeyExpiresAt: Date
    @OptionalField(key: "new_credential_id") var newCredentialId: String?
    @OptionalField(key: "new_public_key") var newPublicKey: String?
    @OptionalField(key: "new_sign_count") var newSignCount: Int?
    @OptionalField(key: "new_backup_eligible") var newBackupEligible: Bool?
    /// SHA-256 of the status token the recovering client keeps.
    @OptionalField(key: "status_token_hash") var statusTokenHash: String?
    @OptionalField(key: "hold_until") var holdUntil: Date?
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "activated_at") var activatedAt: Date?
    @OptionalField(key: "cancelled_at") var cancelledAt: Date?
    /// The replacement recovery codes were handed to the recovering client (exactly once).
    @OptionalField(key: "codes_issued_at") var codesIssuedAt: Date?

    init() {}

    init(consumerId: UUID, challenge: String, userHandle: String, now: Date) {
        id = UUID()
        self.consumerId = consumerId
        state = "awaiting_passkey"
        self.challenge = challenge
        self.userHandle = userHandle
        passkeyExpiresAt = now.addingTimeInterval(RecoveryPolicy.passkeyWindow)
        createdAt = now
    }
}

/// `(business, operation, key)` → the request it was first used with, and for operations that return a secret the sealed result.
final class BusinessIdempotencyRecord: Model, @unchecked Sendable {
    static let schema = "business_idempotency"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "operation") var operation: String
    @Field(key: "idem_key") var idemKey: String
    @Field(key: "request_hash") var requestHash: String
    @OptionalField(key: "resource_id") var resourceId: UUID?
    /// The response body, AES-GCM sealed (row-bound), for operations that return a one-time secret; wiped after 24 h.
    @OptionalField(key: "result_sealed") var resultSealed: String?
    @Field(key: "created_at") var createdAt: Date

    init() {}

    init(businessId: UUID, operation: String, key: String, requestHash: String, resourceId: UUID?, now: Date) {
        id = UUID()
        self.businessId = businessId
        self.operation = operation
        idemKey = key
        self.requestHash = requestHash
        self.resourceId = resourceId
        createdAt = now
    }
}

/// A device-first account-creation ceremony (§2.5a): the reserved account id and the single-use challenge (stored as a hash).
final class AccountEnrollCeremonyRecord: Model, @unchecked Sendable {
    static let schema = "account_enroll_ceremonies"
    @ID(key: .id) var id: UUID?
    @Field(key: "reserved_account_id") var reservedAccountId: UUID
    @Field(key: "challenge_hash") var challengeHash: String
    /// `open` → `used` (compare-and-swap, exactly once).
    @Field(key: "state") var state: String
    @Field(key: "expires_at") var expiresAt: Date
    @Field(key: "created_at") var createdAt: Date

    init() {}

    init(reservedAccountId: UUID, challengeHash: String, now: Date, ttl: TimeInterval) {
        id = UUID()
        self.reservedAccountId = reservedAccountId
        self.challengeHash = challengeHash
        state = "open"
        createdAt = now
        expiresAt = now.addingTimeInterval(ttl)
    }
}
