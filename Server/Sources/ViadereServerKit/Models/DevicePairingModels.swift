import Fluent
import Foundation
import ViadereCore

/// A pairing code a trusted device made (`device_pairing_invitations`, SECURITY.md §2.105). Only `HMAC(pepper, "device-pairing-code", code)` is
/// stored. `open` → `used` (compare-and-swap, once) or `revoked` (a newer code of the account).
final class DevicePairingInvitationRecord: Model, @unchecked Sendable {
    static let schema = "device_pairing_invitations"
    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "code_hash") var codeHash: String
    @Field(key: "created_by_device_id") var createdByDeviceId: UUID
    @Field(key: "state") var state: String
    @Field(key: "expires_at") var expiresAt: Date
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "used_at") var usedAt: Date?

    init() {}

    init(consumerId: UUID, codeHash: String, createdBy: UUID, now: Date) {
        id = UUID()
        self.consumerId = consumerId
        self.codeHash = codeHash
        createdByDeviceId = createdBy
        state = "open"
        createdAt = now
        expiresAt = now.addingTimeInterval(DevicePairing.invitationTTL)
    }
}

/// One pairing (`device_pairings`). States: `ceremony` (begin: no account yet) → `pending` (start: keys stored, nonce drawn) → `approved`,
/// `denied`, `expired`, `cancelled` or `failed`. Every transition is a compare-and-swap on `state`; at most one `pending` row per account
/// (partial unique index `uq_device_pairings_pending`).
final class DevicePairingRecord: Model, @unchecked Sendable {
    static let schema = "device_pairings"
    @ID(key: .id) var id: UUID?
    @Field(key: "state") var state: String
    @Field(key: "challenge_hash") var challengeHash: String
    @OptionalField(key: "consumer_id") var consumerId: UUID?
    @OptionalField(key: "invitation_id") var invitationId: UUID?
    @OptionalField(key: "nonce") var nonce: String?
    @OptionalField(key: "device_name") var deviceName: String?
    @OptionalField(key: "platform") var platform: String?
    /// The new device's key registrations (purpose, public key, hardware flag), canonical JSON.
    @OptionalField(key: "keys_json") var keysJSON: String?
    @OptionalField(key: "key_list_digest") var keyListDigest: String?
    @OptionalField(key: "comparison_digest") var comparisonDigest: String?
    @OptionalField(key: "status_token_hash") var statusTokenHash: String?
    /// The evaluated integrity (attested, reason, App Attest key id, public key, counter, environment), canonical JSON.
    @OptionalField(key: "attestation_json") var attestationJSON: String?
    @OptionalField(key: "integrity_format") var integrityFormat: String?
    @Field(key: "attempts") var attempts: Int
    /// Delivered without an alert push (paused after repeated denials, or over the hourly budget; ADR-0022 §5.1).
    @Field(key: "silent") var silent: Bool
    @Field(key: "fatigue_warning") var fatigueWarning: Bool
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "started_at") var startedAt: Date?
    @Field(key: "expires_at") var expiresAt: Date
    @OptionalField(key: "shown_at") var shownAt: Date?
    @OptionalField(key: "decided_at") var decidedAt: Date?
    @OptionalField(key: "decided_by_device_id") var decidedByDeviceId: UUID?
    @OptionalField(key: "new_device_id") var newDeviceId: UUID?
    @OptionalField(key: "session_issued_at") var sessionIssuedAt: Date?
    /// Why it ended: `deny`, `report`, `superseded`, `cancelled_by_new_device`, `wrong_number`, `expired`.
    @OptionalField(key: "end_reason") var endReason: String?

    init() {}

    init(challengeHash: String, now: Date) {
        id = UUID()
        state = "ceremony"
        self.challengeHash = challengeHash
        attempts = 0
        silent = false
        fatigueWarning = false
        createdAt = now
        expiresAt = now.addingTimeInterval(DevicePairing.ceremonyTTL)
    }
}

/// What `keys_json` holds per key.
struct StoredPairingKey: Codable, Sendable, Hashable {
    var purpose: DeviceKeyPurpose
    var publicKey: DevicePublicKey
    var hardwareBacked: Bool
}

/// What `attestation_json` holds.
struct StoredPairingAttestation: Codable, Sendable, Hashable {
    var attested: Bool
    var reason: String
    var keyId: String?
    var publicKey: String?
    var counter: Int
    var environment: String?
}
