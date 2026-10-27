import Fluent
import Foundation

/// A person who signs in to the business dashboard (`business`) or the operator console (`operator`).
/// Separate from consumers: different table, different passkeys, different sessions.
final class DashboardUserRecord: Model, @unchecked Sendable {
    static let schema = "dashboard_users"
    @ID(key: .id) var id: UUID?
    /// `business` or `operator`.
    @Field(key: "kind") var kind: String
    @Field(key: "email_hash") var emailHash: String
    @Field(key: "email_ciphertext") var emailCiphertext: String
    @Field(key: "display_name") var displayName: String
    /// WebAuthn user handle (opaque random).
    @Field(key: "user_handle") var userHandle: String
    /// `active`, `unverified` (business sign-up whose emailed code has not been entered), `pending` (operator awaiting enrollment) or `disabled`.
    @Field(key: "status") var status: String
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "last_login_at") var lastLoginAt: Date?

    init() {}

    var isOperator: Bool { kind == "operator" }
}

final class DashboardPasskeyRecord: Model, @unchecked Sendable {
    static let schema = "dashboard_passkeys"
    @ID(key: .id) var id: UUID?
    @Field(key: "user_id") var userId: UUID
    @Field(key: "credential_id") var credentialId: String
    @Field(key: "public_key") var publicKey: String
    @Field(key: "sign_count") var signCount: Int
    @Field(key: "backup_eligible") var backupEligible: Bool
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "last_used_at") var lastUsedAt: Date?

    init() {}
}

/// Short-lived, single-use WebAuthn ceremony for the dashboard (`signup`, `invite`, `enroll`, `login`, `reauth`).
final class DashboardCeremonyRecord: Model, @unchecked Sendable {
    static let schema = "dashboard_ceremonies"
    @ID(key: .id) var id: UUID?
    @Field(key: "kind") var kind: String
    @Field(key: "challenge") var challenge: String
    @OptionalField(key: "user_id") var userId: UUID?
    /// Pending sign-up / invite data (never secrets).
    @OptionalField(key: "payload_json") var payloadJSON: String?
    @Field(key: "state") var state: String
    @Field(key: "expires_at") var expiresAt: Date
    @Field(key: "created_at") var createdAt: Date

    init() {}
}

/// Cookie-backed dashboard session. Only the SHA-256 of the cookie value is stored.
final class DashboardSessionRecord: Model, @unchecked Sendable {
    static let schema = "dashboard_sessions"
    @ID(key: .id) var id: UUID?
    @Field(key: "user_id") var userId: UUID
    /// `business` or `operator`; a cookie only works in its own realm.
    @Field(key: "realm") var realm: String
    @Field(key: "token_hash") var tokenHash: String
    /// The organization the session is acting for (business realm).
    @OptionalField(key: "business_id") var businessId: UUID?
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "last_seen_at") var lastSeenAt: Date
    /// Absolute expiry.
    @Field(key: "expires_at") var expiresAt: Date
    /// Last passkey assertion (login or re-authentication).
    @OptionalField(key: "reauth_at") var reauthAt: Date?
    @OptionalField(key: "revoked_at") var revokedAt: Date?
    /// Hashed address/agent of the sign-in (session inventory and suspicious-login detection); never the raw values.
    @OptionalField(key: "ip_hash") var ipHash: String?
    /// The address with its host part removed (IPv4 /24, IPv6 /48), shown in the session inventory.
    @OptionalField(key: "ip_masked") var ipMasked: String?
    @OptionalField(key: "ua_hash") var uaHash: String?
    /// A short, fixed-vocabulary description such as "Safari on macOS".
    @OptionalField(key: "ua_label") var uaLabel: String?
    @OptionalField(key: "country") var country: String?
    /// `lastSeenAt` as it was before the current request refreshed it (not stored). Privileged operations compare it with the inactivity timeout.
    var priorSeenAt: Date?

    init() {}
}

final class OrgMembershipRecord: Model, @unchecked Sendable {
    static let schema = "org_memberships"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "user_id") var userId: UUID
    @Field(key: "role") var role: String
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "removed_at") var removedAt: Date?

    init() {}
}

final class OrgInviteRecord: Model, @unchecked Sendable {
    static let schema = "org_invites"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "email_hash") var emailHash: String
    @Field(key: "email_ciphertext") var emailCiphertext: String
    @Field(key: "role") var role: String
    @Field(key: "token_hash") var tokenHash: String
    @Field(key: "invited_by") var invitedBy: UUID
    /// `open`, `accepted` or `revoked`.
    @Field(key: "state") var state: String
    @Field(key: "expires_at") var expiresAt: Date
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "accepted_at") var acceptedAt: Date?

    init() {}
}

/// One-time enrollment link for a new operator (created by the `create-operator` command).
final class OperatorEnrollmentRecord: Model, @unchecked Sendable {
    static let schema = "operator_enrollments"
    @ID(key: .id) var id: UUID?
    @Field(key: "user_id") var userId: UUID
    @Field(key: "token_hash") var tokenHash: String
    @Field(key: "state") var state: String
    @Field(key: "expires_at") var expiresAt: Date
    @Field(key: "created_at") var createdAt: Date

    init() {}
}

/// The application an organization submits. Handles and codes are issued only when an operator approves it.
final class BusinessApplicationRecord: Model, @unchecked Sendable {
    static let schema = "business_applications"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @OptionalField(key: "requested_handle") var requestedHandle: String?
    @OptionalField(key: "legal_name") var legalName: String?
    @OptionalField(key: "website") var website: String?
    @OptionalField(key: "description") var detail: String?
    /// `pending`, `approved` or `rejected`.
    @Field(key: "state") var state: String
    @Field(key: "submitted_at") var submittedAt: Date
    @OptionalField(key: "reviewed_at") var reviewedAt: Date?
    @OptionalField(key: "reviewed_by") var reviewedBy: UUID?
    @OptionalField(key: "decision_note") var decisionNote: String?

    init() {}
}

/// Operator- and system-applied controls on a business. Controls can only *restrict*: throttle, suspension
/// reason, and a priority ceiling that can only lower (never raise) what the Trust Engine would allow.
final class BusinessControlRecord: Model, @unchecked Sendable {
    static let schema = "business_controls"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "throttled") var throttled: Bool
    /// `auto` (abuse thresholds) or `operator` (pinned until an operator clears it).
    @OptionalField(key: "throttle_source") var throttleSource: String?
    @OptionalField(key: "throttle_reason") var throttleReason: String?
    @OptionalField(key: "throttled_at") var throttledAt: Date?
    /// `low`, `normal` or `high`; `nil` = no extra cap.
    @OptionalField(key: "priority_ceiling") var priorityCeiling: String?
    @OptionalField(key: "suspension_reason") var suspensionReason: String?
    @Field(key: "updated_at") var updatedAt: Date
    @OptionalField(key: "updated_by") var updatedBy: UUID?

    init() {}
}

/// Minute-bucketed counters for abuse signals (`rate_limited`, …). No consumer data.
final class AbuseSignalRecord: Model, @unchecked Sendable {
    static let schema = "abuse_signals"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "kind") var kind: String
    @Field(key: "bucket") var bucket: Int
    @Field(key: "count") var count: Int

    init() {}
}

/// Metering events: `meter` is what was consumed, `category` is `platform` (Viadere fee basis) or `transport`
/// (carrier/provider pass-through). `(meter, ref)` is unique, so retries never double count.
final class UsageEventRecord: Model, @unchecked Sendable {
    static let schema = "usage_events"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "meter") var meter: String
    @Field(key: "category") var category: String
    @Field(key: "quantity") var quantity: Int
    @Field(key: "livemode") var livemode: Bool
    @Field(key: "ref") var ref: String
    @Field(key: "occurred_at") var occurredAt: Date

    init() {}
}
