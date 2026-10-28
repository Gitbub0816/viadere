import Fluent
import Foundation

/// One row per business: the facts the onboarding state machine (`OnboardingStateMachine`) is computed from. Facts are written by the
/// service that owns them (domain check, operator review, contract acceptance...), never by a client-supplied "stage".
final class BusinessOnboardingRecord: Model, @unchecked Sendable {
    static let schema = "business_onboarding"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "workspace_at") var workspaceAt: Date
    @OptionalField(key: "control_verified_at") var controlVerifiedAt: Date?
    @OptionalField(key: "control_method") var controlMethod: String?
    @OptionalField(key: "control_domain") var controlDomain: String?
    /// `none`, `submitted`, `approved` or `rejected`.
    @Field(key: "legal_status") var legalStatus: String
    @OptionalField(key: "legal_registry_number") var legalRegistryNumber: String?
    @OptionalField(key: "legal_jurisdiction") var legalJurisdiction: String?
    @OptionalField(key: "legal_registry_name") var legalRegistryName: String?
    /// Newline-separated references to evidence held elsewhere (no documents are stored here).
    @OptionalField(key: "legal_evidence_refs") var legalEvidenceRefs: String?
    @OptionalField(key: "legal_submitted_at") var legalSubmittedAt: Date?
    @OptionalField(key: "legal_reviewed_by") var legalReviewedBy: String?
    @OptionalField(key: "legal_reviewed_at") var legalReviewedAt: Date?
    @OptionalField(key: "legal_note") var legalNote: String?
    /// Sensitive categories: `not_required`, `pending`, `approved` or `rejected`.
    @Field(key: "enhanced_status") var enhancedStatus: String
    @OptionalField(key: "enhanced_reference") var enhancedReference: String?
    @OptionalField(key: "enhanced_reviewed_by") var enhancedReviewedBy: String?
    @OptionalField(key: "enhanced_reviewed_at") var enhancedReviewedAt: Date?
    @OptionalField(key: "sandbox_key_at") var sandboxKeyAt: Date?
    @OptionalField(key: "sandbox_relationship_at") var sandboxRelationshipAt: Date?
    @OptionalField(key: "test_event_at") var testEventAt: Date?
    /// `none`, `requested`, `approved` or `rejected`. Production keys exist only while this is `approved`.
    @Field(key: "golive_status") var goLiveStatus: String
    @OptionalField(key: "golive_requested_at") var goLiveRequestedAt: Date?
    @OptionalField(key: "golive_requested_by") var goLiveRequestedBy: String?
    @OptionalField(key: "golive_use_case") var goLiveUseCase: String?
    @OptionalField(key: "golive_volume") var goLiveVolume: String?
    @OptionalField(key: "golive_decided_at") var goLiveDecidedAt: Date?
    @OptionalField(key: "golive_decided_by") var goLiveDecidedBy: String?
    @OptionalField(key: "golive_note") var goLiveNote: String?
    @Field(key: "grandfathered") var grandfathered: Bool
    @OptionalField(key: "contracts_due_at") var contractsDueAt: Date?
    @OptionalField(key: "assurance_checked_at") var assuranceCheckedAt: Date?
    @OptionalField(key: "assurance_grace_started_at") var assuranceGraceStartedAt: Date?
    @OptionalField(key: "assurance_failure") var assuranceFailure: String?
    @Field(key: "assurance_suspended") var assuranceSuspended: Bool
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "updated_at") var updatedAt: Date

    init() {}

    init(businessId: UUID, now: Date) {
        id = UUID()
        self.businessId = businessId
        workspaceAt = now
        legalStatus = "none"
        enhancedStatus = "not_required"
        goLiveStatus = "none"
        grandfathered = false
        assuranceSuspended = false
        createdAt = now
        updatedAt = now
    }

    var evidenceReferences: [String] { (legalEvidenceRefs ?? "").split(separator: "\n").map(String.init) }
}

/// A domain a business claims. `token` is the public value placed in DNS or the well-known file; it is not a secret (anyone who can read the
/// record can read it), it only has to be unguessable by someone who cannot write to the domain.
final class BusinessDomainRecord: Model, @unchecked Sendable {
    static let schema = "business_domains"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "domain") var domain: String
    @Field(key: "token") var token: String
    /// `pending`, `verified` or `failed` (a verified domain whose re-check failed).
    @Field(key: "status") var status: String
    @OptionalField(key: "method") var method: String?
    @OptionalField(key: "verified_domain") var verifiedDomain: String?
    @Field(key: "created_by") var createdBy: String
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "verified_at") var verifiedAt: Date?
    @OptionalField(key: "last_checked_at") var lastCheckedAt: Date?
    @OptionalField(key: "next_check_at") var nextCheckAt: Date?
    @Field(key: "failures") var failures: Int
    @OptionalField(key: "last_error") var lastError: String?

    init() {}
}

final class ContractAcceptanceRecord: Model, @unchecked Sendable {
    static let schema = "contract_acceptances"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    @Field(key: "slug") var slug: String
    @Field(key: "version") var version: String
    @Field(key: "accepted_by") var acceptedBy: UUID
    @Field(key: "accepted_at") var acceptedAt: Date
    /// Peppered, versioned hashes (`Hasher256.versionedHex`): evidence of "same client" without storing the address or agent string.
    @Field(key: "ip_hash") var ipHash: String
    @Field(key: "ua_hash") var uaHash: String

    init() {}
}

final class BusinessSecuritySettingsRecord: Model, @unchecked Sendable {
    static let schema = "business_security_settings"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    /// Comma-separated CIDR blocks; empty = no restriction.
    @Field(key: "console_ip_allowlist") var consoleIPAllowlist: String
    @Field(key: "privileged_inactivity_seconds") var privilegedInactivitySeconds: Int
    @Field(key: "two_person_required") var twoPersonRequired: Bool
    @Field(key: "mtls_required") var mtlsRequired: Bool
    /// Comma-separated `SecurityAlertTopic` values.
    @Field(key: "alert_subscriptions") var alertSubscriptions: String
    /// Sealed JSON array of security-contact email addresses (row-bound).
    @OptionalField(key: "contacts_ciphertext") var contactsCiphertext: String?
    @Field(key: "updated_at") var updatedAt: Date
    @OptionalField(key: "updated_by") var updatedBy: UUID?

    init() {}

    init(businessId: UUID, now: Date) {
        id = UUID()
        self.businessId = businessId
        consoleIPAllowlist = ""
        privilegedInactivitySeconds = 300
        twoPersonRequired = false
        mtlsRequired = false
        alertSubscriptions = ""
        updatedAt = now
    }
}

final class BusinessMTLSCertRecord: Model, @unchecked Sendable {
    static let schema = "business_mtls_certs"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    /// `leaf` (SHA-256 fingerprint of the client certificate) or `issuer` (SHA-256 of the CA certificate that issued it; `issuerSKI` carries its key identifier).
    @Field(key: "kind") var kind: String
    @Field(key: "fingerprint") var fingerprint: String
    /// For an `issuer` binding: the CA's subject key identifier (lowercase hex), used to match the header the edge forwards.
    @OptionalField(key: "issuer_ski") var issuerSKI: String?
    @Field(key: "label") var label: String
    @OptionalField(key: "subject") var subject: String?
    @OptionalField(key: "not_after") var notAfter: Date?
    @Field(key: "created_by") var createdBy: UUID
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "revoked_at") var revokedAt: Date?
    @OptionalField(key: "revoked_by") var revokedBy: UUID?

    init() {}

    func isActive(at now: Date) -> Bool { revokedAt == nil && (notAfter ?? .distantFuture) > now }
}

final class DashboardKnownContextRecord: Model, @unchecked Sendable {
    static let schema = "dashboard_known_contexts"
    @ID(key: .id) var id: UUID?
    @Field(key: "user_id") var userId: UUID
    @Field(key: "dimension") var dimension: String
    @Field(key: "value_hash") var valueHash: String
    @Field(key: "first_seen_at") var firstSeenAt: Date
    @Field(key: "last_seen_at") var lastSeenAt: Date

    init() {}
}

/// A change that needs a second person (enterprise two-person approval). The payload never holds a secret: an approved key creation is
/// completed by the requester, who alone sees the new secret.
final class PendingChangeRecord: Model, @unchecked Sendable {
    static let schema = "pending_changes"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    /// `api_key` or `role_grant`.
    @Field(key: "kind") var kind: String
    @Field(key: "payload_json") var payloadJSON: String
    @Field(key: "requested_by") var requestedBy: UUID
    @Field(key: "requested_at") var requestedAt: Date
    @Field(key: "expires_at") var expiresAt: Date
    /// `pending`, `approved`, `rejected`, `executed`, `expired` or `cancelled`.
    @Field(key: "status") var status: String
    @OptionalField(key: "decided_by") var decidedBy: UUID?
    @OptionalField(key: "decided_at") var decidedAt: Date?
    @OptionalField(key: "decision_note") var decisionNote: String?
    @OptionalField(key: "executed_at") var executedAt: Date?

    init() {}
}

final class SupportTicketRecord: Model, @unchecked Sendable {
    static let schema = "support_tickets"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    /// `ticket` or `appeal`.
    @Field(key: "kind") var kind: String
    @Field(key: "subject") var subject: String
    @Field(key: "body_ciphertext") var bodyCiphertext: String
    /// `open`, `answered`, `closed`.
    @Field(key: "status") var status: String
    @Field(key: "created_by") var createdBy: UUID
    @Field(key: "created_at") var createdAt: Date
    @Field(key: "updated_at") var updatedAt: Date
    @OptionalField(key: "operator_note") var operatorNote: String?
    @OptionalField(key: "decided_by") var decidedBy: String?

    init() {}
}

final class OperatorNoticeRecord: Model, @unchecked Sendable {
    static let schema = "operator_notices"
    @ID(key: .id) var id: UUID?
    /// `business` or `consumer`.
    @Field(key: "audience") var audience: String
    /// `business` (one), `all_businesses`, `consumers_of_business`, `all_consumers`.
    @Field(key: "scope") var scope: String
    @OptionalField(key: "business_id") var businessId: UUID?
    @Field(key: "severity") var severity: String
    @Field(key: "title") var title: String
    @Field(key: "body") var body: String
    @Field(key: "created_by") var createdBy: String
    @Field(key: "created_at") var createdAt: Date
    /// `queued`, `sending` or `done`.
    @Field(key: "status") var status: String
    @OptionalField(key: "cursor") var cursor: String?
    @Field(key: "delivered") var delivered: Int
    /// The runner that is delivering the current batch (compare-and-swap claim, platform gate L5) and when its lease ends (Unix seconds).
    /// A runner that dies mid-batch loses the claim at expiry and another picks the batch up.
    @OptionalField(key: "claim_token") var claimToken: String?
    @OptionalField(key: "claim_expires_at") var claimExpiresAt: Int?

    init() {}
}

final class DataRequestRecord: Model, @unchecked Sendable {
    static let schema = "data_requests"
    @ID(key: .id) var id: UUID?
    @Field(key: "business_id") var businessId: UUID
    /// `export` or `delete`.
    @Field(key: "kind") var kind: String
    /// `requested`, `ready` (export built), `completed`, `rejected`, `expired`.
    @Field(key: "status") var status: String
    @Field(key: "requested_by") var requestedBy: UUID
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "decided_by") var decidedBy: String?
    @OptionalField(key: "decided_at") var decidedAt: Date?
    @OptionalField(key: "note") var note: String?
    /// Sealed export document (row-bound); erased after the download window.
    @OptionalField(key: "artifact") var artifact: String?
    @OptionalField(key: "artifact_expires_at") var artifactExpiresAt: Date?
    @OptionalField(key: "downloaded_at") var downloadedAt: Date?
    @OptionalField(key: "completed_at") var completedAt: Date?

    init() {}
}

/// An operator switch: maintenance mode, sign-up stops, webhook pause, messaging restriction, abuse thresholds. One row per
/// (flag, scope); history is in the audit chain. See `PlatformFlag`.
final class PlatformFlagRecord: Model, @unchecked Sendable {
    static let schema = "platform_flags"
    @ID(key: .id) var id: UUID?
    @Field(key: "flag") var flag: String
    @Field(key: "scope") var scope: String
    @Field(key: "value") var value: String
    @Field(key: "reason") var reason: String
    @Field(key: "updated_by") var updatedBy: String
    @Field(key: "updated_at") var updatedAt: Date

    init() {}
}

final class RetentionSettingRecord: Model, @unchecked Sendable {
    static let schema = "retention_settings"
    @ID(key: .id) var id: UUID?
    /// `global` or a business id.
    @Field(key: "scope") var scope: String
    @Field(key: "data_class") var dataClass: String
    @Field(key: "days") var days: Int
    @Field(key: "updated_by") var updatedBy: String
    @Field(key: "updated_at") var updatedAt: Date

    init() {}
}

final class LegalHoldRecord: Model, @unchecked Sendable {
    static let schema = "legal_holds"
    @ID(key: .id) var id: UUID?
    /// `global`, `business` or `consumer`.
    @Field(key: "scope_kind") var scopeKind: String
    @OptionalField(key: "scope_id") var scopeId: String?
    @Field(key: "reason") var reason: String
    @Field(key: "created_by") var createdBy: String
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "released_at") var releasedAt: Date?
    @OptionalField(key: "released_by") var releasedBy: String?

    init() {}
}

final class ConsumerExportRecord: Model, @unchecked Sendable {
    static let schema = "consumer_exports"
    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "device_id") var deviceId: UUID
    /// `queued`, `ready` or `expired`.
    @Field(key: "status") var status: String
    /// The device's P-256 agreement public key (base64url, X9.63): the only key the export is sealed to.
    @Field(key: "recipient_key") var recipientKey: String
    /// JSON array of `E2EEEnvelope` (base64url), each sealed to `recipient_key`. The server holds no key that opens them.
    @OptionalField(key: "bundle") var bundle: String?
    @Field(key: "created_at") var createdAt: Date
    @OptionalField(key: "ready_at") var readyAt: Date?
    @Field(key: "expires_at") var expiresAt: Date
    @Field(key: "downloads") var downloads: Int

    init() {}
}

final class AccountFreezeRecord: Model, @unchecked Sendable {
    static let schema = "account_freezes"
    @ID(key: .id) var id: UUID?
    @Field(key: "consumer_id") var consumerId: UUID
    @Field(key: "reason") var reason: String
    @Field(key: "frozen_by") var frozenBy: String
    @Field(key: "frozen_at") var frozenAt: Date
    @OptionalField(key: "released_at") var releasedAt: Date?
    @OptionalField(key: "released_by") var releasedBy: String?

    init() {}
}
