import Foundation
import ViadereCore

/// One side of a household grant with the other person's display name (server-resolved; grants only carry ids).
public struct HouseholdGrant: Codable, Sendable, Hashable, Identifiable {
    public enum Status: String, Codable, Sendable {
        case pending, active, expired, revoked
        public init(from decoder: any Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self = Status(rawValue: raw) ?? .expired
        }
    }

    public var grant: DelegationGrant
    /// The other person: the delegate for grants you gave, the grantor for grants you received.
    public var counterpartName: String
    public var businessNames: [String]
    /// Server-computed, so a stale device clock can't show an expired grant as active.
    public var status: Status

    public var id: DelegationID { grant.id }

    public init(grant: DelegationGrant, counterpartName: String, businessNames: [String], status: Status) {
        self.grant = grant
        self.counterpartName = counterpartName
        self.businessNames = businessNames
        self.status = status
    }
}

/// `GET /v1/household`
public struct HouseholdOverview: Codable, Sendable, Hashable {
    /// Grants you gave to others.
    public var given: [HouseholdGrant]
    /// Grants others gave you.
    public var received: [HouseholdGrant]
    public init(given: [HouseholdGrant] = [], received: [HouseholdGrant] = []) {
        self.given = given
        self.received = received
    }
}

/// Invite someone with a scoped, expiring grant. The grant only becomes active when the invitee accepts in their own
/// Viadere app, so no one ever needs to look up another person's account id.
public struct DelegationInvitationRequest: Codable, Sendable, Hashable {
    /// How the person is named in your lists, e.g. "Sam".
    public var delegateLabel: String
    public var role: DelegationGrant.Role
    public var purposes: [InteractionPurpose]
    public var businessIds: [BusinessID]
    /// When the *grant* ends.
    public var expiresAt: Date
    /// True when the scope includes security or account-service access. The server then requires `stepUp`.
    public var includesSensitiveScope: Bool
    /// A fresh Face ID / Touch ID signature over this exact scope from the device's `approvalBiometric` key.
    public var stepUp: DelegationStepUpProof?

    public init(delegateLabel: String, role: DelegationGrant.Role, purposes: [InteractionPurpose], businessIds: [BusinessID],
                expiresAt: Date, includesSensitiveScope: Bool, stepUp: DelegationStepUpProof? = nil) {
        self.delegateLabel = delegateLabel
        self.role = role
        self.purposes = purposes
        self.businessIds = businessIds
        self.expiresAt = expiresAt
        self.includesSensitiveScope = includesSensitiveScope
        self.stepUp = stepUp
    }
}

/// Server-verifiable proof that the owner passed biometrics for exactly this delegation scope.
///
/// `signature` = base64url raw r||s ECDSA-P256-SHA256 by the device's `approvalBiometric` key over the UTF-8 of
/// `"VIADERE-DELEGATION-STEPUP-V1\n" + deviceId + "\n" + signedAt(ISO-8601 ms, UTC) + "\n" + scopeDigest`.
/// `scopeDigest` = lowercase hex SHA-256 of `DelegationScopePolicy.canonicalScope(of:)`. The server recomputes the
/// digest from the request, verifies the signature, and requires `signedAt` within 5 minutes.
public struct DelegationStepUpProof: Codable, Sendable, Hashable {
    public var deviceId: DeviceID
    public var signedAt: Date
    public var scopeDigest: String
    public var signature: String

    public init(deviceId: DeviceID, signedAt: Date, scopeDigest: String, signature: String) {
        self.deviceId = deviceId
        self.signedAt = signedAt
        self.scopeDigest = scopeDigest
        self.signature = signature
    }

    public static let domain = "VIADERE-DELEGATION-STEPUP-V1\n"

    public func signingInput() -> Data {
        Data((Self.domain + deviceId.description + "\n" + ViadereDate.format(signedAt) + "\n" + scopeDigest).utf8)
    }
}

/// The invitation the inviter shares (out of band) with the invitee. Single use, short lived.
public struct DelegationInvitation: Codable, Sendable, Hashable, Identifiable {
    public var id: DelegationID
    /// Short single-use code (for example `K7M2-9QXP`); never reused, never shown in logs.
    public var code: String
    /// When the *invitation* (not the grant) stops working.
    public var inviteExpiresAt: Date
    public init(id: DelegationID, code: String, inviteExpiresAt: Date) {
        self.id = id
        self.code = code
        self.inviteExpiresAt = inviteExpiresAt
    }
}

public struct DelegationInvitationRedeemRequest: Codable, Sendable, Hashable {
    public var code: String
    public init(code: String) { self.code = code }
}

/// What the invitee sees before accepting.
public struct DelegationInvitationPreview: Codable, Sendable, Hashable {
    public var grantorName: String
    public var role: DelegationGrant.Role
    public var purposes: [InteractionPurpose]
    public var businessNames: [String]
    public var expiresAt: Date
    public init(grantorName: String, role: DelegationGrant.Role, purposes: [InteractionPurpose], businessNames: [String], expiresAt: Date) {
        self.grantorName = grantorName
        self.role = role
        self.purposes = purposes
        self.businessNames = businessNames
        self.expiresAt = expiresAt
    }
}

/// One line of the household audit trail (server-resolved names; metadata already redacted).
public struct HouseholdAuditEntry: Codable, Sendable, Hashable, Identifiable {
    public enum Outcome: String, Codable, Sendable {
        case success, denied
        public init(from decoder: any Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self = Outcome(rawValue: raw) ?? .denied
        }
    }

    public var id: AuditEventID
    public var occurredAt: Date
    /// Dotted action, e.g. `delegation.created`, `delegation.revoked`, `delegation.accepted`, `delegation.used`.
    public var action: String
    public var actorName: String
    public var businessName: String?
    public var outcome: Outcome
    /// Set when the action was taken on behalf of someone.
    public var onBehalfOfName: String?

    public init(id: AuditEventID = AuditEventID(), occurredAt: Date, action: String, actorName: String, businessName: String? = nil,
                outcome: Outcome = .success, onBehalfOfName: String? = nil) {
        self.id = id
        self.occurredAt = occurredAt
        self.action = action
        self.actorName = actorName
        self.businessName = businessName
        self.outcome = outcome
        self.onBehalfOfName = onBehalfOfName
    }
}
