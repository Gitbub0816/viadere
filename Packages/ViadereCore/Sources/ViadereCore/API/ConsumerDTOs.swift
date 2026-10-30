import Foundation

// MARK: - Directory

/// How a directory input resolved.
public enum ResolutionMethod: String, Codable, Sendable { case handle, code, link, name }

public struct DirectoryResolveRequest: Codable, Sendable, Hashable {
    /// Free input: `@handle`, code (`AF-2345`), connect link, or name (≤ 256).
    public var input: String
    public init(input: String) { self.input = input }
}

public struct DirectoryResolveResponse: Codable, Sendable, Hashable {
    public var method: ResolutionMethod
    /// Verified matches only. Exactly one for handle/code/link; possibly several for name.
    public var matches: [BusinessSummary]
    /// Verified link context, if a signed link was supplied.
    public var context: ConnectContext?
    public init(method: ResolutionMethod, matches: [BusinessSummary], context: ConnectContext? = nil) {
        self.method = method
        self.matches = matches
        self.context = context
    }
}

/// Client-side classification of directory input, mirroring the server's resolution order:
/// connect link → `@handle` → business code → name.
public enum DirectoryInput: Sendable, Hashable {
    case link(ConnectLink)
    case handle(BusinessHandle)
    case code(BusinessCode)
    case name(String)

    /// `domain`: the link domain a connect link must use (the server passes `ServerConfig.linkDomain`).
    public init(parsing input: String, domain: LinkDomain = .current) {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.lowercased().hasPrefix("https://"), let link = try? ConnectLink.parse(trimmed, domain: domain) {
            self = .link(link)
        } else if trimmed.hasPrefix("@"), let handle = BusinessHandle(parsing: trimmed) {
            self = .handle(handle)
        } else if let code = BusinessCode(parsing: trimmed), trimmed.contains(where: \.isNumber) {
            self = .code(code)
        } else {
            self = .name(String(trimmed.prefix(256)))
        }
    }
}

// MARK: - Relationships & consent

public struct ConnectRequest: Codable, Sendable, Hashable {
    public var businessId: BusinessID
    public var source: ConnectSource
    /// The connect link used, if any (server re-verifies its context).
    public var link: String?
    /// Opt-in purposes chosen at connect time (marketing/rewards are off unless listed).
    public var optInPurposes: [InteractionPurpose]
    public init(businessId: BusinessID, source: ConnectSource, link: String? = nil, optInPurposes: [InteractionPurpose] = []) {
        self.businessId = businessId
        self.source = source
        self.link = link
        self.optInPurposes = optInPurposes
    }
}

public struct ConsentChange: Codable, Sendable, Hashable {
    public var purpose: InteractionPurpose
    public var granted: Bool
    public init(purpose: InteractionPurpose, granted: Bool) {
        self.purpose = purpose
        self.granted = granted
    }
}

public struct ConsentUpdateRequest: Codable, Sendable, Hashable {
    public var changes: [ConsentChange]
    /// Version of the consent copy the user saw.
    public var policyVersion: String
    public init(changes: [ConsentChange], policyVersion: String) {
        self.changes = changes
        self.policyVersion = policyVersion
    }
}

// MARK: - Interactions

/// Lifecycle status of an interaction.
public enum InteractionStatus: String, Codable, Sendable, CaseIterable {
    case pending, approved, denied, confirmed, declined, selected, replied, acknowledged, reported, expired, cancelled, delivered

    public init(from decoder: any Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = InteractionStatus(rawValue: raw) ?? .pending
    }

    /// Final status for a decision.
    public init(decision: Decision) {
        switch decision {
        case .approve: self = .approved
        case .deny: self = .denied
        case .confirm: self = .confirmed
        case .decline: self = .declined
        case .select: self = .selected
        case .reply: self = .replied
        case .acknowledge: self = .acknowledged
        case .report: self = .reported
        }
    }

    public var isTerminal: Bool { self != .pending && self != .delivered }
}

/// An interaction as delivered to the consumer app.
public struct InteractionEnvelope: Codable, Sendable, Hashable, Identifiable {
    public var interaction: Interaction
    public var business: BusinessSummary
    public var status: InteractionStatus
    public var id: InteractionID { interaction.id }

    public init(interaction: Interaction, business: BusinessSummary, status: InteractionStatus) {
        self.interaction = interaction
        self.business = business
        self.status = status
    }
}

public struct DecideInteractionRequest: Codable, Sendable, Hashable {
    public var signedDecision: SignedDecision
    /// Channel the decision was made on (`nativePush` or `inApp`).
    public var channel: Channel
    public init(signedDecision: SignedDecision, channel: Channel) {
        self.signedDecision = signedDecision
        self.channel = channel
    }
}

/// The server's statement that a device-signed decision was verified. Businesses receive this instead of the raw signed
/// decision (which names the consumer's device): see `InteractionOutcome.verification`.
public struct DecisionVerification: Codable, Sendable, Hashable {
    /// Always `true` when present: signature, binding, freshness and assurance policy were checked.
    public var verified: Bool
    /// The key that signed (`approvalBiometric` = device-bound biometric).
    public var keyPurpose: DeviceKeyPurpose
    /// True when the decision carried a v2 `contextDigest` that matched the interaction.
    public var contextBound: Bool
    public var verifiedAt: Date
    /// Opaque reference to the stored signed decision, for disputes with Viadere (`HMAC(server secret, decision id)`).
    public var evidenceRef: String

    public init(verified: Bool = true, keyPurpose: DeviceKeyPurpose, contextBound: Bool, verifiedAt: Date, evidenceRef: String) {
        self.verified = verified
        self.keyPurpose = keyPurpose
        self.contextBound = contextBound
        self.verifiedAt = verifiedAt
        self.evidenceRef = evidenceRef
    }
}

/// The recorded outcome (returned to the app, the business API and webhooks).
///
/// **What a business receives.** A business never gets the device-signed decision: it names the consumer's global device id.
/// The business API and webhooks carry `deviceRef` (a per-business pseudonym of the device, stable for one business and
/// unlinkable across businesses) and `verification` (the server's attestation). The original signed decision stays on the
/// server for disputes (`ViadereServer export-dispute`). The consumer's own `POST .../decision` response still carries `signedDecision`.
public struct InteractionOutcome: Codable, Sendable, Hashable {
    public var interactionId: InteractionID
    public var businessId: BusinessID
    public var status: InteractionStatus
    public var decision: Decision?
    public var selectedOptionIds: [String]?
    public var reply: String?
    public var assurance: DecisionAssurance?
    public var channel: Channel?
    public var decidedAt: Date?
    public var correlationId: String?
    /// The device-signed decision. Present only in the consumer's own decision response; never sent to businesses.
    public var signedDecision: SignedDecision?
    /// Per-business pseudonym of the deciding device.
    public var deviceRef: String?
    /// The server's attestation that the decision was verified (device-signed decisions only).
    public var verification: DecisionVerification?

    public init(interactionId: InteractionID, businessId: BusinessID, status: InteractionStatus, decision: Decision? = nil,
                selectedOptionIds: [String]? = nil, reply: String? = nil, assurance: DecisionAssurance? = nil,
                channel: Channel? = nil, decidedAt: Date? = nil, correlationId: String? = nil, signedDecision: SignedDecision? = nil,
                deviceRef: String? = nil, verification: DecisionVerification? = nil) {
        self.interactionId = interactionId
        self.businessId = businessId
        self.status = status
        self.decision = decision
        self.selectedOptionIds = selectedOptionIds
        self.reply = reply
        self.assurance = assurance
        self.channel = channel
        self.decidedAt = decidedAt
        self.correlationId = correlationId
        self.signedDecision = signedDecision
        self.deviceRef = deviceRef
        self.verification = verification
    }
}

// MARK: - Conversations

public struct StartConversationRequest: Codable, Sendable, Hashable {
    public var businessId: BusinessID
    public init(businessId: BusinessID) { self.businessId = businessId }
}

public struct SendMessageRequest: Codable, Sendable, Hashable {
    /// ≤ 1600 characters.
    public var body: String
    /// Client-generated idempotency id.
    public var clientMessageId: String
    public init(body: String, clientMessageId: String) {
        self.body = body
        self.clientMessageId = clientMessageId
    }
}

// MARK: - Rewards

public struct RedeemRewardRequest: Codable, Sendable, Hashable {
    /// Optional store/location identifier supplied by the business QR at the counter.
    public var locationCode: String?
    public init(locationCode: String? = nil) { self.locationCode = locationCode }
}

public struct RewardRedemption: Codable, Sendable, Hashable {
    public var reward: Reward
    /// Short code the business validates (single-use). Shown on screen; never cached.
    public var redemptionCode: String
    public var expiresAt: Date
    /// Seconds the code stays valid, counted from `serverTime` (about 120). Absent from older servers.
    public var validForSeconds: Int?
    /// Server clock when the code was issued, so the countdown does not depend on the device clock.
    public var serverTime: Date?
    public init(reward: Reward, redemptionCode: String, expiresAt: Date, validForSeconds: Int? = nil, serverTime: Date? = nil) {
        self.reward = reward
        self.redemptionCode = redemptionCode
        self.expiresAt = expiresAt
        self.validForSeconds = validForSeconds
        self.serverTime = serverTime
    }
}

// MARK: - Delegation

public struct CreateDelegationRequest: Codable, Sendable, Hashable {
    public var delegateId: ConsumerID
    public var role: DelegationGrant.Role
    public var purposes: [InteractionPurpose]
    public var businessIds: [BusinessID]
    public var expiresAt: Date
    public init(delegateId: ConsumerID, role: DelegationGrant.Role, purposes: [InteractionPurpose], businessIds: [BusinessID], expiresAt: Date) {
        self.delegateId = delegateId
        self.role = role
        self.purposes = purposes
        self.businessIds = businessIds
        self.expiresAt = expiresAt
    }
}
