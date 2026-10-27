import Foundation

/// Business request to issue an interaction. The server fills id, businessId (from the API key),
/// scope, challenge and timestamps, then validates with `InteractionValidation`.
///
/// Wire: same `kind` + `payload` convention as `Interaction`.
public struct IssueInteractionRequest: Codable, Sendable, Hashable {
    public var relationshipId: RelationshipID
    public var kind: InteractionKind
    public var purpose: InteractionPurpose
    public var payload: InteractionPayload
    public var requestedActions: [RequestedAction]
    public var priority: InteractionPriority
    public var sensitivity: Sensitivity
    public var allowedChannels: [Channel]
    /// Lifetime in seconds (1…`InteractionValidation.Limits.maxLifetime`).
    public var ttlSeconds: Int
    public var idempotencyKey: String
    public var correlationId: String?
    public var accountReference: String?

    public init(relationshipId: RelationshipID, purpose: InteractionPurpose, payload: InteractionPayload,
                requestedActions: [RequestedAction] = [], priority: InteractionPriority = .normal, sensitivity: Sensitivity = .standard,
                allowedChannels: [Channel] = [.nativePush, .inApp], ttlSeconds: Int, idempotencyKey: String,
                correlationId: String? = nil, accountReference: String? = nil) {
        self.relationshipId = relationshipId
        self.kind = payload.kind ?? .unknown("unknown")
        self.purpose = purpose
        self.payload = payload
        self.requestedActions = requestedActions
        self.priority = priority
        self.sensitivity = sensitivity
        self.allowedChannels = allowedChannels
        self.ttlSeconds = ttlSeconds
        self.idempotencyKey = idempotencyKey
        self.correlationId = correlationId
        self.accountReference = accountReference
    }

    enum CodingKeys: String, CodingKey {
        case relationshipId, kind, purpose, payload, requestedActions, priority, sensitivity, allowedChannels
        case ttlSeconds, idempotencyKey, correlationId, accountReference
    }

    public init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        relationshipId = try c.decode(RelationshipID.self, forKey: .relationshipId)
        kind = try c.decode(InteractionKind.self, forKey: .kind)
        purpose = try c.decode(InteractionPurpose.self, forKey: .purpose)
        payload = try InteractionPayload.decode(kind: kind, from: c, forKey: .payload)
        requestedActions = try c.decodeIfPresent([RequestedAction].self, forKey: .requestedActions) ?? []
        priority = try c.decodeIfPresent(InteractionPriority.self, forKey: .priority) ?? .normal
        sensitivity = try c.decodeIfPresent(Sensitivity.self, forKey: .sensitivity) ?? .standard
        allowedChannels = try c.decodeIfPresent([Channel].self, forKey: .allowedChannels) ?? [.nativePush, .inApp]
        ttlSeconds = try c.decode(Int.self, forKey: .ttlSeconds)
        idempotencyKey = try c.decode(String.self, forKey: .idempotencyKey)
        correlationId = try c.decodeIfPresent(String.self, forKey: .correlationId)
        accountReference = try c.decodeIfPresent(String.self, forKey: .accountReference)
    }

    public func encode(to encoder: any Encoder) throws {
        var c = encoder.container(keyedBy: CodingKeys.self)
        try c.encode(relationshipId, forKey: .relationshipId)
        try c.encode(kind, forKey: .kind)
        try c.encode(purpose, forKey: .purpose)
        try payload.encode(to: &c, forKey: .payload)
        try c.encode(requestedActions, forKey: .requestedActions)
        try c.encode(priority, forKey: .priority)
        try c.encode(sensitivity, forKey: .sensitivity)
        try c.encode(allowedChannels, forKey: .allowedChannels)
        try c.encode(ttlSeconds, forKey: .ttlSeconds)
        try c.encode(idempotencyKey, forKey: .idempotencyKey)
        try c.encodeIfPresent(correlationId, forKey: .correlationId)
        try c.encodeIfPresent(accountReference, forKey: .accountReference)
    }

    /// Materializes the interaction (server side).
    public func makeInteraction(id: InteractionID = InteractionID(), businessId: BusinessID, consumerId: ConsumerID, now: Date,
                                challenge: ChallengeNonce = .generate()) -> Interaction {
        Interaction(id: id, businessId: businessId,
                    scope: RelationshipScope(consumerId: consumerId, relationshipId: relationshipId, accountReference: accountReference),
                    purpose: purpose, payload: payload, requestedActions: requestedActions, priority: priority,
                    sensitivity: sensitivity, allowedChannels: allowedChannels, createdAt: now,
                    expiresAt: now.addingTimeInterval(TimeInterval(ttlSeconds)), idempotencyKey: idempotencyKey,
                    correlationId: correlationId, challenge: challenge, kind: kind)
    }
}

public struct BusinessSendMessageRequest: Codable, Sendable, Hashable {
    public var relationshipId: RelationshipID
    /// Reply within an existing session; `nil` starts/uses the current one.
    public var sessionId: SessionID?
    public var body: String
    public var agentName: String?
    public var idempotencyKey: String
    public init(relationshipId: RelationshipID, sessionId: SessionID? = nil, body: String, agentName: String? = nil, idempotencyKey: String) {
        self.relationshipId = relationshipId
        self.sessionId = sessionId
        self.body = body
        self.agentName = agentName
        self.idempotencyKey = idempotencyKey
    }
}

public struct BusinessStatusUpdateRequest: Codable, Sendable, Hashable {
    public var relationshipId: RelationshipID
    public var purpose: InteractionPurpose
    public var status: StatusPayload
    /// Stable key for the ongoing event (e.g. order id) so updates replace earlier ones.
    public var activityKey: String
    public var idempotencyKey: String
    /// Groups this status with the ticket and confirm interactions of the same order, trip or appointment, so the app
    /// shows them as one Activity row. Optional; absent from older senders.
    public var correlationId: String?
    public init(relationshipId: RelationshipID, purpose: InteractionPurpose, status: StatusPayload, activityKey: String,
                idempotencyKey: String, correlationId: String? = nil) {
        self.relationshipId = relationshipId
        self.purpose = purpose
        self.status = status
        self.activityKey = activityKey
        self.idempotencyKey = idempotencyKey
        self.correlationId = correlationId
    }
}

/// Creates a reward. With `relationshipId` the reward is issued to that one connected consumer; without it the reward
/// is part of the business's program and is offered to every consumer connected to the business (the server decides
/// per consumer whether it is eligible).
public struct IssueRewardRequest: Codable, Sendable, Hashable {
    public var relationshipId: RelationshipID?
    public var title: String
    /// `coupon` and `offer` are claimed before use; `perk` and `pointsReward` are redeemed directly. Defaults to `perk`.
    public var kind: RewardKind?
    public var details: String?
    public var validFrom: Date?
    public var validUntil: Date?
    public var recurrence: RewardRecurrence?
    /// Points a `pointsReward` costs; required for that kind and ignored for the others.
    public var pointsCost: Int?
    public var issueWalletPass: Bool
    public var idempotencyKey: String
    public init(relationshipId: RelationshipID? = nil, title: String, kind: RewardKind? = nil, details: String? = nil,
                validFrom: Date? = nil, validUntil: Date? = nil, recurrence: RewardRecurrence? = nil, pointsCost: Int? = nil,
                issueWalletPass: Bool = false, idempotencyKey: String) {
        self.relationshipId = relationshipId
        self.title = title
        self.kind = kind
        self.details = details
        self.validFrom = validFrom
        self.validUntil = validUntil
        self.recurrence = recurrence
        self.pointsCost = pointsCost
        self.issueWalletPass = issueWalletPass
        self.idempotencyKey = idempotencyKey
    }
}

/// A named status level reached at `minimumPoints`.
public struct LoyaltyTier: Codable, Sendable, Hashable {
    public var name: String
    public var minimumPoints: Int
    public init(name: String, minimumPoints: Int) {
        self.name = name
        self.minimumPoints = minimumPoints
    }
}

/// `PUT /v1/business/loyalty/program`: creates or replaces the business's loyalty program.
public struct UpsertLoyaltyProgramRequest: Codable, Sendable, Hashable {
    public var programName: String
    public var summary: String
    /// Version string members accept when joining; changing it makes older enroll calls fail with 409.
    public var termsVersion: String
    /// IANA time zone of the business. Rewards without their own recurrence zone use it for day boundaries.
    public var timeZone: String
    public var tiers: [LoyaltyTier]
    public init(programName: String, summary: String, termsVersion: String, timeZone: String, tiers: [LoyaltyTier] = []) {
        self.programName = programName
        self.summary = summary
        self.termsVersion = termsVersion
        self.timeZone = timeZone
        self.tiers = tiers
    }
}

public struct BusinessLoyaltyProgram: Codable, Sendable, Hashable {
    public var programName: String
    public var summary: String
    public var termsVersion: String
    public var timeZone: String
    public var tiers: [LoyaltyTier]
    public var memberCount: Int
    public var updatedAt: Date
    public init(programName: String, summary: String, termsVersion: String, timeZone: String, tiers: [LoyaltyTier], memberCount: Int, updatedAt: Date) {
        self.programName = programName
        self.summary = summary
        self.termsVersion = termsVersion
        self.timeZone = timeZone
        self.tiers = tiers
        self.memberCount = memberCount
        self.updatedAt = updatedAt
    }
}

/// `POST /v1/business/loyalty/points`: adds or removes points for an enrolled member. Idempotent per key.
public struct AdjustLoyaltyPointsRequest: Codable, Sendable, Hashable {
    public var relationshipId: RelationshipID
    /// Non-zero, at most 1,000,000 in magnitude. A balance never goes below zero.
    public var delta: Int
    /// A short machine-readable reason such as `purchase` or `goodwill` (≤ 40).
    public var reason: String?
    public var idempotencyKey: String
    public init(relationshipId: RelationshipID, delta: Int, reason: String? = nil, idempotencyKey: String) {
        self.relationshipId = relationshipId
        self.delta = delta
        self.reason = reason
        self.idempotencyKey = idempotencyKey
    }
}

public struct LoyaltyPointsResult: Codable, Sendable, Hashable {
    public var relationshipId: RelationshipID
    public var pointsBalance: Int
    public var statusName: String?
    /// False when this call replayed an earlier request with the same idempotency key.
    public var applied: Bool
    public init(relationshipId: RelationshipID, pointsBalance: Int, statusName: String? = nil, applied: Bool = true) {
        self.relationshipId = relationshipId
        self.pointsBalance = pointsBalance
        self.statusName = statusName
        self.applied = applied
    }
}

/// `POST /v1/business/redemptions/consume`: validates a customer's redemption code and consumes it in one atomic step.
public struct ConsumeRedemptionRequest: Codable, Sendable, Hashable {
    /// The code the customer shows (`XXXXX-XXXXX`; case, dashes and spaces are ignored).
    public var code: String
    /// Optional till or store identifier, recorded with the redemption.
    public var locationCode: String?
    public init(code: String, locationCode: String? = nil) {
        self.code = code
        self.locationCode = locationCode
    }
}

/// What the business learns when a code is consumed. The consumer appears only as the per-business pseudonym.
public struct RedemptionReceipt: Codable, Sendable, Hashable {
    public var redemptionId: RedemptionID
    public var rewardId: RewardID
    public var rewardTitle: String
    public var kind: RewardKind
    public var consumerReference: ConsumerID
    public var redeemedAt: Date
    public var pointsSpent: Int?
    public var locationCode: String?
    public init(redemptionId: RedemptionID, rewardId: RewardID, rewardTitle: String, kind: RewardKind, consumerReference: ConsumerID,
                redeemedAt: Date, pointsSpent: Int? = nil, locationCode: String? = nil) {
        self.redemptionId = redemptionId
        self.rewardId = rewardId
        self.rewardTitle = rewardTitle
        self.kind = kind
        self.consumerReference = consumerReference
        self.redeemedAt = redeemedAt
        self.pointsSpent = pointsSpent
        self.locationCode = locationCode
    }
}

// MARK: - Webhooks

/// Webhook event types (open set).
public struct WebhookEventType: RawRepresentable, Hashable, Sendable, Codable {
    public let rawValue: String
    public init(rawValue: String) { self.rawValue = rawValue }

    public static let interactionDecided = WebhookEventType(rawValue: "interaction.decided")
    public static let interactionExpired = WebhookEventType(rawValue: "interaction.expired")
    public static let interactionCancelled = WebhookEventType(rawValue: "interaction.cancelled")
    public static let messageReceived = WebhookEventType(rawValue: "message.received")
    public static let relationshipConnected = WebhookEventType(rawValue: "relationship.connected")
    public static let relationshipDisconnected = WebhookEventType(rawValue: "relationship.disconnected")
    public static let consentUpdated = WebhookEventType(rawValue: "consent.updated")
    public static let rewardRedeemed = WebhookEventType(rawValue: "reward.redeemed")
}

public struct WebhookSubscription: Codable, Sendable, Hashable, Identifiable {
    public var id: WebhookSubscriptionID
    /// HTTPS only.
    public var url: URL
    public var events: [WebhookEventType]
    public var active: Bool
    public var createdAt: Date
    public init(id: WebhookSubscriptionID, url: URL, events: [WebhookEventType], active: Bool, createdAt: Date) {
        self.id = id
        self.url = url
        self.events = events
        self.active = active
        self.createdAt = createdAt
    }
}

public struct CreateWebhookRequest: Codable, Sendable, Hashable {
    public var url: URL
    public var events: [WebhookEventType]
    public init(url: URL, events: [WebhookEventType]) {
        self.url = url
        self.events = events
    }
}

/// Returned once on create/rotate: the only time the secret is shown.
public struct WebhookSecretResponse: Codable, Sendable, Hashable {
    public var subscription: WebhookSubscription
    public var secret: String
    public init(subscription: WebhookSubscription, secret: String) {
        self.subscription = subscription
        self.secret = secret
    }
}

/// Body of every webhook delivery: `{"id","type","createdAt","businessId","data":{…}}`, signed per `WebhookSignature`.
public struct WebhookEvent: Codable, Sendable, Hashable {
    public var id: WebhookDeliveryID
    public var type: WebhookEventType
    public var createdAt: Date
    public var businessId: BusinessID
    public var apiVersion: String
    public var data: JSONValue

    public init(id: WebhookDeliveryID = WebhookDeliveryID(), type: WebhookEventType, createdAt: Date, businessId: BusinessID,
                apiVersion: String = "2026-10-27", data: JSONValue) {
        self.id = id
        self.type = type
        self.createdAt = createdAt
        self.businessId = businessId
        self.apiVersion = apiVersion
        self.data = data
    }

    /// Builds an event whose `data` is any encodable value (via `ViadereJSON`).
    public init<T: Encodable>(type: WebhookEventType, createdAt: Date, businessId: BusinessID, payload: T) throws {
        let data = try ViadereJSON.decode(JSONValue.self, from: ViadereJSON.encode(payload))
        self.init(type: type, createdAt: createdAt, businessId: businessId, data: data)
    }

    /// Decodes `data` into a typed value.
    public func decodeData<T: Decodable>(_ type: T.Type) throws -> T {
        try ViadereJSON.decode(type, from: ViadereJSON.encode(data))
    }
}
