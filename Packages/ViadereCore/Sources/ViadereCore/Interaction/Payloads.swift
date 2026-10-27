import Foundation

/// `authenticate`: a login / MFA challenge.
public struct AuthenticatePayload: Codable, Sendable, Hashable {
    /// What is being signed into, e.g. "Online Banking" (≤ 80).
    public var service: String
    /// Device / browser description, e.g. "Chrome on macOS" (≤ 80).
    public var device: String
    /// Approximate location text supplied by the business, e.g. "Mesa, AZ" (≤ 80).
    public var approximateLocation: String?
    /// Region derived from the requesting IP, e.g. "Arizona, US" (≤ 80).
    public var ipRegion: String?
    /// When the sign-in attempt happened.
    public var attemptedAt: Date
    public var riskIndicators: [RiskIndicator]

    public init(service: String, device: String, approximateLocation: String? = nil, ipRegion: String? = nil,
                attemptedAt: Date, riskIndicators: [RiskIndicator] = []) {
        self.service = service
        self.device = device
        self.approximateLocation = approximateLocation
        self.ipRegion = ipRegion
        self.attemptedAt = attemptedAt
        self.riskIndicators = riskIndicators
    }
}

/// `authorize`: purchase, transfer, account change, or other high-impact request.
public struct AuthorizePayload: Codable, Sendable, Hashable {
    /// Description of the action, e.g. "Card purchase" (≤ 120).
    public var actionDescription: String
    public var amount: MoneyAmount?
    /// Merchant / requester, e.g. "Walmart" (≤ 80).
    public var merchant: String?
    /// Location text, e.g. "in or near Mesa, Arizona" (≤ 80).
    public var location: String?
    /// What approving does, e.g. "The purchase will go through." (≤ 160).
    public var effectOfApproval: String?
    public var riskIndicators: [RiskIndicator]

    public init(actionDescription: String, amount: MoneyAmount? = nil, merchant: String? = nil, location: String? = nil,
                effectOfApproval: String? = nil, riskIndicators: [RiskIndicator] = []) {
        self.actionDescription = actionDescription
        self.amount = amount
        self.merchant = merchant
        self.location = location
        self.effectOfApproval = effectOfApproval
        self.riskIndicators = riskIndicators
    }
}

/// `confirm`: booking, pickup, reservation, order confirmation.
public struct ConfirmPayload: Codable, Sendable, Hashable {
    public var title: String
    public var details: String?
    /// Business reference, e.g. a booking number (≤ 64).
    public var reference: String?
    public var scheduledAt: Date?

    public init(title: String, details: String? = nil, reference: String? = nil, scheduledAt: Date? = nil) {
        self.title = title
        self.details = details
        self.reference = reference
        self.scheduledAt = scheduledAt
    }
}

/// One option of a `choose` interaction.
public struct ChoiceOption: Codable, Sendable, Hashable {
    /// Stable identifier (≤ 64, `[A-Za-z0-9_.-]`).
    public var id: String
    /// Label (≤ 40).
    public var label: String

    public init(id: String, label: String) {
        self.id = id
        self.label = label
    }
}

/// `choose`: select one or more options.
public struct ChoosePayload: Codable, Sendable, Hashable {
    public var prompt: String
    /// 2–10 options.
    public var options: [ChoiceOption]
    public var allowsMultiple: Bool

    public init(prompt: String, options: [ChoiceOption], allowsMultiple: Bool = false) {
        self.prompt = prompt
        self.options = options
        self.allowsMultiple = allowsMultiple
    }
}

/// `acknowledge`: receipt / policy / estimate acknowledgment (not a legal e-signature).
public struct AcknowledgePayload: Codable, Sendable, Hashable {
    public var title: String
    public var body: String
    public var documentURL: URL?
    public var documentVersion: String?

    public init(title: String, body: String, documentURL: URL? = nil, documentVersion: String? = nil) {
        self.title = title
        self.body = body
        self.documentURL = documentURL
        self.documentVersion = documentVersion
    }
}

/// `reply`: a short free-text answer.
public struct ReplyPayload: Codable, Sendable, Hashable {
    public var prompt: String
    /// Maximum reply length (1–1000).
    public var maxLength: Int
    public var suggestedReplies: [String]

    public init(prompt: String, maxLength: Int = 280, suggestedReplies: [String] = []) {
        self.prompt = prompt
        self.maxLength = maxLength
        self.suggestedReplies = suggestedReplies
    }
}

/// `status`: progress / event update; may drive a Live Activity.
public struct StatusPayload: Codable, Sendable, Hashable {
    public var title: String
    public var body: String?
    public var liveActivity: LiveActivityStatus?

    public init(title: String, body: String? = nil, liveActivity: LiveActivityStatus? = nil) {
        self.title = title
        self.body = body
        self.liveActivity = liveActivity
    }
}

/// `reward`: loyalty, offer, redemption, benefit.
public struct RewardPayload: Codable, Sendable, Hashable {
    public var rewardId: RewardID
    public var title: String
    public var details: String?
    public var redeemBy: Date?
    public var walletPassId: WalletPassID?

    public init(rewardId: RewardID, title: String, details: String? = nil, redeemBy: Date? = nil, walletPassId: WalletPassID? = nil) {
        self.rewardId = rewardId
        self.title = title
        self.details = details
        self.redeemBy = redeemBy
        self.walletPassId = walletPassId
    }
}

/// `ticket`: ticket, pass, admission, travel document.
public struct TicketPayload: Codable, Sendable, Hashable {
    public var title: String
    /// e.g. "boarding_pass", "event", "admission" (≤ 40).
    public var ticketType: String
    public var holderName: String?
    public var validFrom: Date?
    public var validUntil: Date?
    public var walletPassId: WalletPassID?

    public init(title: String, ticketType: String, holderName: String? = nil, validFrom: Date? = nil,
                validUntil: Date? = nil, walletPassId: WalletPassID? = nil) {
        self.title = title
        self.ticketType = ticketType
        self.holderName = holderName
        self.validFrom = validFrom
        self.validUntil = validUntil
        self.walletPassId = walletPassId
    }
}

/// `message`: conversation / customer support text.
public struct MessagePayload: Codable, Sendable, Hashable {
    public var text: String
    public var sessionId: SessionID?

    public init(text: String, sessionId: SessionID? = nil) {
        self.text = text
        self.sessionId = sessionId
    }
}

/// Typed payload; the case must match `Interaction.kind`.
public enum InteractionPayload: Sendable, Hashable {
    case authenticate(AuthenticatePayload)
    case authorize(AuthorizePayload)
    case confirm(ConfirmPayload)
    case choose(ChoosePayload)
    case acknowledge(AcknowledgePayload)
    case reply(ReplyPayload)
    case status(StatusPayload)
    case reward(RewardPayload)
    case ticket(TicketPayload)
    case message(MessagePayload)
    /// Payload of an unknown kind, preserved verbatim.
    case unknown(JSONValue)

    /// The kind this payload belongs to (`nil` for `.unknown`).
    public var kind: InteractionKind? {
        switch self {
        case .authenticate: .authenticate
        case .authorize: .authorize
        case .confirm: .confirm
        case .choose: .choose
        case .acknowledge: .acknowledge
        case .reply: .reply
        case .status: .status
        case .reward: .reward
        case .ticket: .ticket
        case .message: .message
        case .unknown: nil
        }
    }

    func encode<K: CodingKey>(to container: inout KeyedEncodingContainer<K>, forKey key: K) throws {
        switch self {
        case .authenticate(let p): try container.encode(p, forKey: key)
        case .authorize(let p): try container.encode(p, forKey: key)
        case .confirm(let p): try container.encode(p, forKey: key)
        case .choose(let p): try container.encode(p, forKey: key)
        case .acknowledge(let p): try container.encode(p, forKey: key)
        case .reply(let p): try container.encode(p, forKey: key)
        case .status(let p): try container.encode(p, forKey: key)
        case .reward(let p): try container.encode(p, forKey: key)
        case .ticket(let p): try container.encode(p, forKey: key)
        case .message(let p): try container.encode(p, forKey: key)
        case .unknown(let v): try container.encode(v, forKey: key)
        }
    }

    static func decode<K: CodingKey>(kind: InteractionKind, from container: KeyedDecodingContainer<K>, forKey key: K) throws -> InteractionPayload {
        switch kind {
        case .authenticate: return .authenticate(try container.decode(AuthenticatePayload.self, forKey: key))
        case .authorize: return .authorize(try container.decode(AuthorizePayload.self, forKey: key))
        case .confirm: return .confirm(try container.decode(ConfirmPayload.self, forKey: key))
        case .choose: return .choose(try container.decode(ChoosePayload.self, forKey: key))
        case .acknowledge: return .acknowledge(try container.decode(AcknowledgePayload.self, forKey: key))
        case .reply: return .reply(try container.decode(ReplyPayload.self, forKey: key))
        case .status: return .status(try container.decode(StatusPayload.self, forKey: key))
        case .reward: return .reward(try container.decode(RewardPayload.self, forKey: key))
        case .ticket: return .ticket(try container.decode(TicketPayload.self, forKey: key))
        case .message: return .message(try container.decode(MessagePayload.self, forKey: key))
        case .unknown: return .unknown(try container.decodeIfPresent(JSONValue.self, forKey: key) ?? .null)
        }
    }
}
