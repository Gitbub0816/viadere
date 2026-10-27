import Foundation

// MARK: - P3 wire types: rewards, loyalty, Wallet, household and acknowledgments
//
// Shared by the server and the iOS app. Eligibility is computed ONLY by the server; clients display it.

// MARK: - Eligibility (computed by the server, only displayed by the client)

/// The server's verdict on a reward at `checkedAt`. The client never derives eligibility from `RewardRecurrence`,
/// the device clock or the points balance: it shows this state and offers `nextAction` only when the server says so.
public struct RewardEligibility: Codable, Sendable, Hashable {
    public enum State: String, Codable, Sendable, CaseIterable {
        /// Can be claimed or redeemed right now.
        case eligible
        /// A recurring reward on a day it doesn't apply (for example "free coffee on Tuesdays").
        case notToday
        /// The per-day (or per-period) limit has been used.
        case limitReached
        case notYetValid
        case insufficientPoints
        case redeemed
        case expired
        case revoked
        /// Anything the server declines for a reason this version doesn't know.
        case unavailable

        public init(from decoder: any Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self = State(rawValue: raw) ?? .unavailable
        }
    }

    /// What the single primary button does. `none` means no button.
    public enum Action: String, Codable, Sendable {
        /// Save the offer to the account (and optionally Wallet).
        case claim
        /// Ask the server for a short-lived redemption code.
        case redeem
        case none

        public init(from decoder: any Decoder) throws {
            let raw = try decoder.singleValueContainer().decode(String.self)
            self = Action(rawValue: raw) ?? .none
        }
    }

    public var state: State
    public var nextAction: Action
    /// Server time when this was evaluated.
    public var checkedAt: Date
    /// When it next becomes eligible (recurring rewards, validity start), server-computed.
    public var nextEligibleAt: Date?
    /// Points still needed for `.insufficientPoints`.
    public var pointsShortfall: Int?

    public init(state: State, nextAction: Action = .none, checkedAt: Date, nextEligibleAt: Date? = nil, pointsShortfall: Int? = nil) {
        self.state = state
        self.nextAction = nextAction
        self.checkedAt = checkedAt
        self.nextEligibleAt = nextEligibleAt
        self.pointsShortfall = pointsShortfall
    }
}

public enum RewardKind: String, Codable, Sendable, CaseIterable {
    case coupon, perk, offer, pointsReward

    public init(from decoder: any Decoder) throws {
        let raw = try decoder.singleValueContainer().decode(String.self)
        self = RewardKind(rawValue: raw) ?? .perk
    }
}

/// A reward plus the server's eligibility verdict.
public struct RewardEntry: Codable, Sendable, Hashable, Identifiable {
    public var reward: Reward
    public var kind: RewardKind
    public var eligibility: RewardEligibility
    /// Points this costs, for `pointsReward`.
    public var pointsCost: Int?
    public var claimedAt: Date?

    public var id: RewardID { reward.id }
    public var business: BusinessSummary { reward.business }

    public init(reward: Reward, kind: RewardKind, eligibility: RewardEligibility, pointsCost: Int? = nil, claimedAt: Date? = nil) {
        self.reward = reward
        self.kind = kind
        self.eligibility = eligibility
        self.pointsCost = pointsCost
        self.claimedAt = claimedAt
    }
}

/// A loyalty membership at one business: points, status, and (when issued) the Wallet card.
public struct LoyaltyAccount: Codable, Sendable, Hashable, Identifiable {
    public var business: BusinessSummary
    public var programName: String
    public var pointsBalance: Int
    /// e.g. "Silver".
    public var statusName: String?
    public var nextStatusName: String?
    public var pointsToNextStatus: Int?
    public var memberSince: Date
    /// Masked business-side member number, e.g. "••4821".
    public var memberReference: String?
    public var walletPass: WalletPassMetadata?

    public var id: BusinessID { business.id }

    public init(business: BusinessSummary, programName: String, pointsBalance: Int, statusName: String? = nil,
                nextStatusName: String? = nil, pointsToNextStatus: Int? = nil, memberSince: Date,
                memberReference: String? = nil, walletPass: WalletPassMetadata? = nil) {
        self.business = business
        self.programName = programName
        self.pointsBalance = pointsBalance
        self.statusName = statusName
        self.nextStatusName = nextStatusName
        self.pointsToNextStatus = pointsToNextStatus
        self.memberSince = memberSince
        self.memberReference = memberReference
        self.walletPass = walletPass
    }
}

/// `GET /v1/rewards/overview`: everything the aggregated Rewards screen shows.
public struct RewardsOverview: Codable, Sendable, Hashable {
    public var accounts: [LoyaltyAccount]
    public var rewards: [RewardEntry]
    public init(accounts: [LoyaltyAccount] = [], rewards: [RewardEntry] = []) {
        self.accounts = accounts
        self.rewards = rewards
    }
}

/// What a business offers: the program terms, the person's membership if any, and its rewards.
public struct LoyaltyProgramOverview: Codable, Sendable, Hashable {
    public var programName: String
    /// One or two sentences describing how the program works.
    public var summary: String
    /// Version of the program terms the person accepts by joining.
    public var termsVersion: String
    public var account: LoyaltyAccount?
    public var rewards: [RewardEntry]
    public init(programName: String, summary: String, termsVersion: String, account: LoyaltyAccount? = nil, rewards: [RewardEntry] = []) {
        self.programName = programName
        self.summary = summary
        self.termsVersion = termsVersion
        self.account = account
        self.rewards = rewards
    }
}

/// Enroll in a program, optionally linking an existing business-side membership.
public struct LoyaltyEnrollRequest: Codable, Sendable, Hashable {
    /// Existing member number or phone/email the business uses to look the member up. Never logged.
    public var existingMemberReference: String?
    public var acceptedTermsVersion: String
    public init(existingMemberReference: String? = nil, acceptedTermsVersion: String) {
        self.existingMemberReference = existingMemberReference
        self.acceptedTermsVersion = acceptedTermsVersion
    }
}

/// Ask the server to issue (and sign) a Wallet pass. The app never signs or builds passes.
public struct WalletPassIssueRequest: Codable, Sendable, Hashable {
    public var kind: WalletPassKind
    public var businessId: BusinessID
    public var rewardId: RewardID?
    public var interactionId: InteractionID?
    public init(kind: WalletPassKind, businessId: BusinessID, rewardId: RewardID? = nil, interactionId: InteractionID? = nil) {
        self.kind = kind
        self.businessId = businessId
        self.rewardId = rewardId
        self.interactionId = interactionId
    }
}
