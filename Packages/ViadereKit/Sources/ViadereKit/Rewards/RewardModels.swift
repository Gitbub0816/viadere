import Foundation
import ViadereCore

// MARK: - Provisional P3 contract
//
// These DTOs and routes describe what the P3 screens need and ViadereCore's `APIRoutes` does not carry yet.
// Follow the `ProvisionalRoutes` convention: paths under `/v1`, `deviceSignedBearer`, and `404` means "not
// available yet" (the UI hides the feature). When the server lands them, promote the types into ViadereCore.

extension ProvisionalRoutes {
    // Rewards & loyalty
    public static let rewardsOverview = Endpoint<EmptyBody, RewardsOverview>(
        "rewards.overview", .GET, "/v1/rewards/overview", auth: .deviceSignedBearer)
    public static let loyaltyProgram = Endpoint<EmptyBody, LoyaltyProgramOverview>(
        "loyalty.program", .GET, "/v1/loyalty/{businessId}", auth: .deviceSignedBearer)
    public static let loyaltyEnroll = Endpoint<LoyaltyEnrollRequest, LoyaltyAccount>(
        "loyalty.enroll", .POST, "/v1/loyalty/{businessId}/enroll", auth: .deviceSignedBearer)
    public static let rewardClaim = Endpoint<EmptyBody, RewardEntry>(
        "rewards.claim", .POST, "/v1/rewards/{rewardId}/claim", auth: .deviceSignedBearer)

    // Wallet
    public static let walletPasses = Endpoint<EmptyBody, [WalletPassMetadata]>(
        "wallet.passes.list", .GET, "/v1/wallet/passes", auth: .deviceSignedBearer)
    public static let walletPassIssue = Endpoint<WalletPassIssueRequest, WalletPassMetadata>(
        "wallet.passes.issue", .POST, "/v1/wallet/passes", auth: .deviceSignedBearer)

    // Household (delegation) beyond Core's create/list/revoke
    public static let household = Endpoint<EmptyBody, HouseholdOverview>(
        "household.overview", .GET, "/v1/household", auth: .deviceSignedBearer)
    public static let householdInvite = Endpoint<DelegationInvitationRequest, DelegationInvitation>(
        "household.invitations.create", .POST, "/v1/household/invitations", auth: .deviceSignedBearer)
    public static let householdInvitationPreview = Endpoint<DelegationInvitationRedeemRequest, DelegationInvitationPreview>(
        "household.invitations.preview", .POST, "/v1/household/invitations/preview", auth: .deviceSignedBearer)
    public static let householdInvitationAccept = Endpoint<DelegationInvitationRedeemRequest, HouseholdGrant>(
        "household.invitations.accept", .POST, "/v1/household/invitations/accept", auth: .deviceSignedBearer)
    public static let householdAudit = Endpoint<EmptyBody, [HouseholdAuditEntry]>(
        "household.audit", .GET, "/v1/household/audit", auth: .deviceSignedBearer)

    // Acknowledgment records
    public static let acknowledgments = Endpoint<EmptyBody, [AcknowledgmentRecord]>(
        "acknowledgments.list", .GET, "/v1/acknowledgments", auth: .deviceSignedBearer)
}

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

// MARK: - Display copy (describes the rule; never decides eligibility)

public enum RewardCopy {
    /// "Every Tuesday", "Weekdays", "Mon, Wed and Fri". Describes the business's rule for the person to read.
    public static func recurrence(_ recurrence: RewardRecurrence) -> String {
        let days = Set(recurrence.weekdays.filter { (1...7).contains($0) }).sorted()
        guard !days.isEmpty else { return "" }
        let long = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        let short = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        let text: String
        if days == [1, 2, 3, 4, 5] {
            text = "Weekdays"
        } else if days == [6, 7] {
            text = "Weekends"
        } else if days.count == 7 {
            text = "Every day"
        } else if days.count == 1 {
            text = "Every \(long[days[0] - 1])"
        } else {
            let names = days.map { short[$0 - 1] }
            text = names.dropLast().joined(separator: ", ") + " and " + (names.last ?? "")
        }
        return recurrence.perDayLimit > 1 ? "\(text) · up to \(recurrence.perDayLimit) a day" : text
    }

    public static func points(_ value: Int) -> String {
        let formatted = value.formatted(.number.grouping(.automatic))
        return value == 1 ? "1 point" : "\(formatted) points"
    }
}

/// How one reward row reads: a status line and whether to offer the primary action.
public struct RewardRowPresentation: Equatable, Sendable {
    public enum Tone: Sendable, Equatable { case available, waiting, finished }

    public var statusLine: String
    public var tone: Tone
    /// The server's action when (and only when) the server says the reward is eligible and the check is fresh.
    public var action: RewardEligibility.Action
    /// The verdict is old enough that the screen should refresh before offering the action.
    public var needsRefresh: Bool

    /// A verdict older than this is re-fetched before its action is offered. This is freshness, not eligibility.
    public static let freshness: TimeInterval = 300

    /// - Parameter fetchedAt: when *this device* received the verdict (device clock to device clock, so a skewed
    ///   clock can't hide or show actions; the server re-checks every claim and redemption regardless).
    public init(_ entry: RewardEntry, now: Date, fetchedAt: Date, timeZone: TimeZone = .current) {
        let e = entry.eligibility
        needsRefresh = now.timeIntervalSince(fetchedAt) > Self.freshness
        switch e.state {
        case .eligible:
            tone = .available
            if let until = entry.reward.validUntil { statusLine = "Available · until \(Self.day(until, timeZone))" } else { statusLine = "Available now" }
            action = e.nextAction
        case .notToday:
            tone = .waiting
            statusLine = e.nextEligibleAt.map { "Next available \(Self.day($0, timeZone))" } ?? "Not available today"
            action = .none
        case .limitReached:
            tone = .waiting
            statusLine = e.nextEligibleAt.map { "Used for now · back \(Self.day($0, timeZone))" } ?? "Used for now"
            action = .none
        case .notYetValid:
            tone = .waiting
            statusLine = (e.nextEligibleAt ?? entry.reward.validFrom).map { "Starts \(Self.day($0, timeZone))" } ?? "Not active yet"
            action = .none
        case .insufficientPoints:
            tone = .waiting
            statusLine = e.pointsShortfall.map { "\(RewardCopy.points($0)) to go" } ?? "Not enough points yet"
            action = .none
        case .redeemed:
            tone = .finished
            statusLine = entry.reward.redeemedAt.map { "Redeemed \(Self.day($0, timeZone))" } ?? "Redeemed"
            action = .none
        case .expired:
            tone = .finished
            statusLine = "Expired"
            action = .none
        case .revoked:
            tone = .finished
            statusLine = "No longer available"
            action = .none
        case .unavailable:
            tone = .waiting
            statusLine = "Not available right now"
            action = .none
        }
        // Even a server-eligible verdict never shows an action while it is stale.
        if needsRefresh { action = .none }
    }

    static func day(_ date: Date, _ zone: TimeZone) -> String {
        var style = Date.FormatStyle(date: .abbreviated, time: .omitted)
        style.timeZone = zone
        return date.formatted(style)
    }

    public var actionTitle: String? {
        switch action {
        case .claim: "Claim"
        case .redeem: "Use now"
        case .none: nil
        }
    }
}
