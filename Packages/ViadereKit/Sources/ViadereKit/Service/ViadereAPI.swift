import Foundation
import ViadereCore

/// Provisional consumer routes that ViadereCore's `APIRoutes` does not describe yet. They keep the same
/// conventions (paths under `/v1`, `deviceSignedBearer`). Until the server implements them the app treats
/// `404` as "not available yet" and hides the feature gracefully.
public enum ProvisionalRoutes {
    public static let phoneLinks = Endpoint<EmptyBody, [PhoneLink]>(
        "phoneLinks.list", .GET, "/v1/phone-links", auth: .deviceSignedBearer)
    public static let phoneLinkDelete = Endpoint<EmptyBody, EmptyBody>(
        "phoneLinks.delete", .DELETE, "/v1/phone-links/{phoneLinkId}", auth: .deviceSignedBearer)
    public static let sessions = Endpoint<EmptyBody, [ConsumerSession]>(
        "sessions.list", .GET, "/v1/sessions", auth: .deviceSignedBearer)
    public static let sessionRevoke = Endpoint<EmptyBody, EmptyBody>(
        "sessions.revoke", .DELETE, "/v1/sessions/{sessionId}", auth: .deviceSignedBearer)
    public static let accountDelete = Endpoint<EmptyBody, EmptyBody>(
        "account.delete", .DELETE, "/v1/account", auth: .deviceSignedBearer)
}

/// A signed-in session (a bearer-token family), shown under Settings → Signed-in sessions.
public struct ConsumerSession: Codable, Sendable, Hashable, Identifiable {
    public var id: String
    public var deviceName: String
    public var createdAt: Date
    public var lastSeenAt: Date?
    public var isCurrent: Bool

    public init(id: String, deviceName: String, createdAt: Date, lastSeenAt: Date? = nil, isCurrent: Bool = false) {
        self.id = id
        self.deviceName = deviceName
        self.createdAt = createdAt
        self.lastSeenAt = lastSeenAt
        self.isCurrent = isCurrent
    }
}

/// Everything the UI and the extensions need from the server, as typed async calls.
/// `LiveViadereAPI` talks HTTP; `MockViadereAPI` is an in-memory server for previews, tests and demos.
public protocol ViadereAPI: Sendable {
    // MARK: Auth
    func beginRegistration(displayName: String) async throws -> PasskeyRegistrationOptions
    func finishRegistration(_ request: PasskeyRegistrationFinishRequest) async throws -> AuthSession
    func beginLogin() async throws -> PasskeyAssertionOptions
    func finishLogin(_ request: PasskeyLoginFinishRequest) async throws -> AuthSession
    func logout() async throws
    func deleteAccount() async throws

    // MARK: Devices
    func beginDeviceEnrollment() async throws -> DeviceEnrollmentChallenge
    func enrollDevice(_ request: DeviceEnrollRequest) async throws -> Device
    func devices() async throws -> [Device]
    func revokeDevice(_ id: DeviceID) async throws

    // MARK: Phones & sessions
    func startPhoneLink(phone: PhoneNumber) async throws -> PhoneLinkStartResponse
    func verifyPhoneLink(id: PhoneLinkID, code: String) async throws -> PhoneLink
    func redeemSMSLink(token: String, confirmPhoneLast4: String) async throws -> PhoneLink
    func phoneLinks() async throws -> [PhoneLink]
    func removePhoneLink(_ id: PhoneLinkID) async throws
    func sessions() async throws -> [ConsumerSession]
    func revokeSession(_ id: String) async throws

    // MARK: Directory
    func searchDirectory(query: String) async throws -> [BusinessSummary]
    func businessProfile(handle: BusinessHandle) async throws -> BusinessProfile
    func businessProfile(code: BusinessCode) async throws -> BusinessProfile
    func resolve(input: String) async throws -> DirectoryResolveResponse

    // MARK: Relationships & consent
    func connect(_ request: ConnectRequest) async throws -> Relationship
    func relationships() async throws -> [Relationship]
    func disconnect(_ id: RelationshipID) async throws
    func consents(for id: RelationshipID) async throws -> [ConsentGrant]
    func updateConsents(for id: RelationshipID, _ request: ConsentUpdateRequest) async throws -> [ConsentGrant]

    // MARK: Interactions
    func interactions(status: InteractionStatus?, cursor: String?) async throws -> Page<InteractionEnvelope>
    func interaction(_ id: InteractionID) async throws -> InteractionEnvelope
    func decide(_ id: InteractionID, _ request: DecideInteractionRequest) async throws -> InteractionOutcome
    /// Redeems a `/h/{token}` secure-handoff link inside the app (`POST /v1/handoff/redeem`).
    func redeemHandoff(token: String) async throws -> HandoffRedeemResponse

    // MARK: Conversations
    func conversations() async throws -> [ConversationSummary]
    func startConversation(with business: BusinessID) async throws -> ConversationSummary
    func messages(in session: SessionID, cursor: String?) async throws -> Page<ConversationMessage>
    func sendMessage(in session: SessionID, _ request: SendMessageRequest) async throws -> ConversationMessage

    // MARK: Rewards, loyalty and Wallet (P3)
    /// Accounts and rewards across every connected business, with the server's eligibility verdict on each reward.
    func rewardsOverview() async throws -> RewardsOverview
    /// One business's program, the person's membership (if any) and its rewards. `404` = the business has no program.
    func loyaltyProgram(business: BusinessID) async throws -> LoyaltyProgramOverview
    func enrollLoyalty(business: BusinessID, _ request: LoyaltyEnrollRequest) async throws -> LoyaltyAccount
    /// Device-signed. The server re-checks eligibility and may refuse (`409`).
    func claimReward(_ id: RewardID) async throws -> RewardEntry
    /// Device-signed. Returns a short-lived, single-use redemption code. Never cache the result.
    func redeemReward(_ id: RewardID, _ request: RedeemRewardRequest) async throws -> RewardRedemption
    func walletPasses() async throws -> [WalletPassMetadata]
    func issueWalletPass(_ request: WalletPassIssueRequest) async throws -> WalletPassMetadata
    /// The signed `.pkpass` bytes. The app only validates and presents it.
    func walletPass(_ id: WalletPassID) async throws -> Data

    // MARK: Household (delegation)
    func household() async throws -> HouseholdOverview
    func createDelegationInvitation(_ request: DelegationInvitationRequest) async throws -> DelegationInvitation
    func previewDelegationInvitation(code: String) async throws -> DelegationInvitationPreview
    func acceptDelegationInvitation(code: String) async throws -> HouseholdGrant
    func revokeDelegation(_ id: DelegationID) async throws
    func householdAudit() async throws -> [HouseholdAuditEntry]

    // MARK: Acknowledgments
    func acknowledgments() async throws -> [AcknowledgmentRecord]

    // MARK: Push
    func registerAPNsToken(_ registration: APNsTokenRegistration) async throws
    func registerLiveActivityToken(_ registration: LiveActivityTokenRegistration) async throws
}

extension ViadereAPI {
    public func interactions(status: InteractionStatus? = nil) async throws -> Page<InteractionEnvelope> {
        try await interactions(status: status, cursor: nil)
    }

    public func messages(in session: SessionID) async throws -> Page<ConversationMessage> {
        try await messages(in: session, cursor: nil)
    }
}
