import Foundation
import ViadereCore

/// `ViadereAPI` over HTTP, using ViadereCore's `APIRoutes` through `APIClient`.
public struct LiveViadereAPI: ViadereAPI {
    private let client: APIClient

    public init(client: APIClient) { self.client = client }

    // MARK: Auth
    public func beginRegistration(displayName: String) async throws -> PasskeyRegistrationOptions {
        try await client.call(APIRoutes.registerBegin, body: PasskeyRegistrationBeginRequest(displayName: displayName))
    }
    public func finishRegistration(_ request: PasskeyRegistrationFinishRequest) async throws -> AuthSession {
        try await client.call(APIRoutes.registerFinish, body: request)
    }
    public func beginLogin() async throws -> PasskeyAssertionOptions {
        try await client.call(APIRoutes.loginBegin, body: PasskeyLoginBeginRequest())
    }
    public func finishLogin(_ request: PasskeyLoginFinishRequest) async throws -> AuthSession {
        try await client.call(APIRoutes.loginFinish, body: request)
    }
    public func logout() async throws { _ = try await client.call(APIRoutes.logout) }
    public func deleteAccount() async throws { _ = try await client.call(APIRoutes.accountDelete) }

    // MARK: Devices
    public func beginDeviceEnrollment() async throws -> DeviceEnrollmentChallenge { try await client.call(APIRoutes.deviceEnrollBegin) }
    public func enrollDevice(_ request: DeviceEnrollRequest) async throws -> Device {
        try await client.call(APIRoutes.deviceEnroll, body: request)
    }
    public func devices() async throws -> [Device] { try await client.call(APIRoutes.devicesList) }
    public func revokeDevice(_ id: DeviceID) async throws {
        _ = try await client.call(APIRoutes.deviceRevoke, params: ["deviceId": id.description])
    }
    public func confirmDevice(_ id: DeviceID, proof: ConfirmationProof) async throws -> Device {
        try await client.call(APIRoutes.deviceConfirm, params: ["deviceId": id.description], body: ConfirmationRequest(proof: proof))
    }

    // MARK: Phones & sessions
    public func startPhoneLink(phone: PhoneNumber) async throws -> PhoneLinkStartResponse {
        try await client.call(APIRoutes.phoneLinkStart, body: PhoneLinkStartRequest(phone: phone))
    }
    public func verifyPhoneLink(id: PhoneLinkID, code: String) async throws -> PhoneLink {
        try await client.call(APIRoutes.phoneLinkVerify, body: PhoneLinkVerifyRequest(phoneLinkId: id, code: code))
    }
    public func previewPhoneLink(token: String) async throws -> SMSLinkPreview {
        try await client.call(APIRoutes.smsLinkPreview, params: ["token": token])
    }
    public func redeemSMSLink(_ request: SMSLinkRedeemRequest) async throws -> PhoneLink {
        try await client.call(APIRoutes.smsLinkRedeem, body: request)
    }
    public func phoneLinks() async throws -> [PhoneLink] { try await client.call(APIRoutes.phoneLinksList) }
    public func removePhoneLink(_ id: PhoneLinkID) async throws {
        _ = try await client.call(APIRoutes.phoneLinkDelete, params: ["phoneLinkId": id.description])
    }
    public func confirmPhoneLink(_ id: PhoneLinkID, proof: ConfirmationProof) async throws -> PhoneLink {
        try await client.call(APIRoutes.phoneLinkConfirm, params: ["phoneLinkId": id.description], body: ConfirmationRequest(proof: proof))
    }
    public func sessions() async throws -> [ConsumerSession] { try await client.call(APIRoutes.sessionsList).map(ConsumerSession.init(_:)) }
    public func revokeSession(_ id: String) async throws {
        _ = try await client.call(APIRoutes.sessionRevoke, params: ["sessionId": id])
    }

    // MARK: Directory
    public func searchDirectory(query: String) async throws -> [BusinessSummary] {
        let page = try await client.call(APIRoutes.directorySearch, query: [("q", String(query.prefix(256))), ("limit", "20")])
        return page.items.filter(\.isVerified)
    }
    public func businessProfile(handle: BusinessHandle) async throws -> BusinessProfile {
        try await client.call(APIRoutes.directoryHandle, params: ["handle": handle.value])
    }
    public func businessProfile(code: BusinessCode) async throws -> BusinessProfile {
        try await client.call(APIRoutes.directoryCode, params: ["code": code.canonical])
    }
    public func resolve(input: String) async throws -> DirectoryResolveResponse {
        var response = try await client.call(APIRoutes.directoryResolve, body: DirectoryResolveRequest(input: String(input.prefix(256))))
        response.matches = response.matches.filter(\.isVerified)
        return response
    }

    // MARK: Relationships & consent
    public func connect(_ request: ConnectRequest) async throws -> Relationship {
        try await client.call(APIRoutes.relationshipConnect, body: request)
    }
    public func relationships() async throws -> [Relationship] { try await client.call(APIRoutes.relationshipsList) }
    public func disconnect(_ id: RelationshipID) async throws {
        _ = try await client.call(APIRoutes.relationshipDisconnect, params: ["relationshipId": id.description])
    }
    public func consents(for id: RelationshipID) async throws -> [ConsentGrant] {
        try await client.call(APIRoutes.consentsGet, params: ["relationshipId": id.description])
    }
    public func updateConsents(for id: RelationshipID, _ request: ConsentUpdateRequest) async throws -> [ConsentGrant] {
        try await client.call(APIRoutes.consentsUpdate, params: ["relationshipId": id.description], body: request)
    }

    // MARK: Interactions
    public func interactions(status: InteractionStatus?, cursor: String?) async throws -> Page<InteractionEnvelope> {
        var query: [(String, String)] = [("limit", "30")]
        if let status { query.append(("status", status.rawValue)) }
        if let cursor { query.append(("cursor", cursor)) }
        return try await client.call(APIRoutes.interactionsList, query: query)
    }
    public func interaction(_ id: InteractionID) async throws -> InteractionEnvelope {
        try await client.call(APIRoutes.interactionGet, params: ["interactionId": id.description])
    }
    public func decide(_ id: InteractionID, _ request: DecideInteractionRequest) async throws -> InteractionOutcome {
        try await client.call(APIRoutes.interactionDecide, params: ["interactionId": id.description], body: request)
    }
    public func redeemHandoff(token: String) async throws -> HandoffRedeemResponse {
        try await client.call(APIRoutes.handoffRedeem, body: HandoffRedeemRequest(token: token))
    }

    // MARK: Conversations
    public func conversations() async throws -> [ConversationSummary] { try await client.call(APIRoutes.conversationsList) }
    public func startConversation(with business: BusinessID) async throws -> ConversationSummary {
        try await client.call(APIRoutes.conversationStart, body: StartConversationRequest(businessId: business))
    }
    public func messages(in session: SessionID, cursor: String?) async throws -> Page<ConversationMessage> {
        var query: [(String, String)] = [("limit", "50")]
        if let cursor { query.append(("cursor", cursor)) }
        return try await client.call(APIRoutes.conversationMessages, params: ["sessionId": session.description], query: query)
    }
    public func sendMessage(in session: SessionID, _ request: SendMessageRequest) async throws -> ConversationMessage {
        try await client.call(APIRoutes.conversationSend, params: ["sessionId": session.description], body: request)
    }

    // MARK: Rewards, loyalty and Wallet
    public func rewardsOverview() async throws -> RewardsOverview { try await client.call(APIRoutes.rewardsOverview) }
    public func loyaltyProgram(business: BusinessID) async throws -> LoyaltyProgramOverview {
        try await client.call(APIRoutes.loyaltyProgram, params: ["businessId": business.description])
    }
    public func enrollLoyalty(business: BusinessID, _ request: LoyaltyEnrollRequest) async throws -> LoyaltyAccount {
        try await client.call(APIRoutes.loyaltyEnroll, params: ["businessId": business.description], body: request)
    }
    public func claimReward(_ id: RewardID) async throws -> RewardEntry {
        try await client.call(APIRoutes.rewardClaim, params: ["rewardId": id.description])
    }
    public func redeemReward(_ id: RewardID, _ request: RedeemRewardRequest) async throws -> RewardRedemption {
        try await client.call(APIRoutes.rewardRedeem, params: ["rewardId": id.description], body: request)
    }
    public func walletPasses() async throws -> [WalletPassMetadata] { try await client.call(APIRoutes.walletPasses) }
    public func issueWalletPass(_ request: WalletPassIssueRequest) async throws -> WalletPassMetadata {
        try await client.call(APIRoutes.walletPassIssue, body: request)
    }
    public func walletPass(_ id: WalletPassID) async throws -> Data {
        try await client.data(APIRoutes.walletPass, params: ["passId": id.description])
    }

    // MARK: Household
    public func household() async throws -> HouseholdOverview { try await client.call(APIRoutes.household) }
    public func createDelegationInvitation(_ request: DelegationInvitationRequest) async throws -> DelegationInvitation {
        try await client.call(APIRoutes.householdInvite, body: request)
    }
    public func previewDelegationInvitation(code: String) async throws -> DelegationInvitationPreview {
        try await client.call(APIRoutes.householdInvitationPreview, body: DelegationInvitationRedeemRequest(code: code))
    }
    public func acceptDelegationInvitation(code: String) async throws -> HouseholdGrant {
        try await client.call(APIRoutes.householdInvitationAccept, body: DelegationInvitationRedeemRequest(code: code))
    }
    public func revokeDelegation(_ id: DelegationID) async throws {
        _ = try await client.call(APIRoutes.delegationRevoke, params: ["delegationId": id.description])
    }
    public func householdAudit() async throws -> [HouseholdAuditEntry] { try await client.call(APIRoutes.householdAudit) }

    // MARK: Acknowledgments
    public func acknowledgments() async throws -> [AcknowledgmentRecord] { try await client.call(APIRoutes.acknowledgments) }

    // MARK: Push
    public func registerAPNsToken(_ registration: APNsTokenRegistration) async throws {
        _ = try await client.call(APIRoutes.apnsTokenRegister, body: registration)
    }
    public func registerLiveActivityToken(_ registration: LiveActivityTokenRegistration) async throws {
        _ = try await client.call(APIRoutes.liveActivityTokenRegister, body: registration)
    }
}
