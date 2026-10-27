import Foundation

/// The complete HTTP route catalog shared by the server and clients. All paths are under `/v1`.
///
/// Conventions: JSON bodies use `ViadereJSON`; errors use `APIErrorResponse`; list endpoints that
/// paginate accept `cursor` and `limit` query parameters and return `Page<T>`.
public enum APIRoutes {
    // MARK: Consumer auth (passkeys)
    public static let registerBegin = Endpoint<PasskeyRegistrationBeginRequest, PasskeyRegistrationOptions>(
        "auth.register.begin", .POST, "/v1/auth/register/begin", auth: .none)
    public static let registerFinish = Endpoint<PasskeyRegistrationFinishRequest, AuthSession>(
        "auth.register.finish", .POST, "/v1/auth/register/finish", auth: .none)
    public static let loginBegin = Endpoint<PasskeyLoginBeginRequest, PasskeyAssertionOptions>(
        "auth.login.begin", .POST, "/v1/auth/login/begin", auth: .none)
    public static let loginFinish = Endpoint<PasskeyLoginFinishRequest, AuthSession>(
        "auth.login.finish", .POST, "/v1/auth/login/finish", auth: .none)
    /// Public: the refresh token itself is the credential (single-use, rotated, reuse revokes the family).
    public static let authRefresh = Endpoint<AuthRefreshRequest, AuthSession>(
        "auth.refresh", .POST, "/v1/auth/refresh", auth: .none)
    /// Ends **this session only** (its tokens). It never revokes devices: use `devices.revoke` for that. Device-signed, so a stolen
    /// bearer token alone cannot sign the owner out.
    public static let logout = Endpoint<EmptyBody, EmptyBody>(
        "auth.logout", .POST, "/v1/auth/logout", auth: .deviceSignedBearer)

    // MARK: Devices
    /// Returns the enrollment challenge **and** WebAuthn assertion options over that same challenge (`DeviceEnrollmentChallenge`).
    public static let deviceEnrollBegin = Endpoint<EmptyBody, DeviceEnrollmentChallenge>(
        "devices.enroll.begin", .POST, "/v1/devices/enroll/begin", auth: .bearer)
    /// Bearer plus a fresh, user-verified passkey assertion over the enrollment challenge (or a fresh unused passkey sign-in).
    public static let deviceEnroll = Endpoint<DeviceEnrollRequest, Device>(
        "devices.enroll", .POST, "/v1/devices", auth: .bearer)
    /// Lifts the new-device cool-down of `{deviceId}`; signed by a different, trusted device (`ConfirmationProof`).
    public static let deviceConfirm = Endpoint<ConfirmationRequest, Device>(
        "devices.confirm", .POST, "/v1/devices/{deviceId}/confirm", auth: .deviceSignedBearer)
    public static let devicesList = Endpoint<EmptyBody, [Device]>(
        "devices.list", .GET, "/v1/devices", auth: .deviceSignedBearer)
    public static let deviceRevoke = Endpoint<EmptyBody, EmptyBody>(
        "devices.revoke", .DELETE, "/v1/devices/{deviceId}", auth: .deviceSignedBearer)

    // MARK: Phone links & SMS account linking
    public static let phoneLinkStart = Endpoint<PhoneLinkStartRequest, PhoneLinkStartResponse>(
        "phoneLinks.start", .POST, "/v1/phone-links/start", auth: .deviceSignedBearer)
    public static let phoneLinkVerify = Endpoint<PhoneLinkVerifyRequest, PhoneLink>(
        "phoneLinks.verify", .POST, "/v1/phone-links/verify", auth: .deviceSignedBearer)
    public static let phoneLinksList = Endpoint<EmptyBody, [PhoneLink]>(
        "phoneLinks.list", .GET, "/v1/phone-links", auth: .deviceSignedBearer)
    public static let phoneLinkDelete = Endpoint<EmptyBody, EmptyBody>(
        "phoneLinks.delete", .DELETE, "/v1/phone-links/{phoneLinkId}", auth: .deviceSignedBearer)
    /// Makes a newly linked phone usable for delivery and RCS/SMS replies now (`ConfirmationProof`, subject `phoneLink`).
    public static let phoneLinkConfirm = Endpoint<ConfirmationRequest, PhoneLink>(
        "phoneLinks.confirm", .POST, "/v1/phone-links/{phoneLinkId}/confirm", auth: .deviceSignedBearer)

    // MARK: Sessions & account
    public static let sessionsList = Endpoint<EmptyBody, [SessionInfo]>(
        "sessions.list", .GET, "/v1/sessions", auth: .deviceSignedBearer)
    public static let sessionRevoke = Endpoint<EmptyBody, EmptyBody>(
        "sessions.revoke", .DELETE, "/v1/sessions/{sessionId}", auth: .deviceSignedBearer)
    /// Undismissed in-app security notices (device or phone added, App Clip started, device set up again), newest first.
    public static let securityNotices = Endpoint<EmptyBody, [SecurityNotice]>(
        "securityNotices.list", .GET, "/v1/security-notices", auth: .deviceSignedBearer)
    /// Dismisses a notice. Needs a trusted device (`403 device_cool_down` while the device is new).
    public static let securityNoticeDismiss = Endpoint<EmptyBody, EmptyBody>(
        "securityNotices.dismiss", .POST, "/v1/security-notices/{noticeId}/dismiss", auth: .deviceSignedBearer)
    /// Revokes every device and token, erases/anonymizes personal data, keeps a redacted audit record.
    public static let accountDelete = Endpoint<EmptyBody, EmptyBody>(
        "account.delete", .DELETE, "/v1/account", auth: .deviceSignedBearer)

    /// Read-only: what the one-time SMS link token would link (`{maskedPhone, expiresAt}`). Does not consume the token.
    public static let smsLinkPreview = Endpoint<EmptyBody, SMSLinkPreview>(
        "sms.linkTokens.preview", .GET, "/v1/sms/link-tokens/{token}/preview", auth: .deviceSignedBearer)
    /// The one-time SMS link token is redeemed **inside the app** after the person confirmed the masked phone (device-signed).
    public static let smsLinkRedeem = Endpoint<SMSLinkRedeemRequest, PhoneLink>(
        "sms.linkTokens.redeem", .POST, "/v1/sms/link-tokens/redeem", auth: .deviceSignedBearer)

    /// App-side redemption of an SMS secure-handoff token; the token must have been minted for this consumer.
    public static let handoffRedeem = Endpoint<HandoffRedeemRequest, HandoffRedeemResponse>(
        "handoff.redeem", .POST, "/v1/handoff/redeem", auth: .deviceSignedBearer)

    // MARK: Directory (public, rate-limited)
    /// Query: `q` (required), `limit` (≤ 20), `cursor`.
    public static let directorySearch = Endpoint<EmptyBody, Page<BusinessSummary>>(
        "directory.search", .GET, "/v1/directory/search", auth: .none)
    public static let directoryHandle = Endpoint<EmptyBody, BusinessProfile>(
        "directory.handle", .GET, "/v1/directory/handles/{handle}", auth: .none)
    public static let directoryCode = Endpoint<EmptyBody, BusinessProfile>(
        "directory.code", .GET, "/v1/directory/codes/{code}", auth: .none)
    public static let directoryResolve = Endpoint<DirectoryResolveRequest, DirectoryResolveResponse>(
        "directory.resolve", .POST, "/v1/directory/resolve", auth: .none)

    // MARK: Relationships & consent
    public static let relationshipConnect = Endpoint<ConnectRequest, Relationship>(
        "relationships.connect", .POST, "/v1/relationships", auth: .deviceSignedBearer)
    public static let relationshipsList = Endpoint<EmptyBody, [Relationship]>(
        "relationships.list", .GET, "/v1/relationships", auth: .deviceSignedBearer)
    public static let relationshipDisconnect = Endpoint<EmptyBody, EmptyBody>(
        "relationships.disconnect", .DELETE, "/v1/relationships/{relationshipId}", auth: .deviceSignedBearer)
    public static let consentsGet = Endpoint<EmptyBody, [ConsentGrant]>(
        "consents.get", .GET, "/v1/relationships/{relationshipId}/consents", auth: .deviceSignedBearer)
    public static let consentsUpdate = Endpoint<ConsentUpdateRequest, [ConsentGrant]>(
        "consents.update", .PUT, "/v1/relationships/{relationshipId}/consents", auth: .deviceSignedBearer)

    // MARK: Interactions
    /// Query: `status` (optional), `cursor`, `limit`.
    public static let interactionsList = Endpoint<EmptyBody, Page<InteractionEnvelope>>(
        "interactions.list", .GET, "/v1/interactions", auth: .deviceSignedBearer)
    public static let interactionGet = Endpoint<EmptyBody, InteractionEnvelope>(
        "interactions.get", .GET, "/v1/interactions/{interactionId}", auth: .deviceSignedBearer)
    public static let interactionDecide = Endpoint<DecideInteractionRequest, InteractionOutcome>(
        "interactions.decide", .POST, "/v1/interactions/{interactionId}/decision", auth: .deviceSignedBearer)

    // MARK: Conversations
    public static let conversationsList = Endpoint<EmptyBody, [ConversationSummary]>(
        "conversations.list", .GET, "/v1/conversations", auth: .deviceSignedBearer)
    public static let conversationStart = Endpoint<StartConversationRequest, ConversationSummary>(
        "conversations.start", .POST, "/v1/conversations", auth: .deviceSignedBearer)
    /// Query: `cursor`, `limit`.
    public static let conversationMessages = Endpoint<EmptyBody, Page<ConversationMessage>>(
        "conversations.messages", .GET, "/v1/conversations/{sessionId}/messages", auth: .deviceSignedBearer)
    public static let conversationSend = Endpoint<SendMessageRequest, ConversationMessage>(
        "conversations.send", .POST, "/v1/conversations/{sessionId}/messages", auth: .deviceSignedBearer)

    // MARK: Rewards & Wallet
    /// Bare rewards without eligibility. `rewardsOverview` supersedes it for the app; kept for older clients.
    public static let rewardsList = Endpoint<EmptyBody, [Reward]>(
        "rewards.list", .GET, "/v1/rewards", auth: .deviceSignedBearer)
    /// Accounts and rewards across every connected business, each reward with the server's eligibility verdict.
    public static let rewardsOverview = Endpoint<EmptyBody, RewardsOverview>(
        "rewards.overview", .GET, "/v1/rewards/overview", auth: .deviceSignedBearer)
    /// `404` when the business has no loyalty program.
    public static let loyaltyProgram = Endpoint<EmptyBody, LoyaltyProgramOverview>(
        "loyalty.program", .GET, "/v1/loyalty/{businessId}", auth: .deviceSignedBearer)
    /// `409` when `acceptedTermsVersion` is not the program's current version.
    public static let loyaltyEnroll = Endpoint<LoyaltyEnrollRequest, LoyaltyAccount>(
        "loyalty.enroll", .POST, "/v1/loyalty/{businessId}/enroll", auth: .deviceSignedBearer)
    /// `409` when the reward is not claimable right now.
    public static let rewardClaim = Endpoint<EmptyBody, RewardEntry>(
        "rewards.claim", .POST, "/v1/rewards/{rewardId}/claim", auth: .deviceSignedBearer)
    /// Re-checks eligibility (`409` when not eligible) and returns a single-use code valid for about two minutes.
    public static let rewardRedeem = Endpoint<RedeemRewardRequest, RewardRedemption>(
        "rewards.redeem", .POST, "/v1/rewards/{rewardId}/redeem", auth: .deviceSignedBearer)
    public static let walletPasses = Endpoint<EmptyBody, [WalletPassMetadata]>(
        "wallet.passes.list", .GET, "/v1/wallet/passes", auth: .deviceSignedBearer)
    public static let walletPassIssue = Endpoint<WalletPassIssueRequest, WalletPassMetadata>(
        "wallet.passes.issue", .POST, "/v1/wallet/passes", auth: .deviceSignedBearer)
    /// Response is the binary `.pkpass` (`application/vnd.apple.pkpass`).
    public static let walletPass = Endpoint<EmptyBody, Data>(
        "wallet.pass", .GET, "/v1/wallet/passes/{passId}", auth: .deviceSignedBearer)

    // MARK: Push & Live Activities
    public static let apnsTokenRegister = Endpoint<APNsTokenRegistration, EmptyBody>(
        "push.apnsToken", .POST, "/v1/push/apns-token", auth: .deviceSignedBearer)
    public static let liveActivityTokenRegister = Endpoint<LiveActivityTokenRegistration, EmptyBody>(
        "liveActivities.token", .POST, "/v1/live-activities/tokens", auth: .deviceSignedBearer)

    // MARK: Delegation (household)
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

    // MARK: Acknowledgments
    public static let acknowledgments = Endpoint<EmptyBody, [AcknowledgmentRecord]>(
        "acknowledgments.list", .GET, "/v1/acknowledgments", auth: .deviceSignedBearer)

    /// Direct (id-based) delegation. Kept for completeness; the app uses the invitation flow.
    public static let delegationCreate = Endpoint<CreateDelegationRequest, DelegationGrant>(
        "delegations.create", .POST, "/v1/delegations", auth: .deviceSignedBearer)
    public static let delegationsList = Endpoint<EmptyBody, [DelegationGrant]>(
        "delegations.list", .GET, "/v1/delegations", auth: .deviceSignedBearer)
    public static let delegationRevoke = Endpoint<EmptyBody, EmptyBody>(
        "delegations.revoke", .DELETE, "/v1/delegations/{delegationId}", auth: .deviceSignedBearer)

    // MARK: Business API
    public static let businessIssueInteraction = Endpoint<IssueInteractionRequest, Interaction>(
        "business.interactions.issue", .POST, "/v1/business/interactions", auth: .businessAPIKey)
    public static let businessInteractionOutcome = Endpoint<EmptyBody, InteractionOutcome>(
        "business.interactions.outcome", .GET, "/v1/business/interactions/{interactionId}", auth: .businessAPIKey)
    public static let businessCancelInteraction = Endpoint<EmptyBody, InteractionOutcome>(
        "business.interactions.cancel", .POST, "/v1/business/interactions/{interactionId}/cancel", auth: .businessAPIKey)
    public static let businessSendMessage = Endpoint<BusinessSendMessageRequest, ConversationMessage>(
        "business.messages.send", .POST, "/v1/business/messages", auth: .businessAPIKey)
    public static let businessUpdateStatus = Endpoint<BusinessStatusUpdateRequest, Interaction>(
        "business.statuses.update", .POST, "/v1/business/statuses", auth: .businessAPIKey)
    public static let businessIssueReward = Endpoint<IssueRewardRequest, Reward>(
        "business.rewards.issue", .POST, "/v1/business/rewards", auth: .businessAPIKey)
    public static let businessRewardsList = Endpoint<EmptyBody, [Reward]>(
        "business.rewards.list", .GET, "/v1/business/rewards", auth: .businessAPIKey)
    public static let businessRewardRevoke = Endpoint<EmptyBody, Reward>(
        "business.rewards.revoke", .POST, "/v1/business/rewards/{rewardId}/revoke", auth: .businessAPIKey)
    public static let businessLoyaltyProgramGet = Endpoint<EmptyBody, BusinessLoyaltyProgram>(
        "business.loyalty.program.get", .GET, "/v1/business/loyalty/program", auth: .businessAPIKey)
    public static let businessLoyaltyProgramPut = Endpoint<UpsertLoyaltyProgramRequest, BusinessLoyaltyProgram>(
        "business.loyalty.program.put", .PUT, "/v1/business/loyalty/program", auth: .businessAPIKey)
    public static let businessAdjustPoints = Endpoint<AdjustLoyaltyPointsRequest, LoyaltyPointsResult>(
        "business.loyalty.points", .POST, "/v1/business/loyalty/points", auth: .businessAPIKey)
    /// Validates and consumes a redemption code atomically: exactly one caller can ever succeed per code.
    public static let businessConsumeRedemption = Endpoint<ConsumeRedemptionRequest, RedemptionReceipt>(
        "business.redemptions.consume", .POST, "/v1/business/redemptions/consume", auth: .businessAPIKey)
    /// Test-mode keys only: creates a sandbox consumer connected to the business. Test keys can target nothing else.
    public static let businessSandboxRelationship = Endpoint<EmptyBody, SandboxRelationship>(
        "business.sandbox.relationships.create", .POST, "/v1/business/sandbox/relationships", auth: .businessAPIKey)
    public static let businessWebhooksList = Endpoint<EmptyBody, [WebhookSubscription]>(
        "business.webhooks.list", .GET, "/v1/business/webhooks", auth: .businessAPIKey)
    public static let businessWebhookCreate = Endpoint<CreateWebhookRequest, WebhookSecretResponse>(
        "business.webhooks.create", .POST, "/v1/business/webhooks", auth: .businessAPIKey)
    public static let businessWebhookDelete = Endpoint<EmptyBody, EmptyBody>(
        "business.webhooks.delete", .DELETE, "/v1/business/webhooks/{webhookId}", auth: .businessAPIKey)
    public static let businessWebhookRotate = Endpoint<EmptyBody, WebhookSecretResponse>(
        "business.webhooks.rotate", .POST, "/v1/business/webhooks/{webhookId}/rotate-secret", auth: .businessAPIKey)

    // MARK: Messaging provider
    /// Raw provider payload (e.g. form-encoded); verified with the provider's signature scheme.
    public static let providerSMSInbound = Endpoint<Data, EmptyBody>(
        "providers.sms.inbound", .POST, "/v1/providers/sms/inbound", auth: .providerSignature)
    /// Delivery receipts.
    public static let providerSMSStatus = Endpoint<Data, EmptyBody>(
        "providers.sms.status", .POST, "/v1/providers/sms/status", auth: .providerSignature)
    /// RCS Business Messaging provider webhook (JSON): free text, suggestion postbacks and receipts, authenticated
    /// by an HMAC signature header (`X-RCS-Signature: t=…,v1=…`).
    public static let providerRCSInbound = Endpoint<Data, EmptyBody>(
        "providers.rcs.inbound", .POST, "/v1/providers/rcs/inbound", auth: .providerSignature)

    /// Every endpoint, for route registration, docs and contract tests.
    public static let all: [AnyEndpoint] = [
        registerBegin.descriptor, registerFinish.descriptor, loginBegin.descriptor, loginFinish.descriptor,
        authRefresh.descriptor, logout.descriptor,
        deviceEnrollBegin.descriptor, deviceEnroll.descriptor, deviceConfirm.descriptor, devicesList.descriptor, deviceRevoke.descriptor,
        phoneLinkStart.descriptor, phoneLinkVerify.descriptor, smsLinkPreview.descriptor, smsLinkRedeem.descriptor, handoffRedeem.descriptor,
        phoneLinkConfirm.descriptor,
        phoneLinksList.descriptor, phoneLinkDelete.descriptor, sessionsList.descriptor, sessionRevoke.descriptor, securityNotices.descriptor, securityNoticeDismiss.descriptor, accountDelete.descriptor,
        directorySearch.descriptor, directoryHandle.descriptor, directoryCode.descriptor, directoryResolve.descriptor,
        relationshipConnect.descriptor, relationshipsList.descriptor, relationshipDisconnect.descriptor,
        consentsGet.descriptor, consentsUpdate.descriptor,
        interactionsList.descriptor, interactionGet.descriptor, interactionDecide.descriptor,
        conversationsList.descriptor, conversationStart.descriptor, conversationMessages.descriptor, conversationSend.descriptor,
        rewardsList.descriptor, rewardsOverview.descriptor, loyaltyProgram.descriptor, loyaltyEnroll.descriptor,
        rewardClaim.descriptor, rewardRedeem.descriptor, walletPasses.descriptor, walletPassIssue.descriptor, walletPass.descriptor,
        household.descriptor, householdInvite.descriptor, householdInvitationPreview.descriptor,
        householdInvitationAccept.descriptor, householdAudit.descriptor, acknowledgments.descriptor,
        apnsTokenRegister.descriptor, liveActivityTokenRegister.descriptor,
        delegationCreate.descriptor, delegationsList.descriptor, delegationRevoke.descriptor,
        businessIssueInteraction.descriptor, businessInteractionOutcome.descriptor, businessCancelInteraction.descriptor,
        businessSendMessage.descriptor, businessUpdateStatus.descriptor, businessIssueReward.descriptor,
        businessRewardsList.descriptor, businessRewardRevoke.descriptor, businessLoyaltyProgramGet.descriptor,
        businessLoyaltyProgramPut.descriptor, businessAdjustPoints.descriptor, businessConsumeRedemption.descriptor,
        businessWebhooksList.descriptor, businessWebhookCreate.descriptor, businessWebhookDelete.descriptor,
        businessWebhookRotate.descriptor, businessSandboxRelationship.descriptor,
        providerSMSInbound.descriptor, providerSMSStatus.descriptor, providerRCSInbound.descriptor,
    ]

    /// Web (non-API) paths served on `viadere.com`.
    public enum Web {
        /// Connect link: `/c/{CODE}` (see `ConnectLink`).
        public static let connectPrefix = "/c/"
        /// SMS account-link landing: `/l/{token}`.
        public static let accountLinkPrefix = "/l/"
        /// Secure handoff landing: `/h/{token}`.
        public static let handoffPrefix = "/h/"
        /// Business dashboard (server-rendered, passkey sign-in).
        public static let dashboardPrefix = "/dashboard"
        /// Viadere operator console (separate realm, passkey sign-in).
        public static let operatorPrefix = "/operator"

        public static func accountLinkURL(token: String) -> URL? { URL(string: "https://\(ViadereCore.domain)\(accountLinkPrefix)\(token)") }
        public static func handoffURL(token: String) -> URL? { URL(string: "https://\(ViadereCore.domain)\(handoffPrefix)\(token)") }
    }
}
