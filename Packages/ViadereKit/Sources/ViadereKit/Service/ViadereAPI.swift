import Foundation
import ViadereCore

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

    /// The server's `SessionInfo` carries no device name (a session is a token family, not a device), so the label is generic.
    public init(_ info: SessionInfo) {
        self.init(id: info.id.uuidString.lowercased(), deviceName: info.current ? "This iPhone" : "Signed-in session",
                  createdAt: info.createdAt, lastSeenAt: nil, isCurrent: info.current)
    }
}

extension SMSLinkPreview {
    /// The last four digits shown in `maskedPhone`, or `nil` if the server's mask doesn't end in four digits.
    public var last4: String? {
        let digits = maskedPhone.filter { $0.isASCII && $0.isNumber }
        return digits.count >= 4 ? String(digits.suffix(4)) : nil
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
    /// `POST /v1/devices`. Unless the begin response said `assertionOptional`, `request.assertion` must carry a user-verified
    /// passkey assertion over the enrollment challenge.
    func enrollDevice(_ request: DeviceEnrollRequest) async throws -> Device
    func devices() async throws -> [Device]
    func revokeDevice(_ id: DeviceID) async throws
    /// `POST /v1/devices/{id}/confirm`: a trusted device lifts the new-device cool-down of another one (`ConfirmationProof`, subject `device`).
    func confirmDevice(_ id: DeviceID, proof: ConfirmationProof) async throws -> Device
    /// `POST /v1/devices/{id}/cancel-replacement`: "Not you? Cancel" on a pending replacement. `id` is the NEW device, which is revoked;
    /// the old one keeps working. Needs a trusted device other than `id` (`403 device_cool_down` otherwise).
    func cancelDeviceReplacement(_ id: DeviceID) async throws

    // MARK: Account recovery (§2.26)
    /// `POST /v1/recovery/begin` (public): spends one code and returns options for a NEW passkey. Every failure is one `401`.
    func beginRecovery(_ request: RecoveryBeginRequest) async throws -> PasskeyRegistrationOptions
    /// `POST /v1/recovery/finish` (public): registers the new passkey and starts the 72 h hold; the response carries the `statusToken`.
    func finishRecovery(_ request: RecoveryFinishRequest) async throws -> RecoveryStatus
    /// `POST /v1/recovery/complete` (public): polls with the status token; returns the replacement codes once after activation.
    func completeRecovery(_ request: RecoveryCompleteRequest) async throws -> RecoveryStatus
    /// `POST /v1/recovery/{id}/cancel`: "Not you? Cancel". A trusted device.
    func cancelRecovery(_ id: RecoveryID) async throws -> RecoveryStatus
    func recoveryInfo() async throws -> RecoveryInfo
    /// `POST /v1/recovery/codes/begin`: passkey assertion options for regenerating codes (trusted device).
    func beginRecoveryCodes() async throws -> PasskeyAssertionOptions
    /// `POST /v1/recovery/codes/regenerate`: a fresh passkey assertion in, a new `RecoveryCodeSet` out (once).
    func regenerateRecoveryCodes(_ request: RecoveryCodesRegenerateRequest) async throws -> RecoveryCodeSet

    // MARK: Phones & sessions
    func startPhoneLink(phone: PhoneNumber) async throws -> PhoneLinkStartResponse
    func verifyPhoneLink(id: PhoneLinkID, code: String) async throws -> PhoneLink
    /// Read-only preview of what a `/l/{token}` link would link (`GET /v1/sms/link-tokens/{token}/preview`). Does not consume the token.
    func previewPhoneLink(token: String) async throws -> SMSLinkPreview
    /// Redeems the token after the person confirmed the previewed number: sends the last four digits and the exact masked number.
    func redeemSMSLink(_ request: SMSLinkRedeemRequest) async throws -> PhoneLink
    func phoneLinks() async throws -> [PhoneLink]
    func removePhoneLink(_ id: PhoneLinkID) async throws
    /// `POST /v1/phone-links/{id}/confirm`: makes a newly linked phone usable now (`ConfirmationProof`, subject `phoneLink`).
    func confirmPhoneLink(_ id: PhoneLinkID, proof: ConfirmationProof) async throws -> PhoneLink
    func sessions() async throws -> [ConsumerSession]
    func revokeSession(_ id: String) async throws
    /// `GET /v1/security-notices`: undismissed notices, newest first, without the ones this device caused.
    func securityNotices() async throws -> [SecurityNotice]
    /// `POST /v1/security-notices/{id}/dismiss`: needs a trusted device (`403 device_cool_down` otherwise).
    func dismissSecurityNotice(_ id: UUID) async throws

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
