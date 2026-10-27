import Foundation

/// SMS conversation states (gateway spec).
public enum GatewayState: String, Codable, Sendable, CaseIterable {
    case new = "NEW"
    case unlinked = "UNLINKED"
    case linkPending = "LINK_PENDING"
    case idleMenu = "IDLE_MENU"
    case recentMenu = "RECENT_MENU"
    case searchPending = "SEARCH_PENDING"
    case disambiguation = "DISAMBIGUATION"
    case confirmDestination = "CONFIRM_DESTINATION"
    case connected = "CONNECTED"
    case sessionMenu = "SESSION_MENU"
    case optedOut = "OPTED_OUT"
    case expired = "EXPIRED"
}

/// Menu families.
public enum MenuKind: String, Codable, Sendable {
    case main, unlinkedMain, linkPending, more, recent, disambiguation, confirm, session, expired
}

/// What selecting a menu option does.
public enum MenuAction: Codable, Sendable, Hashable {
    case showRecent
    case findBusiness
    case accountHelp
    case moreOptions
    case linkAccount
    case help
    case selectBusiness(BusinessSummary)
    case confirmDestination
    case cancelDestination
    case continueSession
    case switchBusiness
    case endSession
    case resume(BusinessSummary)
    case mainMenu
    case howItWorks
    case privacy
    case manageInApp
}

/// One numbered menu option.
public struct MenuOption: Codable, Sendable, Hashable {
    public var number: Int
    public var label: String
    public var action: MenuAction

    public init(number: Int, label: String, action: MenuAction) {
        self.number = number
        self.label = label
        self.action = action
    }
}

/// The menu currently awaiting a numeric reply. Digits are only interpreted while one is active
/// and unexpired, and only for replies received at/after `issuedAt`.
public struct ActiveMenu: Codable, Sendable, Hashable {
    /// `{kind}-{version}`.
    public var id: String
    /// Monotonic per conversation.
    public var version: Int
    public var kind: MenuKind
    public var options: [MenuOption]
    public var issuedAt: Date
    public var expiresAt: Date

    public func isActive(at now: Date) -> Bool { now < expiresAt }
}

/// The business-scoped routing session currently bound to this SMS thread.
public struct ActiveSession: Codable, Sendable, Hashable {
    public var sessionId: SessionID
    /// Snapshot of the verified business at connect time; used for attribution.
    public var business: BusinessSummary
    public var startedAt: Date
    public var lastActivityAt: Date
}

/// A destination awaiting explicit confirmation, with the message that triggered it.
public struct PendingDestination: Codable, Sendable, Hashable {
    public var business: BusinessSummary
    /// Message to forward once confirmed (direct addressing), if any.
    public var message: String?
    public var providerMessageId: String?
}

/// SMS channel consent (carrier opt-in/out), distinct from per-business purpose consent.
public struct SMSConsentState: Codable, Sendable, Hashable {
    public var optedOut: Bool
    /// Version of the consent/terms copy in force.
    public var consentVersion: String
    public var updatedAt: Date?

    public init(optedOut: Bool = false, consentVersion: String, updatedAt: Date? = nil) {
        self.optedOut = optedOut
        self.consentVersion = consentVersion
        self.updatedAt = updatedAt
    }
}

/// Everything the engine needs to know about one SMS thread (persisted by the server per sender).
public struct ConversationContext: Codable, Sendable, Hashable {
    public var phone: PhoneNumber
    public var state: GatewayState
    /// Linked Viadere consumer, if the phone number is linked (set by the server).
    public var consumerId: ConsumerID?
    public var menu: ActiveMenu?
    /// Last menu version issued.
    public var menuVersion: Int
    public var session: ActiveSession?
    public var pending: PendingDestination?
    public var consent: SMSConsentState
    public var linkPendingUntil: Date?
    public var lastActivityAt: Date?
    /// Recently processed provider message ids (engine-level idempotency; server also dedups).
    public var recentProviderMessageIds: [String]
    /// Incremented on every transition. Persist with compare-and-swap to avoid lost updates.
    public var revision: Int

    public init(phone: PhoneNumber, consumerId: ConsumerID? = nil, consentVersion: String = "2026-10") {
        self.phone = phone
        self.state = .new
        self.consumerId = consumerId
        self.menu = nil
        self.menuVersion = 0
        self.session = nil
        self.pending = nil
        self.consent = SMSConsentState(consentVersion: consentVersion)
        self.linkPendingUntil = nil
        self.lastActivityAt = nil
        self.recentProviderMessageIds = []
        self.revision = 0
    }

    public var isLinked: Bool { consumerId != nil }
}

/// An inbound SMS from the provider webhook (after webhook authenticity is verified).
public struct InboundSMS: Codable, Sendable, Hashable {
    public var providerMessageId: String
    public var from: PhoneNumber
    public var text: String
    /// Provider receive timestamp.
    public var receivedAt: Date

    public init(providerMessageId: String, from: PhoneNumber, text: String, receivedAt: Date) {
        self.providerMessageId = providerMessageId
        self.from = from
        self.text = text
        self.receivedAt = receivedAt
    }
}

/// Why a session closed.
public enum SessionCloseReason: String, Codable, Sendable {
    case switched, endedByUser, expired, optedOut, businessUnavailable
}

/// Purpose of a secure handoff link.
public enum HandoffPurpose: String, Codable, Sendable {
    case accountHelp, manageBusinesses, interaction
}

/// Redacted audit record emitted by the engine (never contains message text).
public struct GatewayAudit: Codable, Sendable, Hashable {
    public var action: String
    public var from: GatewayState
    public var to: GatewayState
    public var businessId: BusinessID?
    public var sessionId: SessionID?
    public var providerMessageId: String?
}

/// Side effects for the server to execute **in order**.
public enum GatewayEffect: Codable, Sendable, Hashable {
    /// Send an SMS to the conversation's phone number.
    case sendSMS(String)
    /// Forward consumer text verbatim to the business session.
    case forwardToBusiness(businessId: BusinessID, sessionId: SessionID, text: String, providerMessageId: String)
    case openSession(businessId: BusinessID, sessionId: SessionID)
    case closeSession(businessId: BusinessID, sessionId: SessionID, reason: SessionCloseReason)
    /// Create a single-use, short-TTL account-link token bound to this phone + conversation revision,
    /// and send `GatewayCopy.accountLink(url:ttlMinutes:)`.
    case sendAccountLink
    /// Create a short-lived secure handoff link and send `GatewayCopy.secureHandoff(url:ttlMinutes:)`.
    case sendSecureHandoff(HandoffPurpose)
    /// Persist an SMS consent change (opt-out / opt-in) with the keyword used.
    case recordConsent(optedOut: Bool, keyword: String, at: Date)
    /// A business message that must not be shown in the current thread context; store in history only.
    case holdBusinessMessage(businessId: BusinessID, sessionId: SessionID)
    case audit(GatewayAudit)
}

/// The engine's output.
public struct GatewayTransition: Sendable, Hashable {
    public var context: ConversationContext
    public var effects: [GatewayEffect]

    /// SMS bodies in order (test/debug convenience).
    public var smsBodies: [String] {
        effects.compactMap { if case .sendSMS(let body) = $0 { body } else { nil } }
    }
}

/// Directory access used by the engine. Implementations must return only businesses the
/// consumer may see; the engine additionally filters to `isVerified`.
public protocol DirectoryLookup: Sendable {
    func business(byCode code: BusinessCode) async throws -> BusinessSummary?
    func business(byHandle handle: BusinessHandle) async throws -> BusinessSummary?
    func business(byId id: BusinessID) async throws -> BusinessSummary?
    /// Name search, best match first.
    func search(name: String, limit: Int) async throws -> [BusinessSummary]
    /// Recent businesses for this consumer/phone, most recent first.
    func recentBusinesses(consumerId: ConsumerID?, phone: PhoneNumber, limit: Int) async throws -> [BusinessSummary]
}

/// Engine configuration.
public struct GatewayConfiguration: Sendable, Hashable {
    public var menuTTL: TimeInterval
    public var sessionIdleTTL: TimeInterval
    public var linkTTL: TimeInterval
    /// When true (default), unlinked numbers may browse but not route messages to businesses.
    public var requireLinkForRouting: Bool
    /// Max provider message ids remembered for idempotency.
    public var dedupMemory: Int
    /// Max characters of a forwarded message.
    public var maxForwardLength: Int
    /// A menu digit received less than this many seconds after the menu was issued is treated as a reply to the menu before it
    /// (the menu is shown again). `0` disables the guard.
    public var menuRaceWindow: TimeInterval

    public init(menuTTL: TimeInterval = 10 * 60, sessionIdleTTL: TimeInterval = 24 * 3600, linkTTL: TimeInterval = 15 * 60,
                requireLinkForRouting: Bool = true, dedupMemory: Int = 50, maxForwardLength: Int = 1600,
                menuRaceWindow: TimeInterval = 0) {
        self.menuRaceWindow = menuRaceWindow
        self.menuTTL = menuTTL
        self.sessionIdleTTL = sessionIdleTTL
        self.linkTTL = linkTTL
        self.requireLinkForRouting = requireLinkForRouting
        self.dedupMemory = dedupMemory
        self.maxForwardLength = maxForwardLength
    }
}
