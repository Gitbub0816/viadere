import Foundation
import ViadereCore

/// A push to one device. By design this carries **no sensitive details**: the visible text is generic
/// and the only identifier is the opaque interaction id; the app fetches details over the authenticated API.
public struct PushMessage: Sendable, Equatable {
    public var deviceToken: String
    public var environment: APNsTokenRegistration.Environment
    public var topic: String
    public var title: String
    public var body: String
    public var category: String
    public var threadID: String
    /// `passive`, `active` or `time-sensitive`.
    public var interruptionLevel: String
    public var mutableContent: Bool
    /// Opaque id the app uses to fetch the interaction (`iid` at the top level of the payload).
    public var interactionId: String?
    public var highPriority: Bool
    public var collapseID: String?

    public init(deviceToken: String, environment: APNsTokenRegistration.Environment, topic: String, title: String, body: String,
                category: String, threadID: String, interruptionLevel: String, mutableContent: Bool = true,
                interactionId: String?, highPriority: Bool, collapseID: String? = nil) {
        self.deviceToken = deviceToken
        self.environment = environment
        self.topic = topic
        self.title = title
        self.body = body
        self.category = category
        self.threadID = threadID
        self.interruptionLevel = interruptionLevel
        self.mutableContent = mutableContent
        self.interactionId = interactionId
        self.highPriority = highPriority
        self.collapseID = collapseID
    }
}

public enum PushOutcome: Sendable, Equatable {
    case delivered
    /// APNs reported the token as unregistered/invalid; the server stops using it.
    case tokenInvalid
    case failed
}

/// An ActivityKit push (`apns-push-type: liveactivity`, topic `<bundle>.push-type.liveactivity`).
///
/// The only content is `LiveActivityStatus` (an order, delivery, flight or appointment state), so it is never marketing and
/// never carries more than the Live Activity already shows. `start` also carries the generic attributes and a neutral alert.
public struct LiveActivityPush: Sendable, Equatable {
    public enum Event: String, Sendable { case start, update, end }

    /// The static attributes of `ViadereActivityAttributes` (a push-to-start must supply them).
    public struct Attributes: Sendable, Equatable, Encodable {
        public var businessName: String
        public var businessId: String
        public var interactionId: String
        public init(businessName: String, businessId: String, interactionId: String) {
            self.businessName = businessName
            self.businessId = businessId
            self.interactionId = interactionId
        }
    }

    /// The Swift type name of the app's `ActivityAttributes`, required by push-to-start.
    public static let attributesType = "ViadereActivityAttributes"

    public var deviceToken: String
    public var environment: APNsTokenRegistration.Environment
    public var bundleId: String
    public var event: Event
    public var content: LiveActivityStatus
    /// Seconds since 1970 when the server produced this state (ActivityKit ignores out-of-order updates).
    public var timestamp: Int
    public var attributes: Attributes?
    /// Neutral alert shown when an activity is started remotely.
    public var alertTitle: String?
    public var alertBody: String?

    public var topic: String { bundleId + ".push-type.liveactivity" }

    public init(deviceToken: String, environment: APNsTokenRegistration.Environment, bundleId: String, event: Event,
                content: LiveActivityStatus, timestamp: Int, attributes: Attributes? = nil, alertTitle: String? = nil,
                alertBody: String? = nil) {
        self.deviceToken = deviceToken
        self.environment = environment
        self.bundleId = bundleId
        self.event = event
        self.content = content
        self.timestamp = timestamp
        self.attributes = attributes
        self.alertTitle = alertTitle
        self.alertBody = alertBody
    }
}

/// Abstraction over APNs so the real client can be replaced by a recording fake in tests.
public protocol APNsSender: Sendable {
    func send(_ message: PushMessage) async -> PushOutcome
    /// Sends an ActivityKit push. Implementations that cannot (development, test fakes) report `.failed`.
    func sendLiveActivity(_ push: LiveActivityPush) async -> PushOutcome
}

extension APNsSender {
    public func sendLiveActivity(_ push: LiveActivityPush) async -> PushOutcome { .failed }
}

/// Sends the empty "your pass changed" push that makes Wallet re-download a pass from the web service. APNs authenticates
/// these with the **Pass Type ID certificate** (not the token key used for the app), topic = the pass type identifier.
public protocol PassPushSender: Sendable {
    func notify(pushToken: String, passTypeIdentifier: String) async -> PushOutcome
}

/// Used when no pass certificate is configured: nothing to update.
public struct DisabledPassPushSender: PassPushSender {
    public init() {}
    public func notify(pushToken: String, passTypeIdentifier: String) async -> PushOutcome { .failed }
}

/// Builds push messages from interactions. Sensitive content (amounts, merchants, devices, locations,
/// message text) never enters the payload.
public enum PushPayloadBuilder {
    public static let genericTitle = "Viadere"

    public static func message(for interaction: Interaction, business: BusinessSummary, token: APNsTokenRegistrationRecord,
                               topic: String) -> PushMessage {
        let rendering = ChannelRenderer.notification(interaction, business: business)
        let body: String
        switch interaction.kind {
        case .authenticate, .authorize: body = "Action needed. Open to review a security request."
        case .message: body = "You have a new message."
        case .status: body = "There is an update."
        default: body = "You have a new request."
        }
        return PushMessage(
            deviceToken: token.token, environment: token.environment, topic: token.bundleId.isEmpty ? topic : token.bundleId,
            title: genericTitle, body: body, category: rendering.category.identifier, threadID: rendering.threadIdentifier,
            interruptionLevel: rendering.interruptionLevel == .timeSensitive ? "time-sensitive" : rendering.interruptionLevel.rawValue,
            mutableContent: true, interactionId: interaction.id.description,
            highPriority: rendering.interruptionLevel != .passive, collapseID: nil)
    }

    /// A generic account-security notice ("a device was added"). Carries no names, numbers or other details.
    public static func securityNotice(body: String, token: APNsTokenRegistrationRecord, topic: String) -> PushMessage {
        PushMessage(deviceToken: token.token, environment: token.environment,
                    topic: token.bundleId.isEmpty ? topic : token.bundleId, title: genericTitle, body: body,
                    category: "viadere.security.notice", threadID: "viadere.security", interruptionLevel: "time-sensitive",
                    mutableContent: true, interactionId: nil, highPriority: true)
    }

    /// Generic notification for a business message in a conversation (no text).
    public static func messageNotice(business: BusinessSummary, token: APNsTokenRegistrationRecord, topic: String) -> PushMessage {
        PushMessage(deviceToken: token.token, environment: token.environment,
                    topic: token.bundleId.isEmpty ? topic : token.bundleId, title: genericTitle, body: "You have a new message.",
                    category: "viadere.message", threadID: "business.\(business.id)", interruptionLevel: "active",
                    mutableContent: true, interactionId: nil, highPriority: true)
    }
}

/// Plain value describing a registered push token (decoupled from the Fluent model).
public struct APNsTokenRegistrationRecord: Sendable, Equatable {
    public var token: String
    public var environment: APNsTokenRegistration.Environment
    public var bundleId: String
}

/// Used when APNs is not configured (development): pushes are dropped.
public struct DisabledAPNsSender: APNsSender {
    public init() {}
    public func send(_ message: PushMessage) async -> PushOutcome { .failed }
}
