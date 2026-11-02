import Foundation

// Authentication delivery (ADR-0020, spec v2 section 6). Viadere is a transport for what a business already decided to send: a
// business-supplied magic link, a partner-generated one-time code, or a security notice. **OPENED is never authentication success.**
// Nothing here is delivered over SMS (owner decisions 1 and 9): the channel enum has no `sms` member, so a request naming one cannot decode.

/// A delivery id on the wire: `adl_` + the base64url form of the 16 bytes of its UUID (22 characters). The server stores the UUID; the wire form is
/// canonical (a non-canonical base64url spelling of the same bytes is refused), so one delivery has exactly one id string.
public struct AuthDeliveryID: Hashable, Sendable, Codable, CustomStringConvertible, LosslessStringConvertible {
    public static let prefix = "adl_"
    public let uuid: UUID

    public init(_ uuid: UUID) { self.uuid = uuid }
    public init() { uuid = UUID() }

    public init?(_ description: String) {
        guard description.hasPrefix(Self.prefix), description.utf8.count == Self.prefix.utf8.count + 22 else { return nil }
        let body = String(description.dropFirst(Self.prefix.count))
        guard Base64URL.isValid(body, minLength: 22, maxLength: 22), let bytes = Base64URL.decode(body), bytes.count == 16 else { return nil }
        let b = Array(bytes)
        let uuid = UUID(uuid: (b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]))
        guard AuthDeliveryID(uuid).description == description else { return nil }
        self.uuid = uuid
    }

    public var description: String {
        let u = uuid.uuid
        let bytes: [UInt8] = [u.0, u.1, u.2, u.3, u.4, u.5, u.6, u.7, u.8, u.9, u.10, u.11, u.12, u.13, u.14, u.15]
        return Self.prefix + Base64URL.encode(Data(bytes))
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        let raw = try container.decode(String.self)
        guard let id = AuthDeliveryID(raw) else { throw DecodingError.dataCorruptedError(in: container, debugDescription: "Invalid delivery id") }
        self = id
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(description)
    }
}

/// What is delivered.
public enum AuthDeliveryMethod: String, Codable, Sendable, CaseIterable, Hashable {
    case magicLink = "magic_link"
    case otp
    case notice
}

/// Why (selects the allowed templates and the lifetime bounds).
public enum AuthDeliveryPurpose: String, Codable, Sendable, CaseIterable, Hashable {
    case signIn = "sign_in"
    case stepUp = "step_up"
    case verifyContact = "verify_contact"
    case accountNotice = "account_notice"
}

/// Where Viadere may deliver. **There is no SMS member** (decisions 1 and 9): `["sms"]` does not decode, so it is a `422` and no adapter can be selected.
public enum AuthDeliveryChannel: String, Codable, Sendable, CaseIterable, Hashable {
    case push
    case inbox
    case email
}

/// Who creates and verifies the link's bearer token (ADR-0021 section 1).
public enum AuthLinkMode: String, Codable, Sendable, CaseIterable, Hashable {
    /// The business supplies a single-use URL on its verified host; Viadere delivers it and asserts nothing.
    case business
    /// The optional Viadere link service (needs the authority, Stage 6): refused until it exists.
    case viadere
}

/// What a delivered code is. Viadere never verifies either kind (decision 3).
public enum AuthCodeKind: String, Codable, Sendable, CaseIterable, Hashable {
    case otp
    case totp
}

/// The delivery state machine's states (lowercase on the wire).
public enum AuthDeliveryStatus: String, Codable, Sendable, CaseIterable, Hashable {
    case created, validated, queued, sent, delivered, opened
    case completed, expired, cancelled, denied, failed

    public var isTerminal: Bool {
        switch self {
        case .completed, .expired, .cancelled, .denied, .failed: true
        default: false
        }
    }

    /// The states a delivery can still be opened from.
    public var isOpenable: Bool { [.queued, .sent, .delivered].contains(self) }
}

/// Who causes a transition (ADR-0020 section 5, table "Actor and trigger").
public enum AuthDeliveryActor: String, Sendable, CaseIterable, Hashable {
    case api, worker, device, business, `operator`, system
}

/// Webhook and event names (`auth.delivery.*`). They are **v2-signature only** from the first release (ADR-0025 section 3): never a `v1=` entry.
public enum AuthDeliveryEventName: String, Codable, Sendable, CaseIterable, Hashable {
    case created = "auth.delivery.created"
    case sent = "auth.delivery.sent"
    case delivered = "auth.delivery.delivered"
    case opened = "auth.delivery.opened"
    case completed = "auth.delivery.completed"
    case failed = "auth.delivery.failed"
    case denied = "auth.delivery.denied"
    case cancelled = "auth.delivery.cancelled"
    case expired = "auth.delivery.expired"

    /// The event a transition into `status` emits (`validated` and `queued` are internal steps of the create transaction).
    public static func forTransition(into status: AuthDeliveryStatus) -> AuthDeliveryEventName? {
        switch status {
        case .created: .created
        case .validated, .queued: nil
        case .sent: .sent
        case .delivered: .delivered
        case .opened: .opened
        case .completed: .completed
        case .failed: .failed
        case .denied: .denied
        case .cancelled: .cancelled
        case .expired: .expired
        }
    }
}

public extension WebhookEventType {
    static let authDeliveryCreated = WebhookEventType(rawValue: AuthDeliveryEventName.created.rawValue)
    static let authDeliverySent = WebhookEventType(rawValue: AuthDeliveryEventName.sent.rawValue)
    static let authDeliveryDelivered = WebhookEventType(rawValue: AuthDeliveryEventName.delivered.rawValue)
    static let authDeliveryOpened = WebhookEventType(rawValue: AuthDeliveryEventName.opened.rawValue)
    static let authDeliveryCompleted = WebhookEventType(rawValue: AuthDeliveryEventName.completed.rawValue)
    static let authDeliveryFailed = WebhookEventType(rawValue: AuthDeliveryEventName.failed.rawValue)
    static let authDeliveryDenied = WebhookEventType(rawValue: AuthDeliveryEventName.denied.rawValue)
    static let authDeliveryCancelled = WebhookEventType(rawValue: AuthDeliveryEventName.cancelled.rawValue)
    static let authDeliveryExpired = WebhookEventType(rawValue: AuthDeliveryEventName.expired.rawValue)

    /// Every `auth.*` event type. A subscription may name these only with signature `v2` and the opaque envelope.
    static let authEvents: [WebhookEventType] = AuthDeliveryEventName.allCases.map { WebhookEventType(rawValue: $0.rawValue) }

    /// Whether the type belongs to the `auth.` family (v2 signature only).
    var isAuthEvent: Bool { rawValue.hasPrefix("auth.") }
}

/// The state machine (ADR-0020 section 5). Pure and shared: the server enforces it with compare-and-swap, tests and SDKs read the same table.
public enum AuthDeliveryStateMachine {
    public struct Transition: Hashable, Sendable {
        public var from: AuthDeliveryStatus
        public var to: AuthDeliveryStatus
        public var actor: AuthDeliveryActor
    }

    /// Every allowed `(from, to, actor)`. Anything else is refused.
    public static let transitions: Set<Transition> = {
        var set = Set<Transition>()
        func add(_ from: [AuthDeliveryStatus], _ to: AuthDeliveryStatus, _ actors: [AuthDeliveryActor]) {
            for f in from { for a in actors { set.insert(Transition(from: f, to: to, actor: a)) } }
        }
        let live = AuthDeliveryStatus.allCases.filter { !$0.isTerminal }
        add([.created], .validated, [.api])
        add([.validated], .queued, [.api])
        add([.queued], .sent, [.worker, .api])
        // First device fetch (or, later, an email provider receipt).
        add([.queued, .sent], .delivered, [.device, .worker])
        // A device-signed open; the secret is deleted in the same transaction.
        add([.queued, .sent, .delivered], .opened, [.device])
        // OPENED is not success: only the business reports its own verification outcome. Viadere never infers it.
        add([.opened], .completed, [.business])
        add([.opened], .failed, [.business])
        add(live, .denied, [.device])
        add(live, .cancelled, [.business, .operator, .system, .api])
        add(live, .expired, [.system, .worker])
        add([.queued], .failed, [.worker, .system])
        return set
    }()

    public static func isAllowed(from: AuthDeliveryStatus, to: AuthDeliveryStatus, by actor: AuthDeliveryActor) -> Bool {
        transitions.contains(Transition(from: from, to: to, actor: actor))
    }
}
