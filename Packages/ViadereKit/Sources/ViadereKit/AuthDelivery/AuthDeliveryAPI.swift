import Foundation

/// Feature switches for authentication delivery on the device. Everything that depends on a server or authority piece that does not
/// exist yet ships **off** and fails closed; the switches are read where a screen would be presented, never by the security checks.
public struct AuthDeliveryFlags: Sendable, Equatable {
    /// ADR-0033 §4.1 comparison-code screens (new device shows the code, existing device types it). The authority side is Stage 6.
    public var deviceAddComparison: Bool
    /// ADR-0031 §4: the business-signed destination is verified on the device against an authority-signed tenant record. Stage 6.
    /// While false, every business link fails closed (S-LINK-09) and Continue never enables.
    public var destinationVerification: Bool

    public init(deviceAddComparison: Bool = false, destinationVerification: Bool = false) {
        self.deviceAddComparison = deviceAddComparison
        self.destinationVerification = destinationVerification
    }

    /// What ships today.
    public static let shipping = AuthDeliveryFlags()
}

/// An auth-delivery item reduced to what the device may show (ADR-0020 §6: the push carries only the delivery id; the display is fetched).
public struct AuthLinkDisplay: Sendable, Equatable {
    public enum State: String, Sendable, Equatable { case open, expired, used, cancelled }

    public var deliveryId: UUID
    /// The verified display name from the authority-signed record (never a Brand Kit field or business-supplied text).
    public var business: String
    public var businessVerified: Bool
    /// The destination host from the signed statement, lowercase A-label form.
    public var host: String
    public var expiresAt: Date
    public var state: State

    public init(deliveryId: UUID, business: String, businessVerified: Bool, host: String, expiresAt: Date, state: State = .open) {
        self.deliveryId = deliveryId
        self.business = business
        self.businessVerified = businessVerified
        self.host = host
        self.expiresAt = expiresAt
        self.state = state
    }
}

/// How a push target is addressed to the delivery API.
public enum AuthPushTarget: Sendable, Equatable {
    /// An Approve v2 request (`viadere.approve`, push key `req`).
    case approveRequest(String)
    /// A link or code delivery (`viadere.auth.link`, `viadere.auth.code`, push key `adl`).
    case delivery(UUID)
}

/// A reduce-only answer: it can only say no. Signed by the device `request` key, never by an approval key (ADR-0022 §5.5).
public enum ReduceAction: String, Sendable, Equatable {
    case deny
    /// "This wasn't me": `decision: report`, `deny_reason: not_me`.
    case report
    /// A refusal because the destination failed verification on the device (`deny_reason: destination_unverified`, ADR-0031 §4).
    case denyDestinationUnverified
}

public enum AuthDeliveryError: Error, Sendable, Equatable {
    /// No network or the service could not be reached. Nothing was queued.
    case offline
    case expired
    case alreadyUsed
    case notActive
    /// The build has no auth-delivery client yet.
    case unavailable
    case failed
}

/// The device's calls for auth delivery (ADR-0020 endpoints). Kept behind this protocol: the server API is built in parallel, the App
/// supplies `UnavailableAuthDeliveryAPI` until the live client exists, and tests supply `MockAuthDeliveryAPI`.
public protocol AuthDeliveryAPI: Sendable {
    /// `GET /v1/auth-deliveries/{id}/display`: business, host, expiry. Consumes nothing.
    func linkDisplay(deliveryId: UUID) async throws -> AuthLinkDisplay
    /// `POST /v1/auth-deliveries/{id}/open` (device-signed): returns the URL once. Only called after an explicit tap.
    func openLink(deliveryId: UUID) async throws -> URL
    /// Device-signed, reduce-only. For a link this is the "This wasn't me" action (`report: true`).
    func reduce(_ target: AuthPushTarget, action: ReduceAction) async throws
}

/// The default until the live client exists: every call fails closed.
public struct UnavailableAuthDeliveryAPI: AuthDeliveryAPI {
    public init() {}
    public func linkDisplay(deliveryId: UUID) async throws -> AuthLinkDisplay { throw AuthDeliveryError.unavailable }
    public func openLink(deliveryId: UUID) async throws -> URL { throw AuthDeliveryError.unavailable }
    public func reduce(_ target: AuthPushTarget, action: ReduceAction) async throws { throw AuthDeliveryError.unavailable }
}

/// A recording fake for tests and previews.
public actor MockAuthDeliveryAPI: AuthDeliveryAPI {
    public var displays: [UUID: AuthLinkDisplay] = [:]
    public var urls: [UUID: URL] = [:]
    public private(set) var openCalls: [UUID] = []
    public private(set) var reduceCalls: [(AuthPushTarget, ReduceAction)] = []
    public var reduceError: AuthDeliveryError?
    public var openError: AuthDeliveryError?

    public init() {}

    public func add(_ display: AuthLinkDisplay, url: URL) {
        displays[display.deliveryId] = display
        urls[display.deliveryId] = url
    }
    public func failReduce(with error: AuthDeliveryError?) { reduceError = error }
    public func failOpen(with error: AuthDeliveryError?) { openError = error }

    public func linkDisplay(deliveryId: UUID) async throws -> AuthLinkDisplay {
        guard let display = displays[deliveryId] else { throw AuthDeliveryError.notActive }
        return display
    }
    public func openLink(deliveryId: UUID) async throws -> URL {
        openCalls.append(deliveryId)
        if let openError { throw openError }
        guard let url = urls[deliveryId] else { throw AuthDeliveryError.notActive }
        return url
    }
    public func reduce(_ target: AuthPushTarget, action: ReduceAction) async throws {
        reduceCalls.append((target, action))
        if let reduceError { throw reduceError }
    }
}

/// Posts the local "Deny not sent yet" notice (N-09, ADR-0022 §5.6). The App implements it with `UNUserNotificationCenter`.
public protocol LocalSecurityNoticePosting: Sendable {
    func postDenyNotSent() async
}

public struct NoLocalSecurityNotices: LocalSecurityNoticePosting {
    public init() {}
    public func postDenyNotSent() async {}
}
