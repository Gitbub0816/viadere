import Foundation
import ViadereCore

/// Feature switches for authentication delivery on the device. Everything that depends on a server or authority piece that does not
/// exist yet ships **off** and fails closed; the switches are read where a screen would be presented, never by the security checks.
public struct AuthDeliveryFlags: Sendable, Equatable {
    /// ADR-0033 §4.1 comparison-code screens (new device shows the code, existing device types it). The authority side is Stage 6.
    public var deviceAddComparison: Bool
    /// ADR-0031 §4: the business-signed destination is verified on the device against an authority-signed tenant record. Stage 6.
    /// While false, every business link fails closed (S-LINK-09) and Continue never enables.
    public var destinationVerification: Bool
    /// The Deny action on `viadere.approve` notifications (ADR-0022 §5.5). Off until the server sends `req` in Approve v2 pushes and
    /// accepts a request-key-signed reduce-only deny (Stage 4 review R4-03): a Deny button that cannot succeed must never be shown.
    public var notificationDeny: Bool

    public init(deviceAddComparison: Bool = false, destinationVerification: Bool = false, notificationDeny: Bool = false) {
        self.deviceAddComparison = deviceAddComparison
        self.destinationVerification = destinationVerification
        self.notificationDeny = notificationDeny
    }

    /// What ships today (production builds).
    public static let shipping = AuthDeliveryFlags()
    /// Staging and local builds: the `viadere.approve` Deny action is shown. The server now sends `req` in Approve v2 pushes and accepts a request-key
    /// reduce-only deny (`POST /v1/approve/requests/{id}/deny`, Stage 5), which closes R4-03. Production stays off until the pilot.
    public static let staging = AuthDeliveryFlags(notificationDeny: true)

    /// The flags for a build: staging diagnostics or a local build get `.staging`, everything else `.shipping`.
    public static func forConfiguration(_ configuration: ViadereConfiguration) -> AuthDeliveryFlags {
        configuration.stagingDiagnostics || configuration.mode == .local ? .staging : .shipping
    }
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

/// One delivery as the device may show it (`AuthDeliveryDisplay` reduced and checked). It never carries the URL, the code, the signed
/// destination statement or the template variables: a secret reaches the device only through `open`, after an explicit tap.
public struct AuthDeliveryItem: Sendable, Equatable, Identifiable {
    public enum Kind: Sendable, Equatable {
        case link
        case code(AuthCodeKind)
        case notice
    }

    public var deliveryId: UUID
    public var kind: Kind
    public var businessId: BusinessID
    /// The business name as the api knows it. Untrusted for layout: every presenter passes it through `UntrustedText.name`.
    public var business: String
    /// Links only: the destination host, lowercase A-label form.
    public var host: String?
    public var purpose: AuthDeliveryPurpose
    public var createdAt: Date
    public var expiresAt: Date
    public var state: AuthLinkDisplay.State
    /// Delivered without an alert push (over a per-subject budget, ADR-0020 §8): the inbox is the only place it shows.
    public var silent: Bool

    public var id: UUID { deliveryId }

    public init(deliveryId: UUID, kind: Kind, businessId: BusinessID, business: String, host: String? = nil, purpose: AuthDeliveryPurpose = .signIn,
                createdAt: Date, expiresAt: Date, state: AuthLinkDisplay.State = .open, silent: Bool = false) {
        self.deliveryId = deliveryId
        self.kind = kind
        self.businessId = businessId
        self.business = business
        self.host = host
        self.purpose = purpose
        self.createdAt = createdAt
        self.expiresAt = expiresAt
        self.state = state
        self.silent = silent
    }

    /// Strict reading of the wire object: a link without a valid lowercase host, a code or notice that names a host, or a name that is
    /// absurdly long is refused whole rather than shown with a gap.
    public init(display: AuthDeliveryDisplay) throws {
        guard display.businessName.unicodeScalars.count <= 512, display.expiresAt >= display.createdAt else { throw AuthDeliveryError.failed }
        var host: String?
        let kind: Kind
        switch display.method {
        case .magicLink:
            guard let raw = display.destinationHost, raw == raw.lowercased(), Self.isValidHost(raw) else { throw AuthDeliveryError.failed }
            host = raw
            kind = .link
        case .otp:
            guard display.destinationHost == nil else { throw AuthDeliveryError.failed }
            kind = .code(display.codeKind ?? .otp)
        case .notice:
            guard display.destinationHost == nil else { throw AuthDeliveryError.failed }
            kind = .notice
        }
        let state: AuthLinkDisplay.State
        switch display.status {
        case .created, .validated, .queued, .sent, .delivered: state = .open
        case .opened, .completed, .failed: state = .used
        case .expired: state = .expired
        case .cancelled, .denied: state = .cancelled
        }
        self.init(deliveryId: display.id.uuid, kind: kind, businessId: display.businessId, business: display.businessName, host: host,
                  purpose: display.purpose, createdAt: display.createdAt, expiresAt: display.expiresAt, state: state, silent: display.silent)
    }

    static func isValidHost(_ host: String) -> Bool {
        do { try AuthDestinationValidator.validateHost(host); return true } catch { return false }
    }

    /// The link screen's view of this item (`nil` for a code or a notice). `businessVerified` stays false: the name is the api's, not the
    /// authority-signed tenant record's (ADR-0031, Stage 6), and nothing is opened on its strength.
    public var linkDisplay: AuthLinkDisplay? {
        guard kind == .link, let host else { return nil }
        return AuthLinkDisplay(deliveryId: deliveryId, business: business, businessVerified: false, host: host, expiresAt: expiresAt, state: state)
    }
}

/// A one-time code the service handed over **once** (`open`). It lives only in memory, for the code sheet; its descriptions are redacted so
/// an interpolation or a log line can never carry the digits.
public struct DeliveredCode: Sendable, Equatable, CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var value: String
    public var kind: AuthCodeKind

    public init(value: String, kind: AuthCodeKind) {
        self.value = value
        self.kind = kind
    }

    public var description: String { "DeliveredCode(redacted)" }
    public var debugDescription: String { description }
    public var customMirror: Mirror { Mirror(self, children: [:]) }
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
    /// This process has no auth-delivery client, or the call needs a piece that does not exist yet (destination verification).
    case unavailable
    case failed
}

/// The device's calls for auth delivery (ADR-0020 endpoints, `APIRoutes.authDeliveries…`). Kept behind this protocol: the App Clip and
/// processes without a session supply `UnavailableAuthDeliveryAPI`, tests supply `MockAuthDeliveryAPI`.
public protocol AuthDeliveryAPI: Sendable {
    /// `GET /v1/auth-deliveries`: the open deliveries of this account, newest first. Consumes nothing.
    func deliveries() async throws -> [AuthDeliveryItem]
    /// `GET /v1/auth-deliveries/{id}`: who, what, when (and where, for a link). The first fetch marks the delivery `delivered`, never
    /// `opened`; it returns no URL and no code.
    func item(deliveryId: UUID) async throws -> AuthDeliveryItem
    /// The same fetch, for the link screen: business, host, expiry. Consumes nothing. A code or a notice is `notActive` here.
    func linkDisplay(deliveryId: UUID) async throws -> AuthLinkDisplay
    /// `POST /v1/auth-deliveries/{id}/open` (device-signed): returns the URL once. Only called after an explicit tap, and only when the
    /// destination was verified on the device.
    func openLink(deliveryId: UUID) async throws -> URL
    /// `POST /v1/auth-deliveries/{id}/open` for a one-time code: returns the code **once** (a second call is `alreadyUsed`). Only called
    /// after an explicit tap on the code sheet.
    func openCode(deliveryId: UUID) async throws -> DeliveredCode
    /// Device-signed, reduce-only. For a link or a code this is the "This wasn't me" action (`report: true`).
    func reduce(_ target: AuthPushTarget, action: ReduceAction) async throws
}

/// The live client, over the device-signed `APIClient` (the device `request` key; no approval key, no Face ID).
///
/// - The list and the display object are read-only and carry no secret.
/// - `openCode` hands the code over once and checks that what came back is a code and nothing else.
/// - `openLink` stays **unavailable** while `flags.destinationVerification` is off (Stage 6): with no tenant record nothing can be verified,
///   so the URL is never requested and the delivery is never consumed, whatever a screen asks for.
/// - The reduce-only answers always go through.
public struct LiveAuthDeliveryAPI: AuthDeliveryAPI {
    let client: APIClient
    let flags: AuthDeliveryFlags

    public init(client: APIClient, flags: AuthDeliveryFlags = .shipping) {
        self.client = client
        self.flags = flags
    }

    /// The server lists at most this many; a longer answer is cut, never trusted.
    static let listLimit = 50

    public func deliveries() async throws -> [AuthDeliveryItem] {
        let client = self.client
        let rows: [AuthDeliveryDisplay] = try await Self.mapped { try await client.call(APIRoutes.authDeliveries) }
        // A row that does not pass the strict reading is dropped on its own; the others still show.
        var seen = Set<UUID>()
        return rows.prefix(Self.listLimit).compactMap { try? AuthDeliveryItem(display: $0) }.filter { seen.insert($0.deliveryId).inserted }
    }

    public func item(deliveryId: UUID) async throws -> AuthDeliveryItem {
        let client = self.client
        let display: AuthDeliveryDisplay = try await Self.mapped {
            try await client.call(APIRoutes.authDeliveryGet, params: ["deliveryId": AuthDeliveryID(deliveryId).description])
        }
        // The answer must be about the delivery that was asked for.
        guard display.id.uuid == deliveryId else { throw AuthDeliveryError.failed }
        return try AuthDeliveryItem(display: display)
    }

    public func linkDisplay(deliveryId: UUID) async throws -> AuthLinkDisplay {
        guard let display = try await item(deliveryId: deliveryId).linkDisplay else { throw AuthDeliveryError.notActive }
        return display
    }

    public func openLink(deliveryId: UUID) async throws -> URL {
        guard flags.destinationVerification else { throw AuthDeliveryError.unavailable }
        let opened = try await open(deliveryId)
        guard opened.method == .magicLink, opened.code == nil, let raw = opened.url, Self.isStrictDestination(raw),
              let url = URL(string: raw) else { throw AuthDeliveryError.failed }
        return url
    }

    public func openCode(deliveryId: UUID) async throws -> DeliveredCode {
        let opened = try await open(deliveryId)
        guard opened.method == .otp, opened.url == nil, let code = opened.code, AuthDeliveryValidation.isValidCode(code) else { throw AuthDeliveryError.failed }
        return DeliveredCode(value: code, kind: opened.codeKind ?? .otp)
    }

    private func open(_ deliveryId: UUID) async throws -> AuthDeliveryOpenResponse {
        let client = self.client
        let opened: AuthDeliveryOpenResponse = try await Self.mapped {
            try await client.call(APIRoutes.authDeliveryOpen, params: ["deliveryId": AuthDeliveryID(deliveryId).description])
        }
        guard opened.id.uuid == deliveryId else { throw AuthDeliveryError.failed }
        return opened
    }

    static func isStrictDestination(_ raw: String) -> Bool {
        do { _ = try AuthDestinationValidator.parse(raw); return true } catch { return false }
    }

    public func reduce(_ target: AuthPushTarget, action: ReduceAction) async throws {
        do {
            switch target {
            case .approveRequest(let id):
                // `req` is this device's delivery id (a lowercase UUID); anything else is not sent.
                guard let uuid = UUID(uuidString: id), action != .denyDestinationUnverified else { throw AuthDeliveryError.notActive }
                let _: SubmitApprovalResultResponse = try await client.call(APIRoutes.approveRequestDeny, params: ["approvalId": uuid.uuidString.lowercased()],
                                                                             body: ApproveDenyRequest(report: action == .report ? true : nil))
            case .delivery(let id):
                let body = AuthDeliveryDenyRequest(report: action == .report ? true : nil, reason: action == .denyDestinationUnverified ? "destination_unverified" : nil)
                let _: AuthDeliveryView = try await client.call(APIRoutes.authDeliveryDeny, params: ["deliveryId": AuthDeliveryID(id).description], body: body)
            }
        } catch let error as AuthDeliveryError {
            throw error
        } catch let error as APIError {
            throw Self.map(error)
        } catch {
            throw AuthDeliveryError.offline
        }
    }

    /// Runs a read or an open and turns its failure into the screens' vocabulary. Only a transport failure is "offline"; an answer the
    /// app cannot read, a missing session and anything unexpected are `failed` (nothing is retried, nothing is queued).
    static func mapped<T: Sendable>(_ call: @Sendable () async throws -> T) async throws -> T {
        do { return try await call() } catch let error as AuthDeliveryError {
            throw error
        } catch let error as APIError {
            throw map(error)
        } catch {
            throw AuthDeliveryError.failed
        }
    }

    static func map(_ error: APIError) -> AuthDeliveryError {
        if case .transport = error { return .offline }
        switch error.code {
        case .gone?, .expired?: return .expired
        case .conflict?, .alreadyOpened?, .replayDetected?: return .alreadyUsed
        case .notFound?: return .notActive
        default: return .failed
        }
    }
}

/// For processes with no auth-delivery client (the App Clip, tests that do not use it): every call fails closed.
public struct UnavailableAuthDeliveryAPI: AuthDeliveryAPI {
    public init() {}
    public func deliveries() async throws -> [AuthDeliveryItem] { throw AuthDeliveryError.unavailable }
    public func item(deliveryId: UUID) async throws -> AuthDeliveryItem { throw AuthDeliveryError.unavailable }
    public func linkDisplay(deliveryId: UUID) async throws -> AuthLinkDisplay { throw AuthDeliveryError.unavailable }
    public func openLink(deliveryId: UUID) async throws -> URL { throw AuthDeliveryError.unavailable }
    public func openCode(deliveryId: UUID) async throws -> DeliveredCode { throw AuthDeliveryError.unavailable }
    public func reduce(_ target: AuthPushTarget, action: ReduceAction) async throws { throw AuthDeliveryError.unavailable }
}

/// A recording fake for tests and previews.
public actor MockAuthDeliveryAPI: AuthDeliveryAPI {
    public var displays: [UUID: AuthLinkDisplay] = [:]
    public var urls: [UUID: URL] = [:]
    public var items: [UUID: AuthDeliveryItem] = [:]
    public var codes: [UUID: DeliveredCode] = [:]
    public private(set) var listCalls = 0
    public private(set) var itemCalls: [UUID] = []
    public private(set) var openCalls: [UUID] = []
    public private(set) var openCodeCalls: [UUID] = []
    public private(set) var reduceCalls: [(AuthPushTarget, ReduceAction)] = []
    public var reduceError: AuthDeliveryError?
    public var openError: AuthDeliveryError?
    /// Fails `deliveries`, `item` and `linkDisplay`.
    public var readError: AuthDeliveryError?

    public init() {}

    public func add(_ display: AuthLinkDisplay, url: URL) {
        displays[display.deliveryId] = display
        urls[display.deliveryId] = url
    }
    /// A delivery in the inbox; a code is handed over once by `openCode`.
    public func add(_ item: AuthDeliveryItem, code: DeliveredCode? = nil) {
        items[item.deliveryId] = item
        codes[item.deliveryId] = code
        if let display = item.linkDisplay { displays[item.deliveryId] = display }
    }
    public func remove(_ id: UUID) {
        items[id] = nil
        displays[id] = nil
        codes[id] = nil
    }
    public func failReduce(with error: AuthDeliveryError?) { reduceError = error }
    public func failOpen(with error: AuthDeliveryError?) { openError = error }
    public func failRead(with error: AuthDeliveryError?) { readError = error }

    public func deliveries() async throws -> [AuthDeliveryItem] {
        listCalls += 1
        if let readError { throw readError }
        return items.values.filter { $0.state == .open }.sorted { $0.createdAt > $1.createdAt }
    }
    public func item(deliveryId: UUID) async throws -> AuthDeliveryItem {
        itemCalls.append(deliveryId)
        if let readError { throw readError }
        guard let item = items[deliveryId] else { throw AuthDeliveryError.notActive }
        return item
    }
    public func linkDisplay(deliveryId: UUID) async throws -> AuthLinkDisplay {
        if let readError { throw readError }
        guard let display = displays[deliveryId] else { throw AuthDeliveryError.notActive }
        return display
    }
    public func openLink(deliveryId: UUID) async throws -> URL {
        openCalls.append(deliveryId)
        if let openError { throw openError }
        guard let url = urls[deliveryId] else { throw AuthDeliveryError.notActive }
        return url
    }
    public func openCode(deliveryId: UUID) async throws -> DeliveredCode {
        openCodeCalls.append(deliveryId)
        if let openError { throw openError }
        // Once: the second call finds nothing, like the server's `409 already_opened`.
        guard let code = codes.removeValue(forKey: deliveryId) else { throw AuthDeliveryError.alreadyUsed }
        items[deliveryId]?.state = .used
        return code
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
