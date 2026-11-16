import Crypto
import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

// The Viadere link service on the phone (`link_mode: "viadere"`; SECURITY.md §2.110 "Link service", ADR-0021 §5.3, ADR-0033 §2).
//
// A link-service delivery holds no URL: it carries the authority's signed `link_open` challenge, relayed unchanged by the api. The phone answers it
// the way it answers an OIDC sign-in (`OIDCSignInViewModel`): verify the statement against the build-pinned statement keys, show who is asking and
// where from the authority-built display only, type the number when the challenge asks for one, and sign a `viadere-factor+jws` with the biometric
// approval key, sent to `POST /v1/auth-deliveries/{id}/link-evidence`. Only after the authority **accepted** a same-device approval does the phone
// open the signed return URL with the one-time code in the fragment, once, through the system opener (`LinkServiceHandoff`); nothing else opens.

/// UX_COPY LS-01 to LS-08 (the link-service screen). `{Business}` is the authority-signed `tenant_name`, never an api display field.
public enum LinkServiceCopy {
    public static func title(business: String) -> String { "Sign in to \(business)?" }
    public static let websiteLabel = "Website"
    public static let serviceLabel = "Service"
    public static func subtitle(business: String) -> String { "Only approve if you asked \(business) to sign you in." }
    /// S-LINK-03 (another device: the number the business shows).
    public static func numberLabel(business: String) -> String { "Number on \(business)" }
    public static func numberHelp(business: String) -> String {
        "Enter the 2-digit number on the \(business) screen where you're signing in. No number there, or someone gave it to you? Tap This wasn't me."
    }
    public static let deny = "Deny"
    public static let approve = "Approve"
    public static let notMe = "This wasn't me"
    public static func approved(business: String) -> String { "Approved. Go back to \(business) to finish signing in." }
    public static let denied = "Denied. Nobody was signed in."
    public static func reported(business: String) -> String { AuthDeliveryCopy.linkReported(business: business) }
    public static func wrongNumber(business: String) -> String { "That number doesn't match the one on \(business). Check it and try again." }
    public static func stopped(business: String) -> String { "This sign-in was stopped after three wrong numbers. Ask \(business) for a new link." }
    public static let expired = "This sign-in link has expired. Ask for a new one where you started signing in."
    public static let alreadyAnswered = "This sign-in link was already answered."
    public static let refused = "Viadere didn't accept this answer, so nobody was signed in. Ask for a new link where you started signing in."
    public static let gone = AuthDeliveryCopy.noLongerActive
    /// E-01 for an authority-backed flow: the statement could not be verified; nothing was shown or signed.
    public static let cannotVerify = OIDCCopy.cannotVerify
    public static let offline = AuthDeliveryCopy.offline
    public static let noKey = "Approving sign-ins needs Face ID or Touch ID on this device."
    /// LS-09: same device, after the system opened the signed return URL.
    public static func opened(host: String) -> String { AuthDeliveryCopy.linkOpened(host: host) }
    /// LS-10: the hand-off could not be made (the system did not open it, the request ran out, or the URL would not be the signed one). The code is gone.
    public static func notFinished(host: String) -> String {
        "We couldn't open \(AuthDeliveryCopy.iso(host)), so you're not signed in. Ask for a new link where you started signing in."
    }
}

/// What the phone shows for a verified `link_open` statement: only values from the authority-built, authority-signed display.
public struct LinkServiceDisplay: Sendable, Equatable {
    /// The tenant's reviewed name (`tenant_name`).
    public var business: String
    /// The link client's reviewed name (`client_name`).
    public var client: String
    /// The exact signed return URL and its host.
    public var returnURL: String
    public var host: String
    /// `nil` for a same-device challenge; 2 when the challenge asks for the number the business shows (cross-device).
    public var matchDigits: Int?

    /// Strict: purpose `link_open`, exactly the members the authority builds (`AuthorityDisplay.linkOpen`), the display's `return_url` equal to the
    /// statement's byte for byte, an https URL whose host is `return_host`, names of 1 to 60 characters, and `match_digits` 2 exactly when the
    /// statement requires a number. Anything else is refused (the screen never improvises).
    public init?(statement: AuthorityChallengeStatement) {
        guard statement.purpose == .linkOpen, let signedURL = statement.returnURL, case .object(let o) = statement.display else { return nil }
        let base: Set<String> = ["v", "purpose", "tenant_name", "client_name", "return_url", "return_host"]
        guard Set(o.keys) == (statement.matchRequired ? base.union(["match_digits"]) : base), o["v"]?.authorityInteger == 1,
              o["purpose"]?.stringValue == AuthorityPurpose.linkOpen.rawValue,
              let business = o["tenant_name"]?.stringValue, (1...60).contains(business.count),
              let client = o["client_name"]?.stringValue, (1...60).contains(client.count),
              let url = o["return_url"]?.stringValue, Data(url.utf8) == Data(signedURL.utf8),
              let components = URLComponents(string: url), components.scheme == "https", components.user == nil, components.password == nil,
              let host = o["return_host"]?.stringValue, !host.isEmpty, host == components.host?.lowercased(), components.fragment == nil else { return nil }
        if statement.matchRequired {
            guard o["match_digits"]?.authorityInteger == 2 else { return nil }
            matchDigits = 2
        } else {
            matchDigits = nil
        }
        self.business = UntrustedText.line(business, max: 60)
        self.client = UntrustedText.line(client, max: 60)
        guard !self.business.isEmpty, !self.client.isEmpty else { return nil }
        returnURL = url
        self.host = host
    }
}

/// The same-device hand-off of ADR-0021 §5.3: the exact signed return URL with the one-time code in the fragment, `<return_url>#vdr_code=<link_code>`.
/// The fragment keeps the code out of the first request, the business's access logs and any `Referer`; the business page's own script reads it.
public enum LinkServiceHandoff {
    /// `link_code`: 32 random bytes, base64url without padding (43 characters).
    public static func isValidCode(_ code: String) -> Bool { Base64URL.isValid(code, minLength: 43, maxLength: 43) && Base64URL.decode(code)?.count == 32 }

    /// The URL the system is asked to open, or `nil` when it would not be exactly the signed one: `returnURL` must be https (lowercase scheme, as
    /// signed) on exactly `host` (the signed `return_host`), without user info, a port other than 443 or a fragment of its own; the result must be
    /// `returnURL` byte for byte followed by `#vdr_code=` and the code (Foundation must not rewrite a single byte), at most 2048 bytes.
    public static func url(returnURL: String, host: String, code: String) -> URL? {
        guard isValidCode(code), returnURL.hasPrefix("https://"), !returnURL.contains("#") else { return nil }
        let raw = returnURL + "#vdr_code=" + code
        guard let url = URL(string: raw), url.absoluteString == raw, LinkConfirmationViewModel.isAcceptable(url, host: host),
              let components = URLComponents(url: url, resolvingAgainstBaseURL: false), components.percentEncodedFragment == "vdr_code=" + code else { return nil }
        return url
    }
}

/// The link-service delivery as the device fetches it (`GET /v1/auth-deliveries/{id}`): only what the screen needs, the signed statement unverified.
public struct LinkServiceDelivery: Sendable, Equatable {
    public var deliveryId: UUID
    public var state: AuthLinkDisplay.State
    public var expiresAt: Date
    /// The compact `viadere-challenge+jws` as relayed (absent once the delivery has ended).
    public var challenge: String?

    public init(deliveryId: UUID, state: AuthLinkDisplay.State, expiresAt: Date, challenge: String?) {
        self.deliveryId = deliveryId
        self.state = state
        self.expiresAt = expiresAt
        self.challenge = challenge
    }
}

public enum LinkServiceError: Error, Sendable, Equatable {
    case offline
    /// Unknown, not a link-service delivery, or not this account's.
    case notActive
    /// `401 evidence_invalid`: the authority or the api refused the answer (one generic refusal: a wrong number, an unknown key, a mismatch).
    case refused
    case expired
    /// `409`: already answered.
    case alreadyAnswered
    /// The link service is off (`404` from `link-evidence`) or unreachable (`503`).
    case unavailable
}

/// The device calls of the link service (`APIRoutes.authDeliveryGet`, `authDeliveryLinkEvidence`).
public protocol LinkServiceDeviceAPI: Sendable {
    func delivery(deliveryId: UUID) async throws -> LinkServiceDelivery
    /// The authority's decision, relayed. Never a grant or a code.
    func submit(deliveryId: UUID, factor: String) async throws -> FactorDecision
}

/// The live client over the device-signed `APIClient`.
public struct LiveLinkServiceDeviceAPI: LinkServiceDeviceAPI {
    let client: APIClient
    public init(client: APIClient) { self.client = client }

    public func delivery(deliveryId: UUID) async throws -> LinkServiceDelivery {
        let client = self.client
        let display: AuthDeliveryDisplay = try await Self.mapped {
            try await client.call(APIRoutes.authDeliveryGet, params: ["deliveryId": AuthDeliveryID(deliveryId).description])
        }
        // The answer must be about this delivery, and a link-service one.
        guard display.id.uuid == deliveryId, display.method == .magicLink, display.linkMode == .viadere else { throw LinkServiceError.notActive }
        if let challenge = display.authorityChallenge, challenge.utf8.count > AuthorityJWS.maxBytes { throw LinkServiceError.notActive }
        let state: AuthLinkDisplay.State
        switch display.status {
        case .created, .validated, .queued, .sent, .delivered: state = .open
        case .opened, .completed, .failed: state = .used
        case .expired: state = .expired
        case .cancelled, .denied: state = .cancelled
        }
        return LinkServiceDelivery(deliveryId: deliveryId, state: state, expiresAt: display.expiresAt, challenge: display.authorityChallenge)
    }

    public func submit(deliveryId: UUID, factor: String) async throws -> FactorDecision {
        let client = self.client
        let response: AuthLinkEvidenceResponse = try await Self.mapped {
            try await client.call(APIRoutes.authDeliveryLinkEvidence, params: ["deliveryId": AuthDeliveryID(deliveryId).description],
                                  body: AuthLinkEvidenceRequest(factor: factor))
        }
        return response.decision
    }

    static func mapped<T: Sendable>(_ call: @Sendable () async throws -> T) async throws -> T {
        do { return try await call() } catch let error as LinkServiceError {
            throw error
        } catch let error as APIError {
            if error.isConnectivityFailure { throw LinkServiceError.offline }
            switch error.code {
            case .unauthorized?, .forbidden?: throw LinkServiceError.refused
            case .gone?, .expired?: throw LinkServiceError.expired
            case .conflict?, .alreadyOpened?, .replayDetected?: throw LinkServiceError.alreadyAnswered
            case .notFound?: throw LinkServiceError.notActive
            case .unavailable?: throw LinkServiceError.unavailable
            default: throw LinkServiceError.refused
            }
        } catch { throw LinkServiceError.offline }
    }
}

/// The default where the build has no client (App Clip, extensions): every call fails closed.
public struct UnavailableLinkServiceDeviceAPI: LinkServiceDeviceAPI {
    public init() {}
    public func delivery(deliveryId: UUID) async throws -> LinkServiceDelivery { throw LinkServiceError.unavailable }
    public func submit(deliveryId: UUID, factor: String) async throws -> FactorDecision { throw LinkServiceError.unavailable }
}

/// A recording fake for tests and previews.
public actor MockLinkServiceDeviceAPI: LinkServiceDeviceAPI {
    public var deliveries: [UUID: LinkServiceDelivery] = [:]
    public var submitError: LinkServiceError?
    public var readError: LinkServiceError?
    public private(set) var submitted: [(deliveryId: UUID, factor: String)] = []

    public init() {}

    public func set(_ delivery: LinkServiceDelivery) { deliveries[delivery.deliveryId] = delivery }
    public func set(submitError: LinkServiceError?) { self.submitError = submitError }
    public func set(readError: LinkServiceError?) { self.readError = readError }

    public func delivery(deliveryId: UUID) async throws -> LinkServiceDelivery {
        if let readError { throw readError }
        guard let delivery = deliveries[deliveryId] else { throw LinkServiceError.notActive }
        return delivery
    }

    public func submit(deliveryId: UUID, factor: String) async throws -> FactorDecision {
        submitted.append((deliveryId, factor))
        if let submitError { throw submitError }
        return try FactorAssertion.parse(factor).claims.decision
    }
}

/// The link-service screen (UX_COPY LS-01 to LS-10). Deny, Approve and This wasn't me carry equal weight (one component, safe actions first);
/// Approve is disabled until the number is complete when the challenge asks for one. Nothing is signed until a tap, "Approved" appears only after
/// the authority accepted the answer, and the only URL ever opened is the same-device hand-off (`LinkServiceHandoff`), once, after that acceptance.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class LinkServiceViewModel {
    public enum Phase: Sendable, Equatable {
        case loading
        case reviewing
        case submitting
        /// Cross device: accepted; nothing opens on the phone.
        case approved
        /// Same device: accepted, and the system opened the signed return URL with the code.
        case opened
        /// Same device: the hand-off could not be made; the code was discarded and the person is told the sign-in did not finish.
        case notFinished
        case denied
        case reported
        /// Three refused numbers: the authority fails the challenge at its third signature-valid wrong number.
        case stopped
        case expired
        case alreadyAnswered
        /// The authority refused a signed answer that needed no number (one generic refusal).
        case refused
        case gone
        case cannotVerify
        case offline
        case noKey
    }

    public static let maxWrongEntries = 3

    public private(set) var phase: Phase = .loading
    public private(set) var display: LinkServiceDisplay?
    public private(set) var entry = ""
    public private(set) var wrongEntries = 0
    public private(set) var notice: String?

    private let deliveryId: UUID
    private let api: any LinkServiceDeviceAPI
    private let signer: any AuthorityFactorSigning
    private let pinnedKeys: [P256.Signing.PublicKey]
    private let revokedKids: Set<String>
    private let environment: AuthorityEnvironment
    private let opener: any SystemURLOpening
    private let clock: @Sendable () -> Date
    private let makeCode: @Sendable () -> String
    private var statement: AuthorityChallengeStatement?
    private var deliveryExpiresAt: Date?
    /// Set once the hand-off was attempted: it is never made twice, whatever happens next.
    private var handedOff = false

    /// - Parameters:
    ///   - opener: the system opener (`UIApplication.open` in the App; never a web view). Called at most once, for the same-device hand-off.
    ///   - makeCode: the same-device link code (32 random bytes, base64url; ADR-0021 §5.3). Replaceable only for tests.
    public init(deliveryId: UUID, api: any LinkServiceDeviceAPI, signer: any AuthorityFactorSigning, pinnedKeys: [P256.Signing.PublicKey],
                revokedKids: Set<String> = [], environment: AuthorityEnvironment, opener: any SystemURLOpening, clock: @escaping @Sendable () -> Date = { Date() },
                makeCode: @escaping @Sendable () -> String = { Base64URL.encode(SecureToken.randomBytes(32)) }) {
        self.deliveryId = deliveryId
        self.api = api
        self.signer = signer
        self.pinnedKeys = pinnedKeys
        self.revokedKids = revokedKids
        self.environment = environment
        self.opener = opener
        self.clock = clock
        self.makeCode = makeCode
    }

    // MARK: Presentation

    public var business: String { display?.business ?? "" }
    public var title: String { display.map { LinkServiceCopy.title(business: $0.business) } ?? "" }
    public var subtitle: String? { display.map { LinkServiceCopy.subtitle(business: $0.business) } }
    public var host: HostPresentation? { display.map { HostPresentation(host: $0.host) } }
    /// The link client's name, shown only when it is not just the business's name again.
    public var service: String? { display.flatMap { $0.client == $0.business ? nil : $0.client } }
    public var asksForNumber: Bool { display?.matchDigits != nil }
    public var numberLabel: String? { asksForNumber ? display.map { LinkServiceCopy.numberLabel(business: $0.business) } : nil }
    public var numberHelp: String? { asksForNumber ? display.map { LinkServiceCopy.numberHelp(business: $0.business) } : nil }

    public var canApprove: Bool {
        guard phase == .reviewing, let display else { return false }
        if let digits = display.matchDigits { return entry.count == digits }
        return true
    }
    public var canRefuse: Bool { phase == .reviewing }

    /// The three answers, one component: equal look, safe actions first, Approve disabled (never hidden) until it can be sent.
    public var buttons: [SafeActionButton] {
        [SafeActionButton(role: .notMe, title: LinkServiceCopy.notMe, isEnabled: canRefuse),
         SafeActionButton(role: .deny, title: LinkServiceCopy.deny, isEnabled: canRefuse),
         SafeActionButton(role: .approve, title: LinkServiceCopy.approve, isEnabled: canApprove)]
    }

    public var message: String? {
        switch phase {
        case .loading, .reviewing, .submitting: return nil
        case .approved: return display.map { LinkServiceCopy.approved(business: $0.business) }
        case .opened: return display.map { LinkServiceCopy.opened(host: $0.host) }
        case .notFinished: return display.map { LinkServiceCopy.notFinished(host: $0.host) }
        case .denied: return LinkServiceCopy.denied
        case .reported: return display.map { LinkServiceCopy.reported(business: $0.business) } ?? LinkServiceCopy.denied
        case .stopped: return display.map { LinkServiceCopy.stopped(business: $0.business) }
        case .expired: return LinkServiceCopy.expired
        case .alreadyAnswered: return LinkServiceCopy.alreadyAnswered
        case .refused: return LinkServiceCopy.refused
        case .gone: return LinkServiceCopy.gone
        case .cannotVerify: return LinkServiceCopy.cannotVerify
        case .offline: return LinkServiceCopy.offline
        case .noKey: return LinkServiceCopy.noKey
        }
    }

    public var offersTryAgain: Bool { phase == .offline }

    /// The number field's rules (`NumberMatcher.applyEdit`): one typed digit at a time or a deletion, ASCII digits only, at most the field length.
    public func setEntry(_ text: String) {
        guard let digits = display?.matchDigits else { return }
        entry = NumberMatcher.applyEdit(previous: entry, proposed: text, digits: digits)
    }

    // MARK: Flow

    /// Fetches and verifies the statement. Signs nothing, consumes nothing.
    public func load() async {
        phase = .loading
        display = nil
        statement = nil
        let fetched: LinkServiceDelivery
        do { fetched = try await api.delivery(deliveryId: deliveryId) } catch let error as LinkServiceError {
            phase = Self.phase(for: error)
            return
        } catch { phase = .gone; return }
        switch fetched.state {
        case .expired: phase = .expired; return
        case .used: phase = .alreadyAnswered; return
        case .cancelled: phase = .gone; return
        case .open: break
        }
        guard fetched.expiresAt > clock() else { phase = .expired; return }
        // Pinned keys only (an empty pin list fails closed), the exact type, issuer, audience and environment, and the link_open display.
        guard let compact = fetched.challenge,
              let verified = try? AuthorityStatementVerifier.verifyChallenge(compact, pinnedKeys: pinnedKeys, revokedKids: revokedKids, environment: environment,
                                                                             now: clock()),
              let shown = LinkServiceDisplay(statement: verified) else {
            phase = .cannotVerify
            return
        }
        guard Int64(clock().timeIntervalSince1970) <= verified.expiresAt else { phase = .expired; return }
        guard await signer.userVerification() != nil else { phase = .noKey; return }
        statement = verified
        display = shown
        deliveryExpiresAt = fetched.expiresAt
        phase = .reviewing
    }

    public func tryAgain() async { await load() }

    public func approve() async {
        guard canApprove, !handedOff, let display else { return }
        let match = display.matchDigits == nil ? nil : entry
        // Same device: a fresh link code, held only in this call; only its hash is signed and sent (the authority records the hash, ADR-0021 §5.3).
        // The hand-off URL is built before anything is signed: a code or return URL that could not be opened exactly as signed is never registered.
        let code = display.matchDigits == nil ? makeCode() : nil
        if let code, LinkServiceHandoff.url(returnURL: display.returnURL, host: display.host, code: code) == nil {
            phase = .notFinished
            return
        }
        let codeHash = code.map { Base64URL.encode(Data(SHA256.hash(data: Data($0.utf8)))) }
        guard let outcome = await answer(.approve, match: match, codeHash: codeHash) else { return }
        switch outcome {
        case .approve:
            if let code { await handOff(code: code, display: display) } else { phase = .approved }
        case .deny, .report:
            phase = .denied
        }
    }

    /// ADR-0021 §5.3, only after the authority accepted this approval: opens `<signed return_url>#vdr_code=<code>` once through the system opener.
    /// Nothing is logged. If the request ran out meanwhile, the URL is not exactly the signed one, or the system cannot open it, the code is dropped
    /// (it lives only in this call) and the person is told the sign-in did not finish.
    private func handOff(code: String, display: LinkServiceDisplay) async {
        guard !handedOff else { return }
        handedOff = true
        let now = clock()
        guard let statement, Int64(now.timeIntervalSince1970) <= statement.expiresAt, let deliveryExpiresAt, now < deliveryExpiresAt,
              let url = LinkServiceHandoff.url(returnURL: display.returnURL, host: display.host, code: code) else {
            phase = .notFinished
            return
        }
        phase = await opener.open(url) ? .opened : .notFinished
    }

    public func deny() async {
        guard canRefuse, !handedOff, await answer(.deny, match: nil, codeHash: nil) != nil else { return }
        phase = .denied
    }

    public func thisWasntMe() async {
        guard canRefuse, !handedOff, await answer(.report, match: nil, codeHash: nil) != nil else { return }
        phase = .reported
    }

    /// Signs and sends one answer. A refused approve with a number counts as a wrong number (one generic refusal); the third ends the screen.
    private func answer(_ decision: FactorDecision, match: String?, codeHash: String?) async -> FactorDecision? {
        guard let statement, let uv = await signer.userVerification() else { phase = .noKey; return nil }
        guard Int64(clock().timeIntervalSince1970) <= statement.expiresAt else { phase = .expired; return nil }
        phase = .submitting
        notice = nil
        let factor: String
        do {
            let claims = try FactorAssertionClaims.answering(statement, decision: decision, userVerification: uv, match: match, codeHash: codeHash, now: clock())
            factor = try await signer.sign(claims, prompt: SigningPrompt(reason: title.isEmpty ? "Confirm it's you" : title))
        } catch {
            // Cancelled Face ID or no usable key: nothing was sent; the person can try again.
            phase = .reviewing
            return nil
        }
        do {
            return try await api.submit(deliveryId: deliveryId, factor: factor)
        } catch let error as LinkServiceError {
            if error == .refused, decision == .approve, match != nil {
                wrongEntries += 1
                entry = ""
                if wrongEntries >= Self.maxWrongEntries {
                    phase = .stopped
                } else {
                    notice = display.map { LinkServiceCopy.wrongNumber(business: $0.business) }
                    phase = .reviewing
                }
            } else {
                phase = Self.phase(for: error)
            }
            return nil
        } catch {
            phase = .offline
            return nil
        }
    }

    private static func phase(for error: LinkServiceError) -> Phase {
        switch error {
        case .offline: .offline
        case .expired: .expired
        case .alreadyAnswered: .alreadyAnswered
        case .refused: .refused
        case .notActive, .unavailable: .gone
        }
    }
}
