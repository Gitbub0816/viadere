import Crypto
import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

/// UX_COPY OIDC-05, OIDC-08 to OIDC-10 (the phone side of "Sign in with Viadere").
public enum OIDCCopy {
    /// OIDC-08 title.
    public static func title(client: String) -> String { "Sign in to \(client)?" }
    /// OIDC-08 row label (the value is the redirect host).
    public static let websiteLabel = "Website"
    /// OIDC-08 subtitle.
    public static let subtitle = "Only approve if you opened this page yourself."
    /// OIDC-05, shown on first use of a client by this account (ADR-0024 §8).
    public static func consent(client: String, host: String) -> String {
        "\(client) wants to confirm it's you. It gets an ID that only \(client) can use. It doesn't get your name, email or phone number, and other apps "
            + "can't match it. You'll return to \(host)."
    }
    public static let numberLabel = "Number shown on the website"
    public static func numberHelp(digits: Int) -> String { "Enter the \(digits)-digit number shown on the website." }
    public static let deny = "Deny"
    public static let approve = "Approve"
    /// OIDC-08 footer.
    public static let notMe = "This wasn't me"
    public static let wrongNumber = "That number doesn't match the one on the website. Check it and try again."
    public static let stopped = "This sign-in was stopped after three wrong numbers. Start again on the website."
    public static func approved(client: String) -> String { "Approved. Go back to the website to finish signing in to \(client)." }
    public static let denied = "Denied. Nobody was signed in."
    public static let reported = "Thanks for telling us. Nobody was signed in."
    public static let expired = "This sign-in request expired. Start again on the website."
    public static let gone = "This sign-in request is no longer active."
    /// E-01 for an authority-backed flow (FLOW_MATRIX note 15): the statement could not be verified, nothing was shown or signed.
    public static let cannotVerify = "We couldn't confirm this sign-in request came from Viadere. Nothing was approved."
    public static let offline = "You're offline. Nothing was sent. Try again when you're connected."
    public static let noKey = "This device can't approve sign-ins yet."

    /// OIDC-09.
    public static let listTitle = "Apps you've signed in to with Viadere"
    public static func listRow(client: String, lastUsed: String) -> String { "\(client), last used \(lastUsed)" }
    public static let listEmpty = "You haven't signed in to any apps with Viadere."
    /// OIDC-10.
    public static func revoke(client: String) -> String { "Stop \(client) recognizing me" }
    public static func revokeConfirm(client: String) -> String {
        "\(client) won't be listed here any more. The next time you sign in to \(client) with Viadere, you'll be asked again."
    }
}

/// What the phone shows for a verified `oidc_login` statement: only values from the authority-built, authority-signed display.
public struct OIDCSignInDisplay: Sendable, Equatable {
    public var clientName: String
    public var host: String
    public var redirectURI: String
    public var matchDigits: Int

    /// Strict: purpose `oidc_login`, exactly the members the authority builds, a redirect host equal to the host of the signed `redirect_uri`,
    /// and a 2-digit number field (ADR-0033 §1, ADR-0022 §2). Anything else is refused (the screen never improvises).
    public init?(statement: AuthorityChallengeStatement) {
        guard statement.purpose == .oidcLogin, statement.matchRequired, let redirect = statement.redirectURI, case .object(let o) = statement.display,
              Set(o.keys) == ["v", "purpose", "client_name", "redirect_uri", "redirect_host", "match_digits"], o["v"]?.authorityInteger == 1,
              let name = o["client_name"]?.stringValue, !name.isEmpty, name.count <= 60, o["redirect_uri"]?.stringValue == redirect,
              let host = o["redirect_host"]?.stringValue, host == URLComponents(string: redirect)?.host?.lowercased(), !host.isEmpty,
              o["match_digits"]?.authorityInteger == 2 else { return nil }
        clientName = name
        self.host = host
        redirectURI = redirect
        matchDigits = 2
    }
}

/// The confirm screen of the OIDC app path (UX_COPY OIDC-08; FLOW_MATRIX F13): opened from the QR universal link or a `login_hint` push.
/// The phone types the number shown on the website and never displays it; Deny and Approve are one component, Deny first; "This wasn't me"
/// is in the footer. Nothing is signed until the person taps, and "Approved" is shown only after the authority accepted the answer.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class OIDCSignInViewModel {
    public enum Phase: Sendable, Equatable {
        case loading
        case reviewing
        case submitting
        case approved
        case denied
        case reported
        /// Three refused numbers: the authority fails the challenge at its third signature-valid wrong number (ADR-0023 §3 step 6).
        case stopped
        case expired
        case gone
        case cannotVerify
        case offline
        case noKey
    }

    public static let maxWrongEntries = 3

    public private(set) var phase: Phase = .loading
    public private(set) var display: OIDCSignInDisplay?
    /// OIDC-05 is shown when this account has no consent for this client (or the list could not be read: then it is shown too).
    public private(set) var showsConsent = true
    public private(set) var entry = ""
    public private(set) var wrongEntries = 0
    public private(set) var notice: String?

    private let challengeId: String
    private let api: any OIDCDeviceAPI
    private let signer: any AuthorityFactorSigning
    private let pinnedKeys: [P256.Signing.PublicKey]
    private let revokedKids: Set<String>
    private let environment: AuthorityEnvironment
    private let clock: @Sendable () -> Date
    private var statement: AuthorityChallengeStatement?

    public init(challengeId: String, api: any OIDCDeviceAPI, signer: any AuthorityFactorSigning, pinnedKeys: [P256.Signing.PublicKey],
                revokedKids: Set<String> = [], environment: AuthorityEnvironment, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.challengeId = challengeId
        self.api = api
        self.signer = signer
        self.pinnedKeys = pinnedKeys
        self.revokedKids = revokedKids
        self.environment = environment
        self.clock = clock
    }

    // MARK: Presentation

    public var title: String { display.map { OIDCCopy.title(client: $0.clientName) } ?? "" }
    public var consentText: String? { showsConsent ? display.map { OIDCCopy.consent(client: $0.clientName, host: $0.host) } : nil }
    public var host: HostPresentation? { display.map { HostPresentation(host: $0.host) } }
    public var numberHelp: String { OIDCCopy.numberHelp(digits: display?.matchDigits ?? 2) }
    public var canApprove: Bool { phase == .reviewing && display.map { entry.count == $0.matchDigits } == true }
    public var canRefuse: Bool { phase == .reviewing }

    public var message: String? {
        switch phase {
        case .loading, .reviewing, .submitting: return nil
        case .approved: return display.map { OIDCCopy.approved(client: $0.clientName) }
        case .denied: return OIDCCopy.denied
        case .reported: return OIDCCopy.reported
        case .stopped: return OIDCCopy.stopped
        case .expired: return OIDCCopy.expired
        case .gone: return OIDCCopy.gone
        case .cannotVerify: return OIDCCopy.cannotVerify
        case .offline: return OIDCCopy.offline
        case .noKey: return OIDCCopy.noKey
        }
    }

    /// The number field's rules (`NumberMatcher.applyEdit`, ADR-0022 §2.3): one typed digit at a time or a deletion, ASCII digits only, no
    /// leading zero, at most the field length; a paste or a replacement leaves the entry unchanged.
    public func setEntry(_ text: String) {
        entry = NumberMatcher.applyEdit(previous: entry, proposed: text, digits: display?.matchDigits ?? 2)
    }

    // MARK: Flow

    /// Fetches and verifies the statement. Signs nothing.
    public func load() async {
        phase = .loading
        let compact: String
        do { compact = try await api.statement(challengeId: challengeId) } catch let error as OIDCDeviceError {
            phase = error == .offline ? .offline : .gone
            return
        } catch { phase = .gone; return }
        // Pinned keys only (empty pin list: fail closed), the exact type, issuer, audience and environment, and this challenge.
        guard let verified = try? AuthorityStatementVerifier.verifyChallenge(compact, pinnedKeys: pinnedKeys, revokedKids: revokedKids, environment: environment,
                                                                             now: clock()),
              verified.challengeId == challengeId, let shown = OIDCSignInDisplay(statement: verified) else {
            phase = .cannotVerify
            return
        }
        guard Int64(clock().timeIntervalSince1970) <= verified.expiresAt else { phase = .expired; return }
        guard await signer.userVerification() != nil else { phase = .noKey; return }
        statement = verified
        display = shown
        if let consents = try? await api.consents() {
            showsConsent = !consents.contains { $0.clientName == shown.clientName && $0.host == shown.host }
        } else {
            showsConsent = true
        }
        phase = .reviewing
    }

    public func approve() async {
        guard canApprove else { return }
        let typed = entry
        guard let outcome = await answer(.approve, match: typed) else { return }
        switch outcome {
        case .approve: phase = .approved
        case .deny, .report: phase = .denied
        }
    }

    public func deny() async {
        guard canRefuse, await answer(.deny, match: nil) != nil else { return }
        phase = .denied
    }

    public func thisWasntMe() async {
        guard canRefuse, await answer(.report, match: nil) != nil else { return }
        phase = .reported
    }

    /// Signs and sends one answer. A refused approve counts as a wrong number (the authority gives one generic refusal); the third ends the screen.
    private func answer(_ decision: FactorDecision, match: String?) async -> FactorDecision? {
        guard let statement, let uv = await signer.userVerification() else { phase = .noKey; return nil }
        guard Int64(clock().timeIntervalSince1970) <= statement.expiresAt else { phase = .expired; return nil }
        phase = .submitting
        notice = nil
        let factor: String
        do {
            let claims = try FactorAssertionClaims.answering(statement, decision: decision, userVerification: uv, match: match, now: clock())
            factor = try await signer.sign(claims, prompt: SigningPrompt(reason: display.map { OIDCCopy.title(client: $0.clientName) } ?? "Confirm it's you"))
        } catch {
            // Cancelled Face ID or no usable key: nothing was sent; the person can try again.
            phase = .reviewing
            return nil
        }
        do {
            return try await api.submit(challengeId: challengeId, factor: factor)
        } catch let error as OIDCDeviceError {
            switch error {
            case .offline: phase = .offline
            case .notActive: phase = .gone
            case .unavailable: phase = .gone
            case .refused:
                guard decision == .approve else { phase = .gone; return nil }
                wrongEntries += 1
                entry = ""
                if wrongEntries >= Self.maxWrongEntries {
                    phase = .stopped
                } else {
                    notice = OIDCCopy.wrongNumber
                    phase = .reviewing
                }
            }
            return nil
        } catch {
            phase = .offline
            return nil
        }
    }
}

/// Settings → "Apps you've signed in to with Viadere" (UX_COPY OIDC-09, OIDC-10; ADR-0024 §8). Revoking only removes the consent (reduce-only).
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class OIDCConsentsViewModel {
    public enum Phase: Sendable, Equatable { case loading, loaded, failed, unavailable }

    public private(set) var phase: Phase = .loading
    public private(set) var consents: [OIDCConsentView] = []
    public private(set) var notice: String?
    private let api: any OIDCDeviceAPI

    public init(api: any OIDCDeviceAPI) { self.api = api }

    public var title: String { OIDCCopy.listTitle }
    public var emptyText: String { OIDCCopy.listEmpty }

    /// Names are display text from the authority's reviewed registration, still treated as untrusted text on the device.
    public func name(_ consent: OIDCConsentView) -> String { UntrustedText.name(consent.clientName, max: 60, attribution: nil).text }
    public func row(_ consent: OIDCConsentView, formatter: (Date) -> String) -> String { OIDCCopy.listRow(client: name(consent), lastUsed: formatter(consent.lastUsedAt)) }
    public func revokeTitle(_ consent: OIDCConsentView) -> String { OIDCCopy.revoke(client: name(consent)) }
    public func revokeConfirmation(_ consent: OIDCConsentView) -> String { OIDCCopy.revokeConfirm(client: name(consent)) }

    public func load() async {
        phase = .loading
        do {
            consents = try await api.consents().sorted { $0.lastUsedAt > $1.lastUsedAt }
            phase = .loaded
        } catch OIDCDeviceError.unavailable {
            phase = .unavailable
        } catch {
            phase = .failed
        }
    }

    /// Called only after the person confirmed. On success the row disappears; on failure it stays and a notice says nothing changed.
    public func revoke(_ consent: OIDCConsentView) async {
        notice = nil
        do {
            _ = try await api.revokeConsent(clientId: consent.clientId)
            consents.removeAll { $0.clientId == consent.clientId }
        } catch {
            notice = "We couldn't remove \(name(consent)). Nothing changed. Try again."
        }
    }
}
