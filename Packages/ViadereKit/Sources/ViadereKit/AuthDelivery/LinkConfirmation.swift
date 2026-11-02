import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

// Confirm before open (ADR-0021 §4, ADR-0031 §4, UX_COPY §2; fixes F-08's pattern for every hand-off).
//
// Nothing here consumes a token or opens a URL on its own. The screen shows the verified business, the destination host and the expiry;
// only an explicit Continue asks the service for the URL (device-signed), re-checks it on the device and opens it through the system.
// "This wasn't me" is a signed, reduce-only answer. When the destination cannot be verified, Continue never enables (fail closed).

/// The result of checking a business-signed destination on the device (ADR-0031 §4).
public enum DestinationCheck: Sendable, Equatable {
    /// The signature, the tenant record and the host all checked out: this host is the business's.
    case verified(host: String)
    /// The host is not one the business verified (S-LINK-08).
    case wrongDestination
    /// The signature failed or is missing (S-LINK-09). Sends `destination_unverified`; never counts toward a pause.
    case signatureFailed
    /// The tenant record is stale or unavailable: the delivery stays open, nothing is sent (S-LINK-11).
    case unavailable
    /// The device clock is outside the allowed window (S-LINK-12).
    case clockOutsideWindow
    /// This build cannot verify business-signed destinations yet (Stage 6): fails closed like `signatureFailed`, but it is not evidence
    /// of tampering, so nothing is reported to the business.
    case notYetSupported
}

/// Verifies the business-signed destination of a link (ADR-0031: `viadere-destination+jws` against the authority-signed tenant record).
public protocol DestinationVerifying: Sendable {
    func verify(_ display: AuthLinkDisplay) async -> DestinationCheck
}

/// What ships until Stage 6 delivers the authority tenant record: nothing is verifiable, so every business link fails closed with
/// S-LINK-09 ("We couldn't confirm this link came from the business. We didn't open it.").
public struct FailClosedDestinationVerifier: DestinationVerifying {
    public init() {}
    public func verify(_ display: AuthLinkDisplay) async -> DestinationCheck { .notYetSupported }
}

/// Opens a verified URL with the system. The App implements it with `UIApplication.open` from the foreground; never a web view.
public protocol SystemURLOpening: Sendable {
    @MainActor func open(_ url: URL) async -> Bool
}

/// How a host is laid out on the link screen (UX_COPY S-LINK-01, ADR-0021 §3 item 5): the full host, never truncated, with its registrable
/// domain in strong type, and any `xn--` label shown as is with a note.
public struct HostPresentation: Sendable, Equatable {
    public var full: String
    /// The registrable domain in strong type. Without the public-suffix list in the Kit this is the last two labels (three when the second
    /// to last is a common second-level suffix such as `co`); the full host is always shown beside it, so the approximation cannot hide a label.
    public var strong: String
    /// The labels in front of the strong part, shown in regular type (`login.` in `login.example.com`).
    public var prefix: String
    public var hasUnusualCharacters: Bool

    public init(host rawHost: String) {
        let host = rawHost.lowercased()
        full = host
        let labels = host.split(separator: ".", omittingEmptySubsequences: false).map(String.init)
        hasUnusualCharacters = labels.contains { $0.hasPrefix("xn--") }
        let secondLevel: Set<String> = ["co", "com", "org", "net", "gov", "edu", "ac"]
        var keep = min(2, labels.count)
        if labels.count >= 3, let second = labels.dropLast().last, second.count <= 3, secondLevel.contains(second), labels.last?.count == 2 { keep = 3 }
        strong = labels.suffix(keep).joined(separator: ".")
        let rest = labels.dropLast(keep)
        prefix = rest.isEmpty ? "" : rest.joined(separator: ".") + "."
    }
}

/// The sign-in link screen (S-LINK-01 and the failure screens).
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class LinkConfirmationViewModel {
    public enum Phase: Sendable, Equatable {
        case loading
        /// The question is on screen. `canContinue` is true only after the destination check passed.
        case reviewing
        case opening
        case opened(host: String)
        case reported
        case expired
        case alreadyUsed
        /// S-LINK-08 / S-LINK-09: nothing was opened and nothing will be.
        case notOpened(Reason)
        /// S-LINK-11 / S-LINK-12 with a Try again button.
        case cannotCheck(clock: Bool)
        /// The delivery is gone (cancelled or unknown): E-03.
        case gone
        /// The service could not be reached (E-02 / S-MFA-11 style). Nothing was queued.
        case offline
    }

    public enum Reason: Sendable, Equatable { case wrongDestination, signatureFailed }

    public private(set) var phase: Phase = .loading
    public private(set) var display: AuthLinkDisplay?
    public private(set) var destinationVerified = false

    private let deliveryId: UUID
    private let api: any AuthDeliveryAPI
    private let verifier: any DestinationVerifying
    private let opener: any SystemURLOpening
    private let clock: @Sendable () -> Date
    private var verifiedHost: String?

    public init(deliveryId: UUID, api: any AuthDeliveryAPI, verifier: any DestinationVerifying = FailClosedDestinationVerifier(),
                opener: any SystemURLOpening, clock: @escaping @Sendable () -> Date = { Date() }) {
        self.deliveryId = deliveryId
        self.api = api
        self.verifier = verifier
        self.opener = opener
        self.clock = clock
    }

    // MARK: Presentation

    public var business: String { UntrustedText.name(display?.business ?? "", max: 40, attribution: nil).text }
    public var host: HostPresentation? { display.map { HostPresentation(host: $0.host) } }
    public var title: String { AuthDeliveryCopy.linkTitle(business: business) }
    public var body: String? { host.map { AuthDeliveryCopy.linkBody(business: business, host: $0.full) } }
    public var footnote: String { AuthDeliveryCopy.linkFootnote(business: business) }
    public var unusualHostNote: String? { host?.hasUnusualCharacters == true ? AuthDeliveryCopy.unusualHost : nil }
    public var continueAccessibilityLabel: String { "Continue to \(host?.full ?? "")" }

    public func expiryLine(formatter: (Date) -> String) -> String? { display.map { AuthDeliveryCopy.expiresAt(formatter($0.expiresAt)) } }

    /// The buttons, one component: identical weight, safe action first (UX_COPY §0.2).
    public var buttons: [SafeActionButton] {
        [SafeActionButton(role: .notMe, title: AuthDeliveryCopy.notMe, isEnabled: canReport),
         SafeActionButton(role: .proceed, title: AuthDeliveryCopy.continueTitle, isEnabled: canContinue)]
    }

    public var canContinue: Bool { phase == .reviewing && destinationVerified }
    public var canReport: Bool {
        switch phase {
        case .reviewing, .notOpened: return true
        default: return false
        }
    }

    /// The line the screen shows for the current phase, when it is not the main question.
    public var message: String? {
        switch phase {
        case .loading, .reviewing, .opening: return nil
        case .opened(let host): return AuthDeliveryCopy.linkOpened(host: host)
        case .reported: return AuthDeliveryCopy.linkReported(business: business)
        case .expired: return AuthDeliveryCopy.linkExpired(business: business)
        case .alreadyUsed: return AuthDeliveryCopy.linkUsed(business: business)
        case .notOpened(.wrongDestination): return AuthDeliveryCopy.linkWrongDestination(business: business)
        case .notOpened(.signatureFailed): return AuthDeliveryCopy.linkSignatureFailed(business: business)
        case .cannotCheck(let clock): return clock ? AuthDeliveryCopy.linkClock : AuthDeliveryCopy.linkCannotCheck
        case .gone: return AuthDeliveryCopy.noLongerActive
        case .offline: return AuthDeliveryCopy.offline
        }
    }

    public var offersTryAgain: Bool {
        switch phase {
        case .cannotCheck, .offline: return true
        default: return false
        }
    }

    // MARK: Flow

    /// Fetches the display and checks the destination. Consumes nothing and opens nothing.
    public func load() async {
        phase = .loading
        destinationVerified = false
        verifiedHost = nil
        let fetched: AuthLinkDisplay
        do { fetched = try await api.linkDisplay(deliveryId: deliveryId) } catch let error as AuthDeliveryError {
            phase = error == .offline ? .offline : .gone
            return
        } catch { phase = .gone; return }
        display = fetched
        switch fetched.state {
        case .expired: phase = .expired; return
        case .used: phase = .alreadyUsed; return
        case .cancelled: phase = .gone; return
        case .open: break
        }
        guard fetched.expiresAt > clock() else { phase = .expired; return }
        switch await verifier.verify(fetched) {
        case .verified(let host) where host.lowercased() == fetched.host.lowercased():
            destinationVerified = true
            verifiedHost = host.lowercased()
            phase = .reviewing
        case .verified: phase = .notOpened(.wrongDestination)
        case .wrongDestination: phase = .notOpened(.wrongDestination)
        case .signatureFailed:
            phase = .notOpened(.signatureFailed)
            // An integrity failure is reported once (never counts toward a pause, ADR-0022 §5.4); a failure to *check* is not.
            await reportDestinationFailure()
        case .notYetSupported: phase = .notOpened(.signatureFailed)
        case .unavailable: phase = .cannotCheck(clock: false)
        case .clockOutsideWindow: phase = .cannotCheck(clock: true)
        }
    }

    public func tryAgain() async { await load() }

    /// Continue: the only path that asks for the URL, and only when the destination was verified for this host.
    public func proceed() async {
        guard canContinue, let host = verifiedHost, let display, display.expiresAt > clock() else {
            if phase == .reviewing, let display, display.expiresAt <= clock() { phase = .expired }
            return
        }
        phase = .opening
        let url: URL
        do { url = try await api.openLink(deliveryId: deliveryId) } catch let error as AuthDeliveryError {
            switch error {
            case .expired: phase = .expired
            case .alreadyUsed: phase = .alreadyUsed
            case .offline: phase = .offline
            default: phase = .gone
            }
            return
        } catch { phase = .gone; return }
        // The URL the service returned must still be the verified host, over https, with no userinfo or non-default port: re-checked here,
        // on the device, right before it is opened (ADR-0031 §4: the device checks the URL bytes against the signed digest).
        guard Self.isAcceptable(url, host: host) else {
            phase = .notOpened(.signatureFailed)
            await reportDestinationFailure()
            return
        }
        if await opener.open(url) {
            phase = .opened(host: host)
        } else {
            // The system declined to open it (no handler): nothing else is tried, and the link is not retried silently.
            phase = .notOpened(.wrongDestination)
        }
    }

    /// "This wasn't me": a signed, reduce-only report. Never needs the destination check.
    public func thisWasntMe() async {
        guard canReport else { return }
        do {
            try await api.reduce(.delivery(deliveryId), action: .report)
            phase = .reported
        } catch let error as AuthDeliveryError {
            phase = error == .offline ? .offline : (error == .expired ? .expired : .gone)
        } catch { phase = .gone }
    }

    private func reportDestinationFailure() async {
        // `deny_reason: destination_unverified` (ADR-0022 §5.4: never counts toward a pause).
        try? await api.reduce(.delivery(deliveryId), action: .denyDestinationUnverified)
    }

    nonisolated static func isAcceptable(_ url: URL, host: String) -> Bool {
        guard url.scheme?.lowercased() == "https", let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              components.user == nil, components.password == nil, components.port == nil || components.port == 443,
              components.host?.lowercased() == host, !url.absoluteString.contains("\\"), url.absoluteString.utf8.count <= 2048 else { return false }
        return true
    }
}

/// A button of the equal-prominence pair (UX_COPY §0.2, ADR-0022 §2.5).
public struct SafeActionButton: Sendable, Equatable, Identifiable {
    public enum Role: String, Sendable, Equatable { case deny, notMe, approve, proceed }
    /// One look for every button of the pair: no red on the safe action, no filled primary on the affirmative one.
    public enum Style: String, Sendable, Equatable { case neutralEqual }

    public var id: String { role.rawValue }
    public var role: Role
    public var title: String
    /// Disabled, never hidden (Approve until the number is complete).
    public var isEnabled: Bool
    public var style: Style = .neutralEqual

    public init(role: Role, title: String, isEnabled: Bool) {
        self.role = role
        self.title = title
        self.isEnabled = isEnabled
    }
}
