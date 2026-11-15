import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

/// The state behind "Add business" by link session (WP-C1): look the code up, show the verified business and what it asks for, link, then show the six
/// digits and the account pseudonym to compare in the business's page, and wait for its confirmation. All crypto lives in `LinkSessionFlow`.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class LinkController {
    public enum Phase: Equatable, Sendable { case idle, working }

    public private(set) var phase: Phase = .idle
    public private(set) var offer: LinkOffer?
    public private(set) var completion: LinkCompletion?
    public private(set) var outcome: LinkOutcome?
    public private(set) var message: String?

    private let flow: LinkSessionFlow?

    public init(flow: LinkSessionFlow?) { self.flow = flow }

    /// False when the build pins no `link-descriptor` key or transparency-log key: linking stays closed rather than trusting the network.
    public var isAvailable: Bool { flow?.isConfigured ?? false }

    public func reset() {
        offer = nil
        completion = nil
        outcome = nil
        message = nil
    }

    public func lookup(code: String, secret: LinkSessionSecret?, checkCode: String?) async {
        reset()
        guard let flow, flow.isConfigured else { message = LinkText.notAvailable; return }
        phase = .working
        defer { phase = .idle }
        do { offer = try await flow.lookup(code: code, secret: secret, checkCode: checkCode) } catch { message = LinkText.describe(error) }
    }

    /// The person confirmed in the sheet. Returns whether the link was sent.
    @discardableResult
    public func confirm() async -> Bool {
        guard let flow, let offer else { return false }
        phase = .working
        defer { phase = .idle }
        do {
            completion = try await flow.link(offer)
            outcome = .waiting
            return true
        } catch {
            message = LinkText.describe(error)
            return false
        }
    }

    /// Asks once whether the business confirmed (the sheet calls it while it shows the digits, and the app on foreground).
    public func refresh() async {
        guard let flow, let completion else { return }
        do {
            let result = try await flow.refresh(sessionId: completion.sessionId)
            outcome = result
            switch result {
            case .substitutionDetected: message = LinkText.substitution
            case .expired: message = LinkText.expired(completion.businessName)
            case .linked, .waiting: break
            }
        } catch { message = LinkText.describe(error) }
    }
}

/// The words of the link flow (Viadere's own: never business-supplied).
public enum LinkText {
    public static let notAvailable = "Linking a business isn't available in this version of Viadere."
    public static let substitution = "The business confirmed a different link than the one on this phone, so we removed it. Nothing was linked."
    public static func expired(_ business: String) -> String { "\(business) didn't confirm the link in time, so nothing was linked. Ask for a new code." }

    public static func capability(_ capability: Capability) -> String {
        switch capability {
        case .messageSend: "Send you messages about your account"
        case .contactReachable: "Check that they can reach you"
        case .consentRequest: "Ask for your consent"
        case .authChallenge: "Ask you to approve sign-ins"
        case .transactionApprove: "Ask you to approve payments and transfers"
        default: "Something this version of Viadere doesn't know"
        }
    }

    static func describe(_ error: any Error) -> String {
        switch error as? LinkError {
        case .notConfigured?: return notAvailable
        case .secretRequired?: return "Scan the business's code, or type both of its codes."
        case .descriptorInvalid?: return "We couldn't verify this code. Don't continue, and ask the business for a new one."
        case .businessMismatch?: return "This code doesn't match the business's published keys. Don't continue."
        case .businessNotReady?: return "This business isn't ready to link accounts yet."
        case .deviceCannotSatisfy?: return "Set up Face ID or Touch ID to link this business."
        case .userCancelled?: return "Linking was cancelled."
        case .substitutionDetected?: return substitution
        case .expired?: return "This code has expired. Ask the business for a new one."
        case .api(let api)?:
            switch api.code {
            case .notFound?: return "That code isn't valid or has already been used."
            case .gone?: return "This code has expired. Ask the business for a new one."
            case .conflict?: return "This code was already used."
            case .deviceCoolDown?: return "Approve this iPhone from a device you already trust before linking approvals."
            default: return api.userMessage
            }
        case .directory?, .keysUnavailable?, nil: return "We couldn't link this business. Try again."
        }
    }
}
