import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

/// Confirm before redeem for the legacy `/h/` hand-off (F-08, ADR-0021 §4 item 4): handling the universal link never redeems it.
///
/// The token says nothing about who sent it until it is redeemed, so this screen names no business: it says where the link came from,
/// that opening uses it up, and offers **Open** and **This wasn't me** (equal prominence, safe action first). When the hand-off is retired
/// (ADR-0027 §4), `LegacyHandoffPolicy.isRetired` makes the screen the "no longer used" notice, which never redeems either (ST-ML-14).
public enum LegacyHandoffPolicy {
    /// Flip when ADR-0027's retirement ships: `/l/` and `/h/` then show S-LINK-10 and never call `redeemHandoff`.
    public static let isRetired = false
}

@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class HandoffConfirmationViewModel {
    public enum Phase: Sendable, Equatable {
        case confirming
        case redeeming
        /// Redeemed; the App routes to `HandoffRedeemResponse.purpose`.
        case redeemed(HandoffRedeemResponse)
        case dismissedAsNotMe
        case expired
        /// ADR-0027: the link is no longer used.
        case retired
    }

    public private(set) var phase: Phase
    public let token: String
    private let api: any ViadereAPI

    public init(token: String, api: any ViadereAPI, retired: Bool = LegacyHandoffPolicy.isRetired) {
        self.token = token
        self.api = api
        phase = retired ? .retired : .confirming
    }

    public var title: String { phase == .retired ? AuthDeliveryCopy.linkRetired : AuthDeliveryCopy.handoffTitle }
    public var body: String? { phase == .confirming ? AuthDeliveryCopy.handoffBody : nil }

    public var buttons: [SafeActionButton] {
        guard phase == .confirming || phase == .redeeming else { return [] }
        return [SafeActionButton(role: .notMe, title: AuthDeliveryCopy.notMe, isEnabled: phase == .confirming),
                SafeActionButton(role: .proceed, title: AuthDeliveryCopy.open, isEnabled: phase == .confirming)]
    }

    public var message: String? {
        switch phase {
        case .dismissedAsNotMe: return AuthDeliveryCopy.handoffNotMeDone
        case .expired: return AuthDeliveryCopy.handoffExpired
        default: return nil
        }
    }

    /// The only place a hand-off token is redeemed: an explicit tap on Open.
    public func open() async {
        guard phase == .confirming else { return }
        phase = .redeeming
        do { phase = .redeemed(try await api.redeemHandoff(token: token)) } catch { phase = .expired }
    }

    /// "This wasn't me" on a hand-off: the token is simply never redeemed (there is no business to tell yet).
    public func thisWasntMe() {
        guard phase == .confirming else { return }
        phase = .dismissedAsNotMe
    }
}
