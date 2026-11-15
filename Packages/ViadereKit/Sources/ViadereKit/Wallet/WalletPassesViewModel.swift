import Foundation
import ViadereCore
#if canImport(Observation) && !os(Linux)
import Observation
#endif

/// How one pass reads in the app: the list row, the detail header and the code panel. Pure, so it is tested on Linux.
public struct WalletPassPresentation: Equatable, Sendable {
    public enum Status: Equatable, Sendable {
        /// Wallet is available and the pass is not in it yet.
        case readyToAdd
        case inWallet
        /// This device can't hold passes: the in-app code is the way to show it.
        case appOnly
        case checkedIn(Date)
        case voided
    }

    public var kindTitle: String
    /// SF Symbol name (no shield imagery).
    public var symbol: String
    public var businessName: String
    public var status: Status
    public var statusText: String
    /// The code to draw as a QR, when showing it makes sense: a valid, well-formed code on a pass that was not used or voided.
    public var scanCode: String?
    public var codeInstructions: String?
    public var accessibilityLabel: String

    /// Never-empty title for a kind.
    public static func kindTitle(_ kind: WalletPassKind) -> String {
        switch kind {
        case .storeCard: "Loyalty card"
        case .coupon: "Offer"
        case .eventTicket: "Ticket"
        case .boardingPass: "Boarding pass"
        case .generic: "Reservation"
        }
    }

    public static func symbol(_ kind: WalletPassKind) -> String {
        switch kind {
        case .storeCard: "wallet.pass"
        case .coupon: "tag"
        case .eventTicket: "ticket"
        case .boardingPass: "airplane"
        case .generic: "calendar"
        }
    }

    public static func make(_ pass: WalletPassMetadata, walletState: WalletPassState, businessName: String?, now: Date) -> WalletPassPresentation {
        let kind = kindTitle(pass.kind)
        let business = businessName.flatMap { $0.isEmpty ? nil : $0 } ?? "A business you're connected to"
        let status: Status
        if pass.voided || walletState == .voided {
            status = .voided
        } else if let used = pass.usedAt {
            status = .checkedIn(used)
        } else {
            switch walletState {
            case .inWallet: status = .inWallet
            case .notInWallet: status = .readyToAdd
            case .unavailable, .voided: status = .appOnly
            }
        }
        let statusText: String = switch status {
        case .readyToAdd: "Not in Wallet yet"
        case .inWallet: "In Wallet"
        case .appOnly: "Show it from this app"
        case .checkedIn(let date): "Checked in \(Self.short(date, now: now))"
        case .voided: "No longer valid"
        }
        var code: String?
        switch status {
        case .readyToAdd, .inWallet, .appOnly:
            if let raw = pass.scanCode, WalletScanCode.isWellFormed(raw) { code = raw.trimmingCharacters(in: .whitespacesAndNewlines) }
        case .checkedIn, .voided:
            code = nil
        }
        let instructions: String? = code.map { _ in
            switch pass.kind {
            case .storeCard: "Show this at the counter so \(business) can find your membership."
            case .coupon: "Show this at the counter. It works once; \(business) scans it to apply the offer."
            case .eventTicket, .boardingPass: "Show this at the entrance. It admits once."
            case .generic: "Show this when you arrive. It checks you in once."
            }
        }
        return WalletPassPresentation(kindTitle: kind, symbol: symbol(pass.kind), businessName: business, status: status, statusText: statusText,
                                      scanCode: code, codeInstructions: instructions,
                                      accessibilityLabel: "\(kind) from \(business). \(statusText).")
    }

    private static func short(_ date: Date, now: Date) -> String {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = .current
        let calendar = Calendar.current
        formatter.dateFormat = calendar.isDate(date, inSameDayAs: now) ? "'today at' h:mm a" : "MMM d"
        return formatter.string(from: date)
    }
}

/// The Wallet passes screen: every pass the server issued to this person (by them or by a business), current first, with the
/// add / "In Wallet" state from `WalletPassCoordinator` and the in-app code for people without Wallet.
@MainActor
#if canImport(Observation) && !os(Linux)
@Observable
#endif
public final class WalletPassesViewModel {
    public private(set) var passes: [WalletPassMetadata] = []
    public private(set) var isLoading = false
    public private(set) var hasLoaded = false
    public private(set) var errorMessage: String?
    /// The "Beta" label on Wallet screens (an owner decision; `ViadereConfiguration.walletBetaLabel`).
    public let showsBetaLabel: Bool

    private let services: ViadereServices
    private let wallet: WalletPassCoordinator

    public init(services: ViadereServices, wallet: WalletPassCoordinator, showsBetaLabel: Bool? = nil) {
        self.services = services
        self.wallet = wallet
        self.showsBetaLabel = showsBetaLabel ?? services.configuration.walletBetaLabel
    }

    public func load() async {
        isLoading = true
        defer { isLoading = false }
        do {
            passes = try await services.api.walletPasses()
            errorMessage = nil
            wallet.refresh(passes)
        } catch let error as APIError {
            errorMessage = error.userMessage
        } catch {
            errorMessage = "Your passes couldn't be loaded. Try again."
        }
        hasLoaded = true
    }

    /// Valid passes not yet used, newest first.
    public var current: [WalletPassMetadata] { passes.filter { !$0.voided && $0.usedAt == nil } }
    /// Used or voided passes, kept for reference.
    public var past: [WalletPassMetadata] { passes.filter { $0.voided || $0.usedAt != nil } }

    public func pass(_ id: WalletPassID) -> WalletPassMetadata? { passes.first { $0.id == id } }

    public func presentation(for pass: WalletPassMetadata, businessName: String?) -> WalletPassPresentation {
        WalletPassPresentation.make(pass, walletState: wallet.state(for: pass), businessName: businessName, now: services.clock())
    }
}
