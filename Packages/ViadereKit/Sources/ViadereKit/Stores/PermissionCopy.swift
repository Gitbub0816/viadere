import Foundation
import ViadereCore

/// Plain-language copy for purpose-scoped consent, shared by the connect review and business detail screens.
public enum PermissionCopy {
    /// Bumped whenever the wording below changes; recorded with every consent change.
    public static let policyVersion = "2026-10"

    public struct Row: Equatable, Sendable, Identifiable {
        public var id: InteractionPurpose { purpose }
        public var purpose: InteractionPurpose
        public var title: String
        public var detail: String
        public var isOn: Bool
        /// Security and account notices can't be switched off while connected.
        public var isLocked: Bool
    }

    public static func title(_ purpose: InteractionPurpose) -> String {
        switch purpose {
        case .security: "Security and sign-in"
        case .accountService: "Account service"
        case .transactional: "Orders and receipts"
        case .support: "Customer support"
        case .marketing: "Offers and news"
        case .rewards: "Rewards"
        }
    }

    public static func detail(_ purpose: InteractionPurpose) -> String {
        switch purpose {
        case .security: "Sign-in checks and approvals. Always on."
        case .accountService: "Important notices about your account. Always on."
        case .transactional: "Confirmations, deliveries and appointments."
        case .support: "Replies and help when you ask for it."
        case .marketing: "Promotions and announcements. Off unless you choose."
        case .rewards: "Loyalty points and perks. Off unless you choose."
        }
    }

    /// Rows in a stable, calm order. `granted` supplies current values (defaults apply when absent).
    public static func rows(supported: [InteractionPurpose], granted: [InteractionPurpose: Bool]) -> [Row] {
        let order: [InteractionPurpose] = [.security, .accountService, .transactional, .support, .marketing, .rewards]
        return order.filter { $0.isEssential || supported.contains($0) }.map { purpose in
            Row(purpose: purpose, title: title(purpose), detail: detail(purpose),
                isOn: purpose.isRevocable ? (granted[purpose] ?? purpose.isGrantedByDefault) : true,
                isLocked: !purpose.isRevocable)
        }
    }
}
