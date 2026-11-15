import Foundation

/// The closed list of follow-up actions a campaign link may name (`ConnectContext.action`, docs/SECURITY.md §2.106).
///
/// An action is a **destination to offer after** the customer has reviewed the verified business and connected. It never selects, skips or
/// changes a consent choice, never opens anything before the connection exists, and anything outside this list is refused when a campaign
/// is created and ignored when a link is opened.
public enum CampaignAction: String, Sendable, Codable, CaseIterable, Hashable {
    /// Opens Benefits, where the customer can choose rewards. It does not turn the rewards purpose on.
    case enrollRewards = "enroll_rewards"
    case openMessages = "open_messages"
    case openBenefits = "open_benefits"

    /// Where the app goes once the connection exists.
    public enum Destination: String, Sendable, Codable, Hashable { case messages, benefits }

    public var destination: Destination {
        switch self {
        case .enrollRewards, .openBenefits: .benefits
        case .openMessages: .messages
        }
    }

    /// Console label.
    public var label: String {
        switch self {
        case .enrollRewards: "Show rewards (Benefits)"
        case .openMessages: "Open Messages"
        case .openBenefits: "Open Benefits"
        }
    }

    /// The action a **server-verified** context names, if it is on the list. Never call this with a context read from a link on the device.
    public init?(verified context: ConnectContext?) {
        guard let raw = context?.action, let action = CampaignAction(rawValue: raw) else { return nil }
        self = action
    }
}
