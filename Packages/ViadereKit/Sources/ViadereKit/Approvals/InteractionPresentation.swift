import Foundation
import ViadereCore

/// Presentation copy derived from interactions. Pure and testable; views only lay it out.
public enum InteractionPresentation {
    /// One-line headline for list rows ("$285.28 at Northfield Market").
    public static func headline(_ interaction: Interaction) -> String {
        switch interaction.payload {
        case .authorize(let p):
            if let amount = p.amount { return [amount.formatted, p.merchant.map { "at \($0)" }].compactMap { $0 }.joined(separator: " ") }
            return p.actionDescription
        case .authenticate(let p): return "Sign in to \(p.service)"
        case .confirm(let p): return p.title
        case .choose(let p): return p.prompt
        case .acknowledge(let p): return p.title
        case .reply(let p): return p.prompt
        case .status(let p): return p.title
        case .reward(let p): return p.title
        case .ticket(let p): return p.title
        case .message(let p): return p.text
        case .unknown: return "New request"
        }
    }

    /// Short kind label ("Approval", "Sign-in").
    public static func kindLabel(_ interaction: Interaction) -> String {
        switch interaction.kind {
        case .authenticate: "Sign-in request"
        case .authorize: "Approval request"
        case .confirm: "Confirmation"
        case .choose: "Choice"
        case .acknowledge: "Acknowledgment"
        case .reply: "Reply requested"
        case .status: "Update"
        case .reward: "Reward"
        case .ticket: "Ticket"
        case .message: "Message"
        case .unknown: "Request"
        }
    }

    /// The question a person answers: "Someone is trying to spend $285.28 at … Is this you?"
    public static func question(_ interaction: Interaction) -> String {
        switch interaction.payload {
        case .authorize(let p): return ChannelRenderer.authorizeSentence(p)
        case .authenticate(let p):
            var text = "Someone is trying to sign in to \(p.service)"
            if let place = p.approximateLocation ?? p.ipRegion { text += " near \(place)" }
            return text + ". Is this you?"
        default: return headline(interaction)
        }
    }

    /// The facts table for the approval sheet. Only rows with data are included.
    public static func details(_ envelope: InteractionEnvelope, now: Date = Date(), timeZone: TimeZone = .current) -> [PresentedDetail] {
        let interaction = envelope.interaction
        var rows: [PresentedDetail] = [PresentedDetail(label: "From", value: envelope.business.displayName)]
        switch interaction.payload {
        case .authorize(let p):
            rows.append(PresentedDetail(label: "Purpose", value: p.actionDescription))
            if let amount = p.amount {
                rows.append(PresentedDetail(label: "Amount", value: "\(amount.formatted) \(amount.currency.value)", emphasized: true))
            }
            if let merchant = p.merchant { rows.append(PresentedDetail(label: "Merchant", value: merchant)) }
            if let location = p.location { rows.append(PresentedDetail(label: "Location", value: location)) }
            if let account = interaction.scope.accountReference { rows.append(PresentedDetail(label: "Account", value: account)) }
        case .authenticate(let p):
            rows.append(PresentedDetail(label: "Signing in to", value: p.service))
            rows.append(PresentedDetail(label: "Device", value: p.device))
            if let location = p.approximateLocation ?? p.ipRegion { rows.append(PresentedDetail(label: "Location", value: location)) }
            if let account = interaction.scope.accountReference { rows.append(PresentedDetail(label: "Account", value: account)) }
            rows.append(PresentedDetail(label: "Attempted", value: relative(p.attemptedAt, now: now)))
        default:
            rows.append(PresentedDetail(label: "Request", value: headline(interaction)))
        }
        if case .authorize = interaction.payload {
            rows.append(PresentedDetail(label: "Requested", value: relative(interaction.createdAt, now: now)))
        }
        return rows
    }

    public static func riskIndicators(_ interaction: Interaction) -> [RiskIndicator] {
        switch interaction.payload {
        case .authorize(let p): p.riskIndicators
        case .authenticate(let p): p.riskIndicators
        default: []
        }
    }

    public static func effectOfApproval(_ interaction: Interaction) -> String? {
        switch interaction.payload {
        case .authorize(let p): p.effectOfApproval
        case .authenticate(let p): "Approving lets this sign-in to \(p.service) continue."
        default: nil
        }
    }

    /// "Face ID required", "Passcode or Face ID", or nil.
    public static func verificationLabel(_ plan: SigningPlan?) -> String? {
        switch plan?.assurance {
        case .biometric: "Face ID or Touch ID required"
        case .devicePasscode: "Face ID, Touch ID or passcode"
        default: nil
        }
    }

    /// "Expires in 4:32" / "Expired".
    public static func countdown(until expiry: Date, now: Date) -> String {
        let remaining = Int(expiry.timeIntervalSince(now).rounded(.down))
        guard remaining > 0 else { return "Expired" }
        if remaining >= 3_600 { return "Expires in \(remaining / 3_600) h \((remaining % 3_600) / 60) min" }
        return String(format: "Expires in %d:%02d", remaining / 60, remaining % 60)
    }

    public static func relative(_ date: Date, now: Date) -> String {
        let seconds = Int(now.timeIntervalSince(date))
        if seconds < 10 { return "Just now" }
        if seconds < 60 { return "\(seconds) seconds ago" }
        if seconds < 3_600 { return "\(seconds / 60) min ago" }
        if seconds < 86_400 { return "\(seconds / 3_600) h ago" }
        return "\(seconds / 86_400) d ago"
    }
}

public struct PresentedDetail: Sendable, Hashable, Identifiable {
    public var id: String { label }
    public var label: String
    public var value: String
    public var emphasized: Bool

    public init(label: String, value: String, emphasized: Bool = false) {
        self.label = label
        self.value = value
        self.emphasized = emphasized
    }
}
