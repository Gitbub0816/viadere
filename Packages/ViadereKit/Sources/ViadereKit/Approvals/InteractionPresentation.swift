import Foundation
import ViadereCore

/// Presentation copy derived from interactions. Pure and testable; views only lay it out.
public enum InteractionPresentation {
    /// Caps for each kind of business-supplied text. Money is never truncated; free text is cut on its own.
    public enum Limit {
        public static let headline = 80, title = 100, detail = 100, merchant = 40, service = 40, location = 40,
                          device = 60, reference = 40, effect = 160, risk = 60, option = 40, message = 160
    }

    /// One-line headline for list rows ("$285.28 at Northfield Market"). Business text is sanitized and capped.
    public static func headline(_ interaction: Interaction) -> String {
        switch interaction.payload {
        case .authorize(let p):
            if let amount = p.amount {
                let merchant = UntrustedText.optionalLine(p.merchant, max: Limit.merchant)
                return [amount.formatted, merchant.map { "at \($0)" }].compactMap { $0 }.joined(separator: " ")
            }
            return text(p.actionDescription, Limit.headline)
        case .authenticate(let p): return "Sign in to \(service(p.service))"
        case .confirm(let p): return text(p.title, Limit.headline)
        case .choose(let p): return text(p.prompt, Limit.headline)
        case .acknowledge(let p): return text(p.title, Limit.headline)
        case .reply(let p): return text(p.prompt, Limit.headline)
        case .status(let p): return text(p.title, Limit.headline)
        case .reward(let p): return text(p.title, Limit.headline)
        case .ticket(let p): return text(p.title, Limit.headline)
        case .message(let p): return text(p.text, Limit.message)
        case .unknown: return "New request"
        }
    }

    /// Sanitized single-line business text (empty string if nothing printable is left).
    public static func text(_ raw: String, _ limit: Int) -> String { UntrustedText.line(raw, max: limit) }

    /// A service or merchant name, quoted if it imitates Viadere.
    static func service(_ raw: String) -> String { UntrustedText.name(raw, max: Limit.service, attribution: nil).text }

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
    /// The amount comes first and is never cut; the merchant and place are sanitized and capped separately.
    public static func question(_ interaction: Interaction) -> String {
        switch interaction.payload {
        case .authorize(let p): return authorizeSentence(p)
        case .authenticate(let p):
            var line = "Someone is trying to sign in to \(service(p.service))"
            if let place = UntrustedText.optionalLine(p.approximateLocation ?? p.ipRegion, max: Limit.location) { line += " near \(place)" }
            return line + ". Is this you?"
        default: return headline(interaction)
        }
    }

    /// "Someone is trying to spend $285.28 at Walmart near Mesa, Arizona. Is this you?" with sanitized pieces.
    public static func authorizeSentence(_ p: AuthorizePayload) -> String {
        var line: String
        if let amount = p.amount {
            line = "Someone is trying to spend \(amount.formatted)"
            if let merchant = UntrustedText.optionalLine(p.merchant, max: Limit.merchant) { line += " at \(UntrustedText.name(merchant, max: Limit.merchant, attribution: nil).text)" }
        } else {
            line = text(p.actionDescription, Limit.title)
            if let merchant = UntrustedText.optionalLine(p.merchant, max: Limit.merchant) { line += " - \(merchant)" }
        }
        if let place = UntrustedText.optionalLine(p.location, max: Limit.location) {
            let lower = place.lowercased()
            line += (lower.hasPrefix("in ") || lower.hasPrefix("near ") || lower.hasPrefix("at ")) ? " \(place)" : " near \(place)"
        }
        return line + ". Is this you?"
    }

    /// The facts table for the approval sheet. Only rows with data are included. Labels are fixed by Viadere;
    /// every value is business text made single-line, so nothing can add a row of its own or pose as one.
    public static func details(_ envelope: InteractionEnvelope, now: Date = Date(), timeZone: TimeZone = .current) -> [PresentedDetail] {
        let interaction = envelope.interaction
        let business = UntrustedText.name(envelope.business.displayName, max: 40)
        var rows: [PresentedDetail] = [PresentedDetail(label: "From", value: business.text)]
        func add(_ label: String, _ raw: String?, _ limit: Int) {
            if let value = UntrustedText.optionalLine(raw, max: limit) { rows.append(PresentedDetail(label: label, value: value)) }
        }
        switch interaction.payload {
        case .authorize(let p):
            add("Purpose", p.actionDescription, Limit.detail)
            if let amount = p.amount {
                rows.append(PresentedDetail(label: "Amount", value: "\(amount.formatted) \(amount.currency.value)", emphasized: true))
            }
            if let merchant = p.merchant, !UntrustedText.clean(merchant).isEmpty {
                rows.append(PresentedDetail(label: "Merchant", value: UntrustedText.name(merchant, max: Limit.merchant, attribution: nil).text))
            }
            add("Location", p.location, Limit.location)
            add("Account", interaction.scope.accountReference, Limit.reference)
        case .authenticate(let p):
            rows.append(PresentedDetail(label: "Signing in to", value: service(p.service)))
            add("Device", p.device, Limit.device)
            add("Location", p.approximateLocation ?? p.ipRegion, Limit.location)
            add("Account", interaction.scope.accountReference, Limit.reference)
            rows.append(PresentedDetail(label: "Attempted", value: relative(p.attemptedAt, now: now)))
        default:
            rows.append(PresentedDetail(label: "Request", value: headline(interaction)))
        }
        if case .authorize = interaction.payload {
            rows.append(PresentedDetail(label: "Requested", value: relative(interaction.createdAt, now: now)))
        }
        return rows
    }

    /// Risk indicators with sanitized, capped labels (an empty label falls back to a generic one).
    public static func riskIndicators(_ interaction: Interaction) -> [RiskIndicator] {
        let raw: [RiskIndicator]
        switch interaction.payload {
        case .authorize(let p): raw = p.riskIndicators
        case .authenticate(let p): raw = p.riskIndicators
        default: raw = []
        }
        return raw.map { indicator in
            var copy = indicator
            let cleaned = UntrustedText.line(indicator.label, max: Limit.risk)
            let label = cleaned.isEmpty ? "Unusual activity" : cleaned
            copy.label = label
            copy.code = UntrustedText.clean(indicator.code).lowercased().filter { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "_") }
            return copy
        }
    }

    public static func effectOfApproval(_ interaction: Interaction) -> String? {
        switch interaction.payload {
        case .authorize(let p): UntrustedText.optionalLine(p.effectOfApproval, max: Limit.effect)
        case .authenticate(let p): "Approving lets this sign-in to \(service(p.service)) continue."
        default: nil
        }
    }

    // MARK: Other payload text (approval sheet bodies)

    public static func confirmTitle(_ p: ConfirmPayload) -> String { text(p.title, Limit.title) }
    public static func confirmDetails(_ p: ConfirmPayload) -> String? { UntrustedText.optionalLine(p.details, max: Limit.effect) }
    public static func prompt(_ raw: String) -> String { text(raw, Limit.title) }
    public static func optionLabel(_ option: ChoiceOption) -> String { text(option.label, Limit.option) }
    public static func suggestedReply(_ raw: String) -> String { text(raw, Limit.option) }

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
