import Foundation
import ViadereCore

/// Why an interaction can or cannot be decided on this device right now.
public enum ApprovalAvailability: Sendable, Equatable {
    /// Ready; the plan says which key will sign (and whether Face ID is needed).
    case actionable(SigningPlan)
    case expired
    /// Already approved/denied/cancelled (possibly on another device).
    case alreadyHandled(InteractionStatus)
    /// Unknown interaction kind (newer server): never rendered as actionable.
    case unsupported
    /// This device's keys cannot meet the required assurance (e.g. no biometrics enrolled).
    case needsStrongerDevice(RequiredAssurance)
    case notEnrolled

    public var isActionable: Bool {
        if case .actionable = self { return true }
        return false
    }
}

/// Pure approval rules (no I/O), shared by the approval sheet, notification actions and the watch bridge.
public enum ApprovalPolicy {
    /// The plan that satisfies `interaction`'s required assurance given the device's best key.
    /// Prefers the cheapest sufficient key (passcode-or-biometric before biometric-only).
    public static func plan(for interaction: Interaction, device: DeviceRecord?) -> SigningPlan? {
        let required = AssurancePolicy.requiredAssurance(for: interaction)
        let preferred = SigningPlan.plan(for: required)
        guard let device else { return nil }
        let candidates: [DecisionAssurance] = DecisionAssurance.allCases.filter { $0 >= preferred.assurance }
        for assurance in candidates {
            let plan = SigningPlan(assurance: assurance)
            if assurance == .none || device.purposes.contains(plan.purpose) { return plan }
        }
        return nil
    }

    public static func availability(of envelope: InteractionEnvelope, device: DeviceRecord?, now: Date) -> ApprovalAvailability {
        if envelope.interaction.kind.isUnknown { return .unsupported }
        if envelope.status != .pending { return .alreadyHandled(envelope.status) }
        if envelope.interaction.isExpired(at: now) { return .expired }
        guard let device else { return .notEnrolled }
        guard let plan = plan(for: envelope.interaction, device: device) else {
            return .needsStrongerDevice(AssurancePolicy.requiredAssurance(for: envelope.interaction))
        }
        return .actionable(plan)
    }

    /// Slide-to-approve is used for anything that needs strong verification or moves money.
    public static func usesSlideToApprove(_ interaction: Interaction) -> Bool {
        switch interaction.kind {
        case .authorize: interaction.effectiveSensitivity >= .standard
        case .authenticate: interaction.effectiveSensitivity >= .high
        default: false
        }
    }

    /// Maximum length of the Face ID / passcode sheet text.
    public static let promptLimit = 90

    /// Text for the Face ID / passcode sheet. States the business and amount. Every business-supplied piece is
    /// sanitized (no bidi/zero-width/newlines) and capped on its own, and the amount comes first, so a long
    /// merchant name can be cut but never hides what is being approved. A business that imitates "Viadere" is
    /// shown quoted, e.g. `Business "Viadere Security"`.
    public static func promptReason(for envelope: InteractionEnvelope, decision: Decision, onBehalfOf: String? = nil) -> String {
        let business = UntrustedText.name(envelope.business.displayName, max: 30).text
        let text: String
        switch (envelope.interaction.payload, decision) {
        case (.authorize(let p), .approve):
            if let amount = p.amount {
                let place = p.merchant.flatMap { UntrustedText.clean($0).isEmpty ? nil : UntrustedText.name($0, max: 30, attribution: nil).text } ?? business
                text = "Approve \(amount.formatted) at \(place)"
            } else {
                text = "Approve the request from \(business)"
            }
        case (.authenticate(let p), .approve):
            text = "Approve sign-in to \(UntrustedText.name(p.service, max: 30, attribution: nil).text) with \(business)"
        case (_, .deny), (_, .decline):
            text = "Deny the request from \(business)"
        case (_, .report):
            text = "Report this request from \(business)"
        default:
            text = "Confirm with \(business)"
        }
        if let onBehalfOf {
            let suffix = " on behalf of \(UntrustedText.line(onBehalfOf, max: 30))"
            return UntrustedText.truncate(text, max: max(0, promptLimit - suffix.count)) + suffix
        }
        return UntrustedText.truncate(text, max: promptLimit)
    }
}

extension InteractionKind {
    public var isUnknown: Bool {
        if case .unknown = self { return true }
        return false
    }
}
