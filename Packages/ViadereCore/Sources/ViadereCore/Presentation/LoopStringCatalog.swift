import Foundation

/// Every Viadere-written string a Loop surface shows (English source; plan K5: "Loops" is a codename and all customer copy goes through
/// one catalog so a rename or a counsel revision is one change). Business-authored text never fills these slots.
public enum LoopStringCatalog {
    /// Version of the attribution wording and placement rules (`attribution_policy_version` in the publication manifest). A manifest
    /// naming any other version is refused (safe fallback).
    public static let attributionPolicyVersion: Int64 = 1
    public static let supportedAttributionPolicyVersions: Set<Int64> = [1]

    /// Button labels a business may choose among (per action: `LoopActionDefinition.allowedLabelKeys`).
    public static let actionLabels: [String: String] = [
        "acknowledge": "Acknowledge", "got_it": "Got it", "send_request": "Send request", "confirm": "Confirm",
        "confirm_attendance": "Confirm attendance", "i_will_attend": "I'll be there",
        "request_callback": "Request a callback", "call_me_back": "Call me back",
        "send_inquiry": "Send inquiry", "send": "Send",
        "check_in": "Check in", "i_have_arrived": "I've arrived",
        "continue": "Continue", "choose": "Choose", "next": "Next", "choose_time": "Choose this time",
        "review_estimate": "Review estimate", "send_acknowledgement": "Send acknowledgment",
        "approve_estimate": "Approve estimate",
    ]

    // MARK: Attribution (spec A6a)

    /// Visible attribution: "Built by {verified business name}".
    static func builtBy(_ name: String) -> String { "Built by \(name)" }
    /// Read first by VoiceOver / TalkBack (A6a.T5).
    static func builtByAccessibility(_ name: String) -> String { "Built by \(name), a business on Viadere" }
    /// Concise origin for notifications, Live Activities, widgets (A6a.T6).
    static func compactOrigin(_ name: String) -> String { "By \(name)" }
    static let verifiedBadge = "Verified business"

    // MARK: Fixed notices

    static let unavailableTitle = "This request can't be shown"
    static let unavailableBody = "Viadere couldn't confirm who built this request, so it isn't shown. You can close it or report it."
    static let noHealthDetails = "Don't share health details here."
    static let close = "Close"
    static let report = "Report"
    static let cancel = "Cancel"
    static let pausedTitle = "This request is paused"
    static let previewLabel = "Preview, not exactly what customers see"

    // MARK: Outcomes (plan section 4.5; never promissory)

    public static func outcomeText(_ outcome: LoopActionOutcome, business: String) -> String {
        switch outcome {
        case .accepted: "\(business) confirmed"
        case .rejected: "\(business) couldn't do this"
        case .pending: "Sent to \(business). Waiting for them to confirm."
        case .timedOut: "\(business) hasn't answered. You can contact them."
        case .unknown: "We couldn't confirm that \(business) received this."
        }
    }

    static func fill(_ template: String, business: String, amount: String?) -> String {
        var text = template.replacingOccurrences(of: "{business}", with: business)
        text = text.replacingOccurrences(of: "{amount}", with: amount ?? "")
        return text
    }
}
