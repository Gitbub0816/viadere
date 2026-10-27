import Foundation

/// What a numbered SMS reply (or RCS postback) maps to.
public enum ChoiceTarget: Sendable, Hashable, Codable {
    case decision(Decision)
    case option(String)
    /// Show the next page of a long `choose` (page index).
    case nextPage(Int)
}

/// A numbered SMS choice.
public struct SMSChoice: Sendable, Hashable, Codable {
    public var number: Int
    public var label: String
    public var target: ChoiceTarget
}

/// SMS rendering of an interaction.
public struct SMSRendering: Sendable, Hashable {
    public var body: String
    public var choices: [SMSChoice]
    /// True when the interaction could not be presented inline and a secure handoff was rendered.
    public var isSecureHandoff: Bool
    public var encoding: SMSEncoding.Info

    /// Maps an inbound reply ("2", " 2. ") to its target, or `nil`.
    public func target(forReply text: String) -> ChoiceTarget? {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines).trimmingCharacters(in: CharacterSet(charactersIn: ".)"))
        guard let number = Int(trimmed) else { return nil }
        return choices.first { $0.number == number }?.target
    }
}

/// RCS-like suggested reply / action.
public struct RCSSuggestion: Sendable, Hashable, Codable {
    public enum Kind: String, Sendable, Codable { case reply, openURL }
    public var kind: Kind
    /// ≤ 25 characters.
    public var text: String
    /// `viadere:{interactionId}:{target}` for replies. Postbacks are *not* authentication.
    public var postbackData: String?
    public var url: URL?
}

/// RCS rendering of an interaction.
public struct RCSRendering: Sendable, Hashable {
    public var text: String
    public var suggestions: [RCSSuggestion]
    public var isSecureHandoff: Bool
}

/// A notification action, mirroring `UNNotificationAction` options.
public struct NotificationActionSpec: Sendable, Hashable, Codable {
    public enum Style: String, Sendable, Codable { case normal, destructive, textInput }
    /// e.g. `viadere.approve`, `viadere.option.<id>`.
    public var identifier: String
    public var title: String
    public var style: Style
    /// `.authenticationRequired`: device must be unlocked.
    public var requiresAuthentication: Bool
    /// `.foreground`: opens the app (needed for biometric signing).
    public var opensApp: Bool

    public init(identifier: String, title: String, style: Style, requiresAuthentication: Bool, opensApp: Bool) {
        self.identifier = identifier
        self.title = title
        self.style = style
        self.requiresAuthentication = requiresAuthentication
        self.opensApp = opensApp
    }
}

/// A notification category (register with `UNUserNotificationCenter` — dynamic `choose`
/// categories should be registered by the Notification Service Extension before display).
public struct NotificationCategorySpec: Sendable, Hashable, Codable {
    public var identifier: String
    public var actions: [NotificationActionSpec]

    public init(identifier: String, actions: [NotificationActionSpec]) {
        self.identifier = identifier
        self.actions = actions
    }
}

/// Native notification rendering.
public struct NotificationRendering: Sendable, Hashable {
    public enum InterruptionLevel: String, Sendable, Codable { case passive, active, timeSensitive }
    public var category: NotificationCategorySpec
    /// Business display name.
    public var title: String
    public var subtitle: String
    public var body: String
    /// `business.{businessId}` — groups per business; never mixes tenants.
    public var threadIdentifier: String
    public var interruptionLevel: InterruptionLevel
    /// String user-info for routing the action back (`interactionId`, `businessId`, `kind`).
    public var userInfo: [String: String]
    /// True when approval must happen in the app (secure step-up).
    public var requiresSecureFlow: Bool

    public init(category: NotificationCategorySpec, title: String, subtitle: String, body: String, threadIdentifier: String,
                interruptionLevel: InterruptionLevel, userInfo: [String: String], requiresSecureFlow: Bool) {
        self.category = category
        self.title = title
        self.subtitle = subtitle
        self.body = body
        self.threadIdentifier = threadIdentifier
        self.interruptionLevel = interruptionLevel
        self.userInfo = userInfo
        self.requiresSecureFlow = requiresSecureFlow
    }
}

/// Pure, transport-agnostic rendering of interactions into channel formats.
///
/// Rules:
/// - Never renders a security-sensitive kind (`authenticate`, `authorize`, unknown) or any interaction
///   whose `RequiredAssurance` exceeds `.channelReply` as an SMS/RCS YES/NO; it renders a secure handoff.
/// - All business-supplied text is single-lined, spoof-stripped and length-capped.
/// - Every rendering is attributed to exactly one verified business.
/// - SMS menus contain at most 4 numbered choices.
public enum ChannelRenderer {
    /// Maximum numbered choices per SMS menu.
    public static let maxSMSChoices = 4

    // MARK: SMS

    /// Renders for SMS. `handoffURL` is a short-lived secure link (app universal link or web) for
    /// interactions that cannot be completed by text. `page` pages long `choose` lists.
    public static func sms(_ interaction: Interaction, business: BusinessSummary, handoffURL: URL?, page: Int = 0) -> SMSRendering {
        let name = SMSEncoding.field(business.displayName, maxLength: 40)
        let prefix = "[\(name)]: "
        if !AssurancePolicy.canPresentInline(interaction, on: .sms) {
            return finish(prefix + secureHandoffText(interaction, url: handoffURL), choices: [], handoff: true)
        }
        switch interaction.payload {
        case .confirm(let p):
            var text = prefix + SMSEncoding.field(p.title, maxLength: 80)
            if let details = p.details { text += ". " + SMSEncoding.field(details, maxLength: 160) }
            if let reference = p.reference { text += " Ref " + SMSEncoding.field(reference, maxLength: 32) }
            let choices = [SMSChoice(number: 1, label: "Confirm", target: .decision(.confirm)),
                           SMSChoice(number: 2, label: "Decline", target: .decision(.decline))]
            return finish(text + "\n" + menuLines(choices), choices: choices, handoff: false)
        case .choose(let p):
            let choices = chooseChoices(p.options, page: page)
            let text = prefix + SMSEncoding.field(p.prompt, maxLength: 120) + "\n" + menuLines(choices)
            return finish(text, choices: choices, handoff: false)
        case .acknowledge(let p):
            let choices = [SMSChoice(number: 1, label: "Acknowledge", target: .decision(.acknowledge))]
            let text = prefix + SMSEncoding.field(p.title, maxLength: 80) + ". " + SMSEncoding.field(p.body, maxLength: 240)
                + "\n" + menuLines(choices)
            return finish(text, choices: choices, handoff: false)
        case .reply(let p):
            return finish(prefix + SMSEncoding.field(p.prompt, maxLength: 160) + " Reply with your answer.", choices: [], handoff: false)
        case .status(let p):
            var text = prefix + SMSEncoding.field(p.title, maxLength: 80)
            if let body = p.body { text += ". " + SMSEncoding.field(body, maxLength: 240) }
            return finish(text, choices: [], handoff: false)
        case .reward(let p):
            var text = prefix + SMSEncoding.field(p.title, maxLength: 80)
            if let details = p.details { text += ". " + SMSEncoding.field(details, maxLength: 160) }
            text += handoffURL.map { " Redeem in Viadere: \($0.absoluteString)" } ?? " Redeem in the Viadere app."
            return finish(text, choices: [], handoff: false)
        case .ticket(let p):
            let text = prefix + SMSEncoding.field(p.title, maxLength: 80)
                + (handoffURL.map { ". View your ticket: \($0.absoluteString)" } ?? ". View your ticket in the Viadere app.")
            return finish(text, choices: [], handoff: false)
        case .message(let p):
            return finish(prefix + SMSEncoding.stripSpoofingCharacters(SMSEncoding.gsmFriendly(p.text), allowNewlines: true),
                          choices: [], handoff: false)
        case .authenticate, .authorize, .unknown:
            return finish(prefix + secureHandoffText(interaction, url: handoffURL), choices: [], handoff: true)
        }
    }

    /// Formats numbered menu lines: `1. Label` separated by newlines.
    public static func menuLines(_ choices: [SMSChoice]) -> String {
        choices.map { "\($0.number). \($0.label)" }.joined(separator: "\n")
    }

    static func chooseChoices(_ options: [ChoiceOption], page: Int) -> [SMSChoice] {
        let perPage = options.count <= maxSMSChoices ? maxSMSChoices : maxSMSChoices - 1
        let start = max(0, page) * perPage
        guard start < options.count else { return chooseChoices(options, page: 0) }
        let slice = Array(options[start..<min(options.count, start + perPage)])
        var choices = slice.enumerated().map { index, option in
            SMSChoice(number: index + 1, label: SMSEncoding.field(option.label, maxLength: 40), target: .option(option.id))
        }
        if options.count > maxSMSChoices {
            let nextPage = start + perPage < options.count ? page + 1 : 0
            choices.append(SMSChoice(number: maxSMSChoices, label: nextPage == 0 ? "Back to start" : "More options",
                                     target: .nextPage(nextPage)))
        }
        return choices
    }

    static func secureHandoffText(_ interaction: Interaction, url: URL?) -> String {
        let what: String
        switch interaction.kind {
        case .authenticate: what = "A sign-in request needs your review."
        case .authorize: what = "An approval request needs your review."
        default: what = "A secure request needs your review."
        }
        let where_ = url.map { " Review it securely: \($0.absoluteString)" } ?? " Open the Viadere app to review it."
        return what + where_ + " Viadere never asks you to approve by text."
    }

    private static func finish(_ body: String, choices: [SMSChoice], handoff: Bool) -> SMSRendering {
        SMSRendering(body: body, choices: choices, isSecureHandoff: handoff, encoding: SMSEncoding.analyze(body))
    }

    // MARK: RCS

    /// Renders for an RCS-like channel with suggested replies.
    public static func rcs(_ interaction: Interaction, business: BusinessSummary, handoffURL: URL?) -> RCSRendering {
        let name = SMSEncoding.field(business.displayName, maxLength: 40)
        func postback(_ target: String) -> String { "viadere:\(interaction.id):\(target)" }
        func reply(_ text: String, _ target: String) -> RCSSuggestion {
            RCSSuggestion(kind: .reply, text: SMSEncoding.field(text, maxLength: 25), postbackData: postback(target), url: nil)
        }
        if !AssurancePolicy.canPresentInline(interaction, on: .rcs) {
            let suggestions = handoffURL.map { [RCSSuggestion(kind: .openURL, text: "Review securely", postbackData: nil, url: $0)] } ?? []
            return RCSRendering(text: "[\(name)]: " + secureHandoffText(interaction, url: nil), suggestions: suggestions, isSecureHandoff: true)
        }
        let sms = sms(interaction, business: business, handoffURL: handoffURL)
        var suggestions: [RCSSuggestion] = []
        switch interaction.payload {
        case .confirm:
            suggestions = [reply("Confirm", "decision.confirm"), reply("Decline", "decision.decline")]
        case .choose(let p):
            suggestions = p.options.prefix(11).map { reply($0.label, "option.\($0.id)") }
        case .acknowledge:
            suggestions = [reply("Acknowledge", "decision.acknowledge")]
        case .reply(let p):
            suggestions = p.suggestedReplies.prefix(4).enumerated().map { reply($1, "suggested.\($0)") }
        default:
            break
        }
        // RCS shows suggestions as chips, so drop the numbered lines from the text.
        let text: String
        if case .choose(let p) = interaction.payload {
            text = "[\(name)]: " + SMSEncoding.field(p.prompt, maxLength: 120)
        } else if !sms.choices.isEmpty, let firstLine = sms.body.split(separator: "\n").first {
            text = String(firstLine)
        } else {
            text = sms.body
        }
        return RCSRendering(text: text, suggestions: suggestions, isSecureHandoff: false)
    }

    // MARK: Native notifications

    /// Renders an actionable notification. For assurance above `.deviceSignature`, approve
    /// actions open the app so the device can perform biometric/passcode signing.
    public static func notification(_ interaction: Interaction, business: BusinessSummary) -> NotificationRendering {
        let required = interaction.requiredAssurance
        let secure = required > .deviceSignature
        func action(_ id: String, _ title: String, _ style: NotificationActionSpec.Style = .normal,
                    auth: Bool = true, foreground: Bool = false) -> NotificationActionSpec {
            NotificationActionSpec(identifier: "viadere.\(id)", title: title, style: style, requiresAuthentication: auth, opensApp: foreground)
        }
        var subtitle: String
        var body: String
        var actions: [NotificationActionSpec]
        var categoryId: String
        switch interaction.payload {
        case .authenticate(let p):
            subtitle = "Sign-in request"
            var text = "Sign-in to \(SMSEncoding.field(p.service, maxLength: 60)) from \(SMSEncoding.field(p.device, maxLength: 60))"
            if let location = p.approximateLocation ?? p.ipRegion { text += " near \(SMSEncoding.field(location, maxLength: 60))" }
            body = text + ". Is this you?"
            actions = [action("approve", "Yes, it's me", foreground: secure), action("deny", "No", .destructive),
                       action("report", "Not me - report", .destructive)]
            categoryId = secure ? "viadere.authenticate.secure" : "viadere.authenticate"
        case .authorize(let p):
            subtitle = "Approval request"
            body = authorizeSentence(p)
            actions = [action("approve", "Approve", foreground: secure), action("deny", "Deny", .destructive),
                       action("report", "Not me - report", .destructive)]
            categoryId = secure ? "viadere.authorize.secure" : "viadere.authorize"
        case .confirm(let p):
            subtitle = "Please confirm"
            body = SMSEncoding.field(p.title, maxLength: 80) + (p.details.map { ". " + SMSEncoding.field($0, maxLength: 160) } ?? "")
            actions = [action("confirm", "Confirm", foreground: secure), action("decline", "Decline", .destructive)]
            categoryId = secure ? "viadere.confirm.secure" : "viadere.confirm"
        case .choose(let p):
            subtitle = "Choose an option"
            body = SMSEncoding.field(p.prompt, maxLength: 160)
            let inline = p.allowsMultiple ? [] : Array(p.options.prefix(p.options.count <= 4 ? 4 : 3))
            actions = inline.map { action("option.\($0.id)", SMSEncoding.field($0.label, maxLength: 40), foreground: secure) }
            if p.allowsMultiple || p.options.count > 4 { actions.append(action("open", "More options", auth: true, foreground: true)) }
            categoryId = "viadere.choose.\(interaction.id)"
        case .acknowledge(let p):
            subtitle = SMSEncoding.field(p.title, maxLength: 60)
            body = SMSEncoding.field(p.body, maxLength: 200)
            actions = [action("acknowledge", "Acknowledge", foreground: secure), action("open", "View", foreground: true)]
            categoryId = secure ? "viadere.acknowledge.secure" : "viadere.acknowledge"
        case .reply(let p):
            subtitle = "Reply requested"
            body = SMSEncoding.field(p.prompt, maxLength: 160)
            actions = [action("reply", "Reply", .textInput, foreground: secure)]
            categoryId = "viadere.reply"
        case .status(let p):
            subtitle = SMSEncoding.field(p.title, maxLength: 60)
            body = p.body.map { SMSEncoding.field($0, maxLength: 200) } ?? ""
            actions = []
            categoryId = "viadere.status"
        case .reward(let p):
            subtitle = "Reward"
            body = SMSEncoding.field(p.title, maxLength: 80) + (p.details.map { ". " + SMSEncoding.field($0, maxLength: 120) } ?? "")
            actions = [action("open", "View", foreground: true)]
            categoryId = "viadere.reward"
        case .ticket(let p):
            subtitle = "Ticket"
            body = SMSEncoding.field(p.title, maxLength: 120)
            actions = [action("open", "View", foreground: true)]
            categoryId = "viadere.ticket"
        case .message(let p):
            subtitle = "Message"
            body = SMSEncoding.field(p.text, maxLength: 200)
            actions = [action("reply", "Reply", .textInput)]
            categoryId = "viadere.message"
        case .unknown:
            subtitle = "Update"
            body = "Open Viadere to view this request."
            actions = [action("open", "Open", foreground: true)]
            categoryId = "viadere.unknown"
        }
        let level: NotificationRendering.InterruptionLevel
        switch (interaction.purpose, interaction.effectivePriority) {
        case (.marketing, _), (.rewards, _), (_, .low): level = .passive
        case (.security, .high), (.security, .urgent), (.transactional, .high): level = .timeSensitive
        default: level = .active
        }
        return NotificationRendering(
            category: NotificationCategorySpec(identifier: categoryId, actions: actions),
            title: SMSEncoding.field(business.displayName, maxLength: 40),
            subtitle: subtitle,
            body: body,
            threadIdentifier: "business.\(business.id)",
            interruptionLevel: level,
            userInfo: ["interactionId": interaction.id.description, "businessId": business.id.description,
                       "kind": interaction.kind.rawValue],
            requiresSecureFlow: secure
        )
    }

    /// "Someone is trying to spend $285.28 at Walmart in or near Mesa, Arizona. Is this you?"
    public static func authorizeSentence(_ p: AuthorizePayload) -> String {
        var text: String
        if let amount = p.amount {
            text = "Someone is trying to spend \(amount.formatted)"
            if let merchant = p.merchant { text += " at \(SMSEncoding.field(merchant, maxLength: 60))" }
        } else {
            text = SMSEncoding.field(p.actionDescription, maxLength: 120)
            if let merchant = p.merchant { text += " - \(SMSEncoding.field(merchant, maxLength: 60))" }
        }
        if let location = p.location {
            let loc = SMSEncoding.field(location, maxLength: 60)
            let lower = loc.lowercased()
            text += (lower.hasPrefix("in ") || lower.hasPrefix("near ") || lower.hasPrefix("at ")) ? " \(loc)" : " near \(loc)"
        }
        return text + ". Is this you?"
    }

    /// Static categories the app should register at launch (dynamic `choose` categories excluded).
    public static let staticCategories: [String] = [
        "viadere.authenticate", "viadere.authenticate.secure", "viadere.authorize", "viadere.authorize.secure",
        "viadere.confirm", "viadere.confirm.secure", "viadere.acknowledge", "viadere.acknowledge.secure",
        "viadere.reply", "viadere.status", "viadere.reward", "viadere.ticket", "viadere.message", "viadere.unknown",
    ]
}
