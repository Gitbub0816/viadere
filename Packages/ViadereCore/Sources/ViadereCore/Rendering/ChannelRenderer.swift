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

/// Orientation of an RBM standalone rich card.
public enum RCSCardOrientation: String, Sendable, Hashable, Codable {
    case vertical = "VERTICAL"
    case horizontal = "HORIZONTAL"
}

/// Width of the cards in an RBM carousel.
public enum RCSCardWidth: String, Sendable, Hashable, Codable {
    case small = "SMALL"
    case medium = "MEDIUM"
}

/// The content of one RCS Business Messaging rich card: a title, an optional description and at most
/// `ChannelRenderer.maxRCSCardSuggestions` suggested replies.
///
/// There is deliberately **no media member**: no interaction payload carries a media reference that is safe to hand to a provider
/// (brand images are served only from Viadere's own asset host and are not part of an interaction), so a card is text only.
/// Every string has passed `DisplayTextSanitizer.sanitize`, `SMSEncoding.businessLine` and `SMSEncoding.field`; every suggestion is a
/// `.reply` whose postback is the same renderer placeholder the chip list uses (the server swaps each for its signed single-use token).
public struct RCSCardContent: Sendable, Hashable, Codable {
    /// ≤ `ChannelRenderer.maxRCSCardTitle` characters (RBM allows 200).
    public var title: String
    /// ≤ `ChannelRenderer.maxRCSCardDescription` characters (RBM allows 2000).
    public var description: String?
    /// ≤ `ChannelRenderer.maxRCSCardSuggestions` (the RBM per-card limit), replies only.
    public var suggestions: [RCSSuggestion]

    public init(title: String, description: String? = nil, suggestions: [RCSSuggestion] = []) {
        self.title = title
        self.description = description
        self.suggestions = suggestions
    }
}

/// An RBM standalone rich card (`richCard.standaloneCard`).
public struct RCSStandaloneCard: Sendable, Hashable, Codable {
    public var orientation: RCSCardOrientation
    public var content: RCSCardContent

    public init(orientation: RCSCardOrientation = .vertical, content: RCSCardContent) {
        self.orientation = orientation
        self.content = content
    }
}

/// An RBM carousel (`richCard.carouselCard`): `ChannelRenderer.rcsCarouselCards` (2-10) cards of one width.
public struct RCSCarousel: Sendable, Hashable, Codable {
    public var width: RCSCardWidth
    public var cards: [RCSCardContent]

    public init(width: RCSCardWidth = .medium, cards: [RCSCardContent]) {
        self.width = width
        self.cards = cards
    }
}

/// RCS rendering of an interaction.
///
/// `text` and `suggestions` are always the complete plain message (text plus suggested-reply chips), so a consumer that ignores rich
/// cards still sends a correct message. `card` and `carousel` are optional rich forms of the **same** content; at most one is set, and
/// never for a secure handoff.
public struct RCSRendering: Sendable, Hashable {
    public var text: String
    public var suggestions: [RCSSuggestion]
    public var isSecureHandoff: Bool
    /// `status`, `reward` and `ticket`: the same content as one standalone card.
    public var card: RCSStandaloneCard? = nil
    /// A `choose` whose options do not fit as chips: one card per option, each carrying exactly that option's chip.
    public var carousel: RCSCarousel? = nil

    /// Every suggestion of the rich form (card or carousel), in order; empty without one.
    public var richSuggestions: [RCSSuggestion] {
        (card.map { [$0.content] } ?? carousel?.cards ?? []).flatMap(\.suggestions)
    }
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

    /// Renders for SMS. Interactions that cannot be completed by text say "Open the Viadere app": no link, no code and no token ever
    /// appears in a rendering (decision 9, ADR-0027). `page` pages long `choose` lists.
    public static func sms(_ interaction: Interaction, business: BusinessSummary, page: Int = 0) -> SMSRendering {
        let name = SMSEncoding.field(business.displayName, maxLength: 40)
        let prefix = "[\(name)]: "
        if !AssurancePolicy.canPresentInline(interaction, on: .sms) {
            return finish(prefix + secureHandoffText(interaction), choices: [], handoff: true)
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
            text += " Redeem in the Viadere app."
            return finish(text, choices: [], handoff: false)
        case .ticket(let p):
            let text = prefix + SMSEncoding.field(p.title, maxLength: 80) + ". View your ticket in the Viadere app."
            return finish(text, choices: [], handoff: false)
        case .message(let p):
            return finish(prefix + SMSEncoding.businessLine(p.text), choices: [], handoff: false)
        case .authenticate, .authorize, .unknown:
            return finish(prefix + secureHandoffText(interaction), choices: [], handoff: true)
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

    static func secureHandoffText(_ interaction: Interaction) -> String {
        let what: String
        switch interaction.kind {
        case .authenticate: what = "A sign-in request needs your review."
        case .authorize: what = "An approval request needs your review."
        default: what = "A secure request needs your review."
        }
        return what + " Open the Viadere app to review it. Viadere never asks you to approve by text."
    }

    private static func finish(_ body: String, choices: [SMSChoice], handoff: Bool) -> SMSRendering {
        SMSRendering(body: body, choices: choices, isSecureHandoff: handoff, encoding: SMSEncoding.analyze(body))
    }

    // MARK: RCS

    /// RBM limit on suggested-reply chips in one message.
    public static let maxRCSSuggestions = 11
    /// RBM limit on the text of one suggestion.
    public static let maxRCSSuggestionText = 25
    /// RBM limit on suggestions attached to one rich card.
    public static let maxRCSCardSuggestions = 4
    /// RBM bounds on the number of cards in a carousel.
    public static let rcsCarouselCards = 2...10
    /// Viadere's cap on a card title (RBM allows 200).
    public static let maxRCSCardTitle = 120
    /// Viadere's cap on a card description (RBM allows 2000).
    public static let maxRCSCardDescription = 400

    /// Whether `options` can be shown faithfully as a chip list: at most `maxRCSSuggestions` options and no label longer than
    /// `maxRCSSuggestionText` once rendered (a truncated chip can make two options look the same). A `choose` that does not fit and has
    /// 2-10 options (`rcsCarouselCards`, also the `choose` validation range) gets a carousel in addition to the chips.
    public static func optionsFitAsRCSChips(_ options: [ChoiceOption]) -> Bool {
        options.count <= maxRCSSuggestions
            && options.allSatisfy { SMSEncoding.field($0.label, maxLength: 40).count <= maxRCSSuggestionText }
    }

    /// Whether `interaction` may carry a rich card, a carousel or any actionable suggestion on RCS. The inline rule restated so the rich
    /// path never depends on the order of checks in `rcs`: never a security-sensitive or unknown kind, never above `.channelReply` (so never
    /// `high`/`critical` sensitivity).
    static func rcsRichContentAllowed(_ interaction: Interaction) -> Bool {
        AssurancePolicy.canPresentInline(interaction, on: .rcs) && !interaction.kind.isSecuritySensitive && !interaction.kind.isUnknown
            && interaction.requiredAssurance == .channelReply
    }

    /// Business text for a card: hostile scalars removed (`DisplayTextSanitizer`), one line with a leading `[` or `Viadere` neutralised
    /// (`SMSEncoding.businessLine`), then capped (`SMSEncoding.field`).
    static func rcsCardText(_ text: String, maxLength: Int) -> String {
        let cleaned = DisplayTextSanitizer.sanitize(text, maxCharacters: maxLength * 4)
        return SMSEncoding.field(SMSEncoding.businessLine(cleaned), maxLength: maxLength)
    }

    /// Renders for an RCS-like channel with suggested replies, plus a standalone card (`status`, `reward`, `ticket`) or a carousel (a
    /// `choose` whose options do not fit as chips, `optionsFitAsRCSChips`). The rich forms never change `text` or `suggestions`.
    public static func rcs(_ interaction: Interaction, business: BusinessSummary) -> RCSRendering {
        let name = SMSEncoding.field(business.displayName, maxLength: 40)
        func postback(_ target: String) -> String { "viadere:\(interaction.id):\(target)" }
        func reply(_ text: String, _ target: String) -> RCSSuggestion {
            RCSSuggestion(kind: .reply, text: SMSEncoding.field(text, maxLength: maxRCSSuggestionText), postbackData: postback(target), url: nil)
        }
        if !AssurancePolicy.canPresentInline(interaction, on: .rcs) {
            return RCSRendering(text: "[\(name)]: " + secureHandoffText(interaction), suggestions: [], isSecureHandoff: true)
        }
        let sms = sms(interaction, business: business)
        var suggestions: [RCSSuggestion] = []
        switch interaction.payload {
        case .confirm:
            suggestions = [reply("Confirm", "decision.confirm"), reply("Decline", "decision.decline")]
        case .choose(let p):
            suggestions = p.options.prefix(maxRCSSuggestions).map { reply($0.label, "option.\($0.id)") }
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
        var rendering = RCSRendering(text: text, suggestions: suggestions, isSecureHandoff: false)
        guard rcsRichContentAllowed(interaction) else { return rendering }
        func card(_ title: String, _ parts: [String]) -> RCSStandaloneCard {
            let description = parts.filter { !$0.isEmpty }.joined(separator: " ")
            return RCSStandaloneCard(content: RCSCardContent(
                title: "[\(name)]: " + rcsCardText(title, maxLength: min(80, maxRCSCardTitle - name.count - 4)),
                description: description.isEmpty ? nil : SMSEncoding.field(description, maxLength: maxRCSCardDescription)))
        }
        switch interaction.payload {
        case .status(let p):
            rendering.card = card(p.title, [p.body.map { rcsCardText($0, maxLength: 240) } ?? ""])
        case .reward(let p):
            rendering.card = card(p.title, [p.details.map { rcsCardText($0, maxLength: 160) } ?? "", "Redeem in the Viadere app."])
        case .ticket(let p):
            let place = [p.venue, p.seat].compactMap { $0.map { rcsCardText($0, maxLength: 80) } }.filter { !$0.isEmpty }.joined(separator: ", ")
            rendering.card = card(p.title, [place.isEmpty ? "" : place + ".", "View your ticket in the Viadere app."])
        case .choose(let p) where !optionsFitAsRCSChips(p.options) && rcsCarouselCards.contains(p.options.count):
            // One card per option: the full label as the title, the attributed prompt as the description, and exactly the chip the plain
            // message carries for that option (same text, same postback placeholder, so the same signed token on the wire).
            let prompt = "[\(name)]: " + rcsCardText(p.prompt, maxLength: 120)
            rendering.carousel = RCSCarousel(width: .medium, cards: p.options.map { option in
                RCSCardContent(title: rcsCardText(option.label, maxLength: 40), description: prompt,
                               suggestions: [reply(option.label, "option.\(option.id)")])
            })
        default:
            break
        }
        return rendering
    }

    // MARK: Native notifications

    /// True when a native rendering must finish in the app (assurance above `.deviceSignature`: step-up, Face ID or passcode). The
    /// notification's `requiresSecureFlow` and decision Live Activity eligibility (`LiveActivityPolicy.isDecisionEligible`) share this rule.
    public static func requiresSecureFlow(_ interaction: Interaction) -> Bool {
        interaction.requiredAssurance > .deviceSignature
    }

    /// Renders an actionable notification. For assurance above `.deviceSignature`, approve
    /// actions open the app so the device can perform biometric/passcode signing.
    public static func notification(_ interaction: Interaction, business: BusinessSummary) -> NotificationRendering {
        let secure = requiresSecureFlow(interaction)
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
            // F-14: approve on a security kind always foregrounds the app (an inline approve dead-ends). Refusals never need unlock (A6/A7 H1).
            actions = [action("approve", "Yes, it's me", foreground: true), action("deny", "No", .destructive, auth: false),
                       action("report", "Not me - report", .destructive, auth: false)]
            categoryId = secure ? "viadere.authenticate.secure" : "viadere.authenticate"
        case .authorize(let p):
            subtitle = "Approval request"
            body = authorizeSentence(p)
            actions = [action("approve", "Approve", foreground: true), action("deny", "Deny", .destructive, auth: false),
                       action("report", "Not me - report", .destructive, auth: false)]
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
        // ADR-0022 §5.5: security notifications are `active`, never time-sensitive (urgency adds pressure).
        case (.security, _): level = .active
        case (.transactional, .high): level = .timeSensitive
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
