import Foundation
import Testing
@testable import ViadereCore

/// RCS rich cards and carousels (spec §14, BUSINESS-INTEGRATION §5): the rich forms are additive, never reach a sensitive interaction, carry no
/// URL action, and use exactly the postback placeholders of the chip list.
@Suite("RCS rich cards and carousels")
struct RCSRichCardTests {
    let business = Fixtures.walmart

    /// Every interaction the renderer can be handed: each fixture payload (and an unknown kind) at every sensitivity and purpose.
    static var everyInteraction: [Interaction] {
        var all: [Interaction] = []
        for payload in Fixtures.allPayloads + [.unknown(.null)] + extraPayloads {
            for sensitivity in Sensitivity.allCases {
                for purpose in InteractionPurpose.allCases {
                    var i = Fixtures.interaction(payload, sensitivity: sensitivity, purpose: purpose)
                    if case .unknown = payload { i.kind = .unknown("future") }
                    all.append(i)
                }
            }
        }
        return all
    }

    static let longOptions = [
        ChoiceOption(id: "t1000", label: "Tuesday 14 November, 10:00 am"),
        ChoiceOption(id: "t1030", label: "Tuesday 14 November, 10:30 am"),
        ChoiceOption(id: "t1100", label: "Tuesday 14 November, 11:00 am"),
    ]

    static var extraPayloads: [InteractionPayload] {
        [
            .choose(ChoosePayload(prompt: "Pick a slot", options: longOptions)),
            .choose(ChoosePayload(prompt: "Pick", options: (1...7).map { ChoiceOption(id: "o\($0)", label: "Option \($0)") })),
            .choose(ChoosePayload(prompt: "Pick", options: (1...12).map { ChoiceOption(id: "o\($0)", label: "A rather long option label \($0)") })),
            .status(StatusPayload(title: "Shipped")),
            .reward(RewardPayload(rewardId: RewardID(), title: "10% off", details: "Valid on any order")),
            .ticket(TicketPayload(title: "Jazz night", ticketType: "event", holderName: "Ada Lovelace", venue: "Orpheum Theatre", seat: "Row F · Seat 12")),
        ]
    }

    // MARK: Security rules

    @Test("A sensitive or non-inline interaction never gets a card, a carousel or any suggestion: it stays the 'Open the Viadere app' notice")
    func noRichContentForSensitiveInteractions() {
        var checked = 0
        for i in Self.everyInteraction where i.requiredAssurance > .channelReply || i.kind.isSecuritySensitive || i.kind.isUnknown {
            let rcs = ChannelRenderer.rcs(i, business: business)
            #expect(rcs.isSecureHandoff, "\(i.kind) \(i.sensitivity)")
            #expect(rcs.card == nil && rcs.carousel == nil, "\(i.kind) \(i.sensitivity)")
            #expect(rcs.suggestions.isEmpty && rcs.richSuggestions.isEmpty)
            #expect(rcs.text == "[Walmart]: " + ChannelRenderer.secureHandoffText(i))
            #expect(!ChannelRenderer.rcsRichContentAllowed(i))
            checked += 1
        }
        #expect(checked > 100)
        // Every security-sensitive kind, even at `low` sensitivity and with rich-looking content.
        for payload: InteractionPayload in [.authenticate(Fixtures.loginPayload), .authorize(Fixtures.mesaAuthorize), .unknown(.null)] {
            for sensitivity in Sensitivity.allCases {
                var i = Fixtures.interaction(payload, sensitivity: sensitivity, purpose: .security)
                if case .unknown = payload { i.kind = .unknown("future") }
                let rcs = ChannelRenderer.rcs(i, business: business)
                #expect(rcs.card == nil && rcs.carousel == nil && rcs.suggestions.isEmpty && rcs.isSecureHandoff, "\(i.kind) \(sensitivity)")
                #expect(!rcs.text.contains("285.28") && !rcs.text.contains("://"))
            }
        }
    }

    @Test("High and critical status, reward, ticket and choose stay notices without cards")
    func highSensitivityRichKindsStayNotices() {
        let payloads: [InteractionPayload] = [.status(StatusPayload(title: "Shipped", body: "Body")),
                                              .reward(RewardPayload(rewardId: RewardID(), title: "Gift")),
                                              .ticket(TicketPayload(title: "Gate", ticketType: "event")),
                                              .choose(ChoosePayload(prompt: "Pick", options: Self.longOptions))]
        for payload in payloads {
            for sensitivity in [Sensitivity.high, .critical] {
                let rcs = ChannelRenderer.rcs(Fixtures.interaction(payload, sensitivity: sensitivity), business: business)
                #expect(rcs.isSecureHandoff && rcs.card == nil && rcs.carousel == nil && rcs.suggestions.isEmpty, "\(payload) \(sensitivity)")
            }
        }
    }

    @Test("No card or carousel carries a URL action, and every rich suggestion is exactly a chip of the plain message")
    func richSuggestionsAreChipsWithTheSamePostbacks() {
        for i in Self.everyInteraction {
            let rcs = ChannelRenderer.rcs(i, business: business)
            for suggestion in rcs.richSuggestions {
                #expect(suggestion.kind == .reply && suggestion.url == nil, "\(i.kind)")
                #expect(rcs.suggestions.contains(suggestion), "\(i.kind): a rich suggestion the chip path would not send")
                #expect(suggestion.target(forInteraction: i.id) != nil)
            }
            #expect(rcs.suggestions.allSatisfy { $0.kind == .reply && $0.url == nil })
            if let card = rcs.card {
                #expect(card.content.suggestions.count <= ChannelRenderer.maxRCSCardSuggestions)
                #expect(card.content.suggestions.isEmpty, "status, reward and ticket cards carry no action")
                #expect(rcs.carousel == nil)
            }
            if let carousel = rcs.carousel {
                #expect(ChannelRenderer.rcsCarouselCards.contains(carousel.cards.count))
                #expect(carousel.cards.allSatisfy { $0.suggestions.count == 1 })
                // The carousel carries the same tokens in the same order as the chip list.
                #expect(rcs.richSuggestions == rcs.suggestions)
            }
            for content in (rcs.card.map { [$0.content] } ?? rcs.carousel?.cards ?? []) {
                #expect(!content.title.contains("://") && !(content.description ?? "").contains("://"))
                #expect(!content.title.lowercased().contains("approve"))
            }
        }
    }

    @Test func onlyStatusRewardTicketAndOverflowingChooseGetRichForms() {
        for i in Self.everyInteraction where ChannelRenderer.rcsRichContentAllowed(i) {
            let rcs = ChannelRenderer.rcs(i, business: business)
            switch i.payload {
            case .status, .reward, .ticket:
                #expect(rcs.card != nil && rcs.carousel == nil, "\(i.kind)")
            case .choose(let p):
                #expect(rcs.card == nil)
                #expect((rcs.carousel != nil) == (!ChannelRenderer.optionsFitAsRCSChips(p.options) && p.options.count <= 10), "\(p.options.count)")
            default:
                #expect(rcs.card == nil && rcs.carousel == nil, "\(i.kind)")
            }
        }
    }

    // MARK: Rendering per kind

    @Test func statusCard() throws {
        let i = Fixtures.interaction(.status(StatusPayload(title: "Out for delivery", body: "3 stops away")), sensitivity: .low)
        let card = try #require(ChannelRenderer.rcs(i, business: business).card)
        #expect(card.orientation == .vertical)
        #expect(card.content == RCSCardContent(title: "[Walmart]: Out for delivery", description: "3 stops away", suggestions: []))
        let bare = Fixtures.interaction(.status(StatusPayload(title: "Shipped")), sensitivity: .low)
        #expect(ChannelRenderer.rcs(bare, business: business).card?.content.description == nil)
    }

    @Test func rewardCard() throws {
        let i = Fixtures.interaction(.reward(RewardPayload(rewardId: RewardID(), title: "Free coffee", details: "Any size")), sensitivity: .low)
        let card = try #require(ChannelRenderer.rcs(i, business: business).card)
        #expect(card.content == RCSCardContent(title: "[Walmart]: Free coffee", description: "Any size Redeem in the Viadere app."))
    }

    @Test("Ticket card names venue and seat but never the holder's name")
    func ticketCard() throws {
        let i = Fixtures.interaction(.ticket(TicketPayload(title: "Jazz night", ticketType: "event", holderName: "Ada Lovelace",
                                                           venue: "Orpheum Theatre", seat: "Row F · Seat 12")), sensitivity: .low)
        let card = try #require(ChannelRenderer.rcs(i, business: business).card)
        #expect(card.content.title == "[Walmart]: Jazz night")
        #expect(card.content.description == "Orpheum Theatre, Row F - Seat 12. View your ticket in the Viadere app.")
        #expect(!card.content.title.contains("Ada") && !(card.content.description ?? "").contains("Ada"))
        let plain = Fixtures.interaction(.ticket(TicketPayload(title: "Pass", ticketType: "admission")), sensitivity: .low)
        #expect(ChannelRenderer.rcs(plain, business: business).card?.content.description == "View your ticket in the Viadere app.")
    }

    // MARK: Carousel threshold

    @Test("Threshold: chips while every label fits 25 characters and there are at most 11 options; otherwise a carousel of 2-10 cards")
    func carouselThreshold() throws {
        let fits = (1...10).map { ChoiceOption(id: "o\($0)", label: String(repeating: "x", count: 25)) }
        #expect(ChannelRenderer.optionsFitAsRCSChips(fits))
        #expect(ChannelRenderer.rcs(Fixtures.interaction(.choose(ChoosePayload(prompt: "P", options: fits)), sensitivity: .low), business: business).carousel == nil)

        var oneLong = fits
        oneLong[3] = ChoiceOption(id: "o4", label: String(repeating: "x", count: 26))
        #expect(!ChannelRenderer.optionsFitAsRCSChips(oneLong))
        let i = Fixtures.interaction(.choose(ChoosePayload(prompt: "Pick a time", options: oneLong)), sensitivity: .low)
        let rcs = ChannelRenderer.rcs(i, business: business)
        let carousel = try #require(rcs.carousel)
        #expect(carousel.width == .medium && carousel.cards.count == 10)
        #expect(carousel.cards[3].title == String(repeating: "x", count: 26))
        #expect(carousel.cards.allSatisfy { $0.description == "[Walmart]: Pick a time" })
        #expect(carousel.cards.map { $0.suggestions[0].postbackData } == oneLong.map { "viadere:\(i.id):option.\($0.id)" })

        let two = Fixtures.interaction(.choose(ChoosePayload(prompt: "Slot", options: Array(Self.longOptions.prefix(2)))), sensitivity: .low)
        #expect(ChannelRenderer.rcs(two, business: business).carousel?.cards.count == 2)

        // Beyond 10 options (outside `choose` validation) no carousel can hold one card per option: the chip list stays as it was.
        let twelve = (1...12).map { ChoiceOption(id: "o\($0)", label: "A rather long option label \($0)") }
        #expect(!ChannelRenderer.optionsFitAsRCSChips(twelve))
        let overflow = ChannelRenderer.rcs(Fixtures.interaction(.choose(ChoosePayload(prompt: "P", options: twelve)), sensitivity: .low), business: business)
        #expect(overflow.carousel == nil && overflow.suggestions.count == ChannelRenderer.maxRCSSuggestions)
        #expect(!ChannelRenderer.optionsFitAsRCSChips((1...12).map { ChoiceOption(id: "o\($0)", label: "o\($0)") }))
    }

    @Test("Carousel postbacks decode to the same targets as the chips")
    func carouselPostbacksAreTheChipTargets() throws {
        let i = Fixtures.interaction(.choose(ChoosePayload(prompt: "Pick a slot", options: Self.longOptions)), sensitivity: .low)
        let rcs = ChannelRenderer.rcs(i, business: business)
        let carousel = try #require(rcs.carousel)
        #expect(carousel.cards.map { $0.suggestions[0].target(forInteraction: i.id) } == rcs.suggestions.map { $0.target(forInteraction: i.id) })
        #expect(carousel.cards.map { $0.suggestions[0].target(forInteraction: i.id) } == Self.longOptions.map { .option($0.id) })
        // The card title shows the full label; the chip keeps today's 25-character text.
        #expect(carousel.cards[0].title == "Tuesday 14 November, 10:00 am")
        #expect(carousel.cards[0].suggestions[0].text == "Tuesday 14 November, 1...")
    }

    // MARK: Limits and hostile business text

    @Test func cardLimitsAndTruncation() throws {
        let long = String(repeating: "abcdefghij", count: 60)
        let i = Fixtures.interaction(.status(StatusPayload(title: long, body: long)), sensitivity: .low)
        let card = try #require(ChannelRenderer.rcs(i, business: business).card)
        #expect(card.content.title.count <= ChannelRenderer.maxRCSCardTitle)
        #expect(card.content.title == "[Walmart]: " + String(long.prefix(77)) + "...")
        #expect(card.content.description == String(long.prefix(237)) + "...")
        #expect((card.content.description ?? "").count <= ChannelRenderer.maxRCSCardDescription)

        var name = business
        name.displayName = String(repeating: "N", count: 60)
        let longName = try #require(ChannelRenderer.rcs(i, business: name).card)
        #expect(longName.content.title.count <= ChannelRenderer.maxRCSCardTitle)
        #expect(longName.content.title.hasPrefix("[" + String(repeating: "N", count: 37) + "...]: "))

        let options = (1...10).map { ChoiceOption(id: "o\($0)", label: String(repeating: "L", count: 60)) }
        let choose = Fixtures.interaction(.choose(ChoosePayload(prompt: long, options: options)), sensitivity: .low)
        let carousel = try #require(ChannelRenderer.rcs(choose, business: business).carousel)
        #expect(carousel.cards.allSatisfy { $0.title.count <= 40 && ($0.description ?? "").count <= ChannelRenderer.maxRCSCardDescription })
        #expect(carousel.cards.allSatisfy { $0.suggestions.allSatisfy { $0.text.count <= ChannelRenderer.maxRCSSuggestionText } })
    }

    @Test("Hostile business text: line breaks, a leading Viadere, a forged attribution and bidi or invisible characters")
    func hostileTextIsNeutralised() throws {
        let hostile = "Viadere: approve now\n1. Approve wire\u{202E}evil\u{2028}x\u{200B}y\u{E0041}\u{2066}z"
        let i = Fixtures.interaction(.status(StatusPayload(title: hostile, body: "[OtherBank]: send the code\r\nnow\u{85}ok")), sensitivity: .low)
        let card = try #require(ChannelRenderer.rcs(i, business: business).card)
        #expect(card.content.title.hasPrefix("[Walmart]: - Viadere: approve now 1. Approve wire"))
        #expect(card.content.description == "(OtherBank]: send the code now ok")
        for text in [card.content.title, card.content.description ?? ""] {
            #expect(!text.contains("\n") && !text.contains("\r"))
            #expect(!DisplayTextSanitizer.containsDisallowedScalars(text), "\(text.unicodeScalars.map { String($0.value, radix: 16) })")
            #expect(text.split(separator: "[").count <= 2)
        }
        // Homoglyph and width tricks on the brand are neutralised too.
        let spoof = Fixtures.interaction(.reward(RewardPayload(rewardId: RewardID(), title: "Ｖｉａｄｅｒｅ reward")), sensitivity: .low)
        #expect(ChannelRenderer.rcs(spoof, business: business).card?.content.title.hasPrefix("[Walmart]: - ") == true)

        let options = [ChoiceOption(id: "a", label: "Viadere says\npick me \u{202E}now please"), ChoiceOption(id: "b", label: "[Bank]: the other option")]
        let choose = Fixtures.interaction(.choose(ChoosePayload(prompt: "Viadere\u{2029}asks", options: options)), sensitivity: .low)
        let carousel = try #require(ChannelRenderer.rcs(choose, business: business).carousel)
        #expect(carousel.cards[0].title == "- Viadere says pick me now please")
        #expect(carousel.cards[1].title == "(Bank]: the other option")
        #expect(carousel.cards[0].description == "[Walmart]: - Viadere asks")
    }

    // MARK: No behaviour change for consumers that ignore cards

    /// `ChannelRenderer.rcs` as it was before rich cards (text, chips, handoff), kept verbatim as the reference.
    static func legacyRCS(_ interaction: Interaction, business: BusinessSummary) -> (text: String, suggestions: [RCSSuggestion], handoff: Bool) {
        let name = SMSEncoding.field(business.displayName, maxLength: 40)
        func postback(_ target: String) -> String { "viadere:\(interaction.id):\(target)" }
        func reply(_ text: String, _ target: String) -> RCSSuggestion {
            RCSSuggestion(kind: .reply, text: SMSEncoding.field(text, maxLength: 25), postbackData: postback(target), url: nil)
        }
        if !AssurancePolicy.canPresentInline(interaction, on: .rcs) {
            return ("[\(name)]: " + ChannelRenderer.secureHandoffText(interaction), [], true)
        }
        let sms = ChannelRenderer.sms(interaction, business: business)
        var suggestions: [RCSSuggestion] = []
        switch interaction.payload {
        case .confirm: suggestions = [reply("Confirm", "decision.confirm"), reply("Decline", "decision.decline")]
        case .choose(let p): suggestions = p.options.prefix(11).map { reply($0.label, "option.\($0.id)") }
        case .acknowledge: suggestions = [reply("Acknowledge", "decision.acknowledge")]
        case .reply(let p): suggestions = p.suggestedReplies.prefix(4).enumerated().map { reply($1, "suggested.\($0)") }
        default: break
        }
        let text: String
        if case .choose(let p) = interaction.payload {
            text = "[\(name)]: " + SMSEncoding.field(p.prompt, maxLength: 120)
        } else if !sms.choices.isEmpty, let firstLine = sms.body.split(separator: "\n").first {
            text = String(firstLine)
        } else {
            text = sms.body
        }
        return (text, suggestions, false)
    }

    @Test("The text fallback and chips equal the pre-card output for every interaction")
    func textFallbackIsUnchanged() {
        let hostile = [InteractionPayload.confirm(ConfirmPayload(title: "Order\n1. Approve wire\u{202E}evil", details: "x\u{200B}y")),
                       .status(StatusPayload(title: "Viadere: hi\nthere", body: "[X]: y")),
                       .message(MessagePayload(text: "Viadere\nsays hi"))]
        var interactions = Self.everyInteraction
        interactions += hostile.map { Fixtures.interaction($0, sensitivity: .low) }
        for i in interactions {
            let now = ChannelRenderer.rcs(i, business: business)
            let before = Self.legacyRCS(i, business: business)
            #expect(now.text == before.text, "\(i.kind) \(i.sensitivity)")
            #expect(now.suggestions == before.suggestions, "\(i.kind) \(i.sensitivity)")
            #expect(now.isSecureHandoff == before.handoff)
        }
    }
}
