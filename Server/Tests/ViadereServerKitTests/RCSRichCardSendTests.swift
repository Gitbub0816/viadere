import Fluent
import Foundation
import ViadereCore
import Vapor
import XCTest
@testable import ViadereServerKit

/// G15b: the server sends the rich cards `ChannelRenderer.rcs` renders (`RCSRendering.card` / `.carousel`). Exploit paths first: a card must
/// never mint a second token for a target (that would let one choice be answered twice or outlive its menu), never carry a link, and a
/// provider that refuses rich cards must still get the plain message (and the SMS fallback rules stay as they were).
final class RCSRichCardSendTests: XCTestCase {
    let channels: [DeliveryChannel] = [.nativePush, .inApp, .rcs, .sms]

    private func withRCS(_ body: (TestHarness, ScriptedRCSHTTP) async throws -> Void) async throws {
        let http = ScriptedRCSHTTP()
        try await withHarness(rcs: GenericRBMProvider(config: RCSFixture.config, http: http)) { h in try await body(h, http) }
    }

    private struct World {
        var business: TestBusiness
        var relationship: Relationship
    }

    private func world(_ h: TestHarness) async throws -> World {
        let business = try await h.makeBusiness(name: "Northwind Air", handle: "northwindair")
        let consumer = try await h.readyConsumer()
        try await h.linkVerifiedPhone(consumer)
        return World(business: business, relationship: try await h.connect(consumer, to: business))
    }

    private func issue(_ h: TestHarness, _ w: World, _ payload: InteractionPayload) async throws -> Interaction {
        let r = try await h.issue(w.business, relationship: w.relationship, payload: payload, purpose: .transactional, ttl: 3600, channels: channels)
        XCTAssertEqual(r.status, .created, r.text)
        return try r.json(Interaction.self)
    }

    /// Options whose labels do not fit a 25-character chip: the renderer adds a carousel.
    private let longOptions = [ChoiceOption(id: "early", label: "Early boarding with priority lane"),
                               ChoiceOption(id: "standard", label: "Standard boarding at the gate"),
                               ChoiceOption(id: "late", label: "Last call boarding, no carry-on")]

    private func content(_ message: [String: Any]) -> [String: Any] { message["contentMessage"] as? [String: Any] ?? [:] }

    private func cardTokens(_ message: [String: Any]) -> [String] {
        let rich = content(message)["richCard"] as? [String: Any]
        let cards = ((rich?["carouselCard"] as? [String: Any])?["cardContents"] as? [[String: Any]])
            ?? ((rich?["standaloneCard"] as? [String: Any])?["cardContent"] as? [String: Any]).map { [$0] } ?? []
        return cards.flatMap { ($0["suggestions"] as? [[String: Any]] ?? []).compactMap { ($0["reply"] as? [String: Any])?["postbackData"] as? String } }
    }

    // MARK: Requirement 2: one token per target, shared by chip and card

    func testACarouselCardTapIsAcceptedOnceAndAReplayIsRefused() async throws {
        try await withRCS { h, http in
            let w = try await world(h)
            let interaction = try await issue(h, w, .choose(ChoosePayload(prompt: "How would you like to board?", options: longOptions)))
            try await h.runJobs()
            let sent = try h.rcsSentMessages(http)
            XCTAssertEqual(sent.count, 1)
            let body = content(sent[0])
            // A carousel replaces the text (mutually exclusive in RBM), carries no message-level chips and falls back to the plain text.
            XCTAssertNil(body["text"])
            XCTAssertNil(body["suggestions"])
            XCTAssertEqual(body["fallback"] as? String, "[Northwind Air]: How would you like to board?")
            let carousel = try XCTUnwrap((body["richCard"] as? [String: Any])?["carouselCard"] as? [String: Any])
            XCTAssertEqual(carousel["cardWidth"] as? String, "MEDIUM")
            XCTAssertEqual((carousel["cardContents"] as? [[String: Any]])?.count, 3)
            let tokens = cardTokens(sent[0])
            XCTAssertEqual(tokens.count, 3)
            XCTAssertEqual(Set(tokens).count, 3)
            XCTAssertFalse(tokens.contains { $0.contains("early") || $0.contains("viadere:") }, "tokens are opaque")
            // Exactly one stored token per target: the chips the plain message carries and the cards share them.
            let stored = try await RCSPostbackRecord.query(on: h.db).filter(\.$interactionId == interaction.id.uuid).all()
            XCTAssertEqual(stored.count, 3)
            XCTAssertEqual(Set(stored.map(\.target)).count, 3)
            XCTAssertEqual(Set(stored.map(\.menuVersion)).count, 1)
            // The tap on the second card selects its option, once.
            try await eq(try await h.rcsTap(token: tokens[1], messageId: "card-tap-1").status, .ok)
            let record = try await XCTUnwrapAsync(await InteractionRecord.find(interaction.id.uuid, on: h.db))
            XCTAssertEqual(record.statusValue, .selected)
            XCTAssertEqual(try ViadereJSON.decode(InteractionOutcome.self, from: Data(record.outcomeJSON!.utf8)).selectedOptionIds, ["standard"])
            // A new event with the same token is a replay: refused and audited; another card of the same (now answered) menu does nothing.
            try await eq(try await h.rcsTap(token: tokens[1], messageId: "card-tap-2").status, .ok)
            try await eq(try await h.rcsTap(token: tokens[0], messageId: "card-tap-3").status, .ok)
            try await eq(try await AuditEventRecord.query(on: h.db).filter(\.$action == "interaction.decided").count(), 1)
            let rejections = try await AuditEventRecord.query(on: h.db).filter(\.$action == "rcs.postback_rejected").all()
            XCTAssertGreaterThanOrEqual(rejections.count, 1)
            XCTAssertTrue(rejections.contains { $0.metadataJSON.contains("replayed") })
            let final = try await XCTUnwrapAsync(await InteractionRecord.find(interaction.id.uuid, on: h.db))
            XCTAssertEqual(try ViadereJSON.decode(InteractionOutcome.self, from: Data(final.outcomeJSON!.utf8)).selectedOptionIds, ["standard"])
        }
    }

    func testAStandaloneCardIsSentForAStatusUpdateWithoutText() async throws {
        try await withRCS { h, http in
            let w = try await world(h)
            _ = try await issue(h, w, .status(StatusPayload(title: "Your flight is boarding", body: "Gate 14, boarding group 3.")))
            try await h.runJobs()
            let body = content(try XCTUnwrap(try h.rcsSentMessages(http).first))
            XCTAssertNil(body["text"])
            let standalone = try XCTUnwrap((body["richCard"] as? [String: Any])?["standaloneCard"] as? [String: Any])
            XCTAssertEqual(standalone["cardOrientation"] as? String, "VERTICAL")
            let card = try XCTUnwrap(standalone["cardContent"] as? [String: Any])
            XCTAssertEqual(card["title"] as? String, "[Northwind Air]: Your flight is boarding")
            XCTAssertEqual(card["description"] as? String, "Gate 14, boarding group 3.")
            XCTAssertNil(card["media"])
        }
    }

    // MARK: Requirement 6: a refused rich card is resent as plain text and chips with the same tokens

    func testAProviderThatRefusesRichCardsGetsThePlainMessageWithTheSameTokens() async throws {
        try await withRCS { h, http in
            let w = try await world(h)
            http.queueSendStatuses([400, 200])
            let interaction = try await issue(h, w, .choose(ChoosePayload(prompt: "How would you like to board?", options: longOptions)))
            try await h.runJobs()
            let sent = try h.rcsSentMessages(http)
            XCTAssertEqual(sent.count, 2, "one rich attempt, one plain resend")
            XCTAssertNotNil(content(sent[0])["richCard"])
            let plain = content(sent[1])
            XCTAssertNil(plain["richCard"])
            XCTAssertEqual(plain["text"] as? String, "[Northwind Air]: How would you like to board?")
            let chips = h.replyTokens(in: sent[1])
            XCTAssertEqual(chips.map(\.token), cardTokens(sent[0]), "the plain chips carry exactly the cards' tokens")
            XCTAssertEqual(sent[1]["messageId"] as? String, (sent[0]["messageId"] as? String).map { $0 + "-text" })
            try await eq(try await RCSPostbackRecord.query(on: h.db).filter(\.$interactionId == interaction.id.uuid).count(), 3)
            let row = try await XCTUnwrapAsync(await ChannelOutboundRecord.query(on: h.db).first())
            XCTAssertEqual(row.channel, "rcs")
            XCTAssertEqual(row.status, "sent")
            try await eq(try await h.rcsTap(token: chips[2].token).status, .ok)
            try await eq(try await InteractionRecord.find(interaction.id.uuid, on: h.db)?.statusValue, .selected)
        }
    }

    func testWhenThePlainResendIsAlsoRefusedTheSMSFallbackRulesAreUnchanged() async throws {
        try await withRCS { h, http in
            let w = try await world(h)
            http.queueSendStatuses([422, 422])
            _ = try await issue(h, w, .status(StatusPayload(title: "Your flight is boarding", body: "Gate 14.")))
            try await h.runJobs()
            XCTAssertEqual(http.sends.count, 2)
            let row = try await XCTUnwrapAsync(await ChannelOutboundRecord.query(on: h.db).first())
            XCTAssertEqual(row.channel, "sms")
            XCTAssertEqual(row.fallbackReason, "not_capable")
            try await h.runJobs()
            let sms = try XCTUnwrap(h.texts.sent.last)
            XCTAssertFalse(sms.body.contains("Gate 14"), "details stay out of SMS exactly as before")
            // A 429 on the rich send is a transient error, not a refusal: no plain resend in the same attempt.
            let other = try await world2(h)
            http.queueSendStatuses([429])
            let before = http.sends.count
            _ = try await issue(h, other, .status(StatusPayload(title: "Delayed")))
            try await h.runJobs()
            XCTAssertEqual(http.sends.count, before + 1)
        }
    }

    private func world2(_ h: TestHarness) async throws -> World {
        let business = try await h.makeBusiness(name: "Contoso Rail", handle: "contosorail")
        let consumer = try await h.readyConsumer()
        try await h.linkVerifiedPhone(consumer, phone: "+14805550199")
        return World(business: business, relationship: try await h.connect(consumer, to: business))
    }

    // MARK: Requirement 5: never a link from card content

    func testACardWithAURLSuggestionIsRefusedAndNeverSendsAnOpenURLAction() async throws {
        try await withRCS { h, _ in
            let w = try await world(h)
            let interaction = try await issue(h, w, .choose(ChoosePayload(prompt: "How would you like to board?", options: longOptions)))
            let rendered = ChannelRenderer.rcs(interaction, business: w.business.summary)
            XCTAssertNotNil(RCSChannelAdapter.channelRendering(rendered, interactionId: interaction.id).carousel, "the honest rendering carries its carousel")
            let link = try JSONDecoder().decode(RCSSuggestion.self, from: Data(#"{"kind":"openURL","text":"Open","url":"https://evil.example/x"}"#.utf8))
            var withLink = rendered
            withLink.carousel?.cards[1].suggestions.append(link)
            let mapped = RCSChannelAdapter.channelRendering(withLink, interactionId: interaction.id)
            XCTAssertNil(mapped.carousel, "a card with a URL suggestion is refused")
            XCTAssertEqual(mapped.suggestions.count, rendered.suggestions.count, "the plain chips are unchanged")
            var standalone = rendered
            standalone.carousel = nil
            standalone.card = RCSStandaloneCard(content: RCSCardContent(title: "Hello", suggestions: [link]))
            XCTAssertNil(RCSChannelAdapter.channelRendering(standalone, interactionId: interaction.id).card)
            // A postback naming another interaction is not a target of this one either.
            var foreign = rendered
            foreign.carousel = nil
            let other = try JSONDecoder().decode(RCSSuggestion.self, from: Data(#"{"kind":"reply","text":"Yes","postbackData":"viadere:\#(InteractionID()):decision.confirm"}"#.utf8))
            foreign.card = RCSStandaloneCard(content: RCSCardContent(title: "Hello", suggestions: [other]))
            XCTAssertNil(RCSChannelAdapter.channelRendering(foreign, interactionId: interaction.id).card)
        }
    }

    func testTheTransportRefusesACardWithALinkAndSendsThePlainMessage() async throws {
        // The transport refuses too, whatever reaches it: the message goes out plain, and no `openUrlAction` is ever emitted from a card.
        let http = ScriptedRCSHTTP()
        let provider = GenericRBMProvider(config: RCSFixture.config, http: http)
        let evil = OutboundCard(title: "Hello", suggestions: [.reply("Yes", token: "tok-1"), .openURL("Open", url: URL(string: "https://evil.example/x")!)])
        _ = try await provider.send(OutboundChannelMessage(text: "[Shop]: Hello", suggestions: [.reply("Yes", token: "tok-1")], card: evil),
                                    to: PhoneNumber(RCSFixture.phone)!, reference: "ref-1")
        _ = try await provider.send(OutboundChannelMessage(text: "[Shop]: Pick", carousel: [OutboundCard(title: "A", suggestions: [.reply("A", token: "t-a")]), evil]),
                                    to: PhoneNumber(RCSFixture.phone)!, reference: "ref-2")
        for request in http.sends {
            let text = String(decoding: request.body ?? Data(), as: UTF8.self)
            XCTAssertFalse(text.contains("openUrlAction"), text)
            XCTAssertFalse(text.contains("evil.example"), text)
            XCTAssertFalse(text.contains("richCard"), text)
            XCTAssertTrue(text.contains("\"text\":\"[Shop]:"), text)
        }
        XCTAssertEqual(http.sends.count, 2)
    }

    // MARK: Request-body snapshots (requirement 3)

    func testStandaloneCardRequestBodySnapshot() async throws {
        let http = ScriptedRCSHTTP()
        let provider = GenericRBMProvider(config: RCSFixture.config, http: http)
        let message = OutboundChannelMessage(text: "[Northwind Air]: Your flight is boarding",
                                             card: OutboundCard(title: "[Northwind Air]: Your flight is boarding", description: "Gate 14."))
        _ = try await provider.send(message, to: PhoneNumber(RCSFixture.phone)!, reference: "ref-standalone")
        XCTAssertEqual(String(decoding: try XCTUnwrap(http.sends.first?.body), as: UTF8.self),
                       #"{"agentId":"viadere-agent","contentMessage":{"richCard":{"standaloneCard":{"cardContent":{"description":"Gate 14.","title":"[Northwind Air]: Your flight is boarding"},"cardOrientation":"VERTICAL"}}},"messageId":"ref-standalone","to":"+14805550123"}"#)
        // `description` is omitted when nil; card suggestions are replies with the opaque token.
        _ = try await provider.send(OutboundChannelMessage(text: "[Shop]: Hi", card: OutboundCard(title: "Hi", suggestions: [.reply("Yes", token: "tok-y")])),
                                    to: PhoneNumber(RCSFixture.phone)!, reference: "ref-2")
        XCTAssertEqual(String(decoding: try XCTUnwrap(http.sends.last?.body), as: UTF8.self),
                       #"{"agentId":"viadere-agent","contentMessage":{"richCard":{"standaloneCard":{"cardContent":{"suggestions":[{"reply":{"postbackData":"tok-y","text":"Yes"}}],"title":"Hi"},"cardOrientation":"VERTICAL"}}},"messageId":"ref-2","to":"+14805550123"}"#)
    }

    func testCarouselRequestBodySnapshot() async throws {
        let http = ScriptedRCSHTTP()
        let provider = GenericRBMProvider(config: RCSFixture.config, http: http)
        let message = OutboundChannelMessage(text: "[Shop]: Which?", suggestions: [.reply("A", token: "t-a"), .reply("B", token: "t-b")],
                                             carousel: [OutboundCard(title: "Option A", description: "[Shop]: Which?", suggestions: [.reply("A", token: "t-a")]),
                                                        OutboundCard(title: "Option B", description: "[Shop]: Which?", suggestions: [.reply("B", token: "t-b")])])
        _ = try await provider.send(message, to: PhoneNumber(RCSFixture.phone)!, reference: "ref-carousel")
        XCTAssertEqual(String(decoding: try XCTUnwrap(http.sends.first?.body), as: UTF8.self),
                       #"{"agentId":"viadere-agent","contentMessage":{"fallback":"[Shop]: Which?","richCard":{"carouselCard":{"cardContents":[{"description":"[Shop]: Which?","suggestions":[{"reply":{"postbackData":"t-a","text":"A"}}],"title":"Option A"},{"description":"[Shop]: Which?","suggestions":[{"reply":{"postbackData":"t-b","text":"B"}}],"title":"Option B"}],"cardWidth":"MEDIUM"}}},"messageId":"ref-carousel","to":"+14805550123"}"#)
        // Out-of-range carousels (one card, or eleven) and over-full cards (five suggestions) are not sent as rich cards.
        let one = OutboundChannelMessage(text: "[Shop]: Which?", carousel: [OutboundCard(title: "Only")])
        XCTAssertFalse(GenericRBMProvider.contentJSON(one, rich: true).isRich)
        let eleven = OutboundChannelMessage(text: "t", carousel: Array(repeating: OutboundCard(title: "x"), count: 11))
        XCTAssertFalse(GenericRBMProvider.contentJSON(eleven, rich: true).isRich)
        let crowded = OutboundChannelMessage(text: "t", card: OutboundCard(title: "x", suggestions: (1...5).map { .reply("\($0)", token: "t\($0)") }))
        XCTAssertFalse(GenericRBMProvider.contentJSON(crowded, rich: true).isRich)
    }
}
