import Foundation
import Testing
@testable import ViadereCore

@Suite("RCS postback targets")
struct RCSPostbackTests {
    let business = Fixtures.walmart

    @Test func renderedSuggestionsDecodeToTypedTargets() {
        let confirm = Fixtures.interaction(.confirm(ConfirmPayload(title: "Pickup")), sensitivity: .low)
        let rcs = ChannelRenderer.rcs(confirm, business: business, handoffURL: nil)
        #expect(rcs.suggestions.compactMap { $0.target(forInteraction: confirm.id) } == [.decision(.confirm), .decision(.decline)])

        let choose = Fixtures.interaction(.choose(Fixtures.choosePayload), sensitivity: .low)
        let chips = ChannelRenderer.rcs(choose, business: business, handoffURL: nil)
        #expect(chips.suggestions.compactMap { $0.target(forInteraction: choose.id) } == [.option("am"), .option("pm"), .option("eve")])

        let reply = Fixtures.interaction(.reply(ReplyPayload(prompt: "Fixed?", suggestedReplies: ["Yes", "No"])), sensitivity: .low)
        let replies = ChannelRenderer.rcs(reply, business: business, handoffURL: nil)
        #expect(replies.suggestions.compactMap { $0.target(forInteraction: reply.id) } == [.suggestedReply(0), .suggestedReply(1)])
    }

    @Test func openURLSuggestionsHaveNoTargetAndSensitiveInteractionsOfferNoReplyTargets() {
        let authorize = Fixtures.interaction(.authorize(Fixtures.mesaAuthorize), sensitivity: .high)
        let handoff = URL(string: "https://viadere.com/h/abc")
        let rcs = ChannelRenderer.rcs(authorize, business: business, handoffURL: handoff)
        #expect(rcs.isSecureHandoff)
        #expect(rcs.suggestions.allSatisfy { $0.target(forInteraction: authorize.id) == nil })
    }

    @Test func aPostbackOnlyParsesForItsOwnInteractionAndKnownTargets() {
        let id = InteractionID()
        #expect(RCSPostbackTarget.parse(postback: "viadere:\(id):decision.approve", interactionId: id) == .decision(.approve))
        #expect(RCSPostbackTarget.parse(postback: "viadere:\(id):option.slot-1", interactionId: id) == .option("slot-1"))
        #expect(RCSPostbackTarget.parse(postback: "viadere:\(id):suggested.3", interactionId: id) == .suggestedReply(3))
        for bad in ["viadere:\(InteractionID()):decision.approve", "viadere:\(id):decision.explode", "viadere:\(id):option.", "viadere:\(id):suggested.-1",
                    "viadere:\(id):suggested.x", "viadere:\(id):", "viadere:\(id)", "other:\(id):decision.approve", "", "decision.approve"] {
            #expect(RCSPostbackTarget.parse(postback: bad, interactionId: id) == nil, "\(bad)")
        }
    }

    @Test func storageValuesRoundTrip() {
        let targets: [RCSPostbackTarget] = [.decision(.confirm), .decision(.report), .option("a.b-c_d"), .suggestedReply(0), .suggestedReply(9)]
        for target in targets { #expect(RCSPostbackTarget(storageValue: target.storageValue) == target) }
        for bad in ["", "decision.", "decision.nope", "option.", "suggested.", "suggested.-2", "weird"] { #expect(RCSPostbackTarget(storageValue: bad) == nil, "\(bad)") }
    }

    @Test func theRCSInboundRouteIsInTheCatalogWithProviderSignatureAuth() {
        let route = APIRoutes.all.first { $0.name == "providers.rcs.inbound" }
        #expect(route?.template == "/v1/providers/rcs/inbound")
        #expect(route?.auth == .providerSignature)
        #expect(route?.method == .POST)
        #expect(Set(APIRoutes.all.map(\.name)).count == APIRoutes.all.count)
    }
}
