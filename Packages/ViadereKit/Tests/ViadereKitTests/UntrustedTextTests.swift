import Testing
import Foundation
import ViadereCore
@testable import ViadereKit

/// Business-supplied strings on security-relevant screens: one sanitizer, applied everywhere.
@Suite("Untrusted text")
struct UntrustedTextTests {
    static func envelope(business: String = "Northfield Market", merchant: String? = "Northfield Market",
                         action: String = "Card purchase", location: String? = "in or near Mesa, Arizona",
                         effect: String? = "The purchase will go through.", risk: String = "Far from your usual location",
                         amount: String = "285.28", verified: Bool = true) -> InteractionEnvelope {
        var envelope = PreviewData.authorize(amount: amount)
        envelope.business = BusinessSummary(id: PreviewData.northfield.id, displayName: business, handle: PreviewData.northfield.handle,
                                            code: PreviewData.northfield.code, verificationStatus: verified ? .verified : .pending)
        envelope.interaction.payload = .authorize(AuthorizePayload(
            actionDescription: action, amount: try? MoneyAmount(string: amount, currency: .usd), merchant: merchant, location: location,
            effectOfApproval: effect, riskIndicators: [RiskIndicator(code: "x", label: risk, severity: .warning)]))
        return envelope
    }

    /// Every invisible or reordering character the sanitizer must remove.
    static let hostile: [UInt32] = [
        0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069, 0x200E, 0x200F, 0x061C, 0x180E,
        0x200B, 0x200C, 0x200D, 0x2060, 0xFEFF, 0x00AD, 0x0000, 0x0007, 0x001B, 0x007F, 0x0085, 0x2028, 0x2029, 0xE0041, 0x3164,
    ]

    @Test func stripsEveryBidiZeroWidthAndControlCharacter() {
        for value in Self.hostile {
            let scalar = Unicode.Scalar(value)!
            let cleaned = UntrustedText.clean("Pay\(scalar)ment")
            #expect(!cleaned.unicodeScalars.contains(scalar), "U+\(String(value, radix: 16)) survived")
            #expect(cleaned.unicodeScalars.allSatisfy { UntrustedText.classify($0) != .drop })
        }
    }

    @Test func rightToLeftOverrideCannotReorderTheAmount() {
        // "\u{202E}" would render the rest right-to-left, e.g. to make "$285.28" read as "$82.582".
        let envelope = Self.envelope(merchant: "\u{202E}Mrofdlo\u{202C} Store\u{2067}\u{061C}\u{180E}")
        let question = InteractionPresentation.question(envelope.interaction)
        let reason = ApprovalPolicy.promptReason(for: envelope, decision: .approve)
        for text in [question, reason] + InteractionPresentation.details(envelope).map(\.value) {
            #expect(text.unicodeScalars.allSatisfy { !Self.hostile.contains($0.value) }, "\(text)")
        }
        #expect(question.contains("$285.28"))
        #expect(reason.contains("$285.28"))
    }

    @Test func newlineCannotFakeAnAmountRow() {
        let envelope = Self.envelope(action: "Coffee\nAmount\n$1.00\r\nMerchant: Somewhere kind",
                                     location: "Mesa\u{2028}Account: someone else")
        let rows = InteractionPresentation.details(envelope)
        for row in rows {
            #expect(!row.value.contains("\n") && !row.value.contains("\r"))
            #expect(!row.value.unicodeScalars.contains { $0.value == 0x2028 || $0.value == 0x2029 })
        }
        #expect(rows.filter { $0.label == "Amount" }.count == 1)
        #expect(rows.first { $0.label == "Amount" }?.value == "$285.28 USD")
        #expect(rows.first { $0.label == "Purpose" }?.value == "Coffee Amount $1.00 Merchant: Somewhere kind")
        // labels are Viadere's; the injected words only ever appear inside a value
        #expect(Set(rows.map(\.label)).isSubset(of: ["From", "Purpose", "Amount", "Merchant", "Location", "Account", "Requested"]))
    }

    @Test func viadereImpersonationIsQuotedAndAttributed() {
        for name in ["Viadere Security", "VIADERE", "V1adere Support", "Via\u{200B}dere Team", "V.i.a.d.e.r.e", "Vіadere", "ＶＩＡＤＥＲＥ Alerts"] {
            let safe = UntrustedText.name(name)
            #expect(safe.impersonatesViadere, "\(name)")
            #expect(safe.text.hasPrefix("Business \u{201C}"))
            #expect(safe.text.hasSuffix("\u{201D}"))
        }
        #expect(!UntrustedText.name("Northfield Market").impersonatesViadere)
        #expect(UntrustedText.name("Northfield Market").text == "Northfield Market")

        let envelope = Self.envelope(business: "Viadere Security", merchant: "Viadere Security")
        let reason = ApprovalPolicy.promptReason(for: envelope, decision: .approve)
        #expect(reason.contains("\u{201C}Viadere Security\u{201D}"))
        #expect(InteractionPresentation.details(envelope).first { $0.label == "From" }?.value == "Business \u{201C}Viadere Security\u{201D}")
        #expect(envelope.business.safeName == "Business \u{201C}Viadere Security\u{201D}")
        let card = NotificationCard(envelope: envelope, now: Date(), finishesInApp: true)
        #expect(card.impersonatesViadere)
        #expect(card.business.hasPrefix("Business "))
    }

    @Test func longStringsAreCutButNeverHideTheAmount() {
        let long = String(repeating: "Northfield ", count: 80)
        let envelope = Self.envelope(business: long, merchant: long, action: long, location: long, effect: long, risk: long)
        let reason = ApprovalPolicy.promptReason(for: envelope, decision: .approve, onBehalfOf: long)
        #expect(reason.count <= ApprovalPolicy.promptLimit)
        #expect(reason.contains("$285.28"))
        #expect(reason.contains("on behalf of"))
        let question = InteractionPresentation.question(envelope.interaction)
        #expect(question.contains("$285.28"))
        #expect(question.count < 200 && question.hasSuffix("Is this you?"))
        #expect(InteractionPresentation.headline(envelope.interaction).hasPrefix("$285.28"))
        let rows = InteractionPresentation.details(envelope)
        #expect(rows.first { $0.label == "Amount" }?.value == "$285.28 USD")
        for row in rows { #expect(row.value.count <= 100) }
        #expect(InteractionPresentation.effectOfApproval(envelope.interaction)!.count <= InteractionPresentation.Limit.effect)
        #expect(InteractionPresentation.riskIndicators(envelope.interaction).allSatisfy { $0.label.count <= InteractionPresentation.Limit.risk })
        #expect(UntrustedText.line(long, max: 40).count == 40)
        #expect(UntrustedText.line(long, max: 40).hasSuffix(UntrustedText.ellipsis))
    }

    @Test func combiningMarkStacksAreLimited() {
        let zalgo = "A" + String(repeating: "\u{0301}\u{0316}\u{0489}", count: 40) + "B"
        let cleaned = UntrustedText.clean(zalgo)
        #expect(cleaned.unicodeScalars.count <= 4)
        #expect(cleaned.hasSuffix("B"))
    }

    @Test func collapsesWhitespaceAndHandlesEmpty() {
        #expect(UntrustedText.clean("  a \t\n  b\u{00A0}\u{2003}c  ") == "a b c")
        #expect(UntrustedText.optionalLine("\u{200B}\n", max: 10) == nil)
        #expect(UntrustedText.optionalLine(nil, max: 10) == nil)
        #expect(UntrustedText.name("\u{202E}\u{200B}").text == "Unnamed business")
        #expect(UntrustedText.paragraphs("One\r\n\r\n\r\nTwo\u{202E}\nThree", max: 100) == "One\n\nTwo\nThree")
    }

    @Test func emojiSurviveAndVariationSelectorStays() {
        let cleaned = UntrustedText.clean("Coffee ☕️ shop 🇺🇸")
        #expect(cleaned.unicodeScalars.contains { $0.value == 0x2615 } && cleaned.unicodeScalars.contains { $0.value == 0xFE0F })
        #expect(cleaned.unicodeScalars.contains { $0.value == 0x1F1FA })
    }

    @Test func notificationsAndWatchUseTheSanitizer() async throws {
        let api = MockViadereAPI(seed: false)
        let envelope = Self.envelope(business: "North\u{202E}field\u{200B}\nMarket", merchant: "Shop\u{061C}", action: "x")
        await api.add(envelope)
        let prefs = InMemoryPreferences()
        prefs.setBool(true, for: .richNotificationPreviews)
        let result = try #require(await NotificationEnricher(api: api, preferences: prefs).enrich(userInfo: ["iid": envelope.id.description]))
        for text in [result.title, result.subtitle, result.body] {
            #expect(text.unicodeScalars.allSatisfy { !Self.hostile.contains($0.value) }, "\(text)")
        }
        #expect(result.title == "Northfield Market")
        #expect(result.body.contains("$285.28"))

        let content = HomeContent(pending: [envelope], statuses: [], recent: [])
        let items = WatchSync.items(from: content, now: Date())
        #expect(items.first?.business == "Northfield Market")
        #expect(items.allSatisfy { !$0.headline.contains("\u{061C}") && !$0.headline.contains("\n") })
    }

    @Test func approvalSheetBodiesAreSanitized() {
        #expect(InteractionPresentation.confirmTitle(ConfirmPayload(title: "Pick up\n\u{202E}at 5")) == "Pick up at 5")
        #expect(InteractionPresentation.optionLabel(ChoiceOption(id: "a", label: "Tue\u{200B}\n9:00")) == "Tue 9:00")
        let ack = AcknowledgePayload(title: "Terms\u{202E}", body: "Para one\r\n\r\n\r\nPara\u{061C} two", documentVersion: "v\n2")
        #expect(AcknowledgmentPresentation.title(ack) == "Terms")
        #expect(AcknowledgmentPresentation.body(ack) == "Para one\n\nPara two")
        #expect(AcknowledgmentPresentation.versionLabel(ack) == "Version v 2")
    }

    @Test func liveActivityTextIsSanitized() {
        let order = OrderActivityState(orderReference: "A1\u{202E}\n7", stage: .preparing, estimatedReadyAt: nil, note: "Ready\u{061C}\nsoon")
        let presentation = LiveActivityPresentation(status: .order(order), businessName: "Copper\u{200B}line")
        #expect(!presentation.headline.contains("\n") && !presentation.headline.contains("\u{202E}"))
        #expect(!presentation.detail.contains("\n") && !presentation.detail.contains("\u{061C}"))
    }
}
