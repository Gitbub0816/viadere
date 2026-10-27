import Foundation
import Testing
@testable import ViadereCore

@Suite("Channel rendering")
struct RenderingTests {
    let business = Fixtures.walmart
    let handoff = URL(string: "https://viadere.com/h/abc123")

    @Test("Sensitive interactions are never downgraded to an SMS/RCS YES/NO")
    func neverDowngrade() {
        for payload in Fixtures.allPayloads + [.unknown(.null)] {
            for sensitivity in Sensitivity.allCases {
                for purpose in InteractionPurpose.allCases {
                    var i = Fixtures.interaction(payload, sensitivity: sensitivity, purpose: purpose)
                    if case .unknown = payload { i.kind = .unknown("future") }
                    let required = i.requiredAssurance
                    let sms = ChannelRenderer.sms(i, business: business, handoffURL: handoff)
                    let rcs = ChannelRenderer.rcs(i, business: business, handoffURL: handoff)
                    if required > .channelReply || i.kind.isSecuritySensitive {
                        #expect(sms.isSecureHandoff, "\(i.kind) \(sensitivity)")
                        #expect(sms.choices.isEmpty)
                        #expect(!sms.body.uppercased().contains("REPLY YES"))
                        #expect(rcs.isSecureHandoff)
                        #expect(rcs.suggestions.allSatisfy { $0.kind == .openURL })
                    }
                    #expect(sms.choices.count <= ChannelRenderer.maxSMSChoices)
                    #expect(sms.body.hasPrefix("[Walmart]: "))
                }
            }
        }
    }

    @Test func authorizeHandoffSMS() {
        let i = Fixtures.interaction(.authorize(Fixtures.mesaAuthorize), sensitivity: .high)
        let sms = ChannelRenderer.sms(i, business: business, handoffURL: handoff)
        #expect(sms.isSecureHandoff)
        #expect(sms.body.contains("https://viadere.com/h/abc123"))
        #expect(!sms.body.contains("285.28")) // no transaction details on the insecure channel
        #expect(sms.encoding.kind == .gsm7)
        let noURL = ChannelRenderer.sms(i, business: business, handoffURL: nil)
        #expect(noURL.body.contains("Open the Viadere app"))
    }

    @Test("Mesa example renders accurately in the native notification (spec §19 #4)")
    func mesaNotification() {
        let i = Fixtures.interaction(.authorize(Fixtures.mesaAuthorize), sensitivity: .high, purpose: .security)
        let n = ChannelRenderer.notification(i, business: business)
        #expect(n.body == "Someone is trying to spend $285.28 at Walmart in or near Mesa, Arizona. Is this you?")
        #expect(n.title == "Walmart")
        #expect(n.category.identifier == "viadere.authorize.secure")
        #expect(n.requiresSecureFlow)
        let approve = n.category.actions.first { $0.identifier == "viadere.approve" }
        #expect(approve?.opensApp == true)
        #expect(approve?.requiresAuthentication == true)
        #expect(n.category.actions.contains { $0.identifier == "viadere.deny" && $0.style == .destructive })
        #expect(n.threadIdentifier == "business.\(business.id)")
        #expect(n.userInfo["interactionId"] == i.id.description)
    }

    @Test func lowSensitivityLoginApprovesInBackground() {
        let i = Fixtures.interaction(.authenticate(Fixtures.loginPayload), sensitivity: .low, purpose: .security)
        let n = ChannelRenderer.notification(i, business: business)
        #expect(n.category.identifier == "viadere.authenticate")
        #expect(n.category.actions.first { $0.identifier == "viadere.approve" }?.opensApp == false)
        #expect(n.body.contains("Online Banking") && n.body.contains("Chrome on macOS") && n.body.contains("Mesa, AZ"))
    }

    @Test("Choose renders ≤ 4 numbered SMS options with paging")
    func chooseSMS() {
        let few = Fixtures.interaction(.choose(Fixtures.choosePayload), sensitivity: .low)
        let sms = ChannelRenderer.sms(few, business: business, handoffURL: nil)
        #expect(sms.body == "[Walmart]: Pick a delivery window\n1. Morning\n2. Afternoon\n3. Evening")
        #expect(sms.target(forReply: " 2 ") == .option("pm"))
        #expect(sms.target(forReply: "2.") == .option("pm"))
        #expect(sms.target(forReply: "4") == nil)

        let options = (1...7).map { ChoiceOption(id: "o\($0)", label: "Option \($0)") }
        let many = Fixtures.interaction(.choose(ChoosePayload(prompt: "Pick", options: options)), sensitivity: .low)
        let page0 = ChannelRenderer.sms(many, business: business, handoffURL: nil)
        #expect(page0.choices.count == 4)
        #expect(page0.choices.map(\.target) == [.option("o1"), .option("o2"), .option("o3"), .nextPage(1)])
        let page2 = ChannelRenderer.sms(many, business: business, handoffURL: nil, page: 2)
        #expect(page2.choices.map(\.target) == [.option("o7"), .nextPage(0)])

        let rcs = ChannelRenderer.rcs(many, business: business, handoffURL: nil)
        #expect(rcs.suggestions.count == 7)
        #expect(rcs.suggestions[0].postbackData == "viadere:\(many.id):option.o1")
        #expect(!rcs.text.contains("1."))

        let n = ChannelRenderer.notification(few, business: business)
        #expect(n.category.identifier == "viadere.choose.\(few.id)")
        #expect(n.category.actions.map(\.identifier) == ["viadere.option.am", "viadere.option.pm", "viadere.option.eve"])
    }

    @Test func confirmSMSIsNumberedNotYesNo() {
        let i = Fixtures.interaction(.confirm(ConfirmPayload(title: "Table for 2 at 7pm")), sensitivity: .low)
        let sms = ChannelRenderer.sms(i, business: business, handoffURL: nil)
        #expect(!sms.isSecureHandoff)
        #expect(sms.choices.map(\.target) == [.decision(.confirm), .decision(.decline)])
    }

    @Test("Business text cannot inject lines or spoof direction")
    func spoofing() {
        let evil = ConfirmPayload(title: "Order\n1. Approve wire\u{202E}evil", details: "x\u{200B}y")
        let i = Fixtures.interaction(.confirm(evil), sensitivity: .low)
        let sms = ChannelRenderer.sms(i, business: business, handoffURL: nil)
        let firstLine = sms.body.split(separator: "\n")[0]
        #expect(firstLine.contains("Order 1. Approve wire"))
        #expect(!sms.body.contains("\u{202E}"))
        #expect(!sms.body.contains("\u{200B}"))
    }

    @Test func smsSegments() {
        #expect(SMSEncoding.analyze(String(repeating: "a", count: 160)) == SMSEncoding.Info(kind: .gsm7, units: 160, segments: 1))
        #expect(SMSEncoding.analyze(String(repeating: "a", count: 161)).segments == 2)
        #expect(SMSEncoding.analyze(String(repeating: "a", count: 306)).segments == 2)
        #expect(SMSEncoding.analyze(String(repeating: "a", count: 307)).segments == 3)
        #expect(SMSEncoding.analyze("€").units == 2)
        #expect(SMSEncoding.analyze(String(repeating: "€", count: 80)).segments == 1)
        #expect(SMSEncoding.analyze(String(repeating: "€", count: 81)).segments == 2)
        #expect(SMSEncoding.analyze("hi 😀").kind == .ucs2)
        #expect(SMSEncoding.analyze(String(repeating: "é", count: 70)).kind == .gsm7)
        #expect(SMSEncoding.analyze(String(repeating: "ç", count: 70)) == SMSEncoding.Info(kind: .ucs2, units: 70, segments: 1))
        #expect(SMSEncoding.analyze(String(repeating: "ç", count: 71)).segments == 2)
        #expect(SMSEncoding.gsmFriendly("It\u{2019}s \u{201C}ok\u{201D} \u{2014} yes\u{2026}") == "It's \"ok\" - yes...")
    }

    @Test("Gateway copy stays in GSM-7")
    func copyIsGSM7() {
        let b = Fixtures.walmart
        for text in [GatewayCopy.help, GatewayCopy.optOutConfirmation, GatewayCopy.searchPrompt, GatewayCopy.connected(b),
                     GatewayCopy.confirm(b, hasPendingMessage: true), GatewayCopy.howItWorks, GatewayCopy.privacy] {
            #expect(SMSEncoding.isGSM7(text), "\(text)")
            #expect(SMSEncoding.analyze(text).segments <= 2)
        }
        #expect(GatewayCopy.help.count <= 160)
        #expect(GatewayCopy.optOutConfirmation.count <= 160)
    }
}
