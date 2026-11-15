import Foundation
import Testing
@testable import ViadereCore

/// Decision 9 / ADR-0027: no authentication over SMS. Viadere never sends a code, a link with a token or an approval request by text;
/// phone-number ownership is proven by a customer-originated message (MO) carrying an in-app nonce.
@Suite("Phone link by customer-originated text (ADR-0027)")
struct PhoneLinkMOTests {
    // MARK: Nonce

    @Test func aNonceIsVDRPlusEightCrockfordCharacters() {
        var seen = Set<String>()
        for _ in 0..<500 {
            let nonce = PhoneLinkMO.generateNonce()
            #expect(nonce.hasPrefix("VDR-"))
            let body = nonce.dropFirst(4)
            #expect(body.count == 8)
            #expect(body.allSatisfy { PhoneLinkMO.alphabet.contains($0) }, "\(nonce)")
            #expect(!body.contains(where: { "ILOU".contains($0) }), "Crockford alphabet excludes I L O U")
            seen.insert(nonce)
        }
        #expect(seen.count == 500, "40 bits of randomness: no repeats in 500 draws")
    }

    @Test func theNonceIsFoundAnywhereInAnEditedBody() {
        let nonce = "VDR-7K3M9Q2X"
        #expect(PhoneLinkMO.extractNonce(from: PhoneLinkMO.prefill(nonce: nonce)) == nonce)
        #expect(PhoneLinkMO.extractNonce(from: "link my number vdr-7k3m9q2x please") == nonce)
        #expect(PhoneLinkMO.extractNonce(from: "  VDR - 7K3M 9Q2X \n") == nonce)
        #expect(PhoneLinkMO.extractNonce(from: "Link my number to my Viadere app\u{00A0}VDR-7K3M9Q2X.") == nonce)
        // Crockford confusions are folded the way a person would mistype them.
        #expect(PhoneLinkMO.extractNonce(from: "VDR-7K3M9QZX") == "VDR-7K3M9QZX")
        #expect(PhoneLinkMO.extractNonce(from: "VDR-OILOOILO") == "VDR-01100110")
    }

    @Test func textThatIsNotANonceIsIgnored() {
        for body in ["", "VDR-", "VDR-7K3M9Q2", "VDR-7K3M9Q2XY", "VDR7K3M", "my VDR number", "STOP", "1", "Hi",
                     "VDR-7K3M-9Q2X-EXTRA", "xVDR-7K3M9Q2X"] {
            #expect(PhoneLinkMO.extractNonce(from: body) == nil, "\(body)")
        }
    }

    @Test func theComposeTextSaysWhatItDoes() {
        // UX_COPY S-PH-02: the message itself tells the sender what sending it does (anti-social-engineering wording, ADR-0027 §3.1b).
        let text = PhoneLinkMO.prefill(nonce: "VDR-7K3M9Q2X")
        #expect(text == "Link my number to my Viadere app VDR-7K3M9Q2X")
        #expect(text.lowercased().contains("link my number"))
        #expect(SMSEncoding.analyze(text).kind == .gsm7)
    }

    @Test func theChallengeLivesTenMinutes() {
        #expect(PhoneLinkMO.ttl == 600)
        #expect(PhoneLinkMO.assuranceLabel == "phone_control_mo")
    }

    // MARK: No authentication artefact in any outbound text (ST-PH-05)

    /// Everything Viadere can say over SMS for this thread, across a long scripted conversation of every route that used to mint a link.
    private func transcript(linked: Bool) async -> [String] {
        let h = GatewayHarness(linked: linked)
        var bodies: [String] = []
        let script = ["Hi", "1", "MENU", "2", "bean", "1", "3", "4", "1", "2", "3", "MENU", "@amazon I need help with my order", "1", "1",
                      "HELP", "AF-2345", "yes", "3", "MENU", "4", "3", "2", "BACK", "STOP", "START", "link", "LINK ME", "verify", "code"]
        for text in script {
            let t = await h.send(text)
            bodies += t.smsBodies
        }
        let notices = [GatewayCopy.getViadere(url: GatewayConfiguration().getAppURL), GatewayCopy.openAppToRespond, GatewayCopy.openAppForAccount,
                       GatewayCopy.phoneLinkedNotice, GatewayCopy.unlinkDone, GatewayCopy.secureRequestNotice(business: GatewayHarness.airline),
                       GatewayCopy.linkRequired(GatewayHarness.amazonCo, url: GatewayConfiguration().getAppURL)]
        return bodies + notices
    }

    @Test(arguments: [true, false])
    func noSMSContainsACodeATokenOrAPersonalLink(linked: Bool) async {
        let getURL = GatewayConfiguration().getAppURL
        let bodies = await transcript(linked: linked)
        #expect(!bodies.isEmpty)
        for body in bodies {
            // The only URLs are the static on-ramp page and the two public help pages; none has a path segment after them.
            let urls = body.split(whereSeparator: { $0 == " " || $0 == "\n" }).filter { $0.contains("://") || $0.hasPrefix("viadere.com") }
            for url in urls {
                let cleaned = url.trimmingCharacters(in: CharacterSet(charactersIn: ".,"))
                #expect(cleaned == getURL || cleaned == "viadere.com/help" || cleaned == "viadere.com/privacy", "\(cleaned) in \(body)")
            }
            #expect(!body.contains("/l/") && !body.contains("/h/"), "\(body)")
            #expect(body.range(of: #"\b\d{6}\b"#, options: .regularExpression) == nil, "no six-digit code: \(body)")
            #expect(body.range(of: #"[A-Za-z0-9_-]{24,}"#, options: .regularExpression) == nil, "no bearer-looking token: \(body)")
            let lowered = body.lowercased()
            for phrase in ["verification code", "your code", "one-time", "expires in", "don't share this link", "secure link", "continue here",
                           "review it securely", "reply yes to approve"] {
                #expect(!lowered.contains(phrase), "\(phrase) in \(body)")
            }
        }
    }

    @Test func noEffectMintsALinkOrSendsAHandoff() async {
        let h = GatewayHarness(linked: false)
        var all: [GatewayEffect] = []
        for text in ["Hi", "1", "@amazon help", "1", "2", "3", "4", "MENU", "3", "4", "3"] { all += await h.send(text).effects }
        let h2 = GatewayHarness(linked: true)
        for text in ["Hi", "3", "4", "3", "MENU", "4", "3"] { all += await h2.send(text).effects }
        // Only plain SMS, routing, consent and audit effects exist; the enum has no account-link or handoff case any more.
        for effect in all {
            switch effect {
            case .sendSMS, .forwardToBusiness, .openSession, .closeSession, .recordConsent, .holdBusinessMessage, .audit: break
            }
        }
    }

    @Test func anUnlinkedNumberIsOnlyPointedAtTheApp() async {
        let h = GatewayHarness(linked: false)
        await h.send("Hi")
        let t = await h.send("1")
        #expect(h.state == .unlinked)
        #expect(t.smsBodies.last == GatewayCopy.getViadere(url: GatewayConfiguration().getAppURL))
        #expect(h.context.linkPendingUntil == nil)
    }

    @Test func routingNeedsALinkMadeInTheApp() async {
        let h = GatewayHarness(linked: false)
        await h.send("Hi")
        await h.send("@amazon I need help with my order")
        let t = await h.send("1")
        #expect(h.forwards(t).isEmpty)
        #expect(h.state == .unlinked)
        #expect(t.smsBodies.contains { $0.contains("link this number in the Viadere app") })
        #expect(h.context.pending?.message == "I need help with my order")
        // After the in-app link the held message is offered again, never sent silently.
        let linked = h.engine.accountLinked(consumerId: ConsumerID(), context: h.context, now: h.clock)
        h.context = linked.context
        #expect(h.state == .confirmDestination)
    }

    @Test func aLinkPendingThreadFromAnOlderBuildFallsBackToUnlinked() async {
        let h = GatewayHarness(linked: false)
        h.context.state = .linkPending
        h.context.linkPendingUntil = h.clock.addingTimeInterval(600)
        await h.send("Hi")
        #expect(h.state != .linkPending)
        #expect(h.context.linkPendingUntil == nil)
    }

    @Test func unlinkIsAKeywordLikeStop() {
        #expect(GatewayKeyword.classify(" unlink. ") == .unlink)
        #expect(GatewayKeyword.classify("UNLINK") == .unlink)
        #expect(GatewayKeyword.classify("unlink my account please") == nil)
        #expect(GatewayKeyword.classify("stop") == .optOut)
    }

    @Test func theNoticesUseTheApprovedWording() {
        #expect(GatewayCopy.phoneLinkedNotice == "Viadere: Someone linked this number to a Viadere app using a text sent from this phone. If that wasn't you, reply UNLINK. Reply STOP to stop messages.")
        #expect(GatewayCopy.unlinkDone == "Viadere: Done. Viadere will not use this number for messages or approvals. The Viadere account that holds it can remove it in the app.")
        #expect(GatewayCopy.getViadere(url: "https://viadere.com/get") == "Get the Viadere app to connect with businesses: https://viadere.com/get")
        #expect(GatewayCopy.secureRequestNotice(business: GatewayHarness.airline) == "Viadere: Sky Air sent you something that needs the Viadere app. Open Viadere to respond.")
        for text in [GatewayCopy.phoneLinkedNotice, GatewayCopy.unlinkDone, GatewayCopy.secureRequestNotice(business: GatewayHarness.airline)] {
            #expect(SMSEncoding.analyze(text).kind == .gsm7, "\(text)")
        }
    }

    // MARK: Renderers (ST-PH-05)

    @Test func noInteractionRenderingCarriesALinkOrApprovalByText() {
        let business = Fixtures.walmart
        for payload in Fixtures.allPayloads + [.unknown(.null)] {
            for sensitivity in Sensitivity.allCases {
                var i = Fixtures.interaction(payload, sensitivity: sensitivity)
                if case .unknown = payload { i.kind = .unknown("future") }
                let sms = ChannelRenderer.sms(i, business: business)
                let rcs = ChannelRenderer.rcs(i, business: business)
                #expect(!sms.body.contains("://"), "\(sms.body)")
                #expect(!rcs.text.contains("://"), "\(rcs.text)")
                #expect(rcs.suggestions.allSatisfy { $0.kind != .openURL && $0.url == nil })
                if sms.isSecureHandoff { #expect(sms.body.contains("Open the Viadere app")) }
            }
        }
    }
}
