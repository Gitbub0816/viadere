import Foundation
import Testing
@testable import ViadereCore

@Suite("Decision Live Activities")
struct DecisionActivityTests {
    let now = Fixtures.now

    private var confirm: InteractionPayload { .confirm(ConfirmPayload(title: "Table for 2 at 7pm", details: "Main St", reference: "R-1234")) }

    @Test("The decision case round-trips through the wire codec and ActivityKit's default JSON coding")
    func codecRoundTrip() throws {
        let neutral = LiveActivityStatus.decision(DecisionActivityState(interactionId: InteractionID(), kind: .confirm,
                                                                        expiresAt: now.addingTimeInterval(300)))
        let enriched = LiveActivityStatus.decision(DecisionActivityState(
            interactionId: InteractionID(), kind: .choose, expiresAt: now, stage: .answered, title: "Pick a window", detail: "Delivery",
            options: [.init(id: "am", label: "Morning"), .init(id: "pm", label: "Afternoon")]))
        for status in [neutral, enriched] {
            #expect(try ViadereJSON.decode(LiveActivityStatus.self, from: try ViadereJSON.encode(status)) == status)
            #expect(try JSONDecoder().decode(LiveActivityStatus.self, from: try JSONEncoder().encode(status)) == status)
            #expect(status.type == "decision")
            #expect(status.isDecision)
        }
        // A neutral state carries no text keys at all, not even `null`.
        let json = try #require(JSONSerialization.jsonObject(with: try JSONEncoder().encode(neutral)) as? [String: Any])
        #expect(json["type"] as? String == "decision")
        let body = try #require(json["decision"] as? [String: Any])
        #expect(Set(body.keys) == ["interactionId", "kind", "expiresAt", "stage"])
    }

    @Test("Stages: only pending is live; options are bounded however they arrive")
    func stagesAndBounds() throws {
        let id = InteractionID()
        for stage in DecisionActivityState.Stage.allCases {
            let status = LiveActivityStatus.decision(DecisionActivityState(interactionId: id, kind: .confirm, expiresAt: now, stage: stage))
            #expect(status.isTerminal == (stage != .pending))
        }
        let many = (0..<6).map { DecisionActivityState.Option(id: "o\($0)", label: "Option \($0)") }
        #expect(DecisionActivityState(interactionId: id, kind: .choose, expiresAt: now, options: many).options?.count == 3)
        let wire = """
        {"type":"decision","decision":{"interactionId":"\(id)","kind":"choose","expiresAt":0,"stage":"pending",
        "options":[{"id":"a","label":"A"},{"id":"b","label":"B"},{"id":"c","label":"C"},{"id":"d","label":"D"}]}}
        """
        guard case .decision(let decoded) = try JSONDecoder().decode(LiveActivityStatus.self, from: Data(wire.utf8)) else {
            Issue.record("expected a decision"); return
        }
        #expect(decoded.options?.map(\.id) == ["a", "b", "c"])
        #expect(decoded.isEnriched)
        #expect(!decoded.neutral.isEnriched)
        #expect(decoded.neutral.interactionId == id)
    }

    @Test("Existing cases decode exactly as before")
    func existingCasesUnchanged() throws {
        let order = #"{"type":"order","order":{"orderReference":"1042","stage":"preparing"}}"#
        #expect(try JSONDecoder().decode(LiveActivityStatus.self, from: Data(order.utf8)) == .order(OrderActivityState(orderReference: "1042", stage: .preparing)))
        let delivery = #"{"type":"delivery","delivery":{"trackingReference":"1Z","stage":"delivered"}}"#
        let decoded = try JSONDecoder().decode(LiveActivityStatus.self, from: Data(delivery.utf8))
        #expect(decoded == .delivery(DeliveryActivityState(trackingReference: "1Z", stage: .delivered)))
        #expect(decoded.isTerminal && !decoded.isDecision)
        #expect(throws: DecodingError.self) { try JSONDecoder().decode(LiveActivityStatus.self, from: Data(#"{"type":"poll","poll":{}}"#.utf8)) }
    }

    @Test("A business status can never carry a decision activity")
    func statusCannotCarryDecision() {
        let decision = LiveActivityStatus.decision(DecisionActivityState(interactionId: InteractionID(), kind: .confirm, expiresAt: now))
        #expect(!LiveActivityPolicy.isEligible(purpose: .transactional, status: decision))
        let status = Fixtures.interaction(.status(StatusPayload(title: "Your order", liveActivity: decision)))
        #expect(InteractionValidation.issues(in: status, now: now).contains(InteractionValidation.Issue(.invalidValue, "payload.liveActivity")))
        let fine = Fixtures.interaction(.status(StatusPayload(title: "Your order", liveActivity: .order(OrderActivityState(orderReference: "1", stage: .ready)))))
        #expect(!InteractionValidation.issues(in: fine, now: now).contains { $0.field == "payload.liveActivity" })
    }

    @Test("Eligibility truth table")
    func eligibility() {
        func eligible(_ payload: InteractionPayload, sensitivity: Sensitivity = .low, purpose: InteractionPurpose = .transactional,
                      channels: [Channel] = [.nativePush, .inApp], live: Bool = true) -> Bool {
            LiveActivityPolicy.isDecisionEligible(Fixtures.interaction(payload, sensitivity: sensitivity, purpose: purpose, channels: channels), livemode: live)
        }
        // Kinds: confirm and choose only.
        #expect(eligible(confirm))
        #expect(eligible(.choose(Fixtures.choosePayload)))
        #expect(!eligible(.authenticate(Fixtures.loginPayload)))
        #expect(!eligible(.authorize(Fixtures.mesaAuthorize)))
        for payload in Fixtures.allPayloads {
            if case .confirm = payload { continue }
            if case .choose = payload { continue }
            #expect(!eligible(payload), "\(payload)")
        }
        #expect(!eligible(.unknown(.object(["kind": .string("poll")]))))
        // Purposes: transactional, account service, support.
        for purpose in InteractionPurpose.allCases {
            #expect(eligible(confirm, purpose: purpose) == [.transactional, .accountService, .support].contains(purpose), "\(purpose)")
        }
        // Test keys never.
        #expect(!eligible(confirm, live: false))
        // Native push must be allowed.
        #expect(!eligible(confirm, channels: [.inApp, .sms]))
        // Never what the renderer would mark secure, at any sensitivity.
        for sensitivity in Sensitivity.allCases {
            for payload in [confirm, InteractionPayload.choose(Fixtures.choosePayload)] {
                let interaction = Fixtures.interaction(payload, sensitivity: sensitivity)
                let secure = ChannelRenderer.notification(interaction, business: Fixtures.walmart).requiresSecureFlow
                #expect(ChannelRenderer.requiresSecureFlow(interaction) == secure)
                #expect(LiveActivityPolicy.isDecisionEligible(interaction, livemode: true) == !secure, "\(sensitivity)")
            }
        }
        // Choose: single answer, at most three options.
        let four = ChoosePayload(prompt: "Pick", options: (0..<4).map { ChoiceOption(id: "o\($0)", label: "O\($0)") })
        #expect(!eligible(.choose(four)))
        let multi = ChoosePayload(prompt: "Pick", options: Fixtures.choosePayload.options, allowsMultiple: true)
        #expect(!eligible(.choose(multi)))
        let two = ChoosePayload(prompt: "Pick", options: Array(Fixtures.choosePayload.options.prefix(2)))
        #expect(eligible(.choose(two)))
    }

    @Test("The neutral start state has no business text")
    func neutralState() throws {
        let interaction = Fixtures.interaction(confirm, sensitivity: .low)
        let state = try #require(LiveActivityPolicy.neutralDecisionState(for: interaction, livemode: true))
        #expect(state == DecisionActivityState(interactionId: interaction.id, kind: .confirm, expiresAt: interaction.expiresAt, stage: .pending))
        #expect(!state.isEnriched)
        let text = String(decoding: try JSONEncoder().encode(LiveActivityStatus.decision(state)), as: UTF8.self)
        for secret in ["Table", "Main St", "R-1234"] { #expect(!text.contains(secret)) }
        #expect(LiveActivityPolicy.neutralDecisionState(for: interaction, livemode: false) == nil)
        let choose = Fixtures.interaction(.choose(Fixtures.choosePayload), sensitivity: .low)
        #expect(LiveActivityPolicy.neutralDecisionState(for: choose, livemode: true)?.kind == .choose)
    }
}
