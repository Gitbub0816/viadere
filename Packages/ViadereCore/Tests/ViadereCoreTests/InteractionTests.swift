import Foundation
import Testing
@testable import ViadereCore

@Suite("Interaction protocol")
struct InteractionTests {
    @Test("Every kind round-trips through JSON")
    func roundTrip() throws {
        for payload in Fixtures.allPayloads {
            let interaction = Fixtures.interaction(payload)
            let data = try ViadereJSON.encode(interaction)
            let decoded = try ViadereJSON.decode(Interaction.self, from: data)
            #expect(decoded == interaction)
            #expect(decoded.kind == payload.kind)
            #expect(InteractionValidation.issues(in: decoded, now: Fixtures.now).isEmpty, "\(decoded.kind)")
        }
    }

    @Test("Unknown kinds decode safely and are treated as critical")
    func unknownKind() throws {
        let original = Fixtures.interaction(.message(MessagePayload(text: "hi")))
        var object = try #require(try ViadereJSON.decode(JSONValue.self, from: ViadereJSON.encode(original)).objectValue)
        object["kind"] = .string("hologram")
        object["payload"] = .object(["beam": .string("up")])
        object["sensitivity"] = .string("cosmic")
        object["allowedChannels"] = .array([.string("sms"), .string("telepathy")])
        let decoded = try ViadereJSON.decode(Interaction.self, from: ViadereJSON.encode(JSONValue.object(object)))
        #expect(decoded.kind == .unknown("hologram"))
        #expect(decoded.payload == .unknown(.object(["beam": .string("up")])))
        #expect(decoded.sensitivity == .critical)
        #expect(decoded.allowedChannels == [.sms])
        #expect(decoded.requiredAssurance == .deviceBoundBiometric)
        #expect(InteractionValidation.issues(in: decoded, now: Fixtures.now).contains { $0.code == .unknownKind })
        // Re-encodes losslessly.
        let again = try ViadereJSON.decode(Interaction.self, from: ViadereJSON.encode(decoded))
        #expect(again.kind == decoded.kind && again.payload == decoded.payload)
    }

    @Test func unsupportedSchemaVersionFails() throws {
        var object = try #require(try ViadereJSON.decode(JSONValue.self, from: ViadereJSON.encode(
            Fixtures.interaction(.message(MessagePayload(text: "x"))))).objectValue)
        object["schemaVersion"] = .integer(99)
        #expect(throws: (any Error).self) { try ViadereJSON.decode(Interaction.self, from: ViadereJSON.encode(JSONValue.object(object))) }
    }

    @Test func validationCatchesProblems() {
        var i = Fixtures.interaction(.choose(ChoosePayload(prompt: "", options: [ChoiceOption(id: "a", label: "A")])))
        var codes = Set(InteractionValidation.issues(in: i, now: Fixtures.now).map(\.code))
        #expect(codes.contains(.empty))
        #expect(codes.contains(.invalidCount))

        i = Fixtures.interaction(.message(MessagePayload(text: "x")))
        i.kind = .authorize
        codes = Set(InteractionValidation.issues(in: i, now: Fixtures.now).map(\.code))
        #expect(codes.contains(.kindPayloadMismatch))

        i = Fixtures.interaction(.authorize(Fixtures.mesaAuthorize), lifetime: 3600)
        codes = Set(InteractionValidation.issues(in: i, now: Fixtures.now).map(\.code))
        #expect(codes.contains(.invalidLifetime))

        i = Fixtures.interaction(.message(MessagePayload(text: String(repeating: "x", count: 1001))))
        #expect(InteractionValidation.issues(in: i, now: Fixtures.now).map(\.code) == [.tooLong])

        i = Fixtures.interaction(.message(MessagePayload(text: "x")))
        #expect(throws: InteractionValidation.Issue.self) { try InteractionValidation.validate(i, now: Fixtures.now.addingTimeInterval(301)) }

        i = Fixtures.interaction(.authorize(Fixtures.mesaAuthorize), purpose: .marketing)
        #expect(InteractionValidation.issues(in: i, now: Fixtures.now).contains { $0.code == .purposeMismatch })

        i = Fixtures.interaction(.choose(ChoosePayload(prompt: "p", options: [ChoiceOption(id: "a", label: "A"), ChoiceOption(id: "a", label: "B")])))
        #expect(InteractionValidation.issues(in: i, now: Fixtures.now).contains { $0.code == .duplicate })

        i = Fixtures.interaction(.message(MessagePayload(text: "x")))
        i.idempotencyKey = "has spaces"
        #expect(InteractionValidation.issues(in: i, now: Fixtures.now).contains { $0.code == .invalidIdentifier })
    }

    @Test func money() throws {
        let amount = try MoneyAmount(string: "285.28", currency: .usd)
        #expect(amount.formatted == "$285.28")
        #expect(amount.decimalString == "285.28")
        let data = try ViadereJSON.encode(amount)
        #expect(String(decoding: data, as: UTF8.self) == #"{"currency":"USD","value":"285.28"}"#)
        #expect(try ViadereJSON.decode(MoneyAmount.self, from: data) == amount)
        #expect(try MoneyAmount(string: "5", currency: .usd).decimalString == "5.00")
        #expect(try MoneyAmount(string: "1000", currency: #require(CurrencyCode("jpy"))).formatted == "¥1000")
        #expect(throws: MoneyAmount.ValidationError.tooManyFractionDigits) { try MoneyAmount(string: "1.234", currency: .usd) }
        #expect(throws: MoneyAmount.ValidationError.malformed) { try MoneyAmount(string: "-1", currency: .usd) }
        #expect(throws: MoneyAmount.ValidationError.malformed) { try MoneyAmount(string: "1e5", currency: .usd) }
        #expect(throws: MoneyAmount.ValidationError.negative) { try MoneyAmount(Decimal(-1), currency: .usd) }
        #expect(CurrencyCode("US") == nil)
        #expect(CurrencyCode("U$D") == nil)
    }

    @Test("Businesses cannot buy priority (spec §19 #12)")
    func priorityClamp() {
        var i = Fixtures.interaction(.message(MessagePayload(text: "Sale!")), purpose: .marketing)
        i.priority = .urgent
        #expect(i.effectivePriority == .normal)
        i.purpose = .transactional
        #expect(i.effectivePriority == .high)
        i.purpose = .security
        #expect(i.effectivePriority == .urgent)
    }
}

@Suite("Assurance policy")
struct AssuranceTests {
    @Test("Policy table")
    func table() {
        for kind in [InteractionKind.authenticate, .authorize] {
            #expect(AssurancePolicy.requiredAssurance(kind: kind, sensitivity: .low, purpose: .transactional) == .deviceSignature)
            #expect(AssurancePolicy.requiredAssurance(kind: kind, sensitivity: .standard, purpose: .transactional) == .userVerified)
            #expect(AssurancePolicy.requiredAssurance(kind: kind, sensitivity: .high, purpose: .transactional) == .deviceBoundBiometric)
            #expect(AssurancePolicy.requiredAssurance(kind: kind, sensitivity: .critical, purpose: .transactional) == .deviceBoundBiometric)
        }
        #expect(AssurancePolicy.requiredAssurance(kind: .confirm, sensitivity: .standard, purpose: .transactional) == .channelReply)
        #expect(AssurancePolicy.requiredAssurance(kind: .confirm, sensitivity: .high, purpose: .transactional) == .userVerified)
        #expect(AssurancePolicy.requiredAssurance(kind: .confirm, sensitivity: .critical, purpose: .transactional) == .deviceBoundBiometric)
        #expect(AssurancePolicy.requiredAssurance(kind: .confirm, sensitivity: .low, purpose: .security) == .deviceSignature)
        #expect(AssurancePolicy.requiredAssurance(kind: .unknown("x"), sensitivity: .low, purpose: .support) == .deviceBoundBiometric)
    }

    @Test("Authorize/authenticate can never be satisfied by SMS or other text channels")
    func neverSMS() {
        for payload in [InteractionPayload.authorize(Fixtures.mesaAuthorize), .authenticate(Fixtures.loginPayload)] {
            for sensitivity in Sensitivity.allCases {
                let i = Fixtures.interaction(payload, sensitivity: sensitivity, channels: Channel.allCases)
                for channel in [Channel.sms, .rcs, .appleMessagesForBusiness] {
                    for provided in [ProvidedAssurance.unauthenticatedReply, .passkeyAssertion, .deviceSignature(.biometric)] {
                        #expect(!AssurancePolicy.canSatisfy(i, channel: channel, provided: provided))
                    }
                }
            }
        }
    }

    @Test("High/critical authorize requires a device-bound biometric signature")
    func biometricRequired() {
        let i = Fixtures.interaction(.authorize(Fixtures.mesaAuthorize), sensitivity: .high)
        #expect(AssurancePolicy.canSatisfy(i, channel: .nativePush, provided: .deviceSignature(.biometric)))
        #expect(!AssurancePolicy.canSatisfy(i, channel: .nativePush, provided: .deviceSignature(.devicePasscode)))
        #expect(!AssurancePolicy.canSatisfy(i, channel: .nativePush, provided: .deviceSignature(.none)))
        #expect(!AssurancePolicy.canSatisfy(i, channel: .web, provided: .passkeyAssertion))
        let standard = Fixtures.interaction(.authorize(Fixtures.mesaAuthorize), sensitivity: .standard)
        #expect(AssurancePolicy.canSatisfy(standard, channel: .web, provided: .passkeyAssertion))
        #expect(AssurancePolicy.canSatisfy(standard, channel: .inApp, provided: .deviceSignature(.devicePasscode)))
    }

    @Test func channelMustBeAllowedAndCapable() {
        let i = Fixtures.interaction(.confirm(ConfirmPayload(title: "Pickup")), sensitivity: .low, channels: [.nativePush])
        #expect(!AssurancePolicy.canSatisfy(i, channel: .sms, provided: .unauthenticatedReply))
        let j = Fixtures.interaction(.confirm(ConfirmPayload(title: "Pickup")), sensitivity: .low, channels: [.sms])
        #expect(AssurancePolicy.canSatisfy(j, channel: .sms, provided: .unauthenticatedReply))
        #expect(!AssurancePolicy.channel(.sms, canCarry: .deviceSignature(.biometric)))
        #expect(!AssurancePolicy.channel(.web, canCarry: .deviceSignature(.biometric)))
        let push = Fixtures.interaction(.confirm(ConfirmPayload(title: "Pickup")), sensitivity: .low, channels: [.nativePush])
        #expect(AssurancePolicy.canSatisfy(push, channel: .inApp, provided: .deviceSignature(.none)))
        #expect(!AssurancePolicy.canSatisfy(push, channel: .web, provided: .passkeyAssertion))
    }
}
