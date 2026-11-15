import Foundation
import Testing
import ViadereCore
@testable import ViadereBusinessSDK

@Suite("Webhook verification")
struct WebhookTests {
    let secret = WebhookSignature.generateSecret()
    let businessId = BusinessID()

    func event(_ type: WebhookEventType = .interactionDecided, data: some Encodable) throws -> (event: WebhookEvent, body: Data) {
        let event = try WebhookEvent(type: type, createdAt: Fixtures.now, businessId: businessId, payload: data)
        return (event, try ViadereJSON.encode(event))
    }

    func headers(_ body: Data, secrets: [String]? = nil, at: Date = Fixtures.now, event: WebhookEvent? = nil) -> [String: String] {
        var h = [ViadereHeader.signature: WebhookSignature.header(secrets: secrets ?? [secret], body: body, now: at)]
        if let event {
            h[ViadereHeader.eventId] = event.id.description
            h[ViadereHeader.eventType] = event.type.rawValue
        }
        return h
    }

    func outcome() -> InteractionOutcome {
        InteractionOutcome(interactionId: InteractionID(), businessId: businessId, status: .approved, decision: .approve, assurance: .biometric, channel: .nativePush, decidedAt: Fixtures.now)
    }

    @Test func aValidDeliveryVerifiesAndDecodesToATypedEvent() throws {
        let (event, body) = try event(data: outcome())
        let verifier = WebhookVerifier(secret: secret, clock: { Fixtures.now })
        let verified = try verifier.verify(headers: headers(body, event: event), body: body)
        #expect(verified.id == event.id)
        guard case .interactionDecided(let decided) = try verified.typed() else { Issue.record("wrong type"); return }
        #expect(decided.status == .approved)
        #expect(decided.assurance == .biometric)
    }

    @Test func headerNamesAreCaseInsensitive() throws {
        let (event, body) = try event(data: outcome())
        let lowered = Dictionary(uniqueKeysWithValues: headers(body, event: event).map { ($0.key.lowercased(), $0.value) })
        #expect(throws: Never.self) { try WebhookVerifier(secret: secret, clock: { Fixtures.now }).verify(headers: lowered, body: body) }
    }

    @Test func tamperedBodiesWrongSecretsAndMissingHeadersAreRejected() throws {
        let (event, body) = try event(data: outcome())
        let verifier = WebhookVerifier(secret: secret, clock: { Fixtures.now })
        var tampered = body
        tampered[tampered.startIndex + 5] ^= 0x01
        #expect(throws: WebhookVerificationError.noMatchingSignature) { try verifier.verify(headers: headers(body), body: tampered) }
        // Re-serializing the JSON (even without changing meaning) breaks the signature: always verify the raw bytes.
        let reserialized = Data(String(decoding: body, as: UTF8.self).replacingOccurrences(of: ",", with: ", ").utf8)
        #expect(throws: WebhookVerificationError.noMatchingSignature) { try verifier.verify(headers: headers(body), body: reserialized) }
        #expect(throws: WebhookVerificationError.noMatchingSignature) {
            try WebhookVerifier(secret: WebhookSignature.generateSecret(), clock: { Fixtures.now }).verify(headers: headers(body), body: body)
        }
        #expect(throws: WebhookVerificationError.missingSignatureHeader) { try verifier.verify(headers: [:], body: body) }
        for bad in ["", "garbage", "t=abc,v1=00", "v1=" + String(repeating: "0", count: 64), "t=1,v1=zz"] {
            #expect(throws: WebhookVerificationError.malformedSignature) { try verifier.verify(headers: [ViadereHeader.signature: bad], body: body) }
        }
        _ = event
    }

    @Test func staleAndFutureTimestampsAreRejectedAsReplays() throws {
        let (_, body) = try event(data: outcome())
        let verifier = WebhookVerifier(secret: secret, clock: { Fixtures.now })
        #expect(throws: Never.self) { try verifier.verify(headers: headers(body, at: Fixtures.now.addingTimeInterval(-299)), body: body) }
        #expect(throws: WebhookVerificationError.timestampOutsideTolerance) { try verifier.verify(headers: headers(body, at: Fixtures.now.addingTimeInterval(-301)), body: body) }
        #expect(throws: WebhookVerificationError.timestampOutsideTolerance) { try verifier.verify(headers: headers(body, at: Fixtures.now.addingTimeInterval(301)), body: body) }
        // A tighter tolerance can be chosen, but never a looser one than the protocol maximum.
        let tight = WebhookVerifier(secret: secret, tolerance: 30, clock: { Fixtures.now })
        #expect(throws: WebhookVerificationError.timestampOutsideTolerance) { try tight.verify(headers: headers(body, at: Fixtures.now.addingTimeInterval(-60)), body: body) }
        let loose = WebhookVerifier(secret: secret, tolerance: 86_400, clock: { Fixtures.now })
        #expect(throws: WebhookVerificationError.timestampOutsideTolerance) { try loose.verify(headers: headers(body, at: Fixtures.now.addingTimeInterval(-3600)), body: body) }
    }

    @Test func duringARotationEitherSecretVerifiesAndUnknownSchemesAreIgnored() throws {
        let old = WebhookSignature.generateSecret()
        let (_, body) = try event(data: outcome())
        let both = headers(body, secrets: [secret, old])
        #expect(throws: Never.self) { try WebhookVerifier(secrets: [secret, old], clock: { Fixtures.now }).verify(headers: both, body: body) }
        #expect(throws: Never.self) { try WebhookVerifier(secrets: [old], clock: { Fixtures.now }).verify(headers: both, body: body) }
        #expect(throws: Never.self) { try WebhookVerifier(secrets: [secret], clock: { Fixtures.now }).verify(headers: both, body: body) }
        var future = both
        future[ViadereHeader.signature]! += ",v0=ffff,v9=eeee"
        #expect(throws: Never.self) { try WebhookVerifier(secret: secret, clock: { Fixtures.now }).verify(headers: future, body: body) }
    }

    @Test func conveniencHeadersMustAgreeWithTheSignedBody() throws {
        let (event, body) = try event(data: outcome())
        let verifier = WebhookVerifier(secret: secret, clock: { Fixtures.now })
        var wrongId = headers(body, event: event)
        wrongId[ViadereHeader.eventId] = WebhookDeliveryID().description
        #expect(throws: WebhookVerificationError.headerBodyMismatch) { try verifier.verify(headers: wrongId, body: body) }
        var wrongType = headers(body, event: event)
        wrongType[ViadereHeader.eventType] = "interaction.expired"
        #expect(throws: WebhookVerificationError.headerBodyMismatch) { try verifier.verify(headers: wrongType, body: body) }
    }

    @Test func properlySignedButMalformedBodiesAreRejected() throws {
        let body = Data("{\"hello\":\"world\"}".utf8)
        #expect(throws: WebhookVerificationError.malformedBody) {
            try WebhookVerifier(secret: secret, clock: { Fixtures.now }).verify(headers: headers(body), body: body)
        }
    }

    @Test func redeliveriesAreDetectedWhenADeduplicatorIsSupplied() throws {
        let (event, body) = try event(data: outcome())
        let verifier = WebhookVerifier(secret: secret, clock: { Fixtures.now })
        let dedup = InMemoryWebhookDeduplicator()
        _ = try verifier.verify(headers: headers(body, event: event), body: body, deduplicator: dedup)
        #expect(throws: WebhookVerificationError.duplicateEvent) { try verifier.verify(headers: headers(body, event: event), body: body, deduplicator: dedup) }
        // The deduplicator is bounded.
        let small = InMemoryWebhookDeduplicator(capacity: 2)
        #expect(small.markProcessing(eventId: "a"))
        #expect(!small.markProcessing(eventId: "a"))
        #expect(small.markProcessing(eventId: "b"))
        #expect(small.markProcessing(eventId: "c"))
        #expect(small.markProcessing(eventId: "a"), "evicted ids are forgotten")
    }

    @Test func everyEventTypeDecodesToItsTypedPayloadAndUnknownTypesPassThrough() throws {
        let relationship = RelationshipEvent(relationshipId: RelationshipID(), source: .code, occurredAt: Fixtures.now)
        let cases: [(WebhookEventType, any Encodable, (TypedWebhookEvent) -> Bool)] = [
            (.interactionDecided, outcome(), { if case .interactionDecided = $0 { true } else { false } }),
            (.interactionExpired, outcome(), { if case .interactionExpired = $0 { true } else { false } }),
            (.interactionCancelled, outcome(), { if case .interactionCancelled = $0 { true } else { false } }),
            (.messageReceived, MessageReceivedEvent(sessionId: SessionID(), relationshipId: RelationshipID(), messageId: MessageID(), text: "Where is my order 1042?", channel: .sms, receivedAt: Fixtures.now), { if case .messageReceived(let m) = $0 { m.text == "Where is my order 1042?" } else { false } }),
            (.relationshipConnected, relationship, { if case .relationshipConnected = $0 { true } else { false } }),
            (.relationshipDisconnected, relationship, { if case .relationshipDisconnected = $0 { true } else { false } }),
            (.consentUpdated, ConsentUpdatedEvent(relationshipId: RelationshipID(), purpose: .marketing, granted: false, occurredAt: Fixtures.now), { if case .consentUpdated(let c) = $0 { !c.granted && c.purpose == .marketing } else { false } }),
            (WebhookEventType(rawValue: "future.thing"), ["a": "b"], { if case .other(let t, _) = $0 { t.rawValue == "future.thing" } else { false } }),
        ]
        for (type, payload, check) in cases {
            let wrapped = try WebhookEvent(type: type, createdAt: Fixtures.now, businessId: businessId, payload: AnyEncodable(payload))
            let body = try ViadereJSON.encode(wrapped)
            let verified = try WebhookVerifier(secret: secret, clock: { Fixtures.now }).verify(headers: headers(body, event: wrapped), body: body)
            #expect(check(try verified.typed()), "\(type.rawValue)")
        }
        // A payload that does not match its declared type is reported, not crashed on.
        let bad = try WebhookEvent(type: .interactionDecided, createdAt: Fixtures.now, businessId: businessId, payload: ["wrong": "shape"])
        #expect(throws: WebhookVerificationError.malformedBody) { try bad.typed() }
    }

    @Test func theSDKVerifiesWhatTheServerSignsAndRejectsWhatItDidNotSign() throws {
        // The server side of the protocol is Core's `WebhookSignature`; this is the contract the SDK must honour.
        let body = Data("{\"id\":\"x\"}".utf8)
        let header = WebhookSignature.header(secret: secret, body: body, now: Fixtures.now)
        #expect(header.hasPrefix("t=\(ViadereDate.unixSeconds(Fixtures.now)),v1="))
        #expect(throws: WebhookVerificationError.malformedBody) { try WebhookVerifier(secret: secret, clock: { Fixtures.now }).verify(headers: [ViadereHeader.signature: header], body: body) }
    }
}

@Suite("Webhook ownership challenge")
struct WebhookOwnershipChallengeTests {
    let secret = WebhookSignature.generateSecret()

    private func challengeRequest(_ challenge: String = "c-123", type: String = "webhook.verification", secret: String? = nil, at: Date = Fixtures.now) throws -> ([String: String], Data) {
        let body = Data("{\"type\":\"\(type)\",\"challenge\":\"\(challenge)\",\"endpointId\":\"e1\"}".utf8)
        return ([ViadereHeader.signature: WebhookSignature.header(secret: secret ?? self.secret, body: body, now: at), ViadereHeader.eventType: type], body)
    }

    @Test func answersWithTheHMACProofAndNeverEchoesTheChallenge() throws {
        let (headers, body) = try challengeRequest()
        let answer = try WebhookVerifier(secret: secret, clock: { Fixtures.now }).verificationResponse(headers: headers, body: body)
        let object = try #require(try JSONSerialization.jsonObject(with: answer) as? [String: String])
        #expect(object["challenge_response"] == WebhookSignature.verificationResponse(secret: secret, challenge: "c-123"))
        #expect(object["challenge"] == nil)
        #expect(!String(decoding: answer, as: UTF8.self).contains("c-123"))
    }

    @Test func refusesAnythingNotSignedWithTheSecretOrNotAChallenge() throws {
        let verifier = WebhookVerifier(secret: secret, clock: { Fixtures.now })
        let (foreignHeaders, foreignBody) = try challengeRequest(secret: WebhookSignature.generateSecret())
        #expect(throws: WebhookVerificationError.noMatchingSignature) { try verifier.verificationResponse(headers: foreignHeaders, body: foreignBody) }
        let (staleHeaders, staleBody) = try challengeRequest(at: Fixtures.now.addingTimeInterval(-3_600))
        #expect(throws: WebhookVerificationError.timestampOutsideTolerance) { try verifier.verificationResponse(headers: staleHeaders, body: staleBody) }
        let (otherHeaders, otherBody) = try challengeRequest(type: "message.received")
        #expect(throws: WebhookVerificationError.notAVerificationRequest) { try verifier.verificationResponse(headers: otherHeaders, body: otherBody) }
        #expect(throws: WebhookVerificationError.missingSignatureHeader) { try verifier.verificationResponse(headers: [:], body: otherBody) }
    }

    @Test func duringARotationEitherSecretAnswersWithTheOneThatSignedTheRequest() throws {
        let old = WebhookSignature.generateSecret()
        let (headers, body) = try challengeRequest(secret: old)
        let answer = try WebhookVerifier(secrets: [secret, old], clock: { Fixtures.now }).verificationResponse(headers: headers, body: body)
        let object = try #require(try JSONSerialization.jsonObject(with: answer) as? [String: String])
        #expect(object["challenge_response"] == WebhookSignature.verificationResponse(secret: old, challenge: "c-123"))
    }
}

struct AnyEncodable: Encodable {
    let value: any Encodable
    init(_ value: any Encodable) { self.value = value }
    func encode(to encoder: any Encoder) throws { try value.encode(to: encoder) }
}
