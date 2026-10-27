import Crypto
import Foundation
import Testing
@testable import ViadereCore

@Suite("Request signing")
struct RequestSigningTests {
    let key = SoftwareP256SigningKey()
    let deviceId = DeviceID()
    let now = Fixtures.now
    let body = Data(#"{"hello":"world"}"#.utf8)

    @Test func stringToSignFormat() {
        let s = RequestSignature.stringToSign(method: "post", pathAndQuery: "/v1/interactions?limit=20", timestamp: 1_800_000_000,
                                              nonce: "abcdefghijklmnop", bodySHA256Hex: RequestSignature.bodyHash(Data()))
        #expect(s == "VIADERE-SIG-V1\nPOST\n/v1/interactions?limit=20\n1800000000\nabcdefghijklmnop\ne3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")
    }

    @Test func roundTripAndTamper() async throws {
        let signer = RequestSigner(deviceId: deviceId, key: key)
        let headers = try await signer.sign(method: "POST", pathAndQuery: "/v1/interactions/x/decision", body: body, now: now)
        #expect(headers.signature.count == 86)
        let verifier = RequestVerifier()
        try verifier.verify(method: "POST", pathAndQuery: "/v1/interactions/x/decision", body: body, headers: headers,
                            publicKey: key.publicKey, now: now.addingTimeInterval(10))

        func fails(_ method: String = "POST", _ path: String = "/v1/interactions/x/decision", _ b: Data? = nil,
                   h: SignedRequestHeaders? = nil, pk: DevicePublicKey? = nil, at: Date? = nil) -> RequestVerificationError? {
            do {
                try verifier.verify(method: method, pathAndQuery: path, body: b ?? body, headers: h ?? headers,
                                    publicKey: pk ?? key.publicKey, now: at ?? now)
                return nil
            } catch let e as RequestVerificationError { return e } catch { return nil }
        }
        #expect(fails("PUT") == .badSignature)
        #expect(fails("POST", "/v1/interactions/y/decision") == .badSignature)
        #expect(fails("POST", "/v1/interactions/x/decision?a=1") == .badSignature)
        #expect(fails("POST", "/v1/interactions/x/decision", Data(#"{"hello":"World"}"#.utf8)) == .badSignature)
        var h = headers
        h.timestamp += 1
        #expect(fails(h: h) == .badSignature)
        h = headers
        h.nonce = "ZZZZZZZZZZZZZZZZZZZZZZ"
        #expect(fails(h: h) == .badSignature)
        h = headers
        h.nonce = "short"
        #expect(fails(h: h) == .malformedNonce)
        h = headers
        h.signature = "!!"
        #expect(fails(h: h) == .malformedSignature)
        #expect(fails(pk: SoftwareP256SigningKey().publicKey) == .badSignature)
        #expect(fails(at: now.addingTimeInterval(301)) == .clockSkew)
        #expect(fails(at: now.addingTimeInterval(-301)) == .clockSkew)
    }

    @Test("DER signatures are rejected; only raw r||s is accepted")
    func derRejected() async throws {
        let message = Data("x".utf8)
        let sig = try await key.signature(for: message)
        #expect(ViadereSignatureEncoding.decode(Base64URL.encode(sig.derRepresentation)) == nil)
        #expect(ViadereSignatureEncoding.decode(ViadereSignatureEncoding.encode(sig)) != nil)
    }

    @Test func replayProtection() async throws {
        let guardian = InMemoryReplayGuard()
        let signer = RequestSigner(deviceId: deviceId, key: key)
        let headers = try await signer.sign(method: "GET", pathAndQuery: "/v1/devices", body: Data(), now: now)
        let verifier = RequestVerifier()
        try await verifier.verify(method: "GET", pathAndQuery: "/v1/devices", body: Data(), headers: headers,
                                  publicKey: key.publicKey, now: now, replayGuard: guardian)
        await #expect(throws: RequestVerificationError.replayed) {
            try await verifier.verify(method: "GET", pathAndQuery: "/v1/devices", body: Data(), headers: headers,
                                      publicKey: key.publicKey, now: now.addingTimeInterval(1), replayGuard: guardian)
        }
    }

    @Test func headerParsing() throws {
        let headers = SignedRequestHeaders(deviceId: deviceId, timestamp: 1_800_000_000, nonce: "abcdefghijklmnop", signature: "sig")
        let lowercased = Dictionary(uniqueKeysWithValues: headers.fields.map { ($0.key.lowercased(), $0.value) })
        #expect(try SignedRequestHeaders(headers: lowercased) == headers)
        var bad = headers.fields
        bad[ViadereHeader.timestamp] = "12a"
        #expect(throws: RequestVerificationError.malformedTimestamp) { try SignedRequestHeaders(headers: bad) }
        bad = headers.fields
        bad[ViadereHeader.device] = nil
        #expect(throws: RequestVerificationError.missingHeader(ViadereHeader.device)) { try SignedRequestHeaders(headers: bad) }
    }

    @Test func publicKeyFormats() throws {
        let pk = key.publicKey
        #expect(pk.x963.count == 65)
        let raw = try pk.signingKey().rawRepresentation
        #expect(try DevicePublicKey(bytes: raw) == pk)
        #expect(try DevicePublicKey(base64URL: pk.base64URL) == pk)
        #expect(throws: DevicePublicKey.Error.invalidKey) { try DevicePublicKey(bytes: Data(repeating: 4, count: 65)) }
        #expect(throws: DevicePublicKey.Error.invalidKey) { try DevicePublicKey(bytes: Data(repeating: 1, count: 33)) }
        let json = try ViadereJSON.encode([pk])
        #expect(try ViadereJSON.decode([DevicePublicKey].self, from: json) == [pk])
        #expect(pk.fingerprint.count == 64)
    }

    @Test func replayGuardTTL() async throws {
        let g = InMemoryReplayGuard(maxEntries: 2)
        #expect(try await g.registerIfFresh(nonce: "a", scope: "s", expiresAt: now.addingTimeInterval(10), now: now))
        #expect(try await !g.registerIfFresh(nonce: "a", scope: "s", expiresAt: now.addingTimeInterval(10), now: now))
        #expect(try await g.registerIfFresh(nonce: "a", scope: "other", expiresAt: now.addingTimeInterval(10), now: now))
        // Full: fails closed until entries expire.
        #expect(try await !g.registerIfFresh(nonce: "b", scope: "s", expiresAt: now.addingTimeInterval(10), now: now))
        #expect(try await g.registerIfFresh(nonce: "a", scope: "s", expiresAt: now.addingTimeInterval(30), now: now.addingTimeInterval(11)))
        #expect(await g.count == 1)
    }
}

@Suite("Decision signing")
struct DecisionSigningTests {
    let biometricKey = SoftwareP256SigningKey()
    let passcodeKey = SoftwareP256SigningKey()
    let deviceId = DeviceID()
    let now = Fixtures.now

    func payload(for i: Interaction, decision: Decision = .approve, assurance: DecisionAssurance = .biometric,
                 selected: [String]? = nil, challenge: ChallengeNonce? = nil, at: Date? = nil) -> DecisionPayload {
        DecisionPayload(interactionId: i.id, businessId: i.businessId, decision: decision, selectedOptionIds: selected,
                        challenge: challenge ?? i.challenge, signedAt: at ?? now.addingTimeInterval(5), deviceId: deviceId,
                        assurance: assurance)
    }

    @Test func canonicalEncoding() throws {
        let p = DecisionPayload(
            interactionId: try #require(InteractionID("11111111-1111-1111-1111-111111111111")),
            businessId: try #require(BusinessID("22222222-2222-2222-2222-222222222222")),
            decision: .select, selectedOptionIds: ["pm"], reply: "Leave at \"door\"",
            challenge: try #require(ChallengeNonce("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")),
            signedAt: Date(timeIntervalSince1970: 1_800_000_000.1234),
            deviceId: try #require(DeviceID("33333333-3333-3333-3333-333333333333")), assurance: .biometric)
        let json = String(decoding: try p.canonicalJSON(), as: UTF8.self)
        #expect(json == #"{"assurance":"biometric","businessId":"22222222-2222-2222-2222-222222222222","challenge":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA","decision":"select","deviceId":"33333333-3333-3333-3333-333333333333","interactionId":"11111111-1111-1111-1111-111111111111","reply":"Leave at \"door\"","selectedOptionIds":["pm"],"signedAt":"2027-01-15T08:00:00.123Z","v":1}"#)
        #expect(try DecisionPayload.decodeCanonical(p.canonicalJSON()) == p)
        #expect(try p.signingInput().starts(with: Data("VIADERE-DECISION-V1\n{".utf8)))
    }

    @Test("Approve round trip for high-sensitivity authorize (Mesa)")
    func roundTrip() async throws {
        let i = Fixtures.interaction(.authorize(Fixtures.mesaAuthorize), sensitivity: .high)
        let signed = try await DecisionSigner(key: biometricKey).sign(payload(for: i))
        let verified = try DecisionVerifier().verify(signed, for: i, deviceId: deviceId, publicKey: biometricKey.publicKey,
                                                     channel: .nativePush, now: now.addingTimeInterval(10))
        #expect(verified.decision == .approve)
        let wire = try ViadereJSON.decode(SignedDecision.self, from: ViadereJSON.encode(signed))
        #expect(wire == signed)
    }

    @Test("Stale or replayed approvals fail (spec §19 #3)")
    func replayAndStale() async throws {
        let i = Fixtures.interaction(.authenticate(Fixtures.loginPayload), sensitivity: .high, purpose: .security)
        let signed = try await DecisionSigner(key: biometricKey).sign(payload(for: i))
        let guardian = InMemoryReplayGuard()
        let v = DecisionVerifier()
        _ = try await v.verify(signed, for: i, deviceId: deviceId, publicKey: biometricKey.publicKey, channel: .nativePush,
                               now: now.addingTimeInterval(10), replayGuard: guardian)
        await #expect(throws: DecisionVerificationError.replayed) {
            try await v.verify(signed, for: i, deviceId: deviceId, publicKey: biometricKey.publicKey, channel: .nativePush,
                               now: now.addingTimeInterval(11), replayGuard: guardian)
        }
        #expect(throws: DecisionVerificationError.expired) {
            try v.verify(signed, for: i, deviceId: deviceId, publicKey: biometricKey.publicKey, channel: .nativePush,
                         now: i.expiresAt)
        }
        // Signed too long ago.
        let long = Fixtures.interaction(.confirm(ConfirmPayload(title: "x")), lifetime: 3600)
        let old = try await DecisionSigner(key: biometricKey).sign(payload(for: long, decision: .confirm, at: now))
        #expect(throws: DecisionVerificationError.stale) {
            try v.verify(old, for: long, deviceId: deviceId, publicKey: biometricKey.publicKey, channel: .nativePush,
                         now: now.addingTimeInterval(301))
        }
        let future = try await DecisionSigner(key: biometricKey).sign(payload(for: long, decision: .confirm, at: now.addingTimeInterval(120)))
        #expect(throws: DecisionVerificationError.signedInFuture) {
            try v.verify(future, for: long, deviceId: deviceId, publicKey: biometricKey.publicKey, channel: .nativePush, now: now)
        }
    }

    @Test func bindingChecks() async throws {
        let i = Fixtures.interaction(.authorize(Fixtures.mesaAuthorize), sensitivity: .high)
        let other = Fixtures.interaction(.authorize(Fixtures.mesaAuthorize), sensitivity: .high)
        let v = DecisionVerifier()
        let at = now.addingTimeInterval(10)
        let signer = DecisionSigner(key: biometricKey)

        let wrongChallenge = try await signer.sign(payload(for: i, challenge: .generate()))
        #expect(throws: DecisionVerificationError.challengeMismatch) {
            try v.verify(wrongChallenge, for: i, deviceId: deviceId, publicKey: biometricKey.publicKey, channel: .nativePush, now: at)
        }
        let forOther = try await signer.sign(payload(for: other))
        #expect(throws: DecisionVerificationError.interactionMismatch) {
            try v.verify(forOther, for: i, deviceId: deviceId, publicKey: biometricKey.publicKey, channel: .nativePush, now: at)
        }
        let good = try await signer.sign(payload(for: i))
        #expect(throws: DecisionVerificationError.deviceMismatch) {
            try v.verify(good, for: i, deviceId: DeviceID(), publicKey: biometricKey.publicKey, channel: .nativePush, now: at)
        }
        #expect(throws: DecisionVerificationError.badSignature) {
            try v.verify(good, for: i, deviceId: deviceId, publicKey: passcodeKey.publicKey, channel: .nativePush, now: at)
        }
        #expect(throws: DecisionVerificationError.insufficientAssurance) {
            try v.verify(good, for: i, deviceId: deviceId, publicKey: biometricKey.publicKey, channel: .sms, now: at)
        }
        let passcode = try await DecisionSigner(key: passcodeKey).sign(payload(for: i, assurance: .devicePasscode))
        #expect(throws: DecisionVerificationError.insufficientAssurance) {
            try v.verify(passcode, for: i, deviceId: deviceId, publicKey: passcodeKey.publicKey, channel: .nativePush, now: at)
        }
        let wrongDecision = try await signer.sign(payload(for: i, decision: .select))
        #expect(throws: DecisionVerificationError.invalidDecision) {
            try v.verify(wrongDecision, for: i, deviceId: deviceId, publicKey: biometricKey.publicKey, channel: .nativePush, now: at)
        }
    }

    @Test func tamperedPayloadFails() async throws {
        let i = Fixtures.interaction(.authorize(Fixtures.mesaAuthorize), sensitivity: .high)
        let signed = try await DecisionSigner(key: biometricKey).sign(payload(for: i, decision: .deny))
        let bytes = try #require(Base64URL.decode(signed.payload))
        let flipped = String(decoding: bytes, as: UTF8.self).replacingOccurrences(of: "\"deny\"", with: "\"approve\"")
        let tampered = SignedDecision(payload: Base64URL.encode(Data(flipped.utf8)), signature: signed.signature)
        #expect(throws: DecisionVerificationError.badSignature) {
            try DecisionVerifier().verify(tampered, for: i, deviceId: deviceId, publicKey: biometricKey.publicKey,
                                          channel: .nativePush, now: now.addingTimeInterval(10))
        }
        // Non-canonical (whitespace) payloads are rejected even if signed.
        let spaced = String(decoding: bytes, as: UTF8.self).replacingOccurrences(of: ",", with: ", ")
        #expect(throws: DecisionVerificationError.nonCanonicalPayload) { try DecisionPayload.decodeCanonical(Data(spaced.utf8)) }
        let extra = String(decoding: bytes, as: UTF8.self).replacingOccurrences(of: "{", with: #"{"admin":true,"#)
        #expect(throws: DecisionVerificationError.malformedPayload) { try DecisionPayload.decodeCanonical(Data(extra.utf8)) }
    }

    @Test func chooseSelections() async throws {
        let i = Fixtures.interaction(.choose(Fixtures.choosePayload), sensitivity: .low)
        let v = DecisionVerifier()
        let signer = DecisionSigner(key: biometricKey)
        let ok = try await signer.sign(payload(for: i, decision: .select, assurance: .none, selected: ["pm"]))
        #expect(try v.verify(ok, for: i, deviceId: deviceId, publicKey: biometricKey.publicKey, channel: .nativePush,
                             now: now.addingTimeInterval(10)).selectedOptionIds == ["pm"])
        for bad in [["nope"], ["am", "pm"], []] {
            let s = try await signer.sign(payload(for: i, decision: .select, assurance: .none, selected: bad))
            #expect(throws: DecisionVerificationError.invalidSelection) {
                try v.verify(s, for: i, deviceId: deviceId, publicKey: biometricKey.publicKey, channel: .nativePush,
                             now: now.addingTimeInterval(10))
            }
        }
    }

    @Test func deviceEnrollmentProof() async throws {
        let consumer = ConsumerID()
        let reg = try await DeviceEnrollment.register(key: biometricKey, purpose: .approvalBiometric, hardwareBacked: true,
                                                      consumerId: consumer, challenge: "chal")
        #expect(DeviceEnrollment.verify(reg, consumerId: consumer, challenge: "chal"))
        #expect(!DeviceEnrollment.verify(reg, consumerId: ConsumerID(), challenge: "chal"))
        #expect(!DeviceEnrollment.verify(reg, consumerId: consumer, challenge: "other"))
        var swapped = reg
        swapped.purpose = .request
        #expect(!DeviceEnrollment.verify(swapped, consumerId: consumer, challenge: "chal"))
        #expect(DeviceKeyPurpose.required(for: .biometric) == .approvalBiometric)
    }
}

@Suite("Webhook signatures")
struct WebhookSignatureTests {
    let secret = "whsec_test_secret"
    let body = Data(#"{"type":"interaction.decided"}"#.utf8)
    let now = Fixtures.now

    @Test func format() {
        let header = WebhookSignature.header(secret: secret, body: body, now: now)
        #expect(header.hasPrefix("t=1800000000,v1="))
        #expect(header.count == "t=1800000000,v1=".count + 64)
        // Independent recomputation of the documented formula.
        let expected = Hex.encode(HMAC<SHA256>.authenticationCode(for: Data("1800000000.".utf8) + body,
                                                                   using: SymmetricKey(data: Data(secret.utf8))))
        #expect(header == "t=1800000000,v1=\(expected)")
    }

    @Test func verifyWithinTolerance() throws {
        let header = WebhookSignature.header(secret: secret, body: body, now: now)
        #expect(try WebhookSignature.verify(header: header, body: body, secrets: [secret], now: now.addingTimeInterval(299)) == 1_800_000_000)
        #expect(throws: WebhookSignature.Error.timestampOutsideTolerance) {
            try WebhookSignature.verify(header: header, body: body, secrets: [secret], now: now.addingTimeInterval(301))
        }
        #expect(throws: WebhookSignature.Error.timestampOutsideTolerance) {
            try WebhookSignature.verify(header: header, body: body, secrets: [secret], now: now.addingTimeInterval(-301))
        }
    }

    @Test func tamperAndRotation() throws {
        let header = WebhookSignature.header(secret: secret, body: body, now: now)
        #expect(throws: WebhookSignature.Error.noMatchingSignature) {
            try WebhookSignature.verify(header: header, body: body + Data(" ".utf8), secrets: [secret], now: now)
        }
        #expect(throws: WebhookSignature.Error.noMatchingSignature) {
            try WebhookSignature.verify(header: header, body: body, secrets: ["whsec_other"], now: now)
        }
        // Changing t invalidates the MAC.
        let shifted = header.replacingOccurrences(of: "t=1800000000", with: "t=1800000001")
        #expect(throws: WebhookSignature.Error.noMatchingSignature) {
            try WebhookSignature.verify(header: shifted, body: body, secrets: [secret], now: now)
        }
        // Rotation: header carries old+new; receiver with either secret verifies.
        let rotating = WebhookSignature.header(secrets: ["whsec_old", "whsec_new"], body: body, now: now)
        #expect(throws: Never.self) { try WebhookSignature.verify(header: rotating, body: body, secrets: ["whsec_new"], now: now) }
        #expect(throws: Never.self) { try WebhookSignature.verify(header: rotating, body: body, secrets: ["whsec_old"], now: now) }
        #expect(throws: Never.self) { try WebhookSignature.verify(header: header + ",v0=deadbeef", body: body, secrets: [secret], now: now) }
    }

    @Test("Malformed headers", arguments: ["", "t=1800000000", "v1=" + String(repeating: "a", count: 64), "t=abc,v1=00",
                                            "t=1800000000,v1=xyz", "t=1,t=2,v1=" + String(repeating: "a", count: 64), "garbage"])
    func malformed(header: String) {
        #expect(throws: WebhookSignature.Error.malformedHeader) {
            try WebhookSignature.verify(header: header, body: Data(), secrets: ["s"], now: Fixtures.now)
        }
    }

    @Test func secrets() {
        let s = WebhookSignature.generateSecret()
        #expect(s.hasPrefix("whsec_") && s.count == 6 + 43)
    }
}

@Suite("Tokens")
struct TokenTests {
    @Test func generateHashCompare() {
        let a = SecureToken.generate()
        let b = SecureToken.generate()
        #expect(a.count == 43 && a != b)
        #expect(Base64URL.isValid(a))
        let hash = SecureToken.hash(a)
        #expect(hash.count == 64)
        #expect(SecureToken.matches(a, hash: hash))
        #expect(SecureToken.matches(a, hash: hash.uppercased()))
        #expect(!SecureToken.matches(b, hash: hash))
        #expect(!SecureToken.matches(a, hash: "not-hex"))
        #expect(SecureToken.hash("abc") == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        #expect(SecureToken.generate(byteCount: 16).count == 22)
        #expect(ChallengeNonce.generate().value.count == 43)
        #expect(ChallengeNonce("short") == nil)
    }
}
