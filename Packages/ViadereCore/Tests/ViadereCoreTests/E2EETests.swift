import Crypto
import Foundation
import XCTest
@testable import ViadereCore

final class E2EETests: XCTestCase {
    private let now = Date(timeIntervalSince1970: 1_800_000_000)

    private func context(expires: TimeInterval = 120, purpose: String = "approve.request") -> E2EEContext {
        E2EEContext(purpose: purpose, requestId: "req_0123456789abcdef", sender: "biz_00000000-0000-0000-0000-000000000001",
                    recipient: "dev_recipient", expiresAt: now.addingTimeInterval(expires))
    }

    private let expectation = E2EEExpectation(purpose: "approve.request", requestId: "req_0123456789abcdef")

    func testRoundTripAndNoPlaintextOnTheWire() throws {
        let key = SoftwareE2EEPrivateKey()
        let secret = Data("amount=2500.00 payee=Mallory Ltd".utf8)
        let envelope = try E2EE.seal(secret, to: key.publicKey, context: context())
        let wire = try envelope.serialized()
        XCTAssertNil(wire.range(of: Data("Mallory".utf8)), "plaintext must never appear in the envelope")
        XCTAssertNil(wire.range(of: Data("2500".utf8)))
        let parsed = try E2EEEnvelope.parse(wire)
        XCTAssertEqual(parsed, envelope)
        XCTAssertEqual(try E2EE.open(parsed, using: key, expecting: expectation, now: now), secret)
    }

    func testEveryEnvelopeIsFresh() throws {
        let key = SoftwareE2EEPrivateKey()
        let a = try E2EE.seal(Data("x".utf8), to: key.publicKey, context: context())
        let b = try E2EE.seal(Data("x".utf8), to: key.publicKey, context: context())
        XCTAssertNotEqual(a.enc, b.enc, "a fresh ephemeral key per envelope")
        XCTAssertNotEqual(a.ct, b.ct)
    }

    func testRelayCannotOpenOrReroute() throws {
        let device = SoftwareE2EEPrivateKey()
        let relay = SoftwareE2EEPrivateKey()
        let envelope = try E2EE.seal(Data("secret".utf8), to: device.publicKey, context: context())
        XCTAssertThrowsError(try E2EE.open(envelope, using: relay, expecting: expectation, now: now)) {
            XCTAssertEqual($0 as? E2EEError, .wrongRecipientKey)
        }
        // Re-addressing the envelope to the relay's kid still cannot decrypt: the key schedule binds the real recipient key.
        let readdressed = E2EEEnvelope(suite: envelope.suite, kid: relay.publicKey.kid, enc: envelope.enc, ct: envelope.ct, context: envelope.context)
        XCTAssertThrowsError(try E2EE.open(readdressed, using: relay, expecting: expectation, now: now)) {
            XCTAssertEqual($0 as? E2EEError, .authenticationFailed)
        }
    }

    func testTamperingWithAnyFieldIsDetected() throws {
        let key = SoftwareE2EEPrivateKey()
        let envelope = try E2EE.seal(Data("secret".utf8), to: key.publicKey, context: context())
        var flipped = envelope.ct
        flipped[0] ^= 0x01
        let tamperedCT = E2EEEnvelope(suite: envelope.suite, kid: envelope.kid, enc: envelope.enc, ct: flipped, context: envelope.context)
        var truncated = envelope.ct
        truncated.removeLast()
        let tamperedTag = E2EEEnvelope(suite: envelope.suite, kid: envelope.kid, enc: envelope.enc, ct: truncated, context: envelope.context)
        var ctx = envelope.context
        ctx.expiresAtSeconds += 3600
        let longer = E2EEEnvelope(suite: envelope.suite, kid: envelope.kid, enc: envelope.enc, ct: envelope.ct, context: ctx)
        ctx = envelope.context
        ctx.sender = "biz_attacker"
        let otherSender = E2EEEnvelope(suite: envelope.suite, kid: envelope.kid, enc: envelope.enc, ct: envelope.ct, context: ctx)
        ctx = envelope.context
        ctx.recipient = "dev_someone_else"
        let otherRecipient = E2EEEnvelope(suite: envelope.suite, kid: envelope.kid, enc: envelope.enc, ct: envelope.ct, context: ctx)
        let otherEnc = E2EEEnvelope(suite: envelope.suite, kid: envelope.kid, enc: try E2EE.seal(Data(), to: key.publicKey, context: context()).enc,
                                    ct: envelope.ct, context: envelope.context)
        for (name, bad) in [("ct", tamperedCT), ("tag", tamperedTag), ("exp", longer), ("sender", otherSender), ("recipient", otherRecipient), ("enc", otherEnc)] {
            XCTAssertThrowsError(try E2EE.open(bad, using: key, expecting: E2EEExpectation(purpose: "approve.request"), now: now), name) {
                XCTAssertEqual($0 as? E2EEError, .authenticationFailed, name)
            }
        }
    }

    func testExpectationAndExpiry() throws {
        let key = SoftwareE2EEPrivateKey()
        let envelope = try E2EE.seal(Data("secret".utf8), to: key.publicKey, context: context())
        XCTAssertThrowsError(try E2EE.open(envelope, using: key, expecting: E2EEExpectation(purpose: "verify.result"), now: now)) {
            XCTAssertEqual($0 as? E2EEError, .contextMismatch("purpose"))
        }
        XCTAssertThrowsError(try E2EE.open(envelope, using: key, expecting: E2EEExpectation(purpose: "approve.request", requestId: "req_other_other_other"), now: now)) {
            XCTAssertEqual($0 as? E2EEError, .contextMismatch("request_id"))
        }
        XCTAssertThrowsError(try E2EE.open(envelope, using: key, expecting: E2EEExpectation(purpose: "approve.request", sender: "biz_x"), now: now)) {
            XCTAssertEqual($0 as? E2EEError, .contextMismatch("sender"))
        }
        XCTAssertThrowsError(try E2EE.open(envelope, using: key, expecting: expectation, now: now.addingTimeInterval(121))) {
            XCTAssertEqual($0 as? E2EEError, .expired)
        }
    }

    func testStrictParser() throws {
        let key = SoftwareE2EEPrivateKey()
        let good = try E2EE.seal(Data("secret".utf8), to: key.publicKey, context: context())
        guard case .object(var members) = try JSONDecoder().decode(JSONValue.self, from: good.serialized()) else { return XCTFail() }
        func parse(_ members: [String: JSONValue]) throws -> E2EEEnvelope {
            try E2EEEnvelope.parse(try JSONEncoder().encode(JSONValue.object(members)))
        }
        XCTAssertNoThrow(try parse(members))
        var future = members
        future["v"] = .integer(2)
        XCTAssertThrowsError(try parse(future)) { XCTAssertEqual($0 as? E2EEError, .unsupportedVersion(2)) }
        var unknownSuite = members
        unknownSuite["suite"] = .string("hpke-0020-0001-0003")
        XCTAssertThrowsError(try parse(unknownSuite)) { XCTAssertEqual($0 as? E2EEError, .unsupportedSuite("hpke-0020-0001-0003")) }
        var extra = members
        extra["debug"] = .string("x")
        XCTAssertThrowsError(try parse(extra))
        var missing = members
        missing["ct"] = nil
        XCTAssertThrowsError(try parse(missing))
        var badEnc = members
        badEnc["enc"] = .string(Base64URL.encode(Data(repeating: 4, count: 65)))
        XCTAssertThrowsError(try parse(badEnc))
        var badKid = members
        badKid["kid"] = .string("short")
        XCTAssertThrowsError(try parse(badKid))
        var ctx = try XCTUnwrap(members["ctx"]?.objectValue)
        ctx["extra"] = .string("x")
        members["ctx"] = .object(ctx)
        XCTAssertThrowsError(try parse(members))
        XCTAssertThrowsError(try E2EEEnvelope.parse(Data(repeating: 0x20, count: E2EEEnvelope.maxEnvelopeBytes + 1))) { XCTAssertEqual($0 as? E2EEError, .tooLarge) }
        XCTAssertThrowsError(try E2EEEnvelope.parse(Data("[]".utf8)))
        XCTAssertThrowsError(try E2EE.seal(Data(count: E2EEEnvelope.maxPlaintextBytes + 1), to: key.publicKey, context: context())) { XCTAssertEqual($0 as? E2EEError, .tooLarge) }
        XCTAssertThrowsError(try E2EE.seal(Data(), to: key.publicKey, context: E2EEContext(purpose: "Bad Purpose", requestId: "r", sender: "s", recipient: "r", expiresAt: now)))
    }

    func testCodableUsesTheStrictParser() throws {
        let key = SoftwareE2EEPrivateKey()
        let good = try E2EE.seal(Data("secret".utf8), to: key.publicKey, context: context())
        let encoded = try JSONEncoder().encode(good)
        XCTAssertEqual(try JSONDecoder().decode(E2EEEnvelope.self, from: encoded), good)
        XCTAssertThrowsError(try JSONDecoder().decode(E2EEEnvelope.self, from: Data(#"{"v":1}"#.utf8)))
    }

    func testKeyIdentifierIsSHA256OfSPKI() throws {
        let key = P256.KeyAgreement.PrivateKey()
        let viaPrefix = try KeyIdentifier.make(p256X963: key.publicKey.x963Representation)
        XCTAssertEqual(viaPrefix, KeyIdentifier.make(key.publicKey))
        XCTAssertEqual(viaPrefix, Base64URL.encode(Data(SHA256.hash(data: key.publicKey.derRepresentation))))
        XCTAssertEqual(viaPrefix.count, 43)
        XCTAssertTrue(KeyIdentifier.isValid(viaPrefix))
        XCTAssertFalse(KeyIdentifier.isValid("abc"))
        XCTAssertThrowsError(try KeyIdentifier.make(p256X963: Data(repeating: 1, count: 65)))
        // Same key material, whichever API produced it.
        let signing = P256.Signing.PrivateKey()
        XCTAssertEqual(KeyIdentifier.make(signing.publicKey), try KeyIdentifier.make(p256X963: signing.publicKey.x963Representation))
        XCTAssertEqual(KeyIdentifier.displayFingerprint(viaPrefix).count, 23)
    }

    func testRecipientKeyRoundTripsThroughJSON() throws {
        let key = SoftwareE2EEPrivateKey()
        let restored = try SoftwareE2EEPrivateKey(rawRepresentation: key.rawRepresentation)
        XCTAssertEqual(restored.publicKey, key.publicKey)
        let json = try JSONEncoder().encode([key.publicKey])
        XCTAssertEqual(try JSONDecoder().decode([E2EEPublicKey].self, from: json), [key.publicKey])
        XCTAssertThrowsError(try JSONDecoder().decode([E2EEPublicKey].self, from: Data(#"["AAAA"]"#.utf8)))
    }
}
